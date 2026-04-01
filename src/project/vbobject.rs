//! VB6 object (form, module, class) representation.
//!
//! In VB6, every source file compiles into an "object" registered in the
//! ObjectTable. Forms (`.frm`), standard modules (`.bas`), and class modules
//! (`.cls`) are all objects. Each object has a [`PublicObjectDescriptor`]
//! (the array entry), an [`ObjectInfo`] with method/constant table pointers,
//! an optional [`OptionalObjectInfo`] (controls, P-Code counts), and an
//! optional [`PrivateObjectDescriptor`] (function type descriptors, parameter
//! name tables).
//!
//! [`VbObject`] ties these structures together and provides iterators over
//! methods, controls, and method link thunks.

use core::str;

use crate::{
    addressmap::AddressMap,
    error::Error,
    project::{ControlEntryIterator, MethodEntry, MethodLinkIterator, PCodeMethod, VbProject},
    util::read_u32_le,
    vb::{
        constantpool::ConstantPool,
        control::Guid,
        eventname,
        flags::ObjectTypeFlags,
        formdata::{FormControlType, FormDataParser},
        functype::FuncTypDesc,
        guitable::GuiTableEntry,
        object::{GuidTableIter, ObjectInfo, OptionalObjectInfo, PublicObjectDescriptor},
        privateobj::PrivateObjectDescriptor,
        publicbytes::{ClassFormPublicBytes, PublicVarTable},
        varstub::VarStubIter,
    },
};

/// Result of looking up a method name from the method names table.
///
/// Distinguishes between "the object has no names table at all" (common for
/// malware with zeroed-out metadata) and "this particular method slot has
/// no name" (normal for null/runtime slots).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MethodNameResult<'a> {
    /// The object has no method names table (`method_names_va == 0`).
    NoTable,
    /// This method slot has no name (the name VA entry is null).
    Unnamed,
    /// The resolved name bytes (null-terminated ASCII in the PE image).
    Name(&'a [u8]),
}

impl<'a> MethodNameResult<'a> {
    /// Returns the name bytes if available, or `None` for `NoTable`/`Unnamed`.
    pub fn as_bytes(&self) -> Option<&'a [u8]> {
        match self {
            Self::Name(n) => Some(n),
            _ => None,
        }
    }
}

/// Formats a VB6 function signature from a [`FuncTypDesc`] and method name.
///
/// Produces output like `Sub Form_Load()`, `Function GetValue(x As Long) As String`,
/// or `Property Get Name() As String`.
///
/// # Arguments
///
/// * `ftd` - The function type descriptor containing kind, args, return type.
/// * `name` - The method name string.
/// * `map` - Address map for resolving parameter name VAs.
pub fn format_signature(ftd: &FuncTypDesc<'_>, name: &str, map: &AddressMap<'_>) -> String {
    let kind = ftd.kind_keyword();
    let ret = ftd
        .return_type()
        .map(|t| format!(" As {t}"))
        .unwrap_or_default();
    let param_names = ftd.param_names(map);
    let arg_types = ftd.arg_types();
    let args = if param_names.is_empty() && ftd.arg_count() == 0 {
        "()".into()
    } else if param_names.is_empty() && arg_types.is_empty() {
        format!("({} args)", ftd.arg_count())
    } else {
        let count = ftd.arg_count() as usize;
        let params: Vec<String> = (0..count)
            .map(|i| {
                let pname = param_names
                    .get(i)
                    .filter(|n| !n.is_empty())
                    .map(|n| String::from_utf8_lossy(n).into_owned());
                let ptype = arg_types.get(i).map(|t| format!("{t}"));
                match (pname, ptype) {
                    (Some(n), Some(t)) => format!("{n} As {t}"),
                    (Some(n), None) => n,
                    (None, Some(t)) => format!("arg{i} As {t}"),
                    (None, None) => format!("arg{i}"),
                }
            })
            .collect();
        format!("({})", params.join(", "))
    };
    format!("{kind} {name}{args}{ret}")
}

/// A single VB6 object (form, module, class) within the project.
///
/// Provides access to the object's descriptor, info, optional info,
/// and private object descriptor (which contains function type
/// descriptors and parameter name tables).
///
/// Holds a reference to the parent [`VbProject`] so all accessor methods
/// can resolve VAs without requiring the project as a parameter.
#[derive(Debug)]
pub struct VbObject<'a, 'p> {
    /// Reference to the parent project for VA resolution.
    project: &'p VbProject<'a>,
    /// Public object descriptor (0x30-byte entry in the ObjectTable array).
    descriptor: PublicObjectDescriptor<'a>,
    /// Core object info with method table and constants VAs.
    info: ObjectInfo<'a>,
    /// Extended info (controls, P-Code counts); `None` when not flagged.
    optional_info: Option<OptionalObjectInfo<'a>>,
    /// Private descriptor with function types and param names; `None` for
    /// standard modules or when the VA is null/`0xFFFFFFFF`.
    private_object: Option<PrivateObjectDescriptor<'a>>,
}

impl<'a, 'p: 'a> VbObject<'a, 'p> {
    /// Parses a VbObject by index from the object array.
    ///
    /// Resolves the `PublicObjectDescriptor` at position `index`, then
    /// follows pointers to `ObjectInfo`, `OptionalObjectInfo`, and
    /// `PrivateObjectDescriptor`.
    ///
    /// # Arguments
    ///
    /// * `project` - The parent VB6 project.
    /// * `index` - Zero-based index into the object array.
    ///
    /// # Errors
    ///
    /// Returns an error if `index >= total_objects` or if any VA in
    /// the descriptor chain cannot be resolved.
    pub fn parse(project: &'p VbProject<'a>, index: u16) -> Result<Self, Error> {
        let map = project.address_map();
        let ot = project.object_table();
        if index >= ot.total_objects() {
            return Err(Error::ObjectIndexOutOfRange {
                index,
                total: ot.total_objects(),
            });
        }

        // Each PublicObjectDescriptor is 0x30 bytes, starting at object_array_va
        let array_offset = index as usize * PublicObjectDescriptor::SIZE;
        let desc_data = map.slice_from_va(
            ot.object_array_va().wrapping_add(array_offset as u32),
            PublicObjectDescriptor::SIZE,
        )?;
        let descriptor = PublicObjectDescriptor::parse(desc_data)?;

        // Follow descriptor -> ObjectInfo
        let info_data = map.slice_from_va(descriptor.object_info_va(), ObjectInfo::SIZE)?;
        let info = ObjectInfo::parse(info_data)?;

        // OptionalObjectInfo (0x40 bytes) sits between ObjectInfo and the
        // constants table when there is room. For standard modules, the
        // constants table starts immediately after ObjectInfo (gap == 0)
        // and no OptionalObjectInfo exists — regardless of the flag bit.
        let optional_info = if descriptor.has_optional_info() {
            let opt_va = descriptor.object_info_va() + ObjectInfo::SIZE as u32;
            let constants_va = info.constants_va();
            // Only parse if there is a full 0x40-byte gap before the constants
            let has_room =
                constants_va == 0 || constants_va >= opt_va + OptionalObjectInfo::SIZE as u32;
            if has_room {
                map.slice_from_va(opt_va, OptionalObjectInfo::SIZE)
                    .ok()
                    .and_then(|d| OptionalObjectInfo::parse(d).ok())
            } else {
                None
            }
        } else {
            None
        };

        // PrivateObjectDescriptor at ObjectInfo.private_object_va
        let priv_va = info.private_object_va();
        let private_object = if priv_va != 0 && priv_va != 0xFFFFFFFF {
            map.slice_from_va(priv_va, PrivateObjectDescriptor::SIZE)
                .ok()
                .and_then(|d| PrivateObjectDescriptor::parse(d).ok())
        } else {
            None
        };

        Ok(Self {
            project,
            descriptor,
            info,
            optional_info,
            private_object,
        })
    }

    /// Returns a reference to the parent [`VbProject`].
    #[inline]
    pub fn project(&self) -> &'p VbProject<'a> {
        self.project
    }

    /// Returns the [`PublicObjectDescriptor`] for this object.
    #[inline]
    pub fn descriptor(&self) -> &PublicObjectDescriptor<'a> {
        &self.descriptor
    }

    /// Returns the [`ObjectInfo`] for this object.
    #[inline]
    pub fn info(&self) -> &ObjectInfo<'a> {
        &self.info
    }

    /// Returns the [`OptionalObjectInfo`] if present.
    #[inline]
    pub fn optional_info(&self) -> Option<&OptionalObjectInfo<'a>> {
        self.optional_info.as_ref()
    }

    /// Returns the [`PrivateObjectDescriptor`] if present.
    ///
    /// Contains function type descriptors, parameter name tables, and
    /// public function/variable counts. Not available for standard modules
    /// (BAS files) — those have `private_object_va == 0xFFFFFFFF`.
    #[inline]
    pub fn private_object(&self) -> Option<&PrivateObjectDescriptor<'a>> {
        self.private_object.as_ref()
    }

    /// Number of public functions declared in this object.
    ///
    /// Derived from [`PrivateObjectDescriptor::func_count`]. Returns 0
    /// if no private object descriptor is available.
    #[inline]
    pub fn public_func_count(&self) -> u32 {
        self.private_object
            .as_ref()
            .map_or(0, |p| p.func_count() as u32)
    }

    /// Number of public variables declared in this object.
    ///
    /// Derived from [`PrivateObjectDescriptor::var_count`]. Returns 0
    /// if no private object descriptor is available.
    #[inline]
    pub fn public_var_count(&self) -> u32 {
        self.private_object
            .as_ref()
            .map_or(0, |p| p.var_count() as u32)
    }

    /// Reads the object name by resolving the name VA.
    ///
    /// # Errors
    ///
    /// Returns an error if the name VA cannot be resolved.
    pub fn name(&self) -> Result<&'a [u8], Error> {
        self.project
            .read_string_at_va(self.descriptor.object_name_va())
    }

    /// Classifies the object kind based on type flags.
    ///
    /// Uses the two discriminating bits in `fObjectType` (mask `0x82`):
    /// - `0x82` (both `IS_VISUAL` and `HAS_COM_INTERFACE`) → `"Form"`
    /// - `0x02` (`HAS_COM_INTERFACE` only) → `"Class"`
    /// - `0x00` (neither) → `"Module"`
    ///
    /// Delegates to [`ObjectTypeFlags::kind_name`](crate::vb::flags::ObjectTypeFlags::kind_name).
    pub fn object_kind(&self) -> &'static str {
        ObjectTypeFlags(self.descriptor.object_type_raw()).kind_name()
    }

    /// Reads the name of the method at `index` from the method names table.
    ///
    /// Returns a [`MethodNameResult`] that distinguishes:
    /// - `NoTable`: the object has no method names table (`method_names_va == 0`)
    /// - `Unnamed`: this specific method has no name (entry VA is null)
    /// - `Name(&[u8])`: the resolved name bytes
    pub fn method_name(&self, index: u16) -> Result<MethodNameResult<'a>, Error> {
        let names_va = self.descriptor.method_names_va();
        if names_va == 0 {
            return Ok(MethodNameResult::NoTable);
        }
        let entry_va = names_va.wrapping_add(index as u32 * 4);
        let entry_data = self.project.address_map().slice_from_va(entry_va, 4)?;
        let name_va = read_u32_le(entry_data, 0);
        if name_va == 0 {
            return Ok(MethodNameResult::Unnamed);
        }
        self.project
            .read_string_at_va(name_va)
            .map(MethodNameResult::Name)
    }

    /// Returns the number of methods in this object.
    ///
    /// Uses the larger of `ObjectInfo.method_count()` and
    /// `PublicObjectDescriptor.method_count()` — they can differ in
    /// native-compiled binaries where the ObjectInfo count may undercount.
    #[inline]
    pub fn method_count(&self) -> u16 {
        let info_count = self.info.method_count();
        let desc_count = self.descriptor.method_count() as u16;
        info_count.max(desc_count)
    }

    /// Returns the [`ObjectTypeFlags`] for this object.
    #[inline]
    pub fn object_type_flags(&self) -> ObjectTypeFlags {
        ObjectTypeFlags(self.descriptor.object_type_raw())
    }

    /// Returns `true` if this object has P-Code methods.
    pub fn has_pcode(&self) -> bool {
        self.optional_info
            .as_ref()
            .is_some_and(|opt| opt.pcode_count() > 0)
    }

    /// Returns the number of controls on this object (forms only).
    ///
    /// Returns 0 if no optional info is present.
    #[inline]
    pub fn control_count(&self) -> u32 {
        self.optional_info
            .as_ref()
            .map_or(0, |opt| opt.control_count())
    }

    /// Returns an iterator over controls on this object.
    ///
    /// Controls are GUI elements (buttons, textboxes, etc.) on VB6 forms.
    /// Returns an empty iterator if the object has no optional info or
    /// no controls.
    pub fn controls(&self) -> ControlEntryIterator<'a, 'p> {
        let (controls_va, count) = self
            .optional_info
            .as_ref()
            .filter(|opt| opt.control_count() > 0 && opt.controls_va() != 0)
            .map_or((0, 0), |opt| (opt.controls_va(), opt.control_count()));

        ControlEntryIterator::new(self.project.address_map(), controls_va, count)
    }

    /// Returns an iterator over controls enriched with form binary data types.
    ///
    /// Like [`controls`](Self::controls), but each yielded control has its
    /// [`form_control_type`](crate::project::VbControl::form_control_type) populated from the
    /// form binary data `cType` byte — the **authoritative** control type.
    ///
    /// Use this when form data is available (parsed from
    /// [`GuiTableEntry::form_data_va`](crate::vb::guitable::GuiTableEntry::form_data_va)).
    pub fn controls_with_form_data(
        &self,
        form_data: &'p FormDataParser<'a>,
    ) -> ControlEntryIterator<'a, 'p> {
        self.controls().with_form_data(form_data)
    }

    /// Returns an iterator over method link thunks for native-compiled classes.
    ///
    /// The method link table contains JMP thunks that bridge COM vtable
    /// dispatch to the actual native method implementations. Each thunk is
    /// a `jmp <native_code_body>` instruction followed by a `this` pointer
    /// adjustment.
    ///
    /// This is the primary way to discover native method bodies in
    /// native-compiled VB6 classes where `ObjectInfo.methods_va` points
    /// into MSVBVM60.DLL (runtime-patched vtable) rather than PE code.
    ///
    /// Returns an empty iterator if no method link table exists.
    pub fn method_links(&self) -> MethodLinkIterator<'a, 'p> {
        let (table_va, count) = self
            .optional_info
            .as_ref()
            .filter(|opt| opt.method_link_count() > 0 && opt.method_link_table_va() != 0)
            .map_or((0, 0), |opt| {
                (opt.method_link_table_va(), opt.method_link_count() as u32)
            });

        MethodLinkIterator::new(self.project.address_map(), table_va, count)
    }

    /// Returns `true` if this object has a real method dispatch table.
    ///
    /// When `methods_va == constants_va`, the "method table" is actually
    /// the constants/variable pool and should not be iterated as methods.
    pub fn has_method_table(&self) -> bool {
        let m = self.info.methods_va();
        let c = self.info.constants_va();
        m != 0 && m != c
    }

    /// Returns an iterator over all method table entries, classified by type.
    ///
    /// Each entry is classified as [`MethodEntry::Null`], [`MethodEntry::PCode`],
    /// [`MethodEntry::Native`], or [`MethodEntry::Runtime`]. This is the full
    /// view of the dispatch table — use [`pcode_methods`](Self::pcode_methods)
    /// if you only want P-Code methods.
    ///
    /// Returns an empty iterator if the object has no method table (e.g.,
    /// modules that only declare public variables).
    pub fn methods(&self) -> MethodIterator<'a, 'p> {
        let total = if self.has_method_table() {
            self.method_count()
        } else {
            0
        };
        MethodIterator {
            map: self.project.address_map(),
            methods_va: self.info.methods_va(),
            index: 0,
            total,
        }
    }

    /// Returns an iterator over P-Code methods in this object.
    ///
    /// Non-P-Code entries (null, native, runtime) are silently skipped.
    /// Use [`methods`](Self::methods) to see all entries with classification.
    pub fn pcode_methods(&self) -> PCodeMethodIterator<'a, 'p> {
        let total = if self.has_method_table() {
            self.method_count()
        } else {
            0
        };
        PCodeMethodIterator {
            map: self.project.address_map(),
            methods_va: self.info.methods_va(),
            index: 0,
            total,
        }
    }

    /// Parses the [`ClassFormPublicBytes`] for this object (classes and forms only).
    ///
    /// Returns `None` for standard modules (use
    /// [`PublicVarTable`](crate::vb::publicbytes::PublicVarTable) instead)
    /// or when the public bytes VA is null.
    pub fn class_form_public_bytes(&self) -> Option<ClassFormPublicBytes<'a>> {
        if self.object_type_flags().is_module() {
            return None;
        }
        let pb_va = self.descriptor.public_bytes_va();
        if pb_va == 0 {
            return None;
        }
        // Read enough for header + potential entries
        let data = self.project.address_map().slice_from_va(pb_va, 0x80).ok()?;
        ClassFormPublicBytes::parse(data).ok()
    }

    /// Parses the [`PublicVarTable`] for this object (modules only).
    ///
    /// Returns `None` for classes/forms (use
    /// [`class_form_public_bytes`](Self::class_form_public_bytes) instead)
    /// or when the public bytes VA is null.
    pub fn public_var_table(&self) -> Option<PublicVarTable<'a>> {
        if !self.object_type_flags().is_module() {
            return None;
        }
        let pb_va = self.descriptor.public_bytes_va();
        if pb_va == 0 {
            return None;
        }
        let map = self.project.address_map();
        // Read header first to get total size
        let header = map.slice_from_va(pb_va, PublicVarTable::HEADER_SIZE).ok()?;
        let pvt_header = PublicVarTable::parse(header).ok()?;
        let full_size = pvt_header.total_size() as usize;
        if full_size <= PublicVarTable::HEADER_SIZE {
            return Some(pvt_header);
        }
        let full_data = map.slice_from_va(pb_va, full_size).ok()?;
        PublicVarTable::parse(full_data).ok()
    }

    /// Returns all code entry points in this object.
    ///
    /// Combines three sources into a single `Vec`:
    /// 1. **Method table** — P-Code and native methods from the dispatch table
    /// 2. **Method link thunks** — native code bodies discovered via JMP thunks
    /// 3. **Event handlers** — connected event sink handler VAs from controls
    ///
    /// Each entry includes a code VA and a human-readable label. Null entries
    /// and runtime VAs (pointing into MSVBVM60.DLL) are excluded.
    /// # Name Resolution
    ///
    /// Names are resolved using a three-tier fallback:
    /// 1. Method name table (`method_name()`) — from PublicObjectDescriptor
    /// 2. FuncTypDesc signature — from PrivateObjectDescriptor's type info
    /// 3. Positional fallback — `method_NN` for methods, `Control_EventName` for events
    ///
    /// When `form_data` is provided, event handler names use the exact
    /// `FormControlType` from the form binary (e.g., `Timer1_Timer` instead
    /// of `Timer1_Event00`). Without it, falls back to GUID-based class
    /// name lookup which is less reliable.
    pub fn code_entries(&self, form_data: Option<&FormDataParser<'a>>) -> Vec<CodeEntry> {
        let mut entries = Vec::new();
        let map = self.project.address_map();

        // Build FuncTypDesc map for name fallback
        let ftd_map = self.build_func_type_desc_map();

        // 1. Method table entries
        if self.has_method_table() {
            for (i, result) in self.methods().enumerate() {
                match result {
                    Ok(MethodEntry::PCode(pm)) => {
                        let name = self.resolve_method_name(i, &ftd_map);
                        entries.push(CodeEntry {
                            va: pm.pcode_va(),
                            kind: CodeEntryKind::PCode,
                            method_index: Some(i as u16),
                            name,
                            data_const_va: Some(pm.data_const_va()),
                            stub_va: Some(pm.stub_va()),
                            pcode_size: Some(pm.proc_size()),
                        });
                    }
                    Ok(MethodEntry::Native { va }) => {
                        let name = self.resolve_method_name(i, &ftd_map);
                        entries.push(CodeEntry {
                            va,
                            kind: CodeEntryKind::Native,
                            method_index: Some(i as u16),
                            name,
                            data_const_va: None,
                            stub_va: None,
                            pcode_size: None,
                        });
                    }
                    _ => {}
                }
            }
        }

        // 2. Method link thunks (may discover natives not in method table)
        for (link_idx, result) in self.method_links().enumerate() {
            if let Ok(link) = result {
                // Skip if we already have this VA from the method table
                if !entries.iter().any(|e| e.va == link.code_va) {
                    // Try to inherit name from the method table at the same index
                    let name = self.resolve_method_name(link_idx, &ftd_map);
                    entries.push(CodeEntry {
                        va: link.code_va,
                        kind: CodeEntryKind::NativeThunk,
                        method_index: Some(link_idx as u16),
                        name,
                        data_const_va: None,
                        stub_va: None,
                        pcode_size: None,
                    });
                }
            }
        }

        // 3. Event handler VAs from control event sinks
        let controls: Vec<_> = if let Some(fd) = form_data {
            self.controls_with_form_data(fd)
                .filter_map(|r| r.ok())
                .collect()
        } else {
            self.controls().filter_map(|r| r.ok()).collect()
        };

        for ctrl in &controls {
            let ctrl_name_lossy = String::from_utf8_lossy(ctrl.name());
            let ctrl_name = ctrl_name_lossy.as_ref();
            // Resolve FormControlType: prefer form binary data, fall back to GUID class name
            let ctrl_type = ctrl
                .form_control_type()
                .or_else(|| ctrl.class_name().and_then(FormControlType::from_class_name));
            for slot in 0..ctrl.event_count() {
                if let Some(handler_va) = ctrl.event_handler_va(slot)
                    && handler_va != 0
                    && map.va_to_offset(handler_va).is_ok()
                {
                    // Resolve event name: typed template → standard template → Event{NN}
                    let event_name = ctrl_type
                        .and_then(|ct| eventname::event_name(slot, ct))
                        .or_else(|| eventname::standard_event_name(slot));
                    let label = match event_name {
                        Some(en) => format!("{ctrl_name}_{en}"),
                        None => format!("{ctrl_name}_Event{slot:02}"),
                    };
                    if !entries.iter().any(|e| e.va == handler_va) {
                        entries.push(CodeEntry {
                            va: handler_va,
                            kind: CodeEntryKind::EventHandler,
                            method_index: None,
                            name: Some(label),
                            data_const_va: None,
                            stub_va: None,
                            pcode_size: None,
                        });
                    }
                }
            }
        }

        entries
    }

    /// Resolves a method name using three-tier fallback:
    /// 1. Method name table
    /// 2. FuncTypDesc function name
    /// 3. None (caller can format as `method_NN`)
    fn resolve_method_name(
        &self,
        index: usize,
        ftd_map: &[(usize, FuncTypDesc<'a>)],
    ) -> Option<String> {
        // Tier 1: method name table
        if let Ok(result) = self.method_name(index as u16)
            && let MethodNameResult::Name(n) = result
            && let Ok(s) = str::from_utf8(n)
        {
            return Some(s.to_string());
        }

        // Tier 2: FuncTypDesc signature
        for &(fi, ref ftd) in ftd_map {
            if fi == index {
                let name = format_signature(ftd, "", self.project.address_map());
                // format_signature returns " ()" for empty name — strip prefix space
                let trimmed = name.trim();
                if !trimmed.is_empty() && trimmed != "()" {
                    return Some(trimmed.to_string());
                }
            }
        }

        None
    }

    /// Builds a Vec of (index, FuncTypDesc) pairs from the PrivateObjectDescriptor.
    fn build_func_type_desc_map(&self) -> Vec<(usize, FuncTypDesc<'a>)> {
        let Some(priv_obj) = self.private_object() else {
            return Vec::new();
        };
        let ftd_array_va = priv_obj.func_type_descs_va();
        if ftd_array_va == 0 {
            return Vec::new();
        }
        let total = priv_obj.func_count() as u32 + priv_obj.var_count() as u32;
        let map = self.project.address_map();
        let mut result = Vec::new();

        for i in 0..total {
            let ptr_va = ftd_array_va.wrapping_add(i * 4);
            let Ok(ptr_data) = map.slice_from_va(ptr_va, 4) else {
                continue;
            };
            let desc_va = u32::from_le_bytes([ptr_data[0], ptr_data[1], ptr_data[2], ptr_data[3]]);
            if desc_va == 0 {
                continue;
            }
            let Ok(desc_data) = map.slice_from_va(desc_va, 0x40) else {
                continue;
            };
            if let Ok(ftd) = FuncTypDesc::parse_extended(desc_data) {
                result.push((i as usize, ftd));
            }
        }
        result
    }

    /// Parses the form binary data for this object (forms with GUI data only).
    ///
    /// Requires a [`GuiTableEntry`](crate::vb::guitable::GuiTableEntry) that
    /// maps to this form. Returns `None` if the entry has no form data.
    pub fn form_data_from_gui_entry(
        &self,
        gui_entry: &GuiTableEntry<'a>,
    ) -> Option<FormDataParser<'a>> {
        let va = gui_entry.form_data_va();
        let size = gui_entry.form_data_size() as usize;
        if va == 0 || size == 0 {
            return None;
        }
        let data = self.project.address_map().slice_from_va(va, size).ok()?;
        FormDataParser::parse(data).ok()
    }

    /// Returns a [`ConstantPool`] reader for this object's constants.
    ///
    /// The pool base VA comes from [`ObjectInfo::constants_va`] and
    /// contains BSTRs, API stubs, GUIDs, and code object references.
    pub fn constants_pool(&self) -> ConstantPool<'a> {
        ConstantPool::new(self.project.address_map(), self.info.constants_va())
    }

    /// Returns the object's COM CLSID, if present.
    ///
    /// Resolves the CLSID from [`OptionalObjectInfo::object_clsid_va`].
    /// Returns `None` for standard modules or objects without a CLSID.
    pub fn object_clsid(&self) -> Option<Guid> {
        self.optional_info
            .as_ref()
            .and_then(|opt| opt.resolve_clsid(self.project.address_map()))
    }

    /// Returns an iterator over GUI GUIDs for this object.
    ///
    /// Delegates to [`OptionalObjectInfo::gui_guids`]. Returns an empty
    /// iterator if no optional info is present.
    pub fn gui_guids(&self) -> GuidTableIter<'_> {
        match self.optional_info.as_ref() {
            Some(opt) => opt.gui_guids(self.project.address_map()),
            None => GuidTableIter::new(self.project.address_map(), 0, 0),
        }
    }

    /// Returns an iterator over default dispatch interface IIDs.
    ///
    /// Delegates to [`OptionalObjectInfo::default_iids`]. Returns an empty
    /// iterator if no optional info is present.
    pub fn default_iids(&self) -> GuidTableIter<'_> {
        match self.optional_info.as_ref() {
            Some(opt) => opt.default_iids(self.project.address_map()),
            None => GuidTableIter::new(self.project.address_map(), 0, 0),
        }
    }

    /// Returns an iterator over event source interface IIDs.
    ///
    /// Delegates to [`OptionalObjectInfo::events_iids`]. Returns an empty
    /// iterator if no optional info is present.
    pub fn events_iids(&self) -> GuidTableIter<'_> {
        match self.optional_info.as_ref() {
            Some(opt) => opt.events_iids(self.project.address_map()),
            None => GuidTableIter::new(self.project.address_map(), 0, 0),
        }
    }

    /// Returns an iterator over [`FuncTypDesc`] entries.
    ///
    /// Walks the pointer array at [`PrivateObjectDescriptor::func_type_descs_va`],
    /// yielding `(index, FuncTypDesc)` pairs. Returns an empty iterator if
    /// no private object descriptor is present.
    pub fn func_type_descs(&self) -> FuncTypDescIter<'a, 'p> {
        let (ftd_va, total) = self
            .private_object
            .as_ref()
            .filter(|p| p.func_type_descs_va() != 0)
            .map_or((0, 0), |p| {
                (
                    p.func_type_descs_va(),
                    p.func_count() as u32 + p.var_count() as u32,
                )
            });
        FuncTypDescIter {
            map: self.project.address_map(),
            ftd_array_va: ftd_va,
            index: 0,
            total,
        }
    }

    /// Returns an iterator over [`VarStubDesc`](crate::vb::varstub::VarStubDesc) entries.
    ///
    /// Walks the pointer array at [`PrivateObjectDescriptor::var_stubs_va`].
    /// Returns an empty iterator if no private object descriptor is present
    /// or if there are no variable stubs.
    pub fn var_stubs(&self) -> VarStubIter<'a> {
        let (stubs_va, count) = self
            .private_object
            .as_ref()
            .filter(|p| p.var_stubs_va() != 0 && p.var_count() > 0)
            .map_or((0, 0), |p| (p.var_stubs_va(), p.var_count()));
        VarStubIter::new(self.project.address_map(), stubs_va, count)
    }
}

/// Iterator over [`FuncTypDesc`] entries from a
/// [`PrivateObjectDescriptor`]'s pointer array.
///
/// Each entry in the array is a 4-byte VA pointing to a `FuncTypDesc`
/// structure. The iterator resolves each VA lazily, yielding
/// `(index, FuncTypDesc)` pairs. Null entries are silently skipped.
///
/// Created by [`VbObject::func_type_descs`].
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct FuncTypDescIter<'a, 'p> {
    map: &'p AddressMap<'a>,
    ftd_array_va: u32,
    index: u32,
    total: u32,
}

impl<'a, 'p> Iterator for FuncTypDescIter<'a, 'p> {
    type Item = (u32, FuncTypDesc<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.total {
            let i = self.index;
            self.index += 1;

            let ptr_va = self.ftd_array_va.wrapping_add(i * 4);
            let ptr_data = self.map.slice_from_va(ptr_va, 4).ok()?;
            let desc_va = u32::from_le_bytes([ptr_data[0], ptr_data[1], ptr_data[2], ptr_data[3]]);
            if desc_va == 0 {
                continue;
            }

            // Read extended data (0x40 bytes to cover arg types at +0x20)
            let desc_data = self.map.slice_from_va(desc_va, 0x40).ok()?;
            if let Ok(ftd) = FuncTypDesc::parse_extended(desc_data) {
                return Some((i, ftd));
            }
        }
        None
    }
}

/// A code entry point discovered in a VB6 object.
///
/// Returned by [`VbObject::code_entries`], which combines method table entries,
/// method link thunks, and event handler VAs into a single list.
#[derive(Debug, Clone)]
pub struct CodeEntry {
    /// Virtual address of the code entry point.
    pub va: u32,
    /// What kind of code entry this is.
    pub kind: CodeEntryKind,
    /// Method table index (if from dispatch table).
    pub method_index: Option<u16>,
    /// Human-readable name (method name or "ControlName_EventName").
    pub name: Option<String>,
    /// Constant pool base VA (`ObjectInfo.lpConstants`).
    /// Present for [`CodeEntryKind::PCode`] entries.
    pub data_const_va: Option<u32>,
    /// VA of the P-Code call stub (`mov edx, <RTMI>; call ProcCallEngine`).
    /// Present for [`CodeEntryKind::PCode`] entries.
    pub stub_va: Option<u32>,
    /// Size of the P-Code byte stream in bytes.
    /// Present for [`CodeEntryKind::PCode`] entries.
    pub pcode_size: Option<u16>,
}

/// Classification of a code entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeEntryKind {
    /// P-Code procedure (bytecode).
    PCode,
    /// Native compiled method (x86 in PE .text section).
    Native,
    /// Native method discovered via method link JMP thunk.
    NativeThunk,
    /// Event handler connected to a control's event sink vtable.
    EventHandler,
}

/// Iterator over all method table entries in a VB6 object, classified by type.
///
/// Each yielded [`MethodEntry`] is classified as null, P-Code, native, or
/// runtime based on the VA at that slot.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct MethodIterator<'a, 'p> {
    /// Address map for VA resolution.
    map: &'p AddressMap<'a>,
    /// Base VA of the method dispatch table.
    methods_va: u32,
    /// Current zero-based slot position.
    index: u16,
    /// Total number of slots in the method table.
    total: u16,
}

impl<'a, 'p> Iterator for MethodIterator<'a, 'p> {
    type Item = Result<MethodEntry<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.total {
            return None;
        }
        let i = self.index;
        self.index += 1;
        Some(MethodEntry::classify(self.map, self.methods_va, i))
    }
}

/// Iterator over P-Code methods in a VB6 object, skipping non-P-Code entries.
///
/// Walks the same method table as [`MethodIterator`] but silently skips
/// null, native, and runtime slots, yielding only [`PCodeMethod`] values.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct PCodeMethodIterator<'a, 'p> {
    /// Address map for VA resolution.
    map: &'p AddressMap<'a>,
    /// Base VA of the method dispatch table.
    methods_va: u32,
    /// Current zero-based slot position.
    index: u16,
    /// Total number of slots in the method table.
    total: u16,
}

impl<'a, 'p> Iterator for PCodeMethodIterator<'a, 'p> {
    type Item = Result<PCodeMethod<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.total {
            let i = self.index;
            self.index += 1;

            // Read the 4-byte VA for this slot
            let entry_va = self.methods_va.wrapping_add(i as u32 * 4);
            let entry_data = match self.map.slice_from_va(entry_va, 4) {
                Ok(d) => d,
                Err(e) => return Some(Err(e)),
            };
            let method_va = read_u32_le(entry_data, 0);

            // Skip null and out-of-image entries
            if method_va == 0 || !self.map.is_va_in_image(method_va) {
                continue;
            }

            // Check for P-Code stub patterns or direct ProcDscInfo pointer
            let stub_data = match self.map.slice_from_va(method_va, 12) {
                Ok(d) => d,
                Err(e) => return Some(Err(e)),
            };
            let is_stub = stub_data[0] == 0xBA
                || (stub_data[0] == 0x33 && stub_data[1] == 0xC0 && stub_data[2] == 0xBA);
            if !is_stub {
                // Check for direct ProcDscInfo pointer
                let maybe_pt =
                    u32::from_le_bytes([stub_data[0], stub_data[1], stub_data[2], stub_data[3]]);
                let maybe_ps = u16::from_le_bytes([stub_data[8], stub_data[9]]);
                if !self.map.is_va_in_image(maybe_pt) || maybe_ps == 0 || maybe_ps >= 0x8000 {
                    continue; // Not P-Code
                }
            }

            return Some(PCodeMethod::parse(self.map, self.methods_va, i));
        }
        None
    }
}
