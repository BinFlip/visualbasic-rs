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

use std::{borrow::Cow, str};

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

    /// Returns the name as a lossy UTF-8 string if available, or `None`
    /// for `NoTable`/`Unnamed`.
    ///
    /// Borrows when the underlying bytes are already valid UTF-8 (the
    /// common case for ASCII identifier names).
    pub fn as_str(&self) -> Option<Cow<'a, str>> {
        self.as_bytes().map(String::from_utf8_lossy)
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
        if index >= ot.total_objects()? {
            return Err(Error::ObjectIndexOutOfRange {
                index,
                total: ot.total_objects()?,
            });
        }

        // Each PublicObjectDescriptor is 0x30 bytes, starting at object_array_va
        let array_offset = u32::from(index).saturating_mul(PublicObjectDescriptor::SIZE as u32);
        let desc_data = map.slice_from_va(
            ot.object_array_va()?.wrapping_add(array_offset),
            PublicObjectDescriptor::SIZE,
        )?;
        let descriptor = PublicObjectDescriptor::parse(desc_data)?;

        // Follow descriptor -> ObjectInfo
        let info_data = map.slice_from_va(descriptor.object_info_va()?, ObjectInfo::SIZE)?;
        let info = ObjectInfo::parse(info_data)?;

        // OptionalObjectInfo (0x40 bytes) sits between ObjectInfo and the
        // constants table when there is room. For standard modules, the
        // constants table starts immediately after ObjectInfo (gap == 0)
        // and no OptionalObjectInfo exists — regardless of the flag bit.
        let optional_info = if descriptor.has_optional_info() {
            let opt_va = descriptor
                .object_info_va()?
                .wrapping_add(ObjectInfo::SIZE as u32);
            let constants_va = info.constants_va()?;
            // Only parse if there is a full 0x40-byte gap before the constants
            let has_room = constants_va == 0
                || constants_va >= opt_va.wrapping_add(OptionalObjectInfo::SIZE as u32);
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
        let priv_va = info.private_object_va()?;
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
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PrivateObjectDescriptor field
    /// cannot be read.
    #[inline]
    pub fn public_func_count(&self) -> Result<u32, Error> {
        match self.private_object.as_ref() {
            Some(p) => Ok(u32::from(p.func_count()?)),
            None => Ok(0),
        }
    }

    /// Number of public variables declared in this object.
    ///
    /// Derived from [`PrivateObjectDescriptor::var_count`]. Returns 0
    /// if no private object descriptor is available.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying PrivateObjectDescriptor field
    /// cannot be read.
    #[inline]
    pub fn public_var_count(&self) -> Result<u32, Error> {
        match self.private_object.as_ref() {
            Some(p) => Ok(u32::from(p.var_count()?)),
            None => Ok(0),
        }
    }

    /// Reads the object name as a lossy UTF-8 string.
    ///
    /// Borrows when the underlying bytes are already valid UTF-8 (the
    /// common case for ASCII identifier names) and allocates only when
    /// invalid sequences need U+FFFD substitution. Use
    /// [`name_bytes`](Self::name_bytes) when you need the raw bytes
    /// (e.g., for byte-exact comparison or hex display of malformed
    /// names).
    ///
    /// # Errors
    ///
    /// Returns an error if the name VA cannot be resolved.
    pub fn name(&self) -> Result<Cow<'a, str>, Error> {
        Ok(String::from_utf8_lossy(self.name_bytes()?))
    }

    /// Reads the object name as raw bytes from the PE image.
    ///
    /// Returns the slice exactly as stored — no decoding, no fallback.
    /// Prefer [`name`](Self::name) for display.
    ///
    /// # Errors
    ///
    /// Returns an error if the name VA cannot be resolved.
    pub fn name_bytes(&self) -> Result<&'a [u8], Error> {
        self.project
            .read_string_at_va(self.descriptor.object_name_va()?)
    }

    /// Classifies the object kind based on type flags.
    ///
    /// Uses the two discriminating bits in `fObjectType` (mask `0x82`):
    /// - `0x82` (both `IS_VISUAL` and `HAS_COM_INTERFACE`) → `"Form"`
    /// - `0x02` (`HAS_COM_INTERFACE` only) → `"Class"`
    /// - `0x00` (neither) → `"Module"`
    ///
    /// Delegates to [`ObjectTypeFlags::kind_name`](crate::vb::flags::ObjectTypeFlags::kind_name).
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor's `object_type_raw` field cannot
    /// be read.
    pub fn object_kind(&self) -> Result<&'static str, Error> {
        Ok(ObjectTypeFlags(self.descriptor.object_type_raw()?).kind_name())
    }

    /// Reads the name of the method at `index` from the method names table.
    ///
    /// Returns a [`MethodNameResult`] that distinguishes:
    /// - `NoTable`: the object has no method names table (`method_names_va == 0`)
    /// - `Unnamed`: this specific method has no name (entry VA is null)
    /// - `Name(&[u8])`: the resolved name bytes
    pub fn method_name(&self, index: u16) -> Result<MethodNameResult<'a>, Error> {
        let names_va = self.descriptor.method_names_va()?;
        if names_va == 0 {
            return Ok(MethodNameResult::NoTable);
        }
        let entry_va = names_va.wrapping_add(u32::from(index).saturating_mul(4));
        let entry_data = self.project.address_map().slice_from_va(entry_va, 4)?;
        let name_va = read_u32_le(entry_data, 0)?;
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
    ///
    /// # Errors
    ///
    /// Returns an error if either underlying method count cannot be read.
    #[inline]
    pub fn method_count(&self) -> Result<u16, Error> {
        let info_count = self.info.method_count()?;
        let desc_count = self.descriptor.method_count()? as u16;
        Ok(info_count.max(desc_count))
    }

    /// Returns the [`ObjectTypeFlags`] for this object.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor's `object_type_raw` field cannot
    /// be read.
    #[inline]
    pub fn object_type_flags(&self) -> Result<ObjectTypeFlags, Error> {
        Ok(ObjectTypeFlags(self.descriptor.object_type_raw()?))
    }

    /// Returns `true` if this object has P-Code methods.
    ///
    /// # Errors
    ///
    /// Returns an error if the optional info's `pcode_count` cannot be read.
    pub fn has_pcode(&self) -> Result<bool, Error> {
        match self.optional_info.as_ref() {
            Some(opt) => Ok(opt.pcode_count()? > 0),
            None => Ok(false),
        }
    }

    /// Returns the number of controls on this object (forms only).
    ///
    /// Returns 0 if no optional info is present.
    ///
    /// # Errors
    ///
    /// Returns an error if the optional info's `control_count` cannot be read.
    #[inline]
    pub fn control_count(&self) -> Result<u32, Error> {
        match self.optional_info.as_ref() {
            Some(opt) => opt.control_count(),
            None => Ok(0),
        }
    }

    /// Returns an iterator over controls on this object.
    ///
    /// Controls are GUI elements (buttons, textboxes, etc.) on VB6 forms.
    /// Returns an empty iterator if the object has no optional info or
    /// no controls.
    ///
    /// # Errors
    ///
    /// Returns an error if the optional info's control count or VA fields
    /// cannot be read.
    pub fn controls(&self) -> Result<ControlEntryIterator<'a, 'p>, Error> {
        let (controls_va, count) = match self.optional_info.as_ref() {
            Some(opt) => {
                let cc = opt.control_count()?;
                let cv = opt.controls_va()?;
                if cc > 0 && cv != 0 { (cv, cc) } else { (0, 0) }
            }
            None => (0, 0),
        };

        Ok(ControlEntryIterator::new(
            self.project.address_map(),
            controls_va,
            count,
        ))
    }

    /// Returns an iterator over controls enriched with form binary data types.
    ///
    /// Like [`controls`](Self::controls), but each yielded control has its
    /// [`form_control_type`](crate::project::VbControl::form_control_type) populated from the
    /// form binary data `cType` byte — the **authoritative** control type.
    ///
    /// Use this when form data is available (parsed from
    /// [`GuiTableEntry::form_data_va`](crate::vb::guitable::GuiTableEntry::form_data_va)).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying control table fields cannot be read.
    pub fn controls_with_form_data(
        &self,
        form_data: &'p FormDataParser<'a>,
    ) -> Result<ControlEntryIterator<'a, 'p>, Error> {
        Ok(self.controls()?.with_form_data(form_data))
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
    ///
    /// # Errors
    ///
    /// Returns an error if the method link count or table VA cannot be read.
    pub fn method_links(&self) -> Result<MethodLinkIterator<'a, 'p>, Error> {
        let (table_va, count) = match self.optional_info.as_ref() {
            Some(opt) => {
                let mlc = opt.method_link_count()?;
                let mlv = opt.method_link_table_va()?;
                if mlc > 0 && mlv != 0 {
                    (mlv, u32::from(mlc))
                } else {
                    (0, 0)
                }
            }
            None => (0, 0),
        };

        Ok(MethodLinkIterator::new(
            self.project.address_map(),
            table_va,
            count,
        ))
    }

    /// Returns `true` if this object has a real method dispatch table.
    ///
    /// When `methods_va == constants_va`, the "method table" is actually
    /// the constants/variable pool and should not be iterated as methods.
    ///
    /// # Errors
    ///
    /// Returns an error if the methods or constants VA cannot be read.
    pub fn has_method_table(&self) -> Result<bool, Error> {
        let m = self.info.methods_va()?;
        let c = self.info.constants_va()?;
        Ok(m != 0 && m != c)
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
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying method/constants VAs or method
    /// counts cannot be read.
    pub fn methods(&self) -> Result<MethodIterator<'a, 'p>, Error> {
        let total = if self.has_method_table()? {
            self.method_count()?
        } else {
            0
        };
        Ok(MethodIterator {
            map: self.project.address_map(),
            methods_va: self.info.methods_va()?,
            index: 0,
            total,
        })
    }

    /// Returns an iterator over P-Code methods in this object.
    ///
    /// Non-P-Code entries (null, native, runtime) are silently skipped.
    /// Use [`methods`](Self::methods) to see all entries with classification.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying method/constants VAs or method
    /// counts cannot be read.
    pub fn pcode_methods(&self) -> Result<PCodeMethodIterator<'a, 'p>, Error> {
        let total = if self.has_method_table()? {
            self.method_count()?
        } else {
            0
        };
        Ok(PCodeMethodIterator {
            map: self.project.address_map(),
            methods_va: self.info.methods_va()?,
            index: 0,
            total,
        })
    }

    /// Parses the [`ClassFormPublicBytes`] for this object (classes and forms only).
    ///
    /// Returns `None` for standard modules (use
    /// [`PublicVarTable`](crate::vb::publicbytes::PublicVarTable) instead)
    /// or when the public bytes VA is null or any backing field cannot be read.
    pub fn class_form_public_bytes(&self) -> Option<ClassFormPublicBytes<'a>> {
        if self.object_type_flags().ok()?.is_module() {
            return None;
        }
        let pb_va = self.descriptor.public_bytes_va().ok()?;
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
    /// or when the public bytes VA is null or any backing field cannot be read.
    pub fn public_var_table(&self) -> Option<PublicVarTable<'a>> {
        if !self.object_type_flags().ok()?.is_module() {
            return None;
        }
        let pb_va = self.descriptor.public_bytes_va().ok()?;
        if pb_va == 0 {
            return None;
        }
        let map = self.project.address_map();
        // Read header first to get total size
        let header = map.slice_from_va(pb_va, PublicVarTable::HEADER_SIZE).ok()?;
        let pvt_header = PublicVarTable::parse(header).ok()?;
        let full_size = pvt_header.total_size().ok()? as usize;
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
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying method table, method link table,
    /// control table, or any control name VA cannot be read.
    pub fn code_entries(
        &self,
        form_data: Option<&FormDataParser<'a>>,
    ) -> Result<Vec<CodeEntry>, Error> {
        let mut entries = Vec::new();
        let map = self.project.address_map();

        // Build FuncTypDesc map for name fallback
        let ftd_map = self.build_func_type_desc_map()?;

        // 1. Method table entries
        if self.has_method_table()? {
            for (i, result) in self.methods()?.enumerate() {
                match result? {
                    MethodEntry::PCode(pm) => {
                        let name = self.resolve_method_name(i, &ftd_map);
                        entries.push(CodeEntry {
                            va: pm.pcode_va(),
                            kind: CodeEntryKind::PCode,
                            method_index: Some(i as u16),
                            name,
                            data_const_va: Some(pm.data_const_va()),
                            stub_va: Some(pm.stub_va()),
                            pcode_size: Some(pm.proc_size()?),
                        });
                    }
                    MethodEntry::Native { va } => {
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
        for (link_idx, result) in self.method_links()?.enumerate() {
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

        // 3. Event handler VAs from control event sinks. Bad control rows
        //    are silently skipped (fail-soft); under the `tracing` feature
        //    each drop emits a `visualbasic::dropped` warn event.
        let controls: Vec<_> = if let Some(fd) = form_data {
            self.controls_with_form_data(fd)?
                .filter_map(|r| match r {
                    Ok(c) => Some(c),
                    Err(e) => {
                        crate::trace::warn_drop!("code_entries.controls_with_form_data", error = ?e);
                        None
                    }
                })
                .collect()
        } else {
            self.controls()?
                .filter_map(|r| match r {
                    Ok(c) => Some(c),
                    Err(e) => {
                        crate::trace::warn_drop!("code_entries.controls", error = ?e);
                        None
                    }
                })
                .collect()
        };

        for ctrl in &controls {
            let ctrl_name_cow = ctrl.name();
            let ctrl_name = ctrl_name_cow.as_ref();
            // Resolve FormControlType: prefer form binary data, fall back to GUID class name
            let ctrl_type = ctrl
                .form_control_type()
                .or_else(|| ctrl.class_name().and_then(FormControlType::from_class_name));
            for slot in 0..ctrl.event_count()? {
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

        Ok(entries)
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
    fn build_func_type_desc_map(&self) -> Result<Vec<(usize, FuncTypDesc<'a>)>, Error> {
        let Some(priv_obj) = self.private_object() else {
            return Ok(Vec::new());
        };
        let ftd_array_va = priv_obj.func_type_descs_va()?;
        if ftd_array_va == 0 {
            return Ok(Vec::new());
        }
        let total =
            u32::from(priv_obj.func_count()?).saturating_add(u32::from(priv_obj.var_count()?));
        let map = self.project.address_map();
        let mut result = Vec::new();

        for i in 0..total {
            let ptr_va = ftd_array_va.wrapping_add(i.saturating_mul(4));
            let Ok(ptr_data) = map.slice_from_va(ptr_va, 4) else {
                continue;
            };
            let Some(ptr_bytes) = ptr_data.get(..4).and_then(|s| <[u8; 4]>::try_from(s).ok())
            else {
                continue;
            };
            let desc_va = u32::from_le_bytes(ptr_bytes);
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
        Ok(result)
    }

    /// Parses the form binary data for this object (forms with GUI data only).
    ///
    /// Requires a [`GuiTableEntry`](crate::vb::guitable::GuiTableEntry) that
    /// maps to this form. Returns `None` if the entry has no form data.
    pub fn form_data_from_gui_entry(
        &self,
        gui_entry: &GuiTableEntry<'a>,
    ) -> Option<FormDataParser<'a>> {
        let va = gui_entry.form_data_va().ok()?;
        let size = gui_entry.form_data_size().ok()? as usize;
        if va == 0 || size == 0 {
            return None;
        }
        let data = self.project.address_map().slice_from_va(va, size).ok()?;
        FormDataParser::parse(data).ok()
    }

    /// Returns all connected event-handler bindings on this object.
    ///
    /// Walks every control on the form, joins each event sink slot with
    /// the per-control-type event-name template, and yields one
    /// [`EventBinding`] per slot whose `handler_va` is non-zero.
    ///
    /// When `form_data` is provided, the authoritative `cType` byte from
    /// the form binary drives [`FormControlType`] resolution (e.g.,
    /// `Timer` → slot 0 = `"Timer"`, not the default `"Click"`).
    /// Without it, falls back to GUID-based class-name lookup, which
    /// is unreliable for malware samples (8/12 controls misidentified
    /// in the vb_inject sample).
    ///
    /// Returns an empty `Vec` for objects with no controls (modules,
    /// classes without GUI). The order of the returned bindings is:
    /// outer = control order from [`controls`](Self::controls), inner =
    /// ascending event slot index.
    ///
    /// # Errors
    ///
    /// Returns an error if the controls iterator or any control's
    /// [`event_count`](crate::project::VbControl::event_count) cannot
    /// be read.
    pub fn events(
        &self,
        form_data: Option<&'p FormDataParser<'a>>,
    ) -> Result<Vec<EventBinding<'a>>, Error> {
        self.events_inner(form_data, /* connected_only */ true)
    }

    /// Returns every event-handler slot on this object, including
    /// disconnected ones (`handler_va == 0`).
    ///
    /// Like [`events`](Self::events) but does not filter out empty slots
    /// — useful for completeness checks ("how many of this control's
    /// 24 events are wired up?") or for surfacing the full slot
    /// template per control type.
    ///
    /// # Errors
    ///
    /// Returns an error if the controls iterator or any control's
    /// [`event_count`](crate::project::VbControl::event_count) cannot
    /// be read.
    pub fn events_all_slots(
        &self,
        form_data: Option<&'p FormDataParser<'a>>,
    ) -> Result<Vec<EventBinding<'a>>, Error> {
        self.events_inner(form_data, /* connected_only */ false)
    }

    fn events_inner(
        &self,
        form_data: Option<&'p FormDataParser<'a>>,
        connected_only: bool,
    ) -> Result<Vec<EventBinding<'a>>, Error> {
        let mut bindings = Vec::new();
        let controls: Vec<_> = if let Some(fd) = form_data {
            self.controls_with_form_data(fd)?
                .filter_map(|r| match r {
                    Ok(c) => Some(c),
                    Err(e) => {
                        crate::trace::warn_drop!("events.controls_with_form_data", error = ?e);
                        None
                    }
                })
                .collect()
        } else {
            self.controls()?
                .filter_map(|r| match r {
                    Ok(c) => Some(c),
                    Err(e) => {
                        crate::trace::warn_drop!("events.controls", error = ?e);
                        None
                    }
                })
                .collect()
        };

        for ctrl in &controls {
            let ctrl_type = ctrl
                .form_control_type()
                .or_else(|| ctrl.class_name().and_then(FormControlType::from_class_name));
            let ctrl_index = ctrl.index()?;
            let event_count = ctrl.event_count()?;
            for slot in 0..event_count {
                let handler_va = ctrl.event_handler_va(slot).unwrap_or(0);
                if connected_only && handler_va == 0 {
                    continue;
                }
                let event_name = ctrl_type
                    .and_then(|ct| eventname::event_name(slot, ct))
                    .or_else(|| eventname::standard_event_name(slot));
                bindings.push(EventBinding {
                    control_index: ctrl_index,
                    control_name: ctrl.name(),
                    control_type: ctrl_type,
                    event_slot: slot,
                    event_name,
                    handler_va,
                });
            }
        }
        Ok(bindings)
    }

    /// Reserved signature for future form-designer-data extraction.
    ///
    /// Today this is an alias for [`form_data_from_gui_entry`](Self::form_data_from_gui_entry)
    /// and exposes the same [`FormDataParser`]. The reserved name lets
    /// downstream code wire up a "form designer" pane unconditionally
    /// without breaking when the underlying extraction grows richer (e.g.,
    /// resolving embedded resources, decoding more property types, or
    /// surfacing the menu-section tree alongside the control tree).
    ///
    /// # Stability
    ///
    /// Returns the same [`FormDataParser`] as `form_data_from_gui_entry`
    /// today. Future versions may extend the parser with additional
    /// accessors but will not change the method signature or `Option<...>`
    /// shape.
    #[inline]
    pub fn form_designer_data(&self, gui_entry: &GuiTableEntry<'a>) -> Option<FormDataParser<'a>> {
        self.form_data_from_gui_entry(gui_entry)
    }

    /// Returns a [`ConstantPool`] reader for this object's constants.
    ///
    /// The pool base VA comes from [`ObjectInfo::constants_va`] and
    /// contains BSTRs, API stubs, GUIDs, and code object references.
    ///
    /// # Errors
    ///
    /// Returns an error if `ObjectInfo::constants_va` cannot be read.
    pub fn constants_pool(&self) -> Result<ConstantPool<'a>, Error> {
        Ok(ConstantPool::new(
            self.project.address_map(),
            self.info.constants_va()?,
        ))
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
    ///
    /// # Errors
    ///
    /// Returns an error if the private object descriptor's func type descs VA
    /// or counts cannot be read.
    pub fn func_type_descs(&self) -> Result<FuncTypDescIter<'a, 'p>, Error> {
        let (ftd_va, total) = match self.private_object.as_ref() {
            Some(p) => {
                let va = p.func_type_descs_va()?;
                if va == 0 {
                    (0, 0)
                } else {
                    let total =
                        u32::from(p.func_count()?).saturating_add(u32::from(p.var_count()?));
                    (va, total)
                }
            }
            None => (0, 0),
        };
        Ok(FuncTypDescIter {
            map: self.project.address_map(),
            ftd_array_va: ftd_va,
            index: 0,
            total,
        })
    }

    /// Returns an iterator over [`VarStubDesc`](crate::vb::varstub::VarStubDesc) entries.
    ///
    /// Walks the pointer array at [`PrivateObjectDescriptor::var_stubs_va`].
    /// Returns an empty iterator if no private object descriptor is present
    /// or if there are no variable stubs.
    ///
    /// # Errors
    ///
    /// Returns an error if the private object descriptor's `var_stubs_va`
    /// or `var_count` cannot be read.
    pub fn var_stubs(&self) -> Result<VarStubIter<'a>, Error> {
        let (stubs_va, count) = match self.private_object.as_ref() {
            Some(p) => {
                let va = p.var_stubs_va()?;
                let cnt = p.var_count()?;
                if va != 0 && cnt > 0 {
                    (va, cnt)
                } else {
                    (0, 0)
                }
            }
            None => (0, 0),
        };
        Ok(VarStubIter::new(
            self.project.address_map(),
            stubs_va,
            count,
        ))
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
            self.index = self.index.saturating_add(1);

            let ptr_va = self.ftd_array_va.wrapping_add(i.saturating_mul(4));
            let ptr_data = self.map.slice_from_va(ptr_va, 4).ok()?;
            let ptr_bytes: [u8; 4] = ptr_data.get(..4).and_then(|s| s.try_into().ok())?;
            let desc_va = u32::from_le_bytes(ptr_bytes);
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

/// A single event-handler binding on a VB6 form's control.
///
/// Yielded by [`VbObject::events`]. Joins the control's event sink vtable
/// with the per-control-type event-name template, surfacing the
/// (control, slot) → handler-VA → event-name mapping that's otherwise
/// scattered across [`controls`](VbObject::controls), the
/// [`EventSinkVtable`](crate::vb::events::EventSinkVtable) header, and the
/// [`eventname`](crate::vb::eventname) lookup tables.
///
/// Only **connected** handlers are yielded — slots whose
/// `event_handler_va == 0` (event not wired up by the user) are filtered
/// out. Use [`VbObject::events_all_slots`] for the full per-slot view
/// including disconnected events.
#[derive(Debug, Clone)]
pub struct EventBinding<'a> {
    /// Index of the control on the form (matches
    /// [`VbControl::index`](crate::project::VbControl::index)).
    pub control_index: u16,
    /// Control name as a lossy UTF-8 string (e.g., `"Command1"`,
    /// `"Timer1"`). Empty when the control has no name. Borrows the
    /// underlying bytes when they're already valid UTF-8.
    pub control_name: Cow<'a, str>,
    /// Authoritative control type, if it can be resolved.
    ///
    /// Resolution prefers form binary data (`cType` byte) over GUID
    /// fuzzy matching (which is unreliable for malware samples).
    /// `None` when neither source resolves the type — in that case
    /// [`event_name`](Self::event_name) falls back to the standard
    /// 24-event template.
    pub control_type: Option<FormControlType>,
    /// Zero-based slot in the control's event sink vtable.
    pub event_slot: u16,
    /// Resolved event name from the per-control-type template
    /// (e.g., `"Click"`, `"KeyPress"`, `"Timer"`). `None` when the slot
    /// is past the end of every known template (e.g., custom OCX
    /// events with no static lookup).
    pub event_name: Option<&'static str>,
    /// Virtual address of the handler stub. Always non-zero for
    /// bindings yielded by [`VbObject::events`] (the connected-only
    /// walker); may be zero when iterating all slots via
    /// [`VbObject::events_all_slots`].
    pub handler_va: u32,
}

impl<'a> EventBinding<'a> {
    /// Returns `true` if the control has a wired-up handler at this slot.
    #[inline]
    pub fn is_connected(&self) -> bool {
        self.handler_va != 0
    }

    /// Returns a `"ControlName_EventName"` label, falling back to
    /// `"ControlName_Event{NN}"` when the event name is unknown and
    /// `"_Event{NN}"` when the control name is empty.
    pub fn label(&self) -> String {
        let ctrl = self.control_name.as_ref();
        match self.event_name {
            Some(name) => format!("{ctrl}_{name}"),
            None => format!("{ctrl}_Event{:02}", self.event_slot),
        }
    }
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
        self.index = self.index.saturating_add(1);
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
            self.index = self.index.saturating_add(1);

            // Read the 4-byte VA for this slot
            let entry_va = self.methods_va.wrapping_add(u32::from(i).saturating_mul(4));
            let entry_data = match self.map.slice_from_va(entry_va, 4) {
                Ok(d) => d,
                Err(e) => return Some(Err(e)),
            };
            let method_va = match read_u32_le(entry_data, 0) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };

            // Skip null and out-of-image entries
            if method_va == 0 || !self.map.is_va_in_image(method_va) {
                continue;
            }

            // Check for P-Code stub patterns or direct ProcDscInfo pointer
            let stub_data = match self.map.slice_from_va(method_va, 12) {
                Ok(d) => d,
                Err(e) => return Some(Err(e)),
            };
            let is_stub = stub_data.first().copied() == Some(0xBA)
                || (stub_data.first().copied() == Some(0x33)
                    && stub_data.get(1).copied() == Some(0xC0)
                    && stub_data.get(2).copied() == Some(0xBA));
            if !is_stub {
                // Check for direct ProcDscInfo pointer
                let Some(pt_bytes) = stub_data.get(..4).and_then(|s| <[u8; 4]>::try_from(s).ok())
                else {
                    continue;
                };
                let Some(ps_bytes) = stub_data
                    .get(8..10)
                    .and_then(|s| <[u8; 2]>::try_from(s).ok())
                else {
                    continue;
                };
                let maybe_pt = u32::from_le_bytes(pt_bytes);
                let maybe_ps = u16::from_le_bytes(ps_bytes);
                if !self.map.is_va_in_image(maybe_pt) || maybe_ps == 0 || maybe_ps >= 0x8000 {
                    continue; // Not P-Code
                }
            }

            return Some(PCodeMethod::parse(self.map, self.methods_va, i));
        }
        None
    }
}
