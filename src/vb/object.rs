//! PublicObjectDescriptor, ObjectInfo, and OptionalObjectInfo structure parsers.
//!
//! These structures describe individual objects (forms, modules, classes)
//! within a VB6 project.

use crate::{
    addressmap::AddressMap,
    error::Error,
    util::{read_u16_le, read_u32_le},
    vb::control::Guid,
};

/// View over a PublicObjectDescriptor structure (0x30 bytes).
///
/// Each entry in the object array describes one VB6 object (form, module,
/// class). The compiler builds these in `BuildPerObject` (`sub_45899C`)
/// and writes 0x4C-byte records to the compilation stream (0x30 struct
/// + 0x1C bytes of linker tracking data).
///
/// # Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `lpObjectInfo` (VA of [`ObjectInfo`]) |
/// | 0x04 | 4 | Reserved (always 0xFFFFFFFF) |
/// | 0x08 | 4 | `lpPublicBytes` (variable descriptor table) |
/// | 0x0C | 4 | `lpStaticBytes` (always 0 in tested samples) |
/// | 0x10 | 4 | `lpModulePublic` (.data VA, modules only; 0 for forms/classes) |
/// | 0x14 | 4 | `lpModuleStatic` (always 0 in tested samples) |
/// | 0x18 | 4 | `lpszObjectName` (null-terminated ANSI string VA) |
/// | 0x1C | 4 | `dwMethodCount` |
/// | 0x20 | 4 | `lpMethodNames` (VA; forms/classes only; 0 for modules) |
/// | 0x24 | 4 | `oStaticVars` (always 0x0000FFFF — sentinel) |
/// | 0x28 | 4 | `fObjectType` (type flags, see below) |
/// | 0x2C | 4 | Reserved (always 0) |
///
/// # fObjectType values
///
/// | Low byte | Type | Full value (typical) |
/// |----------|------|---------------------|
/// | `0x01` | Standard module (.bas) | `0x00018001` |
/// | `0x03` | Class module (.cls) | `0x00118003` |
/// | `0x83` | Form / UserDocument | `0x00018083` |
#[derive(Clone, Copy, Debug)]
pub struct PublicObjectDescriptor<'a> {
    /// Raw backing bytes borrowed from the PE file buffer.
    bytes: &'a [u8],
}

impl<'a> PublicObjectDescriptor<'a> {
    /// Total size of the structure in bytes.
    pub const SIZE: usize = 0x30;

    /// Parses a PublicObjectDescriptor from the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 0x30`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::TooShort {
                expected: Self::SIZE,
                actual: data.len(),
                context: "PublicObjectDescriptor",
            });
        }
        let bytes = data.get(..Self::SIZE).ok_or(Error::TooShort {
            expected: Self::SIZE,
            actual: data.len(),
            context: "PublicObjectDescriptor",
        })?;
        Ok(Self { bytes })
    }

    /// Virtual address of the [`ObjectInfo`] structure at offset 0x00.
    #[inline]
    pub fn object_info_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x00)
    }

    /// Reserved field at offset 0x04 (always -1).
    #[inline]
    pub fn reserved(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x04)
    }

    /// Public variable descriptor table VA at offset 0x08.
    ///
    /// Points to a [`PublicVarTable`](super::publicbytes::PublicVarTable)
    /// structure with variable type codes and frame offsets.
    #[inline]
    pub fn public_bytes_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x08)
    }

    /// Static variable descriptor table VA at offset 0x0C.
    ///
    /// Always 0 in tested samples (no static var descriptors observed).
    #[inline]
    pub fn static_bytes_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x0C)
    }

    /// Module public variables .data section VA at offset 0x10.
    ///
    /// Non-zero only for standard modules (.bas). Points to the actual
    /// variable storage in the `.data` section, always 8 bytes after
    /// `ObjectInfo.object_data_va` (the 8-byte gap is a runtime header).
    /// Zero for forms and classes.
    #[inline]
    pub fn module_public_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x10)
    }

    /// Module static variables .data section VA at offset 0x14.
    ///
    /// Always 0 in tested samples.
    #[inline]
    pub fn module_static_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x14)
    }

    /// Object name string VA at offset 0x18.
    ///
    /// Points to a null-terminated ANSI string (e.g., `"Form1"`,
    /// `"modUtil"`, `"Cls_Zip"`).
    #[inline]
    pub fn object_name_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x18)
    }

    /// Number of methods at offset 0x1C.
    ///
    /// Includes all methods (event handlers, subs, functions, properties).
    /// Range observed: 0–45.
    #[inline]
    pub fn method_count(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x1C)
    }

    /// Method names string table VA at offset 0x20.
    ///
    /// Points to an array of null-terminated ANSI method name strings.
    /// Non-zero for forms and classes (COM-visible objects); always 0
    /// for standard modules. When `method_count() == 0`, this value
    /// may be uninitialized garbage.
    #[inline]
    pub fn method_names_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x20)
    }

    /// Static variable copy offset at offset 0x24.
    ///
    /// Always `0x0000FFFF` (sentinel for "no static vars") in all
    /// tested samples.
    #[inline]
    pub fn static_vars_offset(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x24)
    }

    /// Object type flags at offset 0x28.
    ///
    /// Low byte determines the object type:
    /// - `0x01` = standard module (.bas)
    /// - `0x03` = class module (.cls)
    /// - `0x83` = form / UserDocument
    ///
    /// See [`ObjectTypeFlags`](super::flags::ObjectTypeFlags) for bit
    /// definitions. The compiler assembles these from the internal type
    /// code at `*(*object + 0x37)` in `BuildPerObject`.
    #[inline]
    pub fn object_type_raw(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x28)
    }

    /// Returns `true` if this object has optional info (flag `0x01`).
    ///
    /// Note: this flag is set for ALL object types in tested samples.
    /// The actual presence of `OptionalObjectInfo` is determined
    /// spatially (gap between `ObjectInfo` and constants table).
    ///
    /// Returns `false` if the underlying type field cannot be read.
    #[inline]
    pub fn has_optional_info(&self) -> bool {
        self.object_type_raw().unwrap_or(0) & 0x01 != 0
    }

    /// Returns `true` if this is a class module (low byte `0x03`).
    ///
    /// Returns `false` if the underlying type field cannot be read.
    #[inline]
    pub fn is_class(&self) -> bool {
        let raw = self.object_type_raw().unwrap_or(0);
        raw & 0x02 != 0 && raw & 0x80 == 0
    }

    /// Returns `true` if this is a form or UserDocument (low byte `0x83`).
    ///
    /// Returns `false` if the underlying type field cannot be read.
    #[inline]
    pub fn is_form(&self) -> bool {
        self.object_type_raw().unwrap_or(0) & 0x82 == 0x82
    }

    /// Returns `true` if this is a standard module (low byte `0x01`).
    ///
    /// Returns `false` if the underlying type field cannot be read.
    #[inline]
    pub fn is_module(&self) -> bool {
        self.object_type_raw().unwrap_or(0) & 0x82 == 0x00
    }

    /// Reserved field at offset 0x2C (always 0 after compilation).
    #[inline]
    pub fn null_2c(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x2C)
    }
}

/// View over an ObjectInfo structure (0x38 bytes).
///
/// Contains method table, constants pool, and links back to the parent
/// structures. The first 12 bytes (wRefCount, wObjectIndex, lpObjectTable,
/// lpIdeData) are set by the linker/runtime, not the compiler.
///
/// Runtime confirmation: `ProcCallEngine_Body` in MSVBVM60.DLL reads
/// `lpObjectTable` (+0x04), `lpPublicObject` (+0x18), and
/// `lpConstants` (+0x34) directly from this structure.
///
/// # Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 2 | `wRefCount` (always 1 in compiled binaries) |
/// | 0x02 | 2 | `wObjectIndex` (zero-based) |
/// | 0x04 | 4 | `lpObjectTable` (back-pointer) |
/// | 0x08 | 4 | `lpIdeData` (always 0 in compiled) |
/// | 0x0C | 4 | `lpPrivateObject` (0xFFFFFFFF for modules) |
/// | 0x10 | 4 | Reserved (always 0xFFFFFFFF) |
/// | 0x14 | 4 | Reserved (always 0) |
/// | 0x18 | 4 | `lpPublicObject` (back-pointer to descriptor) |
/// | 0x1C | 4 | `lpObjectData` (per-object .data section area) |
/// | 0x20 | 2 | `wMethodCount` |
/// | 0x22 | 2 | `wMethodCountIde` (always 0 in compiled) |
/// | 0x24 | 4 | `lpMethods` (dispatch table VA) |
/// | 0x28 | 2 | `wConstantsCount` |
/// | 0x2A | 2 | `wMaxConstants` |
/// | 0x2C | 4 | Reserved (always 0) |
/// | 0x30 | 4 | Reserved (always 0) |
/// | 0x34 | 4 | `lpConstants` (constants pool VA) |
#[derive(Clone, Copy, Debug)]
pub struct ObjectInfo<'a> {
    /// Raw backing bytes borrowed from the PE file buffer.
    bytes: &'a [u8],
}

impl<'a> ObjectInfo<'a> {
    /// Total size of the structure in bytes.
    pub const SIZE: usize = 0x38;

    /// Parses an ObjectInfo from the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 0x38`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::TooShort {
                expected: Self::SIZE,
                actual: data.len(),
                context: "ObjectInfo",
            });
        }
        let bytes = data.get(..Self::SIZE).ok_or(Error::TooShort {
            expected: Self::SIZE,
            actual: data.len(),
            context: "ObjectInfo",
        })?;
        Ok(Self { bytes })
    }

    /// Reference count at offset 0x00 (always 1 after compilation).
    #[inline]
    pub fn ref_count(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x00)
    }

    /// Object index at offset 0x02.
    #[inline]
    pub fn object_index(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x02)
    }

    /// Back-pointer to the [`ObjectTable`](super::objecttable::ObjectTable) at offset 0x04.
    #[inline]
    pub fn object_table_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x04)
    }

    /// IDE data pointer at offset 0x08 (always 0 in compiled binaries).
    #[inline]
    pub fn ide_data(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x08)
    }

    /// Pointer to [`PrivateObjectDescriptor`](super::privateobj::PrivateObjectDescriptor) at offset 0x0C.
    ///
    /// `0xFFFFFFFF` for standard modules (which have no private descriptor).
    #[inline]
    pub fn private_object_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x0C)
    }

    /// Back-pointer to the [`PublicObjectDescriptor`] at offset 0x18.
    #[inline]
    pub fn public_object_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x18)
    }

    /// Per-object data area pointer at offset 0x1C.
    ///
    /// Points to the module's runtime data area in the `.data` section.
    #[inline]
    pub fn object_data_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x1C)
    }

    /// Number of methods at offset 0x20.
    #[inline]
    pub fn method_count(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x20)
    }

    /// IDE-only method count at offset 0x22 (zeroed in compiled binaries).
    #[inline]
    pub fn method_count_ide(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x22)
    }

    /// Virtual address of the method/dispatch table at offset 0x24.
    ///
    /// This table contains pointers to `ProcDscInfo` (RTMI) structures
    /// for each method. For P-Code methods, each entry is the address
    /// of a `mov edx, <rtmi_addr>; call ProcCallEngine` stub.
    ///
    /// Note: the P-Code engine does NOT use this field at runtime for
    /// method dispatch — it goes through ProcDscInfo structures directly.
    /// This field is used during project loading to build dispatch tables.
    /// When `method_count() == 0`, this value may be uninitialized garbage.
    #[inline]
    pub fn methods_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x24)
    }

    /// Constants count at offset 0x28.
    #[inline]
    pub fn constants_count(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x28)
    }

    /// Constants pool max size at offset 0x2A.
    #[inline]
    pub fn max_constants(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x2A)
    }

    /// Constants pool base pointer at offset 0x34.
    ///
    /// Use [`ConstantPool::new`](super::constantpool::ConstantPool::new) to create
    /// a reader for resolving string and API references from this base address.
    ///
    /// This is the most heavily used ObjectInfo field at runtime — the
    /// P-Code engine reads it at the start of every method execution to
    /// set up the constants pool base address. Also accessed via
    /// [`ProcDscInfo::object_info_va`](super::procedure::ProcDscInfo::object_info_va)
    /// → this struct → +0x34.
    #[inline]
    pub fn constants_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x34)
    }
}

/// View over an OptionalObjectInfo structure (0x40 bytes).
///
/// Follows [`ObjectInfo`] in memory (at ObjectInfo + 0x38). Present when
/// `PublicObjectDescriptor.fObjectType & 0x01`. Contains COM interface
/// GUIDs, control array pointers, method dispatch offsets, and P-Code
/// method counts.
///
/// # Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `gui_guids_count` — GUI GUID table entry count |
/// | 0x04 | 4 | `object_clsid_va` — VA of 16-byte object CLSID |
/// | 0x08 | 4 | `null_08` — always 0 (reserved) |
/// | 0x0C | 4 | `gui_guid_table_va` — VA of GUID VA-pointer array |
/// | 0x10 | 4 | `default_iid_count` — default IID table entry count |
/// | 0x14 | 4 | `events_iid_table_va` — VA of event source IID table |
/// | 0x18 | 4 | `events_iid_count` — event source IID count |
/// | 0x1C | 4 | `default_iid_table_va` — VA of default IID VA-pointer array |
/// | 0x20 | 4 | `control_count` — number of controls |
/// | 0x24 | 4 | `controls_va` — VA of ControlInfo array |
/// | 0x28 | 2 | `method_link_count` — method link entries |
/// | 0x2A | 2 | `pcode_count` — P-Code method count (439 = native sentinel) |
/// | 0x2C | 2 | `initialize_event_offset` — dispatch vtable byte offset |
/// | 0x2E | 2 | `terminate_event_offset` — dispatch vtable byte offset |
/// | 0x30 | 4 | `method_link_table_va` — VA of method link table |
/// | 0x34 | 4 | `basic_class_object_va` — VA of runtime dispatch vtable |
/// | 0x38 | 4 | `null_38` — always 0 (reserved) |
/// | 0x3C | 4 | `field_3c` — non-zero, linker-internal VA (not patchable) |
///
/// # GUID Tables
///
/// The GUI GUID table at +0x0C is an array of `gui_guids_count` VA pointers,
/// each pointing to a 16-byte GUID. These correspond to the GUIDs in the
/// [`GuiTable`](super::guitable) entries. The default IID table at +0x1C
/// uses the same format with `default_iid_count` entries. Both tables are
/// adjacent in memory, typically near the constants pool.
///
/// # Initialize / Terminate Offsets
///
/// The offsets at +0x2C and +0x2E are byte offsets into the dispatch vtable
/// (at `basic_class_object_va + 0x28`). Divide by 4 to get the method slot:
///
/// - **Classes**: Initialize at slot 3 (offset 0x0C), Terminate at slot 4 (0x10)
/// - **Forms/UserDocs**: Initialize at slot 26 (offset 0x68), Terminate at slot 27 (0x6C)
///
/// The slot index equals `ProcDscInfo.base_iface_slot_count + 1`.
#[derive(Clone, Copy, Debug)]
pub struct OptionalObjectInfo<'a> {
    /// Raw backing bytes borrowed from the PE file buffer.
    bytes: &'a [u8],
}

impl<'a> OptionalObjectInfo<'a> {
    /// Total size of the structure in bytes.
    pub const SIZE: usize = 0x40;

    /// Parses an OptionalObjectInfo from the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 0x40`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::TooShort {
                expected: Self::SIZE,
                actual: data.len(),
                context: "OptionalObjectInfo",
            });
        }
        let bytes = data.get(..Self::SIZE).ok_or(Error::TooShort {
            expected: Self::SIZE,
            actual: data.len(),
            context: "OptionalObjectInfo",
        })?;
        Ok(Self { bytes })
    }

    /// GUI GUID table entry count at offset 0x00.
    ///
    /// Number of VA pointers in the table at [`gui_guid_table_va`](Self::gui_guid_table_va).
    /// Each entry is a VA pointing to a 16-byte GUID that corresponds to
    /// a [`GuiTableEntry`](super::guitable::GuiTableEntry). Typically 1.
    #[inline]
    pub fn gui_guids_count(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x00)
    }

    /// VA of the object's 16-byte CLSID at offset 0x04.
    #[inline]
    pub fn object_clsid_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x04)
    }

    /// Reserved field at offset 0x08 (always 0).
    #[inline]
    pub fn null_08(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x08)
    }

    /// VA of the GUI GUID VA-pointer table at offset 0x0C.
    ///
    /// Array of [`gui_guids_count`](Self::gui_guids_count) dword VAs, each
    /// pointing to a 16-byte GUID. These GUIDs match the GUIDs in
    /// [`GuiTable`](super::guitable) entries for this object.
    #[inline]
    pub fn gui_guid_table_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x0C)
    }

    /// Default IID table entry count at offset 0x10.
    ///
    /// Number of VA pointers in the table at [`default_iid_table_va`](Self::default_iid_table_va).
    /// Typically 1 (one default dispatch IID per object).
    #[inline]
    pub fn default_iid_count(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x10)
    }

    /// VA of the events source IID table at offset 0x14.
    ///
    /// When [`events_iid_count`](Self::events_iid_count) is 0 (no custom
    /// events), this may share the same address as [`controls_va`](Self::controls_va).
    #[inline]
    pub fn events_iid_table_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x14)
    }

    /// Event source IID count at offset 0x18.
    ///
    /// Number of event source interfaces. Zero in all tested samples
    /// (forms/classes without custom event sources).
    #[inline]
    pub fn events_iid_count(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x18)
    }

    /// VA of the default IID VA-pointer table at offset 0x1C.
    ///
    /// Array of [`default_iid_count`](Self::default_iid_count) dword VAs,
    /// each pointing to a 16-byte IID. This is the default dispatch
    /// interface IID for COM QueryInterface resolution.
    #[inline]
    pub fn default_iid_table_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x1C)
    }

    /// Number of controls in the control array at offset 0x20.
    #[inline]
    pub fn control_count(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x20)
    }

    /// VA of the [`ControlInfo`](super::control::ControlInfo) array at offset 0x24.
    ///
    /// Use [`ControlIterator`](super::control::ControlIterator) to iterate
    /// [`control_count`](Self::control_count) entries.
    #[inline]
    pub fn controls_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x24)
    }

    /// Method link count at offset 0x28.
    #[inline]
    pub fn method_link_count(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x28)
    }

    /// P-Code method count at offset 0x2A.
    ///
    /// Number of methods in the dispatch table that are P-Code (as opposed
    /// to native thunks or event stubs). The value 439 (0x1B7) is a
    /// sentinel indicating native compilation — not an actual method count.
    #[inline]
    pub fn pcode_count(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x2A)
    }

    /// Byte offset to the Initialize event in the dispatch vtable at 0x2C.
    ///
    /// This is a byte offset into the dispatch vtable at `basic_class_object_va + 0x28`.
    /// Divide by 4 to get the zero-based method slot index.
    ///
    /// - **Classes**: 0x0C (slot 3, after IUnknown)
    /// - **Forms/UserDocs**: 0x68 (slot 26, after base interface methods)
    ///
    /// Related: `ProcDscInfo.base_iface_slot_count = (initialize_event_offset / 4) - 1`.
    #[inline]
    pub fn initialize_event_offset(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x2C)
    }

    /// Byte offset to the Terminate event in the dispatch vtable at 0x2E.
    ///
    /// Always `initialize_event_offset + 4` (next slot after Initialize).
    #[inline]
    pub fn terminate_event_offset(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x2E)
    }

    /// VA of the method link table at offset 0x30.
    #[inline]
    pub fn method_link_table_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x30)
    }

    /// Per-object dispatch vtable VA at offset 0x34.
    ///
    /// Points to compiler-allocated .data section space (zeroed on disk).
    /// At runtime, MSVBVM60 populates this with a dispatch vtable:
    ///
    /// - **0x28-byte header** (IUnknown + class metadata)
    /// - **method_count × 4 bytes** (one dispatch pointer per method)
    ///
    /// For classes: total size = `0x28 + method_count * 4` (confirmed
    /// across 4 class objects).
    /// For forms: larger allocation that includes control event dispatch.
    ///
    /// The runtime resolves this via an array at `ExecProj+0x22C`
    /// indexed by `ObjectInfo.wObjectIndex`.
    #[inline]
    pub fn basic_class_object_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x34)
    }

    /// Reserved field at offset 0x38 (always 0).
    #[inline]
    pub fn null_38(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x38)
    }

    /// Linker-internal field at offset 0x3C.
    ///
    /// Non-zero in all tested samples, but contains an address outside the
    /// PE image range — appears to be an unpatched linker-internal VA from
    /// the VBA6.DLL compilation environment. Not read by the runtime.
    #[inline]
    pub fn field_3c(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x3C)
    }

    /// Resolves the object's CLSID from [`object_clsid_va`](Self::object_clsid_va).
    pub fn resolve_clsid(&self, map: &AddressMap<'_>) -> Option<Guid> {
        let va = self.object_clsid_va().ok()?;
        if va == 0 {
            return None;
        }
        let data = map.slice_from_va(va, 16).ok()?;
        Guid::from_bytes(data)
    }

    /// Returns an iterator over GUIDs from the GUI GUID table.
    ///
    /// Yields [`gui_guids_count`](Self::gui_guids_count) GUIDs. Each table
    /// entry is a VA pointer to a 16-byte GUID. These GUIDs correspond to
    /// the [`GuiTableEntry`](super::guitable::GuiTableEntry) entries for
    /// this object.
    pub fn gui_guids<'b>(&self, map: &'b AddressMap<'_>) -> GuidTableIter<'b> {
        GuidTableIter::new(
            map,
            self.gui_guid_table_va().unwrap_or(0),
            self.gui_guids_count().unwrap_or(0),
        )
    }

    /// Returns an iterator over default dispatch interface IIDs.
    ///
    /// Yields [`default_iid_count`](Self::default_iid_count) IIDs. These
    /// are the default COM dispatch interface GUIDs used for
    /// `QueryInterface` resolution.
    pub fn default_iids<'b>(&self, map: &'b AddressMap<'_>) -> GuidTableIter<'b> {
        GuidTableIter::new(
            map,
            self.default_iid_table_va().unwrap_or(0),
            self.default_iid_count().unwrap_or(0),
        )
    }

    /// Returns an iterator over event source interface IIDs.
    ///
    /// Yields [`events_iid_count`](Self::events_iid_count) IIDs. Empty
    /// for objects without custom event sources.
    pub fn events_iids<'b>(&self, map: &'b AddressMap<'_>) -> GuidTableIter<'b> {
        GuidTableIter::new(
            map,
            self.events_iid_table_va().unwrap_or(0),
            self.events_iid_count().unwrap_or(0),
        )
    }
}

/// Iterator over a VA-pointer GUID table.
///
/// Each table entry is a 4-byte VA pointing to a 16-byte GUID. The
/// iterator resolves each VA lazily, yielding `(guid_va, Guid)` pairs.
/// Entries with unresolvable VAs are silently skipped.
///
/// Created by [`OptionalObjectInfo::gui_guids`],
/// [`OptionalObjectInfo::default_iids`], and
/// [`OptionalObjectInfo::events_iids`].
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct GuidTableIter<'a> {
    map: &'a AddressMap<'a>,
    /// Pre-read pointer table data (4 bytes per entry).
    ptr_data: &'a [u8],
    index: u32,
    count: u32,
}

impl<'a> GuidTableIter<'a> {
    /// Creates a new GUID table iterator.
    pub fn new(map: &'a AddressMap<'a>, table_va: u32, count: u32) -> Self {
        let ptr_data = if table_va != 0 && count > 0 {
            let ptr_size = (count as usize).saturating_mul(4);
            map.slice_from_va(table_va, ptr_size).unwrap_or(&[])
        } else {
            &[]
        };
        Self {
            map,
            ptr_data,
            index: 0,
            count,
        }
    }
}

impl<'a> Iterator for GuidTableIter<'a> {
    /// Yields `(guid_va, Guid)` pairs — the VA of the GUID data and
    /// the parsed 16-byte GUID.
    type Item = (u32, Guid);

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.count {
            let i = self.index as usize;
            self.index = self.index.saturating_add(1);

            let offset = i.checked_mul(4)?;
            let end = offset.checked_add(4)?;
            let chunk = self.ptr_data.get(offset..end)?;
            let guid_va = u32::from_le_bytes(<[u8; 4]>::try_from(chunk).ok()?);
            if guid_va == 0 {
                continue;
            }

            if let Ok(guid_data) = self.map.slice_from_va(guid_va, 16)
                && let Some(guid) = Guid::from_bytes(guid_data)
            {
                return Some((guid_va, guid));
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.count.saturating_sub(self.index) as usize;
        (0, Some(remaining))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_object_descriptor_parse() {
        let mut data = vec![0u8; PublicObjectDescriptor::SIZE];
        data[0x1C..0x20].copy_from_slice(&10u32.to_le_bytes()); // method_count
        // fObjectType = 0x00118003 (class module, as seen in real binaries)
        data[0x28..0x2C].copy_from_slice(&0x00118003u32.to_le_bytes());
        let desc = PublicObjectDescriptor::parse(&data).unwrap();
        assert_eq!(desc.method_count().unwrap(), 10);
        assert!(desc.has_optional_info());
        assert!(desc.is_class());
        assert!(!desc.is_form());
        assert!(!desc.is_module());
    }

    #[test]
    fn test_object_type_detection() {
        let mut data = vec![0u8; PublicObjectDescriptor::SIZE];

        // Module: low byte 0x01
        data[0x28..0x2C].copy_from_slice(&0x00018001u32.to_le_bytes());
        let desc = PublicObjectDescriptor::parse(&data).unwrap();
        assert!(desc.is_module());
        assert!(!desc.is_class());
        assert!(!desc.is_form());

        // Form: low byte 0x83
        data[0x28..0x2C].copy_from_slice(&0x00018083u32.to_le_bytes());
        let desc = PublicObjectDescriptor::parse(&data).unwrap();
        assert!(desc.is_form());
        assert!(!desc.is_class());
        assert!(!desc.is_module());

        // Class: low byte 0x03
        data[0x28..0x2C].copy_from_slice(&0x00118003u32.to_le_bytes());
        let desc = PublicObjectDescriptor::parse(&data).unwrap();
        assert!(desc.is_class());
        assert!(!desc.is_form());
        assert!(!desc.is_module());
    }

    #[test]
    fn test_public_object_descriptor_too_short() {
        let data = vec![0u8; PublicObjectDescriptor::SIZE - 1];
        assert!(matches!(
            PublicObjectDescriptor::parse(&data),
            Err(Error::TooShort { .. })
        ));
    }

    #[test]
    fn test_object_info_parse() {
        let mut data = vec![0u8; ObjectInfo::SIZE];
        data[0x20..0x22].copy_from_slice(&5u16.to_le_bytes()); // method_count
        data[0x24..0x28].copy_from_slice(&0x00404000u32.to_le_bytes()); // methods_va
        let info = ObjectInfo::parse(&data).unwrap();
        assert_eq!(info.method_count().unwrap(), 5);
        assert_eq!(info.methods_va().unwrap(), 0x00404000);
    }

    #[test]
    fn test_object_info_too_short() {
        let data = vec![0u8; ObjectInfo::SIZE - 1];
        assert!(matches!(
            ObjectInfo::parse(&data),
            Err(Error::TooShort { .. })
        ));
    }

    #[test]
    fn test_optional_object_info_parse() {
        let mut data = vec![0u8; OptionalObjectInfo::SIZE];
        data[0x2A..0x2C].copy_from_slice(&3u16.to_le_bytes()); // pcode_count
        data[0x20..0x24].copy_from_slice(&7u32.to_le_bytes()); // control_count
        let opt = OptionalObjectInfo::parse(&data).unwrap();
        assert_eq!(opt.pcode_count().unwrap(), 3);
        assert_eq!(opt.control_count().unwrap(), 7);
    }

    #[test]
    fn test_optional_object_info_too_short() {
        let data = vec![0u8; OptionalObjectInfo::SIZE - 1];
        assert!(matches!(
            OptionalObjectInfo::parse(&data),
            Err(Error::TooShort { .. })
        ));
    }
}
