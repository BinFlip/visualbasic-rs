//! ObjectTable structure parser.
//!
//! The ObjectTable is the third level of the VB6 structure chain.
//! It contains the count and pointer to the array of
//! [`PublicObjectDescriptor`](super::object::PublicObjectDescriptor) entries.
//!
//! Size: `0x54` bytes (84 bytes).

use crate::{
    error::Error,
    util::{read_fixed, read_u16_le, read_u32_le},
};

/// View over an ObjectTable structure (0x54 bytes).
///
/// Runtime confirmation: `ProcCallEngine_Body` in MSVBVM60.DLL reads
/// `lpProjectObject` (+0x14) via `ObjectInfo.lpObjectTable` (+0x04).
///
/// # Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `lpHeapLink` (always 0 after compile) |
/// | 0x04 | 4 | `lpExecProj` (COM exec project VA) |
/// | 0x08 | 4 | `lpProjectInfo2` (secondary project info VA) |
/// | 0x0C | 4 | Reserved (always 0xFFFFFFFF) |
/// | 0x10 | 4 | Reserved (always 0) |
/// | 0x14 | 4 | `lpProjectObject` (runtime project VA) |
/// | 0x18 | 16 | `uuidObject` (project GUID) |
/// | 0x28 | 2 | `fCompileState` (always 0x000A in compiled) |
/// | 0x2A | 2 | `wTotalObjects` |
/// | 0x2C | 2 | `wCompiledObjects` |
/// | 0x2E | 2 | `wObjectsInUse` |
/// | 0x30 | 4 | `lpObjectArray` (VA of descriptor array) |
/// | 0x34 | 4 | IDE flag (0 in compiled) |
/// | 0x38 | 4 | IDE data (0 in compiled) |
/// | 0x3C | 4 | IDE data 2 (0 in compiled) |
/// | 0x40 | 4 | `lpszProjectName` (VA of name string) |
/// | 0x44 | 4 | `dwLcid` (primary locale ID) |
/// | 0x48 | 4 | `dwLcid2` (secondary locale ID) |
/// | 0x4C | 4 | IDE data 3 (0 in compiled) |
/// | 0x50 | 4 | `dwIdentifier` (always 2 — format version) |
#[derive(Clone, Copy, Debug)]
pub struct ObjectTable<'a> {
    bytes: &'a [u8],
}

impl<'a> ObjectTable<'a> {
    /// Total size of the ObjectTable structure in bytes.
    pub const SIZE: usize = 0x54;

    /// Parses an ObjectTable from the given byte slice.
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice containing the ObjectTable structure.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 0x54`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::TooShort {
                expected: Self::SIZE,
                actual: data.len(),
                context: "ObjectTable",
            });
        }
        Ok(Self {
            bytes: &data[..Self::SIZE],
        })
    }

    /// Returns the raw bytes of this structure.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Heap link at offset 0x00 (always 0 in compiled binaries).
    #[inline]
    pub fn heap_link(&self) -> u32 {
        read_u32_le(self.bytes, 0x00)
    }

    /// COM exec project object VA at offset 0x04.
    ///
    /// Points to compiler-allocated .data section space (zeroed on disk,
    /// populated at runtime by MSVBVM60). Always exactly 0x10 bytes after
    /// [`project_object_va`](Self::project_object_va) — they are two
    /// entry points into the same COM object.
    ///
    /// At runtime, the first DWORD at this address contains the VBHeader
    /// VA (confirmed by `sub_6602BD7D` which matches `[node+0x10]` against
    /// VBHeader). Useful for memory forensics to cross-reference the
    /// structure chain from a process dump.
    #[inline]
    pub fn exec_proj_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x04)
    }

    /// Secondary project info (COM type metadata) VA at offset 0x08.
    ///
    /// Points to a [`ProjectInfo2`](super::projectinfo2::ProjectInfo2) header
    /// structure containing COM dispatch interface metadata for the project's
    /// classes and forms. Use [`ProjectInfo2::parse`](super::projectinfo2::ProjectInfo2::parse)
    /// to decode.
    #[inline]
    pub fn project_info2_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x08)
    }

    /// Reserved field at offset 0x0C (always `0xFFFFFFFF`).
    #[inline]
    pub fn reserved(&self) -> u32 {
        read_u32_le(self.bytes, 0x0C)
    }

    /// Runtime project object VA at offset 0x14.
    ///
    /// Points to compiler-allocated .data section space (zeroed on disk).
    /// This is the base of a COM object; [`exec_proj_va`](Self::exec_proj_va)
    /// points 0x10 bytes into the same object.
    ///
    /// Runtime layout of the project node at this address (0x110 bytes,
    /// heap-allocated by `CreateProjectObject` in MSVBVM60):
    ///
    /// | Offset | Field |
    /// |--------|-------|
    /// | +0x00 | vtable (internal linked list interface, NOT IUnknown) |
    /// | +0x04 | secondary data pointer |
    /// | +0x08 | next project node (linked list) |
    /// | +0x0C | prev project node (linked list) |
    /// | +0x10 | VBHeader VA (= `lpExecProj` points here) |
    /// | +0x14 | runtime state pointer (read by ProcCallEngine) |
    /// | +0x1C | thread flags |
    /// | +0x4C | tertiary vtable |
    /// | +0x94 | lpSubMain (from VBHeader+0x2C) |
    ///
    /// `ProcCallEngine_Body` reads `[lpProjectObject+0x14]` then
    /// dereferences `[result+0x0C]` from it.
    #[inline]
    pub fn project_object_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x14)
    }

    /// Object table GUID at offset 0x18 (16 bytes).
    #[inline]
    pub fn uuid(&self) -> &'a [u8] {
        read_fixed(self.bytes, 0x18, 16)
    }

    /// Compilation state flag at offset 0x28 (always `0x000A` in compiled binaries).
    #[inline]
    pub fn compile_state(&self) -> u16 {
        read_u16_le(self.bytes, 0x28)
    }

    /// Total number of objects in the project at offset 0x2A.
    ///
    /// This determines the length of the
    /// [`PublicObjectDescriptor`](super::object::PublicObjectDescriptor) array.
    #[inline]
    pub fn total_objects(&self) -> u16 {
        read_u16_le(self.bytes, 0x2A)
    }

    /// Compiled objects count at offset 0x2C.
    #[inline]
    pub fn compiled_objects(&self) -> u16 {
        read_u16_le(self.bytes, 0x2C)
    }

    /// Objects in use count at offset 0x2E.
    #[inline]
    pub fn objects_in_use(&self) -> u16 {
        read_u16_le(self.bytes, 0x2E)
    }

    /// Virtual address of the [`PublicObjectDescriptor`](super::object::PublicObjectDescriptor)
    /// array at offset 0x30.
    #[inline]
    pub fn object_array_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x30)
    }

    /// IDE-only flag at offset 0x34 (always 0 in compiled binaries).
    #[inline]
    pub fn ide_flag(&self) -> u32 {
        read_u32_le(self.bytes, 0x34)
    }

    /// Project name string VA at offset 0x40.
    ///
    /// Points to a null-terminated ANSI string with the VB project name.
    #[inline]
    pub fn project_name_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x40)
    }

    /// Primary locale ID at offset 0x44 (e.g., `0x0409` for US English).
    #[inline]
    pub fn lcid(&self) -> u32 {
        read_u32_le(self.bytes, 0x44)
    }

    /// Secondary locale ID at offset 0x48.
    ///
    /// May differ from the primary LCID (e.g., `0x0416` for Portuguese
    /// when the primary is `0x0409` US English).
    #[inline]
    pub fn lcid2(&self) -> u32 {
        read_u32_le(self.bytes, 0x48)
    }

    /// Format version identifier at offset 0x50 (always `2` in all tested samples).
    #[inline]
    pub fn identifier(&self) -> u32 {
        read_u32_le(self.bytes, 0x50)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_object_table() -> Vec<u8> {
        let mut buf = vec![0u8; ObjectTable::SIZE];
        // reserved = -1
        buf[0x0C..0x10].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        // total_objects = 4
        buf[0x2A..0x2C].copy_from_slice(&4u16.to_le_bytes());
        // object_array_va = 0x00403000
        buf[0x30..0x34].copy_from_slice(&0x00403000u32.to_le_bytes());
        // lcid = 0x0409
        buf[0x44..0x48].copy_from_slice(&0x0409u32.to_le_bytes());
        buf
    }

    #[test]
    fn test_parse_valid() {
        let data = make_object_table();
        let ot = ObjectTable::parse(&data).unwrap();
        assert_eq!(ot.reserved(), 0xFFFFFFFF);
        assert_eq!(ot.total_objects(), 4);
        assert_eq!(ot.object_array_va(), 0x00403000);
        assert_eq!(ot.lcid(), 0x0409);
    }

    #[test]
    fn test_parse_too_short() {
        let data = vec![0u8; ObjectTable::SIZE - 1];
        assert!(matches!(
            ObjectTable::parse(&data),
            Err(Error::TooShort { .. })
        ));
    }

    #[test]
    fn test_all_fields() {
        let data = make_object_table();
        let ot = ObjectTable::parse(&data).unwrap();
        let _ = ot.heap_link();
        let _ = ot.exec_proj_va();
        let _ = ot.project_info2_va();
        let _ = ot.project_object_va();
        let _ = ot.uuid();
        let _ = ot.compile_state();
        let _ = ot.compiled_objects();
        let _ = ot.objects_in_use();
        let _ = ot.ide_flag();
        let _ = ot.project_name_va();
        let _ = ot.lcid2();
        let _ = ot.identifier();
        let _ = ot.as_bytes();
    }
}
