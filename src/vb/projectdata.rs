//! ProjectData structure parser.
//!
//! The ProjectData structure is the second level of the VB6 structure chain,
//! pointed to by [`VbHeader::project_data_va`](super::header::VbHeader::project_data_va).
//! Its most critical field is `lpNativeCode`: if zero, the binary contains P-Code.
//!
//! Size: `0x23C` bytes (572 bytes).

use crate::{
    error::Error,
    util::{read_fixed, read_u32_le},
};

/// View over a ProjectData structure (0x23C bytes).
///
/// # Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `dwVersion` (always 0x1F4 = VB 5.00) |
/// | 0x04 | 4 | `lpObjectTable` (.text VA) |
/// | 0x08 | 4 | Reserved (always 0) |
/// | 0x0C | 4 | `lpCodeStart` (.text VA — start of native/P-Code region) |
/// | 0x10 | 4 | `lpCodeEnd` (.text VA — end of code region) |
/// | 0x14 | 4 | `dwDataSize` (size of VB object structures in bytes) |
/// | 0x18 | 4 | `lpThreadSpace` (.data VA — per-object data area base) |
/// | 0x1C | 4 | `lpVbaSeh` (.text VA — `__vbaExceptHandler` import thunk) |
/// | 0x20 | 4 | `lpNativeCode` (.data VA; **0 = P-Code!**) |
/// | 0x24 | 528 | `szPathInfo` (null-terminated VBP path; often zeroed in malware) |
/// | 0x234 | 4 | `lpExternalTable` (.text VA) |
/// | 0x238 | 4 | `dwExternalCount` |
///
/// # Relationships
///
/// - For native binaries: `lpNativeCode` = .data section start,
///   `lpThreadSpace` = `lpNativeCode + 8`.
/// - For P-Code binaries: `lpNativeCode` = 0, `lpThreadSpace` = .data start.
/// - `lpVbaSeh` always points to a `jmp [__vbaExceptHandler]` import thunk.
#[derive(Clone, Copy, Debug)]
pub struct ProjectData<'a> {
    bytes: &'a [u8],
}

impl<'a> ProjectData<'a> {
    /// Total size of the ProjectData structure in bytes.
    pub const SIZE: usize = 0x23C;

    /// Parses a ProjectData from the given byte slice.
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice containing the ProjectData structure.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 0x23C`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::TooShort {
                expected: Self::SIZE,
                actual: data.len(),
                context: "ProjectData",
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

    /// Version number at offset 0x00.
    ///
    /// Expected value: `0x1F4` (500 decimal, meaning VB 5.00).
    #[inline]
    pub fn version(&self) -> u32 {
        read_u32_le(self.bytes, 0x00)
    }

    /// Virtual address of the [`ObjectTable`](super::objecttable::ObjectTable) at offset 0x04.
    #[inline]
    pub fn object_table_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x04)
    }

    /// Reserved field at offset 0x08 (always 0).
    #[inline]
    pub fn null_08(&self) -> u32 {
        read_u32_le(self.bytes, 0x08)
    }

    /// Start of the native/P-Code region in .text at offset 0x0C.
    ///
    /// For native binaries, this spans the compiled native code.
    /// For P-Code binaries, this is a tiny stub (e.g., 16 bytes).
    #[inline]
    pub fn code_start_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x0C)
    }

    /// End of the native/P-Code region in .text at offset 0x10.
    #[inline]
    pub fn code_end_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x10)
    }

    /// Size of VB object structures in bytes at offset 0x14.
    #[inline]
    pub fn data_size(&self) -> u32 {
        read_u32_le(self.bytes, 0x14)
    }

    /// Per-object data area base in .data section at offset 0x18.
    ///
    /// For native binaries: always `lpNativeCode + 8`.
    /// For P-Code binaries: equals the .data section start.
    /// This is the base from which per-module variable storage is allocated.
    #[inline]
    pub fn thread_space_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x18)
    }

    /// VBA exception handler VA at offset 0x1C.
    ///
    /// Points to the `__vbaExceptHandler` import thunk (`jmp [imm32]`)
    /// in the .text section.
    #[inline]
    pub fn vba_seh_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x1C)
    }

    /// Native code base VA at offset 0x20.
    ///
    /// **If this is zero, the binary contains P-Code.**
    /// If non-zero, points to the start of the .data section where the
    /// VB runtime's native code data resides. Always 8 bytes before
    /// [`thread_space_va`](Self::thread_space_va) in native binaries.
    #[inline]
    pub fn native_code_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x20)
    }

    /// Returns `true` if this binary contains P-Code (not native code).
    ///
    /// This is the definitive test: `lpNativeCode == 0` means P-Code.
    #[inline]
    pub fn is_pcode(&self) -> bool {
        self.native_code_va() == 0
    }

    /// Path and ID string at offset 0x24 (528-byte fixed region).
    #[inline]
    pub fn path_info(&self) -> &'a [u8] {
        read_fixed(self.bytes, 0x24, 528)
    }

    /// Virtual address of the external table at offset 0x234.
    #[inline]
    pub fn external_table_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x234)
    }

    /// External object count at offset 0x238.
    #[inline]
    pub fn external_count(&self) -> u32 {
        read_u32_le(self.bytes, 0x238)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_project_data() -> Vec<u8> {
        let mut buf = vec![0u8; ProjectData::SIZE];
        // version = 0x1F4
        buf[0x00..0x04].copy_from_slice(&0x1F4u32.to_le_bytes());
        // object_table_va = 0x00402000
        buf[0x04..0x08].copy_from_slice(&0x00402000u32.to_le_bytes());
        // native_code_va = 0 (P-Code)
        buf[0x20..0x24].copy_from_slice(&0u32.to_le_bytes());
        // external_count = 5
        buf[0x238..0x23C].copy_from_slice(&5u32.to_le_bytes());
        buf
    }

    #[test]
    fn test_parse_valid() {
        let data = make_project_data();
        let pd = ProjectData::parse(&data).unwrap();
        assert_eq!(pd.version(), 0x1F4);
        assert_eq!(pd.object_table_va(), 0x00402000);
        assert!(pd.is_pcode());
        assert_eq!(pd.native_code_va(), 0);
        assert_eq!(pd.external_count(), 5);
    }

    #[test]
    fn test_native_code() {
        let mut data = make_project_data();
        data[0x20..0x24].copy_from_slice(&0x00401000u32.to_le_bytes());
        let pd = ProjectData::parse(&data).unwrap();
        assert!(!pd.is_pcode());
        assert_eq!(pd.native_code_va(), 0x00401000);
    }

    #[test]
    fn test_parse_too_short() {
        let data = vec![0u8; ProjectData::SIZE - 1];
        assert!(matches!(
            ProjectData::parse(&data),
            Err(Error::TooShort { .. })
        ));
    }

    #[test]
    fn test_all_fields_accessible() {
        let data = make_project_data();
        let pd = ProjectData::parse(&data).unwrap();
        let _ = pd.null_08();
        let _ = pd.code_start_va();
        let _ = pd.code_end_va();
        let _ = pd.data_size();
        let _ = pd.thread_space_va();
        let _ = pd.vba_seh_va();
        let _ = pd.path_info();
        let _ = pd.external_table_va();
        let _ = pd.as_bytes();
    }
}
