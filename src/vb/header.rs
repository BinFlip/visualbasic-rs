//! VBHeader (EXEPROJECTINFO) structure parser.
//!
//! The VBHeader is the root of the VB6 internal structure chain. It is
//! located via the `push <imm32>` instruction at the PE entry point and
//! always starts with the `"VB5!"` magic signature.
//!
//! Size: `0x68` bytes parsed (104 bytes). The compiler (`sub_4598E5` in
//! VB6.EXE v6.00.8176) actually writes `0x78` bytes (120), but the runtime
//! never reads past offset `0x54` (`lpComRegisterData`). The fields at
//! `0x58`–`0x64` (bSZ string offsets) and `0x68`–`0x77` (reserved) are
//! dead data from the runtime's perspective — used only by the IDE/compiler.

use crate::{
    error::Error,
    util::{read_fixed_cstr, read_u16_le, read_u32_le},
};

/// View over a VBHeader (EXEPROJECTINFO) structure.
///
/// The VBHeader is 0x68 bytes and begins with `"VB5!"`. It is the top-level
/// structure that the VB6 runtime reads when initializing a VB6 executable.
///
/// # Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `szVbMagic` ("VB5!") |
/// | 0x04 | 2 | `wRuntimeBuild` |
/// | 0x06 | 14 | `szLangDll` |
/// | 0x14 | 14 | `szSecLangDll` |
/// | 0x22 | 2 | `wRuntimeRevision` |
/// | 0x24 | 4 | `dwLCID` |
/// | 0x28 | 4 | `dwSecLCID` |
/// | 0x2C | 4 | `lpSubMain` |
/// | 0x30 | 4 | `lpProjectData` |
/// | 0x34 | 4 | `fMdlIntCtls` |
/// | 0x38 | 4 | `fMdlIntCtls2` |
/// | 0x3C | 4 | `dwThreadFlags` |
/// | 0x40 | 4 | `dwThreadCount` |
/// | 0x44 | 2 | `wFormCount` |
/// | 0x46 | 2 | `wExternalCount` |
/// | 0x48 | 4 | `dwThunkCount` |
/// | 0x4C | 4 | `lpGuiTable` |
/// | 0x50 | 4 | `lpExternalTable` |
/// | 0x54 | 4 | `lpComRegisterData` |
/// | 0x58 | 4 | `bSZProjectDescription` |
/// | 0x5C | 4 | `bSZProjectExeName` |
/// | 0x60 | 4 | `bSZProjectHelpFile` |
/// | 0x64 | 4 | `bSZProjectName` |
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VbHeader<'a> {
    bytes: &'a [u8],
}

impl<'a> VbHeader<'a> {
    /// Total size of the VBHeader structure in bytes.
    pub const SIZE: usize = 0x68;

    /// Expected magic signature at offset 0x00.
    pub const MAGIC: &'static [u8; 4] = b"VB5!";

    /// Parses a VBHeader from the given byte slice.
    ///
    /// Validates that the slice is at least [`SIZE`](Self::SIZE) bytes long
    /// and starts with the `"VB5!"` magic signature.
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice containing the VBHeader. Only the first
    ///   `0x68` bytes are used; additional bytes are ignored.
    ///
    /// # Errors
    ///
    /// - [`Error::TooShort`] if `data.len() < 0x68`.
    /// - [`Error::BadMagic`] if the first 4 bytes are not `"VB5!"`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::TooShort {
                expected: Self::SIZE,
                actual: data.len(),
                context: "VbHeader",
            });
        }
        let magic = [data[0], data[1], data[2], data[3]];
        if &magic != Self::MAGIC {
            return Err(Error::BadMagic {
                expected: "VB5!",
                got: magic,
            });
        }
        Ok(Self {
            bytes: &data[..Self::SIZE],
        })
    }

    /// Returns the raw bytes of this VBHeader.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Magic signature at offset 0x00 (always `"VB5!"`).
    #[inline]
    pub fn magic(&self) -> &'a [u8] {
        &self.bytes[0x00..0x04]
    }

    /// Runtime build number at offset 0x04.
    #[inline]
    pub fn runtime_build(&self) -> u16 {
        read_u16_le(self.bytes, 0x04)
    }

    /// Language extension DLL name at offset 0x06 (14-byte null-padded ANSI).
    #[inline]
    pub fn lang_dll(&self) -> &'a [u8] {
        read_fixed_cstr(self.bytes, 0x06, 14)
    }

    /// Secondary language DLL name at offset 0x14 (14-byte null-padded ANSI).
    #[inline]
    pub fn sec_lang_dll(&self) -> &'a [u8] {
        read_fixed_cstr(self.bytes, 0x14, 14)
    }

    /// Internal runtime revision at offset 0x22.
    #[inline]
    pub fn runtime_revision(&self) -> u16 {
        read_u16_le(self.bytes, 0x22)
    }

    /// Language DLL LCID at offset 0x24.
    #[inline]
    pub fn lcid(&self) -> u32 {
        read_u32_le(self.bytes, 0x24)
    }

    /// Secondary language LCID at offset 0x28.
    #[inline]
    pub fn sec_lcid(&self) -> u32 {
        read_u32_le(self.bytes, 0x28)
    }

    /// Virtual address of Sub Main procedure at offset 0x2C.
    ///
    /// Zero if the project does not have a `Sub Main` entry point.
    #[inline]
    pub fn sub_main_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x2C)
    }

    /// Virtual address of the [`ProjectData`](super::projectdata::ProjectData) structure at offset 0x30.
    ///
    /// This is the most important pointer -- it leads to the rest of
    /// the VB6 structure chain.
    #[inline]
    pub fn project_data_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x30)
    }

    /// VB control flags for control IDs < 32 at offset 0x34.
    #[inline]
    pub fn mdl_int_ctls(&self) -> u32 {
        read_u32_le(self.bytes, 0x34)
    }

    /// VB control flags for control IDs >= 32 at offset 0x38.
    #[inline]
    pub fn mdl_int_ctls2(&self) -> u32 {
        read_u32_le(self.bytes, 0x38)
    }

    /// Threading mode flags at offset 0x3C.
    ///
    /// See [`ThreadFlags`](super::flags::ThreadFlags) for flag values.
    #[inline]
    pub fn thread_flags(&self) -> u32 {
        read_u32_le(self.bytes, 0x3C)
    }

    /// Thread pool size at offset 0x40.
    #[inline]
    pub fn thread_count(&self) -> u32 {
        read_u32_le(self.bytes, 0x40)
    }

    /// Number of forms at offset 0x44.
    #[inline]
    pub fn form_count(&self) -> u16 {
        read_u16_le(self.bytes, 0x44)
    }

    /// External controls count at offset 0x46.
    #[inline]
    pub fn external_count(&self) -> u16 {
        read_u16_le(self.bytes, 0x46)
    }

    /// Thunk count at offset 0x48.
    #[inline]
    pub fn thunk_count(&self) -> u32 {
        read_u32_le(self.bytes, 0x48)
    }

    /// Virtual address of the GUI element table at offset 0x4C.
    ///
    /// Points to the first [`GuiTableEntry`](super::guitable::GuiTableEntry).
    /// Use [`GuiTableIter`](super::guitable::GuiTableIter) to iterate
    /// [`form_count`](Self::form_count) entries. Each entry is variable-length
    /// (first dword = self-relative offset to next entry).
    #[inline]
    pub fn gui_table_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x4C)
    }

    /// Virtual address of the external components table at offset 0x50.
    ///
    /// Points to an array of 8-byte entries, one per external component.
    /// Use [`VbProject::externals()`](crate::VbProject::externals) to iterate.
    /// Count is [`external_count`](Self::external_count).
    #[inline]
    pub fn external_table_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x50)
    }

    /// Virtual address of COM registration data at offset 0x54.
    ///
    /// Points to a [`ComRegData`](super::comreg::ComRegData) header structure
    /// containing the project's TypeLib GUID, version, and a linked list of
    /// per-object [`ComRegObject`](super::comreg::ComRegObject) records.
    #[inline]
    pub fn com_register_data_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x54)
    }

    /// Project description string offset at offset 0x58.
    #[inline]
    pub fn project_description_offset(&self) -> u32 {
        read_u32_le(self.bytes, 0x58)
    }

    /// Project EXE name string offset at offset 0x5C.
    #[inline]
    pub fn project_exe_name_offset(&self) -> u32 {
        read_u32_le(self.bytes, 0x5C)
    }

    /// Project help file path string offset at offset 0x60.
    #[inline]
    pub fn project_help_file_offset(&self) -> u32 {
        read_u32_le(self.bytes, 0x60)
    }

    /// Project name string offset at offset 0x64.
    #[inline]
    pub fn project_name_offset(&self) -> u32 {
        read_u32_le(self.bytes, 0x64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a valid VBHeader byte buffer with known field values.
    fn make_vb_header() -> Vec<u8> {
        let mut buf = vec![0u8; VbHeader::SIZE];
        // Magic
        buf[0x00..0x04].copy_from_slice(b"VB5!");
        // runtime_build = 9848
        buf[0x04..0x06].copy_from_slice(&9848u16.to_le_bytes());
        // lang_dll = "VB6EN.DLL"
        buf[0x06..0x0F].copy_from_slice(b"VB6EN.DLL");
        // runtime_revision = 0x0009
        buf[0x22..0x24].copy_from_slice(&9u16.to_le_bytes());
        // lcid = 0x0409 (US English)
        buf[0x24..0x28].copy_from_slice(&0x0409u32.to_le_bytes());
        // project_data_va = 0x00401234
        buf[0x30..0x34].copy_from_slice(&0x00401234u32.to_le_bytes());
        // thread_flags = 0x01 (apartment model)
        buf[0x3C..0x40].copy_from_slice(&0x01u32.to_le_bytes());
        // form_count = 3
        buf[0x44..0x46].copy_from_slice(&3u16.to_le_bytes());
        // external_count = 2
        buf[0x46..0x48].copy_from_slice(&2u16.to_le_bytes());
        // project_name_offset = 0x00405678
        buf[0x64..0x68].copy_from_slice(&0x00405678u32.to_le_bytes());
        buf
    }

    #[test]
    fn test_parse_valid() {
        let data = make_vb_header();
        let hdr = VbHeader::parse(&data).unwrap();
        assert_eq!(hdr.magic(), b"VB5!");
        assert_eq!(hdr.runtime_build(), 9848);
        assert_eq!(hdr.lang_dll(), b"VB6EN.DLL");
        assert_eq!(hdr.runtime_revision(), 9);
        assert_eq!(hdr.lcid(), 0x0409);
        assert_eq!(hdr.project_data_va(), 0x00401234);
        assert_eq!(hdr.thread_flags(), 0x01);
        assert_eq!(hdr.form_count(), 3);
        assert_eq!(hdr.external_count(), 2);
        assert_eq!(hdr.project_name_offset(), 0x00405678);
    }

    #[test]
    fn test_parse_too_short() {
        let data = vec![0u8; VbHeader::SIZE - 1];
        assert_eq!(
            VbHeader::parse(&data),
            Err(Error::TooShort {
                expected: VbHeader::SIZE,
                actual: VbHeader::SIZE - 1,
                context: "VbHeader",
            })
        );
    }

    #[test]
    fn test_parse_bad_magic() {
        let mut data = make_vb_header();
        data[0..4].copy_from_slice(b"MZ\x90\x00");
        assert_eq!(
            VbHeader::parse(&data),
            Err(Error::BadMagic {
                expected: "VB5!",
                got: [0x4D, 0x5A, 0x90, 0x00],
            })
        );
    }

    #[test]
    fn test_parse_extra_bytes_ignored() {
        let mut data = make_vb_header();
        data.extend_from_slice(&[0xFF; 100]);
        let hdr = VbHeader::parse(&data).unwrap();
        assert_eq!(hdr.as_bytes().len(), VbHeader::SIZE);
    }

    #[test]
    fn test_all_zero_fields() {
        let mut data = vec![0u8; VbHeader::SIZE];
        data[0..4].copy_from_slice(b"VB5!");
        let hdr = VbHeader::parse(&data).unwrap();
        assert_eq!(hdr.sub_main_va(), 0);
        assert_eq!(hdr.sec_lcid(), 0);
        assert_eq!(hdr.sec_lang_dll(), b"");
        assert_eq!(hdr.thread_count(), 0);
        assert_eq!(hdr.thunk_count(), 0);
        assert_eq!(hdr.gui_table_va(), 0);
        assert_eq!(hdr.external_table_va(), 0);
        assert_eq!(hdr.com_register_data_va(), 0);
        assert_eq!(hdr.project_description_offset(), 0);
        assert_eq!(hdr.project_exe_name_offset(), 0);
        assert_eq!(hdr.project_help_file_offset(), 0);
        assert_eq!(hdr.mdl_int_ctls(), 0);
        assert_eq!(hdr.mdl_int_ctls2(), 0);
    }

    #[test]
    fn test_copy_semantics() {
        let data = make_vb_header();
        let hdr1 = VbHeader::parse(&data).unwrap();
        let hdr2 = hdr1; // Copy
        assert_eq!(hdr1.runtime_build(), hdr2.runtime_build());
    }
}
