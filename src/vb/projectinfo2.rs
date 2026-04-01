//! ProjectInfo2 structure parser — COM dispatch interface metadata.
//!
//! The `ProjectInfo2` structure is pointed to by `ObjectTable.lpProjectInfo2`
//! (+0x08). It contains COM type information for the project's forms and
//! classes, including control type registrations with CLSIDs and instance
//! names, plus property/parameter name strings.
//!
//! # Layout
//!
//! The structure has a 0x28-byte header, followed by a variable number of
//! 12-byte control type entries, followed by null-terminated name strings.
//!
//! ## Header (0x28 bytes)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0x00 | 4 | Reserved (always 0) |
//! | 0x04 | 4 | `lpObjectTable` (back-pointer) |
//! | 0x08 | 4 | Reserved (always 0xFFFFFFFF) |
//! | 0x0C | 4 | Reserved (always 0) |
//! | 0x10 | 4 | `lpObjectDescs` (PrivateObjectDescriptor VA array) |
//! | 0x14 | 12 | Reserved (always 0) |
//! | 0x20 | 4 | Reserved (always 0xFFFFFFFF) |
//! | 0x24 | 4 | Reserved (always 0) |
//!
//! ## Control Type Entries (0x0C bytes each, at +0x28)
//!
//! Each entry registers a unique control type used in the project:
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0x00 | 4 | `lpInterfaceMetadata` (interface method/property info) |
//! | 0x04 | 4 | `lpGuidData` (16-byte CLSID + instance name string) |
//! | 0x08 | 4 | `lpDispatchSlot` (.data section dispatch table entry) |

use core::str;

use crate::{
    addressmap::AddressMap,
    error::Error,
    util::{read_cstr, read_u32_le},
    vb::control::Guid,
};

/// View over a ProjectInfo2 header (0x28 bytes).
#[derive(Clone, Copy, Debug)]
pub struct ProjectInfo2<'a> {
    bytes: &'a [u8],
}

impl<'a> ProjectInfo2<'a> {
    /// Header size in bytes.
    pub const HEADER_SIZE: usize = 0x28;

    /// Size of each control type entry.
    pub const ENTRY_SIZE: usize = 0x0C;

    /// Parses the ProjectInfo2 header from the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 0x28`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::HEADER_SIZE {
            return Err(Error::TooShort {
                expected: Self::HEADER_SIZE,
                actual: data.len(),
                context: "ProjectInfo2",
            });
        }
        Ok(Self {
            bytes: &data[..Self::HEADER_SIZE],
        })
    }

    /// ObjectTable back-pointer at offset 0x04.
    #[inline]
    pub fn object_table_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x04)
    }

    /// VA of the PrivateObjectDescriptor pointer array at offset 0x10.
    ///
    /// Contains one DWORD per object (total_objects entries). Each entry
    /// is either a PrivateObjectDescriptor VA or 0xFFFFFFFF (for modules).
    #[inline]
    pub fn object_descs_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x10)
    }
}

/// Interface metadata structure (0x24 bytes) at each entry's `interface_metadata_va`.
///
/// Contains typelib GUID/path references and a dispatch name table.
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `lpTypelibGuid` (16-byte GUID followed by path string) |
/// | 0x04 | 4 | Reserved (always 0) |
/// | 0x08 | 4 | Flags A (always 6) |
/// | 0x0C | 4 | Flags B (always 9) |
/// | 0x10 | 4 | `lpTypelibPath` (null-terminated path string) |
/// | 0x14 | 4 | `lpNameTable` (dispatch method/property name strings) |
/// | 0x18 | 4 | `lpDataSlot` (.data section VA) |
/// | 0x1C | 4 | Reserved (always 0) |
/// | 0x20 | 4 | Reserved (always 0) |
#[derive(Clone, Copy, Debug)]
pub struct InterfaceMetadata<'a> {
    bytes: &'a [u8],
}

impl<'a> InterfaceMetadata<'a> {
    /// Total size of the structure in bytes.
    pub const SIZE: usize = 0x24;

    /// Parses interface metadata from the given byte slice.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::TooShort {
                expected: Self::SIZE,
                actual: data.len(),
                context: "InterfaceMetadata",
            });
        }
        Ok(Self {
            bytes: &data[..Self::SIZE],
        })
    }

    /// VA of the dispatch name table at offset 0x14.
    ///
    /// Points to null-terminated name strings: a library/module name
    /// followed by method/property names for this interface.
    #[inline]
    pub fn name_table_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x14)
    }

    /// VA of the typelib GUID at offset 0x00.
    #[inline]
    pub fn typelib_guid_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x00)
    }

    /// Reads dispatch name strings from the first block in the name table.
    ///
    /// Returns a list of null-terminated ANSI strings (library name +
    /// method/property names) from the first name block only. Use
    /// [`all_dispatch_names`](Self::all_dispatch_names) to get names
    /// from all blocks.
    pub fn dispatch_names(&self, map: &AddressMap<'a>) -> Vec<&'a str> {
        let va = self.name_table_va();
        if va == 0 {
            return Vec::new();
        }
        let Ok(data) = map.slice_from_va(va, 512) else {
            return Vec::new();
        };
        extract_name_block(data, 0).0
    }

    /// Reads ALL dispatch name blocks from the name table.
    ///
    /// The name table contains multiple blocks (one per class) interleaved
    /// with binary metadata. Each block contains a library name followed
    /// by method/property names for that class. Returns a vector of
    /// name blocks, where each block is a vector of strings.
    pub fn all_dispatch_names(&self, map: &AddressMap<'a>) -> Vec<Vec<&'a str>> {
        let va = self.name_table_va();
        if va == 0 {
            return Vec::new();
        }
        let Ok(data) = map.slice_from_va(va, 4096) else {
            return Vec::new();
        };
        extract_all_name_blocks(data)
    }
}

/// A single control type registration entry (0x0C bytes).
#[derive(Debug, Clone, Copy)]
pub struct ControlTypeEntry {
    /// VA of the interface metadata structure (method/property counts and names).
    pub interface_metadata_va: u32,
    /// VA of the GUID data: 16-byte CLSID followed by null-terminated instance name.
    pub guid_data_va: u32,
    /// VA of the dispatch table slot in the .data section.
    pub dispatch_slot_va: u32,
}

impl ControlTypeEntry {
    /// Reads the 16-byte control CLSID from the GUID data.
    pub fn control_guid<'a>(&self, map: &AddressMap<'a>) -> Option<Guid> {
        let data = map.slice_from_va(self.guid_data_va, 16).ok()?;
        Guid::from_bytes(data)
    }

    /// Reads the control instance name string (after the 16-byte GUID).
    pub fn control_name<'a>(&self, map: &AddressMap<'a>) -> Option<&'a str> {
        let data = map.slice_from_va(self.guid_data_va + 16, 64).ok()?;
        let name = read_cstr(data, 0);
        if name.is_empty() {
            return None;
        }
        str::from_utf8(name).ok()
    }

    /// Parses the interface metadata for this entry.
    pub fn interface_metadata<'a>(&self, map: &'a AddressMap<'a>) -> Option<InterfaceMetadata<'a>> {
        let data = map
            .slice_from_va(self.interface_metadata_va, InterfaceMetadata::SIZE)
            .ok()?;
        InterfaceMetadata::parse(data).ok()
    }
}

/// Iterates control type entries in a ProjectInfo2 structure.
///
/// Entries are 12-byte triplets starting at header+0x28. The iterator
/// stops when it encounters a value that doesn't resolve as a valid VA
/// in the PE image (indicating the start of the name string area).
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ControlTypeIter<'a> {
    map: &'a AddressMap<'a>,
    base_va: u32,
    index: u32,
}

impl<'a> ControlTypeIter<'a> {
    /// Creates a new iterator over control type entries.
    ///
    /// `pi2_va` is the VA of the ProjectInfo2 header.
    pub fn new(map: &'a AddressMap<'a>, pi2_va: u32) -> Self {
        Self {
            map,
            base_va: pi2_va + ProjectInfo2::HEADER_SIZE as u32,
            index: 0,
        }
    }
}

impl<'a> Iterator for ControlTypeIter<'a> {
    type Item = ControlTypeEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let entry_va = self.base_va + self.index * ProjectInfo2::ENTRY_SIZE as u32;
        let data = self
            .map
            .slice_from_va(entry_va, ProjectInfo2::ENTRY_SIZE)
            .ok()?;

        let a = read_u32_le(data, 0);
        let b = read_u32_le(data, 4);

        // Stop if first two DWORDs don't resolve as valid VAs in the PE
        if !self.map.is_va_in_image(a) || !self.map.is_va_in_image(b) {
            return None;
        }

        let c = read_u32_le(data, 8);
        self.index += 1;

        Some(ControlTypeEntry {
            interface_metadata_va: a,
            guid_data_va: b,
            dispatch_slot_va: c,
        })
    }
}

/// Collects the null-terminated name strings that follow the entries.
///
/// Returns a vector of property/parameter name strings.
pub fn read_name_strings<'a>(
    map: &'a AddressMap<'a>,
    pi2_va: u32,
    entry_count: u32,
) -> Vec<&'a str> {
    let names_va =
        pi2_va + ProjectInfo2::HEADER_SIZE as u32 + entry_count * ProjectInfo2::ENTRY_SIZE as u32;

    let Ok(data) = map.slice_from_va(names_va, 1024) else {
        return Vec::new();
    };

    let mut names = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        // Skip null padding
        if data[pos] == 0 {
            pos += 1;
            continue;
        }
        // Stop if not printable ASCII
        if data[pos] < 0x20 || data[pos] > 0x7E {
            break;
        }
        let name = read_cstr(data, pos);
        if name.is_empty() {
            break;
        }
        if let Ok(s) = str::from_utf8(name) {
            names.push(s);
        }
        pos += name.len() + 1;
        // Align to 4-byte boundary
        while pos % 4 != 0 && pos < data.len() {
            pos += 1;
        }
    }
    names
}

/// Checks if a byte sequence looks like a VB6 identifier.
fn is_vb_identifier(name: &[u8]) -> bool {
    name.len() >= 2
        && name
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.')
}

/// Extracts one name block starting at `pos` in `data`.
///
/// A name block is a sequence of null-terminated VB6 identifier strings,
/// each null-padded to 4-byte alignment. The block ends at the first
/// non-identifier byte sequence or a 4+ byte null run.
///
/// Returns `(names, end_pos)` where `end_pos` is the byte offset
/// after the block (including the null terminator).
fn extract_name_block(data: &[u8], start: usize) -> (Vec<&str>, usize) {
    let mut names = Vec::new();
    let mut pos = start;

    while pos < data.len() {
        // Skip null padding
        if data[pos] == 0 {
            let nulls = data[pos..].iter().take_while(|&&b| b == 0).count();
            if nulls >= 4 && !names.is_empty() {
                // End of name block
                return (names, pos + nulls);
            }
            pos += nulls;
            continue;
        }
        let name = read_cstr(data, pos);
        if !is_vb_identifier(name) {
            break;
        }
        if let Ok(s) = str::from_utf8(name) {
            names.push(s);
        }
        pos += name.len() + 1;
    }
    (names, pos)
}

/// Extracts ALL name blocks from a name table, skipping binary metadata
/// between blocks.
///
/// The name table contains per-class blocks interleaved with binary
/// metadata (dispatch tables, GUIDs, paths). This function scans for
/// runs of VB6 identifier strings, collecting each run as a separate
/// block.
fn extract_all_name_blocks(data: &[u8]) -> Vec<Vec<&str>> {
    let mut blocks = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        // Skip non-identifier bytes (binary metadata between blocks)
        if data[pos] == 0 {
            pos += 1;
            continue;
        }
        if data[pos] < 0x20 || data[pos] > 0x7E {
            pos += 1;
            continue;
        }

        // Try to extract a name block starting here
        let name = read_cstr(data, pos);
        if !is_vb_identifier(name) {
            pos += 1;
            continue;
        }

        // Found a valid identifier — extract the full block
        let (block, end) = extract_name_block(data, pos);
        if !block.is_empty() {
            blocks.push(block);
        }
        pos = end;
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_header() {
        let mut data = vec![0u8; ProjectInfo2::HEADER_SIZE];
        data[0x04..0x08].copy_from_slice(&0x00402000u32.to_le_bytes());
        data[0x08..0x0C].copy_from_slice(&0xFFFFFFFFu32.to_le_bytes());
        data[0x10..0x14].copy_from_slice(&0x00405000u32.to_le_bytes());
        let pi2 = ProjectInfo2::parse(&data).unwrap();
        assert_eq!(pi2.object_table_va(), 0x00402000);
        assert_eq!(pi2.object_descs_va(), 0x00405000);
    }

    #[test]
    fn test_parse_too_short() {
        let data = vec![0u8; ProjectInfo2::HEADER_SIZE - 1];
        assert!(matches!(
            ProjectInfo2::parse(&data),
            Err(Error::TooShort { .. })
        ));
    }
}
