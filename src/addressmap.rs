//! PE address translation utilities.
//!
//! The [`AddressMap`] bridges virtual addresses (VA) used in VB6 structures
//! with file offsets in the PE binary. It wraps a parsed `goblin` PE's
//! section table to provide efficient VA-to-file-offset resolution.
//!
//! VB6 structures use 32-bit virtual addresses as "pointers." To read
//! the data at those addresses from the file on disk, we must translate
//! each VA through the PE section table.

use crate::error::Error;

/// A single PE section's addressing information.
///
/// Extracted from goblin's section headers into a compact, owned form
/// so that [`AddressMap`] does not borrow from the goblin PE.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct SectionEntry {
    /// Section's RVA (relative virtual address) when loaded in memory.
    pub virtual_address: u32,
    /// Size of the section in memory (may exceed raw data size for BSS).
    pub virtual_size: u32,
    /// Offset of the section's raw data in the PE file.
    pub raw_data_offset: u32,
    /// Size of the section's raw data in the PE file.
    pub raw_data_size: u32,
}

/// Address translation context for a PE file.
///
/// Created once during initial parsing and threaded through all
/// downstream structure parsers. Provides access to the original
/// file buffer via translated virtual addresses.
///
/// # Lifetime
///
/// The `'a` lifetime ties the address map to the underlying file buffer.
/// All byte slices returned by [`slice_from_va`](AddressMap::slice_from_va)
/// borrow from this same buffer.
#[derive(Debug, Clone)]
pub struct AddressMap<'a> {
    /// The complete PE file bytes.
    file: &'a [u8],
    /// PE image base address (typically `0x00400000` for EXEs).
    image_base: u32,
    /// Section table entries, extracted from goblin.
    sections: Vec<SectionEntry>,
}

impl<'a> AddressMap<'a> {
    /// Creates an [`AddressMap`] from a goblin-parsed PE and the raw file bytes.
    ///
    /// # Arguments
    ///
    /// * `file` - The complete PE file as a byte slice.
    /// * `pe` - A reference to a goblin-parsed PE. Only the section table
    ///   and optional header are read; the PE object is not stored.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Not32Bit`] if the PE is not a 32-bit (PE32) executable.
    pub fn from_goblin(file: &'a [u8], pe: &goblin::pe::PE<'_>) -> Result<Self, Error> {
        // Verify this is PE32 (not PE32+)
        let oh = pe.header.optional_header.as_ref().ok_or(Error::TooShort {
            expected: 1,
            actual: 0,
            context: "PE optional header",
        })?;

        // goblin exposes is_64 but not the raw magic easily;
        // for PE32, image_base fits in u32.
        if pe.is_64 {
            // PE32+ magic is 0x020B
            return Err(Error::Not32Bit { magic: 0x020B });
        }

        let image_base = oh.windows_fields.image_base as u32;

        let sections = pe
            .sections
            .iter()
            .map(|s| SectionEntry {
                virtual_address: s.virtual_address,
                virtual_size: s.virtual_size,
                raw_data_offset: s.pointer_to_raw_data,
                raw_data_size: s.size_of_raw_data,
            })
            .collect();

        Ok(Self {
            file,
            image_base,
            sections,
        })
    }

    /// Returns the PE image base address.
    ///
    /// Typically `0x00400000` for VB6 executables.
    #[inline]
    pub fn image_base(&self) -> u32 {
        self.image_base
    }

    /// Returns a reference to the complete file buffer.
    #[inline]
    pub fn file(&self) -> &'a [u8] {
        self.file
    }

    /// Creates an `AddressMap` from raw parts (for testing and internal use).
    ///
    /// # Arguments
    ///
    /// * `file` - The complete PE file bytes.
    /// * `image_base` - The PE image base address.
    /// * `sections` - Pre-built section entries.
    #[cfg(test)]
    pub(crate) fn from_parts(file: &'a [u8], image_base: u32, sections: Vec<SectionEntry>) -> Self {
        Self {
            file,
            image_base,
            sections,
        }
    }

    /// Converts a 32-bit relative virtual address (RVA) to a file offset.
    ///
    /// # Arguments
    ///
    /// * `rva` - The relative virtual address to translate.
    ///
    /// # Errors
    ///
    /// - [`Error::RvaNotMapped`] if the RVA does not fall within any section.
    /// - [`Error::RvaInBssRegion`] if the RVA falls in a BSS region
    ///   (virtual size exceeds raw data size) with no file backing.
    pub fn rva_to_offset(&self, rva: u32) -> Result<usize, Error> {
        for s in &self.sections {
            if rva >= s.virtual_address && rva < s.virtual_address + s.virtual_size {
                let offset_within = rva - s.virtual_address;
                if offset_within >= s.raw_data_size {
                    return Err(Error::RvaInBssRegion { rva });
                }
                return Ok((s.raw_data_offset + offset_within) as usize);
            }
        }
        Err(Error::RvaNotMapped { rva })
    }

    /// Converts a 32-bit virtual address (VA) to a file offset.
    ///
    /// A VA is `image_base + RVA`. This subtracts the image base and
    /// delegates to [`rva_to_offset`](AddressMap::rva_to_offset).
    ///
    /// # Arguments
    ///
    /// * `va` - The virtual address to translate.
    ///
    /// # Errors
    ///
    /// - [`Error::VaBelowImageBase`] if `va < image_base`.
    /// - All errors from [`rva_to_offset`](AddressMap::rva_to_offset).
    pub fn va_to_offset(&self, va: u32) -> Result<usize, Error> {
        let rva = va
            .checked_sub(self.image_base)
            .ok_or(Error::VaBelowImageBase {
                va,
                image_base: self.image_base,
            })?;
        self.rva_to_offset(rva)
    }

    /// Converts a file offset to a virtual address.
    ///
    /// Returns `None` if the offset does not fall within any section's
    /// raw data range.
    pub fn offset_to_va(&self, offset: usize) -> Option<u32> {
        let offset = offset as u32;
        for s in &self.sections {
            if offset >= s.raw_data_offset && offset < s.raw_data_offset + s.raw_data_size {
                let rva = s.virtual_address + (offset - s.raw_data_offset);
                return Some(self.image_base + rva);
            }
        }
        None
    }

    /// Returns `true` if the given VA falls within the PE image's mapped sections.
    ///
    /// This is useful for classifying pointers: a VA that returns `false` likely
    /// points into an external DLL (e.g., MSVBVM60.DLL) rather than the PE file.
    #[inline]
    pub fn is_va_in_image(&self, va: u32) -> bool {
        self.va_to_offset(va).is_ok()
    }

    /// Returns a byte slice starting at the given VA with at least `min_len` bytes.
    ///
    /// This is the primary method for reading VB6 structures: given a VA
    /// from a pointer field, get a slice into the file buffer.
    ///
    /// The returned slice extends from the resolved offset to the **end of
    /// the file buffer**, not just `min_len` bytes. This allows callers to
    /// read variable-length data (e.g., null-terminated strings) or parse
    /// headers then access trailing fields without a second lookup. Callers
    /// that need an exact-length slice should re-slice the result.
    ///
    /// # Arguments
    ///
    /// * `va` - The virtual address where the data starts.
    /// * `min_len` - Minimum number of bytes that must be available.
    ///
    /// # Errors
    ///
    /// - All errors from [`va_to_offset`](AddressMap::va_to_offset).
    /// - [`Error::TooShort`] if fewer than `min_len` bytes remain after the offset.
    pub fn slice_from_va(&self, va: u32, min_len: usize) -> Result<&'a [u8], Error> {
        let offset = self.va_to_offset(va)?;
        let remaining = self.file.len().saturating_sub(offset);
        if remaining < min_len {
            return Err(Error::TooShort {
                expected: min_len,
                actual: remaining,
                context: "slice_from_va",
            });
        }
        Ok(&self.file[offset..])
    }

    /// Returns a byte slice starting at the given RVA with at least `min_len` bytes.
    ///
    /// Like [`slice_from_va`](AddressMap::slice_from_va) but takes an RVA directly.
    /// The returned slice extends to the end of the file buffer (see
    /// [`slice_from_va`](AddressMap::slice_from_va) for details).
    ///
    /// # Arguments
    ///
    /// * `rva` - The relative virtual address where the data starts.
    /// * `min_len` - Minimum number of bytes that must be available.
    ///
    /// # Errors
    ///
    /// - All errors from [`rva_to_offset`](AddressMap::rva_to_offset).
    /// - [`Error::TooShort`] if fewer than `min_len` bytes remain after the offset.
    pub fn slice_from_rva(&self, rva: u32, min_len: usize) -> Result<&'a [u8], Error> {
        let offset = self.rva_to_offset(rva)?;
        let remaining = self.file.len().saturating_sub(offset);
        if remaining < min_len {
            return Err(Error::TooShort {
                expected: min_len,
                actual: remaining,
                context: "slice_from_rva",
            });
        }
        Ok(&self.file[offset..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: build an AddressMap with a fake section table.
    fn make_map(file: &[u8], image_base: u32, sections: Vec<SectionEntry>) -> AddressMap<'_> {
        AddressMap {
            file,
            image_base,
            sections,
        }
    }

    fn text_section() -> SectionEntry {
        SectionEntry {
            virtual_address: 0x1000,
            virtual_size: 0x2000,
            raw_data_offset: 0x200,
            raw_data_size: 0x2000,
        }
    }

    fn bss_section() -> SectionEntry {
        SectionEntry {
            virtual_address: 0x5000,
            virtual_size: 0x1000,
            raw_data_offset: 0x3000,
            raw_data_size: 0x100, // much smaller than virtual_size
        }
    }

    #[test]
    fn test_rva_to_offset_basic() {
        let file = vec![0u8; 0x5000];
        let map = make_map(&file, 0x00400000, vec![text_section()]);
        // RVA 0x1000 -> raw offset 0x200
        assert_eq!(map.rva_to_offset(0x1000).unwrap(), 0x200);
        // RVA 0x1100 -> raw offset 0x300
        assert_eq!(map.rva_to_offset(0x1100).unwrap(), 0x300);
    }

    #[test]
    fn test_rva_to_offset_end_of_section() {
        let file = vec![0u8; 0x5000];
        let map = make_map(&file, 0x00400000, vec![text_section()]);
        // RVA 0x2FFF is the last byte of the section
        assert_eq!(map.rva_to_offset(0x2FFF).unwrap(), 0x200 + 0x1FFF);
    }

    #[test]
    fn test_rva_not_mapped() {
        let file = vec![0u8; 0x5000];
        let map = make_map(&file, 0x00400000, vec![text_section()]);
        // RVA 0x4000 is outside any section
        assert_eq!(
            map.rva_to_offset(0x4000),
            Err(Error::RvaNotMapped { rva: 0x4000 })
        );
    }

    #[test]
    fn test_rva_in_bss() {
        let file = vec![0u8; 0x5000];
        let map = make_map(&file, 0x00400000, vec![bss_section()]);
        // RVA 0x5200 is within virtual_size but beyond raw_data_size
        assert_eq!(
            map.rva_to_offset(0x5200),
            Err(Error::RvaInBssRegion { rva: 0x5200 })
        );
    }

    #[test]
    fn test_va_to_offset() {
        let file = vec![0u8; 0x5000];
        let map = make_map(&file, 0x00400000, vec![text_section()]);
        // VA 0x00401000 -> RVA 0x1000 -> offset 0x200
        assert_eq!(map.va_to_offset(0x00401000).unwrap(), 0x200);
    }

    #[test]
    fn test_va_below_image_base() {
        let file = vec![0u8; 0x5000];
        let map = make_map(&file, 0x00400000, vec![text_section()]);
        assert_eq!(
            map.va_to_offset(0x100),
            Err(Error::VaBelowImageBase {
                va: 0x100,
                image_base: 0x00400000,
            })
        );
    }

    #[test]
    fn test_slice_from_va() {
        let mut file = vec![0u8; 0x5000];
        // Put known bytes at raw offset 0x200
        file[0x200] = 0x56;
        file[0x201] = 0x42;
        file[0x202] = 0x35;
        file[0x203] = 0x21;

        let map = make_map(&file, 0x00400000, vec![text_section()]);
        let slice = map.slice_from_va(0x00401000, 4).unwrap();
        assert_eq!(&slice[..4], b"VB5!");
    }

    #[test]
    fn test_slice_from_va_too_short() {
        let file = vec![0u8; 0x201]; // Only 1 byte after offset 0x200
        let map = make_map(&file, 0x00400000, vec![text_section()]);
        assert!(matches!(
            map.slice_from_va(0x00401000, 4),
            Err(Error::TooShort { .. })
        ));
    }

    #[test]
    fn test_slice_from_rva() {
        let mut file = vec![0u8; 0x5000];
        file[0x200] = 0xAA;
        let map = make_map(&file, 0x00400000, vec![text_section()]);
        let slice = map.slice_from_rva(0x1000, 1).unwrap();
        assert_eq!(slice[0], 0xAA);
    }

    #[test]
    fn test_image_base() {
        let file = vec![0u8; 1];
        let map = make_map(&file, 0x00400000, vec![]);
        assert_eq!(map.image_base(), 0x00400000);
    }

    #[test]
    fn test_file_accessor() {
        let file = vec![1, 2, 3];
        let map = make_map(&file, 0, vec![]);
        assert_eq!(map.file(), &[1, 2, 3]);
    }

    #[test]
    fn test_multiple_sections() {
        let file = vec![0u8; 0x8000];
        let sec1 = SectionEntry {
            virtual_address: 0x1000,
            virtual_size: 0x1000,
            raw_data_offset: 0x200,
            raw_data_size: 0x1000,
        };
        let sec2 = SectionEntry {
            virtual_address: 0x3000,
            virtual_size: 0x2000,
            raw_data_offset: 0x2000,
            raw_data_size: 0x2000,
        };
        let map = make_map(&file, 0x00400000, vec![sec1, sec2]);

        // First section
        assert_eq!(map.rva_to_offset(0x1500).unwrap(), 0x200 + 0x500);
        // Second section
        assert_eq!(map.rva_to_offset(0x3100).unwrap(), 0x2000 + 0x100);
        // Between sections (unmapped gap)
        assert!(map.rva_to_offset(0x2500).is_err());
    }
}
