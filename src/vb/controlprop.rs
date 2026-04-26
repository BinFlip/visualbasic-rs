//! Control property initialization entry parser.
//!
//! Class and form objects store default property values for their embedded
//! controls in a variable-length entry array within
//! [`ClassFormPublicBytes`](super::publicbytes::ClassFormPublicBytes) starting
//! at offset +0x0C.
//!
//! # Runtime Confirmation
//!
//! Entries are processed by `InitControlProperties` (0x6601505E) which
//! iterates `wControlCount` entries, advancing by `CalcControlPropertyEntrySize`
//! (0x66016972). Each entry is handled by `ProcessControlPropertyEntry`
//! (0x660481FC) which dispatches on the type byte to initialize strings,
//! arrays, objects, etc. in the instance data buffer.
//!
//! # Entry Layout
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0x00 | 2 | `wFrameOffset` — target byte offset within instance data |
//! | 0x02 | 1 | `bType` — bits \[3:0\] = [`ControlPropertyType`], upper bits = modifier flags |
//! | 0x03 | 1 | `bFlags` — additional flags (bit 0 checked for SafeArray) |
//! | 0x04 | var | Type-dependent data |

use std::fmt;

use crate::{error::Error, util::read_u16_le};

/// Type of a control property initialization entry.
///
/// Derived from the low 4 bits of the type byte at entry+0x02.
/// Size mapping verified against `CalcPropertyDataSize` (0x660169D3) in MSVBVM60.DLL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlPropertyType {
    /// Type 0: Empty / no data (0-byte entry data).
    Empty,
    /// Type 1: Short/Integer (4-byte entry data).
    Short,
    /// Type 2: Integer (4-byte entry data).
    Integer,
    /// Type 3: Long (4-byte entry data).
    Long,
    /// Type 4: String — allocates a BSTR. Entry+0x08 = u16 char count.
    String,
    /// Type 5: SafeArray (variable-length, size from inline descriptor).
    SafeArray,
    /// Type 6: Variant value (4-byte entry data).
    Variant,
    /// Type 8: Fixed data block (6-byte entry data).
    FixedData,
    /// Type 9: Object reference (0x1C-byte entry data).
    Object,
    /// Type 0xA: String variant (same layout as String).
    StringVariant,
    /// Type 0xB: Boolean (4-byte entry data, value in low 2 bytes).
    Boolean,
    /// Type 0xC: Variant reference (0-byte or flags-dependent entry data).
    VariantRef,
    /// Unknown type.
    Unknown(u8),
}

impl ControlPropertyType {
    /// Converts a raw 4-bit type code to a [`ControlPropertyType`].
    pub fn from_raw(raw: u8) -> Self {
        match raw & 0x0F {
            0 => Self::Empty,
            1 => Self::Short,
            2 => Self::Integer,
            3 => Self::Long,
            4 => Self::String,
            5 => Self::SafeArray,
            6 => Self::Variant,
            8 => Self::FixedData,
            9 => Self::Object,
            0xA => Self::StringVariant,
            0xB => Self::Boolean,
            0xC => Self::VariantRef,
            n => Self::Unknown(n),
        }
    }

    /// Returns the base entry data size (excluding the 4-byte header) for
    /// fixed-size types. SafeArray sizes depend on the inline descriptor and
    /// must be computed via [`ControlPropertyEntry::total_size`].
    ///
    /// Mirrors `CalcPropertyDataSize` (0x660169D3) in MSVBVM60.DLL.
    pub fn base_data_size(self) -> usize {
        match self {
            Self::Empty | Self::VariantRef => 0,
            Self::Short | Self::Integer | Self::Long | Self::Variant | Self::Boolean => 4,
            Self::String | Self::StringVariant => 6,
            Self::FixedData => 6,
            Self::Object => 0x1C,
            Self::SafeArray => 0, // Dynamic — see ControlPropertyEntry::total_size
            Self::Unknown(_) => 0,
        }
    }
}

impl fmt::Display for ControlPropertyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Empty"),
            Self::Short => write!(f, "Short"),
            Self::Integer => write!(f, "Integer"),
            Self::Long => write!(f, "Long"),
            Self::String | Self::StringVariant => write!(f, "String"),
            Self::SafeArray => write!(f, "SafeArray"),
            Self::Variant => write!(f, "Variant"),
            Self::FixedData => write!(f, "FixedData"),
            Self::Object => write!(f, "Object"),
            Self::Boolean => write!(f, "Boolean"),
            Self::VariantRef => write!(f, "VariantRef"),
            Self::Unknown(n) => write!(f, "Type{n}"),
        }
    }
}

/// A single control property initialization entry.
///
/// Each entry describes a default value to write into the instance data
/// buffer at [`frame_offset`](Self::frame_offset) when a new object is
/// created. The runtime's `ResolvePropertyTarget` (0x66016937) computes
/// the actual target address as `instance_base + frame_offset`.
#[derive(Debug, Clone, Copy)]
pub struct ControlPropertyEntry<'a> {
    bytes: &'a [u8],
}

impl<'a> ControlPropertyEntry<'a> {
    /// Minimum entry size (4-byte header).
    pub const HEADER_SIZE: usize = 4;

    /// Target offset within instance data buffer at entry+0x00.
    #[inline]
    pub fn frame_offset(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x00)
    }

    /// Raw type byte at entry+0x02.
    ///
    /// Returns 0 if the backing buffer is shorter than the header.
    #[inline]
    pub fn raw_type(&self) -> u8 {
        self.bytes.get(0x02).copied().unwrap_or(0)
    }

    /// Property type (low 4 bits of type byte).
    ///
    /// Returns [`ControlPropertyType::Empty`] if the backing buffer is shorter
    /// than the header (since the raw byte defaults to 0).
    pub fn property_type(&self) -> ControlPropertyType {
        ControlPropertyType::from_raw(self.raw_type())
    }

    /// Flags byte at entry+0x03.
    ///
    /// Returns 0 if the backing buffer is shorter than the header.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.bytes.get(0x03).copied().unwrap_or(0)
    }

    /// Type-dependent data bytes starting at entry+0x04.
    pub fn data(&self) -> &'a [u8] {
        self.bytes.get(Self::HEADER_SIZE..).unwrap_or(&[])
    }

    /// Total size of this entry (header + data) in bytes.
    ///
    /// For SafeArray entries, reads the inline descriptor to compute the
    /// actual size. Mirrors `CalcControlPropertyEntrySize` (0x66016972)
    /// → `CalcPropertyDataSize` (0x660169D3) in MSVBVM60.DLL.
    ///
    /// Note: CalcPropertyDataSize returns the TOTAL step size (including
    /// the 4-byte header), so base values 0x28/0x38 already include it.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if the entry header is incomplete or
    /// the SafeArray descriptor cannot be parsed, and
    /// [`Error::ArithmeticOverflow`] if the size computation overflows.
    pub fn total_size(&self) -> Result<usize, Error> {
        let ptype = self.property_type();
        if ptype == ControlPropertyType::SafeArray {
            // CalcPropertyDataSize returns total step size (header included)
            return self.calc_safearray_total_size();
        }
        let base = ptype.base_data_size();
        // Flags byte bit 2 adds a 6-byte minimum
        if base == 0 && self.flags() & 0x04 != 0 {
            return Self::HEADER_SIZE
                .checked_add(6)
                .ok_or(Error::ArithmeticOverflow {
                    context: "ControlPropertyEntry::total_size header+6",
                });
        }
        // Types 1,2,3,0xB: flags bit 5 doubles to 8 bytes
        if matches!(
            ptype,
            ControlPropertyType::Short
                | ControlPropertyType::Integer
                | ControlPropertyType::Long
                | ControlPropertyType::Boolean
        ) && self.flags() & 0x20 != 0
        {
            return Self::HEADER_SIZE
                .checked_add(8)
                .ok_or(Error::ArithmeticOverflow {
                    context: "ControlPropertyEntry::total_size header+8",
                });
        }
        Self::HEADER_SIZE
            .checked_add(base)
            .ok_or(Error::ArithmeticOverflow {
                context: "ControlPropertyEntry::total_size header+base",
            })
    }

    /// Computes the TOTAL entry size for a SafeArray from the inline descriptor.
    ///
    /// The base values (0x28/0x38) already include the 4-byte header.
    /// Mirrors CalcPropertyDataSize which returns total step size.
    fn calc_safearray_total_size(&self) -> Result<usize, Error> {
        // Determine descriptor offset within entry
        let elem_info = self.bytes.get(0x08).copied().unwrap_or(0);
        let desc_offset: usize = if elem_info & 0x60 != 0 { 0x20 } else { 0x10 };

        // Read descriptor: u16 dim_count + u8 elem_flags
        let needed = desc_offset
            .checked_add(3)
            .ok_or(Error::ArithmeticOverflow {
                context: "calc_safearray_total_size desc_offset+3",
            })?;
        if self.bytes.len() < needed {
            // Not enough data — use a safe minimum
            return Ok(0x28);
        }
        let dim_count = read_u16_le(self.bytes, desc_offset)? as usize;
        let elem_flags_offset = desc_offset
            .checked_add(2)
            .ok_or(Error::ArithmeticOverflow {
                context: "calc_safearray_total_size desc_offset+2",
            })?;
        let elem_flags = self
            .bytes
            .get(elem_flags_offset)
            .copied()
            .ok_or(Error::Truncated {
                needed: elem_flags_offset.saturating_add(1),
                available: self.bytes.len(),
            })?;

        // Base size depends on element info
        let base: usize = if elem_info & 0x60 != 0 { 0x38 } else { 0x28 };

        // Per-dimension data: 8 bytes per dim, minus 8 (first dim is in the base)
        let dim_data = if dim_count > 0 {
            dim_count.saturating_sub(1).saturating_mul(8)
        } else {
            0
        };

        // Extra 4 bytes if element type has upper bits set
        let elem_extra: usize = if elem_flags & 0xE0 != 0 { 4 } else { 0 };

        base.checked_add(dim_data)
            .and_then(|v| v.checked_add(elem_extra))
            .ok_or(Error::ArithmeticOverflow {
                context: "calc_safearray_total_size base+dim_data+elem_extra",
            })
    }
}

/// Iterator over control property initialization entries.
///
/// Created by [`ClassFormPublicBytes::control_entries`](super::publicbytes::ClassFormPublicBytes::control_entries).
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ControlPropertyIter<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: u16,
}

impl<'a> ControlPropertyIter<'a> {
    /// Creates a new iterator over control property entries.
    pub fn new(data: &'a [u8], count: u16) -> Self {
        Self {
            data,
            pos: 0,
            remaining: count,
        }
    }
}

impl<'a> Iterator for ControlPropertyIter<'a> {
    type Item = ControlPropertyEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let header_end = self.pos.checked_add(ControlPropertyEntry::HEADER_SIZE)?;
        if header_end > self.data.len() {
            return None;
        }
        let entry_bytes = self.data.get(self.pos..)?;
        if entry_bytes.len() < ControlPropertyEntry::HEADER_SIZE {
            return None;
        }
        let entry = ControlPropertyEntry { bytes: entry_bytes };
        let size = entry
            .total_size()
            .ok()?
            .max(ControlPropertyEntry::HEADER_SIZE);
        self.pos = self.pos.checked_add(size)?;
        self.remaining = self.remaining.checked_sub(1)?;
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_property_types() {
        assert_eq!(ControlPropertyType::from_raw(1), ControlPropertyType::Short);
        assert_eq!(ControlPropertyType::from_raw(3), ControlPropertyType::Long);
        assert_eq!(
            ControlPropertyType::from_raw(4),
            ControlPropertyType::String
        );
        assert_eq!(
            ControlPropertyType::from_raw(5),
            ControlPropertyType::SafeArray
        );
        assert_eq!(
            ControlPropertyType::from_raw(9),
            ControlPropertyType::Object
        );
        assert_eq!(
            ControlPropertyType::from_raw(0xB),
            ControlPropertyType::Boolean
        );
        assert_eq!(format!("{}", ControlPropertyType::String), "String");
        assert_eq!(format!("{}", ControlPropertyType::Object), "Object");
    }

    #[test]
    fn test_entry_sizes() {
        assert_eq!(ControlPropertyType::Long.base_data_size(), 4);
        assert_eq!(ControlPropertyType::String.base_data_size(), 6);
        assert_eq!(ControlPropertyType::Object.base_data_size(), 0x1C);
        // SafeArray is dynamic, base returns 0
        assert_eq!(ControlPropertyType::SafeArray.base_data_size(), 0);
    }

    // Real SafeArray entry from Cls_CRC32 (full entry with descriptor)
    const CLS_CRC32_SA_ENTRY: [u8; 0x30] = [
        0x38, 0x00, 0x05, 0x00, // +0x00: offset=0x38, type=5, flags=0
        0x5C, 0x00, 0x55, 0x00, // +0x04: data
        0x00, 0x00, 0x65, 0x00, // +0x08: elem_info=0 (desc at +0x10)
        0x72, 0x00, 0x5C, 0x00, // +0x0C: data
        0x01, 0x00, 0x92, 0x00, // +0x10: SA descriptor: dim=1, elem_flags=0x92
        0x04, 0x00, 0x00, 0x00, // +0x14: descriptor data
        0x00, 0x00, 0x00, 0x00, // +0x18
        0x00, 0x00, 0x00, 0x00, // +0x1C
        0x00, 0x01, 0x00, 0x00, // +0x20
        0x00, 0x00, 0x00, 0x00, // +0x24
        0x03, 0x00, 0x5C, 0x00, // +0x28
        0xDE, 0x44, 0xAD, 0xB4, // +0x2C
    ];

    #[test]
    fn test_safearray_entry_size() {
        let entry = ControlPropertyEntry {
            bytes: &CLS_CRC32_SA_ENTRY,
        };
        assert_eq!(entry.frame_offset().unwrap(), 0x38);
        assert_eq!(entry.property_type(), ControlPropertyType::SafeArray);
        assert_eq!(entry.flags(), 0x00);
        // Total: base(0x28) + dim_data(0) + elem_extra(4) = 0x2C
        // (base already includes 4-byte header)
        assert_eq!(entry.total_size().unwrap(), 0x2C);
    }

    #[test]
    fn test_long_entry_size() {
        let data: [u8; 8] = [0x34, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00];
        let entry = ControlPropertyEntry { bytes: &data };
        assert_eq!(entry.property_type(), ControlPropertyType::Long);
        assert_eq!(entry.total_size().unwrap(), 4 + 4); // header + 4 bytes
    }

    #[test]
    fn test_long_entry_with_flags() {
        // Type 3 (Long) with flags bit 5 set → 8 bytes data
        let data: [u8; 12] = [
            0x10, 0x00, 0x03, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let entry = ControlPropertyEntry { bytes: &data };
        assert_eq!(entry.property_type(), ControlPropertyType::Long);
        assert_eq!(entry.total_size().unwrap(), 4 + 8); // header + 8 (flags bit 5)
    }

    #[test]
    fn test_iter_empty() {
        let iter = ControlPropertyIter::new(&[], 0);
        assert_eq!(iter.count(), 0);
    }
}
