//! Control / instance property initialization entry parser.
//!
//! Class and form objects store per-instance member descriptors for the
//! members that need allocation or cleanup (strings, variants, objects,
//! arrays, records) in a variable-length entry array within
//! [`ClassFormPublicBytes`](super::publicbytes::ClassFormPublicBytes) starting
//! at offset +0x0C.
//!
//! # Runtime Confirmation
//!
//! The format is pinned from four MSVBVM60.DLL routines:
//!
//! - `InitControlProperties` (0x6601505E) iterates `wControlCount` entries,
//!   advancing by `CalcControlPropertyEntrySize` (0x66016972).
//! - `ProcessControlPropertyEntry` (0x660481FC) is the **init** side: for a
//!   fixed-length string (nibble 4) it calls `SysAllocStringLen` with the char
//!   count at entry+0x08; for an array (nibble 5) it builds the SafeArray.
//! - `CleanupSingleEntry` (0x66016AAA) is the **destruct** side and is the
//!   authoritative source of each member's resource type — it dispatches on the
//!   low nibble of the type byte to `SysFreeString` / `__vbaFreeVar` /
//!   `IUnknown::Release` / `SafeArray*` / `__vbaRecDestructAnsi`.
//! - `CalcPropertyDataSize` (0x660169D3) computes the entry stride; the MLIL of
//!   `CalcControlPropertyEntrySize` returns it verbatim (no header adjustment),
//!   so the value **is** the byte stride to the next entry.
//!
//! Earlier revisions named the nibbles from `CalcPropertyDataSize` alone, which
//! groups members by stride and cannot tell a 4-byte BSTR pointer from a 4-byte
//! `Long`. The names below come from the cleanup dispatcher and are correct.
//!
//! # Entry Layout
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0x00 | 2 | `wFrameOffset` — target byte offset within instance data |
//! | 0x02 | 1 | `bType` — bits \[3:0\] = [`ControlPropertyType`] nibble, bits \[7:4\] = modifiers |
//! | 0x03 | 1 | `bFlags` — modifier flags (bit 2 = 6-byte floor, bit 5 = widen to 8) |
//! | 0x04 | var | Type-dependent data (e.g. +0x08 = string char count / array element info) |

use std::fmt;

use crate::{error::Error, util::read_u16_le};

/// The resource-release action the runtime performs on a member at destruct.
///
/// Recovered from `CleanupSingleEntry` (0x66016AAA): the runtime walks the same
/// entry array on object teardown and dispatches on the type nibble. This is
/// the forensically meaningful classification — it states exactly which members
/// hold heap resources (BSTRs, objects, arrays, records) versus plain inline
/// values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupAction {
    /// Inline value member — no heap resource, nothing to release.
    None,
    /// BSTR freed via `SysFreeString` (nibbles 1 and 4).
    FreeString,
    /// `Variant` cleared via `__vbaFreeVar` (nibble 2).
    FreeVariant,
    /// Object reference released via `IUnknown::Release` (nibble 3).
    ReleaseObject,
    /// Dynamic array torn down via `SafeArrayDestroyData` + `SafeArrayDestroyDescriptor` (nibble 5).
    DestroyArray,
    /// Fixed/locked array released via `SafeArrayUnlock` (nibble 6).
    UnlockArray,
    /// User-defined type destructed via `__vbaRecDestructAnsi` plus a recursive
    /// cleanup of its nested member table (nibble 9).
    DestructRecord,
}

impl fmt::Display for CleanupAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::None => "None",
            Self::FreeString => "FreeString",
            Self::FreeVariant => "FreeVariant",
            Self::ReleaseObject => "ReleaseObject",
            Self::DestroyArray => "DestroyArray",
            Self::UnlockArray => "UnlockArray",
            Self::DestructRecord => "DestructRecord",
        };
        f.write_str(s)
    }
}

/// Type of a class/form instance property entry.
///
/// Derived from the low 4 bits of the type byte at entry+0x02. The resource
/// types (string/variant/object/array/record) are verified against the runtime
/// cleanup dispatcher `CleanupSingleEntry` (0x66016AAA); the inline value
/// members carry no heap resource and the runtime never distinguishes their
/// exact VB scalar type, so they are reported as [`Value`](Self::Value) with the
/// raw nibble preserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlPropertyType {
    /// Nibble 1 — dynamic `String` (BSTR). Zero-initialized, freed on destruct.
    String,
    /// Nibble 2 — `Variant`. Cleared via `__vbaFreeVar` on destruct.
    Variant,
    /// Nibble 3 — object reference (`Object` / typed class). Released on destruct.
    Object,
    /// Nibble 4 — fixed-length `String`. Allocated to a fixed char count
    /// (`SysAllocStringLen`, length at entry+0x08) at init, freed on destruct.
    FixedString,
    /// Nibble 5 — dynamic array (`SafeArray`). Built at init, destroyed on destruct.
    Array,
    /// Nibble 6 — fixed/locked array. Released via `SafeArrayUnlock` on destruct.
    FixedArray,
    /// Nibble 9 — user-defined type (record). Destructed recursively on teardown.
    Udt,
    /// Inline value member with no heap resource (nibbles 0, 7, 8, 0xA, 0xB, 0xC).
    ///
    /// The runtime performs no init/cleanup for these, so the exact VB scalar
    /// type (Integer/Long/Single/Boolean/…) is not recoverable from the
    /// metadata; the raw nibble is preserved for callers that want it.
    Value(u8),
    /// Unknown / unobserved nibble.
    Unknown(u8),
}

impl ControlPropertyType {
    /// Converts a raw 4-bit type code to a [`ControlPropertyType`].
    pub fn from_raw(raw: u8) -> Self {
        match raw & 0x0F {
            1 => Self::String,
            2 => Self::Variant,
            3 => Self::Object,
            4 => Self::FixedString,
            5 => Self::Array,
            6 => Self::FixedArray,
            9 => Self::Udt,
            n @ (0 | 7 | 8 | 0xA | 0xB | 0xC) => Self::Value(n),
            n => Self::Unknown(n),
        }
    }

    /// Returns the resource-release action the runtime performs at destruct.
    ///
    /// Verified against `CleanupSingleEntry` (0x66016AAA).
    pub fn cleanup_action(self) -> CleanupAction {
        match self {
            Self::String | Self::FixedString => CleanupAction::FreeString,
            Self::Variant => CleanupAction::FreeVariant,
            Self::Object => CleanupAction::ReleaseObject,
            Self::Array => CleanupAction::DestroyArray,
            Self::FixedArray => CleanupAction::UnlockArray,
            Self::Udt => CleanupAction::DestructRecord,
            Self::Value(_) | Self::Unknown(_) => CleanupAction::None,
        }
    }

    /// Returns `true` if this member holds a heap resource freed on destruct.
    ///
    /// Equivalent to `cleanup_action() != CleanupAction::None`. Reference
    /// members (strings, variants, objects, arrays, records) are the
    /// high-signal members for malware triage.
    #[inline]
    pub fn is_reference(self) -> bool {
        self.cleanup_action() != CleanupAction::None
    }
}

impl fmt::Display for ControlPropertyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::String | Self::FixedString => write!(f, "String"),
            Self::Variant => write!(f, "Variant"),
            Self::Object => write!(f, "Object"),
            Self::Array | Self::FixedArray => write!(f, "Array"),
            Self::Udt => write!(f, "UDT"),
            Self::Value(n) => write!(f, "Value{n}"),
            Self::Unknown(n) => write!(f, "Type{n}"),
        }
    }
}

/// A single class/form instance property initialization entry.
///
/// Each entry describes a member that needs init and/or cleanup in the instance
/// data buffer. The runtime's `ResolvePropertyTarget` (0x66016937) computes the
/// target address as `instance_base + frame_offset`.
#[derive(Debug, Clone, Copy)]
pub struct ControlPropertyEntry<'a> {
    bytes: &'a [u8],
}

impl<'a> ControlPropertyEntry<'a> {
    /// Minimum entry size (4-byte header).
    pub const HEADER_SIZE: usize = 4;

    /// Target offset within instance data buffer at entry+0x00.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if the backing buffer is shorter than the header.
    #[inline]
    pub fn frame_offset(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x00)
    }

    /// Raw type byte at entry+0x02.
    ///
    /// Bits \[3:0\] are the [`ControlPropertyType`] nibble; bits \[7:4\] are
    /// modifier flags consumed by the runtime in array/record edge cases.
    /// Returns 0 if the backing buffer is shorter than the header.
    #[inline]
    pub fn raw_type(&self) -> u8 {
        self.bytes.get(0x02).copied().unwrap_or(0)
    }

    /// Property type (low 4 bits of the type byte).
    ///
    /// Returns [`ControlPropertyType::Value(0)`](ControlPropertyType::Value) if
    /// the backing buffer is shorter than the header (raw byte defaults to 0).
    pub fn property_type(&self) -> ControlPropertyType {
        ControlPropertyType::from_raw(self.raw_type())
    }

    /// Resource-release action for this member at object destruct.
    ///
    /// Convenience for `self.property_type().cleanup_action()`.
    #[inline]
    pub fn cleanup_action(&self) -> CleanupAction {
        self.property_type().cleanup_action()
    }

    /// Flags byte at entry+0x03.
    ///
    /// Bit 2 (`0x04`) raises the entry stride floor to 6 bytes; bit 5 (`0x20`)
    /// widens a scalar member's stride to 8 bytes. Returns 0 if the backing
    /// buffer is shorter than the header.
    #[inline]
    pub fn flags(&self) -> u8 {
        self.bytes.get(0x03).copied().unwrap_or(0)
    }

    /// Type-dependent data bytes starting at entry+0x04.
    pub fn data(&self) -> &'a [u8] {
        self.bytes.get(Self::HEADER_SIZE..).unwrap_or(&[])
    }

    /// Total size (byte stride to the next entry) of this entry.
    ///
    /// Faithful port of `CalcPropertyDataSize` (0x660169D3); the MLIL of
    /// `CalcControlPropertyEntrySize` (0x66016972) returns that value verbatim,
    /// so it already includes the 4-byte header and is the exact advance the
    /// runtime uses. The flag byte at +0x03 adjusts the stride: bit 2 sets a
    /// 6-byte floor, bit 5 widens scalar members to 8.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`]/[`Error::ArithmeticOverflow`] if a SafeArray
    /// entry's inline descriptor cannot be read or its size computation overflows.
    pub fn total_size(&self) -> Result<usize, Error> {
        let nibble = self.raw_type() & 0x0F;
        let flags = self.flags();
        let floor: usize = if flags & 0x04 != 0 { 6 } else { 0 };
        let size = match nibble {
            // Empty / unobserved value nibbles: runtime returns 0. The iterator
            // floors this to HEADER_SIZE to stay deterministic on malformed data.
            0 => 0,
            // String / Variant / Object / 4-byte value: 4 bytes, widened to 8
            // when flag bit 5 is set; never below the 6-byte floor.
            1 | 2 | 3 | 0x0B => {
                let base: usize = if flags & 0x20 != 0 { 8 } else { 4 };
                base.max(floor)
            }
            // Fixed-length string / 10-byte value: 10 bytes.
            4 | 0x0A => 0x0A,
            // Dynamic array: size comes from the inline SafeArray descriptor.
            5 => return self.calc_safearray_total_size(),
            // Fixed/locked array: 4 bytes, honoring the 6-byte floor.
            6 => 4usize.max(floor),
            // 6-byte inline value.
            8 => 6,
            // UDT / record: fixed 0x1C-byte entry (carries a nested table ptr).
            9 => 0x1C,
            // Other nibbles: runtime returns 0.
            _ => 0,
        };
        Ok(size)
    }

    /// Computes the total entry stride for a SafeArray from its inline descriptor.
    ///
    /// Mirrors the `case 5` arm of `CalcPropertyDataSize`: base is `0x28`
    /// (`0x38` when the element-info byte at +0x08 has bits `0x60` set), plus
    /// 8 bytes per extra dimension, plus 4 when the element-flags byte has any
    /// of its top three bits set. The base already includes the 4-byte header.
    fn calc_safearray_total_size(&self) -> Result<usize, Error> {
        // Determine descriptor offset within entry.
        let elem_info = self.bytes.get(0x08).copied().unwrap_or(0);
        let desc_offset: usize = if elem_info & 0x60 != 0 { 0x20 } else { 0x10 };

        // Read descriptor: u16 dim_count + u8 elem_flags.
        let needed = desc_offset
            .checked_add(3)
            .ok_or(Error::ArithmeticOverflow {
                context: "calc_safearray_total_size desc_offset+3",
            })?;
        if self.bytes.len() < needed {
            // Not enough data — use a safe minimum.
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

        // Base size depends on element info.
        let base: usize = if elem_info & 0x60 != 0 { 0x38 } else { 0x28 };

        // Per-dimension data: 8 bytes per dim, minus 8 (first dim is in the base).
        let dim_data = if dim_count > 0 {
            dim_count.saturating_sub(1).saturating_mul(8)
        } else {
            0
        };

        // Extra 4 bytes if element type has upper bits set.
        let elem_extra: usize = if elem_flags & 0xE0 != 0 { 4 } else { 0 };

        base.checked_add(dim_data)
            .and_then(|v| v.checked_add(elem_extra))
            .ok_or(Error::ArithmeticOverflow {
                context: "calc_safearray_total_size base+dim_data+elem_extra",
            })
    }
}

/// Iterator over class/form instance property initialization entries.
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
        // Floor the stride to HEADER_SIZE so a degenerate 0-size nibble can't
        // stall the iterator on malformed data.
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
        // Verified resource types from CleanupSingleEntry.
        assert_eq!(
            ControlPropertyType::from_raw(1),
            ControlPropertyType::String
        );
        assert_eq!(
            ControlPropertyType::from_raw(2),
            ControlPropertyType::Variant
        );
        assert_eq!(
            ControlPropertyType::from_raw(3),
            ControlPropertyType::Object
        );
        assert_eq!(
            ControlPropertyType::from_raw(4),
            ControlPropertyType::FixedString
        );
        assert_eq!(ControlPropertyType::from_raw(5), ControlPropertyType::Array);
        assert_eq!(
            ControlPropertyType::from_raw(6),
            ControlPropertyType::FixedArray
        );
        assert_eq!(ControlPropertyType::from_raw(9), ControlPropertyType::Udt);
        // Inline value nibbles preserve the raw value.
        assert_eq!(
            ControlPropertyType::from_raw(0xB),
            ControlPropertyType::Value(0xB)
        );
        assert_eq!(format!("{}", ControlPropertyType::String), "String");
        assert_eq!(format!("{}", ControlPropertyType::Object), "Object");
        assert_eq!(format!("{}", ControlPropertyType::Udt), "UDT");
    }

    #[test]
    fn test_cleanup_actions() {
        // Each resource type maps to the runtime release call it triggers.
        assert_eq!(
            ControlPropertyType::String.cleanup_action(),
            CleanupAction::FreeString
        );
        assert_eq!(
            ControlPropertyType::FixedString.cleanup_action(),
            CleanupAction::FreeString
        );
        assert_eq!(
            ControlPropertyType::Variant.cleanup_action(),
            CleanupAction::FreeVariant
        );
        assert_eq!(
            ControlPropertyType::Object.cleanup_action(),
            CleanupAction::ReleaseObject
        );
        assert_eq!(
            ControlPropertyType::Array.cleanup_action(),
            CleanupAction::DestroyArray
        );
        assert_eq!(
            ControlPropertyType::FixedArray.cleanup_action(),
            CleanupAction::UnlockArray
        );
        assert_eq!(
            ControlPropertyType::Udt.cleanup_action(),
            CleanupAction::DestructRecord
        );
        assert_eq!(
            ControlPropertyType::Value(0xB).cleanup_action(),
            CleanupAction::None
        );
        // Reference predicate.
        assert!(ControlPropertyType::Object.is_reference());
        assert!(!ControlPropertyType::Value(0xB).is_reference());
    }

    // Real SafeArray entry from Cls_CRC32 (full entry with descriptor).
    const CLS_CRC32_SA_ENTRY: [u8; 0x30] = [
        0x38, 0x00, 0x05, 0x00, // +0x00: offset=0x38, type=5 (Array), flags=0
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
    fn test_safearray_entry() {
        let entry = ControlPropertyEntry {
            bytes: &CLS_CRC32_SA_ENTRY,
        };
        assert_eq!(entry.frame_offset().unwrap(), 0x38);
        assert_eq!(entry.property_type(), ControlPropertyType::Array);
        assert_eq!(entry.cleanup_action(), CleanupAction::DestroyArray);
        assert_eq!(entry.flags(), 0x00);
        // Total: base(0x28) + dim_data(0) + elem_extra(4) = 0x2C (header included).
        assert_eq!(entry.total_size().unwrap(), 0x2C);
    }

    #[test]
    fn test_object_entry_stride() {
        // Nibble 3 = Object. Runtime stride is exactly 4 (just {offset,type});
        // the member is a 4-byte IDispatch slot in the instance buffer.
        let data: [u8; 8] = [0x34, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00];
        let entry = ControlPropertyEntry { bytes: &data };
        assert_eq!(entry.property_type(), ControlPropertyType::Object);
        assert_eq!(entry.cleanup_action(), CleanupAction::ReleaseObject);
        assert_eq!(entry.total_size().unwrap(), 4);
    }

    #[test]
    fn test_scalar_entry_widen_flag() {
        // Nibble 0xB (inline value), flag bit 5 set → stride widens to 8.
        let data: [u8; 12] = [
            0x10, 0x00, 0x0B, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let entry = ControlPropertyEntry { bytes: &data };
        assert_eq!(entry.property_type(), ControlPropertyType::Value(0xB));
        assert_eq!(entry.cleanup_action(), CleanupAction::None);
        assert_eq!(entry.total_size().unwrap(), 8);
    }

    #[test]
    fn test_fixed_string_and_udt_stride() {
        // Fixed-length string (nibble 4) → 10-byte entry.
        let fs: [u8; 10] = [0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00];
        let fs_entry = ControlPropertyEntry { bytes: &fs };
        assert_eq!(fs_entry.property_type(), ControlPropertyType::FixedString);
        assert_eq!(fs_entry.cleanup_action(), CleanupAction::FreeString);
        assert_eq!(fs_entry.total_size().unwrap(), 0x0A);

        // UDT (nibble 9) → 0x1C-byte entry.
        let udt: [u8; 4] = [0x00, 0x00, 0x09, 0x00];
        let udt_entry = ControlPropertyEntry { bytes: &udt };
        assert_eq!(udt_entry.property_type(), ControlPropertyType::Udt);
        assert_eq!(udt_entry.total_size().unwrap(), 0x1C);
    }

    #[test]
    fn test_iter_empty() {
        let iter = ControlPropertyIter::new(&[], 0);
        assert_eq!(iter.count(), 0);
    }
}
