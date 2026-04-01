//! GUI table entry parser.
//!
//! The GUI table is pointed to by `VBHeader.lpGuiTable` (+0x4C) and contains
//! one entry per form/UserControl/MDIForm in the project. The entry count
//! is `VBHeader.wFormCount` (+0x44).
//!
//! Each entry is a variable-length record whose first dword gives the
//! offset to the next entry (self-relative linked array, same pattern as
//! the external table).
//!
//! # Runtime Confirmation
//!
//! Processed by `LoadExternalsAndGUIObjects` (0x6602F564) in MSVBVM60.DLL.
//! The runtime reads `+0x28 & 0xF` as a GUI element type code and creates
//! different COM wrapper objects depending on the type.

use core::fmt;

use crate::{addressmap::AddressMap, error::Error, util::read_u32_le, vb::control::Guid};

/// Type of GUI element, derived from `dwObjectType & 0xF`.
///
/// Mapped by the runtime to different COM wrapper class sizes:
/// - Types 0-2 → class 3 (0x30 bytes, standard forms)
/// - Type 3 → class 4 (0x30 bytes, MDI form)
/// - Type 4 → class 5 (0x6C bytes, user control)
/// - Type 5 → class 6 (external form reference)
/// - Types 6-7 → class 7 (0x34 bytes)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuiObjectType {
    /// Standard form (types 0, 1, 2).
    Form,
    /// MDI form (type 3).
    MdiForm,
    /// User control (type 4).
    UserControl,
    /// Property page or external form (type 5).
    PropertyPage,
    /// Other GUI element (types 6, 7).
    Other(u8),
    /// Unknown type value (> 7).
    Unknown(u8),
}

impl GuiObjectType {
    /// Converts the raw 4-bit type code to a [`GuiObjectType`].
    pub fn from_raw(raw: u8) -> Self {
        match raw & 0x0F {
            0..=2 => Self::Form,
            3 => Self::MdiForm,
            4 => Self::UserControl,
            5 => Self::PropertyPage,
            6 | 7 => Self::Other(raw & 0x0F),
            n => Self::Unknown(n),
        }
    }
}

impl fmt::Display for GuiObjectType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Form => write!(f, "Form"),
            Self::MdiForm => write!(f, "MDIForm"),
            Self::UserControl => write!(f, "UserControl"),
            Self::PropertyPage => write!(f, "PropertyPage"),
            Self::Other(n) => write!(f, "GuiType{n}"),
            Self::Unknown(n) => write!(f, "Unknown({n})"),
        }
    }
}

/// Flag bits in `GuiTableEntry.dwObjectType` (+0x28).
///
/// The low nibble (bits 0-3) encodes the [`GuiObjectType`]. Higher bits
/// carry runtime flags traced from `FormWrapper_Init` (0x6603C261) in
/// MSVBVM60.DLL:
///
/// | Bit | Mask | Meaning |
/// |-----|------|---------|
/// | 4 | `0x0010` | Stored to dispatch vtable wrapper |
/// | 5 | `0x0020` | Runtime flag (wrapper init) |
/// | 7 | `0x0080` | Stored to wrapper flags byte |
/// | 15 | `0x8000` | MDI additional flag |
/// | 16 | `0x10000` | Extended type flag |
/// | 17 | `0x20000` | Extended type flag |
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct GuiTypeFlags(pub u32);

impl GuiTypeFlags {
    /// Bit 4: dispatched to wrapper vtable.
    pub const DISPATCH_FLAG: u32 = 0x0010;
    /// Bit 5: runtime initialization flag.
    pub const RUNTIME_FLAG: u32 = 0x0020;
    /// Bit 7: wrapper flags byte flag.
    pub const WRAPPER_FLAG: u32 = 0x0080;
    /// Bit 15: MDI-specific flag.
    pub const MDI_FLAG: u32 = 0x8000;
    /// Bit 16: extended type flag.
    pub const EXTENDED_1: u32 = 0x10000;
    /// Bit 17: extended type flag.
    pub const EXTENDED_2: u32 = 0x20000;

    /// Returns the GUI object type from the low nibble.
    #[inline]
    pub fn object_type(self) -> GuiObjectType {
        GuiObjectType::from_raw((self.0 & 0xF) as u8)
    }

    /// Tests whether the given flag bit(s) are set.
    #[inline]
    pub fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Returns the raw flag bits above the type nibble.
    #[inline]
    pub fn flag_bits(self) -> u32 {
        self.0 & !0xF
    }
}

impl fmt::Debug for GuiTypeFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GuiTypeFlags(0x{:05X} {})", self.0, self.object_type())?;
        let flags: &[(&str, u32)] = &[
            ("DISPATCH", Self::DISPATCH_FLAG),
            ("RUNTIME", Self::RUNTIME_FLAG),
            ("WRAPPER", Self::WRAPPER_FLAG),
            ("MDI", Self::MDI_FLAG),
            ("EXT1", Self::EXTENDED_1),
            ("EXT2", Self::EXTENDED_2),
        ];
        for &(name, val) in flags {
            if self.has(val) {
                write!(f, " | {name}")?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for GuiTypeFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// View over a GUI table entry.
///
/// # Layout (0x50 bytes)
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `dwEntrySize` — offset to next entry (self-relative) |
/// | 0x04 | 16 | `uuidObject` — primary object GUID |
/// | 0x14 | 16 | `uuidSecondary` — secondary GUID (zeros for standard Forms) |
/// | 0x24 | 4 | `dwField24` — stored to runtime wrapper (zero for Forms) |
/// | 0x28 | 4 | `dwObjectType` — type + flag bits (see below) |
/// | 0x2C | 4 | `dwTypeDataDword` — non-zero for MDI (size/offset), 0 for others |
/// | 0x30 | 16 | `guidTypeDataIID` — interface IID for MDI/UserControl, zeros for Form |
/// | 0x40 | 4 | `dwFormDataSize` — compiled form binary size |
/// | 0x44 | 4 | Reserved (zero) |
/// | 0x48 | 4 | `lpFormData` — VA of form design/binary data |
/// | 0x4C | 4 | `dwFormDataSize2` — secondary size field |
///
/// # dwObjectType Bits
///
/// | Bits | Meaning |
/// |------|---------|
/// | 3:0 | GUI type code (0-2=Form, 3=MDI, 4=UserCtl, 5=PropPage) |
/// | 4 | Stored to wrapper dispatch table |
/// | 5 | Runtime flag bit |
/// | 7 | Stored to wrapper flags byte |
/// | 15 | MDI additional flag |
/// | 16-17 | Type 6-7 flags |
#[derive(Clone, Copy, Debug)]
pub struct GuiTableEntry<'a> {
    bytes: &'a [u8],
    /// VA of this entry in the PE image (0 if parsed without VA context).
    va: u32,
}

impl<'a> GuiTableEntry<'a> {
    /// Minimum size of a GUI table entry in bytes.
    pub const MIN_SIZE: usize = 0x50;

    /// Parses a GUI table entry from the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 0x50`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::MIN_SIZE {
            return Err(Error::TooShort {
                expected: Self::MIN_SIZE,
                actual: data.len(),
                context: "GuiTableEntry",
            });
        }
        Ok(Self {
            bytes: &data[..Self::MIN_SIZE],
            va: 0,
        })
    }

    /// Parses a GUI table entry with a known VA.
    pub fn parse_at(data: &'a [u8], va: u32) -> Result<Self, Error> {
        let mut entry = Self::parse(data)?;
        entry.va = va;
        Ok(entry)
    }

    /// VA of this entry in the PE image.
    #[inline]
    pub fn va(&self) -> u32 {
        self.va
    }

    /// Offset to next entry (self-relative) at offset 0x00.
    ///
    /// The next entry is at `this_entry_va + entry_size`.
    #[inline]
    pub fn entry_size(&self) -> u32 {
        read_u32_le(self.bytes, 0x00)
    }

    /// Primary object GUID at offset 0x04 (16 bytes).
    pub fn guid(&self) -> Option<Guid> {
        Guid::from_bytes(&self.bytes[0x04..0x14])
    }

    /// Secondary GUID at offset 0x14 (16 bytes).
    ///
    /// All zeros for standard Forms. Non-zero for MDIForm, UserControl,
    /// and PropertyPage types.
    pub fn secondary_guid(&self) -> Option<Guid> {
        let data = &self.bytes[0x14..0x24];
        if data.iter().all(|&b| b == 0) {
            return None;
        }
        Guid::from_bytes(data)
    }

    /// Field at offset 0x24.
    ///
    /// Stored to the runtime wrapper's internal structure at +0x88.
    /// Zero for standard Forms.
    #[inline]
    pub fn field_24(&self) -> u32 {
        read_u32_le(self.bytes, 0x24)
    }

    /// Raw object type flags at offset 0x28.
    #[inline]
    pub fn object_type_raw(&self) -> u32 {
        read_u32_le(self.bytes, 0x28)
    }

    /// GUI element type (from bits \[3:0\] of `dwObjectType`).
    pub fn object_type(&self) -> GuiObjectType {
        GuiObjectType::from_raw((self.object_type_raw() & 0xF) as u8)
    }

    /// Typed flag wrapper for the full `dwObjectType` at offset 0x28.
    pub fn gui_type_flags(&self) -> GuiTypeFlags {
        GuiTypeFlags(self.object_type_raw())
    }

    /// Type-specific u32 at offset 0x2C.
    ///
    /// Non-zero for MDI forms (offset/size value used by `FormWrapper_Init`).
    /// Zero for Form and UserControl types.
    #[inline]
    pub fn type_data_dword(&self) -> u32 {
        read_u32_le(self.bytes, 0x2C)
    }

    /// Type-specific interface IID at offset 0x30 (16 bytes).
    ///
    /// Contains an interface IID for MDI and UserControl types (from the
    /// project's typelib). All zeros for standard Form types.
    pub fn type_data_iid(&self) -> Option<Guid> {
        let data = &self.bytes[0x30..0x40];
        if data.iter().all(|&b| b == 0) {
            return None;
        }
        Guid::from_bytes(data)
    }

    /// Compiled form binary size at offset 0x40.
    #[inline]
    pub fn form_data_size(&self) -> u32 {
        read_u32_le(self.bytes, 0x40)
    }

    /// VA of form design/binary data at offset 0x48.
    #[inline]
    pub fn form_data_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x48)
    }

    /// Secondary size field at offset 0x4C.
    #[inline]
    pub fn form_data_size2(&self) -> u32 {
        read_u32_le(self.bytes, 0x4C)
    }
}

/// Iterator over GUI table entries.
///
/// Iterates `form_count` entries from the GUI table, advancing by each
/// entry's self-relative size.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct GuiTableIter<'a> {
    map: &'a AddressMap<'a>,
    current_va: u32,
    remaining: u16,
}

impl<'a> GuiTableIter<'a> {
    /// Creates a new GUI table iterator.
    ///
    /// # Arguments
    ///
    /// * `map` - Address map for VA-to-offset resolution.
    /// * `gui_table_va` - VA of the first GUI table entry.
    /// * `form_count` - Number of entries to iterate.
    pub fn new(map: &'a AddressMap<'a>, gui_table_va: u32, form_count: u16) -> Self {
        Self {
            map,
            current_va: gui_table_va,
            remaining: form_count,
        }
    }
}

impl<'a> Iterator for GuiTableIter<'a> {
    type Item = GuiTableEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.current_va == 0 {
            return None;
        }
        let data = self
            .map
            .slice_from_va(self.current_va, GuiTableEntry::MIN_SIZE)
            .ok()?;
        let entry = GuiTableEntry::parse_at(data, self.current_va).ok()?;
        let size = entry.entry_size();
        if size == 0 {
            return None; // Prevent infinite loop
        }
        self.current_va = self.current_va.wrapping_add(size);
        self.remaining -= 1;
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real data from pe_x86_vb_loader sample, single form entry at 0x401E0C
    const LOADER_FORM: [u8; 0x50] = [
        0x50, 0x00, 0x00, 0x00, // +0x00: entry_size = 0x50
        0x6b, 0x5a, 0x0f, 0x22, 0x7d, 0xc6, 0x82, 0x4f, // +0x04: GUID
        0x8d, 0x47, 0x9d, 0x24, 0x3f, 0x9b, 0x39, 0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, // +0x14: zeros
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0x00,
        0x00, // +0x24: zero, +0x28: type=0x90
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // +0x2C: zeros
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc5, 0x00, 0x00,
        0x00, // +0x3C: zero, +0x40: size=0xC5
        0x00, 0x00, 0x00, 0x00, 0x94, 0x1C, 0x40, 0x00, // +0x44: zero, +0x48: VA
        0x4C, 0x00, 0x00, 0x00, // +0x4C: size2=0x4C
    ];

    #[test]
    fn test_parse_loader_form() {
        let entry = GuiTableEntry::parse(&LOADER_FORM).unwrap();
        assert_eq!(entry.entry_size(), 0x50);
        assert!(entry.guid().is_some());
        assert_eq!(entry.object_type(), GuiObjectType::Form);
        assert_eq!(entry.object_type_raw(), 0x90);
        assert_eq!(entry.form_data_size(), 0xC5);
        assert_eq!(entry.form_data_va(), 0x00401C94);
        assert_eq!(entry.form_data_size2(), 0x4C);
    }

    #[test]
    fn test_gui_object_types() {
        assert_eq!(GuiObjectType::from_raw(0), GuiObjectType::Form);
        assert_eq!(GuiObjectType::from_raw(1), GuiObjectType::Form);
        assert_eq!(GuiObjectType::from_raw(2), GuiObjectType::Form);
        assert_eq!(GuiObjectType::from_raw(3), GuiObjectType::MdiForm);
        assert_eq!(GuiObjectType::from_raw(4), GuiObjectType::UserControl);
        assert_eq!(GuiObjectType::from_raw(5), GuiObjectType::PropertyPage);
        assert_eq!(format!("{}", GuiObjectType::Form), "Form");
        assert_eq!(format!("{}", GuiObjectType::MdiForm), "MDIForm");
    }

    #[test]
    fn test_parse_too_short() {
        let short = [0u8; 0x4F];
        assert!(GuiTableEntry::parse(&short).is_err());
    }
}
