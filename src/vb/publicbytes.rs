//! PublicBytes structure parsers.
//!
//! The `PublicObjectDescriptor.public_bytes_va` field points to a structure
//! that varies by object type:
//!
//! - **Standard modules (.bas)**: [`PublicVarTable`] — variable descriptor table
//!   with frame offsets and type codes for each public variable.
//! - **Classes/Forms**: [`ClassFormPublicBytes`] — COM interface GUIDs, instance
//!   size, and runtime function stubs.
//!
//! Both formats share `+0x02` as a u16 read by `EbLoadRunTime` in the runtime.
//! For modules this is the total public variable data frame size; for
//! classes/forms it's the per-instance data size. In both cases the runtime
//! uses it as the `memset` byte count for zero-initializing the instance.
//!
//! # Module Variable Descriptor Layout
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0x00 | 2 | `wTotalSize` — total byte size of the structure |
//! | 0x02 | 2 | `wDataFrameSize` — instance data frame size in bytes |
//! | 0x04 | 2 | Reserved (0) |
//! | 0x06 | 2 | `wVarCount` — number of public variable descriptors |
//!
//! After the 8-byte header, variable descriptors follow as 4-byte entries:
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0x00 | 2 | `wFrameOffset` — byte offset within the module's public data area |
//! | 0x02 | 2 | `wTypeCode` — variable type (see below) |
//!
//! # Known Type Codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0x0001 | Variant or untyped (default in VB6 for `Public x`) |
//! | 0x0003 | Long |
//! | 0x0008 | String |
//! | 0x0105 | Double (with flags?) |
//!
//! # Discovery
//!
//! Reverse-engineered from pe\_x86\_vb\_loader sample. The format is confirmed
//! for standard modules (`mod_Variaveis`, `modUtil`). Class/form objects use
//! a different format at the same VA which is not yet parsed.

use crate::{
    error::Error,
    util::read_u16_le,
    vb::{control::Guid, controlprop::ControlPropertyIter, external::VbBaseType},
};

/// View over a PublicBytes variable descriptor table.
///
/// The format is shared across all object types (modules, forms, classes).
/// The table contains a mix of public variable descriptors and potentially
/// other data entries. Use [`valid_vars`](Self::valid_vars) to iterate only
/// entries that look like valid variable descriptors.
///
/// # Header (12 bytes)
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 2 | `wTotalSize` — total byte size of the structure |
/// | 0x02 | 2 | `wDataFrameSize` — instance data frame size in bytes (see below) |
/// | 0x04 | 2 | `wExtraCount` — number of non-variable entries mixed in |
/// | 0x06 | 2 | `wVarCount` — total entry count (includes extra entries) |
/// | 0x08 | 4 | Padding (always 0) |
///
/// # Data Frame Size (+0x02)
///
/// Read by `EbLoadRunTime` (stored at `basic_class+0x1C`) and by
/// `InitObjectInstances` as the `memset` byte count when zero-initializing
/// the object's instance data area. For modules this is the total byte
/// size of the public variable data frame. For classes/forms this is the
/// per-instance COM object data size (same semantics as
/// [`ClassFormPublicBytes::instance_size`]).
#[derive(Clone, Copy, Debug)]
pub struct PublicVarTable<'a> {
    /// Raw backing bytes borrowed from the PE file buffer.
    bytes: &'a [u8],
    /// Number of entries parsed from the header.
    var_count: u16,
}

impl<'a> PublicVarTable<'a> {
    /// Header size in bytes (8 bytes of header + 4 bytes of sentinel/padding).
    pub const HEADER_SIZE: usize = 12;

    /// Size of each variable descriptor entry in bytes.
    pub const ENTRY_SIZE: usize = 4;

    /// Parses a PublicVarTable from the given byte slice.
    ///
    /// Reads the 12-byte header and validates that enough data exists for
    /// all declared variable entries.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if the slice is shorter than the header
    /// or doesn't contain enough bytes for the declared variable count.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::HEADER_SIZE {
            return Err(Error::TooShort {
                expected: Self::HEADER_SIZE,
                actual: data.len(),
                context: "PublicVarTable header",
            });
        }

        let var_count = read_u16_le(data, 0x06);

        // Entries follow the header; we need at least header + var_count * 4 bytes.
        // Some objects have extra padding entries, so we tolerate shorter data
        // by clamping var_count to what's available.
        let available_entries = (data.len().saturating_sub(Self::HEADER_SIZE)) / Self::ENTRY_SIZE;
        let effective_count = var_count.min(available_entries as u16);

        Ok(Self {
            bytes: data,
            var_count: effective_count,
        })
    }

    /// Total size declared in the header at offset 0x00.
    #[inline]
    pub fn total_size(&self) -> u16 {
        read_u16_le(self.bytes, 0x00)
    }

    /// Number of non-variable entries at offset 0x04.
    ///
    /// When non-zero, some entries in the table are NOT variable descriptors
    /// but other data (COM interface info, string fragments, etc.).
    /// Use [`valid_vars`](Self::valid_vars) to skip these.
    #[inline]
    pub fn extra_count(&self) -> u16 {
        read_u16_le(self.bytes, 0x04)
    }

    /// Instance data frame size in bytes at offset 0x02.
    ///
    /// Read by `EbLoadRunTime` (0x6602f6ce) and stored at `basic_class+0x1C`.
    /// Used by `InitObjectInstances` (0x6602b56d) as the `memset` byte count
    /// to zero-initialize the object's data area.
    ///
    /// For modules: total byte size of the public variable data frame
    /// (e.g., 0x48 for 15 variables ending at offset 0x3C + 8-byte Double).
    /// For classes/forms: equivalent to [`ClassFormPublicBytes::instance_size`].
    #[inline]
    pub fn data_frame_size(&self) -> u16 {
        read_u16_le(self.bytes, 0x02)
    }

    /// Number of public variable descriptors.
    #[inline]
    pub fn var_count(&self) -> u16 {
        self.var_count
    }

    /// Returns the variable descriptor at `index`.
    ///
    /// Returns `None` if `index >= var_count()`.
    pub fn var(&self, index: u16) -> Option<PublicVarEntry> {
        if index >= self.var_count {
            return None;
        }
        let offset = Self::HEADER_SIZE + index as usize * Self::ENTRY_SIZE;
        if offset + Self::ENTRY_SIZE > self.bytes.len() {
            return None;
        }
        Some(PublicVarEntry {
            frame_offset: read_u16_le(self.bytes, offset),
            type_code: read_u16_le(self.bytes, offset + 2),
        })
    }

    /// Returns an iterator over all entries (including potentially invalid ones).
    pub fn vars(&self) -> PublicVarIter<'_> {
        PublicVarIter {
            table: self,
            index: 0,
        }
    }

    /// Returns an iterator over only valid variable descriptors.
    ///
    /// Filters out entries that don't look like variable descriptors
    /// (e.g., COM interface data mixed into the table when `extra_count > 0`).
    pub fn valid_vars(&self) -> impl Iterator<Item = PublicVarEntry> + '_ {
        self.vars().filter(|e| e.is_valid())
    }
}

/// A single public variable descriptor entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicVarEntry {
    /// Byte offset within the module's public data area.
    pub frame_offset: u16,
    /// Type code for the variable.
    ///
    /// Known values: `0x0001` = Variant/untyped, `0x0003` = Long,
    /// `0x0008` = String. Other values are type+flags combinations
    /// whose exact encoding is not fully documented.
    pub type_code: u16,
}

impl PublicVarEntry {
    /// Returns the base type as a [`VbBaseType`] enum.
    ///
    /// The low byte of `type_code` uses the same VB type encoding as
    /// [`VbType`](crate::vb::external::VbType). Note: code `0x01` in
    /// PublicVarTable means Variant (not Null as in VarType), and
    /// `0x0C` also maps to Variant.
    pub fn base_type(&self) -> VbBaseType {
        // PublicVarTable uses slightly different codes than VbType:
        // 0x01 = Variant (not Null), 0x0C = Variant (not Boolean)
        match self.type_code & 0xFF {
            0x01 | 0x0C => VbBaseType::Variant,
            0x09 => VbBaseType::Object,
            other => VbBaseType::from_raw(other as u8),
        }
    }

    /// Returns a human-readable type name based on the low byte of the type code.
    pub fn type_name(&self) -> &'static str {
        self.base_type().name()
    }

    /// Returns the flags in the high byte of the type code.
    ///
    /// Known values: `0x01` in `0x0105` (Double with flag). Exact semantics
    /// of individual bits are not fully documented.
    #[inline]
    pub fn type_flags(&self) -> u8 {
        (self.type_code >> 8) as u8
    }

    /// Returns `true` if this entry looks like a valid variable descriptor.
    ///
    /// Some PublicBytes tables contain non-variable entries (COM interface data,
    /// string fragments) mixed in. This checks that the frame offset is reasonable
    /// and the type code has a known base type.
    pub fn is_valid(&self) -> bool {
        // Exclude null/sentinel entries (offset=0 AND type=0)
        if self.frame_offset == 0 && self.type_code == 0 {
            return false;
        }
        let base = self.type_code & 0xFF;
        let known_type = matches!(
            base,
            0x01 | 0x02
                | 0x03
                | 0x04
                | 0x05
                | 0x06
                | 0x07
                | 0x08
                | 0x09
                | 0x0B
                | 0x0C
                | 0x0D
                | 0x11
        );
        known_type && self.frame_offset < 0x1000
    }
}

/// Iterator over public variable descriptors in a [`PublicVarTable`].
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct PublicVarIter<'a> {
    /// Reference to the parent table.
    table: &'a PublicVarTable<'a>,
    /// Current zero-based position.
    index: u16,
}

impl Iterator for PublicVarIter<'_> {
    type Item = PublicVarEntry;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.table.var(self.index)?;
        self.index += 1;
        Some(entry)
    }
}

/// View over a class/form PublicBytes structure.
///
/// For classes and forms, `PublicObjectDescriptor.public_bytes_va` points to
/// a structure with instance size and control initialization data, NOT the
/// variable descriptor table used by modules.
///
/// # Runtime Access (verified via MSVBVM60.DLL tracing)
///
/// - `EbLoadRunTime`: reads `+0x02` (wInstanceSize) → `basic_class+0x1C`
/// - `sub_6602b56d`: reads `+0x02` for `memset` sizing of instance buffer
/// - `sub_6601505e`: reads `+0x04` (wPropertyCount), `+0x06` (wControlCount),
///   then iterates typed entries starting at `+0x0C`
/// - `+0x00` (wDataSize) is **not read** by the runtime
///
/// # Layout
///
/// | Offset | Size | Field | Runtime reads? |
/// |--------|------|-------|----------------|
/// | 0x00 | 2 | `wDataSize` — compiler metadata (header size) | No |
/// | 0x02 | 2 | `wInstanceSize` — per-object instance size in bytes | Yes |
/// | 0x04 | 2 | `wPropertyCount` — property init entries in the array | Yes |
/// | 0x06 | 2 | `wControlCount` — total control init entries | Yes |
/// | 0x08 | 4 | Reserved / flags | No |
/// | 0x0C | var | Control/property init entries (typed, variable-length) | Yes (when counts > 0) |
///
/// When `wControlCount == 0` (forms with no embedded controls), the data at
/// +0x0C may contain COM interface GUIDs written by the compiler but not
/// read by the runtime.
#[derive(Clone, Copy, Debug)]
pub struct ClassFormPublicBytes<'a> {
    bytes: &'a [u8],
}

impl<'a> ClassFormPublicBytes<'a> {
    /// Minimum size to read the header fields.
    pub const MIN_SIZE: usize = 0x0C;

    /// Parses class/form PublicBytes from the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 0x0C`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::MIN_SIZE {
            return Err(Error::TooShort {
                expected: Self::MIN_SIZE,
                actual: data.len(),
                context: "ClassFormPublicBytes",
            });
        }
        Ok(Self { bytes: data })
    }

    /// Header/data area size at offset 0x00.
    ///
    /// Compiler metadata. Not read by the runtime.
    /// Forms: typically 0x0C. Classes: 0x38+.
    #[inline]
    pub fn data_size(&self) -> u16 {
        read_u16_le(self.bytes, 0x00)
    }

    /// Per-object instance data size at offset 0x02.
    ///
    /// Read by `EbLoadRunTime` and stored at `basic_class+0x1C`.
    /// Also used by `sub_6602b56d` to `memset` the instance buffer.
    /// - Forms: typically 0x44 (68 bytes)
    /// - Classes: typically 0x28-0x60+ depending on member variables
    #[inline]
    pub fn instance_size(&self) -> u16 {
        read_u16_le(self.bytes, 0x02)
    }

    /// Number of property init entries at offset 0x04.
    ///
    /// Inner loop limit in `sub_6601505e`. Zero for forms without
    /// embedded control properties.
    #[inline]
    pub fn property_count(&self) -> u16 {
        read_u16_le(self.bytes, 0x04)
    }

    /// Total number of control init entries at offset 0x06.
    ///
    /// Outer loop count in `sub_6601505e`. Each entry at +0x0C is a
    /// typed control property descriptor with variable length.
    /// Zero for forms without embedded controls.
    #[inline]
    pub fn control_count(&self) -> u16 {
        read_u16_le(self.bytes, 0x06)
    }

    /// Returns `true` if this structure has control initialization entries.
    #[inline]
    pub fn has_controls(&self) -> bool {
        self.control_count() > 0
    }

    /// Raw bytes of the control/property entry array starting at +0x0C.
    ///
    /// When [`has_controls`](Self::has_controls) is true, this contains
    /// typed control property descriptors parsed by `sub_660481fc`.
    /// When false, may contain COM interface GUIDs (compiler metadata).
    pub fn entry_data(&self) -> &'a [u8] {
        if self.bytes.len() > 0x0C {
            &self.bytes[0x0C..]
        } else {
            &[]
        }
    }

    /// Default interface IID at offset 0x0C (when no controls are present).
    ///
    /// Only meaningful when `control_count() == 0`. When controls ARE present,
    /// offset +0x0C contains control property data instead.
    pub fn default_iid(&self) -> Option<Guid> {
        if self.has_controls() || self.bytes.len() < 0x1C {
            return None;
        }
        Guid::from_bytes(&self.bytes[0x0C..0x1C])
    }

    /// Events interface IID at offset 0x1C (when no controls are present).
    ///
    /// Only meaningful when `control_count() == 0`.
    pub fn events_iid(&self) -> Option<Guid> {
        if self.has_controls() || self.bytes.len() < 0x2C {
            return None;
        }
        Guid::from_bytes(&self.bytes[0x1C..0x2C])
    }

    /// Returns an iterator over control/property init entries starting at +0x0C.
    ///
    /// Only meaningful when [`has_controls`](Self::has_controls) is true.
    /// See [`controlprop`](super::controlprop) for entry types and format.
    pub fn control_entries(&self) -> ControlPropertyIter<'a> {
        ControlPropertyIter::new(self.entry_data(), self.control_count())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real data from mod_Variaveis in pe_x86_vb_loader sample
    // 15 public variables, all type 0x0001 except last = 0x0105
    const MOD_VARIAVEIS: [u8; 78] = [
        0x4E, 0x00, 0x48, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x04, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x0C, 0x00, 0x01, 0x00, 0x10, 0x00,
        0x01, 0x00, 0x14, 0x00, 0x01, 0x00, 0x18, 0x00, 0x01, 0x00, 0x1C, 0x00, 0x01, 0x00, 0x20,
        0x00, 0x01, 0x00, 0x24, 0x00, 0x01, 0x00, 0x28, 0x00, 0x01, 0x00, 0x2C, 0x00, 0x01, 0x00,
        0x30, 0x00, 0x01, 0x00, 0x3C, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
        0x00, 0x01, 0x00,
    ];

    // Real data from modUtil — 1 public variable of type Long
    const MOD_UTIL: [u8; 16] = [
        0x10, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        0x00,
    ];

    #[test]
    fn test_parse_mod_variaveis() {
        let table = PublicVarTable::parse(&MOD_VARIAVEIS).unwrap();
        assert_eq!(table.total_size(), 0x4E);
        assert_eq!(table.var_count(), 15);

        // First variable
        let v0 = table.var(0).unwrap();
        assert_eq!(v0.frame_offset, 0x0000);
        assert_eq!(v0.type_code, 0x0001);
        assert_eq!(v0.type_name(), "Variant");

        // Second variable
        let v1 = table.var(1).unwrap();
        assert_eq!(v1.frame_offset, 0x0004);
        assert_eq!(v1.type_code, 0x0001);

        // Iterator count
        assert_eq!(table.vars().count(), 15);
    }

    #[test]
    fn test_parse_mod_util() {
        let table = PublicVarTable::parse(&MOD_UTIL).unwrap();
        assert_eq!(table.total_size(), 0x10);
        assert_eq!(table.var_count(), 1);

        let v0 = table.var(0).unwrap();
        assert_eq!(v0.frame_offset, 0x0000);
        assert_eq!(v0.type_code, 0x0003);
        assert_eq!(v0.type_name(), "Long");
        assert_eq!(v0.type_flags(), 0);
    }

    #[test]
    fn test_var_out_of_range() {
        let table = PublicVarTable::parse(&MOD_UTIL).unwrap();
        assert!(table.var(1).is_none());
    }

    #[test]
    fn test_parse_too_short() {
        assert!(PublicVarTable::parse(&[0; 7]).is_err());
    }

    #[test]
    fn test_type_names() {
        let entry = PublicVarEntry {
            frame_offset: 0,
            type_code: 0x0003,
        };
        assert_eq!(entry.type_name(), "Long");

        let entry = PublicVarEntry {
            frame_offset: 0,
            type_code: 0x0105,
        };
        assert_eq!(entry.type_name(), "Double");
        assert_eq!(entry.type_flags(), 0x01);
    }

    // Real data from Form1 in pe_x86_vb_loader sample (no embedded controls)
    const FORM1_PUBLIC_BYTES: [u8; 0x40] = [
        0x0C, 0x00, 0x44, 0x00, // +0x00: data_size=12, instance_size=68
        0x00, 0x00, 0x00, 0x00, // +0x04: property_count=0, control_count=0
        0x00, 0x00, 0x00, 0x00, // +0x08: reserved
        0x23, 0x3D, 0xFB, 0xFC, 0xFA, 0xA0, 0x68, 0x10, // +0x0C: default IID (no controls)
        0xA7, 0x38, 0x08, 0x00, 0x2B, 0x33, 0x71, 0xB5, 0x22, 0x3D, 0xFB, 0xFC, 0xFA, 0xA0, 0x68,
        0x10, // +0x1C: events IID (no controls)
        0xA7, 0x38, 0x08, 0x00, 0x2B, 0x33, 0x71, 0xB5, 0x02, 0x00, 0x00,
        0x00, // +0x2C: GUID pointer count
        0x68, 0x2F, 0x40, 0x00, // +0x30: VA to default IID
        0x78, 0x2F, 0x40, 0x00, // +0x34: VA to events IID
        0x00, 0x00, 0x00, 0x00, // +0x38: zero
        0x79, 0x4F, 0xAD, 0x33, // +0x3C: unknown
    ];

    // Real data from Cls_CRC32 in pe_x86_vb_loader sample (has controls)
    const CLS_CRC32_PUBLIC_BYTES: [u8; 0x18] = [
        0x38, 0x00, 0x60, 0x00, // +0x00: data_size=56, instance_size=96
        0x01, 0x00, 0x01, 0x00, // +0x04: property_count=1, control_count=1
        0x00, 0x00, 0x00, 0x00, // +0x08: reserved
        0x38, 0x00, 0x05, 0x00, // +0x0C: first control entry (type=5 at +0x0E)
        0x5C, 0x00, 0x55, 0x00, // +0x10: entry data continues...
        0x00, 0x00, 0x65, 0x00, // +0x14: ...
    ];

    #[test]
    fn test_form_no_controls() {
        let cfpb = ClassFormPublicBytes::parse(&FORM1_PUBLIC_BYTES).unwrap();
        assert_eq!(cfpb.data_size(), 0x0C);
        assert_eq!(cfpb.instance_size(), 0x44);
        assert_eq!(cfpb.property_count(), 0);
        assert_eq!(cfpb.control_count(), 0);
        assert!(!cfpb.has_controls());
        // GUIDs available when no controls
        assert!(cfpb.default_iid().is_some());
        assert!(cfpb.events_iid().is_some());
        assert_ne!(cfpb.default_iid(), cfpb.events_iid());
    }

    #[test]
    fn test_class_with_controls() {
        let cfpb = ClassFormPublicBytes::parse(&CLS_CRC32_PUBLIC_BYTES).unwrap();
        assert_eq!(cfpb.data_size(), 0x38);
        assert_eq!(cfpb.instance_size(), 0x60);
        assert_eq!(cfpb.property_count(), 1);
        assert_eq!(cfpb.control_count(), 1);
        assert!(cfpb.has_controls());
        // GUIDs NOT available when controls present (+0x0C is control data)
        assert!(cfpb.default_iid().is_none());
        assert!(cfpb.events_iid().is_none());
        // Entry data is available
        assert!(!cfpb.entry_data().is_empty());
    }

    #[test]
    fn test_class_control_entries() {
        use crate::vb::controlprop::ControlPropertyType;
        let cfpb = ClassFormPublicBytes::parse(&CLS_CRC32_PUBLIC_BYTES).unwrap();
        let entries: Vec<_> = cfpb.control_entries().collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].frame_offset(), 0x38);
        assert_eq!(entries[0].property_type(), ControlPropertyType::SafeArray);
        assert_eq!(entries[0].flags(), 0x00);
    }

    #[test]
    fn test_form_no_control_entries() {
        let cfpb = ClassFormPublicBytes::parse(&FORM1_PUBLIC_BYTES).unwrap();
        assert_eq!(cfpb.control_entries().count(), 0);
    }

    #[test]
    fn test_class_form_too_short() {
        assert!(ClassFormPublicBytes::parse(&[0; 0x0B]).is_err());
    }
}
