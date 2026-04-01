//! ControlInfo structure for GUI controls.
//!
//! Describes ActiveX/VB controls embedded in forms. Each form's
//! [`OptionalObjectInfo`](crate::vb::object::OptionalObjectInfo) points
//! to an array of `ControlInfo` entries via `lpControls`.
//!
//! The exact layout of ControlInfo is not fully documented in public
//! research. The fields below are based on cross-referencing multiple
//! reverse engineering sources (VBDec, python-vb, Semi-VBDecompiler).

use core::fmt;

use crate::{
    error::Error,
    util::{read_u16_le, read_u32_le},
};

/// A COM GUID (CLSID/IID) as stored in PE data — 16 bytes, little-endian.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Guid {
    /// Raw 16-byte GUID in binary form.
    pub bytes: [u8; 16],
}

impl Guid {
    /// Parses a GUID from a 16-byte slice.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&data[..16]);
        Some(Self { bytes })
    }

    /// Returns a human-readable name if this is a well-known VB6 intrinsic control.
    ///
    /// Uses **exact CLSID matching** only — no fuzzy/IID variant guessing.
    /// The lookup table is generated at build time from `data/vb6_control_guids.csv`.
    ///
    /// For reliable control type identification, prefer
    /// [`FormControlType`](crate::vb::formdata::FormControlType) from form binary
    /// data (via [`VbControl::form_control_type`](crate::VbControl::form_control_type)).
    pub fn control_class_name(&self) -> Option<&'static str> {
        generated::lookup_control_name(&self.bytes)
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.bytes;
        let d1 = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
        let d2 = u16::from_le_bytes([b[4], b[5]]);
        let d3 = u16::from_le_bytes([b[6], b[7]]);
        write!(
            f,
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

/// Build-time generated lookup tables from CSV data files.
pub(crate) mod generated {
    include!(concat!(env!("OUT_DIR"), "/vb6_data_generated.rs"));
}

// Event-related types (EventHandlerThunk, NativeEventThunk, EventSinkVtable)

/// View over a ControlInfo structure (0x28 bytes).
///
/// Each entry describes one GUI control on a VB6 form. The array is
/// at [`OptionalObjectInfo::controls_va`](crate::vb::object::OptionalObjectInfo::controls_va)
/// with [`control_count`](crate::vb::object::OptionalObjectInfo::control_count) entries.
///
/// # Layout
///
/// | Offset | Size | Field | Description |
/// |--------|------|-------|-------------|
/// | 0x00 | 2 | `wFlags` | Control flags (always 0x0040 in compiled binaries) |
/// | 0x02 | 2 | `wEventHandlerSlots` | Event handler slot count in the event sink vtable |
/// | 0x04 | 2 | `wDispatchOffset` | Byte offset of this control's event slot in the dispatch vtable |
/// | 0x06 | 2 | Reserved | Always 0 |
/// | 0x08 | 4 | `lpGuid` | VA of 16-byte control CLSID |
/// | 0x0C | 2 | `wIndex` | Control index (Name property ID, 0xFFFF = form default) |
/// | 0x0E | 2 | `wMemberType` | Member type constant (always 3 for normal controls, 0xFFFF for default) |
/// | 0x10 | 4 | `wDispIdCount` / `lpDispIdTable` | On disk: 0. At runtime: DISPID dispatch entry count (u16 at +0x10) |
/// | 0x14 | 4 | `lpDispIdTable` | On disk: 0. At runtime: pointer to DISPID→handler dispatch table |
/// | 0x18 | 4 | `lpEventSinkVtable` | VA of event sink vtable (0x18 header + slots×4) |
/// | 0x1C | 4 | `lpLinkerTypeData` | Per-control-type linker workspace VA (unpatched, not in PE image) |
/// | 0x20 | 4 | `lpName` | VA of control name string (null-terminated ANSI) |
/// | 0x24 | 4 | `dwControlId` | Packed control identifier: `(wMemberType << 16) \| wIndex` |
///
/// # Runtime Fields (+0x10, +0x14)
///
/// The DISPID dispatch fields are zeroed in the compiled binary and populated
/// at runtime by `EVENT_SINK_Invoke_Inner` (0x6600FF9C) in MSVBVM60.DLL:
/// - `+0x10` (u16): Number of entries in the DISPID dispatch table
/// - `+0x14` (u32): Pointer to an array of `{u32 DISPID, u32 handler_offset}` pairs
///
/// The dispatch table maps COM DISPIDs to event handler offsets. The runtime
/// accesses these fields through the event sink vtable's back-pointer at
/// vtable_base+0x04 (resolved by `EventSink_GetVtableBase` at 0x6600B7CC).
///
/// # Control Identifier (+0x24)
///
/// The packed `(wMemberType << 16) | wIndex` value serves as the hash key
/// for runtime control lookup via `ControlNameHashLookup`. `LoadFormControls`
/// passes this dword directly to `CreateControlEntry`.
///
/// # Linker Type Data (+0x1C)
///
/// The VA at +0x1C points to per-control-type data in the linker's workspace
/// address space (typically 0x0073xxxx). Controls with the same CLSID share
/// the same +0x1C value. This pointer is NOT patched to a valid PE VA — it's
/// a vestigial linker artifact. In memory dumps it may be overwritten.
///
/// # Name Resolution
///
/// The control name is at [`name_va`](Self::name_va) (+0x20), NOT at +0x18.
/// The name is a null-terminated ANSI string followed by padding to 4-byte
/// alignment, then a 16-byte interface GUID for the control.
#[derive(Clone, Copy, Debug)]
pub struct ControlInfo<'a> {
    /// Raw backing bytes borrowed from the PE file buffer.
    bytes: &'a [u8],
}

impl<'a> ControlInfo<'a> {
    /// Size of the ControlInfo structure in bytes.
    pub const MIN_SIZE: usize = 0x28;

    /// Parses a ControlInfo from the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 0x28`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::MIN_SIZE {
            return Err(Error::TooShort {
                expected: Self::MIN_SIZE,
                actual: data.len(),
                context: "ControlInfo",
            });
        }
        Ok(Self {
            bytes: &data[..Self::MIN_SIZE],
        })
    }

    /// Control flags at offset 0x00 (u16, always 0x0040 in compiled binaries).
    ///
    /// **Not read by the runtime.** Exhaustive search of MSVBVM60.DLL control
    /// consumers (`CreateControlEntry`, `ControlNameHashLookup`, `LoadFormControls`,
    /// `FormWrapper_Init`, `InitControlProperties`, `EventSink_GetVtableBase`)
    /// confirmed none access this field. Value 0x0040 is compiler/linker metadata
    /// indicating a compiled control entry; other values may exist in IDE/debug
    /// contexts but are irrelevant for static analysis of compiled binaries.
    #[inline]
    pub fn flags(&self) -> u16 {
        read_u16_le(self.bytes, 0x00)
    }

    /// Event handler slot count at offset 0x02.
    ///
    /// Varies by control type (e.g., PictureBox=20, TextBox=24, Menu=15,
    /// CheckBox=1, OptionButton=31).
    #[inline]
    pub fn event_handler_slots(&self) -> u16 {
        read_u16_le(self.bytes, 0x02)
    }

    /// Control type flags at offset 0x00 (u32 view of flags + event_handler_slots).
    #[inline]
    pub fn control_type(&self) -> u32 {
        read_u32_le(self.bytes, 0x00)
    }

    /// Dispatch vtable byte offset at offset 0x04.
    ///
    /// Byte offset of this control's event handler slot within the object's
    /// dispatch vtable. Values are sequential multiples of 4 across controls
    /// in the same form (e.g., 60, 64, 68, 72...), with each control
    /// occupying one 4-byte slot.
    #[inline]
    pub fn dispatch_offset(&self) -> u16 {
        read_u16_le(self.bytes, 0x04)
    }

    /// VA of the control's 16-byte CLSID at offset 0x08.
    #[inline]
    pub fn guid_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x08)
    }

    /// Control index at offset 0x0C.
    ///
    /// Corresponds to the control's Name property index in the VB6 IDE.
    /// Value 0xFFFF indicates the form's default/implicit control.
    #[inline]
    pub fn index(&self) -> u16 {
        read_u16_le(self.bytes, 0x0C)
    }

    /// COM dispatch member type at offset 0x0E (`DESCKIND`).
    ///
    /// Always 3 (`DESCKIND_TYPECOMP`) for normal controls — controls are type
    /// components in the COM IDispatch namespace. 0xFFFF for the form's default
    /// control (the implicit control with `index == 0xFFFF`). Used as the high
    /// word of the packed [`control_id`](Self::control_id) at +0x24 for hash
    /// lookup in `ControlNameHashLookup`.
    #[inline]
    pub fn member_type(&self) -> u16 {
        read_u16_le(self.bytes, 0x0E)
    }

    /// DISPID dispatch count / table at offset 0x10.
    ///
    /// On disk: always 0.
    /// At runtime: the low u16 is the number of entries in the DISPID dispatch
    /// table, used by `EVENT_SINK_Invoke_Inner` for event handler resolution.
    #[inline]
    pub fn dispid_count_or_zero(&self) -> u32 {
        read_u32_le(self.bytes, 0x10)
    }

    /// DISPID dispatch table pointer at offset 0x14.
    ///
    /// On disk: always 0.
    /// At runtime: pointer to an array of `{u32 DISPID, u32 handler_offset}`
    /// pairs. `EVENT_SINK_Invoke_Inner` walks this table to find the handler
    /// for a given COM DISPID.
    #[inline]
    pub fn dispid_table_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x14)
    }

    /// VA of the control's event sink vtable at offset 0x18.
    ///
    /// Points to a variable-length structure:
    ///
    /// | Offset | Field |
    /// |--------|-------|
    /// | +0x00 | null (reserved) |
    /// | +0x04 | back-pointer to this ControlInfo entry |
    /// | +0x08 | back-pointer to parent ObjectInfo |
    /// | +0x0C | EVENT_SINK_QueryInterface thunk VA |
    /// | +0x10 | EVENT_SINK_AddRef thunk VA |
    /// | +0x14 | EVENT_SINK_Release thunk VA |
    /// | +0x18 | event handler VAs ([`event_handler_slots`](Self::event_handler_slots) entries) |
    ///
    /// Total size = `0x18 + event_handler_slots * 4`.
    ///
    /// On disk, the event handler VAs are typically zero (populated at
    /// runtime when event handlers are connected to controls).
    #[inline]
    pub fn event_sink_vtable_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x18)
    }

    /// VA of the control name string at offset 0x20.
    ///
    /// Points to a null-terminated ANSI name string (the control's Name
    /// property from the VB6 IDE, e.g., "Command1", "Timer1").
    /// The name is stored in a shared data region alongside control CLSIDs.
    #[inline]
    pub fn name_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x20)
    }

    /// Per-type linker workspace VA at offset 0x1C.
    ///
    /// Unpatched pointer into the VB6 linker's address space (typically
    /// 0x0073xxxx). Controls with the same CLSID share the same value.
    /// Not a valid VA within the PE image. In memory dumps, this field
    /// may be overwritten by the runtime.
    #[inline]
    pub fn linker_type_data_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x1C)
    }

    /// Packed control identifier at offset 0x24.
    ///
    /// Equals `(member_type << 16) | index`. Used as the hash key by
    /// `ControlNameHashLookup` in the runtime. The value 0xFFFFFFFF
    /// indicates the form's default/implicit control.
    #[inline]
    pub fn control_id(&self) -> u32 {
        read_u32_le(self.bytes, 0x24)
    }
}

/// Iterator over control info entries in an object.
///
/// Created from [`OptionalObjectInfo`](crate::vb::object::OptionalObjectInfo)
/// when iterating controls on a form.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ControlIterator<'a> {
    /// Byte slice spanning the full control info array.
    data: &'a [u8],
    /// Current byte offset into `data`.
    offset: usize,
    /// Number of control entries left to yield.
    remaining: u32,
}

impl<'a> ControlIterator<'a> {
    /// Creates a new iterator over `count` controls starting at `data`.
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice starting at the first ControlInfo entry.
    /// * `count` - Number of controls to iterate.
    pub fn new(data: &'a [u8], count: u32) -> Self {
        Self {
            data,
            offset: 0,
            remaining: count,
        }
    }
}

impl<'a> Iterator for ControlIterator<'a> {
    type Item = Result<ControlInfo<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;

        if self.offset + ControlInfo::MIN_SIZE > self.data.len() {
            return Some(Err(Error::TooShort {
                expected: ControlInfo::MIN_SIZE,
                actual: self.data.len().saturating_sub(self.offset),
                context: "ControlInfo",
            }));
        }

        match ControlInfo::parse(&self.data[self.offset..]) {
            Ok(ctrl) => {
                self.offset += ControlInfo::MIN_SIZE;
                Some(Ok(ctrl))
            }
            Err(e) => Some(Err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_control_info() -> Vec<u8> {
        let mut buf = vec![0u8; ControlInfo::MIN_SIZE];
        buf[0x00..0x02].copy_from_slice(&0x0040u16.to_le_bytes()); // flags
        buf[0x02..0x04].copy_from_slice(&0x0014u16.to_le_bytes()); // event_handler_slots
        buf[0x04..0x06].copy_from_slice(&52u16.to_le_bytes()); // event_count
        buf[0x08..0x0C].copy_from_slice(&0x00405000u32.to_le_bytes()); // guid_va
        buf[0x0C..0x0E].copy_from_slice(&1u16.to_le_bytes()); // index
        buf[0x0E..0x10].copy_from_slice(&3u16.to_le_bytes()); // field_0e
        buf[0x10..0x14].copy_from_slice(&0x00406000u32.to_le_bytes()); // event_table_va
        buf[0x20..0x24].copy_from_slice(&0x00407000u32.to_le_bytes()); // name_va (+0x20)
        buf
    }

    #[test]
    fn test_parse_valid() {
        let data = make_control_info();
        let ctrl = ControlInfo::parse(&data).unwrap();
        assert_eq!(ctrl.flags(), 0x0040);
        assert_eq!(ctrl.event_handler_slots(), 0x0014);
        assert_eq!(ctrl.control_type(), 0x00140040);
        assert_eq!(ctrl.dispatch_offset(), 52);
        assert_eq!(ctrl.guid_va(), 0x00405000);
        assert_eq!(ctrl.index(), 1);
        assert_eq!(ctrl.member_type(), 3);
        assert_eq!(ctrl.dispid_count_or_zero(), 0x00406000);
        assert_eq!(ctrl.name_va(), 0x00407000);
    }

    #[test]
    fn test_parse_too_short() {
        let data = vec![0u8; ControlInfo::MIN_SIZE - 1];
        assert!(matches!(
            ControlInfo::parse(&data),
            Err(Error::TooShort { .. })
        ));
    }

    #[test]
    fn test_control_iterator() {
        // Two controls back-to-back
        let mut data = make_control_info();
        let mut ctrl2 = make_control_info();
        ctrl2[0x0C..0x0E].copy_from_slice(&2u16.to_le_bytes()); // index = 2
        data.extend_from_slice(&ctrl2);

        let iter = ControlIterator::new(&data, 2);
        let results: Vec<_> = iter.collect();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].as_ref().unwrap().index(), 1);
        assert_eq!(results[1].as_ref().unwrap().index(), 2);
    }

    #[test]
    fn test_control_iterator_empty() {
        let data = vec![0u8; 0];
        let iter = ControlIterator::new(&data, 0);
        let results: Vec<_> = iter.collect();
        assert!(results.is_empty());
    }

    #[test]
    fn test_control_iterator_truncated() {
        // Claim 2 controls but only provide data for 1
        let data = make_control_info();
        let iter = ControlIterator::new(&data, 2);
        let results: Vec<_> = iter.collect();
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
    }
}
