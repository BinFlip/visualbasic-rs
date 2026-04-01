//! Event sink structures for VB6 control event dispatch.
//!
//! VB6 controls fire events (Click, DblClick, KeyPress, etc.) through COM
//! connection point interfaces. Each control has an [`EventSinkVtable`] that
//! maps event slots to handler methods. The handler VAs point to either
//! P-Code [`EventHandlerThunk`]s or native [`NativeEventThunk`]s.

use core::fmt;

use crate::{addressmap::AddressMap, error::Error, util::read_u32_le};

/// Parsed P-Code event handler thunk (20-byte dual-entry method stub).
///
/// VB6 methods use a compact 0x14-byte stub with **two entry points**:
///
/// ```text
/// +0x00  B8 XX XX XX XX   mov eax, event_dispatch_id  <- event sink entry
/// +0x05  66 3D            cmp ax, imm16 (overlaps +0x07)
/// +0x07  33 C0            xor eax, eax                <- method table entry
/// +0x09  BA XX XX XX XX   mov edx, ProcDscInfo_VA
/// +0x0E  68 XX XX XX XX   push return_handler_va
/// +0x13  C3               ret                         -> tail-call ProcCallEngine
/// ```
///
/// The event sink vtable points to +0x00, where `eax` is loaded with the
/// event dispatch ID before falling through to the P-Code engine. The method
/// dispatch table points to +0x07, where `eax` is cleared (direct call, no
/// event). The `66 3D` at +0x05 is a `cmp ax, imm16` that harmlessly overlaps
/// with the `xor eax, eax` bytes — a VB6 compiler space optimization.
#[derive(Clone, Copy, Debug)]
pub struct EventHandlerThunk {
    /// Event dispatch ID passed in eax (from `mov eax, imm32` at +0x00).
    /// Zero when the stub has no event prefix.
    pub event_dispatch_id: u32,
    /// VA of the ProcDscInfo (RTMI) structure (from `mov edx, imm32` at +0x09).
    pub proc_dsc_info_va: u32,
    /// VA of the return handler (from `push imm32` at +0x0E).
    pub return_handler_va: u32,
    /// VA of the method table entry point (+0x07 from the event entry).
    pub method_entry_va: u32,
}

impl EventHandlerThunk {
    /// Total size of the thunk in bytes.
    pub const SIZE: usize = 0x14;

    /// Byte offset from the event entry to the method entry (`xor eax, eax`).
    pub const METHOD_ENTRY_OFFSET: usize = 0x07;

    /// Parses an event handler thunk from the event sink entry point.
    ///
    /// `data` should start at the `mov eax, imm32` instruction (+0x00).
    /// Returns `None` if the byte pattern doesn't match the expected stub.
    pub fn parse_from_event_entry(data: &[u8], event_entry_va: u32) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        if data[0] != 0xB8 {
            return None;
        }
        let event_dispatch_id = u32::from_le_bytes([data[1], data[2], data[3], data[4]]);
        if data[5] != 0x66 || data[6] != 0x3D {
            return None;
        }
        if data[7] != 0x33 || data[8] != 0xC0 {
            return None;
        }
        if data[9] != 0xBA {
            return None;
        }
        let proc_dsc_info_va = u32::from_le_bytes([data[10], data[11], data[12], data[13]]);
        if data[14] != 0x68 {
            return None;
        }
        let return_handler_va = u32::from_le_bytes([data[15], data[16], data[17], data[18]]);
        if data[19] != 0xC3 {
            return None;
        }
        Some(Self {
            event_dispatch_id,
            proc_dsc_info_va,
            return_handler_va,
            method_entry_va: event_entry_va + Self::METHOD_ENTRY_OFFSET as u32,
        })
    }

    /// Parses from the method table entry point (`xor eax, eax` at +0x07).
    ///
    /// Reads 7 bytes backwards to find the event prefix. Returns `None` if
    /// the bytes before the method entry don't match the event thunk pattern
    /// (the method may not have an event prefix).
    pub fn parse_from_method_entry(data: &[u8], method_entry_va: u32) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        Self::parse_from_event_entry(
            data,
            method_entry_va.wrapping_sub(Self::METHOD_ENTRY_OFFSET as u32),
        )
    }
}

impl fmt::Display for EventHandlerThunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "event_id={} rtmi=0x{:08X} method=0x{:08X}",
            self.event_dispatch_id, self.proc_dsc_info_va, self.method_entry_va
        )
    }
}

/// Parsed native event handler thunk (13-byte `this`-adjusting JMP stub).
///
/// Native-compiled VB6 controls use a different thunk pattern:
///
/// ```text
/// +0x00  81 6C 24 04 XX XX XX XX   sub dword [esp+4], this_adjust
/// +0x08  E9 XX XX XX XX            jmp native_handler
/// ```
#[derive(Clone, Copy, Debug)]
pub struct NativeEventThunk {
    /// Adjustment subtracted from the COM `this` pointer.
    pub this_adjust: u32,
    /// VA of the native method body (JMP target).
    pub handler_va: u32,
}

impl NativeEventThunk {
    /// Total size of the native thunk in bytes.
    pub const SIZE: usize = 13;

    /// Parses a native event thunk from the given bytes.
    pub fn parse(data: &[u8], thunk_va: u32) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        if data[0..4] != [0x81, 0x6C, 0x24, 0x04] {
            return None;
        }
        let this_adjust = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if data[8] != 0xE9 {
            return None;
        }
        let rel32 = i32::from_le_bytes([data[9], data[10], data[11], data[12]]);
        let handler_va = (thunk_va as i64 + 13 + rel32 as i64) as u32;
        Some(Self {
            this_adjust,
            handler_va,
        })
    }
}

impl fmt::Display for NativeEventThunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "this_adjust=0x{:X} -> 0x{:08X}",
            self.this_adjust, self.handler_va
        )
    }
}

/// Parsed IUnknown thunk from EventSinkVtable (+0x0C, +0x10, +0x14).
///
/// These are 6-byte `FF 25 imm32` (`jmp [IAT_addr]`) indirect jumps through
/// the Import Address Table to `EVENT_SINK_QueryInterface`, `EVENT_SINK_AddRef`,
/// and `EVENT_SINK_Release` in MSVBVM60.DLL.
///
/// All controls in the same object share the same three thunk VAs.
#[derive(Clone, Copy, Debug)]
pub struct IUnknownThunk {
    /// VA of the IAT entry (target of the `jmp [addr]` instruction).
    pub iat_va: u32,
}

impl IUnknownThunk {
    /// Thunk instruction size in bytes (`FF 25 imm32` = 6 bytes).
    pub const SIZE: usize = 6;

    /// Parses a `jmp [IAT_addr]` thunk from the given bytes.
    ///
    /// Returns `None` if the bytes don't start with `FF 25`.
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < Self::SIZE {
            return None;
        }
        if data[0] != 0xFF || data[1] != 0x25 {
            return None;
        }
        let iat_va = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
        Some(Self { iat_va })
    }
}

impl fmt::Display for IUnknownThunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "jmp [0x{:08X}]", self.iat_va)
    }
}

/// View over a control's event sink vtable.
///
/// This is a COM connection point interface that receives events from the
/// control (Click, DblClick, KeyPress, etc.). The runtime populates the
/// event handler VAs when connecting methods like `Private Sub Command1_Click()`.
///
/// # Layout (variable-length: 0x18 + event_handler_slots * 4)
///
/// | Offset | Field |
/// |--------|-------|
/// | 0x00 | Reserved (always 0) |
/// | 0x04 | Back-pointer to this control's [`ControlInfo`](crate::vb::control::ControlInfo) entry |
/// | 0x08 | Back-pointer to parent [`ObjectInfo`](crate::vb::object::ObjectInfo) |
/// | 0x0C | `EVENT_SINK_QueryInterface` thunk VA — `jmp [IAT]` to MSVBVM60 |
/// | 0x10 | `EVENT_SINK_AddRef` thunk VA — `jmp [IAT]` to MSVBVM60 |
/// | 0x14 | `EVENT_SINK_Release` thunk VA — `jmp [IAT]` to MSVBVM60 |
/// | 0x18+ | Event handler VAs (0 = not connected) |
///
/// The IUnknown thunks at +0x0C-0x14 are 6-byte `FF 25 imm32` indirect jumps
/// through the Import Address Table to MSVBVM60.DLL. All controls in the same
/// object share the same three thunk VAs. Use [`resolve_iunknown_thunk`](Self::resolve_iunknown_thunk)
/// to parse the thunk code. Event handler slots at +0x18+ are zero on disk and
/// populated at runtime.
#[derive(Clone, Copy, Debug)]
pub struct EventSinkVtable<'a> {
    bytes: &'a [u8],
    handler_count: u16,
}

impl<'a> EventSinkVtable<'a> {
    /// Header size before event handler entries.
    pub const HEADER_SIZE: usize = 0x18;

    /// Parses an EventSinkVtable from a byte slice.
    ///
    /// `handler_count` is [`ControlInfo::event_handler_slots`](crate::vb::control::ControlInfo::event_handler_slots).
    pub fn parse(data: &'a [u8], handler_count: u16) -> Result<Self, Error> {
        let total = Self::HEADER_SIZE + handler_count as usize * 4;
        if data.len() < total {
            return Err(Error::TooShort {
                expected: total,
                actual: data.len(),
                context: "EventSinkVtable",
            });
        }
        Ok(Self {
            bytes: &data[..total],
            handler_count,
        })
    }

    /// Back-pointer to this control's ControlInfo entry at +0x04.
    #[inline]
    pub fn control_info_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x04)
    }

    /// Back-pointer to the parent ObjectInfo at +0x08.
    #[inline]
    pub fn object_info_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x08)
    }

    /// VA of the EVENT_SINK_QueryInterface thunk at +0x0C.
    #[inline]
    pub fn query_interface_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x0C)
    }

    /// VA of the EVENT_SINK_AddRef thunk at +0x10.
    #[inline]
    pub fn add_ref_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x10)
    }

    /// VA of the EVENT_SINK_Release thunk at +0x14.
    #[inline]
    pub fn release_va(&self) -> u32 {
        read_u32_le(self.bytes, 0x14)
    }

    /// Number of event handler slots.
    #[inline]
    pub fn handler_count(&self) -> u16 {
        self.handler_count
    }

    /// Returns the VA of the event handler at the given slot index.
    ///
    /// Returns 0 if the event has no handler connected (typical on disk).
    /// Returns `None` if `slot >= handler_count`.
    pub fn handler_va(&self, slot: u16) -> Option<u32> {
        if slot >= self.handler_count {
            return None;
        }
        let offset = Self::HEADER_SIZE + slot as usize * 4;
        Some(read_u32_le(self.bytes, offset))
    }

    /// Resolves an event handler VA into a parsed [`EventHandlerThunk`].
    ///
    /// Reads the 20-byte dual-entry stub at the handler VA and extracts
    /// the event dispatch ID, ProcDscInfo VA, and method entry point.
    /// Returns `None` if the slot is empty or the bytes don't match.
    pub fn resolve_handler_thunk(
        &self,
        slot: u16,
        map: &AddressMap<'_>,
    ) -> Option<EventHandlerThunk> {
        let va = self.handler_va(slot)?;
        if va == 0 {
            return None;
        }
        let data = map.slice_from_va(va, EventHandlerThunk::SIZE).ok()?;
        EventHandlerThunk::parse_from_event_entry(data, va)
    }

    /// Resolves an event handler VA into a parsed [`NativeEventThunk`].
    ///
    /// Tries the `sub [esp+4]; jmp` pattern used by native-compiled controls.
    pub fn resolve_native_thunk(
        &self,
        slot: u16,
        map: &AddressMap<'_>,
    ) -> Option<NativeEventThunk> {
        let va = self.handler_va(slot)?;
        if va == 0 {
            return None;
        }
        let data = map.slice_from_va(va, NativeEventThunk::SIZE).ok()?;
        NativeEventThunk::parse(data, va)
    }

    /// Resolves an IUnknown thunk VA (QI, AddRef, or Release) into a
    /// parsed [`IUnknownThunk`].
    ///
    /// The thunk is a 6-byte `FF 25 imm32` indirect jump through the IAT.
    /// Returns `None` if the VA is zero or the bytes don't match.
    pub fn resolve_iunknown_thunk(&self, va: u32, map: &AddressMap<'_>) -> Option<IUnknownThunk> {
        if va == 0 {
            return None;
        }
        let data = map.slice_from_va(va, IUnknownThunk::SIZE).ok()?;
        IUnknownThunk::parse(data)
    }

    /// Returns the number of connected (non-zero) event handlers.
    pub fn connected_count(&self) -> u16 {
        (0..self.handler_count)
            .filter(|&i| self.handler_va(i).is_some_and(|va| va != 0))
            .count() as u16
    }

    /// Returns an iterator over `(slot_index, handler_va)` for all
    /// connected (non-zero) event handlers.
    pub fn connected_handlers(&self) -> impl Iterator<Item = (u16, u32)> + '_ {
        (0..self.handler_count).filter_map(|i| {
            let va = self.handler_va(i)?;
            if va != 0 { Some((i, va)) } else { None }
        })
    }
}
