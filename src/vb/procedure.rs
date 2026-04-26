//! ProcDscInfo (RTMI) structure parser.
//!
//! `ProcDscInfo` trails each P-Code byte stream and contains the frame size,
//! argument size, and a pointer to the parent [`ObjectInfo`](super::object::ObjectInfo).
//!
//! The critical relationship for locating P-Code bytes:
//!
//! ```text
//! P-Code Start = &ProcDscInfo - ProcDscInfo.wPCodeBackOffset
//! ```
//!
//! # Runtime Confirmation (ProcCallEngine_Body at 0x66108C00)
//!
//! The first dword of ProcDscInfo is dereferenced as an ObjectInfo pointer:
//! - `*ProcDscInfo` → ObjectInfo
//! - `ObjectInfo.lpConstants` (+0x34) → constant pool base for P-Code execution
//! - `ObjectInfo.lpObjectTable` (+0x04) → ObjectTable → project data
//!
//! # Variable-Length Structure
//!
//! ProcDscInfo is **not** a fixed-size struct. The base header is 0x18 bytes,
//! followed by an error handler table whose size is given by `wErrTableSize`
//! (+0x18). Total size = `wTotalSize` (+0x0A) = 0x18 + wErrTableSize.

use std::fmt;

use crate::{
    error::Error,
    util::{read_u16_le, read_u32_le},
    vb::controlprop::ControlPropertyIter,
};

/// View over a cleanup/property table.
///
/// This is the common table format used by both the primary cleanup table
/// (at ProcDscInfo +0x18, processed by `InitLocalCleanupAll`) and the
/// secondary table (immediately following table 1, purpose unknown —
/// not processed by MSVBVM60.DLL during normal method entry/exit).
///
/// # Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 2 | `wSize` — total table size in bytes (including this header) |
/// | 0x02 | 2 | Reserved (always 0) |
/// | 0x04 | 2 | `wCount` — entries to actively process on exit/error |
/// | 0x06 | 2 | `wTotal` — total entry count in the table |
/// | 0x08 | 4 | Flags (bit 0 at byte +0x0B checked by `InitLocalCleanupEntries`) |
/// | 0x0C | var | [`ControlPropertyEntry`](super::controlprop::ControlPropertyEntry) records |
///
/// Minimum size is 0x0C (header only, no entries).
#[derive(Clone, Copy, Debug)]
pub struct CleanupTable<'a> {
    bytes: &'a [u8],
}

impl<'a> CleanupTable<'a> {
    /// Size of the fixed header before entries.
    pub const HEADER_SIZE: usize = 0x0C;

    /// Parses a cleanup table from the given byte slice.
    ///
    /// The slice must be at least [`HEADER_SIZE`](Self::HEADER_SIZE) bytes.
    /// The actual table extent is [`size`](Self::size) bytes.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < Self::HEADER_SIZE {
            return None;
        }
        let size = read_u16_le(data, 0x00).ok()? as usize;
        if size < Self::HEADER_SIZE || size > data.len() {
            return None;
        }
        Some(Self {
            bytes: data.get(..size)?,
        })
    }

    /// Total table size in bytes (header + entries) at offset 0x00.
    #[inline]
    pub fn size(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x00)
    }

    /// Number of entries to actively process on exit/error at offset 0x04.
    ///
    /// Used by `InitLocalCleanupEntries` as the iteration limit for
    /// entries requiring resource release.
    #[inline]
    pub fn count(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x04)
    }

    /// Total number of entries in the table at offset 0x06.
    ///
    /// May exceed [`count`](Self::count) — entries beyond `count` exist
    /// in the table but are not actively processed for cleanup.
    #[inline]
    pub fn total(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x06)
    }

    /// Flags dword at offset 0x08.
    ///
    /// Bit 0 of byte +0x0B is checked by `InitLocalCleanupEntries` to
    /// skip the first entry when set.
    #[inline]
    pub fn flags(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x08)
    }

    /// Returns `true` if the table has any entries.
    #[inline]
    pub fn has_entries(&self) -> bool {
        self.total().unwrap_or(0) > 0
    }

    /// Returns an iterator over the table's entries.
    ///
    /// Each entry is a [`ControlPropertyEntry`](super::controlprop::ControlPropertyEntry)
    /// with a frame offset and type. For cleanup tables, the frame offset
    /// is a **signed i16** (negative offset from EBP), unlike instance
    /// data entries which use unsigned offsets.
    pub fn entries(&self) -> ControlPropertyIter<'a> {
        if self.bytes.len() > Self::HEADER_SIZE {
            let total = self.total().unwrap_or(0);
            match self.bytes.get(Self::HEADER_SIZE..) {
                Some(rest) => ControlPropertyIter::new(rest, total),
                None => ControlPropertyIter::new(&[], 0),
            }
        } else {
            ControlPropertyIter::new(&[], 0)
        }
    }

    /// Raw bytes of the table (header + entries).
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// View over a ProcDscInfo (RTMI) structure.
///
/// This structure immediately follows the P-Code byte stream for each
/// procedure. The P-Code start address is calculated as:
///
/// ```text
/// pcode_start = address_of(ProcDscInfo) - ProcDscInfo.wPCodeBackOffset
/// ```
///
/// # Layout
///
/// ```text
/// +0x00: Base header (0x18 bytes)
///   +0x00  u32  lpObjectInfo       VA of parent ObjectInfo
///   +0x04  u16  wArgSize           caller arg bytes (like retn N)
///   +0x06  u16  wFrameSize         local variable frame size
///   +0x08  u16  wPCodeBackOffset   P-Code stream size (back-offset)
///   +0x0A  u16  wTotalSize         0x18 + primary_table_size
///   +0x0C  u16  wProcOptFlags      error handling (bit 4=OnError, bit 5=ResumeNext)
///   +0x0E  u16  reserved
///   +0x10  u16  wBosSkipTableOff   Resume instruction-size table offset
///   +0x12  u16  base_iface_slot    (init_event_offset/4) - 1
///   +0x14  u16  reserved
///   +0x16  u16  reserved
///
/// +0x18: Primary CleanupTable (processed by InitLocalCleanupAll)
///   +0x00  u16  wSize              table size including this header
///   +0x02  u16  reserved
///   +0x04  u16  wCount             entries to process on exit/error
///   +0x06  u16  wTotal             total entry count
///   +0x08  u32  flags
///   +0x0C  var  ControlPropertyEntry[] records
///
/// +0x18 + primary_size: Secondary CleanupTable (NOT processed by runtime)
///   Same header format as primary table. Purpose unknown —
///   not read by MSVBVM60.DLL during method entry/exit.
///   Always present (minimum 0x0C bytes).
/// ```
///
/// The primary cleanup table describes local variables needing resource
/// release on procedure exit or error (strings via `SysFreeString`, COM
/// objects via `IUnknown::Release`, SafeArrays via `SafeArrayDestroy`, etc.).
///
/// `wTotalSize` at +0x0A only covers `0x18 + primary_table_size`. Use
/// [`actual_size`](Self::actual_size) for the true extent including the
/// secondary table. The next method's P-Code starts immediately after.
#[derive(Clone, Copy, Debug)]
pub struct ProcDscInfo<'a> {
    /// Raw backing bytes borrowed from the PE file buffer.
    bytes: &'a [u8],
}

impl<'a> ProcDscInfo<'a> {
    /// Minimum size needed to read the fixed fields (through +0x1C).
    pub const MIN_SIZE: usize = 0x1E;

    /// Size of the fixed header portion (before error handler table).
    pub const HEADER_SIZE: usize = 0x18;

    /// Parses a ProcDscInfo from the given byte slice.
    ///
    /// Reads at least [`MIN_SIZE`](Self::MIN_SIZE) bytes. The full structure
    /// may be larger — use [`total_size`](Self::total_size) to determine
    /// the actual extent.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < MIN_SIZE`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::MIN_SIZE {
            return Err(Error::TooShort {
                expected: Self::MIN_SIZE,
                actual: data.len(),
                context: "ProcDscInfo",
            });
        }
        // Keep all available data (structure is variable-length)
        Ok(Self { bytes: data })
    }

    /// Virtual address of the parent [`ObjectInfo`](super::object::ObjectInfo)
    /// structure at offset 0x00.
    ///
    /// Read the constant pool base via [`read_constants_va`]:
    /// ```ignore
    /// let oi_data = map.slice_from_va(pdi.object_info_va()?, OBJECT_INFO_MIN_SIZE)?;
    /// let const_va = read_constants_va(oi_data);
    /// ```
    ///
    /// The runtime's ProcCallEngine_Body dereferences this to access:
    /// - [`ObjectInfo::constants_va`](super::object::ObjectInfo::constants_va) (+0x34)
    /// - [`ObjectInfo::object_table_va`](super::object::ObjectInfo::object_table_va) (+0x04)
    #[inline]
    pub fn object_info_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x00)
    }

    /// Caller argument bytes to clean on return at offset 0x04.
    ///
    /// Used by the ExitProc opcode handler path (`sub_6610a574`) to adjust
    /// the stack pointer on return, like a stdcall `retn N`.
    /// - Value 0x10 (16) = 4 DWORDs (typical: `this` + 3 COM dispatch args)
    /// - Value 0x04 (4) = 1 DWORD (typical: just `this` pointer)
    #[inline]
    pub fn arg_size(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x04)
    }

    /// Stack frame size for local variables at offset 0x06.
    ///
    /// Confirmed by ProcCallEngine_Body: `sub esp, wFrameSize; memset(0)`.
    #[inline]
    pub fn frame_size(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x06)
    }

    /// P-Code byte stream back-offset at offset 0x08.
    ///
    /// The P-Code bytes are located at `[addr - offset .. addr]`
    /// where `addr` is the address of this ProcDscInfo structure.
    #[inline]
    pub fn pcode_back_offset(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x08)
    }

    /// Alias for [`pcode_back_offset`](Self::pcode_back_offset) (legacy name).
    #[inline]
    pub fn proc_size(&self) -> Result<u16, Error> {
        self.pcode_back_offset()
    }

    /// Total structure size at offset 0x0A.
    ///
    /// Equals `HEADER_SIZE (0x18) + wCleanupTableSize`. The structure is
    /// variable-length due to the local cleanup table.
    #[inline]
    pub fn total_size(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x0A)
    }

    /// Procedure option flags at offset 0x0C as a [`ProcOptFlags`] wrapper.
    ///
    /// Only two bits are used by the P-Code engine (`ProcCallEngine_Body`
    /// in MSVBVM60.DLL, exhaustively verified):
    /// - Bit 4 (`0x10`): Procedure has an `On Error` exception handler.
    /// - Bit 5 (`0x20`): Procedure uses `On Error Resume Next`.
    ///
    /// All other bits are unused/reserved.
    #[inline]
    pub fn proc_opt_flags(&self) -> Result<ProcOptFlags, Error> {
        Ok(ProcOptFlags(read_u16_le(self.bytes, 0x0C)?))
    }

    /// Raw procedure option flags value at offset 0x0C.
    #[inline]
    pub fn proc_opt_flags_raw(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x0C)
    }

    /// Returns `true` if this procedure has an `On Error` handler.
    #[inline]
    pub fn has_error_handler(&self) -> bool {
        self.proc_opt_flags()
            .map(|f| f.has_error_handler())
            .unwrap_or(false)
    }

    /// Returns `true` if this procedure uses `On Error Resume Next`.
    #[inline]
    pub fn has_resume_next(&self) -> bool {
        self.proc_opt_flags()
            .map(|f| f.has_resume_next())
            .unwrap_or(false)
    }

    /// Reserved field at offset 0x0E (not read by MSVBVM60.DLL runtime).
    #[inline]
    pub fn reserved_0e(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x0E)
    }

    /// Operand-size skip table offset at offset 0x10.
    ///
    /// Self-relative offset from the start of ProcDscInfo to a **per-opcode
    /// instruction size table** used by `Resume Next` error recovery.
    ///
    /// # BOS Skip Table Layout (traced from `op_Lead2_Resume` at 0x6610f212)
    ///
    /// ```text
    /// table_base = ProcDscInfo_VA + bos_skip_table_offset
    /// skip_bytes = *(u16*)(table_base + opcode * 2 + 2)
    /// ```
    ///
    /// The table is an array of u16 values with one entry per primary opcode
    /// (0x00-0xFF). Entry `[N+1]` gives the total byte length of instruction
    /// with primary opcode N (including the opcode byte itself). The first
    /// u16 at offset +0 is a sentinel/header (skipped by the `+ 2` in the
    /// runtime lookup).
    ///
    /// For BOS markers (opcode 0 or 1), the table is not consulted — the
    /// instruction size comes directly from the marker's operand byte.
    ///
    /// Zero when the method has no `Resume` / `Resume Next` capability
    /// (i.e., `proc_opt_flags` has no error handling bits set).
    ///
    /// # Error Handler Dispatch
    ///
    /// There is no separate "error handler table" structure. The `On Error
    /// GoTo <label>` statement (opcode 0x4B) stores the handler's P-Code
    /// address directly into the runtime state at `EBP-0x3C`. The BOS skip
    /// table only handles the `Resume Next` case (advancing past the
    /// faulting instruction).
    #[inline]
    pub fn bos_skip_table_offset(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x10)
    }

    /// Base interface method count (minus 1) at offset 0x12.
    ///
    /// Equal to `(OptionalObjectInfo.initialize_event_offset / 4) - 1`,
    /// i.e., the 0-based index of the last dispatch table slot before the
    /// Initialize event. Constant across all methods within the same object.
    /// Not read by MSVBVM60.DLL at runtime — compiler metadata only.
    ///
    /// Known values: Class=2, Form/UserDoc=25, UserControl=25.
    #[inline]
    pub fn base_iface_slot_count(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x12)
    }

    /// Reserved field at offset 0x14 (not read by MSVBVM60.DLL runtime).
    #[inline]
    pub fn reserved_14(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x14)
    }

    /// Reserved field at offset 0x16 (not read by MSVBVM60.DLL runtime).
    #[inline]
    pub fn reserved_16(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x16)
    }

    /// Size of the primary cleanup table at offset 0x18.
    ///
    /// The table starts at ProcDscInfo +0x18 and extends for this many
    /// bytes. Minimum value is 0x0C (header only, no entries).
    ///
    /// `total_size` = 0x18 + `cleanup_table_size`.
    #[inline]
    pub fn cleanup_table_size(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x18)
    }

    /// Reserved field at offset 0x1A (not read by MSVBVM60.DLL runtime).
    #[inline]
    pub fn reserved_1a(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x1A)
    }

    /// Number of cleanup entries to process at offset 0x1C.
    ///
    /// Used by `InitLocalCleanupEntries` (0x660ecaf9) as the iteration limit.
    #[inline]
    pub fn cleanup_count(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x1C)
    }

    /// Total number of cleanup entries at offset 0x1E.
    ///
    /// May be larger than [`cleanup_count`](Self::cleanup_count) — entries
    /// beyond `count` exist but are not actively processed for resource release.
    #[inline]
    pub fn cleanup_total(&self) -> u16 {
        if self.bytes.len() > 0x1F {
            read_u16_le(self.bytes, 0x1E).unwrap_or(0)
        } else {
            0
        }
    }

    /// Returns `true` if this procedure has local variables needing cleanup.
    #[inline]
    pub fn has_cleanup(&self) -> bool {
        self.cleanup_count().unwrap_or(0) > 0 || self.cleanup_total() > 0
    }

    /// Returns the primary [`CleanupTable`] (at ProcDscInfo +0x18).
    ///
    /// This table is processed by `InitLocalCleanupAll` during method entry
    /// and by the exit handlers for resource release. It describes local
    /// variables needing cleanup (strings, COM objects, SafeArrays, etc.).
    pub fn cleanup_table(&self) -> Option<CleanupTable<'a>> {
        let offset = Self::HEADER_SIZE; // 0x18
        let min_len = offset.checked_add(CleanupTable::HEADER_SIZE)?;
        if self.bytes.len() > min_len {
            CleanupTable::parse(self.bytes.get(offset..)?)
        } else {
            None
        }
    }

    /// Returns the secondary [`CleanupTable`] that follows the primary table.
    ///
    /// This table has the same header format as the primary table and is
    /// always present (minimum 0x0C bytes). It is **not** processed by
    /// MSVBVM60.DLL during normal method entry/exit — its purpose is
    /// unknown (possibly compiler/IDE metadata).
    ///
    /// Located at `ProcDscInfo + total_size`, i.e., immediately after the
    /// primary cleanup table.
    pub fn secondary_table(&self) -> Option<CleanupTable<'a>> {
        let offset = self.total_size().ok()? as usize;
        let min_len = offset.checked_add(CleanupTable::HEADER_SIZE)?;
        if offset >= Self::HEADER_SIZE && self.bytes.len() > min_len {
            CleanupTable::parse(self.bytes.get(offset..)?)
        } else {
            None
        }
    }

    /// Actual total size of the ProcDscInfo structure including both
    /// cleanup tables.
    ///
    /// This is `0x18 + primary_table_size + secondary_table_size` and
    /// represents the true extent of the structure in the PE image.
    /// The next method's P-Code bytes start immediately after.
    ///
    /// Note: [`total_size`](Self::total_size) at offset +0x0A only covers
    /// the header and primary table. This method accounts for both tables.
    pub fn actual_size(&self) -> Result<usize, Error> {
        let base = self.total_size()? as usize;
        if let Some(secondary) = self.secondary_table() {
            let sec_size = secondary.size()? as usize;
            base.checked_add(sec_size).ok_or(Error::ArithmeticOverflow {
                context: "ProcDscInfo::actual_size base + secondary",
            })
        } else {
            Ok(base)
        }
    }

    /// Returns an iterator over primary cleanup table entries.
    ///
    /// Each entry describes a local variable that needs resource release
    /// (string, COM object, SafeArray, etc.) on procedure exit or error.
    /// Entry types reuse [`ControlPropertyType`](super::controlprop::ControlPropertyType).
    ///
    /// Note: `frame_offset` in cleanup entries is a **signed i16** (negative
    /// offset from EBP), unlike instance data entries which use unsigned offsets.
    pub fn cleanup_entries(&self) -> ControlPropertyIter<'a> {
        match self.cleanup_table() {
            Some(table) => table.entries(),
            None => ControlPropertyIter::new(&[], 0),
        }
    }

    /// Returns the number of caller arguments (from `arg_size / 4`).
    ///
    /// Each argument is 4 bytes (DWORD) on the x86 stack.
    #[inline]
    pub fn arg_count(&self) -> Result<u16, Error> {
        Ok(self.arg_size()? / 4)
    }
}

/// Offset within ObjectInfo where the constant pool VA is stored.
///
/// This is `ObjectInfo.lpConstants` (+0x34). ProcDscInfo.object_info_va()?
/// points to ObjectInfo, and we read the constant pool base from +0x34.
pub const OBJECT_INFO_CONSTANTS_OFFSET: usize = 0x34;

/// Minimum bytes needed from ObjectInfo to read the constants VA.
pub const OBJECT_INFO_MIN_SIZE: usize = OBJECT_INFO_CONSTANTS_OFFSET + 4;

/// Reads the constant pool base VA from ObjectInfo data.
#[inline]
pub fn read_constants_va(object_info_data: &[u8]) -> Result<u32, Error> {
    read_u32_le(object_info_data, OBJECT_INFO_CONSTANTS_OFFSET)
}

/// Procedure option flags from `ProcDscInfo` offset 0x0C.
///
/// Only two bits are used by the P-Code engine (exhaustively verified
/// against `ProcCallEngine_Body` in MSVBVM60.DLL).
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProcOptFlags(pub u16);

impl ProcOptFlags {
    /// Procedure has an `On Error` exception handler.
    pub const HAS_ERROR_HANDLER: u16 = 0x10;
    /// Procedure uses `On Error Resume Next`.
    pub const HAS_RESUME_NEXT: u16 = 0x20;

    /// Tests whether the given flag bit(s) are set.
    #[inline]
    pub fn has(self, flag: u16) -> bool {
        self.0 & flag != 0
    }

    /// Returns `true` if this procedure has an `On Error` handler.
    #[inline]
    pub fn has_error_handler(self) -> bool {
        self.has(Self::HAS_ERROR_HANDLER)
    }

    /// Returns `true` if this procedure uses `On Error Resume Next`.
    #[inline]
    pub fn has_resume_next(self) -> bool {
        self.has(Self::HAS_RESUME_NEXT)
    }
}

impl fmt::Debug for ProcOptFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ProcOptFlags(0x{:02X}", self.0)?;
        if self.has_error_handler() {
            write!(f, " HAS_ERROR_HANDLER")?;
        }
        if self.has_resume_next() {
            write!(f, " | HAS_RESUME_NEXT")?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for ProcOptFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// P-Code runtime stack frame layout (housekeeping region).
///
/// When `ProcCallEngine_Body` (0x66108C00) enters a P-Code procedure, it
/// establishes an x86 stack frame with 0x88 bytes of runtime housekeeping
/// slots above the user's local variable area. Opcode handlers receive
/// the frame pointer as `arg1` and access slots via `arg1[-N]` indexing.
///
/// This struct documents the layout for P-Code analysis and lifting.
/// The frame is NOT stored in the PE file — it exists only at runtime.
///
/// # Stack Layout (high to low addresses)
///
/// ```text
/// ┌─────────────────────────┐ ← caller's ESP
/// │  caller arguments       │
/// │  return address          │
/// ├─────────────────────────┤ ← EBP (frame pointer, arg1 to opcode handlers)
/// │  saved EBP        [-01] │  EBP-0x04
/// │  state_flag       [-02] │  EBP-0x08  (initially 0)
/// │  saved_seh_link   [-03] │  EBP-0x0C
/// │  (gap)            [-04] │  EBP-0x10
/// │  (gap)            [-05] │  EBP-0x14
/// │  saved_pcode_ip   [-06] │  EBP-0x18
/// │  ... SEH record ...     │  EBP-0x1C..EBP-0x2B
/// │  seh_handler_data [-0B] │  EBP-0x2C
/// │  object_ptr       [-0C] │  EBP-0x30
/// │  (gap)            [-0D] │  EBP-0x34
/// │  error_state      [-0E] │  EBP-0x38  (initially 0)
/// │  error_handler_ip [-0F] │  EBP-0x3C  (On Error GoTo target)
/// │  error_target     [-10] │  EBP-0x40  (resolved handler: 0=off, -2=resume next)
/// │  engine_context   [-11] │  EBP-0x44  (runtime state, has +0x78/+0x98 fields)
/// │  engine_tls       [-12] │  EBP-0x48  (thread-local engine state)
/// │  proc_flags       [-13] │  EBP-0x4C  (error handling mode flags)
/// │  proc_dsc_info    [-14] │  EBP-0x50  (ProcDscInfo/RTMI pointer)
/// │  proc_dsc_arg     [-15] │  EBP-0x54  (ProcDscInfo, original arg2)
/// │  const_pool_va    [-16] │  EBP-0x58  (ObjectInfo.constants_va)
/// │  pcode_ip         [-17] │  EBP-0x5C  (current P-Code instruction pointer)
/// │  prev_exc_link    [-18] │  EBP-0x60  (previous exception chain link)
/// │  (gap)                  │  EBP-0x64..EBP-0x6F
/// │  handler_fn       [-1C] │  EBP-0x70  (dispatch handler function ptr)
/// │  (gap)                  │  EBP-0x74..EBP-0x7F
/// │  saved_ebx        [-20] │  EBP-0x80
/// │  saved_esi        [-21] │  EBP-0x84
/// │  saved_edi        [-22] │  EBP-0x88
/// ├─────────────────────────┤ ← start of user local variables
/// │  local variables        │  EBP-0x88-wFrameSize .. EBP-0x89
/// │  (zeroed by memset)     │  size = ProcDscInfo.wFrameSize
/// └─────────────────────────┘ ← ESP during P-Code execution
/// ```
///
/// # Key Fields for Analysis
///
/// - **`pcode_ip` (EBP-0x5C)**: Updated by branch/call opcodes. The current
///   instruction address.
/// - **`const_pool_va` (EBP-0x58)**: Base VA for all constant pool references
///   (`%s` operand format). Equal to `ObjectInfo.constants_va`.
/// - **`proc_dsc_info` (EBP-0x50)**: Pointer to the ProcDscInfo/RTMI structure.
///   Used by Resume handler for BOS skip table lookup.
/// - **`error_handler_ip` (EBP-0x3C)**: Set by `On Error GoTo <label>` (opcode
///   0x4B). Cleared to 0 by `On Error GoTo 0`. Set to -2 for `Resume Next`.
/// - **`engine_context` (EBP-0x44)**: Pointer to runtime engine state with
///   error tracking (+0x78 = current error info, +0x98 = error code).
pub mod pcode_frame {
    /// Offset of the current P-Code instruction pointer from EBP.
    pub const PCODE_IP: i32 = -0x5C;
    /// Offset of the constant pool base VA from EBP.
    pub const CONST_POOL_VA: i32 = -0x58;
    /// Offset of the ProcDscInfo (RTMI) pointer from EBP.
    pub const PROC_DSC_INFO: i32 = -0x50;
    /// Offset of the error handler P-Code address from EBP.
    pub const ERROR_HANDLER_IP: i32 = -0x3C;
    /// Offset of the resolved error target from EBP.
    /// 0 = disabled, -2 = Resume Next, else = P-Code VA.
    pub const ERROR_TARGET: i32 = -0x40;
    /// Offset of the runtime engine context pointer from EBP.
    pub const ENGINE_CONTEXT: i32 = -0x44;
    /// Offset of the thread-local engine state from EBP.
    pub const ENGINE_TLS: i32 = -0x48;
    /// Offset of the procedure flags (error mode) from EBP.
    pub const PROC_FLAGS: i32 = -0x4C;
    /// Offset of the object/dispatch pointer from EBP.
    pub const OBJECT_PTR: i32 = -0x30;
    /// Offset of the error state from EBP.
    pub const ERROR_STATE: i32 = -0x38;
    /// Offset of the saved P-Code IP (for returns) from EBP.
    pub const SAVED_PCODE_IP: i32 = -0x18;
    /// Offset of the dispatch handler function pointer from EBP.
    pub const HANDLER_FN: i32 = -0x70;
    /// Total size of the housekeeping region (bytes above local vars).
    pub const HOUSEKEEPING_SIZE: u32 = 0x88;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_dsc_info_parse() {
        let mut data = vec![0u8; ProcDscInfo::MIN_SIZE];
        data[0x04..0x06].copy_from_slice(&0x0010u16.to_le_bytes()); // arg_size = 16
        data[0x06..0x08].copy_from_slice(&0x0100u16.to_le_bytes()); // frame_size = 256
        data[0x08..0x0A].copy_from_slice(&0x0050u16.to_le_bytes()); // pcode_back_offset = 80
        data[0x0A..0x0C].copy_from_slice(&0x0024u16.to_le_bytes()); // total_size = 36
        data[0x18..0x1A].copy_from_slice(&0x000Cu16.to_le_bytes()); // cleanup_table_size = 12
        data[0x1C..0x1E].copy_from_slice(&0x0000u16.to_le_bytes()); // cleanup_count = 0
        let pdi = ProcDscInfo::parse(&data).unwrap();
        assert_eq!(pdi.arg_size().unwrap(), 0x0010);
        assert_eq!(pdi.arg_count().unwrap(), 4);
        assert_eq!(pdi.frame_size().unwrap(), 0x0100);
        assert_eq!(pdi.pcode_back_offset().unwrap(), 0x0050);
        assert_eq!(pdi.proc_size().unwrap(), 0x0050); // legacy alias
        assert_eq!(pdi.total_size().unwrap(), 0x0024);
        assert_eq!(pdi.cleanup_table_size().unwrap(), 0x000C);
        assert_eq!(pdi.cleanup_count().unwrap(), 0);
        assert!(!pdi.has_cleanup());
    }

    #[test]
    fn test_proc_dsc_info_with_error_handler() {
        let mut data = vec![0u8; ProcDscInfo::MIN_SIZE];
        data[0x0A..0x0C].copy_from_slice(&0x0054u16.to_le_bytes()); // total_size = 84
        data[0x18..0x1A].copy_from_slice(&0x003Cu16.to_le_bytes()); // cleanup_table_size = 60
        data[0x1C..0x1E].copy_from_slice(&0x0001u16.to_le_bytes()); // cleanup_count = 1
        let pdi = ProcDscInfo::parse(&data).unwrap();
        assert_eq!(pdi.total_size().unwrap(), 0x0054);
        assert_eq!(pdi.cleanup_table_size().unwrap(), 0x003C);
        assert_eq!(pdi.cleanup_count().unwrap(), 1);
        assert!(pdi.has_cleanup());
        // Verify: total = header(0x18) + err_table(0x3C) = 0x54
        assert_eq!(
            ProcDscInfo::HEADER_SIZE as u16 + pdi.cleanup_table_size().unwrap(),
            pdi.total_size().unwrap()
        );
    }

    #[test]
    fn test_proc_dsc_info_too_short() {
        let data = vec![0u8; ProcDscInfo::MIN_SIZE - 1];
        assert!(matches!(
            ProcDscInfo::parse(&data),
            Err(Error::TooShort { .. })
        ));
    }

    #[test]
    fn test_proc_dsc_info_all_fields() {
        let data = vec![0u8; ProcDscInfo::MIN_SIZE];
        let pdi = ProcDscInfo::parse(&data).unwrap();
        let _ = pdi.object_info_va().unwrap();
        let _ = pdi.arg_size().unwrap();
        let _ = pdi.arg_count().unwrap();
        let _ = pdi.pcode_back_offset().unwrap();
        let _ = pdi.total_size().unwrap();
        let _ = pdi.proc_opt_flags().unwrap();
        let _ = pdi.reserved_0e().unwrap();
        let _ = pdi.bos_skip_table_offset().unwrap();
        let _ = pdi.base_iface_slot_count().unwrap();
        let _ = pdi.reserved_14().unwrap();
        let _ = pdi.reserved_16().unwrap();
        let _ = pdi.cleanup_table_size().unwrap();
        let _ = pdi.reserved_1a().unwrap();
        let _ = pdi.cleanup_count().unwrap();
        let _ = pdi.has_cleanup();
    }

    #[test]
    fn test_read_constants_va() {
        let mut data = vec![0u8; OBJECT_INFO_MIN_SIZE];
        data[0x34..0x38].copy_from_slice(&0x00405000u32.to_le_bytes());
        assert_eq!(read_constants_va(&data).unwrap(), 0x00405000);
    }

    // Real data from vb_inject sample, method_2B
    #[test]
    fn test_real_method_2b() {
        let data: [u8; 0x1E] = [
            0xD8, 0x21, 0x41, 0x00, // +0x00: lpObjectInfo = 0x004121D8
            0x10, 0x00, // +0x04: wArgSize = 16
            0x08, 0x00, // +0x06: wFrameSize = 8
            0x08, 0x00, // +0x08: wPCodeBackOffset = 8
            0x24, 0x00, // +0x0A: wTotalSize = 36
            0x00, 0x00, // +0x0C: wProcOptFlags = 0
            0x00, 0x00, // +0x0E
            0x00, 0x00, // +0x10
            0x19, 0x00, // +0x12: 25 (constant per object)
            0x00, 0x00, // +0x14
            0x00, 0x00, // +0x16
            0x0C, 0x00, // +0x18: wErrTableSize = 12
            0x00, 0x00, // +0x1A
            0x00, 0x00, // +0x1C: wErrBranchCount = 0
        ];
        let pdi = ProcDscInfo::parse(&data).unwrap();
        assert_eq!(pdi.object_info_va().unwrap(), 0x004121D8);
        assert_eq!(pdi.arg_size().unwrap(), 16);
        assert_eq!(pdi.arg_count().unwrap(), 4);
        assert_eq!(pdi.frame_size().unwrap(), 8);
        assert_eq!(pdi.pcode_back_offset().unwrap(), 8);
        assert_eq!(pdi.total_size().unwrap(), 0x24);
        assert!(!pdi.has_cleanup());
        // Verify: total = 0x18 + err_table(0x0C) = 0x24
        assert_eq!(
            0x18 + pdi.cleanup_table_size().unwrap(),
            pdi.total_size().unwrap()
        );
    }
}
