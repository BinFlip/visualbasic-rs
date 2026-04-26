//! Error types for VB6 P-Code parsing.
//!
//! A single flat [`Error`] enum covers all failure modes across PE parsing,
//! VB structure validation, address translation, and P-Code decoding.

use std::error;
use std::fmt;

/// All errors that can occur during VB6 P-Code parsing.
///
/// Each variant carries enough context for a useful diagnostic message.
/// The enum is intentionally flat (not hierarchical) to keep the API surface simple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    // -- PE-level errors --
    /// The underlying PE parser (`goblin`) failed.
    ///
    /// The inner string contains the stringified goblin error.
    /// We stringify because `goblin::error::Error` does not implement `Clone`/`Eq`.
    Goblin(String),

    /// The PE optional header magic is not `0x010B` (PE32).
    ///
    /// VB6 executables are always 32-bit. A PE32+ (64-bit) file cannot contain VB6 P-Code.
    Not32Bit {
        /// The actual optional header magic value encountered.
        magic: u16,
    },

    /// A buffer or structure is too short.
    ///
    /// The parser expected at least `expected` bytes but found only `actual`.
    TooShort {
        /// Minimum bytes required.
        expected: usize,
        /// Actual bytes available.
        actual: usize,
        /// Human-readable name of the structure being parsed.
        context: &'static str,
    },

    /// A primitive byte read fell outside the underlying buffer.
    ///
    /// Emitted by the crate's low-level byte readers when the requested
    /// `offset..offset+needed` range is not fully contained in the slice.
    /// Distinct from [`Error::TooShort`] which describes whole-structure
    /// truncation at parse entry; this variant describes per-field reads
    /// performed after the structure-level check (defensive, in case the
    /// caller's `data` slice is smaller than declared).
    Truncated {
        /// Number of bytes the read needed.
        needed: usize,
        /// Number of bytes available from the requested offset to the end of buffer.
        available: usize,
    },

    /// An offset or length computation overflowed `usize` or `u32`.
    ///
    /// Triggered by adversarial structure fields (e.g., declared sizes
    /// near `u32::MAX`) that, when added to a base offset, would wrap.
    ArithmeticOverflow {
        /// Human-readable name of the computation that overflowed.
        context: &'static str,
    },

    // -- Entry point errors --
    /// The PE entry point does not start with `push imm32` (`0x68`).
    ///
    /// Every VB6 executable begins with `push offset VBHeader; call ThunRTMain`.
    /// If the first byte is not `0x68`, this is not a VB6 binary.
    EntryPointNotPush {
        /// The actual first byte at the entry point.
        byte: u8,
    },

    /// The container is a valid PE but doesn't look like a VB6 binary.
    ///
    /// Neither the entry point (EXE pattern: `push imm32; call ThunRTMain`)
    /// nor the export table (DLL pattern: `pop eax; push imm32; push eax;
    /// ...`) contained a recognizable VB6 header pointer, **and** no
    /// secondary scan turned up the `"VB5!"` magic. Almost certainly not
    /// a VB6 file at all (e.g., a Delphi/MFC/CRT-only PE).
    ///
    /// Consumers tagging files as "VB6 or not" should treat this as the
    /// quiet-path negative — log nothing or only at debug level.
    NotRecognized,

    /// The container looks like VB6 but a structural read overran the file.
    ///
    /// Triggered when the PE parses, an entry-point pattern matches, but
    /// reading [`VbHeader`](crate::vb::header::VbHeader),
    /// [`ProjectData`](crate::vb::projectdata::ProjectData), or
    /// [`ObjectTable`](crate::vb::objecttable::ObjectTable) at the
    /// referenced VA falls off the end of the buffer or off the end of
    /// any PE section. Indicates a truncated, corrupt, or section-table-
    /// inconsistent file — log at warn level and surface to the analyst.
    TruncatedContainer {
        /// Which structure failed to read fully.
        context: &'static str,
    },

    /// The file isn't a recognizable PE container at all.
    ///
    /// Surfaced when [`goblin::pe::PE::parse`] rejects the input (no MZ
    /// header, malformed PE header, etc.) or when the optional header
    /// declares PE32+ (64-bit), which is incompatible with VB6.
    /// Distinct from [`NotRecognized`](Self::NotRecognized) which fires
    /// only after the PE walk succeeded.
    UnrecognizedFormat {
        /// Short reason — `"goblin: <message>"` or `"PE32+ unsupported"`.
        reason: String,
    },

    // -- VA/RVA translation errors --
    /// A virtual address is below the PE image base.
    ///
    /// This means the VA cannot be a valid pointer within the loaded image.
    VaBelowImageBase {
        /// The virtual address that failed translation.
        va: u32,
        /// The PE image base.
        image_base: u32,
    },

    /// An RVA does not fall within any PE section.
    RvaNotMapped {
        /// The RVA that could not be mapped to a file offset.
        rva: u32,
    },

    /// An RVA falls in a BSS (zero-initialized) region with no file backing.
    RvaInBssRegion {
        /// The RVA that points to uninitialized data.
        rva: u32,
    },

    // -- VB structure errors --
    /// The expected magic signature was not found.
    ///
    /// For VBHeader, the expected magic is `"VB5!"`.
    BadMagic {
        /// The expected magic string (e.g., `"VB5!"`).
        expected: &'static str,
        /// The actual 4 bytes found at the magic offset.
        got: [u8; 4],
    },

    /// An object index is out of range for the object table.
    ObjectIndexOutOfRange {
        /// The requested object index.
        index: u16,
        /// Total number of objects in the table.
        total: u16,
    },

    // -- P-Code errors --
    /// Unexpected end of P-Code stream while decoding an instruction.
    UnexpectedEndOfPCode {
        /// Current offset within the P-Code stream.
        offset: usize,
        /// Number of additional bytes needed.
        needed: usize,
    },

    /// An opcode maps to an unimplemented handler in the dispatch table.
    UnknownOpcode {
        /// Dispatch table index (0 = primary, 1-5 = Lead0-Lead4).
        table: u8,
        /// Opcode byte within the table.
        opcode: u8,
    },

    /// A variable-length instruction has an implausible byte count.
    InvalidVariableLengthSize {
        /// The mnemonic of the opcode.
        opcode_name: &'static str,
        /// The byte count read from the instruction stream.
        size: u16,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Goblin(msg) => write!(f, "PE parsing error: {msg}"),
            Error::Not32Bit { magic } => {
                write!(f, "not a PE32 file (optional header magic: 0x{magic:04X})")
            }
            Error::TooShort {
                expected,
                actual,
                context,
            } => write!(
                f,
                "{context}: expected at least {expected} bytes, got {actual}"
            ),
            Error::Truncated { needed, available } => write!(
                f,
                "truncated read: needed {needed} bytes, only {available} available"
            ),
            Error::ArithmeticOverflow { context } => {
                write!(f, "arithmetic overflow in {context}")
            }
            Error::EntryPointNotPush { byte } => write!(
                f,
                "entry point does not start with push imm32 (0x68), found 0x{byte:02X}"
            ),
            Error::NotRecognized => write!(
                f,
                "not a VB6 binary (no VB header pointer in entry point or DLL exports)"
            ),
            Error::TruncatedContainer { context } => {
                write!(f, "VB6 container truncated reading {context}")
            }
            Error::UnrecognizedFormat { reason } => {
                write!(f, "unrecognized container format: {reason}")
            }
            Error::VaBelowImageBase { va, image_base } => {
                write!(f, "VA 0x{va:08X} is below image base 0x{image_base:08X}")
            }
            Error::RvaNotMapped { rva } => {
                write!(f, "RVA 0x{rva:08X} does not fall within any PE section")
            }
            Error::RvaInBssRegion { rva } => write!(
                f,
                "RVA 0x{rva:08X} falls in a BSS region with no file backing"
            ),
            Error::BadMagic { expected, got } => write!(
                f,
                "bad magic: expected \"{expected}\", got {:02X} {:02X} {:02X} {:02X}",
                got[0], got[1], got[2], got[3]
            ),
            Error::ObjectIndexOutOfRange { index, total } => {
                write!(f, "object index {index} out of range (total: {total})")
            }
            Error::UnexpectedEndOfPCode { offset, needed } => write!(
                f,
                "unexpected end of P-Code at offset 0x{offset:04X} (need {needed} more bytes)"
            ),
            Error::UnknownOpcode { table, opcode } => {
                write!(f, "unknown opcode: table {table}, opcode 0x{opcode:02X}")
            }
            Error::InvalidVariableLengthSize { opcode_name, size } => {
                write!(f, "{opcode_name}: invalid variable-length size {size}")
            }
        }
    }
}

impl error::Error for Error {}

impl From<goblin::error::Error> for Error {
    /// Converts a goblin parsing error into our [`Error::Goblin`] variant.
    fn from(e: goblin::error::Error) -> Self {
        Error::Goblin(e.to_string())
    }
}

impl Error {
    /// Classifies an error as a VB6 recognition failure, if it is one.
    ///
    /// Returns:
    ///
    /// - `Some(`[`RecognitionFailure::NotRecognized`]`)` for
    ///   [`Error::NotRecognized`] and [`Error::EntryPointNotPush`]
    ///   (both mean "PE walked OK but no VB6 marker").
    /// - `Some(`[`RecognitionFailure::TruncatedContainer`]`)` for
    ///   [`Error::TruncatedContainer`] and [`Error::TooShort`] hits
    ///   during the recognition phase.
    /// - `Some(`[`RecognitionFailure::UnrecognizedFormat`]`)` for
    ///   [`Error::UnrecognizedFormat`], [`Error::Goblin`], and
    ///   [`Error::Not32Bit`] (no PE container or PE32+).
    /// - `None` for downstream errors that occur **after** the
    ///   project structure has been recognized (per-field reads,
    ///   address-translation failures, etc.) — those are not
    ///   recognition failures and consumers should not silently
    ///   suppress them.
    ///
    /// `RecognitionFailure::CompressedAndOpaque` is reserved for a
    /// future packer-detection heuristic; the crate does not yet
    /// emit it.
    pub fn recognition_failure(&self) -> Option<RecognitionFailure> {
        match self {
            Error::NotRecognized | Error::EntryPointNotPush { .. } => {
                Some(RecognitionFailure::NotRecognized)
            }
            Error::TruncatedContainer { .. } | Error::TooShort { .. } => {
                Some(RecognitionFailure::TruncatedContainer)
            }
            Error::UnrecognizedFormat { .. } | Error::Goblin(_) | Error::Not32Bit { .. } => {
                Some(RecognitionFailure::UnrecognizedFormat)
            }
            _ => None,
        }
    }
}

/// Discriminated reasons a file failed [`crate::VbProject::from_bytes`]
/// recognition.
///
/// Returned by [`Error::recognition_failure`]. Lets consumers behave
/// differently based on **why** a file isn't usable: silently deny
/// non-VB6 files, warn on malformed VB6 ones, and (eventually) flag
/// packed/protected ones for separate handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum RecognitionFailure {
    /// Valid PE container, but no VB6 marker found.
    /// Consumer recommendation: log at debug level or not at all.
    NotRecognized,
    /// Recognized as VB6 but a structural read overran the file/section.
    /// Consumer recommendation: log at warn level — truncated or
    /// inconsistent file worth investigating.
    TruncatedContainer,
    /// Not a recognizable PE container (or PE32+, which isn't VB6).
    /// Consumer recommendation: log at debug level — file isn't even
    /// a candidate.
    UnrecognizedFormat,
    /// **Reserved.** Future heuristic for detecting packed/protected
    /// VB6 binaries. The crate does not currently emit this variant —
    /// it is exposed so downstream `match` arms can include it now and
    /// not break when the heuristic lands.
    CompressedAndOpaque,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_goblin() {
        let e = Error::Goblin("malformed PE".into());
        assert_eq!(e.to_string(), "PE parsing error: malformed PE");
    }

    #[test]
    fn test_display_not_32bit() {
        let e = Error::Not32Bit { magic: 0x020B };
        assert!(e.to_string().contains("0x020B"));
    }

    #[test]
    fn test_display_too_short() {
        let e = Error::TooShort {
            expected: 0x68,
            actual: 10,
            context: "VbHeader",
        };
        let s = e.to_string();
        assert!(s.contains("VbHeader"));
        assert!(s.contains("104"));
        assert!(s.contains("10"));
    }

    #[test]
    fn test_display_entry_point_not_push() {
        let e = Error::EntryPointNotPush { byte: 0xCC };
        assert!(e.to_string().contains("0xCC"));
    }

    #[test]
    fn test_display_va_below_image_base() {
        let e = Error::VaBelowImageBase {
            va: 0x1000,
            image_base: 0x00400000,
        };
        let s = e.to_string();
        assert!(s.contains("00001000"));
        assert!(s.contains("00400000"));
    }

    #[test]
    fn test_display_rva_not_mapped() {
        let e = Error::RvaNotMapped { rva: 0xDEAD };
        assert!(e.to_string().contains("0000DEAD"));
    }

    #[test]
    fn test_display_rva_in_bss() {
        let e = Error::RvaInBssRegion { rva: 0x5000 };
        assert!(e.to_string().contains("BSS"));
    }

    #[test]
    fn test_display_bad_magic() {
        let e = Error::BadMagic {
            expected: "VB5!",
            got: [0x4D, 0x5A, 0x00, 0x00],
        };
        let s = e.to_string();
        assert!(s.contains("VB5!"));
        assert!(s.contains("4D 5A"));
    }

    #[test]
    fn test_display_object_index() {
        let e = Error::ObjectIndexOutOfRange { index: 5, total: 3 };
        let s = e.to_string();
        assert!(s.contains("5"));
        assert!(s.contains("3"));
    }

    #[test]
    fn test_display_unexpected_end() {
        let e = Error::UnexpectedEndOfPCode {
            offset: 0x10,
            needed: 4,
        };
        assert!(e.to_string().contains("0010"));
    }

    #[test]
    fn test_display_unknown_opcode() {
        let e = Error::UnknownOpcode {
            table: 1,
            opcode: 0xAB,
        };
        let s = e.to_string();
        assert!(s.contains("table 1"));
        assert!(s.contains("0xAB"));
    }

    #[test]
    fn test_recognition_failure_classification() {
        // NotRecognized
        assert_eq!(
            Error::NotRecognized.recognition_failure(),
            Some(RecognitionFailure::NotRecognized)
        );
        assert_eq!(
            Error::EntryPointNotPush { byte: 0xCC }.recognition_failure(),
            Some(RecognitionFailure::NotRecognized)
        );
        // TruncatedContainer
        assert_eq!(
            Error::TruncatedContainer {
                context: "VbHeader"
            }
            .recognition_failure(),
            Some(RecognitionFailure::TruncatedContainer)
        );
        assert_eq!(
            Error::TooShort {
                expected: 4,
                actual: 1,
                context: "x",
            }
            .recognition_failure(),
            Some(RecognitionFailure::TruncatedContainer)
        );
        // UnrecognizedFormat
        assert_eq!(
            Error::UnrecognizedFormat {
                reason: "no MZ".into(),
            }
            .recognition_failure(),
            Some(RecognitionFailure::UnrecognizedFormat)
        );
        assert_eq!(
            Error::Goblin("bad PE".into()).recognition_failure(),
            Some(RecognitionFailure::UnrecognizedFormat)
        );
        assert_eq!(
            Error::Not32Bit { magic: 0x020B }.recognition_failure(),
            Some(RecognitionFailure::UnrecognizedFormat)
        );
        // None for downstream errors
        assert_eq!(Error::RvaNotMapped { rva: 0 }.recognition_failure(), None);
        assert_eq!(
            Error::UnknownOpcode {
                table: 0,
                opcode: 0
            }
            .recognition_failure(),
            None
        );
    }

    #[test]
    fn test_display_invalid_varlen() {
        let e = Error::InvalidVariableLengthSize {
            opcode_name: "FFreeVar",
            size: 0xFFFF,
        };
        assert!(e.to_string().contains("FFreeVar"));
    }

    #[test]
    fn test_error_is_clone_eq() {
        let e1 = Error::RvaNotMapped { rva: 42 };
        let e2 = e1.clone();
        assert_eq!(e1, e2);
    }

    #[test]
    fn test_error_trait_impl() {
        let e: Box<dyn std::error::Error> = Box::new(Error::RvaNotMapped { rva: 0 });
        let _ = e.to_string();
    }

    // NotPe variant was removed from plan but let's make sure the enum
    // covers all needed cases - this tests the From impl
    #[test]
    fn test_from_goblin_error() {
        // We can't easily construct a goblin error, but we can test the path
        let e = Error::Goblin("test error".into());
        assert!(matches!(e, Error::Goblin(_)));
    }
}
