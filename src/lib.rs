//! Parse and inspect Visual Basic 6 compiled binaries.
//!
//! This crate provides typed access to all internal structures within a
//! VB6 compiled executable, from the PE entry point down to individual
//! P-Code bytecode instructions.
//!
//! # Quick Start
//!
//! ```no_run
//! use visualbasic::VbProject;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let file_bytes = std::fs::read("sample.exe")?;
//! let project = VbProject::from_bytes(&file_bytes)?;
//!
//! println!("Objects: {}", project.object_count()?);
//! for obj in project.objects()? {
//!     let obj = obj?;
//!     println!("  Object: {:?}", obj.name()?);
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Architecture
//!
//! The crate is organized in layers:
//!
//! - **Address translation** ([`addressmap::AddressMap`]): Converts VAs/RVAs to file offsets
//!   using section tables from [`goblin`].
//! - **VB structures** ([`vb`]): View types for each structure in the VB6
//!   internal format (VBHeader, ProjectData, ObjectTable, etc.).
//! - **P-Code decoding** ([`pcode`]): Opcode tables, operand types, and a streaming
//!   instruction iterator.
//! - **High-level API** ([`VbProject`]): Ties everything together into a convenient
//!   exploration interface.
//!
//! # Design
//!
//! All structure types borrow from the original file byte slice (`&'a [u8]`).
//! Accessor methods read directly from the underlying buffer using
//! little-endian byte decoding.
//!
//! # Robustness contract
//!
//! VB6 binaries from the wild include malware samples that may be truncated,
//! have inconsistent structure-size fields, or carry intentionally adversarial
//! VAs. Every public API in this crate falls into one of three behavioural
//! categories — pick the one that matches your call site:
//!
//! ## 1. Fail-loud at the byte boundary (primitive accessors)
//!
//! Every fixed-offset accessor like
//! [`VbHeader::project_data_va`](crate::vb::header::VbHeader::project_data_va),
//! [`ProcDscInfo::frame_size`](crate::vb::procedure::ProcDscInfo::frame_size), or
//! [`VbObject::name_bytes`](crate::project::VbObject::name_bytes) returns
//! `Result<T, Error>`. The crate's underlying byte readers are
//! panic-free (no `unwrap`, no panicking indexing, no unchecked arithmetic);
//! out-of-buffer reads surface as
//! [`Error::Truncated`] and offset overflows as [`Error::ArithmeticOverflow`].
//! Use `?` to propagate.
//!
//! ## 2. Skip-and-continue (per-entry iterators)
//!
//! Iterators like
//! [`InstructionIterator`](crate::pcode::decoder::InstructionIterator),
//! [`PCodeMethodIterator`](crate::project::PCodeMethodIterator), and
//! [`ConstPoolIter`](crate::vb::constantpool::ConstPoolIter) yield
//! `Item = Result<T, Error>` per entry — they emit one `Err` per malformed
//! row and *keep going*, so a single bad entry does not poison the whole
//! sweep. Match on each `Item` to pull successes, log failures, or stop
//! early on first error per your policy. Iteration ends only when the
//! underlying byte stream is exhausted (or a structural-truncation
//! `Err` is yielded — most iterators continue past per-entry errors).
//!
//! ## 3. Silent fail-soft (high-level joins)
//!
//! High-level convenience methods like
//! [`VbObject::events`](crate::project::VbObject::events),
//! [`VbProject::code_entrypoints`](crate::project::VbProject::code_entrypoints),
//! and the [`pcode::calltarget`] resolvers eagerly
//! collect from one or more underlying iterators and **silently drop**
//! malformed rows (`filter_map(|r| r.ok())`) so the returned `Vec` is
//! "everything that parsed". This matches malware-analysis triage: one
//! corrupt control should not block enumeration of the other 50.
//! Enable the optional `tracing` feature to capture the dropped rows
//! as `target = "visualbasic::dropped"` `warn` events.
//!
//! ## 4. Recognition-time errors at [`VbProject::from_bytes`]
//!
//! Parse failures during the recognition phase are classified by
//! [`Error::recognition_failure`] into one of:
//!
//! - [`RecognitionFailure::NotRecognized`] — valid PE but no VB6 marker.
//! - [`RecognitionFailure::TruncatedContainer`] — looks VB6 but truncated.
//! - [`RecognitionFailure::UnrecognizedFormat`] — not a PE container at all.
//!
//! Consumers tagging files as "VB6 or not" should match on this
//! classification to silently skip non-VB6 files and only log the
//! `TruncatedContainer` cases.
//!
//! # Adversarial input invariants
//!
//! The crate is built under the lint set
//! `clippy::{unwrap_used, expect_used, panic, arithmetic_side_effects,
//! indexing_slicing}` — every byte read goes through a checked helper, every
//! offset computation uses `checked_add` / `wrapping_add` / `saturating_add`
//! depending on semantics, and every slice access uses `.get(...)` rather
//! than `[]`. **No input byte sequence can panic this parser.** Tests are
//! exempt from these lints.

// This crate is used for malware analysis: every input byte is
// adversarial and must not be allowed to panic the parser.
#![deny(
    missing_docs,
    unsafe_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::arithmetic_side_effects,
        clippy::indexing_slicing
    )
)]

pub mod addressmap;
pub mod entrypoint;
pub mod error;
pub mod pcode;
pub mod project;
pub mod vb;

mod trace;
mod util;

/// Internal re-export of [`tracing`] for use by [`crate::trace::warn_drop`].
///
/// Hidden from rustdoc; consumers should depend on `tracing` directly.
/// The re-export lets the macro emit `$crate::__tracing::warn!(...)`
/// instead of an absolute `::tracing::warn!(...)` path, satisfying the
/// project's no-absolute-paths guideline while preserving macro hygiene
/// (the macro can be expanded from any module without requiring
/// `tracing` to be in scope at the call site).
#[cfg(feature = "tracing")]
#[doc(hidden)]
pub use tracing as __tracing;

// Re-export primary types at crate root.
pub use addressmap::AddressMap;
pub use error::{Error, RecognitionFailure};
pub use project::{
    CodeEntrypoint, CompilationMode, DiagnosticKind, DiagnosticSeverity, EntrypointKind,
    MethodEntry, PCodeMethod, ParseDiagnostic, VbControl, VbObject, VbProject,
};

// Thread-safety guarantee: VbProject and PCodeMethod borrow from a `&[u8]`
// file buffer, hold no interior mutability, and contain no raw pointers or
// `Cell`/`RefCell`. They are therefore both `Send` and `Sync` whenever the
// borrowed buffer is — i.e., always, for any `&'a [u8]` input. This static
// assertion makes that guarantee a compile-time invariant: a future change
// that adds a non-Send/non-Sync field will break the build here, not silently
// at a downstream `.await` point.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<VbProject<'static>>();
    assert_send_sync::<PCodeMethod<'static>>();
};
