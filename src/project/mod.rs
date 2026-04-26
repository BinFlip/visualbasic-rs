//! High-level VB6 project exploration API.
//!
//! [`VbProject`] is the primary entry point for the library. It chains
//! together PE parsing, VB structure navigation, and P-Code access into
//! a single convenient type with lifetime `'a` tied to the file buffer.
//!
//! # Example
//!
//! ```ignore
//! let data = std::fs::read("sample.exe")?;
//! let project = VbProject::from_bytes(&data)?;
//!
//! for obj in project.objects() {
//!     let obj = obj?;
//!     println!("Object: {:?}", obj.name()?);
//!     for method in obj.pcode_methods() {
//!         let method = method?;
//!         for insn in method.instructions() {
//!             println!("  {}", insn?);
//!         }
//!     }
//! }
//! ```

mod methodentry;
mod methodlink;
mod pcodemethod;
mod vbcontrol;
mod vbobject;
mod vbproject;

// Re-export all public types at the module level.
pub use methodentry::MethodEntry;
pub use methodlink::{MethodLink, MethodLinkIterator};
pub use pcodemethod::PCodeMethod;
pub use vbcontrol::{ControlEntryIterator, VbControl};
pub use vbobject::{
    CodeEntry, CodeEntryKind, EventBinding, FuncTypDescIter, MethodIterator, MethodNameResult,
    PCodeMethodIterator, VbObject, format_signature,
};
pub use vbproject::{
    CodeEntrypoint, CompilationMode, DiagnosticKind, DiagnosticSeverity, EntrypointKind,
    ExternalIterator, GuiEntriesWithFormData, GuiEntryWithFormData, ObjectIterator,
    ParseDiagnostic, VbProject,
};
