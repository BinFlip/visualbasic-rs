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
//! let file_bytes = std::fs::read("sample.exe").unwrap();
//! let project = VbProject::from_bytes(&file_bytes).unwrap();
//!
//! println!("Objects: {}", project.object_count());
//! for obj in project.objects() {
//!     let obj = obj.unwrap();
//!     println!("  Object: {:?}", obj.name());
//! }
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

#![deny(missing_docs, unsafe_code)]

pub mod addressmap;
pub mod entrypoint;
pub mod error;
pub mod pcode;
pub mod project;
pub mod vb;

mod util;

// Re-export primary types at crate root.
pub use addressmap::AddressMap;
pub use error::Error;
pub use project::{MethodEntry, PCodeMethod, VbControl, VbObject, VbProject};
