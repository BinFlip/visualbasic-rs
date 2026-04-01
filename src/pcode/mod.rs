//! P-Code bytecode decoding.
//!
//! This module handles the VB6 P-Code instruction set:
//!
//! - **Opcode tables** ([`opcode`]): Static lookup tables for all 6 dispatch
//!   tables (1536 entries total), generated at build time from a CSV source.
//! - **Operands** ([`operand`]): Typed operand representation and format
//!   string decoding.
//! - **Decoder** ([`decoder`]): A streaming [`InstructionIterator`](decoder::InstructionIterator)
//!   that yields decoded instructions from a P-Code byte stream.
//! - **Display** ([`display`]): Human-readable formatting for disassembly output.

pub mod calltarget;
pub mod decoder;
pub mod display;
pub mod framevar;
pub mod opcode;
pub mod operand;
pub mod semantics;
