//! Opcode definitions and dispatch table lookup.
//!
//! Contains static lookup tables for all 6 VB6 P-Code dispatch tables
//! (1536 entries total), generated at build time from `data/opcodes.csv`.
//!
//! # Dispatch Table Organization
//!
//! | Table | Lead Byte | Purpose |
//! |-------|-----------|---------|
//! | Primary | None | Core instruction set (256 opcodes) |
//! | Lead0 | `0xFB` | Extended comparisons, logic, math |
//! | Lead1 | `0xFC` | Type conversions, array ops, I/O |
//! | Lead2 | `0xFD` | Branches, print, member ops |
//! | Lead3 | `0xFE` | VCalls, For/Next, late binding, ReDim |
//! | Lead4 | `0xFF` | Misc, array records, UDT ops |

/// Dispatch table identifier.
///
/// The VB6 VM uses 6 dispatch tables: one primary table and five
/// extended tables accessed via lead bytes `0xFB`-`0xFF`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum DispatchTable {
    /// Primary table (no lead byte prefix). 256 opcodes.
    Primary = 0,
    /// Lead0 table (prefix `0xFB`). Extended comparisons, logic, math.
    Lead0 = 1,
    /// Lead1 table (prefix `0xFC`). Type conversions, array ops, I/O.
    Lead1 = 2,
    /// Lead2 table (prefix `0xFD`). Branches, print, member ops.
    Lead2 = 3,
    /// Lead3 table (prefix `0xFE`). VCalls, For/Next, late binding, ReDim.
    Lead3 = 4,
    /// Lead4 table (prefix `0xFF`). Misc, array records, UDT ops.
    Lead4 = 5,
}

/// Metadata for a single P-Code opcode.
///
/// Each entry describes one slot in one of the 6 dispatch tables,
/// combining encoding information with verified runtime semantics
/// traced from MSVBVM60.DLL handler disassembly.
///
/// All semantic fields (`semantics`, `data_type`) are resolved at
/// **build time** from the CSV data — no runtime string parsing.
#[derive(Debug, Clone, Copy)]
pub struct OpcodeInfo {
    /// Which dispatch table this opcode belongs to.
    pub table: DispatchTable,
    /// The opcode byte within the table (`0x00`-`0xFF`).
    pub index: u8,
    /// Total instruction size in bytes (excluding lead byte).
    ///
    /// - **Positive**: fixed-size instruction (includes the opcode byte itself).
    /// - **`-1`**: variable-length instruction (size encoded as `u16` after opcode).
    /// - **`0`**: unimplemented/invalid opcode slot.
    pub size: i8,
    /// Mnemonic name (e.g., `"FLdRfVar"`, `"AddI4"`, `"InvalidExcode"`).
    pub mnemonic: &'static str,
    /// Operand format string (e.g., `"%a"`, `"%s %2"`, `""` for no operands).
    ///
    /// Format specifiers:
    /// - `%1` - 1-byte literal
    /// - `%2` - 2-byte (Int16) literal
    /// - `%4` - 4-byte (Int32) literal
    /// - `%a` - Stack variable reference (signed Int16 EBP offset)
    /// - `%s` - Constant pool index (Int16)
    /// - `%l` - Jump target (unsigned Int16 from function start)
    /// - `%c` - Control/import index (Int16)
    /// - `%v` - VTable reference (two Int16 values)
    /// - `%x` - External call (two Int16 values)
    pub operand_format: &'static str,
    /// Evaluation stack slots consumed (4 bytes each).
    /// `-1` means variable (depends on operand encoding).
    pub pops: i8,
    /// Evaluation stack slots produced (4 bytes each).
    pub pushes: i8,
    /// x87 FPU stack values consumed.
    pub fpu_pops: u8,
    /// x87 FPU stack values produced.
    pub fpu_push: u8,
    /// `true` if this instruction modifies the FPU TOS value in place.
    ///
    /// These opcodes (e.g., `FnAbsR8`, `FnNegR8`) read ST(0) and write
    /// the result back to ST(0) without pushing or popping the FPU stack.
    /// Both `fpu_pops` and `fpu_push` are 0 because the stack depth is
    /// unchanged, but the value at TOS **is** modified.
    pub fpu_inplace: bool,
    /// Bytes read from memory (0 = none).
    pub mem_read: u8,
    /// Bytes written to memory (0 = none).
    pub mem_write: u8,
    /// Semantic category string (e.g., `"arith"`, `"load_frame"`, `"branch"`).
    pub category: &'static str,
    /// Typed semantic classification (generated at build time).
    pub semantics: OpcodeSemantics,
    /// Data type from mnemonic suffix (generated at build time).
    pub data_type: Option<PCodeDataType>,
}

impl OpcodeInfo {
    /// Returns `true` if this opcode is implemented in the VM.
    ///
    /// Unimplemented slots have mnemonic `"InvalidExcode"` or `"Unknown"`.
    #[inline]
    pub fn is_implemented(&self) -> bool {
        self.mnemonic != "InvalidExcode" && self.mnemonic != "Unknown" && self.size != 0
    }

    /// Returns `true` if this is a variable-length instruction.
    ///
    /// Variable-length instructions (like `FFreeVar`, `FFreeStr`, `FFreeAd`)
    /// encode their payload size as a `u16` immediately after the opcode byte.
    #[inline]
    pub fn is_variable_length(&self) -> bool {
        self.size < 0
    }

    /// Returns `true` if this instruction has any FPU stack effect.
    ///
    /// Covers pushes, pops, **and** in-place TOS modifications.
    #[inline]
    pub fn touches_fpu(&self) -> bool {
        self.fpu_pops > 0 || self.fpu_push > 0 || self.fpu_inplace
    }

    /// Returns `true` if this opcode is a lead byte (`0xFB`-`0xFF`).
    #[inline]
    pub fn is_lead_byte(&self) -> bool {
        matches!(
            self.mnemonic,
            "Lead0" | "Lead1" | "Lead2" | "Lead3" | "Lead4"
        )
    }

    /// Returns `true` if this opcode terminates the basic block.
    ///
    /// Includes returns ([`OpcodeSemantics::Return`]) and unconditional
    /// branches ([`OpcodeSemantics::Branch`] with `conditional: false`).
    /// Conditional branches **do not** terminate — control falls through
    /// to the next instruction on the not-taken path.
    ///
    /// Useful for CFG construction and basic-block splitting.
    #[inline]
    pub fn is_terminator(&self) -> bool {
        matches!(
            self.semantics,
            OpcodeSemantics::Return | OpcodeSemantics::Branch { conditional: false }
        )
    }

    /// Returns `true` if this opcode is a call instruction.
    ///
    /// Matches any [`OpcodeSemantics::Call`] regardless of [`CallKind`]
    /// (vtable, this-vtable, import-address, late-bound, or other).
    /// Useful for CFG construction (calls split basic blocks in some
    /// analyses) and call-graph extraction.
    #[inline]
    pub fn is_call(&self) -> bool {
        matches!(self.semantics, OpcodeSemantics::Call { .. })
    }
}

/// Sentinel returned by [`lookup`] when a lead byte's secondary opcode index
/// somehow falls outside the 256-entry dispatch table.
///
/// Statically the cast `u8 as usize` cannot exceed 255 and the tables are
/// `[OpcodeInfo; 256]`, so this fallback is unreachable at runtime — it
/// exists to satisfy `clippy::indexing_slicing` without resorting to
/// unchecked indexing in the generated code.
pub static UNKNOWN_OPCODE: OpcodeInfo = OpcodeInfo {
    table: DispatchTable::Primary,
    index: 0,
    size: 0,
    mnemonic: "Unknown",
    operand_format: "",
    pops: 0,
    pushes: 0,
    fpu_pops: 0,
    fpu_push: 0,
    fpu_inplace: false,
    mem_read: 0,
    mem_write: 0,
    category: "",
    semantics: crate::pcode::semantics::OpcodeSemantics::Unclassified,
    data_type: None,
};

// Include the build-time generated tables and lookup function.
include!(concat!(env!("OUT_DIR"), "/opcode_generated.rs"));

/// Returns the total number of implemented (non-Invalid/Unknown) opcodes
/// across all 6 dispatch tables.
pub fn implemented_count() -> usize {
    let tables: [&[OpcodeInfo; 256]; 6] = [
        &PRIMARY_TABLE,
        &LEAD0_TABLE,
        &LEAD1_TABLE,
        &LEAD2_TABLE,
        &LEAD3_TABLE,
        &LEAD4_TABLE,
    ];
    tables
        .iter()
        .flat_map(|t| t.iter())
        .filter(|o| o.is_implemented())
        .count()
}

/// Returns a reference to one of the 6 dispatch tables by index.
///
/// # Arguments
///
/// * `table` - The dispatch table to retrieve.
///
/// # Returns
///
/// A reference to the static `[OpcodeInfo; 256]` array.
pub fn table_by_index(table: DispatchTable) -> &'static [OpcodeInfo; 256] {
    match table {
        DispatchTable::Primary => &PRIMARY_TABLE,
        DispatchTable::Lead0 => &LEAD0_TABLE,
        DispatchTable::Lead1 => &LEAD1_TABLE,
        DispatchTable::Lead2 => &LEAD2_TABLE,
        DispatchTable::Lead3 => &LEAD3_TABLE,
        DispatchTable::Lead4 => &LEAD4_TABLE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_tables_have_256_entries() {
        assert_eq!(PRIMARY_TABLE.len(), 256);
        assert_eq!(LEAD0_TABLE.len(), 256);
        assert_eq!(LEAD1_TABLE.len(), 256);
        assert_eq!(LEAD2_TABLE.len(), 256);
        assert_eq!(LEAD3_TABLE.len(), 256);
        assert_eq!(LEAD4_TABLE.len(), 256);
    }

    #[test]
    fn test_lead_byte_slots_in_primary() {
        assert_eq!(PRIMARY_TABLE[0xFB].mnemonic, "Lead0");
        assert_eq!(PRIMARY_TABLE[0xFC].mnemonic, "Lead1");
        assert_eq!(PRIMARY_TABLE[0xFD].mnemonic, "Lead2");
        assert_eq!(PRIMARY_TABLE[0xFE].mnemonic, "Lead3");
        assert_eq!(PRIMARY_TABLE[0xFF].mnemonic, "Lead4");
    }

    #[test]
    fn test_lead_bytes_size_is_1() {
        for (i, entry) in PRIMARY_TABLE.iter().enumerate().skip(0xFB) {
            assert_eq!(entry.size, 1, "Lead byte 0x{:02X} should have size 1", i);
        }
    }

    #[test]
    fn test_known_primary_opcodes() {
        // 0x14 = ExitProc, size 1
        assert_eq!(PRIMARY_TABLE[0x14].mnemonic, "ExitProc");
        assert_eq!(PRIMARY_TABLE[0x14].size, 1);

        // 0x1E = Branch, size 3
        assert_eq!(PRIMARY_TABLE[0x1E].mnemonic, "Branch");
        assert_eq!(PRIMARY_TABLE[0x1E].size, 3);

        // 0xF3 = LitI2, size 3
        assert_eq!(PRIMARY_TABLE[0xF3].mnemonic, "LitI2");
        assert_eq!(PRIMARY_TABLE[0xF3].size, 3);

        // 0xF5 = LitI4, size 5
        assert_eq!(PRIMARY_TABLE[0xF5].mnemonic, "LitI4");
        assert_eq!(PRIMARY_TABLE[0xF5].size, 5);

        // 0xA9 = AddI2, size 1
        assert_eq!(PRIMARY_TABLE[0xA9].mnemonic, "AddI2");
        assert_eq!(PRIMARY_TABLE[0xA9].size, 1);
    }

    #[test]
    fn test_variable_length_opcodes() {
        // 0x29 = FFreeAd, size -1
        assert_eq!(PRIMARY_TABLE[0x29].mnemonic, "FFreeAd");
        assert!(PRIMARY_TABLE[0x29].is_variable_length());

        // 0x32 = FFreeStr, size -1
        assert_eq!(PRIMARY_TABLE[0x32].mnemonic, "FFreeStr");
        assert!(PRIMARY_TABLE[0x32].is_variable_length());

        // 0x36 = FFreeVar, size -1
        assert_eq!(PRIMARY_TABLE[0x36].mnemonic, "FFreeVar");
        assert!(PRIMARY_TABLE[0x36].is_variable_length());
    }

    #[test]
    fn test_lookup_primary() {
        let (info, consumed) = lookup(0x14, None);
        assert_eq!(info.mnemonic, "ExitProc");
        assert_eq!(consumed, 1);
    }

    #[test]
    fn test_lookup_lead0() {
        // Lead0 (0xFB), then some opcode
        let (info, consumed) = lookup(0xFB, Some(0x00));
        assert_eq!(consumed, 2);
        assert_eq!(info.table, DispatchTable::Lead0);
    }

    #[test]
    fn test_lookup_lead4() {
        let (info, consumed) = lookup(0xFF, Some(0x10));
        assert_eq!(consumed, 2);
        assert_eq!(info.table, DispatchTable::Lead4);
    }

    #[test]
    fn test_implemented_count() {
        let count = implemented_count();
        // The research says ~822 unique handlers. Our count should be in that range.
        // Allow some variance due to how we count vs the research.
        // modPCode.bas defines ~1165 named opcodes; the ~822 from research refers to
        // unique handler addresses in the DLL (many opcodes share implementations).
        assert!(count > 1000, "Expected >1000 named opcodes, got {}", count);
        assert!(count < 1300, "Expected <1300 named opcodes, got {}", count);
    }

    #[test]
    fn test_is_implemented() {
        assert!(PRIMARY_TABLE[0x14].is_implemented()); // ExitProc
        assert!(!PRIMARY_TABLE[0x01].is_implemented()); // InvalidExcode
    }

    #[test]
    fn test_is_lead_byte() {
        assert!(PRIMARY_TABLE[0xFB].is_lead_byte());
        assert!(!PRIMARY_TABLE[0x14].is_lead_byte());
    }

    #[test]
    fn test_is_terminator() {
        // ExitProc (0x14) — Return semantics, terminates the block.
        assert!(PRIMARY_TABLE[0x14].is_terminator());
        // Branch (0x1E) — unconditional Branch{conditional:false}, terminates.
        assert!(PRIMARY_TABLE[0x1E].is_terminator());
        // BranchT (0x1C) — conditional, does NOT terminate (falls through).
        assert!(!PRIMARY_TABLE[0x1C].is_terminator());
        // BranchF (0x1D) — conditional, does NOT terminate.
        assert!(!PRIMARY_TABLE[0x1D].is_terminator());
        // AddI2 (0xA9) — arithmetic, not a terminator.
        assert!(!PRIMARY_TABLE[0xA9].is_terminator());
        // FLdRfVar (0x04) — load, not a terminator.
        assert!(!PRIMARY_TABLE[0x04].is_terminator());
    }

    #[test]
    fn test_is_call() {
        // ImpAdCallI4 lives in Lead3 — find any Call-classified opcode.
        let any_primary_call = PRIMARY_TABLE.iter().any(|o| o.is_call());
        let any_lead3_call = LEAD3_TABLE.iter().any(|o| o.is_call());
        // At least one of the primary or Lead3 tables must contain calls.
        assert!(
            any_primary_call || any_lead3_call,
            "expected at least one Call opcode across primary+lead3 tables"
        );
        // ExitProc is not a call.
        assert!(!PRIMARY_TABLE[0x14].is_call());
        // AddI2 is not a call.
        assert!(!PRIMARY_TABLE[0xA9].is_call());
        // Branch is not a call.
        assert!(!PRIMARY_TABLE[0x1E].is_call());
    }

    #[test]
    fn test_terminator_and_call_are_disjoint() {
        // No opcode should be both a terminator and a call.
        let tables: [&[OpcodeInfo; 256]; 6] = [
            &PRIMARY_TABLE,
            &LEAD0_TABLE,
            &LEAD1_TABLE,
            &LEAD2_TABLE,
            &LEAD3_TABLE,
            &LEAD4_TABLE,
        ];
        for entry in tables.iter().flat_map(|t| t.iter()) {
            assert!(
                !(entry.is_terminator() && entry.is_call()),
                "{} is both terminator and call",
                entry.mnemonic
            );
        }
    }

    #[test]
    fn test_table_by_index() {
        let primary = table_by_index(DispatchTable::Primary);
        assert_eq!(primary[0x14].mnemonic, "ExitProc");

        let lead0 = table_by_index(DispatchTable::Lead0);
        assert_eq!(lead0.len(), 256);
    }

    #[test]
    fn test_operand_format_specifiers_normalized() {
        // LitI2 should have format %2
        assert_eq!(PRIMARY_TABLE[0xF3].operand_format, "%2");

        // Branch should have format %l
        assert_eq!(PRIMARY_TABLE[0x1E].operand_format, "%l");

        // FLdRfVar should have format %a
        assert_eq!(PRIMARY_TABLE[0x04].operand_format, "%a");

        // LitStr should have format %s
        assert_eq!(PRIMARY_TABLE[0x1B].operand_format, "%s");
    }

    #[test]
    fn test_semantics_fields_populated() {
        // AddI4 (0xA9): pops=2, pushes=1, category=arith
        assert_eq!(PRIMARY_TABLE[0xA9].pops, 2);
        assert_eq!(PRIMARY_TABLE[0xA9].pushes, 1);
        assert_eq!(PRIMARY_TABLE[0xA9].category, "arith");

        // FLdRfVar (0x04): pops=0, pushes=1, mem_read=4, category=load_frame
        assert_eq!(PRIMARY_TABLE[0x04].pops, 0);
        assert_eq!(PRIMARY_TABLE[0x04].pushes, 1);
        assert_eq!(PRIMARY_TABLE[0x04].mem_read, 4);
        assert_eq!(PRIMARY_TABLE[0x04].category, "load_frame");

        // FStR8 (0x72): pops=2, pushes=0, mem_write=8
        assert_eq!(PRIMARY_TABLE[0x72].pops, 2);
        assert_eq!(PRIMARY_TABLE[0x72].pushes, 0);
        assert_eq!(PRIMARY_TABLE[0x72].mem_write, 8);

        // FLdFPR4 (0x6E): fpu_push=1, no eval stack change
        assert_eq!(PRIMARY_TABLE[0x6E].fpu_push, 1);
        assert_eq!(PRIMARY_TABLE[0x6E].pops, 0);
        assert_eq!(PRIMARY_TABLE[0x6E].pushes, 0);

        // FStFPR8 (0x74): fpu_pops=1
        assert_eq!(PRIMARY_TABLE[0x74].fpu_pops, 1);

        // InvalidExcode (0x01): all semantics zero, empty category
        assert_eq!(PRIMARY_TABLE[0x01].pops, 0);
        assert_eq!(PRIMARY_TABLE[0x01].pushes, 0);
        assert_eq!(PRIMARY_TABLE[0x01].category, "");

        // Lead0 table: AddVar (0x94) pops=4, pushes=4
        assert_eq!(LEAD0_TABLE[0x94].mnemonic, "AddVar");
        assert_eq!(LEAD0_TABLE[0x94].pops, 4);
        assert_eq!(LEAD0_TABLE[0x94].pushes, 4);
        assert_eq!(LEAD0_TABLE[0x94].category, "arith");

        // Lead1 table: CStrR8 (0x00) fpu_pops=1, pushes=1
        assert_eq!(LEAD1_TABLE[0x00].fpu_pops, 1);
        assert_eq!(LEAD1_TABLE[0x00].pushes, 1);
        assert_eq!(LEAD1_TABLE[0x00].category, "convert");
    }

    #[test]
    fn test_all_opcodes_have_valid_table_field() {
        let tables: [(DispatchTable, &[OpcodeInfo; 256]); 6] = [
            (DispatchTable::Primary, &PRIMARY_TABLE),
            (DispatchTable::Lead0, &LEAD0_TABLE),
            (DispatchTable::Lead1, &LEAD1_TABLE),
            (DispatchTable::Lead2, &LEAD2_TABLE),
            (DispatchTable::Lead3, &LEAD3_TABLE),
            (DispatchTable::Lead4, &LEAD4_TABLE),
        ];
        for (expected_table, table) in &tables {
            for entry in table.iter() {
                assert_eq!(
                    entry.table, *expected_table,
                    "Opcode 0x{:02X} in {:?} has wrong table field {:?}",
                    entry.index, expected_table, entry.table
                );
            }
        }
    }
}
