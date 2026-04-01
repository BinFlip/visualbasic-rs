//! Semantic classification of P-Code opcodes.
//!
//! Provides typed enums for classifying every P-Code opcode by its
//! data type and semantic operation. All classification is performed
//! at **build time** by `build.rs` — the generated opcode tables contain
//! fully typed enum values with zero runtime string parsing.

/// Data type operated on by a P-Code instruction.
///
/// Determined at build time from the opcode mnemonic suffix
/// (e.g., `"AddI4"` → `I4`, `"FLdFPR8"` → `FPR8`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PCodeDataType {
    /// 8-bit unsigned integer (Byte). 1 byte, zero-extended to 4B on eval stack.
    UI1,
    /// 16-bit signed integer (Integer). 2 bytes, sign-extended to 4B on eval stack.
    I2,
    /// 32-bit signed integer (Long). 4 bytes, 1 eval stack slot.
    I4,
    /// 32-bit float (Single). On FPU stack (not eval stack).
    R4,
    /// 64-bit float (Double). On FPU stack or 2 eval stack slots.
    R8,
    /// 64-bit fixed-point Currency. 2 eval stack slots (8 bytes).
    Cy,
    /// BSTR pointer. 4 bytes, 1 eval stack slot.
    Str,
    /// 16-byte Variant. 4 eval stack slots.
    Var,
    /// VB Boolean (-1=True, 0=False). 2 bytes, stored as i32 on eval stack.
    Bool,
    /// 4-byte address/pointer (COM object, UDT, etc.).
    Ad,
    /// Date as f64. On FPU stack or 2 eval stack slots.
    Date,
    /// Single-precision float via FPU load/store path.
    FPR4,
    /// Double-precision float via FPU load/store path.
    FPR8,
    /// Variable-argument Variant (ParamArray element).
    Varg,
}

impl PCodeDataType {
    /// Returns the size in bytes of this data type on the eval stack.
    ///
    /// FPU types (`R4`, `FPR4`, `FPR8`) return 0 since they
    /// live on the x87 FPU stack, not the eval stack.
    pub fn eval_stack_bytes(self) -> u8 {
        match self {
            Self::UI1 | Self::I2 | Self::I4 | Self::Bool | Self::Str | Self::Ad => 4,
            Self::R8 | Self::Cy | Self::Date => 8,
            Self::Var | Self::Varg => 16,
            Self::R4 | Self::FPR4 | Self::FPR8 => 0,
        }
    }

    /// Returns the number of eval stack slots (4 bytes each).
    pub fn eval_stack_slots(self) -> u8 {
        match self {
            Self::UI1 | Self::I2 | Self::I4 | Self::Bool | Self::Str | Self::Ad => 1,
            Self::R8 | Self::Cy | Self::Date => 2,
            Self::Var | Self::Varg => 4,
            Self::R4 | Self::FPR4 | Self::FPR8 => 0,
        }
    }

    /// Returns true if this type uses the x87 FPU stack.
    pub fn is_fpu(self) -> bool {
        matches!(
            self,
            Self::R4 | Self::R8 | Self::FPR4 | Self::FPR8 | Self::Date
        )
    }
}

/// Semantic classification of a P-Code opcode.
///
/// Generated at build time from the CSV `category` and `mnemonic` columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpcodeSemantics {
    /// Load value (from frame, literal, memory, or indirect).
    Load {
        /// Where the value is loaded from.
        source: LoadSource,
    },
    /// Store value (to frame, memory, or indirect).
    Store {
        /// Where the value is stored to.
        target: StoreTarget,
    },
    /// Binary arithmetic operation.
    Arithmetic {
        /// Which arithmetic operation.
        op: ArithOp,
    },
    /// Unary operation (Not, negation, Abs).
    Unary {
        /// Which unary operation.
        op: ArithOp,
    },
    /// Comparison operation.
    Compare,
    /// Type conversion.
    Convert {
        /// Source data type (what is being converted from).
        from: Option<PCodeDataType>,
        /// Target data type (what is being converted to).
        to: Option<PCodeDataType>,
    },
    /// Branch (conditional or unconditional).
    Branch {
        /// True if branch depends on a condition.
        conditional: bool,
    },
    /// Subroutine/method call.
    Call {
        /// What kind of call mechanism.
        kind: CallKind,
    },
    /// Return from procedure.
    Return,
    /// Stack manipulation (free, pop, push temp, etc.).
    Stack,
    /// Debug/NOP marker (Bos, LargeBos).
    Nop,
    /// I/O operation (Print, Input, Open, Close, Get, Put).
    Io,
    /// Opcode not classified (InvalidExcode, Unknown, lead bytes).
    Unclassified,
}

/// Source of a load operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadSource {
    /// Frame variable via EBP offset (`%a`).
    Frame,
    /// Literal constant (inline in instruction stream).
    Literal,
    /// Object member via object pointer + offset.
    Memory,
    /// Double-indirection via pointer at frame slot.
    Indirect,
}

/// Target of a store operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreTarget {
    /// Frame variable via EBP offset (`%a`).
    Frame,
    /// Object member via object pointer + offset.
    Memory,
    /// Double-indirection via pointer at frame slot.
    Indirect,
}

/// Arithmetic/logical operation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArithOp {
    /// Addition.
    Add,
    /// Subtraction.
    Sub,
    /// Multiplication.
    Mul,
    /// Floating-point division (`/`).
    Div,
    /// Integer division (`\`).
    IDiv,
    /// Modulo.
    Mod,
    /// Exponentiation (`^`).
    Pow,
    /// Unary negation.
    Neg,
    /// String concatenation (`&`).
    Concat,
    /// Bitwise AND.
    And,
    /// Bitwise OR.
    Or,
    /// Bitwise XOR.
    Xor,
    /// Bitwise NOT.
    Not,
    /// Bitwise EQV (equivalence).
    Eqv,
    /// Bitwise IMP (implication).
    Imp,
    /// Absolute value.
    Abs,
    /// Unrecognized arithmetic.
    Other,
}

/// Kind of call operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallKind {
    /// COM vtable call (`VCall*`).
    VCall,
    /// COM vtable call on `Me` (`ThisVCall*`).
    ThisVCall,
    /// Import address call (`ImpAdCall*`).
    ImpAdCall,
    /// Late-bound IDispatch call (`Late*`).
    LateCall,
    /// Other call type.
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::opcode::{
        LEAD0_TABLE, LEAD1_TABLE, LEAD2_TABLE, LEAD3_TABLE, LEAD4_TABLE, PRIMARY_TABLE,
    };

    #[test]
    fn test_data_type_sizes() {
        assert_eq!(PCodeDataType::I4.eval_stack_slots(), 1);
        assert_eq!(PCodeDataType::R8.eval_stack_slots(), 2);
        assert_eq!(PCodeDataType::Var.eval_stack_slots(), 4);
        assert_eq!(PCodeDataType::FPR4.eval_stack_slots(), 0);
        assert!(PCodeDataType::FPR8.is_fpu());
        assert!(!PCodeDataType::I4.is_fpu());
    }

    #[test]
    fn test_data_type_from_opcode() {
        // AddI4 should have data_type = Some(I4)
        let info = &PRIMARY_TABLE[0xAA]; // AddI4
        assert_eq!(info.mnemonic, "AddI4");
        assert_eq!(info.data_type, Some(PCodeDataType::I4));

        // FLdFPR8 should have data_type = Some(FPR8)
        let info = &PRIMARY_TABLE[0x6F]; // FLdFPR8
        assert_eq!(info.data_type, Some(PCodeDataType::FPR8));

        // Branch has no data type
        let info = &PRIMARY_TABLE[0x1E]; // Branch
        assert_eq!(info.data_type, None);

        // InvalidExcode has no data type
        let info = &PRIMARY_TABLE[0x01];
        assert_eq!(info.data_type, None);
    }

    #[test]
    fn test_semantics_from_opcode() {
        // AddI4 → Arithmetic/Add
        let info = &PRIMARY_TABLE[0xAA];
        assert_eq!(
            info.semantics,
            OpcodeSemantics::Arithmetic { op: ArithOp::Add }
        );

        // FLdRfVar → Load/Frame
        let info = &PRIMARY_TABLE[0x04];
        assert_eq!(
            info.semantics,
            OpcodeSemantics::Load {
                source: LoadSource::Frame
            }
        );

        // Branch → Branch/unconditional
        let info = &PRIMARY_TABLE[0x1E];
        assert_eq!(
            info.semantics,
            OpcodeSemantics::Branch { conditional: false }
        );

        // BranchF → Branch/conditional
        let info = &PRIMARY_TABLE[0x1C];
        assert_eq!(
            info.semantics,
            OpcodeSemantics::Branch { conditional: true }
        );

        // VCallHresult → Call/VCall
        let info = &PRIMARY_TABLE[0x0D];
        assert_eq!(
            info.semantics,
            OpcodeSemantics::Call {
                kind: CallKind::VCall
            }
        );

        // LargeBos → Nop
        let info = &PRIMARY_TABLE[0x00];
        assert_eq!(info.semantics, OpcodeSemantics::Nop);

        // InvalidExcode → Unclassified
        let info = &PRIMARY_TABLE[0x01];
        assert_eq!(info.semantics, OpcodeSemantics::Unclassified);
    }

    #[test]
    fn test_convert_types() {
        // CStrR8 → Convert from R8 to Str
        let info = &LEAD1_TABLE[0x00]; // CStrR8
        assert_eq!(info.mnemonic, "CStrR8");
        let OpcodeSemantics::Convert { from, to } = info.semantics else {
            panic!("expected Convert, got {:?}", info.semantics);
        };
        assert_eq!(from, Some(PCodeDataType::R8));
        assert_eq!(to, Some(PCodeDataType::Str));
    }

    #[test]
    fn test_all_implemented_opcodes_have_semantics() {
        let tables: [&[crate::pcode::opcode::OpcodeInfo; 256]; 6] = [
            &PRIMARY_TABLE,
            &LEAD0_TABLE,
            &LEAD1_TABLE,
            &LEAD2_TABLE,
            &LEAD3_TABLE,
            &LEAD4_TABLE,
        ];

        let mut classified = 0;

        for table in &tables {
            for info in table.iter() {
                if info.is_implemented() && !info.is_lead_byte() {
                    if info.semantics != OpcodeSemantics::Unclassified {
                        classified += 1;
                    } else {
                        // Only opcodes with empty category should be unclassified
                        assert!(
                            info.category.is_empty(),
                            "Implemented opcode {} (table {:?}, 0x{:02X}) with category '{}' is Unclassified",
                            info.mnemonic,
                            info.table,
                            info.index,
                            info.category
                        );
                    }
                }
            }
        }

        assert!(
            classified > 1000,
            "Expected >1000 classified opcodes, got {}",
            classified
        );
    }
}
