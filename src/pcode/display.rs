//! Display formatting for P-Code instructions and operands.
//!
//! Provides human-readable disassembly output in the style:
//! ```text
//! 0000  LitI2 0x0005
//! 0003  LitI2 0x000A
//! 0006  AddI2
//! 0007  ExitProc
//! ```

use std::fmt;

use crate::pcode::{decoder::Instruction, operand::Operand};

/// Formats as `{offset:04X}  {mnemonic} {operands...}`.
///
/// `Resume` / `OnErrorGoto` instructions render their source-level form
/// (`Resume Next`, `On Error GoTo 0`, …) via [`Instruction::error_flow`] rather
/// than printing a sentinel operand as a bogus `loc_FFFF`.
impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ef) = self.error_flow() {
            return write!(f, "{:04X}  {ef}", self.offset);
        }
        write!(f, "{:04X}  {}", self.offset, self.info.mnemonic)?;
        for op in &self.operands {
            match op {
                Some(operand) => write!(f, " {operand}")?,
                None => break,
            }
        }
        Ok(())
    }
}

/// Formats each operand variant in disassembly notation (e.g. `0x0005`,
/// `var_90`, `[pool+0010]`, `loc_0020`).
impl fmt::Display for Operand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Operand::Byte(v) => write!(f, "0x{v:02X}"),
            Operand::Int16(v) => {
                if *v < 0 {
                    write!(f, "-0x{:04X}", v.unsigned_abs())
                } else {
                    write!(f, "0x{v:04X}")
                }
            }
            Operand::Int32(v) => {
                if *v < 0 {
                    write!(f, "-0x{:08X}", v.unsigned_abs())
                } else {
                    write!(f, "0x{v:08X}")
                }
            }
            Operand::StackVar(v) => {
                if *v < 0 {
                    write!(f, "var_{:X}", v.unsigned_abs())
                } else {
                    write!(f, "arg_{:X}", *v as u16)
                }
            }
            Operand::ConstPoolIndex(i) => write!(f, "[pool+{i:04X}]"),
            Operand::JumpTarget(t) => write!(f, "loc_{t:04X}"),
            Operand::ControlIndex(i) => write!(f, "ctrl_{i:04X}"),
            Operand::VTableRef { offset, control } => {
                write!(f, "vtbl({offset:04X}, ctrl_{control:04X})")
            }
            Operand::ExternalCall { import, arg_info } => {
                write!(f, "ext({import:04X}, {arg_info:04X})")
            }
            Operand::VariableLength { byte_count } => {
                write!(f, "({byte_count} bytes)")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::decoder::InstructionIterator;

    #[test]
    fn test_display_instruction_no_operands() {
        let bytes = [0x14]; // ExitProc
        let mut iter = InstructionIterator::new(&bytes, 1);
        let insn = iter.next().unwrap().unwrap();
        let s = format!("{insn}");
        assert_eq!(s, "0000  ExitProc");
    }

    #[test]
    fn test_display_instruction_with_operand() {
        let bytes = [0xF3, 0x05, 0x00]; // LitI2 5
        let mut iter = InstructionIterator::new(&bytes, 3);
        let insn = iter.next().unwrap().unwrap();
        let s = format!("{insn}");
        assert_eq!(s, "0000  LitI2 0x0005");
    }

    #[test]
    fn test_display_stack_var_local() {
        let op = Operand::StackVar(-144); // var_90
        assert_eq!(format!("{op}"), "var_90");
    }

    #[test]
    fn test_display_stack_var_arg() {
        let op = Operand::StackVar(8);
        assert_eq!(format!("{op}"), "arg_8");
    }

    #[test]
    fn test_display_jump_target() {
        let op = Operand::JumpTarget(0x0020);
        assert_eq!(format!("{op}"), "loc_0020");
    }

    #[test]
    fn test_display_const_pool() {
        let op = Operand::ConstPoolIndex(0x0010);
        assert_eq!(format!("{op}"), "[pool+0010]");
    }

    #[test]
    fn test_display_byte() {
        let op = Operand::Byte(0x42);
        assert_eq!(format!("{op}"), "0x42");
    }

    #[test]
    fn test_display_int32_negative() {
        let op = Operand::Int32(-1);
        assert_eq!(format!("{op}"), "-0x00000001");
    }

    #[test]
    fn test_display_vtable_ref() {
        let op = Operand::VTableRef {
            offset: 0x10,
            control: 3,
        };
        assert_eq!(format!("{op}"), "vtbl(0010, ctrl_0003)");
    }

    #[test]
    fn test_display_external_call() {
        let op = Operand::ExternalCall {
            import: 2,
            arg_info: 4,
        };
        assert_eq!(format!("{op}"), "ext(0002, 0004)");
    }

    #[test]
    fn test_display_variable_length() {
        let op = Operand::VariableLength { byte_count: 6 };
        assert_eq!(format!("{op}"), "(6 bytes)");
    }

    #[test]
    fn test_display_control_index() {
        let op = Operand::ControlIndex(5);
        assert_eq!(format!("{op}"), "ctrl_0005");
    }

    #[test]
    fn test_display_full_disassembly() {
        let bytes = [
            0xF3, 0x05, 0x00, // LitI2 5
            0xF3, 0x0A, 0x00, // LitI2 10
            0xA9, // AddI2
            0x14, // ExitProc
        ];
        let iter = InstructionIterator::new(&bytes, bytes.len() as u16);
        let lines: Vec<String> = iter.map(|r| format!("{}", r.unwrap())).collect();
        assert_eq!(lines[0], "0000  LitI2 0x0005");
        assert_eq!(lines[1], "0003  LitI2 0x000A");
        assert_eq!(lines[2], "0006  AddI2");
        assert_eq!(lines[3], "0007  ExitProc");
    }
}
