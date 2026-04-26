//! P-Code instruction decoder and streaming iterator.
//!
//! The [`InstructionIterator`] yields decoded [`Instruction`]s from a
//! P-Code byte stream. It handles all three instruction categories:
//!
//! 1. **Primary opcodes** (1 byte): Direct index into the primary dispatch table.
//! 2. **Extended opcodes** (2 bytes): Lead byte (`0xFB`-`0xFF`) followed by
//!    the actual opcode byte, indexed into the corresponding extended table.
//! 3. **Variable-length opcodes** (size == -1): A `u16` byte count follows the
//!    opcode, then that many bytes of payload data.

use crate::{
    error::Error,
    pcode::opcode::{self, OpcodeInfo},
    pcode::operand::{self, Operand},
    pcode::semantics::PCodeDataType,
    util::read_u16_le,
};

/// Maximum sentinel raw length when an instruction's byte span exceeds `u8::MAX`.
///
/// VB6 instructions are at most a few dozen bytes, but variable-length
/// payloads could in principle exceed 255. We saturate the [`Instruction::raw_len`]
/// field rather than panic; the iterator's `pos` is the source of truth for stream
/// progress, so this only affects the public-facing length field.
const RAW_LEN_SATURATION: u8 = u8::MAX;

/// A single decoded P-Code instruction.
///
/// Contains the opcode metadata, decoded operands, and positional information
/// within the P-Code stream.
#[derive(Debug, Clone)]
pub struct Instruction {
    /// Byte offset of this instruction within the P-Code stream
    /// (relative to the start of the procedure's P-Code).
    pub offset: u16,
    /// Total raw byte length of this instruction in the stream.
    ///
    /// For primary opcodes: 1 (opcode) + operand bytes.
    /// For extended opcodes: 2 (lead byte + opcode) + operand bytes.
    /// For variable-length: opcode bytes + 2 (size field) + payload bytes.
    pub raw_len: u8,
    /// Static reference to the opcode's metadata (mnemonic, size, format).
    pub info: &'static OpcodeInfo,
    /// Decoded operands (up to 4). Unused slots are `None`.
    pub operands: [Option<Operand>; 4],
}

impl Instruction {
    /// Returns the type the opcode imprints on its evaluation-stack result, if any.
    ///
    /// Mirrors the `data_type` field on the parent [`OpcodeInfo`] — for
    /// example `LitI4` returns `Some(PCodeDataType::I4)`, `FStR8` returns
    /// `Some(PCodeDataType::R8)`, control-flow / Nop / Stack opcodes return
    /// `None`. Build-time-resolved from the opcode's mnemonic suffix; no
    /// runtime string parsing.
    ///
    /// This is the type-level signal consumers should prefer over
    /// pattern-matching on mnemonic strings (e.g., `mnemonic.ends_with("I4")`),
    /// which is fragile across renamings and does not generalize across
    /// the six dispatch tables.
    #[inline]
    pub fn data_type(&self) -> Option<PCodeDataType> {
        self.info.data_type
    }

    /// Returns the inferred type of the operand at slot `index`, if any.
    ///
    /// Today this projects the parent opcode's
    /// [`data_type`](Self::data_type) for every operand slot — VB6 P-Code
    /// opcodes are monomorphic in their operand kinds (a `LitI4` always
    /// produces `I4`, an `FStR8` always stores `R8`), so the per-operand
    /// type equals the per-instruction type when one is defined. The
    /// per-slot signature is preserved so future revisions can refine it
    /// to per-operand types (for example, `Convert { from, to }` opcodes
    /// where the source operand has a different type than the result).
    ///
    /// Returns `None` for out-of-range `index`, for empty operand slots,
    /// and for opcodes whose [`OpcodeInfo::data_type`] is `None`
    /// (control flow, stack manipulation, debug markers).
    #[inline]
    pub fn operand_type(&self, index: usize) -> Option<PCodeDataType> {
        // Validate the slot exists and carries an operand.
        let _ = self.operands.get(index)?.as_ref()?;
        self.info.data_type
    }
}

/// Streaming iterator over P-Code instructions.
///
/// Yields one [`Instruction`] per call to [`next()`](Iterator::next),
/// consuming bytes from the P-Code stream. Returns `None` when the
/// stream is exhausted (position reaches `limit`).
///
/// # Example
///
/// ```ignore
/// let iter = InstructionIterator::new(pcode_bytes, proc_size);
/// for result in iter {
///     let insn = result?;
///     println!("{:04X}  {}", insn.offset, insn.info.mnemonic);
/// }
/// ```
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct InstructionIterator<'a> {
    /// The P-Code byte stream for one procedure.
    bytes: &'a [u8],
    /// Current position within `bytes`.
    pos: usize,
    /// Total expected length (from `ProcDscInfo.wProcSize`).
    limit: usize,
}

impl<'a> InstructionIterator<'a> {
    /// Creates a new iterator over `pcode_bytes[..proc_size]`.
    ///
    /// # Arguments
    ///
    /// * `pcode_bytes` - The raw P-Code byte stream for one procedure.
    ///   Must be at least `proc_size` bytes long.
    /// * `proc_size` - The procedure size from `ProcDscInfo.wProcSize`.
    ///   The iterator stops at this boundary.
    pub fn new(pcode_bytes: &'a [u8], proc_size: u16) -> Self {
        let limit = (proc_size as usize).min(pcode_bytes.len());
        Self {
            bytes: pcode_bytes,
            pos: 0,
            limit,
        }
    }

    /// Returns the current byte position within the P-Code stream.
    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }
}

impl Iterator for InstructionIterator<'_> {
    type Item = Result<Instruction, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.limit {
            return None;
        }

        let start = self.pos;

        // Read first byte
        let Some(&first_byte) = self.bytes.get(self.pos) else {
            return Some(Err(Error::UnexpectedEndOfPCode {
                offset: self.pos,
                needed: 1,
            }));
        };
        self.pos = match self.pos.checked_add(1) {
            Some(v) => v,
            None => {
                return Some(Err(Error::ArithmeticOverflow {
                    context: "decoder pos advance after first byte",
                }));
            }
        };

        // Determine if this is a lead byte
        let next_byte = if self.pos < self.limit {
            self.bytes.get(self.pos).copied()
        } else {
            None
        };

        let (info, opcode_bytes_consumed) = opcode::lookup(first_byte, next_byte);

        // If it's an extended opcode, consume the second byte
        if opcode_bytes_consumed == 2 {
            if self.pos >= self.limit {
                return Some(Err(Error::UnexpectedEndOfPCode {
                    offset: start,
                    needed: 2,
                }));
            }
            self.pos = match self.pos.checked_add(1) {
                Some(v) => v,
                None => {
                    return Some(Err(Error::ArithmeticOverflow {
                        context: "decoder pos advance after lead byte",
                    }));
                }
            };
        }

        // Now decode the operands
        let operands;

        if info.is_variable_length() {
            // Variable-length instruction: read u16 byte count, then payload
            let after_size = match self.pos.checked_add(2) {
                Some(v) => v,
                None => {
                    return Some(Err(Error::ArithmeticOverflow {
                        context: "decoder variable-length size offset",
                    }));
                }
            };
            if after_size > self.limit {
                let needed = after_size.saturating_sub(start);
                return Some(Err(Error::UnexpectedEndOfPCode {
                    offset: start,
                    needed,
                }));
            }
            let byte_count = match read_u16_le(self.bytes, self.pos) {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
            self.pos = after_size;

            // Validate and skip the payload
            let payload_end = match self.pos.checked_add(byte_count as usize) {
                Some(v) => v,
                None => {
                    return Some(Err(Error::ArithmeticOverflow {
                        context: "decoder variable-length payload end",
                    }));
                }
            };
            if payload_end > self.limit {
                return Some(Err(Error::InvalidVariableLengthSize {
                    opcode_name: info.mnemonic,
                    size: byte_count,
                }));
            }
            self.pos = payload_end;

            operands = [
                Some(Operand::VariableLength { byte_count }),
                None,
                None,
                None,
            ];
        } else if info.size > 0 {
            // Fixed-size instruction: decode operands according to format string.
            // The 'size' includes the opcode byte itself (but not the lead byte).
            match operand::decode_operands(
                info.operand_format,
                self.bytes,
                &mut self.pos,
                self.limit,
            ) {
                Ok(ops) => operands = ops,
                Err(e) => return Some(Err(e)),
            }

            // Ensure pos advances to the declared instruction size even when
            // the operand format is empty or incomplete. Many opcodes have
            // size > 1 but no documented operand format specifiers — we still
            // need to skip over their operand bytes to stay aligned.
            let lead_extra = opcode_bytes_consumed.saturating_sub(1);
            let expected_end = start
                .checked_add(lead_extra)
                .and_then(|v| v.checked_add(info.size as usize));
            if let Some(expected_end) = expected_end
                && self.pos < expected_end
                && expected_end <= self.limit
            {
                self.pos = expected_end;
            }
        } else {
            // Unimplemented/invalid opcode (size == 0)
            operands = [None; 4];
        }

        let raw_len = u8::try_from(self.pos.saturating_sub(start)).unwrap_or(RAW_LEN_SATURATION);
        let offset_u16 = u16::try_from(start).unwrap_or(u16::MAX);

        Some(Ok(Instruction {
            offset: offset_u16,
            raw_len,
            info,
            operands,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcode::opcode::{DispatchTable, PRIMARY_TABLE};

    /// Collect all instructions from a byte stream, asserting no errors.
    fn decode_all(bytes: &[u8]) -> Vec<Instruction> {
        let iter = InstructionIterator::new(bytes, bytes.len() as u16);
        iter.map(|r| r.expect("decode error")).collect()
    }

    #[test]
    fn test_exit_proc() {
        // 0x14 = ExitProc, size 1 (no operands)
        let insns = decode_all(&[0x14]);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].info.mnemonic, "ExitProc");
        assert_eq!(insns[0].raw_len, 1);
        assert_eq!(insns[0].offset, 0);
        assert!(insns[0].operands[0].is_none());
    }

    #[test]
    fn test_lit_i2() {
        // 0xF3 = LitI2, size 3, format "%2"
        let insns = decode_all(&[0xF3, 0x05, 0x00]);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].info.mnemonic, "LitI2");
        assert_eq!(insns[0].raw_len, 3);
        assert_eq!(insns[0].operands[0], Some(Operand::Int16(5)));
    }

    #[test]
    fn test_branch() {
        // 0x1E = Branch, size 3, format "%l"
        let insns = decode_all(&[0x1E, 0x20, 0x00]);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].info.mnemonic, "Branch");
        assert_eq!(insns[0].operands[0], Some(Operand::JumpTarget(0x20)));
    }

    #[test]
    fn test_lit_str() {
        // 0x1B = LitStr, size 3, format "%s"
        let insns = decode_all(&[0x1B, 0x10, 0x00]);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].info.mnemonic, "LitStr");
        assert_eq!(insns[0].operands[0], Some(Operand::ConstPoolIndex(0x10)));
    }

    #[test]
    fn test_fld_rf_var() {
        // 0x04 = FLdRfVar, size 3, format "%a"
        let insns = decode_all(&[0x04, 0x70, 0xFF]);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].info.mnemonic, "FLdRfVar");
        assert_eq!(insns[0].operands[0], Some(Operand::StackVar(-144))); // var_90
    }

    #[test]
    fn test_lit_i4() {
        // 0xF5 = LitI4, size 5, format "%4"
        let insns = decode_all(&[0xF5, 0x78, 0x56, 0x34, 0x12]);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].info.mnemonic, "LitI4");
        assert_eq!(insns[0].operands[0], Some(Operand::Int32(0x12345678)));
    }

    #[test]
    fn test_multiple_instructions() {
        // LitI2 5; LitI2 10; AddI2; ExitProc
        let bytes = [
            0xF3, 0x05, 0x00, // LitI2 5
            0xF3, 0x0A, 0x00, // LitI2 10
            0xA9, // AddI2
            0x14, // ExitProc
        ];
        let insns = decode_all(&bytes);
        assert_eq!(insns.len(), 4);
        assert_eq!(insns[0].info.mnemonic, "LitI2");
        assert_eq!(insns[0].offset, 0);
        assert_eq!(insns[1].info.mnemonic, "LitI2");
        assert_eq!(insns[1].offset, 3);
        assert_eq!(insns[2].info.mnemonic, "AddI2");
        assert_eq!(insns[2].offset, 6);
        assert_eq!(insns[3].info.mnemonic, "ExitProc");
        assert_eq!(insns[3].offset, 7);
    }

    #[test]
    fn test_extended_opcode_lead0() {
        // 0xFB 0x00 = Lead0 table, opcode 0x00
        let bytes = [0xFB, 0x00];
        let insns = decode_all(&bytes);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].info.table, DispatchTable::Lead0);
        assert_eq!(insns[0].raw_len, 2);
    }

    #[test]
    fn test_ffree_var_variable_length() {
        // 0x36 = FFreeVar (size = -1)
        // Format: [0x36] [u16 byte_count=6] [6 bytes of payload]
        let bytes = [
            0x36, // FFreeVar opcode
            0x06, 0x00, // byte_count = 6
            0x70, 0xFF, // var_90
            0x68, 0xFF, // var_98
            0x60, 0xFF, // var_A0
        ];
        let insns = decode_all(&bytes);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].info.mnemonic, "FFreeVar");
        assert_eq!(
            insns[0].operands[0],
            Some(Operand::VariableLength { byte_count: 6 })
        );
        assert_eq!(insns[0].raw_len, 9); // 1 + 2 + 6
    }

    #[test]
    fn test_ffree_str_variable_length() {
        // 0x32 = FFreeStr (size = -1)
        let bytes = [
            0x32, // FFreeStr
            0x02, 0x00, // byte_count = 2
            0x80, 0xFF, // one var ref
        ];
        let insns = decode_all(&bytes);
        assert_eq!(insns.len(), 1);
        assert_eq!(insns[0].info.mnemonic, "FFreeStr");
    }

    #[test]
    fn test_truncated_instruction() {
        // LitI2 needs 3 bytes total, but we only provide 2
        // The decoder reads the opcode (1 byte), then tries to read operands
        // and hits UnexpectedEndOfPCode
        let bytes = [0xF3, 0x05];
        let iter = InstructionIterator::new(&bytes, bytes.len() as u16);
        let results: Vec<_> = iter.collect();
        // At least one result should be an error
        assert!(results.iter().any(|r| r.is_err()));
    }

    #[test]
    fn test_truncated_lead_byte() {
        // Lead byte 0xFB at the very end, no second byte within limit
        let bytes = [0xFB];
        let iter = InstructionIterator::new(&bytes, bytes.len() as u16);
        let results: Vec<_> = iter.collect();
        // Should yield something (possibly an error or the lead byte's own entry)
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_empty_stream() {
        let bytes: &[u8] = &[];
        let insns = decode_all(bytes);
        assert!(insns.is_empty());
    }

    #[test]
    fn test_data_type_and_operand_type() {
        // LitI4 — should report I4 as both instruction- and operand-type.
        let insns = decode_all(&[0xF5, 0x78, 0x56, 0x34, 0x12]);
        let insn = &insns[0];
        assert_eq!(insn.data_type(), Some(PCodeDataType::I4));
        assert_eq!(insn.operand_type(0), Some(PCodeDataType::I4));
        // LitI2
        let insns = decode_all(&[0xF3, 0x05, 0x00]);
        let insn = &insns[0];
        assert_eq!(insn.data_type(), Some(PCodeDataType::I2));
        assert_eq!(insn.operand_type(0), Some(PCodeDataType::I2));
        // ExitProc — Return semantics, no data type.
        let insns = decode_all(&[0x14]);
        let insn = &insns[0];
        assert_eq!(insn.data_type(), None);
        // Out-of-range and empty-slot handling.
        assert_eq!(insn.operand_type(0), None);
        assert_eq!(insn.operand_type(7), None);
    }

    #[test]
    fn test_position_tracking() {
        let bytes = [0x14, 0x14]; // Two ExitProc
        let mut iter = InstructionIterator::new(&bytes, bytes.len() as u16);
        assert_eq!(iter.position(), 0);
        let _ = iter.next();
        assert_eq!(iter.position(), 1);
        let _ = iter.next();
        assert_eq!(iter.position(), 2);
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_invalid_variable_length_size() {
        // FFreeVar with byte_count that exceeds remaining stream
        let bytes = [
            0x36, // FFreeVar
            0xFF, 0x00, // byte_count = 255 (way too large)
        ];
        let iter = InstructionIterator::new(&bytes, bytes.len() as u16);
        let results: Vec<_> = iter.collect();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_err());
    }

    #[test]
    fn test_decode_all_single_byte_primary_opcodes() {
        // Verify that every size-1 primary opcode decodes to exactly 1 byte
        for i in 0..=0xFA_u8 {
            // Skip lead bytes 0xFB-0xFF
            let info = &PRIMARY_TABLE[i as usize];
            if info.size == 1 && info.is_implemented() {
                let bytes = [i];
                let insns = decode_all(&bytes);
                assert_eq!(
                    insns.len(),
                    1,
                    "Opcode 0x{:02X} ({}) should decode to 1 instruction",
                    i,
                    info.mnemonic
                );
                assert_eq!(insns[0].raw_len, 1);
            }
        }
    }
}
