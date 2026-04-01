//! P-Code operand types and decoding.
//!
//! Operands are the arguments to P-Code instructions. They are decoded
//! according to format specifiers embedded in the opcode table:
//!
//! | Specifier | Meaning | Bytes Consumed |
//! |-----------|---------|----------------|
//! | `%1` | 1-byte unsigned literal | 1 |
//! | `%2` | 2-byte (Int16) literal | 2 |
//! | `%4` | 4-byte (Int32) literal | 4 |
//! | `%a` | Stack variable reference (signed Int16 EBP offset) | 2 |
//! | `%s` | Constant pool index (unsigned Int16) | 2 |
//! | `%l` | Jump target (unsigned Int16 from function start) | 2 |
//! | `%c` | Control/import index (unsigned Int16) | 2 |
//! | `%v` | VTable reference (two Int16 values) | 4 |
//! | `%x` | External call (two Int16 values) | 4 |

use crate::{
    error::Error,
    util::{read_i16_le, read_i32_le, read_u16_le},
};

/// A decoded operand from a P-Code instruction.
///
/// Each variant corresponds to one of the format specifiers in the opcode table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operand {
    /// `%1`: 1-byte unsigned literal value.
    Byte(u8),
    /// `%2`: 2-byte signed integer literal.
    Int16(i16),
    /// `%4`: 4-byte signed integer literal.
    Int32(i32),
    /// `%a`: Stack variable reference (signed 16-bit offset from EBP).
    ///
    /// Negative values are local variables (e.g., `-0x90` = `var_90`),
    /// positive values are function arguments.
    StackVar(i16),
    /// `%s`: Constant pool index (unsigned 16-bit).
    ///
    /// Resolved as `DataConst + index` to find the constant.
    ConstPoolIndex(u16),
    /// `%l`: Jump target (unsigned 16-bit offset from function start).
    JumpTarget(u16),
    /// `%c`: Control/import index (unsigned 16-bit).
    ControlIndex(u16),
    /// `%v`: VTable reference (vtable offset + control index).
    VTableRef {
        /// VTable offset within the object's vtable.
        offset: u16,
        /// Control index for the object.
        control: u16,
    },
    /// `%x`: External call reference (import index + argument info).
    ExternalCall {
        /// Index into the import/external table.
        import: u16,
        /// Argument count or stack adjustment info.
        arg_info: u16,
    },
    /// Variable-length byte list (for `FFreeVar`, `FFreeStr`, `FFreeAd`, etc.).
    ///
    /// The `byte_count` gives the number of payload bytes. The payload
    /// typically consists of `byte_count / 2` stack variable references.
    VariableLength {
        /// Number of payload bytes following the size field.
        byte_count: u16,
    },
}

/// Decodes operands from the instruction stream according to the format string.
///
/// Reads operand bytes starting at `stream[pos]` and advances `pos`
/// past the consumed bytes.
///
/// # Arguments
///
/// * `format` - The operand format string from the opcode table (e.g., `"%a"`, `"%s %2"`).
/// * `stream` - The raw byte stream (the entire P-Code procedure).
/// * `pos` - Current position in the stream. Advanced past consumed bytes on return.
/// * `limit` - Maximum valid position in the stream.
///
/// # Returns
///
/// An array of up to 4 decoded operands. Unused slots are `None`.
///
/// # Errors
///
/// Returns [`Error::UnexpectedEndOfPCode`] if the stream is too short for the operands.
pub fn decode_operands(
    format: &str,
    stream: &[u8],
    pos: &mut usize,
    limit: usize,
) -> Result<[Option<Operand>; 4], Error> {
    let mut operands = [None; 4];
    let mut op_idx = 0;

    let chars: Vec<char> = format.chars().collect();
    let mut i = 0;

    while i < chars.len() && op_idx < 4 {
        if chars[i] == '%' && i + 1 < chars.len() {
            let spec = chars[i + 1];
            let operand = match spec {
                '1' => {
                    ensure_bytes(stream, *pos, 1, limit)?;
                    let val = stream[*pos];
                    *pos += 1;
                    Operand::Byte(val)
                }
                '2' => {
                    ensure_bytes(stream, *pos, 2, limit)?;
                    let val = read_i16_le(stream, *pos);
                    *pos += 2;
                    Operand::Int16(val)
                }
                '4' => {
                    ensure_bytes(stream, *pos, 4, limit)?;
                    let val = read_i32_le(stream, *pos);
                    *pos += 4;
                    Operand::Int32(val)
                }
                'a' => {
                    ensure_bytes(stream, *pos, 2, limit)?;
                    let val = read_i16_le(stream, *pos);
                    *pos += 2;
                    Operand::StackVar(val)
                }
                's' => {
                    ensure_bytes(stream, *pos, 2, limit)?;
                    let val = read_u16_le(stream, *pos);
                    *pos += 2;
                    Operand::ConstPoolIndex(val)
                }
                'l' => {
                    ensure_bytes(stream, *pos, 2, limit)?;
                    let val = read_u16_le(stream, *pos);
                    *pos += 2;
                    Operand::JumpTarget(val)
                }
                'c' => {
                    ensure_bytes(stream, *pos, 2, limit)?;
                    let val = read_u16_le(stream, *pos);
                    *pos += 2;
                    Operand::ControlIndex(val)
                }
                'v' => {
                    ensure_bytes(stream, *pos, 4, limit)?;
                    let offset = read_u16_le(stream, *pos);
                    let control = read_u16_le(stream, *pos + 2);
                    *pos += 4;
                    Operand::VTableRef { offset, control }
                }
                'x' => {
                    ensure_bytes(stream, *pos, 4, limit)?;
                    let import = read_u16_le(stream, *pos);
                    let arg_info = read_u16_le(stream, *pos + 2);
                    *pos += 4;
                    Operand::ExternalCall { import, arg_info }
                }
                '}' => {
                    // End-of-procedure marker, consumes 0 bytes
                    i += 2;
                    continue;
                }
                _ => {
                    // Unknown specifier, skip
                    i += 2;
                    continue;
                }
            };
            operands[op_idx] = Some(operand);
            op_idx += 1;
            i += 2;
        } else {
            i += 1;
        }
    }

    Ok(operands)
}

/// Ensures that at least `needed` bytes are available at `pos` within `limit`.
fn ensure_bytes(stream: &[u8], pos: usize, needed: usize, limit: usize) -> Result<(), Error> {
    let available = limit
        .saturating_sub(pos)
        .min(stream.len().saturating_sub(pos));
    if available < needed {
        return Err(Error::UnexpectedEndOfPCode {
            offset: pos,
            needed,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_byte_operand() {
        let stream = [0x42];
        let mut pos = 0;
        let ops = decode_operands("%1", &stream, &mut pos, stream.len()).unwrap();
        assert_eq!(ops[0], Some(Operand::Byte(0x42)));
        assert_eq!(ops[1], None);
        assert_eq!(pos, 1);
    }

    #[test]
    fn test_decode_int16_operand() {
        let stream = [0x34, 0x12];
        let mut pos = 0;
        let ops = decode_operands("%2", &stream, &mut pos, stream.len()).unwrap();
        assert_eq!(ops[0], Some(Operand::Int16(0x1234)));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_decode_int32_operand() {
        let stream = [0x78, 0x56, 0x34, 0x12];
        let mut pos = 0;
        let ops = decode_operands("%4", &stream, &mut pos, stream.len()).unwrap();
        assert_eq!(ops[0], Some(Operand::Int32(0x12345678)));
        assert_eq!(pos, 4);
    }

    #[test]
    fn test_decode_stack_var() {
        // -0x90 = 0xFF70 as i16
        let stream = [0x70, 0xFF];
        let mut pos = 0;
        let ops = decode_operands("%a", &stream, &mut pos, stream.len()).unwrap();
        assert_eq!(ops[0], Some(Operand::StackVar(-144)));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_decode_const_pool_index() {
        let stream = [0x10, 0x00];
        let mut pos = 0;
        let ops = decode_operands("%s", &stream, &mut pos, stream.len()).unwrap();
        assert_eq!(ops[0], Some(Operand::ConstPoolIndex(0x0010)));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_decode_jump_target() {
        let stream = [0x20, 0x00];
        let mut pos = 0;
        let ops = decode_operands("%l", &stream, &mut pos, stream.len()).unwrap();
        assert_eq!(ops[0], Some(Operand::JumpTarget(0x0020)));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_decode_control_index() {
        let stream = [0x05, 0x00];
        let mut pos = 0;
        let ops = decode_operands("%c", &stream, &mut pos, stream.len()).unwrap();
        assert_eq!(ops[0], Some(Operand::ControlIndex(5)));
        assert_eq!(pos, 2);
    }

    #[test]
    fn test_decode_vtable_ref() {
        let stream = [0x10, 0x00, 0x03, 0x00];
        let mut pos = 0;
        let ops = decode_operands("%v", &stream, &mut pos, stream.len()).unwrap();
        assert_eq!(
            ops[0],
            Some(Operand::VTableRef {
                offset: 0x10,
                control: 0x03,
            })
        );
        assert_eq!(pos, 4);
    }

    #[test]
    fn test_decode_external_call() {
        let stream = [0x02, 0x00, 0x04, 0x00];
        let mut pos = 0;
        let ops = decode_operands("%x", &stream, &mut pos, stream.len()).unwrap();
        assert_eq!(
            ops[0],
            Some(Operand::ExternalCall {
                import: 2,
                arg_info: 4,
            })
        );
        assert_eq!(pos, 4);
    }

    #[test]
    fn test_decode_multiple_operands() {
        // LitVarI2: %a %2
        let stream = [0x70, 0xFF, 0x05, 0x00];
        let mut pos = 0;
        let ops = decode_operands("%a %2", &stream, &mut pos, stream.len()).unwrap();
        assert_eq!(ops[0], Some(Operand::StackVar(-144)));
        assert_eq!(ops[1], Some(Operand::Int16(5)));
        assert_eq!(ops[2], None);
        assert_eq!(pos, 4);
    }

    #[test]
    fn test_decode_empty_format() {
        let stream = [0x00];
        let mut pos = 0;
        let ops = decode_operands("", &stream, &mut pos, stream.len()).unwrap();
        assert_eq!(ops[0], None);
        assert_eq!(pos, 0);
    }

    #[test]
    fn test_decode_end_of_procedure_marker() {
        let stream = [];
        let mut pos = 0;
        let ops = decode_operands("%}", &stream, &mut pos, stream.len()).unwrap();
        assert_eq!(ops[0], None); // %} consumes no bytes and produces no operand
        assert_eq!(pos, 0);
    }

    #[test]
    fn test_decode_truncated_stream() {
        let stream = [0x01]; // Only 1 byte, but %2 needs 2
        let mut pos = 0;
        assert!(matches!(
            decode_operands("%2", &stream, &mut pos, stream.len()),
            Err(Error::UnexpectedEndOfPCode { .. })
        ));
    }

    #[test]
    fn test_decode_truncated_at_limit() {
        let stream = [0x01, 0x02, 0x03, 0x04];
        let mut pos = 0;
        // Limit is 1, so only 1 byte available even though stream has 4
        assert!(matches!(
            decode_operands("%2", &stream, &mut pos, 1),
            Err(Error::UnexpectedEndOfPCode { .. })
        ));
    }

    #[test]
    fn test_decode_max_4_operands() {
        let stream = [0x01, 0x02, 0x03, 0x04, 0x05];
        let mut pos = 0;
        let ops = decode_operands("%1 %1 %1 %1 %1", &stream, &mut pos, stream.len()).unwrap();
        // Only 4 operands can be stored
        assert!(ops[0].is_some());
        assert!(ops[1].is_some());
        assert!(ops[2].is_some());
        assert!(ops[3].is_some());
        assert_eq!(pos, 4); // Only consumed 4 bytes (stopped at 4th operand)
    }
}
