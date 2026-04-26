//! Frame variable resolution for P-Code stack offsets.
//!
//! Resolves `%a` operands (`StackVar(i16)` EBP-relative offsets) to
//! named variables with type information. The resolver distinguishes:
//!
//! - **Arguments** (positive offsets above EBP+0x08)
//! - **Housekeeping** (EBP-0x04 through EBP-0x88, runtime frame slots)
//! - **Locals** (below EBP-0x88, procedure-specific variables)

use crate::{
    addressmap::AddressMap,
    vb::{
        functype::{ArgType, FuncTypDesc},
        procedure::{ProcDscInfo, pcode_frame},
    },
};

/// Resolved information about a frame variable.
#[derive(Debug, Clone)]
pub enum FrameVar {
    /// Local variable within the procedure's frame.
    Local {
        /// Byte offset from the start of the local variable area.
        frame_offset: u16,
    },
    /// Function argument.
    Argument {
        /// Zero-based argument index.
        index: u8,
        /// Parameter name from FuncTypDesc, if available.
        name: Option<String>,
        /// Parameter type from FuncTypDesc, if available.
        arg_type: Option<ArgType>,
    },
    /// Runtime housekeeping slot (pcode_ip, const_pool_va, etc.).
    Housekeeping {
        /// Named constant from the pcode_frame module.
        name: &'static str,
    },
    /// Offset that doesn't fit recognized patterns.
    Unknown {
        /// The raw EBP offset.
        offset: i16,
    },
}

/// Resolves EBP-relative stack offsets to named frame variables.
///
/// Constructed once per method from `ProcDscInfo` and optional
/// `FuncTypDesc`, then reused for every `%a` operand in that method.
pub struct FrameResolver {
    frame_size: u16,
    param_names: Vec<String>,
    arg_types: Vec<ArgType>,
}

impl FrameResolver {
    /// Creates a resolver for the given procedure.
    ///
    /// If `func_type` is available (from `PrivateObjectDescriptor`),
    /// parameter names and types will be resolved. Otherwise, arguments
    /// are identified by index only.
    pub fn new(
        proc_dsc: &ProcDscInfo<'_>,
        func_type: Option<&FuncTypDesc<'_>>,
        map: &AddressMap<'_>,
    ) -> Self {
        let (param_names, arg_types) = if let Some(ftd) = func_type {
            let names: Vec<String> = ftd
                .param_names(map)
                .into_iter()
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            let types = ftd.arg_types();
            (names, types)
        } else {
            (Vec::new(), Vec::new())
        };

        Self {
            frame_size: proc_dsc.frame_size().unwrap_or(0),
            param_names,
            arg_types,
        }
    }

    /// Resolves an EBP-relative offset to a [`FrameVar`].
    ///
    /// # Layout
    ///
    /// ```text
    /// EBP+0x08+N  = argument N (4 bytes each)
    /// EBP+0x04    = saved return address
    /// EBP+0x00    = saved EBP
    /// EBP-0x04    = first housekeeping slot
    /// ...
    /// EBP-0x88    = last housekeeping slot
    /// EBP-0x8C    = first local variable (if frame_size > 0)
    /// ...
    /// EBP-(0x88+frame_size) = last local byte
    /// ```
    pub fn resolve(&self, offset: i16) -> FrameVar {
        if offset >= 0x08 {
            // Positive offset: function argument. Use checked arithmetic to
            // avoid panicking on absurd offsets like i16::MAX.
            let arg_byte = i32::from(offset).saturating_sub(0x08);
            let arg_index = arg_byte / 4;
            let index = u8::try_from(arg_index).unwrap_or(u8::MAX);
            let name = self.param_names.get(index as usize).cloned();
            let arg_type = self.arg_types.get(index as usize).copied();
            return FrameVar::Argument {
                index,
                name,
                arg_type,
            };
        }

        if offset > 0 && offset < 0x08 {
            // Saved EBP / return address area
            return FrameVar::Unknown { offset };
        }

        if offset == 0 {
            return FrameVar::Unknown { offset };
        }

        // Negative offset: check housekeeping vs local. Compute abs via i32 to
        // avoid `-i16::MIN` overflow in plain `-(offset as i32)`.
        let abs_offset = i32::from(offset).unsigned_abs();

        if abs_offset <= pcode_frame::HOUSEKEEPING_SIZE {
            // Runtime housekeeping slot
            let name = match i32::from(offset) {
                pcode_frame::PCODE_IP => "pcode_ip",
                pcode_frame::CONST_POOL_VA => "const_pool_va",
                pcode_frame::PROC_DSC_INFO => "proc_dsc_info",
                pcode_frame::ERROR_HANDLER_IP => "error_handler_ip",
                pcode_frame::ERROR_TARGET => "error_target",
                pcode_frame::ENGINE_CONTEXT => "engine_context",
                pcode_frame::ENGINE_TLS => "engine_tls",
                pcode_frame::PROC_FLAGS => "proc_flags",
                pcode_frame::OBJECT_PTR => "object_ptr",
                pcode_frame::ERROR_STATE => "error_state",
                pcode_frame::SAVED_PCODE_IP => "saved_pcode_ip",
                pcode_frame::HANDLER_FN => "handler_fn",
                _ => "housekeeping",
            };
            return FrameVar::Housekeeping { name };
        }

        // Local variable
        let local_byte = abs_offset.saturating_sub(pcode_frame::HOUSEKEEPING_SIZE);
        let frame_offset = u16::try_from(local_byte).unwrap_or(u16::MAX);
        if frame_offset <= self.frame_size {
            return FrameVar::Local { frame_offset };
        }

        FrameVar::Unknown { offset }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addressmap::SectionEntry;

    fn make_test_map(file: &[u8]) -> AddressMap<'_> {
        AddressMap::from_parts(
            file,
            0x00400000,
            vec![SectionEntry {
                virtual_address: 0x1000,
                virtual_size: 0x2000,
                raw_data_offset: 0x200,
                raw_data_size: 0x2000,
            }],
        )
    }

    fn make_proc_dsc(frame_size: u16, arg_size: u16) -> Vec<u8> {
        let mut data = vec![0u8; 0x1E]; // ProcDscInfo::MIN_SIZE
        data[0x04..0x06].copy_from_slice(&arg_size.to_le_bytes());
        data[0x06..0x08].copy_from_slice(&frame_size.to_le_bytes());
        data[0x08..0x0A].copy_from_slice(&0x0050u16.to_le_bytes()); // proc_size
        data[0x0A..0x0C].copy_from_slice(&0x001Eu16.to_le_bytes()); // total_size
        data
    }

    #[test]
    fn test_resolve_argument() {
        let file = vec![0u8; 0x3000];
        let map = make_test_map(&file);
        let pdi_data = make_proc_dsc(0x100, 0x10);
        let pdi = ProcDscInfo::parse(&pdi_data).unwrap();
        let resolver = FrameResolver::new(&pdi, None, &map);

        // EBP+0x08 = arg 0
        assert!(
            matches!(
                resolver.resolve(0x08),
                FrameVar::Argument {
                    index: 0,
                    name: None,
                    ..
                }
            ),
            "expected Argument(0), got {:?}",
            resolver.resolve(0x08)
        );

        // EBP+0x0C = arg 1
        assert!(
            matches!(resolver.resolve(0x0C), FrameVar::Argument { index: 1, .. }),
            "expected Argument(1), got {:?}",
            resolver.resolve(0x0C)
        );
    }

    #[test]
    fn test_resolve_housekeeping() {
        let file = vec![0u8; 0x3000];
        let map = make_test_map(&file);
        let pdi_data = make_proc_dsc(0x100, 0x10);
        let pdi = ProcDscInfo::parse(&pdi_data).unwrap();
        let resolver = FrameResolver::new(&pdi, None, &map);

        // EBP-0x5C = pcode_ip
        assert!(
            matches!(
                resolver.resolve(-0x5C),
                FrameVar::Housekeeping { name: "pcode_ip" }
            ),
            "expected Housekeeping(pcode_ip), got {:?}",
            resolver.resolve(-0x5C)
        );

        // EBP-0x30 = object_ptr
        assert!(
            matches!(
                resolver.resolve(-0x30),
                FrameVar::Housekeeping { name: "object_ptr" }
            ),
            "expected Housekeeping(object_ptr), got {:?}",
            resolver.resolve(-0x30)
        );
    }

    #[test]
    fn test_resolve_local() {
        let file = vec![0u8; 0x3000];
        let map = make_test_map(&file);
        let pdi_data = make_proc_dsc(0x100, 0x10);
        let pdi = ProcDscInfo::parse(&pdi_data).unwrap();
        let resolver = FrameResolver::new(&pdi, None, &map);

        // EBP-0x8C = first local (offset 4 from local area start)
        assert!(
            matches!(resolver.resolve(-0x8C), FrameVar::Local { frame_offset: 4 }),
            "expected Local(4), got {:?}",
            resolver.resolve(-0x8C)
        );

        // EBP-0x90 = local at offset 8
        assert!(
            matches!(resolver.resolve(-0x90), FrameVar::Local { frame_offset: 8 }),
            "expected Local(8), got {:?}",
            resolver.resolve(-0x90)
        );
    }
}
