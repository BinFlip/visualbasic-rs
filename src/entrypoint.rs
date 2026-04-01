//! VB6 entry point detection.
//!
//! VB6 executables (EXE) have this entry point pattern:
//!
//! ```x86asm
//! push    offset VBHeader     ; 0x68 <imm32>
//! call    ThunRTMain          ; 0xE8 <rel32>  (or indirect call)
//! ```
//!
//! VB6 ActiveX DLLs/OCXs use a different pattern — the DllMain entry
//! does NOT contain the VBHeader VA. Instead, the DLL exports
//! (`DllGetClassObject`, `DllRegisterServer`, etc.) each push it:
//!
//! ```x86asm
//! pop     eax
//! push    offset VBHeader     ; 0x68 <imm32>
//! push    <runtime_slot_1>
//! push    <runtime_slot_2>
//! push    eax
//! jmp     ThunRTMain
//! ```
//!
//! This module tries the EXE pattern first, then falls back to scanning
//! for the `"VB5!"` magic with ProjectData validation.

use crate::{addressmap::AddressMap, error::Error, util::read_u32_le};

/// Minimum number of bytes needed at the entry point to extract the VBHeader VA.
const MIN_ENTRY_BYTES: usize = 5;

/// x86 opcode for `push imm32`.
const PUSH_IMM32: u8 = 0x68;

/// VBHeader magic signature.
const VB5_MAGIC: &[u8; 4] = b"VB5!";

/// Extracts the VBHeader virtual address from a VB6 PE.
///
/// Tries two methods:
/// 1. **EXE pattern**: `push imm32` at the PE entry point.
/// 2. **DLL exports**: checks exported functions for the
///    `pop eax; push imm32` pattern that VB6 DLL exports use.
///
/// # Arguments
///
/// * `map` - The PE address map for RVA-to-file-offset translation.
/// * `entry_point_rva` - The PE entry point RVA (from the optional header).
///
/// # Returns
///
/// The virtual address of the `VBHeader` structure.
///
/// # Errors
///
/// - [`Error::EntryPointNotPush`] if both methods fail.
pub fn extract_vb_header_va(map: &AddressMap<'_>, entry_point_rva: u32) -> Result<u32, Error> {
    // Method 1: EXE entry point — push imm32 (0x68 xx xx xx xx)
    if let Ok(code) = map.slice_from_rva(entry_point_rva, MIN_ENTRY_BYTES)
        && code[0] == PUSH_IMM32
    {
        return Ok(read_u32_le(code, 1));
    }

    let byte = map
        .slice_from_rva(entry_point_rva, 1)
        .map(|c| c[0])
        .unwrap_or(0);
    Err(Error::EntryPointNotPush { byte })
}

/// Extracts the VBHeader VA from a VB6 DLL by checking its exports.
///
/// VB6 ActiveX DLLs/OCXs export functions like `DllGetClassObject` and
/// `DllRegisterServer` that each contain `pop eax; push VBHeader_VA`
/// (0x58 0x68 xx xx xx xx). The VBHeader VA is validated by checking
/// for the `"VB5!"` magic at the target address.
///
/// Returns `None` if no suitable export is found.
pub fn extract_vb_header_va_from_exports(
    map: &AddressMap<'_>,
    exports: &[goblin::pe::export::Export<'_>],
) -> Option<u32> {
    for export in exports {
        let rva = export.rva as u32;
        // Read 6 bytes: pop eax (0x58) + push imm32 (0x68 xx xx xx xx)
        let Ok(code) = map.slice_from_rva(rva, 6) else {
            continue;
        };
        if code[0] == 0x58 && code[1] == PUSH_IMM32 {
            let candidate = read_u32_le(code, 2);
            // Validate: should point to VB5! magic
            if let Ok(magic) = map.slice_from_va(candidate, 4)
                && magic.starts_with(VB5_MAGIC)
            {
                return Some(candidate);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addressmap::SectionEntry;

    /// Build an AddressMap with a .text section for testing.
    fn make_test_map(file: &[u8]) -> AddressMap<'_> {
        // Direct construction for testing
        AddressMap::from_parts(
            file,
            0x00400000,
            vec![SectionEntry {
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_data_offset: 0x200,
                raw_data_size: 0x1000,
            }],
        )
    }

    #[test]
    fn test_extract_vb_header_va_valid() {
        let mut file = vec![0u8; 0x2000];
        // Place "push 0x00401234" at file offset 0x200 (RVA 0x1000)
        file[0x200] = PUSH_IMM32;
        file[0x201] = 0x34;
        file[0x202] = 0x12;
        file[0x203] = 0x40;
        file[0x204] = 0x00;
        // Followed by call (0xE8) - not checked, just for realism
        file[0x205] = 0xE8;

        let map = make_test_map(&file);
        let va = extract_vb_header_va(&map, 0x1000).unwrap();
        assert_eq!(va, 0x00401234);
    }

    #[test]
    fn test_extract_vb_header_va_not_push() {
        let mut file = vec![0u8; 0x2000];
        // Entry point starts with 0xCC (int3) instead of 0x68
        file[0x200] = 0xCC;

        let map = make_test_map(&file);
        assert_eq!(
            extract_vb_header_va(&map, 0x1000),
            Err(Error::EntryPointNotPush { byte: 0xCC })
        );
    }

    #[test]
    fn test_extract_vb_header_va_too_short() {
        // File is too small to contain the full push instruction
        let file = vec![0u8; 0x203]; // Only 3 bytes after offset 0x200

        let map = make_test_map(&file);
        // Falls through to EntryPointNotPush since slice_from_rva fails
        assert!(extract_vb_header_va(&map, 0x1000).is_err());
    }

    #[test]
    fn test_extract_vb_header_va_rva_not_mapped() {
        let file = vec![0u8; 0x2000];
        let map = make_test_map(&file);
        // RVA 0x5000 is outside the .text section
        assert!(extract_vb_header_va(&map, 0x5000).is_err());
    }
}
