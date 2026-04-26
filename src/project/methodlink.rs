//! Native method link thunks for native-compiled VB6 classes.
//!
//! The method link table (from [`OptionalObjectInfo::method_link_table_va`](crate::vb::object::OptionalObjectInfo::method_link_table_va))
//! is a flat `u32[method_link_count]` array of VAs. Each VA points to a
//! JMP thunk that bridges COM vtable dispatch to the actual native method
//! implementation in the `.text` section.
//!
//! # Thunk Format
//!
//! Each thunk starts with a 5-byte `JMP rel32` to the native code body.
//! Some thunks have an additional 8-byte `SUB [esp+4], imm32` instruction
//! that adjusts the COM `this` pointer for interface delegation:
//!
//! ```text
//! +0x00  E9 xx xx xx xx            JMP <native_code>     (5 bytes, always present)
//! +0x05  81 6C 24 04 xx xx 00 00   SUB [esp+4], <adjust>  (8 bytes, optional)
//! ```
//!
//! The `this_adjust` values observed:
//! - `0xFFFF`: placeholder — the method uses runtime vtable dispatch, not
//!   direct COM interface delegation. Common for standalone class modules.
//! - Non-zero small values (e.g., `0x33`, `0x93`): real COM interface offset
//!   adjustment. Matches the event sink thunk adjustments for the same object.
//! - Absent (no SUB instruction): the thunk is a direct JMP with no adjustment.
//!
//! # Table Layout
//!
//! The table is at `OptionalObjectInfo.method_link_table_va` (+0x30) with
//! `method_link_count` (+0x28) entries. Each entry is a 4-byte VA pointer.
//! The method link index corresponds 1:1 to the method table index.

use crate::{addressmap::AddressMap, error::Error, util::read_u32_le};

/// A method link thunk entry for native-compiled VB6 classes.
///
/// Maps a method index to its native code body via a JMP thunk,
/// optionally with a COM `this` pointer adjustment.
#[derive(Debug, Clone, Copy)]
pub struct MethodLink {
    /// VA of the thunk JMP instruction.
    pub thunk_va: u32,
    /// VA of the actual native method body (JMP target).
    pub code_va: u32,
    /// COM `this` pointer adjustment from the SUB instruction.
    ///
    /// - `Some(0xFFFF)`: placeholder — runtime vtable dispatch method.
    /// - `Some(n)`: real interface offset adjustment (n bytes subtracted from `this`).
    /// - `None`: no SUB instruction follows the JMP (direct call, no adjustment).
    pub this_adjust: Option<u32>,
}

/// Iterator over method link thunks in a VB6 object.
///
/// Walks the method link table from
/// [`OptionalObjectInfo::method_link_table_va`](crate::vb::object::OptionalObjectInfo::method_link_table_va),
/// reading each 4-byte VA, then decoding the JMP thunk to extract the
/// actual native method body address and optional `this` adjustment.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct MethodLinkIterator<'a, 'p> {
    /// Address map for VA resolution.
    map: &'p AddressMap<'a>,
    /// Base VA of the method link table.
    table_va: u32,
    /// Current zero-based position in the table.
    index: u32,
    /// Total number of method link entries.
    total: u32,
}

impl<'a, 'p> MethodLinkIterator<'a, 'p> {
    /// Creates a new iterator over method link thunks starting at `table_va`.
    pub fn new(map: &'p AddressMap<'a>, table_va: u32, total: u32) -> Self {
        Self {
            map,
            table_va,
            index: 0,
            total,
        }
    }
}

impl<'a, 'p> Iterator for MethodLinkIterator<'a, 'p> {
    type Item = Result<MethodLink, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.total || self.table_va == 0 {
            return None;
        }

        let ptr_va = self.table_va.wrapping_add(self.index.saturating_mul(4));
        self.index = self.index.saturating_add(1);

        let ptr_data = match self.map.slice_from_va(ptr_va, 4) {
            Ok(d) => d,
            Err(e) => return Some(Err(e)),
        };
        let thunk_va = match read_u32_le(ptr_data, 0) {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        // Read the JMP instruction (E9 rel32) + possible SUB from the thunk.
        // We read 13 bytes to cover both formats (5-byte JMP or 13-byte JMP+SUB).
        let thunk_data = match self.map.slice_from_va(thunk_va, 13) {
            Ok(d) => d,
            Err(_) => {
                // Fall back to 5 bytes if 13 aren't available
                match self.map.slice_from_va(thunk_va, 5) {
                    Ok(d) => d,
                    Err(e) => return Some(Err(e)),
                }
            }
        };

        let code_va = if thunk_data.first().copied() == Some(0xE9) {
            let rel_bytes: [u8; 4] = match thunk_data.get(1..5).and_then(|s| s.try_into().ok()) {
                Some(b) => b,
                None => {
                    return Some(Err(Error::Truncated {
                        needed: 5,
                        available: thunk_data.len(),
                    }));
                }
            };
            let rel32 = i32::from_le_bytes(rel_bytes);
            i64::from(thunk_va)
                .wrapping_add(5)
                .wrapping_add(i64::from(rel32)) as u32
        } else {
            // Not a JMP — the thunk VA IS the code VA
            thunk_va
        };

        // Check for SUB [esp+4], imm32 after the JMP (bytes 5-12)
        // Pattern: 81 6C 24 04 xx xx 00 00
        let this_adjust = if thunk_data.len() >= 13
            && thunk_data.get(5).copied() == Some(0x81)
            && thunk_data.get(6).copied() == Some(0x6C)
            && thunk_data.get(7).copied() == Some(0x24)
            && thunk_data.get(8).copied() == Some(0x04)
        {
            match read_u32_le(thunk_data, 9) {
                Ok(v) => Some(v),
                Err(e) => return Some(Err(e)),
            }
        } else {
            None
        };

        Some(Ok(MethodLink {
            thunk_va,
            code_va,
            this_adjust,
        }))
    }
}
