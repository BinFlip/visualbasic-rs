//! VB6 constant name resolution.
//!
//! Provides reverse lookup from integer values to VB6 named constants
//! (e.g., `13` → `"vbCr"`, `65` → `"vbKeyA"`).
//!
//! The lookup table is generated at build time from `data/vb6_constants.csv`,
//! which is extracted from the MSVBVM60.DLL type libraries.

use crate::vb::control::generated;

/// Returns the VB6 constant name for an integer value, if known.
///
/// Searches the ~711 named constants extracted from the VB6 runtime
/// type libraries (KeyCode, MouseButton, Color, MsgBox constants, etc.).
///
/// # Examples
///
/// ```ignore
/// assert_eq!(constant_name(13), Some("vbCr"));
/// assert_eq!(constant_name(65), Some("vbKeyA"));
/// assert_eq!(constant_name(999999), None);
/// ```
pub fn constant_name(value: i64) -> Option<&'static str> {
    generated::lookup_constant_name(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_known_constants() {
        // vbKeyA = 65
        assert_eq!(constant_name(65), Some("vbKeyA"));
        // Value 1 has multiple matches (vbAlignTop, vbLeftButton, etc.)
        assert!(constant_name(1).is_some());
    }

    #[test]
    fn test_unknown_value() {
        assert_eq!(constant_name(999999), None);
    }
}
