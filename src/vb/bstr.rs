//! COM BSTR (Basic String) type.
//!
//! VB6 uses COM BSTRs for all string constants. A BSTR is a length-prefixed
//! UTF-16LE string stored in the PE image:
//!
//! ```text
//! VA-4:  u32    byte_length       (number of bytes of string data)
//! VA:    [u8]   UTF-16LE chars    (the BSTR pointer points HERE)
//! VA+N:  u16    null terminator   (0x0000)
//! ```
//!
//! The BSTR pointer (stored in constant pools, etc.) points to the **first
//! character**, not the length prefix. This matches the COM `BSTR` convention
//! where `SysStringLen(bstr)` reads `*(bstr - 4)`.
//!
//! # Binary Layout
//!
//! For a string "Hello" (5 UTF-16 chars = 10 bytes):
//!
//! ```text
//! offset  data
//! ------  ----
//! VA-4    0A 00 00 00          length prefix: 10 bytes
//! VA      48 00 65 00 6C 00    'H' 'e' 'l'
//! VA+6    6C 00 6F 00          'l' 'o'
//! VA+10   00 00                null terminator
//! ```
//!
//! Total binary footprint: `4 + byte_length + 2` bytes.

use core::fmt;

/// View of a COM BSTR in the PE image.
///
/// Borrows the UTF-16LE string data from the file buffer. The length
/// prefix and null terminator are not included in the data slice but
/// their sizes are accounted for in [`total_binary_size`](Self::total_binary_size).
#[derive(Clone, Copy)]
pub struct BStr<'a> {
    /// VA of the string data (the BSTR pointer value).
    va: u32,
    /// Number of bytes of string data (from the length prefix at VA-4).
    byte_length: u32,
    /// Raw UTF-16LE string bytes (without length prefix or null terminator).
    data: &'a [u8],
}

impl<'a> BStr<'a> {
    /// Creates a new `BStr` from pre-validated components.
    ///
    /// # Arguments
    ///
    /// * `va` - VA of the string data (the BSTR pointer value, NOT the length prefix).
    /// * `byte_length` - Number of bytes of string data (from the `u32` at `va - 4`).
    /// * `data` - The raw UTF-16LE bytes (must be `byte_length` bytes long).
    #[inline]
    pub fn new(va: u32, byte_length: u32, data: &'a [u8]) -> Self {
        Self {
            va,
            byte_length,
            data,
        }
    }

    /// Creates an empty `BStr` with VA 0.
    #[inline]
    pub fn empty() -> Self {
        Self {
            va: 0,
            byte_length: 0,
            data: &[],
        }
    }

    /// VA of the string data (the BSTR pointer value).
    ///
    /// This is where the UTF-16LE characters begin. The 4-byte length
    /// prefix is at `va - 4`.
    #[inline]
    pub fn va(&self) -> u32 {
        self.va
    }

    /// VA of the 4-byte length prefix (`va - 4`).
    ///
    /// This is the start of the BSTR's binary footprint in the PE image.
    #[inline]
    pub fn length_prefix_va(&self) -> u32 {
        self.va.wrapping_sub(4)
    }

    /// Number of bytes of string data (from the length prefix).
    #[inline]
    pub fn byte_length(&self) -> u32 {
        self.byte_length
    }

    /// Number of UTF-16 code units (characters) in the string.
    #[inline]
    pub fn char_count(&self) -> usize {
        self.byte_length as usize / 2
    }

    /// Total binary footprint in the PE image: `4 (length) + byte_length + 2 (null)`.
    #[inline]
    pub fn total_binary_size(&self) -> usize {
        4 + self.byte_length as usize + 2
    }

    /// Raw UTF-16LE string bytes (without length prefix or null terminator).
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }

    /// Returns `true` if the string is empty (zero bytes of character data).
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.byte_length == 0
    }

    /// Decodes the UTF-16LE data into a Rust `String`.
    ///
    /// Invalid UTF-16 surrogates are replaced with U+FFFD.
    pub fn to_string_lossy(&self) -> String {
        if self.data.is_empty() {
            return String::new();
        }
        let u16s: Vec<u16> = self
            .data
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16_lossy(&u16s)
    }
}

impl fmt::Debug for BStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BStr(0x{:08X}, {:?})", self.va, self.to_string_lossy())
    }
}

impl fmt::Display for BStr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty() {
        let bstr = BStr::empty();
        assert_eq!(bstr.va(), 0);
        assert_eq!(bstr.byte_length(), 0);
        assert_eq!(bstr.char_count(), 0);
        assert!(bstr.is_empty());
        assert_eq!(bstr.total_binary_size(), 6); // 4 + 0 + 2
        assert_eq!(bstr.to_string_lossy(), "");
    }

    #[test]
    fn test_hello() {
        // "Hello" in UTF-16LE
        let data: &[u8] = &[0x48, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F, 0x00];
        let bstr = BStr::new(0x00401004, 10, data);
        assert_eq!(bstr.va(), 0x00401004);
        assert_eq!(bstr.length_prefix_va(), 0x00401000);
        assert_eq!(bstr.byte_length(), 10);
        assert_eq!(bstr.char_count(), 5);
        assert!(!bstr.is_empty());
        assert_eq!(bstr.total_binary_size(), 16); // 4 + 10 + 2
        assert_eq!(bstr.to_string_lossy(), "Hello");
    }

    #[test]
    fn test_debug_display() {
        let data: &[u8] = &[0x48, 0x00, 0x69, 0x00]; // "Hi"
        let bstr = BStr::new(0x00401004, 4, data);
        assert_eq!(format!("{bstr}"), "Hi");
        assert_eq!(format!("{bstr:?}"), "BStr(0x00401004, \"Hi\")");
    }
}
