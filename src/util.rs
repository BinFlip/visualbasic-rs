//! Low-level byte-reading utilities for little-endian structure access.
//!
//! Each function compiles to a single `mov` instruction on x86 targets.
//! All functions assume the caller has validated buffer bounds.

/// Reads a little-endian `u16` from `data` at the given byte `offset`.
///
/// # Panics
///
/// Panics if `offset + 2 > data.len()`. Callers must validate bounds
/// before calling (typically in the structure's `parse()` constructor).
#[inline(always)]
pub(crate) fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Reads a little-endian `u32` from `data` at the given byte `offset`.
///
/// # Panics
///
/// Panics if `offset + 4 > data.len()`. Callers must validate bounds
/// before calling (typically in the structure's `parse()` constructor).
#[inline(always)]
pub(crate) fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Reads a little-endian `i16` from `data` at the given byte `offset`.
///
/// # Panics
///
/// Panics if `offset + 2 > data.len()`. Callers must validate bounds
/// before calling (typically in the structure's `parse()` constructor).
#[inline(always)]
pub(crate) fn read_i16_le(data: &[u8], offset: usize) -> i16 {
    i16::from_le_bytes([data[offset], data[offset + 1]])
}

/// Reads a little-endian `i32` from `data` at the given byte `offset`.
///
/// # Panics
///
/// Panics if `offset + 4 > data.len()`. Callers must validate bounds
/// before calling (typically in the structure's `parse()` constructor).
#[inline(always)]
pub(crate) fn read_i32_le(data: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// Reads a null-terminated byte string from `data` starting at `offset`.
///
/// Returns the slice up to (but not including) the first `0x00` byte,
/// or the remainder of the buffer if no null terminator is found.
///
/// # Panics
///
/// Panics if `offset > data.len()`.
pub(crate) fn read_cstr(data: &[u8], offset: usize) -> &[u8] {
    let rest = &data[offset..];
    match rest.iter().position(|&b| b == 0) {
        Some(pos) => &rest[..pos],
        None => rest,
    }
}

/// Reads a fixed-length byte slice from `data` starting at `offset`.
///
/// The returned slice has exactly `len` bytes. Trailing null bytes
/// are **not** stripped (use [`read_fixed_cstr`] for that).
///
/// # Panics
///
/// Panics if `offset + len > data.len()`.
#[inline(always)]
pub(crate) fn read_fixed(data: &[u8], offset: usize, len: usize) -> &[u8] {
    &data[offset..offset + len]
}

/// Reads a fixed-length null-padded string from `data` starting at `offset`.
///
/// Returns the slice up to (but not including) the first `0x00` byte
/// within the fixed-length region, or the full region if no null is found.
///
/// # Panics
///
/// Panics if `offset + len > data.len()`.
pub(crate) fn read_fixed_cstr(data: &[u8], offset: usize, len: usize) -> &[u8] {
    let region = &data[offset..offset + len];
    match region.iter().position(|&b| b == 0) {
        Some(pos) => &region[..pos],
        None => region,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u16_le() {
        let data = [0x34, 0x12];
        assert_eq!(read_u16_le(&data, 0), 0x1234);
    }

    #[test]
    fn test_read_u16_le_offset() {
        let data = [0xFF, 0x34, 0x12, 0xFF];
        assert_eq!(read_u16_le(&data, 1), 0x1234);
    }

    #[test]
    fn test_read_u32_le() {
        let data = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&data, 0), 0x1234_5678);
    }

    #[test]
    fn test_read_u32_le_offset() {
        let data = [0xFF, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&data, 1), 0x1234_5678);
    }

    #[test]
    fn test_read_i16_le_positive() {
        let data = [0x05, 0x00];
        assert_eq!(read_i16_le(&data, 0), 5);
    }

    #[test]
    fn test_read_i16_le_negative() {
        // -144 (0xFF70) which represents var_90 in VB6
        let data = [0x70, 0xFF];
        assert_eq!(read_i16_le(&data, 0), -144);
    }

    #[test]
    fn test_read_i32_le() {
        let data = [0xFE, 0xFF, 0xFF, 0xFF];
        assert_eq!(read_i32_le(&data, 0), -2);
    }

    #[test]
    fn test_read_cstr() {
        let data = b"hello\x00world";
        assert_eq!(read_cstr(data, 0), b"hello");
    }

    #[test]
    fn test_read_cstr_no_null() {
        let data = b"hello";
        assert_eq!(read_cstr(data, 0), b"hello");
    }

    #[test]
    fn test_read_cstr_offset() {
        let data = b"\x00\x00hello\x00";
        assert_eq!(read_cstr(data, 2), b"hello");
    }

    #[test]
    fn test_read_cstr_empty() {
        let data = b"\x00rest";
        assert_eq!(read_cstr(data, 0), b"");
    }

    #[test]
    fn test_read_fixed() {
        let data = b"abcdef";
        assert_eq!(read_fixed(data, 1, 3), b"bcd");
    }

    #[test]
    fn test_read_fixed_cstr() {
        let data = b"hi\x00\x00\x00rest";
        assert_eq!(read_fixed_cstr(data, 0, 5), b"hi");
    }

    #[test]
    fn test_read_fixed_cstr_full() {
        let data = b"hello";
        assert_eq!(read_fixed_cstr(data, 0, 5), b"hello");
    }

    #[test]
    #[should_panic]
    fn test_read_u16_le_out_of_bounds() {
        let data = [0x01];
        read_u16_le(&data, 0);
    }

    #[test]
    #[should_panic]
    fn test_read_u32_le_out_of_bounds() {
        let data = [0x01, 0x02, 0x03];
        read_u32_le(&data, 0);
    }
}
