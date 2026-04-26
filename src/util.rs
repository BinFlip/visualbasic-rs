//! Low-level byte-reading utilities for little-endian structure access.
//!
//! Each helper returns a [`Result`] so adversarial inputs cannot panic the
//! parser. Out-of-bounds reads surface as [`Error::Truncated`]; offset
//! arithmetic that would wrap surfaces as [`Error::ArithmeticOverflow`].
//!
//! Internally the helpers use [`slice::get`] and
//! [`<[u8; N]>::try_from`](TryFrom) to convert validated slices into
//! fixed-size arrays for [`u16::from_le_bytes`] / [`u32::from_le_bytes`] —
//! no panicking indexing or unchecked arithmetic.

use crate::error::Error;

/// Reads a little-endian `u16` from `data` at the given byte `offset`.
///
/// # Errors
///
/// - [`Error::ArithmeticOverflow`] if `offset + 2` would overflow `usize`.
/// - [`Error::Truncated`] if fewer than 2 bytes are available from `offset`.
#[inline]
pub(crate) fn read_u16_le(data: &[u8], offset: usize) -> Result<u16, Error> {
    let bytes = read_array::<2>(data, offset)?;
    Ok(u16::from_le_bytes(bytes))
}

/// Reads a little-endian `u32` from `data` at the given byte `offset`.
///
/// # Errors
///
/// - [`Error::ArithmeticOverflow`] if `offset + 4` would overflow `usize`.
/// - [`Error::Truncated`] if fewer than 4 bytes are available from `offset`.
#[inline]
pub(crate) fn read_u32_le(data: &[u8], offset: usize) -> Result<u32, Error> {
    let bytes = read_array::<4>(data, offset)?;
    Ok(u32::from_le_bytes(bytes))
}

/// Reads a little-endian `i16` from `data` at the given byte `offset`.
///
/// # Errors
///
/// - [`Error::ArithmeticOverflow`] if `offset + 2` would overflow `usize`.
/// - [`Error::Truncated`] if fewer than 2 bytes are available from `offset`.
#[inline]
pub(crate) fn read_i16_le(data: &[u8], offset: usize) -> Result<i16, Error> {
    let bytes = read_array::<2>(data, offset)?;
    Ok(i16::from_le_bytes(bytes))
}

/// Reads a little-endian `i32` from `data` at the given byte `offset`.
///
/// # Errors
///
/// - [`Error::ArithmeticOverflow`] if `offset + 4` would overflow `usize`.
/// - [`Error::Truncated`] if fewer than 4 bytes are available from `offset`.
#[inline]
pub(crate) fn read_i32_le(data: &[u8], offset: usize) -> Result<i32, Error> {
    let bytes = read_array::<4>(data, offset)?;
    Ok(i32::from_le_bytes(bytes))
}

/// Reads a fixed-size byte array `[u8; N]` from `data` at the given `offset`.
///
/// Building block for the typed `read_*_le` helpers above. Validates the
/// `offset + N` arithmetic and the slice bounds, then converts via
/// [`TryFrom`] (which is infallible at runtime once the slice is `N` bytes
/// long, but the conversion is still expressed without panicking).
#[inline]
fn read_array<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N], Error> {
    let end = offset.checked_add(N).ok_or(Error::ArithmeticOverflow {
        context: "read_array offset",
    })?;
    let slice = data.get(offset..end).ok_or(Error::Truncated {
        needed: N,
        available: data.len().saturating_sub(offset),
    })?;
    <[u8; N]>::try_from(slice).map_err(|_| Error::Truncated {
        needed: N,
        available: slice.len(),
    })
}

/// Reads a null-terminated byte string from `data` starting at `offset`.
///
/// Returns the slice up to (but not including) the first `0x00` byte,
/// or the remainder of the buffer if no null terminator is found.
///
/// # Errors
///
/// - [`Error::Truncated`] if `offset > data.len()`.
pub(crate) fn read_cstr(data: &[u8], offset: usize) -> Result<&[u8], Error> {
    let rest = data.get(offset..).ok_or(Error::Truncated {
        needed: 0,
        available: data.len().saturating_sub(offset),
    })?;
    let cstr_len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    rest.get(..cstr_len).ok_or(Error::Truncated {
        needed: cstr_len,
        available: rest.len(),
    })
}

/// Reads a fixed-length byte slice from `data` starting at `offset`.
///
/// The returned slice has exactly `len` bytes. Trailing null bytes
/// are **not** stripped (use [`read_fixed_cstr`] for that).
///
/// # Errors
///
/// - [`Error::ArithmeticOverflow`] if `offset + len` would overflow `usize`.
/// - [`Error::Truncated`] if fewer than `len` bytes are available from `offset`.
#[inline]
pub(crate) fn read_fixed(data: &[u8], offset: usize, len: usize) -> Result<&[u8], Error> {
    let end = offset.checked_add(len).ok_or(Error::ArithmeticOverflow {
        context: "read_fixed offset",
    })?;
    data.get(offset..end).ok_or(Error::Truncated {
        needed: len,
        available: data.len().saturating_sub(offset),
    })
}

/// Reads a fixed-length null-padded string from `data` starting at `offset`.
///
/// Returns the slice up to (but not including) the first `0x00` byte
/// within the fixed-length region, or the full region if no null is found.
///
/// # Errors
///
/// - [`Error::ArithmeticOverflow`] if `offset + len` would overflow `usize`.
/// - [`Error::Truncated`] if fewer than `len` bytes are available from `offset`.
pub(crate) fn read_fixed_cstr(data: &[u8], offset: usize, len: usize) -> Result<&[u8], Error> {
    let region = read_fixed(data, offset, len)?;
    let cstr_len = region.iter().position(|&b| b == 0).unwrap_or(region.len());
    region.get(..cstr_len).ok_or(Error::Truncated {
        needed: cstr_len,
        available: region.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u16_le() {
        let data = [0x34, 0x12];
        assert_eq!(read_u16_le(&data, 0).unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u16_le_offset() {
        let data = [0xFF, 0x34, 0x12, 0xFF];
        assert_eq!(read_u16_le(&data, 1).unwrap(), 0x1234);
    }

    #[test]
    fn test_read_u32_le() {
        let data = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&data, 0).unwrap(), 0x1234_5678);
    }

    #[test]
    fn test_read_u32_le_offset() {
        let data = [0xFF, 0x78, 0x56, 0x34, 0x12];
        assert_eq!(read_u32_le(&data, 1).unwrap(), 0x1234_5678);
    }

    #[test]
    fn test_read_i16_le_positive() {
        let data = [0x05, 0x00];
        assert_eq!(read_i16_le(&data, 0).unwrap(), 5);
    }

    #[test]
    fn test_read_i16_le_negative() {
        // -144 (0xFF70) which represents var_90 in VB6
        let data = [0x70, 0xFF];
        assert_eq!(read_i16_le(&data, 0).unwrap(), -144);
    }

    #[test]
    fn test_read_i32_le() {
        let data = [0xFE, 0xFF, 0xFF, 0xFF];
        assert_eq!(read_i32_le(&data, 0).unwrap(), -2);
    }

    #[test]
    fn test_read_cstr() {
        let data = b"hello\x00world";
        assert_eq!(read_cstr(data, 0).unwrap(), b"hello");
    }

    #[test]
    fn test_read_cstr_no_null() {
        let data = b"hello";
        assert_eq!(read_cstr(data, 0).unwrap(), b"hello");
    }

    #[test]
    fn test_read_cstr_offset() {
        let data = b"\x00\x00hello\x00";
        assert_eq!(read_cstr(data, 2).unwrap(), b"hello");
    }

    #[test]
    fn test_read_cstr_empty() {
        let data = b"\x00rest";
        assert_eq!(read_cstr(data, 0).unwrap(), b"");
    }

    #[test]
    fn test_read_fixed() {
        let data = b"abcdef";
        assert_eq!(read_fixed(data, 1, 3).unwrap(), b"bcd");
    }

    #[test]
    fn test_read_fixed_cstr() {
        let data = b"hi\x00\x00\x00rest";
        assert_eq!(read_fixed_cstr(data, 0, 5).unwrap(), b"hi");
    }

    #[test]
    fn test_read_fixed_cstr_full() {
        let data = b"hello";
        assert_eq!(read_fixed_cstr(data, 0, 5).unwrap(), b"hello");
    }

    #[test]
    fn test_read_u16_le_out_of_bounds() {
        let data = [0x01];
        assert!(matches!(
            read_u16_le(&data, 0),
            Err(Error::Truncated {
                needed: 2,
                available: 1
            })
        ));
    }

    #[test]
    fn test_read_u32_le_out_of_bounds() {
        let data = [0x01, 0x02, 0x03];
        assert!(matches!(
            read_u32_le(&data, 0),
            Err(Error::Truncated {
                needed: 4,
                available: 3
            })
        ));
    }

    #[test]
    fn test_read_u32_le_offset_overflow() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert!(matches!(
            read_u32_le(&data, usize::MAX - 1),
            Err(Error::ArithmeticOverflow { .. })
        ));
    }

    #[test]
    fn test_read_cstr_offset_past_end() {
        let data = b"hi";
        // offset > len should error rather than panic
        assert!(read_cstr(data, 5).is_err());
    }

    #[test]
    fn test_read_fixed_overflow() {
        let data = b"abc";
        assert!(matches!(
            read_fixed(data, 1, usize::MAX),
            Err(Error::ArithmeticOverflow { .. })
        ));
    }
}
