//! Variable implementation stub descriptors.
//!
//! Pointed to by `PrivateObjectDescriptor.var_stubs_va` (+0x28), this is an
//! array of `wVarCount` VA pointers. Each VA points to a variable-length
//! descriptor that tells the compiler which VBA runtime helper functions
//! implement the property Get/Let/Set accessors for a public variable.
//!
//! **Not read by MSVBVM60.DLL at runtime** — this is compiler/IDE metadata
//! only. However, the data is present in compiled binaries and useful for
//! understanding which runtime functions a variable depends on.
//!
//! # Entry Layout
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0x00 | 2 | `wHeaderSize` — header bytes before name data (0x0C + params*4) |
//! | 0x02 | 2 | `wDataSize` — size of name/data section after header |
//! | 0x04 | 2 | Reserved (zero) |
//! | 0x06 | 2 | `wParamCount` — indexed property parameter count |
//! | 0x08 | 2 | `wDataSize2` — copy of wDataSize |
//! | 0x0A | 1 | `bFlags1` |
//! | 0x0B | 1 | `bFlags2` |
//! | 0x0C | N×4 | Parameter descriptors: `[{u16 offset, u16 type}]` × wParamCount |
//! | +hdr | var | Null-terminated name strings (VBA runtime function names) |

use core::str;

use crate::{
    addressmap::AddressMap,
    util::{read_cstr, read_u16_le, read_u32_le},
};

/// A variable implementation stub descriptor.
///
/// Describes which VBA runtime helper functions implement the property
/// accessors for a public variable (e.g., `__vbaDateVar` for Date Get,
/// `__vbaVarSetVar` for Variant Set).
#[derive(Clone, Copy, Debug)]
pub struct VarStubDesc<'a> {
    bytes: &'a [u8],
}

impl<'a> VarStubDesc<'a> {
    /// Minimum header size.
    pub const MIN_SIZE: usize = 0x0C;

    /// Parses a variable stub descriptor from the given byte slice.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < Self::MIN_SIZE {
            return None;
        }
        Some(Self { bytes: data })
    }

    /// Header size at offset 0x00 (0x0C + param_count * 4).
    #[inline]
    pub fn header_size(&self) -> u16 {
        read_u16_le(self.bytes, 0x00)
    }

    /// Data section size at offset 0x02.
    #[inline]
    pub fn data_size(&self) -> u16 {
        read_u16_le(self.bytes, 0x02)
    }

    /// Number of indexed property parameters at offset 0x06.
    #[inline]
    pub fn param_count(&self) -> u16 {
        read_u16_le(self.bytes, 0x06)
    }

    /// Flags byte 1 at offset 0x0A.
    #[inline]
    pub fn flags1(&self) -> u8 {
        self.bytes[0x0A]
    }

    /// Flags byte 2 at offset 0x0B.
    ///
    /// Determines the data section format:
    ///
    /// | Value | Meaning |
    /// |-------|---------|
    /// | `0x04` | Inline VBA runtime function names |
    /// | `0x2C` | Inline property names (Default, CaseSensitive) or VA pointers to DLL+API |
    /// | `0x34` | Extended Declare-style entries (DLL+API function references) |
    ///
    /// Bit 2 (0x04) is always set. Bit 3 (0x08) = has property accessor names.
    /// Bit 5 (0x20) = has COM interface data.
    #[inline]
    pub fn flags2(&self) -> u8 {
        self.bytes[0x0B]
    }

    /// Total size of this entry (header + data).
    #[inline]
    pub fn total_size(&self) -> usize {
        self.header_size() as usize + self.data_size() as usize
    }

    /// Returns `true` if the data section contains VA pointers instead of
    /// inline strings. Detected by checking if the first data byte is
    /// non-printable ASCII (binary data / VA pointer).
    pub fn has_va_data(&self) -> bool {
        let hdr = self.header_size() as usize;
        if hdr >= self.bytes.len() {
            return false;
        }
        let first = self.bytes[hdr];
        first != 0 && !(0x20..=0x7E).contains(&first)
    }

    /// Resolves VA-pointer data section entries to DLL+API name pairs.
    ///
    /// When [`has_va_data()`](Self::has_va_data) is true, the data section
    /// contains VA pointers to null-terminated strings (DLL library name
    /// and API function name). Returns empty if the data is inline strings.
    pub fn resolve_api_names<'b>(&self, map: &AddressMap<'b>) -> Vec<&'b str> {
        if !self.has_va_data() {
            return Vec::new();
        }
        let hdr = self.header_size() as usize;
        let data = &self.bytes[hdr..];
        let mut result = Vec::new();
        let mut pos = 0;
        while pos + 4 <= data.len() {
            let va = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]);
            pos += 4;
            if va == 0 {
                continue;
            }
            if let Ok(off) = map.va_to_offset(va) {
                let name = read_cstr(map.file(), off);
                if let Ok(s) = str::from_utf8(name)
                    && !s.is_empty()
                {
                    result.push(s);
                }
            }
        }
        result
    }

    /// Returns the first name string from the data section.
    ///
    /// This is typically a VBA runtime function name (e.g., `__vbaDateVar`)
    /// or a method name (e.g., `Pack`). Returns empty if the data section
    /// starts with binary data (VA pointers) rather than a string.
    pub fn name(&self) -> &'a str {
        let hdr = self.header_size() as usize;
        if hdr >= self.bytes.len() {
            return "";
        }
        let data = &self.bytes[hdr..];
        // Skip up to 4 leading null bytes (alignment padding)
        let start = data
            .iter()
            .take(4)
            .position(|&b| b != 0)
            .unwrap_or(4)
            .min(data.len());
        if start >= data.len() {
            return "";
        }
        let data = &data[start..];
        // Validate first byte is printable ASCII (not a VA/binary data)
        if data[0] < 0x20 || data[0] > 0x7E {
            return "";
        }
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        str::from_utf8(&data[..end]).unwrap_or("")
    }

    /// Returns all name strings from the data section.
    pub fn names(&self) -> Vec<&'a str> {
        let hdr = self.header_size() as usize;
        if hdr >= self.bytes.len() {
            return Vec::new();
        }
        let data = &self.bytes[hdr..];
        let mut result = Vec::new();
        let mut pos = 0;
        while pos < data.len() {
            // Skip nulls
            while pos < data.len() && data[pos] == 0 {
                pos += 1;
            }
            if pos >= data.len() {
                break;
            }
            let start = pos;
            while pos < data.len() && data[pos] != 0 {
                pos += 1;
            }
            if let Ok(s) = str::from_utf8(&data[start..pos])
                && !s.is_empty()
            {
                result.push(s);
            }
        }
        result
    }
}

/// Iterator over variable stub descriptors from PrivateObjectDescriptor.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct VarStubIter<'a> {
    map: &'a AddressMap<'a>,
    ptr_array_va: u32,
    index: usize,
    count: usize,
}

impl<'a> VarStubIter<'a> {
    /// Creates an iterator over `count` variable stubs from the pointer array at `va`.
    pub fn new(map: &'a AddressMap<'a>, va: u32, count: u16) -> Self {
        Self {
            map,
            ptr_array_va: va,
            index: 0,
            count: count as usize,
        }
    }
}

impl<'a> Iterator for VarStubIter<'a> {
    type Item = VarStubDesc<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        let ptr_va = self.ptr_array_va.wrapping_add(self.index as u32 * 4);
        self.index += 1;

        let ptr_data = self.map.slice_from_va(ptr_va, 4).ok()?;
        let stub_va = read_u32_le(ptr_data, 0);
        if stub_va == 0 {
            return None;
        }

        // Read enough for the header to determine total size
        let header_data = self
            .map
            .slice_from_va(stub_va, VarStubDesc::MIN_SIZE)
            .ok()?;
        let hdr_size = read_u16_le(header_data, 0x00) as usize;
        let data_size = read_u16_le(header_data, 0x02) as usize;
        let total = hdr_size + data_size;

        let full_data = self
            .map
            .slice_from_va(stub_va, total.max(VarStubDesc::MIN_SIZE))
            .ok()?;
        VarStubDesc::parse(full_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Entry 0 from Cls_Zip: "__vbaDateVar"
    const STUB_DATEVAR: [u8; 28] = [
        0x0C, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x04, 0x04,
        // name data: "__vbaDateVar\0\0\0\0"
        0x5F, 0x5F, 0x76, 0x62, 0x61, 0x44, 0x61, 0x74, 0x65, 0x56, 0x61, 0x72, 0x00, 0x00, 0x00,
        0x00,
    ];

    // Entry 3 from Cls_Zip: "Pack"
    const STUB_PACK: [u8; 20] = [
        0x0C, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x04, 0x04, 0x50, 0x61, 0x63,
        0x6B, 0x00, 0x00, 0x00, 0x00, // "Pack\0\0\0\0"
    ];

    #[test]
    fn test_simple_stub() {
        let stub = VarStubDesc::parse(&STUB_DATEVAR).unwrap();
        assert_eq!(stub.header_size(), 0x0C);
        assert_eq!(stub.data_size(), 0x1C);
        assert_eq!(stub.param_count(), 0);
        assert_eq!(stub.name(), "__vbaDateVar");
    }

    #[test]
    fn test_method_stub() {
        let stub = VarStubDesc::parse(&STUB_PACK).unwrap();
        assert_eq!(stub.header_size(), 0x0C);
        assert_eq!(stub.data_size(), 0x0C);
        assert_eq!(stub.param_count(), 0);
        assert_eq!(stub.name(), "Pack");
    }

    #[test]
    fn test_names() {
        let stub = VarStubDesc::parse(&STUB_DATEVAR).unwrap();
        let names = stub.names();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "__vbaDateVar");
    }
}
