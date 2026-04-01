//! Constant pool reader.
//!
//! Each VB6 compilation unit (module, class, form) has its own constant pool,
//! shared by all procedures in that unit. The pool contains:
//!
//! - **BSTR strings**: Length-prefixed little-endian Unicode strings
//! - **API call stubs**: Native `push; jmp DllFunctionCall` thunks
//! - **COM GUIDs**: CLSID/IID pairs
//! - **Code object offsets**: Base addresses for code objects
//!
//! # Addressing
//!
//! The constant pool base address comes from `ObjectInfo.lpConstants` (offset 0x34).
//! P-Code operands with format `%s` (constant pool index) are resolved as:
//!
//! ```text
//! effective_va = data_const_va + (index * 1)
//! ```
//!
//! The value at that effective address is itself a VA pointing to the actual
//! data (a BSTR, a GUID, etc.). This double-indirection is critical:
//! the pool entry is a **pointer**, not the data itself.
//!
//! # BSTR Format
//!
//! VB6 uses COM BSTRs (Basic Strings):
//! - 4 bytes **before** the string pointer: length in bytes (not characters)
//! - Followed by the UTF-16LE string data
//! - Followed by a null terminator (2 bytes, `\0\0`)
//!
//! The BSTR pointer points to the **first character**, not the length prefix.

use crate::{
    addressmap::AddressMap,
    error::Error,
    util::{read_cstr, read_u32_le},
    vb::bstr::BStr,
};

/// Resolved content of a constant pool entry.
#[derive(Debug)]
pub enum ConstPoolEntry<'a> {
    /// BSTR string literal.
    BStr(BStr<'a>),
    /// Null entry (VA was 0).
    Null,
    /// Non-string VA that couldn't be classified as BSTR.
    /// May be an API stub, COM GUID, or other data.
    RawVa(u32),
}

/// Reader for a VB6 constant pool.
///
/// Provides methods to resolve pool indices to strings, API stubs, etc.
///
/// # Lifetime
///
/// The `'a` lifetime ties the reader to the file buffer through the
/// [`AddressMap`].
#[derive(Debug, Clone)]
pub struct ConstantPool<'a> {
    /// Address map used for VA-to-file-offset resolution.
    map: &'a AddressMap<'a>,
    /// Base VA of the constant pool (from `ObjectInfo.lpConstants`).
    data_const_va: u32,
}

impl<'a> ConstantPool<'a> {
    /// Creates a new constant pool reader.
    ///
    /// # Arguments
    ///
    /// * `map` - Address map for VA resolution.
    /// * `data_const_va` - Base VA of the constant pool
    ///   (from [`ObjectInfo::constants_va`](super::object::ObjectInfo::constants_va)).
    pub fn new(map: &'a AddressMap<'a>, data_const_va: u32) -> Self {
        Self { map, data_const_va }
    }

    /// Returns the base VA of the constant pool.
    #[inline]
    pub fn data_const_va(&self) -> u32 {
        self.data_const_va
    }

    /// Reads a raw 4-byte value from the pool at the given byte offset.
    ///
    /// # Arguments
    ///
    /// * `offset` - Byte offset from `data_const_va`.
    ///
    /// # Returns
    ///
    /// The 32-bit value at `data_const_va + offset`.
    ///
    /// # Errors
    ///
    /// Returns an error if the VA cannot be resolved.
    pub fn read_u32(&self, offset: u16) -> Result<u32, Error> {
        let va = self.data_const_va.wrapping_add(offset as u32);
        let data = self.map.slice_from_va(va, 4)?;
        Ok(read_u32_le(data, 0))
    }

    /// Reads a [`BStr`] from the pool at the given byte offset.
    ///
    /// Resolves the pool entry at `data_const_va + offset` as a pointer
    /// to a BSTR, then reads the length prefix and string data.
    ///
    /// # Arguments
    ///
    /// * `offset` - Byte offset into the constant pool.
    ///
    /// # Errors
    ///
    /// Returns an error if any VA in the chain cannot be resolved.
    pub fn read_bstr(&self, offset: u16) -> Result<BStr<'a>, Error> {
        let bstr_va = self.read_u32(offset)?;
        self.resolve_bstr_at_va(bstr_va)
    }

    /// Reads a BSTR and converts it to a Rust `String`.
    ///
    /// Convenience wrapper around [`read_bstr`](Self::read_bstr) that
    /// decodes the UTF-16LE bytes. Invalid UTF-16 sequences are replaced
    /// with U+FFFD.
    pub fn read_bstr_as_string(&self, offset: u16) -> Result<String, Error> {
        Ok(self.read_bstr(offset)?.to_string_lossy())
    }

    /// Resolves a constant pool entry to its typed content.
    ///
    /// Probes the target VA to classify the entry:
    /// 1. VA == 0 → [`Null`](ConstPoolEntry::Null)
    /// 2. VA-4 contains a plausible BSTR length (even, < 64KB) → [`BStr`](ConstPoolEntry::BStr)
    /// 3. Otherwise → [`RawVa`](ConstPoolEntry::RawVa)
    pub fn resolve(&self, offset: u16) -> Result<ConstPoolEntry<'a>, Error> {
        let va = self.read_u32(offset)?;
        if va == 0 {
            return Ok(ConstPoolEntry::Null);
        }

        match self.try_parse_bstr(va) {
            Some(bstr) => Ok(ConstPoolEntry::BStr(bstr)),
            None => Ok(ConstPoolEntry::RawVa(va)),
        }
    }

    /// Resolves a constant pool entry as a string, if it is a BSTR.
    ///
    /// Returns `Ok(Some(string))` for BSTR entries, `Ok(None)` for
    /// non-string entries, and `Err` for VA resolution failures.
    pub fn resolve_string(&self, offset: u16) -> Result<Option<String>, Error> {
        match self.resolve(offset)? {
            ConstPoolEntry::BStr(bstr) => Ok(Some(bstr.to_string_lossy())),
            ConstPoolEntry::Null => Ok(Some(String::new())),
            ConstPoolEntry::RawVa(_) => Ok(None),
        }
    }

    /// Returns an iterator over all constant pool entries.
    ///
    /// Yields `(byte_offset, entry)` pairs for each of the `count` entries.
    /// Each entry is at `data_const_va + offset` where offset advances by 4
    /// bytes per entry (each entry is a 4-byte VA pointer).
    pub fn entries(&self, count: u16) -> ConstPoolIter<'a> {
        ConstPoolIter {
            pool: self.clone(),
            index: 0,
            count,
        }
    }

    /// Returns an iterator over only the BSTR entries in the constant pool.
    ///
    /// Filters out null entries and non-string VAs, yielding only valid,
    /// non-empty BSTRs.
    pub fn bstr_entries(&self, count: u16) -> impl Iterator<Item = BStr<'a>> {
        self.entries(count).filter_map(|(_, r)| match r {
            Ok(ConstPoolEntry::BStr(b)) if b.va() != 0 && !b.is_empty() => Some(b),
            _ => None,
        })
    }

    /// Attempts to parse a BSTR at the given VA.
    ///
    /// Returns `Some(BStr)` if the length prefix looks valid (even, < 64KB),
    /// or `None` if it doesn't look like a BSTR.
    fn try_parse_bstr(&self, va: u32) -> Option<BStr<'a>> {
        let len_va = va.wrapping_sub(4);
        let len_data = self.map.slice_from_va(len_va, 4).ok()?;
        let byte_len = read_u32_le(len_data, 0);

        // Zero-length BSTR is valid
        if byte_len == 0 {
            return Some(BStr::new(va, 0, &[]));
        }

        // Plausible BSTR: even length, under 64KB
        if byte_len >= 0x10000 || byte_len % 2 != 0 {
            return None;
        }

        let str_data = self.map.slice_from_va(va, byte_len as usize).ok()?;
        Some(BStr::new(va, byte_len, &str_data[..byte_len as usize]))
    }

    /// Resolves a raw VA as a [`BStr`], without going through the pool indirection.
    ///
    /// Use this when you already have the BSTR pointer value (e.g., from
    /// reading a pool entry manually).
    pub fn resolve_bstr_at_va(&self, bstr_va: u32) -> Result<BStr<'a>, Error> {
        if bstr_va == 0 {
            return Ok(BStr::empty());
        }

        let len_va = bstr_va.wrapping_sub(4);
        let len_data = self.map.slice_from_va(len_va, 4)?;
        let byte_len = read_u32_le(len_data, 0);

        if byte_len == 0 {
            return Ok(BStr::new(bstr_va, 0, &[]));
        }

        let str_data = self.map.slice_from_va(bstr_va, byte_len as usize)?;
        Ok(BStr::new(bstr_va, byte_len, &str_data[..byte_len as usize]))
    }

    /// Reads a null-terminated ANSI string from a pool-referenced VA.
    ///
    /// The pool entry at `data_const_va + offset` is a VA pointing to
    /// a null-terminated ANSI (single-byte) string.
    ///
    /// # Arguments
    ///
    /// * `offset` - Byte offset into the constant pool.
    ///
    /// # Errors
    ///
    /// Returns an error if the VA cannot be resolved.
    pub fn read_ansi_string(&self, offset: u16) -> Result<&'a [u8], Error> {
        let str_va = self.read_u32(offset)?;
        if str_va == 0 {
            return Ok(&[]);
        }
        let offset = self.map.va_to_offset(str_va)?;
        Ok(read_cstr(self.map.file(), offset))
    }
}

/// Iterator over all entries in a constant pool.
///
/// Yields `(byte_offset, Result<ConstPoolEntry>)` pairs. Each entry is a
/// 4-byte VA pointer at `data_const_va + (index * 4)`. The VA is resolved
/// to determine entry type (BSTR, null, or raw VA).
///
/// Created by [`ConstantPool::entries`].
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ConstPoolIter<'a> {
    pool: ConstantPool<'a>,
    index: u16,
    count: u16,
}

impl<'a> Iterator for ConstPoolIter<'a> {
    type Item = (u16, Result<ConstPoolEntry<'a>, Error>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.count {
            return None;
        }
        let offset = self.index * 4;
        self.index += 1;
        Some((offset, self.pool.resolve(offset)))
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

    #[test]
    fn test_read_u32() {
        let mut file = vec![0u8; 0x3000];
        // data_const at RVA 0x1000 (offset 0x200)
        // Pool entry at offset 0: value 0xDEADBEEF
        file[0x200..0x204].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());

        let map = make_test_map(&file);
        let pool = ConstantPool::new(&map, 0x00401000);
        assert_eq!(pool.read_u32(0).unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn test_read_u32_with_offset() {
        let mut file = vec![0u8; 0x3000];
        // Pool entry at offset 8: value 0x12345678
        file[0x208..0x20C].copy_from_slice(&0x12345678u32.to_le_bytes());

        let map = make_test_map(&file);
        let pool = ConstantPool::new(&map, 0x00401000);
        assert_eq!(pool.read_u32(8).unwrap(), 0x12345678);
    }

    #[test]
    fn test_read_bstr() {
        let mut file = vec![0u8; 0x3000];

        // data_const at RVA 0x1000 (offset 0x200)
        // Pool entry at offset 0: VA pointing to the BSTR (0x00401100 = RVA 0x1100 = offset 0x300)
        file[0x200..0x204].copy_from_slice(&0x00401104u32.to_le_bytes()); // points to string chars

        // BSTR at offset 0x300: [length=10][H\0e\0l\0l\0o\0][\0\0]
        // Length prefix at offset 0x300 (4 bytes before the string data at 0x304)
        file[0x300..0x304].copy_from_slice(&10u32.to_le_bytes()); // 10 bytes = 5 UTF-16 chars
        // "Hello" in UTF-16LE at offset 0x304
        file[0x304] = b'H';
        file[0x305] = 0;
        file[0x306] = b'e';
        file[0x307] = 0;
        file[0x308] = b'l';
        file[0x309] = 0;
        file[0x30A] = b'l';
        file[0x30B] = 0;
        file[0x30C] = b'o';
        file[0x30D] = 0;

        let map = make_test_map(&file);
        let pool = ConstantPool::new(&map, 0x00401000);

        let bstr = pool.read_bstr(0).unwrap();
        assert_eq!(bstr.byte_length(), 10);
        assert_eq!(bstr.char_count(), 5);
        assert_eq!(bstr.va(), 0x00401104);
        assert_eq!(bstr.as_bytes().len(), 10);

        let s = pool.read_bstr_as_string(0).unwrap();
        assert_eq!(s, "Hello");
    }

    #[test]
    fn test_read_bstr_null_pointer() {
        let mut file = vec![0u8; 0x3000];
        // Pool entry is 0 (null pointer)
        file[0x200..0x204].copy_from_slice(&0u32.to_le_bytes());

        let map = make_test_map(&file);
        let pool = ConstantPool::new(&map, 0x00401000);

        let bstr = pool.read_bstr(0).unwrap();
        assert!(bstr.is_empty());

        let s = pool.read_bstr_as_string(0).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn test_read_bstr_zero_length() {
        let mut file = vec![0u8; 0x3000];
        // Pool entry points to a BSTR with length 0
        file[0x200..0x204].copy_from_slice(&0x00401104u32.to_le_bytes());
        file[0x300..0x304].copy_from_slice(&0u32.to_le_bytes()); // length = 0

        let map = make_test_map(&file);
        let pool = ConstantPool::new(&map, 0x00401000);

        let bstr = pool.read_bstr(0).unwrap();
        assert!(bstr.is_empty());
    }

    #[test]
    fn test_read_ansi_string() {
        let mut file = vec![0u8; 0x3000];
        // Pool entry at offset 0: VA pointing to ANSI string
        file[0x200..0x204].copy_from_slice(&0x00401100u32.to_le_bytes());
        // ANSI string at RVA 0x1100 (offset 0x300)
        file[0x300..0x306].copy_from_slice(b"Hello\0");

        let map = make_test_map(&file);
        let pool = ConstantPool::new(&map, 0x00401000);

        let s = pool.read_ansi_string(0).unwrap();
        assert_eq!(s, b"Hello");
    }

    #[test]
    fn test_read_ansi_string_null_va() {
        let mut file = vec![0u8; 0x3000];
        file[0x200..0x204].copy_from_slice(&0u32.to_le_bytes());

        let map = make_test_map(&file);
        let pool = ConstantPool::new(&map, 0x00401000);

        let s = pool.read_ansi_string(0).unwrap();
        assert!(s.is_empty());
    }

    #[test]
    fn test_data_const_va_accessor() {
        let file = vec![0u8; 0x3000];
        let map = make_test_map(&file);
        let pool = ConstantPool::new(&map, 0x00401000);
        assert_eq!(pool.data_const_va(), 0x00401000);
    }

    #[test]
    fn test_resolve_null() {
        let mut file = vec![0u8; 0x3000];
        file[0x200..0x204].copy_from_slice(&0u32.to_le_bytes());

        let map = make_test_map(&file);
        let pool = ConstantPool::new(&map, 0x00401000);

        assert!(
            matches!(pool.resolve(0).unwrap(), ConstPoolEntry::Null),
            "expected Null, got {:?}",
            pool.resolve(0)
        );
    }

    #[test]
    fn test_resolve_bstr() {
        let mut file = vec![0u8; 0x3000];
        // Pool entry → VA pointing to BSTR
        file[0x200..0x204].copy_from_slice(&0x00401104u32.to_le_bytes());
        // BSTR: length=6 at offset 0x300, string at 0x304
        file[0x300..0x304].copy_from_slice(&6u32.to_le_bytes());
        file[0x304] = b'H';
        file[0x305] = 0;
        file[0x306] = b'i';
        file[0x307] = 0;
        file[0x308] = b'!';
        file[0x309] = 0;

        let map = make_test_map(&file);
        let pool = ConstantPool::new(&map, 0x00401000);

        let entry = pool.resolve(0).unwrap();
        let ConstPoolEntry::BStr(bstr) = entry else {
            panic!("expected BStr, got {:?}", entry);
        };
        assert_eq!(bstr.byte_length(), 6);
        assert_eq!(bstr.va(), 0x00401104);

        let s = pool.resolve_string(0).unwrap();
        assert_eq!(s, Some("Hi!".to_string()));
    }

    #[test]
    fn test_resolve_raw_va() {
        let mut file = vec![0u8; 0x3000];
        // Pool entry → VA pointing to non-BSTR data (odd-length prefix)
        file[0x200..0x204].copy_from_slice(&0x00401104u32.to_le_bytes());
        // At VA-4 (offset 0x300): put an odd "length" that fails BSTR check
        file[0x300..0x304].copy_from_slice(&7u32.to_le_bytes()); // odd = not BSTR

        let map = make_test_map(&file);
        let pool = ConstantPool::new(&map, 0x00401000);

        let entry = pool.resolve(0).unwrap();
        let ConstPoolEntry::RawVa(va) = entry else {
            panic!("expected RawVa, got {:?}", entry);
        };
        assert_eq!(va, 0x00401104);

        assert_eq!(pool.resolve_string(0).unwrap(), None);
    }

    #[test]
    fn test_resolve_string_null() {
        let mut file = vec![0u8; 0x3000];
        file[0x200..0x204].copy_from_slice(&0u32.to_le_bytes());

        let map = make_test_map(&file);
        let pool = ConstantPool::new(&map, 0x00401000);

        assert_eq!(pool.resolve_string(0).unwrap(), Some(String::new()));
    }
}
