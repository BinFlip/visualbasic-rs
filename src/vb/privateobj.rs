//! PrivateObjectDescriptor structure parser.
//!
//! The PrivateObjectDescriptor contains per-object private data including
//! function type descriptors, variable counts, and parameter name tables.
//! It is referenced by [`ObjectInfo::private_object_va()`](super::object::ObjectInfo::private_object_va)
//! at offset 0x0C.
//!
//! # Layout (0x40 bytes)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0x00 | 4 | Reserved (always 0 in compiled binaries) |
//! | 0x04 | 4 | `lpObjectInfo` — back-pointer to parent ObjectInfo |
//! | 0x08 | 4 | Reserved (always 0xFFFFFFFF) |
//! | 0x0C | 4 | Reserved (always 0 in compiled binaries) |
//! | 0x10 | 2 | `wFuncCount` — number of public functions/methods |
//! | 0x12 | 2 | `wFuncCount2` — secondary count (non-zero in ActiveX OCXs) |
//! | 0x14 | 2 | `wVarCount` — number of public variables |
//! | 0x16 | 2 | Padding (always 0) |
//! | 0x18 | 4 | `lpFuncTypDescs` — VA to array of FuncTypDesc pointers |
//! | 0x1C | 4 | `lpExtendedFuncData` — secondary FuncTypDesc metadata array (always 0 in compiled; IDE/debug only) |
//! | 0x20 | 4 | `lpMethodNameTable` — secondary method name table (FuncTypDesc pointer array indexed by func index) |
//! | 0x24 | 4 | `lpParamNames` — parameter name string table |
//! | 0x28 | 4 | `lpVarStubs` — runtime stub reference table |
//! | 0x2C | 12 | Reserved (always 0 in compiled binaries) |
//! | 0x38 | 4 | `dwDescSize` — total size of function type descriptors area |
//! | 0x3C | 4 | `dwFlags` — bit 2=valid, bit 8=class module |
//!
//! # Unknown Field Verification (2026-03-29)
//!
//! Fields +0x00, +0x0C, +0x16, +0x1C, +0x2C-0x37 verified as zero across
//! 30 EXE samples + ComCt332.ocx (46 objects total). Runtime code in
//! `sub_660f6349` reads +0x1C as a pointer array, but the code path requires
//! BOTH `(fObjectType & 0x02) == 0` (module-type) AND a valid PrivateObjectDescriptor.
//! These are mutually exclusive in compiled binaries: modules lack
//! PrivateObjectDescriptors (`private_object_va == 0xFFFFFFFF`), so the
//! path is unreachable. Field is likely populated in IDE/debug mode only.
//!
//! # Discovery
//!
//! Layout reverse-engineered from multiple VB6 binaries. The u16 split at
//! +0x10/+0x12 was discovered via ComCt332.ocx (Microsoft Common Controls 3)
//! where `wFuncCount2` is non-zero for objects like CoolBar (13),
//! EmbossedPicture (2), and BandPropertyNotify (1). EXE samples always
//! have `wFuncCount2 == 0`, which masked the u32 vs u16 distinction.

use crate::{
    error::Error,
    util::{read_u16_le, read_u32_le},
};

/// View over a PrivateObjectDescriptor structure (0x40 bytes).
///
/// Contains per-object private data: function type descriptor pointers,
/// variable counts, and parameter name tables.
///
/// # Accessor fallibility
///
/// [`parse`](Self::parse) validates that the fixed 0x40-byte header is
/// present. After that, fixed-offset accessors on this type are only
/// fallible if the already-validated backing slice is unexpectedly too
/// short or arithmetic overflows while reading primitive fields. Methods
/// that only inspect those primitive fields, such as [`is_class`](Self::is_class),
/// do not follow VAs and treat unreadable fields as false predicates.
#[derive(Clone, Copy, Debug)]
pub struct PrivateObjectDescriptor<'a> {
    bytes: &'a [u8],
}

impl<'a> PrivateObjectDescriptor<'a> {
    /// Size of the structure in bytes.
    pub const SIZE: usize = 0x40;

    /// Parses a PrivateObjectDescriptor from the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 0x40`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::TooShort {
                expected: Self::SIZE,
                actual: data.len(),
                context: "PrivateObjectDescriptor",
            });
        }
        let bytes = data.get(..Self::SIZE).ok_or(Error::TooShort {
            expected: Self::SIZE,
            actual: data.len(),
            context: "PrivateObjectDescriptor",
        })?;
        Ok(Self { bytes })
    }

    /// Back-pointer to the parent [`ObjectInfo`](super::object::ObjectInfo) at offset 0x04.
    #[inline]
    pub fn object_info_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x04)
    }

    /// Number of public functions/methods at offset 0x10 (u16).
    #[inline]
    pub fn func_count(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x10)
    }

    /// Secondary function count at offset 0x12 (u16).
    ///
    /// Non-zero in ActiveX DLLs/OCXs (e.g., CoolBar=13, EmbossedPicture=2).
    /// **Not read by any code in MSVBVM60.DLL** — exhaustive search confirmed
    /// the runtime ignores this field. Likely vestigial or IDE-only metadata.
    #[inline]
    pub fn func_count2(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x12)
    }

    /// Number of public variables at offset 0x14 (u16).
    #[inline]
    pub fn var_count(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x14)
    }

    /// VA of the [`FuncTypDesc`](super::functype::FuncTypDesc) pointer array at offset 0x18.
    ///
    /// Points to an array of VAs, one per function. Each VA points to a
    /// [`FuncTypDesc`](super::functype::FuncTypDesc) structure (use
    /// [`FuncTypDesc::parse_extended`](super::functype::FuncTypDesc::parse_extended)
    /// for full arg type access). Null entries (VA == 0) indicate functions
    /// without public prototypes (e.g., event handlers).
    /// Array length = [`func_count`](Self::func_count) + [`var_count`](Self::var_count).
    #[inline]
    pub fn func_type_descs_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x18)
    }

    /// VA of the secondary method name table at offset 0x20.
    #[inline]
    pub fn method_name_table_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x20)
    }

    /// VA of the parameter name string table at offset 0x24.
    ///
    /// Points to an array of VAs to null-terminated parameter name strings.
    /// These are shared across all functions in the object (e.g., `"Data"`,
    /// `"PassWord"`, `"ZipName"`).
    #[inline]
    pub fn param_names_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x24)
    }

    /// VA of variable implementation stub array at offset 0x28.
    ///
    /// Points to an array of `wVarCount` VA pointers, each to a
    /// [`VarStubDesc`](super::varstub::VarStubDesc) structure describing
    /// which VBA runtime functions implement the property accessors for a
    /// public variable. Use [`VarStubIter`](super::varstub::VarStubIter) to iterate.
    ///
    /// **Not read by MSVBVM60.DLL at runtime** — compiler/IDE metadata only.
    /// Still useful for analysis: reveals runtime function dependencies and
    /// method names for each public variable.
    #[inline]
    pub fn var_stubs_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x28)
    }

    /// Total size of the function type descriptors area at offset 0x38.
    #[inline]
    pub fn desc_size(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x38)
    }

    /// Object flags at offset 0x3C.
    ///
    /// Bit field with the following known flags:
    /// - Bit 2 (`0x0004`): Always set — indicates a valid PrivateObjectDescriptor.
    /// - Bit 8 (`0x0100`): Class module flag — set for `.cls` files.
    ///
    /// Observed values across 709 objects in 104 samples:
    /// - `0x0004` (557 objects): Forms, standard modules, UserControls, UserDocuments.
    /// - `0x0104` (157 objects): Class modules (`.cls` files).
    ///
    /// No other values have been observed.
    #[inline]
    pub fn flags(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x3C)
    }

    /// Returns `true` if this object is a class module (`.cls` file).
    ///
    /// Checks bit 8 (`0x0100`) of the flags at +0x3C. This is distinct
    /// from [`PublicObjectDescriptor::is_class()`](super::object::PublicObjectDescriptor::is_class)
    /// which checks bit 4 of `fObjectType`.
    #[inline]
    pub fn is_class(&self) -> bool {
        self.flags().is_ok_and(|f| f & 0x0100 != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Real data from Cls_Zip in pe_x86_vb_loader sample
    const CLS_ZIP: [u8; 0x40] = [
        0x00, 0x00, 0x00, 0x00, 0x1C, 0x28, 0x40, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
        0x00, 0x0E, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0xA8, 0x5C, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x30, 0x5B, 0x40, 0x00, 0x44, 0x55, 0x40, 0x00, 0x44, 0x56, 0x40, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x00, 0x00, 0x00,
        0x04, 0x01, 0x00, 0x00,
    ];

    // Real data from Form1 in pe_x86_vb_loader sample
    const FORM1: [u8; 0x40] = [
        0x00, 0x00, 0x00, 0x00, 0x3C, 0x24, 0x40, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8C, 0x55, 0x40, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x44, 0x55, 0x40, 0x00, 0x44, 0x55, 0x40, 0x00, 0x44, 0x55, 0x40, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
    ];

    #[test]
    fn test_parse_cls_zip() {
        let pod = PrivateObjectDescriptor::parse(&CLS_ZIP).unwrap();
        assert_eq!(pod.object_info_va().unwrap(), 0x0040281C);
        assert_eq!(pod.func_count().unwrap(), 14);
        assert_eq!(pod.var_count().unwrap(), 5);
        assert_eq!(pod.func_type_descs_va().unwrap(), 0x00405CA8);
        assert_eq!(pod.param_names_va().unwrap(), 0x00405544);
        assert_eq!(pod.var_stubs_va().unwrap(), 0x00405644);
        assert_eq!(pod.desc_size().unwrap(), 0x4C);
        assert_eq!(pod.flags().unwrap(), 0x0104);
        assert!(pod.is_class());
    }

    #[test]
    fn test_parse_form1() {
        let pod = PrivateObjectDescriptor::parse(&FORM1).unwrap();
        assert_eq!(pod.object_info_va().unwrap(), 0x0040243C);
        assert_eq!(pod.func_count().unwrap(), 0);
        assert_eq!(pod.var_count().unwrap(), 0);
        assert_eq!(pod.func_type_descs_va().unwrap(), 0x0040558C);
        assert_eq!(pod.desc_size().unwrap(), 0x44);
        assert_eq!(pod.flags().unwrap(), 0x0004);
        assert!(!pod.is_class());
    }

    // Real data from CoolBar in ComCt332.ocx — func_count2 is non-zero (13)
    const COOLBAR_OCX: [u8; 0x40] = [
        0x00, 0x00, 0x00, 0x00, 0x84, 0x71, 0x08, 0x28, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00,
        0x00, 0x1E, 0x00, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x25, 0x09, 0x28, 0x00, 0x00,
        0x00, 0x00, 0x3C, 0x22, 0x09, 0x28, 0xCC, 0x1D, 0x09, 0x28, 0x50, 0x05, 0x09, 0x28, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBC, 0x00, 0x00, 0x00,
        0x04, 0x01, 0x00, 0x00,
    ];

    #[test]
    fn test_parse_coolbar_ocx() {
        let pod = PrivateObjectDescriptor::parse(&COOLBAR_OCX).unwrap();
        assert_eq!(pod.func_count().unwrap(), 30);
        assert_eq!(pod.func_count2().unwrap(), 13);
        assert_eq!(pod.var_count().unwrap(), 0);
        assert_eq!(pod.flags().unwrap(), 0x0104);
        assert!(pod.is_class());
    }

    #[test]
    fn test_parse_too_short() {
        let short = [0u8; 0x3F];
        assert!(PrivateObjectDescriptor::parse(&short).is_err());
    }
}
