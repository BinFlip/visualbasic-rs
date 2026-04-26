//! External table and import descriptor structures.
//!
//! VB6 P-Code executables resolve external DLL/API calls at runtime through
//! `DllFunctionCall` (export of MSVBVM60.DLL) rather than through the
//! conventional PE import table. The external table describes these references.
//!
//! # Structure Hierarchy
//!
//! ```text
//! VbHeader.lpExternalTable / ProjectData.lpExternalTable
//!   └── ExternalTableEntry[]   (one per external component)
//!         └── ExternalComponentInfo
//!               ├── lpLibraryName  -> DLL name string
//!               └── lpFunctionName -> API function name string
//! ```
//!
//! # API Call Mechanism
//!
//! When P-Code executes an `ImpAdCall*` opcode:
//! 1. The opcode references a constant pool entry
//! 2. The pool entry is a native stub: `push offset CallApiStruct; jmp DllFunctionCall`
//! 3. The [`CallApiStub`] contains pointers to the DLL name and function name
//! 4. `DllFunctionCall` resolves via `LoadLibrary`/`GetProcAddress` at runtime

use std::{borrow::Cow, fmt, str};

use crate::{
    addressmap::AddressMap,
    error::Error,
    util::{read_cstr, read_u16_le, read_u32_le},
    vb::control::Guid,
};

/// View over a CallAPI stub structure (8 bytes).
///
/// Found in the constant pool. Each stub contains pointers to the
/// DLL library name and API function name.
///
/// # Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `lpLibraryName` (VA to null-terminated DLL name) |
/// | 0x04 | 4 | `lpFunctionName` (VA to null-terminated API name) |
#[derive(Clone, Copy, Debug)]
pub struct CallApiStub<'a> {
    /// Raw backing bytes borrowed from the PE file buffer.
    bytes: &'a [u8],
}

impl<'a> CallApiStub<'a> {
    /// Size of the CallAPI structure in bytes.
    pub const SIZE: usize = 8;

    /// Parses a CallApiStub from the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 8`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let bytes = data.get(..Self::SIZE).ok_or(Error::TooShort {
            expected: Self::SIZE,
            actual: data.len(),
            context: "CallApiStub",
        })?;
        Ok(Self { bytes })
    }

    /// Virtual address of the DLL name string at offset 0x00.
    #[inline]
    pub fn library_name_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x00)
    }

    /// Virtual address of the API function name string at offset 0x04.
    #[inline]
    pub fn function_name_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x04)
    }

    /// Resolves the DLL library name as a lossy UTF-8 string.
    ///
    /// Use [`library_name_bytes`](Self::library_name_bytes) for raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the VA cannot be resolved.
    pub fn library_name(&self, map: &AddressMap<'a>) -> Result<Cow<'a, str>, Error> {
        Ok(String::from_utf8_lossy(self.library_name_bytes(map)?))
    }

    /// Resolves the DLL library name as raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the VA cannot be resolved.
    pub fn library_name_bytes(&self, map: &AddressMap<'a>) -> Result<&'a [u8], Error> {
        let va = self.library_name_va()?;
        if va == 0 {
            return Ok(b"");
        }
        let offset = map.va_to_offset(va)?;
        read_cstr(map.file(), offset)
    }

    /// Resolves the API function name as a lossy UTF-8 string.
    ///
    /// Use [`function_name_bytes`](Self::function_name_bytes) for raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the VA cannot be resolved.
    pub fn function_name(&self, map: &AddressMap<'a>) -> Result<Cow<'a, str>, Error> {
        Ok(String::from_utf8_lossy(self.function_name_bytes(map)?))
    }

    /// Resolves the API function name as raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the VA cannot be resolved.
    pub fn function_name_bytes(&self, map: &AddressMap<'a>) -> Result<&'a [u8], Error> {
        let va = self.function_name_va()?;
        if va == 0 {
            return Ok(b"");
        }
        let offset = map.va_to_offset(va)?;
        read_cstr(map.file(), offset)
    }
}

/// Resolves an API call stub from the constant pool.
///
/// In the constant pool, API call entries are native code stubs with
/// the pattern:
///
/// ```x86asm
/// push offset CallApiStruct    ; 0x68 <imm32>
/// jmp  DllFunctionCall          ; 0xE9 <rel32>  (or 0xFF 0x25 for indirect)
/// ```
///
/// This function reads the stub at the given VA, extracts the
/// [`CallApiStub`] address from the `push` instruction, and returns it.
///
/// # Arguments
///
/// * `map` - Address map for VA-to-offset translation.
/// * `stub_va` - Virtual address of the native call stub in the constant pool.
///
/// # Errors
///
/// Returns an error if the VA cannot be resolved or the stub does not
/// start with `push imm32` (`0x68`).
pub fn resolve_api_stub<'a>(map: &AddressMap<'a>, stub_va: u32) -> Result<CallApiStub<'a>, Error> {
    // Read enough bytes for push imm32 (5 bytes)
    let stub_data = map.slice_from_va(stub_va, 5)?;

    let first = *stub_data.first().ok_or(Error::TooShort {
        expected: 5,
        actual: stub_data.len(),
        context: "resolve_api_stub",
    })?;
    if first != 0x68 {
        return Err(Error::EntryPointNotPush { byte: first });
    }

    let call_api_va = read_u32_le(stub_data, 1)?;
    let call_api_data = map.slice_from_va(call_api_va, CallApiStub::SIZE)?;
    CallApiStub::parse(call_api_data)
}

/// Type byte enumeration for VB6 function prototype descriptors.
///
/// Used in FuncTypDesc to describe parameter and return types.
/// Modifiers (`ByRef`, `Array`, `Optional`) are OR'd with the base type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VbType(
    /// Raw type byte, possibly OR'd with modifier flags (ByRef, Array, Optional).
    pub u8,
);

impl VbType {
    /// Empty/void type.
    pub const EMPTY: u8 = 0x00;
    /// Null type.
    pub const NULL: u8 = 0x01;
    /// Integer (16-bit).
    pub const INTEGER: u8 = 0x02;
    /// Long (32-bit).
    pub const LONG: u8 = 0x03;
    /// Single-precision float.
    pub const SINGLE: u8 = 0x04;
    /// Double-precision float.
    pub const DOUBLE: u8 = 0x05;
    /// Currency (64-bit fixed-point).
    pub const CURRENCY: u8 = 0x06;
    /// Date (stored as Double).
    pub const DATE: u8 = 0x07;
    /// String (BSTR).
    pub const STRING: u8 = 0x08;
    /// Object reference.
    pub const OBJECT: u8 = 0x0A;
    /// Error type.
    pub const ERROR: u8 = 0x0B;
    /// Boolean.
    pub const BOOLEAN: u8 = 0x0C;
    /// Variant.
    pub const VARIANT: u8 = 0x0D;
    /// Decimal.
    pub const DECIMAL: u8 = 0x0E;
    /// Byte (unsigned 8-bit).
    pub const BYTE: u8 = 0x10;
    /// User Defined Type (UDT). In lpArgTypes, followed by 4-byte aligned extra data.
    pub const UDT: u8 = 0x11;
    /// Typed object reference. In lpArgTypes, followed by 4-byte aligned extra data.
    pub const TYPED_OBJECT: u8 = 0x13;
    /// Typed array. In lpArgTypes, followed by 4-byte aligned extra data.
    pub const TYPED_ARRAY: u8 = 0x14;
    /// Long pointer / handle.
    pub const LONG_PTR: u8 = 0x1B;
    /// Extended decimal. In lpArgTypes, followed by 4-byte aligned extra data.
    pub const EXTENDED_DECIMAL: u8 = 0x1C;
    /// External COM object (followed by 32-bit offset).
    pub const EXTERNAL_COM: u8 = 0x1D;
    /// IDispatch pointer to an internal VB object.
    ///
    /// Used for ByVal String and ByVal Object parameters (passed as 4-byte
    /// dispatch pointers on the stack). As a return type, maps to hidden
    /// HRESULT checking (runtime marshalling code 0x19 in `sub_6600fbff`).
    /// As a parameter type, `ResolveDispatchToFuncTypDesc` forces this
    /// type when resolving variables through the secondary name table.
    pub const DISPATCH_PTR: u8 = 0x1E;

    /// Array modifier (OR'd with base type, bit 5).
    ///
    /// Verified via MSVBVM60.DLL `sub_6600fbff`: `*arg1 & 0x20` checks array flag.
    pub const ARRAY: u8 = 0x20;
    /// ByRef modifier (OR'd with base type, bit 6).
    ///
    /// Verified via MSVBVM60.DLL `sub_6600fbff`: `*arg1 & 0x40` checks ByRef flag.
    pub const BYREF: u8 = 0x40;
    /// Optional parameter modifier (OR'd with base type, bit 7).
    pub const OPTIONAL: u8 = 0x80;

    /// Returns the raw base type code without any modifiers (5-bit).
    #[inline]
    pub fn base_type(self) -> u8 {
        self.0 & 0x1F
    }

    /// Returns the base type as a [`VbBaseType`] enum for typed matching.
    #[inline]
    pub fn base_type_enum(self) -> VbBaseType {
        VbBaseType::from_raw(self.base_type())
    }

    /// Returns `true` if the ByRef modifier is set.
    #[inline]
    pub fn is_byref(self) -> bool {
        self.0 & Self::BYREF != 0
    }

    /// Returns `true` if the Array modifier is set.
    #[inline]
    pub fn is_array(self) -> bool {
        self.0 & Self::ARRAY != 0
    }

    /// Returns `true` if the Optional modifier is set.
    #[inline]
    pub fn is_optional(self) -> bool {
        self.0 & Self::OPTIONAL != 0
    }

    /// Returns a human-readable name for the base type.
    pub fn type_name(self) -> &'static str {
        match self.base_type() {
            Self::EMPTY => "Void",
            Self::NULL => "Null",
            Self::INTEGER => "Integer",
            Self::LONG => "Long",
            Self::SINGLE => "Single",
            Self::DOUBLE => "Double",
            Self::CURRENCY => "Currency",
            Self::DATE => "Date",
            Self::STRING => "String",
            Self::OBJECT => "Object",
            Self::ERROR => "Error",
            Self::BOOLEAN => "Boolean",
            Self::VARIANT => "Variant",
            Self::DECIMAL => "Decimal",
            Self::BYTE => "Byte",
            Self::UDT => "UDT",
            Self::TYPED_OBJECT => "TypedObject",
            Self::TYPED_ARRAY => "TypedArray",
            Self::LONG_PTR => "LongPtr",
            Self::EXTENDED_DECIMAL => "ExtDecimal",
            Self::EXTERNAL_COM => "ExternalCOM",
            Self::DISPATCH_PTR => "DispatchPtr",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for VbType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_optional() {
            write!(f, "Optional ")?;
        }
        if self.is_byref() {
            write!(f, "ByRef ")?;
        }
        write!(f, "{}", self.type_name())?;
        if self.is_array() {
            write!(f, "()")?;
        }
        Ok(())
    }
}

/// Base type enumeration for VB6 type descriptors (5-bit type code).
///
/// Extracted from [`VbType`] via [`VbType::base_type_enum`]. The 3 high bits
/// of VbType carry modifiers (Array, ByRef, Optional); this enum represents
/// only the base type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VbBaseType {
    /// Void / empty (0x00).
    Void,
    /// Null (0x01).
    Null,
    /// Integer, 16-bit signed (0x02).
    Integer,
    /// Long, 32-bit signed (0x03).
    Long,
    /// Single-precision float (0x04).
    Single,
    /// Double-precision float (0x05).
    Double,
    /// Currency, 64-bit fixed-point (0x06).
    Currency,
    /// Date, stored as Double (0x07).
    Date,
    /// String / BSTR (0x08).
    String,
    /// Object reference (0x0A).
    Object,
    /// Error type (0x0B).
    Error,
    /// Boolean (0x0C).
    Boolean,
    /// Variant (0x0D).
    Variant,
    /// Decimal (0x0E).
    Decimal,
    /// Byte, unsigned 8-bit (0x10).
    Byte,
    /// User Defined Type (0x11).
    Udt,
    /// Typed object reference (0x13).
    TypedObject,
    /// Typed array (0x14).
    TypedArray,
    /// Long pointer / handle (0x1B).
    LongPtr,
    /// Extended decimal (0x1C).
    ExtDecimal,
    /// External COM object (0x1D).
    ExternalCom,
    /// IDispatch pointer to internal VB object (0x1E).
    DispatchPtr,
    /// Unknown or undocumented type code.
    Unknown(u8),
}

impl VbBaseType {
    /// Converts a raw 5-bit type code to a `VbBaseType`.
    pub fn from_raw(raw: u8) -> Self {
        match raw & 0x1F {
            0x00 => Self::Void,
            0x01 => Self::Null,
            0x02 => Self::Integer,
            0x03 => Self::Long,
            0x04 => Self::Single,
            0x05 => Self::Double,
            0x06 => Self::Currency,
            0x07 => Self::Date,
            0x08 => Self::String,
            0x0A => Self::Object,
            0x0B => Self::Error,
            0x0C => Self::Boolean,
            0x0D => Self::Variant,
            0x0E => Self::Decimal,
            0x10 => Self::Byte,
            0x11 => Self::Udt,
            0x13 => Self::TypedObject,
            0x14 => Self::TypedArray,
            0x1B => Self::LongPtr,
            0x1C => Self::ExtDecimal,
            0x1D => Self::ExternalCom,
            0x1E => Self::DispatchPtr,
            n => Self::Unknown(n),
        }
    }

    /// Returns a human-readable name for this base type.
    pub fn name(self) -> &'static str {
        match self {
            Self::Void => "Void",
            Self::Null => "Null",
            Self::Integer => "Integer",
            Self::Long => "Long",
            Self::Single => "Single",
            Self::Double => "Double",
            Self::Currency => "Currency",
            Self::Date => "Date",
            Self::String => "String",
            Self::Object => "Object",
            Self::Error => "Error",
            Self::Boolean => "Boolean",
            Self::Variant => "Variant",
            Self::Decimal => "Decimal",
            Self::Byte => "Byte",
            Self::Udt => "UDT",
            Self::TypedObject => "TypedObject",
            Self::TypedArray => "TypedArray",
            Self::LongPtr => "LongPtr",
            Self::ExtDecimal => "ExtDecimal",
            Self::ExternalCom => "ExternalCOM",
            Self::DispatchPtr => "DispatchPtr",
            Self::Unknown(_) => "Unknown",
        }
    }
}

impl fmt::Display for VbBaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// COM VARIANT type code.
///
/// Used in optional parameter default value entries (at the VA pointed to
/// by `FuncTypDesc.optional_defaults_va`). Mirrors the `VARENUM` values
/// from the Windows SDK.
///
/// Size mapping verified against `VarTypeToSize` (0x660F5FF0) in MSVBVM60.DLL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum VarType {
    /// VT_EMPTY (0) — no value.
    Empty = 0,
    /// VT_NULL (1) — SQL-style null.
    Null = 1,
    /// VT_I2 (2) — 16-bit signed integer. Data: 2 bytes.
    I2 = 2,
    /// VT_I4 (3) — 32-bit signed integer. Data: 4 bytes.
    I4 = 3,
    /// VT_R4 (4) — 32-bit float. Data: 4 bytes.
    R4 = 4,
    /// VT_R8 (5) — 64-bit float. Data: 8 bytes.
    R8 = 5,
    /// VT_CY (6) — Currency (64-bit fixed-point). Data: 8 bytes.
    Cy = 6,
    /// VT_DATE (7) — Date (as f64). Data: 8 bytes.
    Date = 7,
    /// VT_BSTR (8) — Unicode string. Data: u16 length + UTF-16LE bytes.
    Bstr = 8,
    /// VT_DISPATCH (9) — IDispatch pointer. Data: 4 bytes.
    Dispatch = 9,
    /// VT_ERROR (10) — SCODE. Data: 4 bytes.
    Error = 10,
    /// VT_BOOL (11) — Boolean (VARIANT_BOOL). Data: 2 bytes.
    Bool = 11,
    /// VT_VARIANT (12) — Variant (nested). Data: variable.
    Variant = 12,
    /// VT_UNKNOWN (13) — IUnknown pointer. Data: 4 bytes.
    Unknown = 13,
    /// VT_DECIMAL (14) — 96-bit decimal. Data: 16 bytes.
    Decimal = 14,
    /// VT_I1 (16) — 8-bit signed integer. Data: 2 bytes (word-aligned).
    I1 = 16,
    /// VT_UI1 (17) — 8-bit unsigned integer. Data: 2 bytes (word-aligned).
    Ui1 = 17,
    /// VT_UI2 (18) — 16-bit unsigned integer. Data: 2 bytes.
    Ui2 = 18,
    /// VT_RECORD (19) — UDT / record. Data: 4 bytes.
    Record = 19,
    /// VT_INT (22) — Machine-sized signed integer. Data: 4 bytes.
    Int = 22,
    /// VT_UINT (23) — Machine-sized unsigned integer. Data: 4 bytes.
    Uint = 23,
}

impl VarType {
    /// Converts a raw u16 to a VarType, returning None for unknown codes.
    pub fn from_raw(v: u16) -> Option<Self> {
        match v {
            0 => Some(Self::Empty),
            1 => Some(Self::Null),
            2 => Some(Self::I2),
            3 => Some(Self::I4),
            4 => Some(Self::R4),
            5 => Some(Self::R8),
            6 => Some(Self::Cy),
            7 => Some(Self::Date),
            8 => Some(Self::Bstr),
            9 => Some(Self::Dispatch),
            10 => Some(Self::Error),
            11 => Some(Self::Bool),
            12 => Some(Self::Variant),
            13 => Some(Self::Unknown),
            14 => Some(Self::Decimal),
            16 => Some(Self::I1),
            17 => Some(Self::Ui1),
            18 => Some(Self::Ui2),
            19 => Some(Self::Record),
            22 => Some(Self::Int),
            23 => Some(Self::Uint),
            _ => None,
        }
    }

    /// Returns the byte size of this type's data portion in a default value entry.
    ///
    /// Mirrors `VarTypeToSize` (0x660F5FF0) in MSVBVM60.DLL.
    /// Returns 0 for variable-size types (BSTR, Variant) and unknown types.
    pub fn data_size(self) -> usize {
        match self {
            Self::Empty | Self::Null => 0,
            Self::I2 => 2,
            Self::I4 | Self::R4 => 4,
            Self::R8 | Self::Cy | Self::Date => 8,
            Self::Bstr => 0, // Variable — handled separately
            Self::Dispatch | Self::Error => 4,
            Self::Bool => 2,
            Self::Variant => 0,
            Self::Unknown => 4,
            Self::Decimal => 16,
            Self::I1 | Self::Ui1 | Self::Ui2 => 2,
            Self::Record => 4,
            Self::Int | Self::Uint => 4,
        }
    }
}

impl fmt::Display for VarType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "Empty"),
            Self::Null => write!(f, "Null"),
            Self::I2 => write!(f, "Integer"),
            Self::I4 => write!(f, "Long"),
            Self::R4 => write!(f, "Single"),
            Self::R8 => write!(f, "Double"),
            Self::Cy => write!(f, "Currency"),
            Self::Date => write!(f, "Date"),
            Self::Bstr => write!(f, "String"),
            Self::Dispatch => write!(f, "Object"),
            Self::Error => write!(f, "Error"),
            Self::Bool => write!(f, "Boolean"),
            Self::Variant => write!(f, "Variant"),
            Self::Unknown => write!(f, "Unknown"),
            Self::Decimal => write!(f, "Decimal"),
            Self::I1 => write!(f, "SByte"),
            Self::Ui1 => write!(f, "Byte"),
            Self::Ui2 => write!(f, "UShort"),
            Self::Record => write!(f, "UDT"),
            Self::Int => write!(f, "Int"),
            Self::Uint => write!(f, "UInt"),
        }
    }
}

/// View over an external component table entry (8 bytes).
///
/// Classification of an external table entry.
///
/// The `fExternalType` field determines what kind of external reference
/// the entry represents and how `lpExternalObject` should be interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalKind {
    /// COM type library reference (`fExternalType == 0x06`).
    ///
    /// The `lpExternalObject` VA points to a 16-byte GUID (the typelib's
    /// CLSID/LIBID). These are references to OCX or ActiveX type libraries
    /// registered on the system.
    TypeLib,

    /// Declare function import (`fExternalType == 0x07`).
    ///
    /// The `lpExternalObject` VA points to a structure whose first two
    /// DWORDs are VAs to null-terminated strings: the DLL library name
    /// and the exported function name (e.g., `kernel32` + `CreateFileA`).
    DeclareFunction,

    /// Unknown or unrecognized external type.
    ///
    /// The raw `fExternalType` value is preserved for inspection.
    Unknown(u32),
}

impl ExternalKind {
    /// Classifies an external type value.
    pub fn from_raw(value: u32) -> Self {
        match value {
            0x06 => Self::TypeLib,
            0x07 => Self::DeclareFunction,
            other => Self::Unknown(other),
        }
    }
}

impl fmt::Display for ExternalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TypeLib => write!(f, "typelib"),
            Self::DeclareFunction => write!(f, "declare"),
            Self::Unknown(v) => write!(f, "unknown(0x{v:08X})"),
        }
    }
}

/// View over an external component table entry (8 bytes).
///
/// The external table is referenced by `ProjectData.external_table_va()?`
/// with `ProjectData.external_count()?` entries. Each entry describes an
/// external COM component (OCX, DLL, typelib) used by the project.
///
/// Use [`kind()`](Self::kind) to determine what the entry represents and
/// how to interpret `external_object_va()`.
///
/// # Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `fExternalType` — see [`ExternalKind`] |
/// | 0x04 | 4 | `lpExternalObject` (VA to component descriptor) |
#[derive(Clone, Copy, Debug)]
pub struct ExternalTableEntry<'a> {
    /// Raw backing bytes borrowed from the PE file buffer.
    bytes: &'a [u8],
}

impl<'a> ExternalTableEntry<'a> {
    /// Size of one external table entry in bytes.
    pub const SIZE: usize = 8;

    /// Parses an external table entry from the given byte slice.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 8`.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let bytes = data.get(..Self::SIZE).ok_or(Error::TooShort {
            expected: Self::SIZE,
            actual: data.len(),
            context: "ExternalTableEntry",
        })?;
        Ok(Self { bytes })
    }

    /// Raw component type flags at offset 0x00.
    #[inline]
    pub fn external_type(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x00)
    }

    /// Classified external kind based on the type flags.
    ///
    /// Use this to determine how to interpret [`external_object_va`](Self::external_object_va):
    /// - [`ExternalKind::DeclareFunction`]: VA points to [`ExternalDeclareInfo`]
    /// - [`ExternalKind::TypeLib`]: VA points to [`ExternalTypelibInfo`]
    ///
    /// # Errors
    ///
    /// Returns [`Error::Truncated`] if the backing buffer is shorter than expected.
    #[inline]
    pub fn kind(&self) -> Result<ExternalKind, Error> {
        Ok(ExternalKind::from_raw(self.external_type()?))
    }

    /// VA of the external component descriptor at offset 0x04.
    #[inline]
    pub fn external_object_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x04)
    }

    /// Parses this entry as a `Declare` function import.
    ///
    /// Returns `None` if the type is not [`ExternalKind::DeclareFunction`]
    /// or the VA cannot be resolved.
    pub fn as_declare(&self, map: &AddressMap<'a>) -> Option<ExternalDeclareInfo<'a>> {
        if !matches!(self.kind().ok()?, ExternalKind::DeclareFunction) {
            return None;
        }
        let va = self.external_object_va().ok()?;
        let data = map.slice_from_va(va, ExternalDeclareInfo::SIZE).ok()?;
        ExternalDeclareInfo::parse(data).ok()
    }

    /// Parses this entry as a TypeLib reference.
    ///
    /// Returns `None` if the type is not [`ExternalKind::TypeLib`]
    /// or the VA cannot be resolved.
    pub fn as_typelib(&self, map: &AddressMap<'a>) -> Option<ExternalTypelibInfo<'a>> {
        let va = self.external_object_va().ok()?;
        let data = map.slice_from_va(va, ExternalTypelibInfo::SIZE).ok()?;
        ExternalTypelibInfo::parse(data).ok()
    }
}

/// External Declare function descriptor (0x10 bytes).
///
/// Describes a `Declare Function`/`Declare Sub` import from a native DLL.
///
/// # Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `lpLibraryName` (VA to DLL name string) |
/// | 0x04 | 4 | `lpFunctionName` (VA to API function name string) |
/// | 0x08 | 4 | `dwFlags` (always 0x00040000 — calling convention) |
/// | 0x0C | 4 | `lpNativeStub` (VA to 12-byte native call stub in .data) |
#[derive(Clone, Copy, Debug)]
pub struct ExternalDeclareInfo<'a> {
    bytes: &'a [u8],
}

impl<'a> ExternalDeclareInfo<'a> {
    /// Size of the structure in bytes.
    pub const SIZE: usize = 0x10;

    /// Parses an external declare info from the given byte slice.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let bytes = data.get(..Self::SIZE).ok_or(Error::TooShort {
            expected: Self::SIZE,
            actual: data.len(),
            context: "ExternalDeclareInfo",
        })?;
        Ok(Self { bytes })
    }

    /// VA of the DLL library name string at offset 0x00.
    #[inline]
    pub fn library_name_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x00)
    }

    /// VA of the API function name string at offset 0x04.
    #[inline]
    pub fn function_name_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x04)
    }

    /// Calling convention/flags at offset 0x08 (always 0x00040000).
    #[inline]
    pub fn flags(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x08)
    }

    /// VA of the native call stub in the .data section at offset 0x0C.
    #[inline]
    pub fn native_stub_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x0C)
    }

    /// Resolves the DLL library name string.
    pub fn library_name(&self, map: &AddressMap<'a>) -> Option<&'a str> {
        let va = self.library_name_va().ok()?;
        if va == 0 {
            return None;
        }
        let off = map.va_to_offset(va).ok()?;
        let name = read_cstr(map.file(), off).ok()?;
        str::from_utf8(name).ok()
    }

    /// Resolves the API function name string.
    pub fn function_name(&self, map: &AddressMap<'a>) -> Option<&'a str> {
        let va = self.function_name_va().ok()?;
        if va == 0 {
            return None;
        }
        let off = map.va_to_offset(va).ok()?;
        let name = read_cstr(map.file(), off).ok()?;
        str::from_utf8(name).ok()
    }
}

/// External TypeLib reference descriptor.
///
/// Describes a referenced COM type library. The GUID is accessed
/// indirectly through a VA pointer.
///
/// # Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `lpTypelibGuid` (VA to 16-byte typelib GUID) |
/// | 0x04 | 4 | `lpRuntimeData` (VA to .data section runtime cache) |
#[derive(Clone, Copy, Debug)]
pub struct ExternalTypelibInfo<'a> {
    bytes: &'a [u8],
}

impl<'a> ExternalTypelibInfo<'a> {
    /// Minimum size of the structure in bytes.
    pub const SIZE: usize = 0x08;

    /// Parses an external typelib info from the given byte slice.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let bytes = data.get(..Self::SIZE).ok_or(Error::TooShort {
            expected: Self::SIZE,
            actual: data.len(),
            context: "ExternalTypelibInfo",
        })?;
        Ok(Self { bytes })
    }

    /// VA to the 16-byte typelib GUID at offset 0x00.
    #[inline]
    pub fn typelib_guid_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x00)
    }

    /// Resolves the typelib GUID by following the VA pointer.
    pub fn typelib_guid(&self, map: &AddressMap<'a>) -> Option<Guid> {
        let va = self.typelib_guid_va().ok()?;
        if va == 0 {
            return None;
        }
        let data = map.slice_from_va(va, 16).ok()?;
        Guid::from_bytes(data)
    }
}

/// View over a variable-length external component entry.
///
/// Used by `VBHeader.external_table_va` (+0x50) for OCX/ActiveX control
/// references. Each entry uses self-relative offsets like ComRegData.
/// The runtime parses these in `sub_6603C89A` during `LoadExternalsAndGUIObjects`.
///
/// # Header Layout (0x34 bytes, 13 dwords)
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `dwEntrySize` — total entry size (self-relative advance to next) |
/// | 0x04 | 4 | `bComponentInfo` — self-rel offset to component info block |
/// | 0x08 | 4 | `bField08` — self-rel offset (interface data 1) |
/// | 0x0C | 4 | `bField0C` — self-rel offset (interface data 2) |
/// | 0x10 | 4 | `bField10` — self-rel offset (interface data 3) |
/// | 0x14 | 4 | `bField14` — self-rel offset (interface data 4) |
/// | 0x18 | 4 | `bEventHandlers` — self-rel offset to event handler array |
/// | 0x1C | 4 | `bField1C` — self-rel offset (interface data 5) |
/// | 0x20 | 4 | `dwInfoBlockSize` — component info block size (direct value) |
/// | 0x24 | 4 | `bField24` — self-rel offset (0 = not present) |
/// | 0x28 | 4 | `bOcxFilename` — self-rel offset to OCX filename string |
/// | 0x2C | 4 | `bProgId` — self-rel offset to ProgID string (e.g., "TabDlg.SSTab") |
/// | 0x30 | 4 | `bClassName` — self-rel offset to class name (e.g., "SSTab") |
///
/// # Component Info Block (at `bComponentInfo`)
///
/// Variable-length block with at least 0x93 bytes:
/// - +0x86 (u8): flags — bit 7 = uses special load path in runtime
/// - +0x92 (u16): event handler count
///
/// # Event Handler Array (at `bEventHandlers`)
///
/// Array of 0x18-byte entries, one per event. Event handler name strings
/// follow immediately after the array.
#[derive(Clone, Copy, Debug)]
pub struct ExternalComponentEntry<'a> {
    bytes: &'a [u8],
}

impl<'a> ExternalComponentEntry<'a> {
    /// Minimum header size in bytes.
    pub const HEADER_SIZE: usize = 0x34;

    /// Size of each event handler array entry.
    pub const EVENT_ENTRY_SIZE: usize = 0x18;

    /// Parses an external component entry from the given byte slice.
    ///
    /// The slice should start at the entry's `dwEntrySize` field.
    /// Only the header is validated; data blocks are accessed lazily.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::HEADER_SIZE {
            return Err(Error::TooShort {
                expected: Self::HEADER_SIZE,
                actual: data.len(),
                context: "ExternalComponentEntry",
            });
        }
        let size = read_u32_le(data, 0x00)? as usize;
        let bytes = data.get(..size).ok_or(Error::TooShort {
            expected: size,
            actual: data.len(),
            context: "ExternalComponentEntry (entry_size)",
        })?;
        if size < Self::HEADER_SIZE {
            return Err(Error::TooShort {
                expected: Self::HEADER_SIZE,
                actual: size,
                context: "ExternalComponentEntry (entry_size)",
            });
        }
        Ok(Self { bytes })
    }

    /// Total entry size at offset 0x00 (advance to next entry).
    #[inline]
    pub fn entry_size(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x00)
    }

    /// OCX/DLL filename as a lossy UTF-8 string (e.g., `"Tabctl32.ocx"`).
    ///
    /// Use [`ocx_filename_bytes`](Self::ocx_filename_bytes) for raw bytes.
    pub fn ocx_filename(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.ocx_filename_bytes())
    }

    /// OCX/DLL filename as raw bytes from self-relative offset at +0x28.
    pub fn ocx_filename_bytes(&self) -> &'a [u8] {
        self.resolve_string(0x28)
    }

    /// ProgID-style name as a lossy UTF-8 string (e.g., `"TabDlg.SSTab"`).
    ///
    /// Use [`prog_id_bytes`](Self::prog_id_bytes) for raw bytes.
    pub fn prog_id(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.prog_id_bytes())
    }

    /// ProgID-style name as raw bytes from self-relative offset at +0x2C.
    pub fn prog_id_bytes(&self) -> &'a [u8] {
        self.resolve_string(0x2C)
    }

    /// Short class name as a lossy UTF-8 string (e.g., `"SSTab"`).
    ///
    /// Use [`class_name_bytes`](Self::class_name_bytes) for raw bytes.
    pub fn class_name(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.class_name_bytes())
    }

    /// Short class name as raw bytes from self-relative offset at +0x30.
    pub fn class_name_bytes(&self) -> &'a [u8] {
        self.resolve_string(0x30)
    }

    /// Component info block flags byte at component_info+0x86.
    ///
    /// Bit 7 = uses special load path in `LoadExternalsAndGUIObjects`.
    pub fn component_flags(&self) -> Option<u8> {
        let off = read_u32_le(self.bytes, 0x04).ok()? as usize;
        let end = off.checked_add(0x87)?;
        if off == 0 || end > self.bytes.len() {
            return None;
        }
        let flags_off = off.checked_add(0x86)?;
        self.bytes.get(flags_off).copied()
    }

    /// Number of event handlers from component_info+0x92.
    pub fn event_count(&self) -> u16 {
        let Ok(off_raw) = read_u32_le(self.bytes, 0x04) else {
            return 0;
        };
        let off = off_raw as usize;
        let Some(end) = off.checked_add(0x94) else {
            return 0;
        };
        if off == 0 || end > self.bytes.len() {
            return 0;
        }
        let Some(field_off) = off.checked_add(0x92) else {
            return 0;
        };
        read_u16_le(self.bytes, field_off).unwrap_or(0)
    }

    /// Component info block size (direct value at +0x20).
    #[inline]
    pub fn info_block_size(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x20)
    }

    /// Returns event handler names for this component.
    ///
    /// Each event is a null-terminated ASCII string. The names follow
    /// the 0x18-byte event array entries sequentially.
    pub fn event_names(&self) -> Vec<&'a str> {
        let Ok(evt_off_raw) = read_u32_le(self.bytes, 0x18) else {
            return Vec::new();
        };
        let evt_off = evt_off_raw as usize;
        if evt_off == 0 {
            return Vec::new();
        }
        let count = self.event_count() as usize;
        if count == 0 {
            return Vec::new();
        }
        // Names start after the array entries
        let Some(array_bytes) = count.checked_mul(Self::EVENT_ENTRY_SIZE) else {
            return Vec::new();
        };
        let Some(names_start) = evt_off.checked_add(array_bytes) else {
            return Vec::new();
        };
        if names_start >= self.bytes.len() {
            return Vec::new();
        }
        let mut names = Vec::with_capacity(count);
        let mut pos = names_start;
        for _ in 0..count {
            let Ok(name) = read_cstr(self.bytes, pos) else {
                break;
            };
            let s = str::from_utf8(name).unwrap_or("?");
            names.push(s);
            let Some(next) = pos.checked_add(name.len()).and_then(|p| p.checked_add(1)) else {
                break;
            };
            pos = next;
            if pos >= self.bytes.len() {
                break;
            }
        }
        names
    }

    /// Resolves a self-relative offset to a null-terminated string.
    fn resolve_string(&self, header_offset: usize) -> &'a [u8] {
        let Ok(off_raw) = read_u32_le(self.bytes, header_offset) else {
            return &[];
        };
        let off = off_raw as usize;
        if off == 0 || off >= self.bytes.len() {
            return &[];
        }
        read_cstr(self.bytes, off).unwrap_or(&[])
    }
}

impl fmt::Display for ExternalComponentEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let filename = self.ocx_filename();
        let class = self.class_name();
        write!(f, "{filename}!{class}")?;
        let ec = self.event_count();
        if ec > 0 {
            write!(f, " ({ec} events)")?;
        }
        Ok(())
    }
}

/// Iterator over variable-length external component entries.
///
/// Walks the external component table at `VBHeader.external_table_va`
/// with `VBHeader.external_count` entries, advancing by each entry's
/// self-relative size.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ExternalComponentIter<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: u16,
}

impl<'a> ExternalComponentIter<'a> {
    /// Creates a new iterator over external component entries.
    ///
    /// `data` should be a slice starting at the first entry. `count`
    /// is the number of entries to iterate.
    pub fn new(data: &'a [u8], count: u16) -> Self {
        Self {
            data,
            pos: 0,
            remaining: count,
        }
    }
}

impl<'a> Iterator for ExternalComponentIter<'a> {
    type Item = ExternalComponentEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.pos >= self.data.len() {
            return None;
        }
        self.remaining = self.remaining.saturating_sub(1);
        let rest = self.data.get(self.pos..)?;
        let entry = ExternalComponentEntry::parse(rest).ok()?;
        let size = entry.entry_size().ok()? as usize;
        if size == 0 {
            return None;
        }
        self.pos = self.pos.checked_add(size)?;
        Some(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addressmap::SectionEntry;

    #[test]
    fn test_call_api_stub_parse() {
        let mut data = vec![0u8; CallApiStub::SIZE];
        data[0x00..0x04].copy_from_slice(&0x00401000u32.to_le_bytes());
        data[0x04..0x08].copy_from_slice(&0x00402000u32.to_le_bytes());
        let stub = CallApiStub::parse(&data).unwrap();
        assert_eq!(stub.library_name_va().unwrap(), 0x00401000);
        assert_eq!(stub.function_name_va().unwrap(), 0x00402000);
    }

    #[test]
    fn test_call_api_stub_too_short() {
        let data = vec![0u8; CallApiStub::SIZE - 1];
        assert!(matches!(
            CallApiStub::parse(&data),
            Err(Error::TooShort { .. })
        ));
    }

    #[test]
    fn test_call_api_stub_zero_va() {
        let data = vec![0u8; CallApiStub::SIZE];
        let stub = CallApiStub::parse(&data).unwrap();
        assert_eq!(stub.library_name_va().unwrap(), 0);
        assert_eq!(stub.function_name_va().unwrap(), 0);
    }

    #[test]
    fn test_resolve_api_stub_valid() {
        // Build a fake file with:
        // - At offset 0x200 (RVA 0x1000): push 0x00401100; jmp ...
        // - At offset 0x300 (RVA 0x1100): CallApiStub with lib_va and func_va
        // - At offset 0x400 (RVA 0x1200): "kernel32.dll\0"
        // - At offset 0x410 (RVA 0x1210): "GetTickCount\0"
        let mut file = vec![0u8; 0x500];

        // The push stub at RVA 0x1000 (offset 0x200)
        file[0x200] = 0x68; // push imm32
        file[0x201..0x205].copy_from_slice(&0x00401100u32.to_le_bytes()); // CallApiStub VA

        // CallApiStub at RVA 0x1100 (offset 0x300)
        file[0x300..0x304].copy_from_slice(&0x00401200u32.to_le_bytes()); // lib name VA
        file[0x304..0x308].copy_from_slice(&0x00401210u32.to_le_bytes()); // func name VA

        // Strings
        file[0x400..0x40C].copy_from_slice(b"kernel32.dll");
        file[0x410..0x41C].copy_from_slice(b"GetTickCount");

        let map = AddressMap::from_parts(
            &file,
            0x00400000,
            vec![SectionEntry {
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_data_offset: 0x200,
                raw_data_size: 0x1000,
            }],
        );

        let stub = resolve_api_stub(&map, 0x00401000).unwrap();
        assert_eq!(stub.library_name_bytes(&map).unwrap(), b"kernel32.dll");
        assert_eq!(stub.function_name_bytes(&map).unwrap(), b"GetTickCount");
        assert_eq!(stub.library_name(&map).unwrap(), "kernel32.dll");
        assert_eq!(stub.function_name(&map).unwrap(), "GetTickCount");
    }

    #[test]
    fn test_resolve_api_stub_not_push() {
        let mut file = vec![0u8; 0x500];
        file[0x200] = 0xCC; // int3 instead of push

        let map = AddressMap::from_parts(
            &file,
            0x00400000,
            vec![SectionEntry {
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_data_offset: 0x200,
                raw_data_size: 0x1000,
            }],
        );

        assert!(matches!(
            resolve_api_stub(&map, 0x00401000),
            Err(Error::EntryPointNotPush { byte: 0xCC })
        ));
    }

    #[test]
    fn test_vb_type_base() {
        let t = VbType(0x03);
        assert_eq!(t.base_type(), VbType::LONG);
        assert_eq!(t.type_name(), "Long");
        assert!(!t.is_byref());
        assert!(!t.is_array());
        assert!(!t.is_optional());
    }

    #[test]
    fn test_vb_type_byref_long() {
        // ByRef Long: BYREF(0x40) | LONG(0x03) = 0x43
        let t = VbType(0x43);
        assert_eq!(t.base_type(), VbType::LONG);
        assert_eq!(t.type_name(), "Long");
        assert!(t.is_byref());
        assert!(!t.is_array());
    }

    #[test]
    fn test_vb_type_optional_array_string() {
        // Optional Array String: OPTIONAL(0x80) | ARRAY(0x20) | STRING(0x08) = 0xA8
        let t = VbType(0xA8);
        assert_eq!(t.base_type(), VbType::STRING);
        assert!(t.is_optional());
        assert!(t.is_array());
        assert!(!t.is_byref());
    }

    #[test]
    fn test_vb_type_byref_array_byte() {
        // ByRef Array of Byte: BYREF(0x40) | ARRAY(0x20) | BYTE(0x10) = 0x70
        // Verified from pe_x86_vb_loader Cls_Zip Pack arg[2] = 0x70
        let t = VbType(0x70);
        assert_eq!(t.base_type(), VbType::BYTE);
        assert!(t.is_byref());
        assert!(t.is_array());
        assert!(!t.is_optional());
        assert_eq!(format!("{t}"), "ByRef Byte()");
    }

    #[test]
    fn test_vb_type_array_byte() {
        // Array of Byte: ARRAY(0x20) | BYTE(0x10) = 0x30
        // Verified from pe_x86_vb_loader Cls_Zip Pack arg[1] = 0x30
        let t = VbType(0x30);
        assert_eq!(t.base_type(), VbType::BYTE);
        assert!(t.is_array());
        assert!(!t.is_byref());
        assert_eq!(format!("{t}"), "Byte()");
    }

    #[test]
    fn test_vb_type_all_base_types() {
        assert_eq!(VbType(0x00).type_name(), "Void");
        assert_eq!(VbType(0x01).type_name(), "Null");
        assert_eq!(VbType(0x02).type_name(), "Integer");
        assert_eq!(VbType(0x04).type_name(), "Single");
        assert_eq!(VbType(0x05).type_name(), "Double");
        assert_eq!(VbType(0x06).type_name(), "Currency");
        assert_eq!(VbType(0x07).type_name(), "Date");
        assert_eq!(VbType(0x0A).type_name(), "Object");
        assert_eq!(VbType(0x0B).type_name(), "Error");
        assert_eq!(VbType(0x0C).type_name(), "Boolean");
        assert_eq!(VbType(0x0D).type_name(), "Variant");
        assert_eq!(VbType(0x0E).type_name(), "Decimal");
        assert_eq!(VbType(0x10).type_name(), "Byte");
        assert_eq!(VbType(0x1D).type_name(), "ExternalCOM");
        assert_eq!(VbType(0x1E).type_name(), "DispatchPtr");
        assert_eq!(VbType(0x1F).type_name(), "Unknown");
    }
}
