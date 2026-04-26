//! Function type descriptor (FuncTypDesc) parser.
//!
//! Describes the prototype of a public VB6 function, including its return
//! type, argument count, property kind, and vtable offset. These descriptors
//! are found via the [`PrivateObjectDescriptor`](super::privateobj::PrivateObjectDescriptor)'s
//! `lpFuncTypDescs` pointer array.
//!
//! # Layout (20 bytes meaningful, padded to 32)
//!
//! | Offset | Size | Field |
//! |--------|------|-------|
//! | 0x00 | 1 | `bArgSize` — encodes arg count (bits 3-7) and property kind (bits 0-2) |
//! | 0x01 | 1 | `bFlags` — bit 0: function has a return type |
//! | 0x02 | 2 | `wVTableOffset` — COM vtable offset; bit 0 is runtime flag (mask off) |
//! | 0x04 | 2 | `iObjectIndex` — signed; -1 (0xFFFF) = no COM object type reference |
//! | 0x06 | 2 | Reserved (always 0) |
//! | 0x08 | 4 | `lpOptionalDefaults` — VA to optional param default values header (see below) |
//! | 0x0C | 2 | `wNameIndex` — method DISPID for IDispatch::GetIDsOfNames resolution |
//! | 0x0E | 1 | `bReturnType` — [`VbType`] byte for the return value |
//! | 0x0F | 1 | `bFuncFlags` — 0x60 for regular Sub/Function, 0x68 for Property |
//! | 0x10 | 4 | `lpParamNames` — VA to parameter name string pointer array |
//! | 0x14 | 12 | Padding (always 0) |
//!
//! # Property Kind Encoding
//!
//! The lowest 3 bits of `bArgSize` encode the property type:
//!
//! | Value | Meaning |
//! |-------|---------|
//! | 0 (`000`) | Regular Sub or Function |
//! | 1 (`001`) | Property Get |
//! | 2 (`010`) | Property Let |
//! | 5 (`101`) | Property Get (variant, observed in native-compiled) |
//! | 7 (`111`) | Property Set |
//!
//! # References
//!
//! - [Gen Digital: Recovery of function prototypes in VB6 executables](https://www.gendigital.com/blog/insights/research/recovery-of-function-prototypes-in-visual-basic-6-executables)
//! - Reverse-engineered from pe\_x86\_vb\_loader sample via BinaryNinja

use std::fmt;

use crate::{
    addressmap::AddressMap,
    error::Error,
    util::{read_cstr, read_u16_le, read_u32_le},
    vb::external::{VarType, VbType},
};

/// Property type encoded in the lowest 3 bits of `arg_size`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyKind {
    /// Not a property (regular Sub/Function).
    None,
    /// Property Get procedure.
    Get,
    /// Property Let procedure.
    Let,
    /// Property Set procedure.
    Set,
    /// Unknown property bits.
    Unknown(u8),
}

impl fmt::Display for PropertyKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => Ok(()),
            Self::Get => write!(f, "Get "),
            Self::Let => write!(f, "Let "),
            Self::Set => write!(f, "Set "),
            Self::Unknown(v) => write!(f, "Prop{v} "),
        }
    }
}

/// View over a function type descriptor (FuncTypDesc).
///
/// Describes a single public function, sub, or property procedure in a
/// VB6 class or form. The structure is always 0x14 bytes of meaningful
/// data (padded to 0x20 with zeros in practice).
///
/// # Example
///
/// For a `Property Get ZipName() As Long`:
/// - `arg_count() == 0`
/// - `property_kind() == PropertyKind::Get`
/// - `has_return_type() == true`
/// - `return_type() == Some(VbType(0x03))` (Long)
#[derive(Clone, Copy, Debug)]
pub struct FuncTypDesc<'a> {
    bytes: &'a [u8],
}

impl<'a> FuncTypDesc<'a> {
    /// Minimum size needed to parse the descriptor.
    pub const MIN_SIZE: usize = 0x14;

    /// Parses a FuncTypDesc from the given byte slice.
    ///
    /// Requires at least 20 bytes (`MIN_SIZE`). Additional padding bytes
    /// beyond offset 0x14 are ignored.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if the slice is too short.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::MIN_SIZE {
            return Err(Error::TooShort {
                expected: Self::MIN_SIZE,
                actual: data.len(),
                context: "FuncTypDesc",
            });
        }
        Ok(Self {
            bytes: data.get(..Self::MIN_SIZE).ok_or(Error::Truncated {
                needed: Self::MIN_SIZE,
                available: data.len(),
            })?,
        })
    }

    /// Raw `arg_size` byte at offset 0x00.
    ///
    /// Encodes both the argument count (bits 3-7) and property kind (bits 0-2).
    #[inline]
    pub fn raw_arg_size(&self) -> u8 {
        self.bytes.first().copied().unwrap_or(0)
    }

    /// Number of explicit arguments (extracted from bits 3-7 of `arg_size`).
    ///
    /// Does not include the implicit return value or `this` pointer.
    #[inline]
    pub fn arg_count(&self) -> u8 {
        self.raw_arg_size() >> 3
    }

    /// Property kind encoded in the lowest 3 bits of `arg_size`.
    pub fn property_kind(&self) -> PropertyKind {
        match self.raw_arg_size() & 0x07 {
            0 => PropertyKind::None,
            1 | 5 => PropertyKind::Get,
            2 => PropertyKind::Let,
            7 => PropertyKind::Set,
            other => PropertyKind::Unknown(other),
        }
    }

    /// Returns `true` if this is a Property (Get/Let/Set) rather than Sub/Function.
    #[inline]
    pub fn is_property(&self) -> bool {
        self.raw_arg_size() & 0x07 != 0
    }

    /// Raw flags byte at offset 0x01.
    ///
    /// | Bit | Mask | Meaning |
    /// |-----|------|---------|
    /// | 0 | 0x01 | Has return type |
    /// | 1 | 0x02 | Has ParamArray (variable argument list) — confirmed in `MarshalDispParamsToNative` |
    /// | 2-7 | 0xFC | Bits 2-7 encode the named argument count (0x3F = none) |
    #[inline]
    pub fn flags(&self) -> u8 {
        self.bytes.get(1).copied().unwrap_or(0)
    }

    /// Returns `true` if this function has a return type.
    ///
    /// When true, [`return_type`](Self::return_type) provides the type.
    /// Functions (not Subs) and Property Get procedures have return types.
    #[inline]
    pub fn has_return_type(&self) -> bool {
        self.flags() & 0x01 != 0
    }

    /// Returns `true` if this function has a ParamArray (variable argument list).
    ///
    /// Confirmed in `MarshalDispParamsToNative` (0x6600f796): when set, one
    /// parameter slot is subtracted from the total argument count to account
    /// for the ParamArray parameter consuming the remaining arguments.
    #[inline]
    pub fn has_param_array(&self) -> bool {
        self.flags() & 0x02 != 0
    }

    /// VTable offset at offset 0x02 (2 bytes, little-endian).
    ///
    /// This is the byte offset into the COM vtable for this method.
    /// Bit 0 is masked off — it indicates "has return type" redundantly
    /// (same as `bFlags` bit 0). Confirmed in `ResolveDispatchToFuncTypDesc`
    /// which reads `*(ftd+2) & 1` to check this flag. The first user method
    /// typically starts at offset 0x1C (after IUnknown + IDispatch = 7 methods).
    #[inline]
    pub fn vtable_offset(&self) -> Result<u16, Error> {
        Ok(read_u16_le(self.bytes, 0x02)? & 0xFFFE)
    }

    /// Object index at offset 0x04 (signed 16-bit).
    ///
    /// -1 (0xFFFF) indicates no COM object type reference. When >= 0, indexes
    /// into the object table for typed object parameters (e.g., a function
    /// returning a specific class type). Always -1 in all tested samples
    /// (104 binaries, 709 objects).
    ///
    /// The runtime copies this field as part of the first 12 bytes during
    /// `ResolveDispatchToFuncTypDesc`, but no consumer was found that
    /// explicitly branches on its value. It may be used by the IDE/debugger
    /// for type resolution or by `ITypeInfo` implementations not in the
    /// runtime hot path.
    #[inline]
    pub fn object_index(&self) -> Result<i16, Error> {
        Ok(read_u16_le(self.bytes, 0x04)? as i16)
    }

    /// VA of optional parameter default values header at offset 0x08.
    ///
    /// Points to an 8-byte header structure used by the runtime's
    /// `OptionalDefaultsNext` (0x660F5FCA) for looking up default values
    /// of optional parameters. **Not** the arg type data (those are inline
    /// at +0x20 — see [`arg_types`](Self::arg_types)).
    ///
    /// # Header Layout (at this VA)
    ///
    /// | Offset | Size | Field |
    /// |--------|------|-------|
    /// | 0x00 | 4 | `dwTotalSize` — bytes in the defaults data area |
    /// | 0x04 | 4 | `lpDefaults` — VA of first default value entry |
    ///
    /// Each default value entry is:
    /// - `u16` VarType code (2=Integer, 3=Long, 8=BSTR, etc.)
    /// - Type-dependent data (BSTR: u16 length + UTF-16LE; others: fixed-size)
    ///
    /// Use [`optional_defaults`](Self::optional_defaults) to parse these.
    #[inline]
    pub fn optional_defaults_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x08)
    }

    /// Method DISPID at offset 0x0C.
    ///
    /// Used by `ResolveDispatchToFuncTypDesc` (0x6600EFC3) in the runtime
    /// for `IDispatch::GetIDsOfNames` resolution. Matches the DISPID that
    /// COM clients use to invoke this method. Observed as a decreasing
    /// index within the object's function type descriptor array.
    #[inline]
    pub fn dispid(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x0C)
    }

    /// Return type as a [`VbType`] at offset 0x0E.
    ///
    /// Only meaningful when [`has_return_type`](Self::has_return_type) is true.
    /// Returns `None` if the function has no return type (i.e., it's a Sub).
    pub fn return_type(&self) -> Option<VbType> {
        if self.has_return_type() {
            self.bytes.get(0x0E).copied().map(VbType)
        } else {
            None
        }
    }

    /// Secondary function flags at offset 0x0F.
    ///
    /// **Not read by the runtime.** Exhaustive search of MSVBVM60.DLL
    /// FuncTypDesc consumers (`ResolveDispatchToFuncTypDesc`, `IDispatchInvoke`,
    /// `MarshalDispParamsToNative`, `BuildFuncTypDescHashTable`,
    /// `LookupFuncTypDescByName`) confirmed none access byte +0x0F. The runtime
    /// only copies the first 12 bytes (3 dwords: +0x00..+0x0B) from FuncTypDesc
    /// into dispatch resolution structures.
    ///
    /// Compiler metadata with the following bit layout:
    ///
    /// | Bit | Mask | Meaning |
    /// |-----|------|---------|
    /// | 3 | 0x08 | Property procedure (Get/Let/Set) |
    /// | 5 | 0x20 | Always set |
    /// | 6 | 0x40 | Always set |
    ///
    /// Observed values: `0x60` for regular Sub/Function, `0x68` for Property.
    #[inline]
    pub fn func_flags(&self) -> u8 {
        self.bytes.get(0x0F).copied().unwrap_or(0)
    }

    /// Returns `true` if `func_flags` bit 3 indicates a property procedure.
    ///
    /// Equivalent to [`is_property`](Self::is_property) but derived from the
    /// secondary flags byte rather than the `bArgSize` encoding.
    #[inline]
    pub fn func_flags_is_property(&self) -> bool {
        self.func_flags() & 0x08 != 0
    }

    /// VA of the parameter name string pointer array at offset 0x10.
    ///
    /// Points to an array of VAs, one per parameter. Each VA points to
    /// a null-terminated ANSI parameter name string.
    #[inline]
    pub fn param_names_va(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x10)
    }

    /// Resolves parameter names from the param names VA array.
    ///
    /// Returns a `Vec` of parameter name byte slices, one per argument.
    /// Names that cannot be resolved (null VA or outside PE) are returned
    /// as empty slices.
    ///
    /// # Arguments
    ///
    /// * `map` - Address map for VA-to-offset resolution.
    pub fn param_names<'b>(&self, map: &AddressMap<'b>) -> Vec<&'b [u8]> {
        let Ok(base) = self.param_names_va() else {
            return Vec::new();
        };
        if base == 0 || self.arg_count() == 0 {
            return Vec::new();
        }
        let count = self.arg_count() as usize;
        let mut names = Vec::with_capacity(count);
        for i in 0..count {
            let ptr_va = base.wrapping_add((i as u32).wrapping_mul(4));
            let name: &'b [u8] = map
                .slice_from_va(ptr_va, 4)
                .ok()
                .and_then(|d| {
                    let name_va = read_u32_le(d, 0).ok()?;
                    if name_va == 0 {
                        return None;
                    }
                    let off = map.va_to_offset(name_va).ok()?;
                    read_cstr(map.file(), off).ok()
                })
                .unwrap_or(b"");
            names.push(name);
        }
        names
    }

    /// Returns the procedure kind keyword for display.
    ///
    /// - `"Sub"` — no return type, not a property
    /// - `"Function"` — has return type, not a property
    /// - `"Property Get"` / `"Property Let"` / `"Property Set"` — property procedures
    pub fn kind_keyword(&self) -> &'static str {
        if self.is_property() {
            match self.property_kind() {
                PropertyKind::Get => "Property Get",
                PropertyKind::Let => "Property Let",
                PropertyKind::Set => "Property Set",
                _ => "Property",
            }
        } else if self.has_return_type() {
            "Function"
        } else {
            "Sub"
        }
    }

    /// Parses argument type information from the inline data at offset 0x20.
    ///
    /// The runtime's `MarshalDispParamsToNative` (0x6600F796) reads type
    /// data from `FuncTypDesc+0x20`, **not** from the `lpArgTypes` VA.
    /// The `lpArgTypes` field (+0x08) is used separately for optional
    /// parameter default value lookup.
    ///
    /// # Inline Arg Type Format (verified via MSVBVM60.DLL disassembly)
    ///
    /// Starting at byte offset 0x20 within the FuncTypDesc data, each
    /// argument is encoded as one or more bytes:
    ///
    /// ```text
    /// byte[0]: type descriptor
    ///   bits 0-4: VbType base code (0x00-0x1F)
    ///   bit 5 (0x20): Array modifier
    ///   bit 6 (0x40): ByRef modifier / extended data
    ///   bit 7 (0x80): Optional argument
    ///
    /// If base type in {0x11(UDT), 0x13(TypedObject), 0x14(TypedArray),
    ///                   0x1C(ExtDecimal), 0x1D(ExternalCOM)}:
    ///   4-byte aligned extra data follows (object ref, UDT descriptor)
    /// ```
    ///
    /// To use this method, the `data` slice passed to [`parse`](Self::parse)
    /// must extend beyond the 0x14-byte minimum — at least `0x20 + arg_count`
    /// bytes are needed. Use [`parse_extended`](Self::parse_extended) to
    /// ensure the slice is large enough.
    ///
    /// Returns a [`Vec<ArgType>`] with one entry per argument.
    ///
    /// Each [`ArgType`] wraps the raw byte and provides `type_name()`,
    /// `is_byref()`, `is_array()`, `is_optional()`, and a `Display` impl
    /// that formats like `"ByRef String()"`.
    ///
    /// Empty if the data doesn't extend to offset 0x20 or there are no arguments.
    pub fn arg_types(&self) -> Vec<ArgType> {
        let count = self.arg_count() as usize;
        if count == 0 {
            return Vec::new();
        }

        // Arg types start at offset 0x20 within the extended FuncTypDesc data
        let Some(data) = self.bytes.get(0x20..) else {
            return Vec::new();
        };
        if data.is_empty() {
            return Vec::new();
        }

        let mut types = Vec::with_capacity(count);
        let mut pos = 0;
        for _ in 0..count {
            let Some(&type_byte) = data.get(pos) else {
                break;
            };
            types.push(ArgType(type_byte));
            pos = pos.saturating_add(calc_arg_type_entry_size(data, pos));
        }
        types
    }

    /// Parses a FuncTypDesc with extended data (0x20 + arg type bytes).
    ///
    /// Unlike [`parse`](Self::parse) which reads only 0x14 bytes, this
    /// reads enough data to include the inline arg type stream at +0x20.
    /// The actual size depends on the arg count and types.
    ///
    /// # Arguments
    ///
    /// * `data` - Byte slice starting at the FuncTypDesc. Should be at
    ///   least `0x24` bytes for proper arg type access.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `data.len() < 0x14`.
    pub fn parse_extended(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::MIN_SIZE {
            return Err(Error::TooShort {
                expected: Self::MIN_SIZE,
                actual: data.len(),
                context: "FuncTypDesc",
            });
        }
        // Keep as much data as available (up to a reasonable max)
        let usable = data.len().min(0x40);
        Ok(Self {
            bytes: data.get(..usable).ok_or(Error::Truncated {
                needed: usable,
                available: data.len(),
            })?,
        })
    }

    /// Parses optional parameter default values from the defaults area.
    ///
    /// The header at [`optional_defaults_va`](Self::optional_defaults_va) contains
    /// a size and VA pointer. Each entry in the defaults area is a u16 VarType
    /// code followed by type-dependent value data.
    ///
    /// Returns a `Vec` of [`OptionalDefault`] entries, one per optional parameter.
    /// Returns empty if `optional_defaults_va` is 0 or if parsing fails.
    pub fn optional_defaults(&self, map: &AddressMap<'_>) -> Vec<OptionalDefault> {
        let Ok(header_va) = self.optional_defaults_va() else {
            return Vec::new();
        };
        if header_va == 0 {
            return Vec::new();
        }

        // Read the 8-byte header: u32 size + u32 va_defaults
        let Ok(hdr) = map.slice_from_va(header_va, 8) else {
            return Vec::new();
        };
        let Ok(total_size) = read_u32_le(hdr, 0) else {
            return Vec::new();
        };
        let total_size = total_size as usize;
        let Ok(defaults_va) = read_u32_le(hdr, 4) else {
            return Vec::new();
        };
        if defaults_va == 0 || total_size == 0 {
            return Vec::new();
        }

        let Ok(data) = map.slice_from_va(defaults_va, total_size) else {
            return Vec::new();
        };

        let mut defaults = Vec::new();
        let mut pos: usize = 0;
        while pos.checked_add(2).is_some_and(|p| p <= data.len()) {
            let Ok(vt_raw) = read_u16_le(data, pos) else {
                break;
            };
            let vt = VarType::from_raw(vt_raw).unwrap_or(VarType::Empty);
            let data_size = vt.data_size();
            let Some(value_start) = pos.checked_add(2) else {
                break;
            };

            if vt == VarType::Bstr {
                // BSTR: u16 type + u16 byte_length + UTF-16LE data
                let Some(after_len) = value_start.checked_add(2) else {
                    break;
                };
                if after_len > data.len() {
                    break;
                }
                let Ok(byte_len_raw) = read_u16_le(data, value_start) else {
                    break;
                };
                let byte_len = byte_len_raw as usize;
                let str_start = after_len;
                let str_end = str_start.saturating_add(byte_len).min(data.len());
                let Some(str_bytes) = data.get(str_start..str_end) else {
                    break;
                };
                let text = String::from_utf16_lossy(
                    &str_bytes
                        .chunks_exact(2)
                        .filter_map(|c| <[u8; 2]>::try_from(c).ok())
                        .map(u16::from_le_bytes)
                        .collect::<Vec<_>>(),
                );
                defaults.push(OptionalDefault {
                    vt,
                    vt_raw,
                    value: DefaultValue::String(text),
                });
                // Advance: u16 type(2) + u16 byte_length(2) + aligned string data
                let aligned_len = byte_len.saturating_add(1) & !1;
                let Some(next) = after_len.checked_add(aligned_len) else {
                    break;
                };
                pos = next;
            } else if data_size > 0 {
                let val_end = value_start.saturating_add(data_size).min(data.len());
                let Some(val_bytes) = data.get(value_start..val_end) else {
                    break;
                };
                let value = match vt {
                    VarType::I2 | VarType::Bool | VarType::I1 | VarType::Ui1 | VarType::Ui2 => {
                        if val_bytes.len() >= 2 {
                            match read_u16_le(val_bytes, 0) {
                                Ok(v) => DefaultValue::Integer(i64::from(v as i16)),
                                Err(_) => DefaultValue::Raw(val_bytes.to_vec()),
                            }
                        } else {
                            DefaultValue::Raw(val_bytes.to_vec())
                        }
                    }
                    VarType::I4
                    | VarType::Dispatch
                    | VarType::Unknown
                    | VarType::R4
                    | VarType::Record
                    | VarType::Int
                    | VarType::Uint => {
                        if val_bytes.len() >= 4 {
                            match read_u32_le(val_bytes, 0) {
                                Ok(v) => DefaultValue::Integer(i64::from(v as i32)),
                                Err(_) => DefaultValue::Raw(val_bytes.to_vec()),
                            }
                        } else {
                            DefaultValue::Raw(val_bytes.to_vec())
                        }
                    }
                    _ => DefaultValue::Raw(val_bytes.to_vec()),
                };
                defaults.push(OptionalDefault { vt, vt_raw, value });
                let Some(next) = value_start.checked_add(data_size) else {
                    break;
                };
                pos = next;
            } else {
                // Zero-size types (Empty, Null, Variant)
                defaults.push(OptionalDefault {
                    vt,
                    vt_raw,
                    value: DefaultValue::Empty,
                });
                pos = value_start;
            }
        }
        defaults
    }
}

/// A parsed optional parameter default value.
#[derive(Debug, Clone)]
pub struct OptionalDefault {
    /// VARIANT type code.
    pub vt: VarType,
    /// Raw VarType code (preserved for unknown types).
    pub vt_raw: u16,
    /// The default value.
    pub value: DefaultValue,
}

/// The actual default value data.
#[derive(Debug, Clone)]
pub enum DefaultValue {
    /// No value (VT_EMPTY, VT_NULL, VT_VARIANT).
    Empty,
    /// Integer value (VT_I2, VT_I4, VT_BOOL, etc.).
    Integer(i64),
    /// String value (VT_BSTR).
    String(String),
    /// Raw bytes for types we don't decode inline.
    Raw(Vec<u8>),
}

impl fmt::Display for OptionalDefault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.value {
            DefaultValue::Empty => write!(f, "Empty"),
            DefaultValue::Integer(v) => {
                if self.vt == VarType::Bool {
                    write!(f, "{}", if *v != 0 { "True" } else { "False" })
                } else {
                    write!(f, "{v}")
                }
            }
            DefaultValue::String(s) => write!(f, "\"{s}\""),
            DefaultValue::Raw(b) => {
                write!(
                    f,
                    "0x{}",
                    b.iter().map(|x| format!("{x:02X}")).collect::<String>()
                )
            }
        }
    }
}

/// Computes the byte size of a single entry in the lpArgTypes stream.
///
/// Mirrors the logic of `CalcArgTypeEntrySize` (0x66009D34) in MSVBVM60.DLL.
///
/// Most entries are 1 byte. Types with base codes 0x11, 0x13, 0x14, 0x1C,
/// or 0x1D include 4-byte aligned extra data (e.g., object reference or
/// UDT descriptor pointer).
fn calc_arg_type_entry_size(data: &[u8], pos: usize) -> usize {
    let Some(&type_byte) = data.get(pos) else {
        return 1;
    };
    let base = type_byte & 0x1F;

    // Base size: 1 byte for the type descriptor
    let base_size: usize = 1;

    // Types that carry 4-byte aligned extra data
    match base {
        0x11 | 0x13 | 0x14 | 0x1C | 0x1D => {
            // Align (pos + base_size) up to 4-byte boundary, then add 4
            let after_type = pos.saturating_add(base_size);
            let aligned = after_type.saturating_add(3) & !3;
            aligned.saturating_sub(pos).saturating_add(4)
        }
        _ => base_size,
    }
}

/// Inline argument type byte from FuncTypDesc+0x20.
///
/// **Uses a DIFFERENT numbering than [`VbType`] (which is for return types).**
///
/// Mapping verified from the lookup table at `0x6600FC48` in MSVBVM60.DLL,
/// used by `sub_6600fbff` to convert arg types to COM VARIANT type codes
/// for `IDispatch::Invoke` parameter marshalling.
///
/// # Encoding
///
/// ```text
/// bits 0-4: base type code (see type_name())
/// bit 5 (0x20): ByRef modifier (→ VT_BYREF in COM)
/// bit 6 (0x40): Array modifier (→ VT_ARRAY in COM)
/// bit 7 (0x80): Optional parameter
/// ```
///
/// Note: modifier bits are DIFFERENT from VbType (which has 0x20=Array, 0x40=ByRef).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArgType(pub u8);

impl ArgType {
    /// Void / Empty (0x00). Maps to VT_NULL.
    pub const VOID: u8 = 0x00;
    /// Boolean (0x03). Maps to VT_BOOL.
    pub const BOOLEAN: u8 = 0x03;
    /// Signed byte (0x04). Maps to VT_I1.
    pub const SBYTE: u8 = 0x04;
    /// Unsigned byte (0x05). Maps to VT_UI1.
    pub const BYTE: u8 = 0x05;
    /// 16-bit integer (0x06). Maps to VT_I2.
    pub const INTEGER: u8 = 0x06;
    /// Unsigned 16-bit (0x07). Maps to VT_UI2.
    pub const USHORT: u8 = 0x07;
    /// 32-bit integer (0x08). Maps to VT_I4.
    pub const LONG: u8 = 0x08;
    /// Unsigned 32-bit (0x09). Maps to VT_UI4.
    pub const ULONG: u8 = 0x09;
    /// Single-precision float (0x0A). Maps to VT_R4.
    pub const SINGLE: u8 = 0x0A;
    /// Double-precision float (0x0B). Maps to VT_R8.
    pub const DOUBLE: u8 = 0x0B;
    /// Date (0x0C). Maps to VT_DATE.
    pub const DATE: u8 = 0x0C;
    /// Currency (0x0D). Maps to VT_CY.
    pub const CURRENCY: u8 = 0x0D;
    /// Decimal (0x0E). Maps to VT_DECIMAL.
    pub const DECIMAL: u8 = 0x0E;
    /// Variant (0x0F). Maps to VT_VARIANT.
    pub const VARIANT: u8 = 0x0F;
    /// String / BSTR (0x10). Maps to VT_BSTR. **Not 0x08 like VbType!**
    pub const STRING: u8 = 0x10;
    /// User Defined Type (0x11). Followed by extra data.
    pub const UDT: u8 = 0x11;
    /// Object / IDispatch (0x13). Maps to VT_DISPATCH.
    pub const OBJECT: u8 = 0x13;
    /// Record (0x14). Maps to VT_RECORD.
    pub const RECORD: u8 = 0x14;
    /// Dispatch pointer (0x1E). Internal VB type for ByVal object/string refs.
    pub const DISPATCH_PTR: u8 = 0x1E;

    /// ByRef modifier (bit 5). Parameter passed by reference.
    pub const BYREF: u8 = 0x20;
    /// Array modifier (bit 6). Parameter is an array.
    pub const ARRAY: u8 = 0x40;
    /// Optional modifier (bit 7). Parameter has a default value.
    pub const OPTIONAL: u8 = 0x80;

    /// Returns the base type code (bits 0-4).
    #[inline]
    pub fn base_type(self) -> u8 {
        self.0 & 0x1F
    }

    /// Returns `true` if this is a ByRef parameter (bit 5).
    #[inline]
    pub fn is_byref(self) -> bool {
        self.0 & Self::BYREF != 0
    }

    /// Returns `true` if this is an array type (bit 6).
    #[inline]
    pub fn is_array(self) -> bool {
        self.0 & Self::ARRAY != 0
    }

    /// Returns `true` if this is an optional parameter (bit 7).
    #[inline]
    pub fn is_optional(self) -> bool {
        self.0 & Self::OPTIONAL != 0
    }

    /// Returns the VB6 type name for the base type.
    pub fn type_name(self) -> &'static str {
        match self.base_type() {
            0x00 | 0x01 => "Void",
            0x02 => "void",
            Self::BOOLEAN => "Boolean",
            Self::SBYTE => "SByte",
            Self::BYTE => "Byte",
            Self::INTEGER => "Integer",
            Self::USHORT => "UShort",
            Self::LONG | 0x1A => "Long",
            Self::ULONG => "ULong",
            Self::SINGLE => "Single",
            Self::DOUBLE => "Double",
            Self::DATE => "Date",
            Self::CURRENCY => "Currency",
            Self::DECIMAL => "Decimal",
            Self::VARIANT => "Variant",
            Self::STRING => "String",
            Self::UDT => "UDT",
            Self::OBJECT | 0x1B | 0x1D => "Object",
            Self::RECORD => "Record",
            0x16 => "IDispatch",
            0x1C => "IUnknown",
            Self::DISPATCH_PTR => "DispPtr",
            _ => "Unknown",
        }
    }
}

impl fmt::Display for ArgType {
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

#[cfg(test)]
mod tests {
    use super::*;

    // Real data from Cls_Zip entry[0]: Function with 1 arg, returns Long
    // AddFile(ByRef Data() As ...) As Long
    const ZIP_FUNC0: [u8; 0x14] = [
        0x08, 0x01, 0x1D, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x03,
        0x60, 0x74, 0x55, 0x40, 0x00,
    ];

    // Real data from Cls_Zip entry[2]: Function with 3 args, returns Long
    const ZIP_FUNC2: [u8; 0x14] = [
        0x18, 0x01, 0x25, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x18, 0x56, 0x40, 0x00, 0x12, 0x00, 0x03,
        0x60, 0x6C, 0x56, 0x40, 0x00,
    ];

    // Real data from Cls_Zip entry[5]: Property Get with 1 arg, returns Long
    const ZIP_PROP_GET: [u8; 0x14] = [
        0x09, 0x01, 0x31, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0D, 0x00, 0x03,
        0x68, 0x7C, 0x55, 0x40, 0x00,
    ];

    // Real data from Cls_CRC32 entry[0]: Sub with 0 args, no return
    const CRC32_SUB: [u8; 0x14] = [
        0x00, 0x00, 0x1D, 0x00, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x03,
        0x60, 0x44, 0x55, 0x40, 0x00,
    ];

    #[test]
    fn test_function_with_one_arg() {
        let ftd = FuncTypDesc::parse(&ZIP_FUNC0).unwrap();
        assert_eq!(ftd.arg_count(), 1);
        assert_eq!(ftd.property_kind(), PropertyKind::None);
        assert!(ftd.has_return_type());
        assert_eq!(ftd.return_type(), Some(VbType(0x03))); // Long
        assert_eq!(ftd.vtable_offset().unwrap(), 0x001C);
        assert_eq!(ftd.object_index().unwrap(), -1);
        assert_eq!(ftd.optional_defaults_va().unwrap(), 0);
        assert_eq!(ftd.param_names_va().unwrap(), 0x00405574);
        assert_eq!(ftd.kind_keyword(), "Function");
    }

    #[test]
    fn test_function_with_three_args() {
        let ftd = FuncTypDesc::parse(&ZIP_FUNC2).unwrap();
        assert_eq!(ftd.arg_count(), 3);
        assert_eq!(ftd.property_kind(), PropertyKind::None);
        assert!(ftd.has_return_type());
        assert_eq!(ftd.return_type(), Some(VbType(0x03)));
        assert_eq!(ftd.vtable_offset().unwrap(), 0x0024);
        assert!(ftd.optional_defaults_va().unwrap() != 0); // Has optional defaults header
        assert_eq!(ftd.kind_keyword(), "Function");
    }

    #[test]
    fn test_property_get() {
        let ftd = FuncTypDesc::parse(&ZIP_PROP_GET).unwrap();
        assert_eq!(ftd.arg_count(), 1);
        assert_eq!(ftd.property_kind(), PropertyKind::Get);
        assert!(ftd.is_property());
        assert!(ftd.has_return_type());
        assert_eq!(ftd.return_type(), Some(VbType(0x03)));
        assert_eq!(ftd.vtable_offset().unwrap(), 0x0030);
        assert_eq!(ftd.func_flags(), 0x68); // Property flag
        assert_eq!(ftd.kind_keyword(), "Property Get");
    }

    #[test]
    fn test_sub_no_args() {
        let ftd = FuncTypDesc::parse(&CRC32_SUB).unwrap();
        assert_eq!(ftd.arg_count(), 0);
        assert_eq!(ftd.property_kind(), PropertyKind::None);
        assert!(!ftd.has_return_type());
        assert_eq!(ftd.return_type(), None);
        assert_eq!(ftd.kind_keyword(), "Sub");
    }

    #[test]
    fn test_parse_too_short() {
        let short = [0u8; 0x13];
        assert!(FuncTypDesc::parse(&short).is_err());
    }

    #[test]
    fn test_vtable_offset_masks_runtime_bit() {
        // vtable_offset raw = 0x001D, masked = 0x001C
        let ftd = FuncTypDesc::parse(&ZIP_FUNC0).unwrap();
        assert_eq!(ftd.vtable_offset().unwrap(), 0x001C);
    }

    #[test]
    fn test_arg_type_names() {
        // Arg type encoding is DIFFERENT from VbType
        assert_eq!(ArgType(0x10).type_name(), "String"); // NOT Byte!
        assert_eq!(ArgType(0x08).type_name(), "Long"); // NOT String!
        assert_eq!(ArgType(0x06).type_name(), "Integer");
        assert_eq!(ArgType(0x03).type_name(), "Boolean");
        assert_eq!(ArgType(0x0A).type_name(), "Single");
        assert_eq!(ArgType(0x0B).type_name(), "Double");
        assert_eq!(ArgType(0x0F).type_name(), "Variant");
        assert_eq!(ArgType(0x13).type_name(), "Object");
        assert_eq!(ArgType(0x1E).type_name(), "DispPtr");
    }

    #[test]
    fn test_arg_type_display() {
        assert_eq!(format!("{}", ArgType(0x1E)), "DispPtr");
        assert_eq!(format!("{}", ArgType(0x10)), "String");
        assert_eq!(format!("{}", ArgType(0x30)), "ByRef String");
        assert_eq!(format!("{}", ArgType(0x50)), "String()");
        assert_eq!(format!("{}", ArgType(0x70)), "ByRef String()");
        assert_eq!(format!("{}", ArgType(0x90)), "Optional String");
    }

    #[test]
    fn test_arg_type_modifiers() {
        let t = ArgType(0x70); // ByRef + Array + String
        assert!(t.is_byref());
        assert!(t.is_array());
        assert!(!t.is_optional());
        assert_eq!(t.base_type(), ArgType::STRING);

        let t = ArgType(0x90); // Optional + String
        assert!(t.is_optional());
        assert!(!t.is_byref());
        assert!(!t.is_array());
    }
}
