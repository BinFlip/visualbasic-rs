//! VB6 form property stream decoder.
//!
//! Decodes the property opcode+value streams in form binary data.
//! Each property is looked up by control type and opcode index in
//! build-time generated tables from `data/vb6_control_properties.csv`.
//!
//! The serialization format is determined by the descriptor flags in
//! MSVBVM60.DLL, traced through the compiler's `WritePropertyStream`
//! function (VB6.EXE `sub_457E57`).

use core::fmt;

use crate::{
    VbProject,
    util::{read_i16_le, read_u16_le, read_u32_le},
    vb::formdata::FormControlType,
    vb::guitable::GuiObjectType,
};

/// Magic value at the start of every StdDataFormat persistence blob.
///
/// This is the first DWORD of the StdDataFormat CLSID
/// `{6B263850-900B-11D0-9484-00A0C91110ED}`, written verbatim as the
/// header signature.
const STD_DATA_FORMAT_MAGIC: u32 = 0x6B263850;

/// VB6 data format type constants (`DataFormatTypeConstants`).
///
/// Determines how the StdDataFormat object applies formatting to
/// data-bound control values. Maps to the `Type` property of the
/// `StdDataFormat` COM object from MSSTDFMT.DLL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFormatType {
    /// General format — no special formatting applied.
    General = 0,
    /// Number format — uses the format string for numeric display.
    Number = 1,
    /// Currency format.
    Currency = 2,
    /// Short date format.
    ShortDate = 3,
    /// Long date format.
    LongDate = 4,
    /// Custom format — fully user-defined via the format string.
    /// When this type is active, TrueValue/FalseValue/NullValue
    /// VARIANT entries are also serialized.
    Custom = 5,
}

impl DataFormatType {
    /// Converts a raw u32 to a `DataFormatType`.
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            0 => Some(Self::General),
            1 => Some(Self::Number),
            2 => Some(Self::Currency),
            3 => Some(Self::ShortDate),
            4 => Some(Self::LongDate),
            5 => Some(Self::Custom),
            _ => None,
        }
    }
}

impl fmt::Display for DataFormatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::General => write!(f, "General"),
            Self::Number => write!(f, "Number"),
            Self::Currency => write!(f, "Currency"),
            Self::ShortDate => write!(f, "ShortDate"),
            Self::LongDate => write!(f, "LongDate"),
            Self::Custom => write!(f, "Custom"),
        }
    }
}

/// Decoded StdDataFormat COM object from a form binary property stream.
///
/// The VB6 compiler serializes `DataFormat` properties (ser_type 0x16)
/// by calling `IPersistStream::Save` (IID `{00000109-...}`) on the
/// StdDataFormat COM object from MSSTDFMT.DLL.
///
/// # Binary Layout (reverse engineered from MSSTDFMT.DLL v6.01.9839)
///
/// The persistence format was traced through the COM delegation chain:
/// `IPersistStream::Save` thunk → `StdDataFormat_PersistSave_Wrapper`
/// → main vtable dispatch → `StdDataFormat_SaveToStream` (0x24dd240c).
///
/// ```text
/// HEADER (0x28 = 40 bytes):
///   +0x00  u32  magic           = 0x6B263850 (CLSID first DWORD, "P8&k")
///   +0x04  u32  version         = 0x60000 | 0x60001 | 0x60002
///   +0x08  u32  format_type     = DataFormatTypeConstants (0-5)
///   +0x0C  u32  reserved1       = 0 (zeroed by constructor)
///   +0x10  u32  reserved2       = 0
///   +0x14  u32  fmt_str_len     = format string length (UTF-16 chars)
///   +0x18  u32  has_custom      = 0 or 1 (1 only when type==Custom)
///   +0x1C  u32  true_val_len    = TrueValue BSTR char count
///   +0x20  u32  false_val_len   = FalseValue BSTR char count
///   +0x24  u32  null_val_len    = NullValue BSTR char count
///
/// FORMAT STRING (variable):
///   [fmt_str_len * 2 bytes]     UTF-16LE format string (e.g., "##,###.00")
///
/// CUSTOM VALUES (only when has_custom != 0):
///   For TrueValue, FalseValue, NullValue:
///     [16 bytes]                VARIANT header (VT at byte 0)
///     If VT == 8 (VT_BSTR):    [len * 2 bytes] BSTR character data
///
/// TRAILER (version-dependent):
///   If version >= 0x60001:      [4 bytes] u32 FirstDayOfWeek
///   If version >= 0x60002:      [4 bytes] u32 FirstWeekOfYear
/// ```
///
/// # Version History
///
/// - `0x60000`: Original format — header + format string + custom values only.
/// - `0x60001`: Adds FirstDayOfWeek trailer field.
/// - `0x60002`: Adds FirstWeekOfYear trailer field (current/most common).
#[derive(Debug, Clone)]
pub struct StdDataFormat {
    /// Persistence format version (0x60000, 0x60001, or 0x60002).
    pub version: u32,
    /// Format type determining how data-bound values are displayed.
    pub format_type: DataFormatType,
    /// Format string (e.g., `"##,###.00"` for Number, `"yyyy-mm-dd"` for dates).
    /// Empty for General type or when no custom format string is set.
    pub format: String,
    /// Whether custom TrueValue/FalseValue/NullValue entries are present.
    /// Only true when `format_type == Custom`.
    pub has_custom_values: bool,
    /// FirstDayOfWeek setting. Present when version >= 0x60001.
    /// Maps to VB6 `vbDayOfWeek` constants (0=system, 1=Sunday..7=Saturday).
    pub first_day_of_week: Option<u32>,
    /// FirstWeekOfYear setting. Present when version >= 0x60002.
    /// Maps to VB6 `vbFirstWeekOfYear` constants.
    pub first_week_of_year: Option<u32>,
    /// Total blob size in bytes consumed from the property stream.
    pub blob_size: u32,
}

/// Property value type encoding for the form binary format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropType {
    /// 1-byte value (booleans, enums, flags).
    Byte,
    /// 2-byte signed integer.
    Int16,
    /// 4-byte value (Long, Color, Single).
    Long,
    /// Variable-length ASCII string: `[u16_le byte_length][string + null]`.
    Str,
    /// Variable-length UTF-16 string (Tag/Connect encoding): `[u16_le char_count][char_count * 2 bytes UTF-16LE]`.
    ///
    /// Used by properties with serialization type 0x0D (Tag, Connect, DatabaseName,
    /// RecordSource). Written by compiler `sub_427270` which calls
    /// `SysStringLen` then writes `char_count(2) + data(char_count * 2)`.
    /// No null terminator.
    TagStr,
    /// 16-byte ControlSize: 8 x i16 (ClientLeft/Top/Width/Height + unused).
    Size16,
    /// 11-byte font descriptor.
    Font,
    /// Picture: 4-byte size then data. `0xFFFFFFFF` = default.
    Picture,
    /// Two consecutive Long values (8 bytes): Left + Top callback pair.
    ///
    /// When a child control's Left property has the callback bit (B2 bit 1)
    /// set, the compiler writes 4 bytes of Left value followed by 4 bytes
    /// of Top value from the callback. This encodes position as 8 bytes.
    LongPair,
    /// StdDataFormat COM object serialized via IPersistStream::Save.
    ///
    /// The compiler (VB6.EXE `WritePropertyStream` case 0x16) calls
    /// `IPersistStream::Save(stream, FALSE)` on the StdDataFormat object
    /// from MSSTDFMT.DLL. The persistence format is:
    ///
    /// - 0x28-byte header: magic(4) + version(4) + type(4) + reserved(8) +
    ///   fmt_str_len(4) + has_custom(4) + 3x custom_len(12)
    /// - Format string: `fmt_str_len * 2` bytes UTF-16LE
    /// - If has_custom: 3x VARIANT entries (0x10 each) + optional BSTRs
    /// - Trailer: `first_day_of_week(4)` (if version >= 0x60001) +
    ///   `first_week_of_year(4)` (if version >= 0x60002)
    ///
    /// Reverse engineered from `StdDataFormat_SaveToStream` and
    /// `StdDataFormat_LoadFromStream` in MSSTDFMT.DLL v6.01.9839.
    DataFormat,
    /// Flag-only: opcode is emitted with NO value data following.
    ///
    /// Used for font sub-properties (FontSize, FontBold, FontItalic,
    /// FontStrikethru, FontUnderline) where the descriptor flags have
    /// bits 16-17 both clear. The opcode marks the property as non-default,
    /// but the actual value is embedded in the Font blob (PropType::Font).
    /// Discovered via compiler tracing: `sub_457E57` in VB6.EXE checks
    /// `(flags & 0x10000) != 0 || (flags & 0x20000) != 0` before retrieving
    /// and writing a value. When both bits are clear, only the opcode byte
    /// is written to the stream.
    Flag,
}

impl PropType {
    /// Returns the fixed byte size, or `None` for variable-length types.
    pub fn fixed_size(&self) -> Option<usize> {
        match self {
            Self::Flag => Some(0),
            Self::Byte => Some(1),
            Self::LongPair => Some(8), // Left + Top callback
            Self::Int16 => Some(2),
            Self::Long => Some(4),
            Self::Size16 => Some(16),
            Self::Font => None,       // 11 base + variable nameLen callback
            Self::DataFormat => None, // StdDataFormat IPersistStream blob
            Self::Str | Self::TagStr | Self::Picture => None,
        }
    }
}

/// Returns the property name and type for a form binary property opcode.
///
/// Property opcodes are **context-dependent** — the same index means different
/// properties for different control types.
///
/// Returns `None` for unknown opcodes.
///
/// Source: `data/vb6_control_properties.csv`, verified against MSVBVM60.DLL descriptor tables.
/// All 22 control types (1038 entries) traced from runtime property pointer tables.
pub fn property_info(ctype: FormControlType, opcode: u8) -> Option<(&'static str, PropType)> {
    generated::lookup_property(ctype.to_u8(), opcode).map(|desc| (desc.name, desc.prop_type))
}

/// Returns the full property descriptor for a form binary property opcode.
///
/// Unlike [`property_info`] which returns only `(name, PropType)`, this
/// provides the serialization type and callback byte count from the
/// MSVBVM60.DLL descriptor metadata.
pub fn property_descriptor(
    ctype: FormControlType,
    opcode: u8,
) -> Option<&'static generated::PropertyDesc> {
    generated::lookup_property(ctype.to_u8(), opcode)
}

/// Control position pair (Left + Top) from callback data.
///
/// When a child control's Left property has the callback bit (B2 bit 1)
/// set in the descriptor flags, the compiler writes 4 bytes of Left
/// followed by 4 bytes of Top from the `vtable+0x34` callback.
///
/// # Binary Layout (8 bytes)
///
/// ```text
/// +0x00  u32  left   Twips coordinate
/// +0x04  u32  top    Twips coordinate
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControlPosition {
    /// Left coordinate in twips.
    pub left: u32,
    /// Top coordinate in twips.
    pub top: u32,
}

impl ControlPosition {
    /// Parses a position pair from raw bytes.
    /// Returns the parsed value and bytes consumed, or `None` if too short.
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 8 {
            return None;
        }
        Some((
            Self {
                left: read_u32_le(data, 0),
                top: read_u32_le(data, 4),
            },
            8,
        ))
    }
}

impl fmt::Display for ControlPosition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{},{}", self.left, self.top)
    }
}

/// Client area rectangle from callback data (ClientLeft/Top/Width/Height).
///
/// Written by the form's `vtable+0x34` callback when the ClientLeft
/// descriptor has 12 callback bytes (B2 bit 1 set, 12B trailing data).
///
/// # Binary Layout (16 bytes)
///
/// ```text
/// +0x00  u32  left    Client area left in twips
/// +0x04  u32  top     Client area top in twips (from callback)
/// +0x08  u32  width   Client area width in twips (from callback)
/// +0x0C  u32  height  Client area height in twips (from callback)
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientRect {
    /// Client area left in twips.
    pub left: u32,
    /// Client area top in twips.
    pub top: u32,
    /// Client area width in twips.
    pub width: u32,
    /// Client area height in twips.
    pub height: u32,
}

impl ClientRect {
    /// Parses a client rectangle from raw bytes.
    /// Returns the parsed value and bytes consumed, or `None` if too short.
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 16 {
            return None;
        }
        Some((
            Self {
                left: read_u32_le(data, 0),
                top: read_u32_le(data, 4),
                width: read_u32_le(data, 8),
                height: read_u32_le(data, 12),
            },
            16,
        ))
    }
}

impl fmt::Display for ClientRect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{},{},{},{}",
            self.left, self.top, self.width, self.height
        )
    }
}

/// Font descriptor from a form binary property stream.
///
/// The VB6 compiler writes font properties as an 11-byte fixed header
/// followed by a variable-length ASCII font name (from the `vtable+0x34`
/// callback, where the name length is byte 10 of the header).
///
/// # Binary Layout (11 + name_len bytes)
///
/// ```text
/// +0x00  u16  charset         Font character set
/// +0x02  u8   pitch_family    Pitch and font family
/// +0x03  u8   flags           Font flags (italic=0x02, underline=0x04, strikeout=0x08)
/// +0x04  u16  weight          Font weight (400=Normal, 700=Bold)
/// +0x06  u32  size_raw        Font size in 1/10000 pt units
/// +0x0A  u8   name_len        Length of trailing font name (ASCII, no null)
/// +0x0B  [name_len bytes]     Font family name (e.g., "MS Sans Serif")
/// ```
#[derive(Debug, Clone)]
pub struct FontDescriptor {
    /// Font size in points (raw value / 10000).
    pub size_pt: u32,
    /// Whether the font is bold (weight >= 700).
    pub bold: bool,
    /// Font weight (400=Normal, 700=Bold, etc.).
    pub weight: u16,
    /// Font family name (e.g., "MS Sans Serif").
    pub name: String,
}

impl FontDescriptor {
    /// Parses a font descriptor from raw bytes.
    /// Returns the parsed value and bytes consumed, or `None` if too short.
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 11 {
            return None;
        }
        let weight = read_u16_le(data, 4);
        let raw_size = read_u32_le(data, 6);
        let name_len = data[10] as usize;
        let mut consumed = 11;
        let name = if name_len > 0 && consumed + name_len <= data.len() {
            let s = String::from_utf8_lossy(&data[consumed..consumed + name_len]).into_owned();
            consumed += name_len;
            s
        } else {
            String::new()
        };
        Some((
            Self {
                size_pt: raw_size / 10000,
                bold: weight >= 700,
                weight,
                name,
            },
            consumed,
        ))
    }
}

impl fmt::Display for FontDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = if self.bold { " Bold" } else { "" };
        write!(f, "({}pt{b}, \"{}\")", self.size_pt, self.name)
    }
}

/// Embedded picture/icon data from a form binary property stream.
///
/// Pictures are serialized with a 4-byte size prefix. The size field
/// includes all overhead (OLE type header + inner data). A sentinel
/// value of `0xFFFFFFFF` indicates the default picture.
///
/// # Binary Layout
///
/// ```text
/// +0x00  u32  size   Total picture data size (or 0xFFFFFFFF for default)
/// +0x04  [size bytes] Picture data (OLE header + BMP/ICO/etc.)
/// ```
#[derive(Debug, Clone)]
pub struct PictureData {
    /// Total picture data size in bytes.
    pub size: u32,
    /// Whether the picture contains a BMP ("BM" magic at offset +8).
    pub is_bmp: bool,
    /// Whether this is the default picture sentinel (0xFFFFFFFF).
    pub is_default: bool,
}

impl PictureData {
    /// Parses picture data from raw bytes.
    /// Returns the parsed value and bytes consumed, or `None` if too short.
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 4 {
            return None;
        }
        let size = read_u32_le(data, 0);
        if size == 0xFFFFFFFF {
            return Some((
                Self {
                    size: 0,
                    is_bmp: false,
                    is_default: true,
                },
                4,
            ));
        }
        let total = size as usize;
        if 4 + total > data.len() {
            return None;
        }
        let bmp_off = 4 + 8; // OLE header is 8 bytes, BMP magic at data start
        let is_bmp = bmp_off + 1 < data.len() && data[bmp_off] == b'B' && data[bmp_off + 1] == b'M';
        Some((
            Self {
                size,
                is_bmp,
                is_default: false,
            },
            4 + total,
        ))
    }
}

impl fmt::Display for PictureData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_default {
            write!(f, "default")
        } else if self.is_bmp {
            write!(f, "(BMP, {}B)", self.size)
        } else {
            write!(f, "({}B)", self.size)
        }
    }
}

impl StdDataFormat {
    /// Parses a StdDataFormat IPersistStream blob from raw bytes.
    /// Returns the parsed value and bytes consumed, or `None` if invalid.
    pub fn parse(data: &[u8]) -> Option<(Self, usize)> {
        if data.len() < 0x28 {
            return None;
        }
        if read_u32_le(data, 0) != STD_DATA_FORMAT_MAGIC {
            return None;
        }
        let version = read_u32_le(data, 4);
        let format_type = read_u32_le(data, 8);
        let fmt_str_len = read_u32_le(data, 0x14) as usize;
        let has_custom = read_u32_le(data, 0x18);
        let true_val_len = read_u32_le(data, 0x1C) as usize;
        let false_val_len = read_u32_le(data, 0x20) as usize;
        let null_val_len = read_u32_le(data, 0x24) as usize;

        let mut off = 0x28;

        // Format string (UTF-16LE)
        let fmt_byte_len = fmt_str_len * 2;
        let format = if fmt_str_len > 0 && off + fmt_byte_len <= data.len() {
            let utf16: Vec<u16> = (0..fmt_str_len)
                .map(|j| read_u16_le(data, off + j * 2))
                .collect();
            off += fmt_byte_len;
            String::from_utf16_lossy(&utf16)
        } else {
            off += fmt_byte_len;
            String::new()
        };

        // Custom values (3x VARIANT + optional BSTRs)
        if has_custom != 0 {
            off += 0x10 + true_val_len * 2; // TrueValue
            off += 0x10 + false_val_len * 2; // FalseValue
            off += 0x10 + null_val_len * 2; // NullValue
        }

        // Trailer (version-dependent)
        let first_day_of_week = if version >= 0x60001 && off + 4 <= data.len() {
            let v = read_u32_le(data, off);
            off += 4;
            Some(v)
        } else {
            None
        };
        let first_week_of_year = if version >= 0x60002 && off + 4 <= data.len() {
            let v = read_u32_le(data, off);
            off += 4;
            Some(v)
        } else {
            None
        };

        Some((
            Self {
                version,
                format_type: DataFormatType::from_u32(format_type)
                    .unwrap_or(DataFormatType::General),
                format,
                has_custom_values: has_custom != 0,
                first_day_of_week,
                first_week_of_year,
                blob_size: off as u32,
            },
            off,
        ))
    }
}

impl fmt::Display for StdDataFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.format.is_empty() {
            write!(f, "({}, {}B)", self.format_type, self.blob_size)
        } else {
            write!(
                f,
                "({}, \"{}\", {}B)",
                self.format_type, self.format, self.blob_size
            )
        }
    }
}

/// Parses a VB6 ASCII string from a property stream.
///
/// Format: `[u16_le byte_length][string_bytes][null_terminator]`.
/// Used by ser_types 1, 18, 26, and 33 (Name, String, DataMember).
fn parse_ascii_str(data: &[u8]) -> Option<(String, usize)> {
    if data.len() < 2 {
        return None;
    }
    let len = read_u16_le(data, 0) as usize;
    if 2 + len >= data.len() {
        return None;
    }
    let s = String::from_utf8_lossy(&data[2..2 + len]).into_owned();
    Some((s, 2 + len + 1)) // +1 null terminator
}

/// Parses a VB6 UTF-16LE string from a property stream.
///
/// Format: `[u16_le char_count][char_count * 2 bytes UTF-16LE]`.
/// Written by compiler `sub_427270`. No null terminator.
/// Used by ser_type 13 (Tag, Connect, DatabaseName, RecordSource).
fn parse_utf16_str(data: &[u8]) -> Option<(String, usize)> {
    if data.len() < 2 {
        return None;
    }
    let char_count = read_u16_le(data, 0) as usize;
    let byte_len = char_count * 2;
    if 2 + byte_len > data.len() {
        return None;
    }
    let utf16: Vec<u16> = (0..char_count)
        .map(|j| read_u16_le(data, 2 + j * 2))
        .collect();
    let s = String::from_utf16_lossy(&utf16);
    Some((s, 2 + byte_len))
}

/// A decoded property value from a form binary property stream.
#[derive(Debug, Clone)]
pub enum PropertyValue {
    /// Flag-only — opcode emitted with no value data.
    Flag,
    /// Boolean/enum byte (1 byte).
    Byte(u8),
    /// 16-bit signed integer.
    Int16(i16),
    /// 32-bit integer.
    Long(u32),
    /// OLE color value.
    Color(u32),
    /// ASCII string.
    Str(String),
    /// UTF-16 string (Tag, Connect, DatabaseName, etc.).
    TagStr(String),
    /// Position pair: Left + Top from callback.
    Position(ControlPosition),
    /// Client rectangle from callback.
    ClientRect(ClientRect),
    /// Font descriptor.
    Font(FontDescriptor),
    /// Embedded picture/icon data.
    Picture(PictureData),
    /// StdDataFormat COM object (from MSSTDFMT.DLL).
    DataFormat(StdDataFormat),
}

impl fmt::Display for PropertyValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Flag => Ok(()),
            Self::Byte(v) => write!(f, "{v}"),
            Self::Int16(v) => write!(f, "{v}"),
            Self::Long(v) => write!(f, "{v}"),
            Self::Color(v) => write!(f, "#{v:06X}"),
            Self::Str(s) | Self::TagStr(s) => {
                write!(f, "\"")?;
                for ch in s.chars() {
                    if ch.is_control() {
                        write!(f, "\\x{:02X}", ch as u32)?;
                    } else {
                        write!(f, "{ch}")?;
                    }
                }
                write!(f, "\"")
            }
            Self::Position(p) => write!(f, "{p}"),
            Self::ClientRect(r) => write!(f, "{r}"),
            Self::Font(font) => write!(f, "{font}"),
            Self::Picture(pic) => write!(f, "{pic}"),
            Self::DataFormat(df) => write!(f, "{df}"),
        }
    }
}

/// A single decoded property from a form binary stream.
#[derive(Debug, Clone)]
pub struct Property {
    /// Property name (e.g., "Caption", "BackColor").
    pub name: &'static str,
    /// Decoded value.
    pub value: PropertyValue,
    /// Byte offset of this property's value within the property stream.
    pub offset: usize,
}

/// Iterator over decoded properties in a form binary property stream.
///
/// Created by [`FormControlRecord::properties`](crate::vb::formdata::FormControlRecord::properties) or
/// [`FormDataParser::form_properties_decoded`](crate::vb::formdata::FormDataParser::form_properties_decoded).
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct PropertyIter<'a> {
    data: &'a [u8],
    pos: usize,
    ctype: FormControlType,
}

impl<'a> PropertyIter<'a> {
    /// Creates a new property iterator over the given raw property stream.
    pub fn new(data: &'a [u8], ctype: FormControlType) -> Self {
        Self {
            data,
            pos: 0,
            ctype,
        }
    }

    /// Decodes a single property value based on ser_type and callback_bytes.
    /// Returns `None` if the stream is truncated.
    fn decode_value(&mut self, ser_type: u8, callback_bytes: i8) -> Option<PropertyValue> {
        let d = self.data;
        let p = self.pos;
        match ser_type {
            0 => Some(PropertyValue::Flag),

            // ASCII string (Name, String, DataMember)
            1 | 18 | 26 | 33 => {
                let (s, consumed) = parse_ascii_str(&d[p..])?;
                self.pos += consumed;
                Some(PropertyValue::Str(s))
            }

            // Int16
            2 | 17 => {
                if p + 2 > d.len() {
                    return None;
                }
                self.pos += 2;
                Some(PropertyValue::Int16(read_i16_le(d, p)))
            }

            // Long
            3 => {
                if p + 4 > d.len() {
                    return None;
                }
                self.pos += 4;
                Some(PropertyValue::Long(read_u32_le(d, p)))
            }

            // Byte
            4 => {
                if p >= d.len() {
                    return None;
                }
                self.pos += 1;
                Some(PropertyValue::Byte(d[p]))
            }

            // OLE_COLOR
            5 => {
                if p + 4 > d.len() {
                    return None;
                }
                self.pos += 4;
                Some(PropertyValue::Color(read_u32_le(d, p)))
            }

            // Enum/Byte + optional callback trailing data
            6 => {
                if p >= d.len() {
                    return None;
                }
                let v = d[p];
                self.pos += 1;
                if callback_bytes > 0 {
                    let skip = callback_bytes as usize;
                    if self.pos + skip <= d.len() {
                        self.pos += skip;
                    }
                }
                Some(PropertyValue::Byte(v))
            }

            // Single/Currency/Twips Y/H (4 bytes, displayed as Long)
            7 | 10 | 11 => {
                if p + 4 > d.len() {
                    return None;
                }
                self.pos += 4;
                Some(PropertyValue::Long(read_u32_le(d, p)))
            }

            // Twips X/W (4 bytes + optional callback for Position/ClientRect)
            8 | 9 => {
                if p + 4 > d.len() {
                    return None;
                }
                match callback_bytes {
                    4 => {
                        let (pos, consumed) = ControlPosition::parse(&d[p..])?;
                        self.pos += consumed;
                        Some(PropertyValue::Position(pos))
                    }
                    12 => {
                        let (rect, consumed) = ClientRect::parse(&d[p..])?;
                        self.pos += consumed;
                        Some(PropertyValue::ClientRect(rect))
                    }
                    _ => {
                        self.pos += 4;
                        Some(PropertyValue::Long(read_u32_le(d, p)))
                    }
                }
            }

            // UTF-16LE string (Tag, Connect, DatabaseName, RecordSource)
            13 => {
                let (s, consumed) = parse_utf16_str(&d[p..])?;
                self.pos += consumed;
                Some(PropertyValue::TagStr(s))
            }

            // Font descriptor (11B header + variable name callback)
            20 => {
                let (font, consumed) = FontDescriptor::parse(&d[p..])?;
                self.pos += consumed;
                Some(PropertyValue::Font(font))
            }

            // Picture / Icon
            21 => {
                let (pic, consumed) = PictureData::parse(&d[p..])?;
                self.pos += consumed;
                Some(PropertyValue::Picture(pic))
            }

            // StdDataFormat IPersistStream blob
            22 => {
                let (df, consumed) = StdDataFormat::parse(&d[p..])?;
                self.pos += consumed;
                Some(PropertyValue::DataFormat(df))
            }

            // Unknown ser_type — treat as flag
            _ => Some(PropertyValue::Flag),
        }
    }
}

impl<'a> Iterator for PropertyIter<'a> {
    type Item = Property;

    fn next(&mut self) -> Option<Property> {
        if self.pos >= self.data.len() {
            return None;
        }
        let opcode = self.data[self.pos];
        if opcode == 0xFF {
            return None;
        }

        let opcode_offset = self.pos;

        // Known property — decode via ser_type dispatch
        if let Some(desc) = property_descriptor(self.ctype, opcode) {
            self.pos += 1; // consume opcode byte
            let value_offset = self.pos;

            if desc.prop_type == PropType::Flag {
                return Some(Property {
                    name: desc.name,
                    value: PropertyValue::Flag,
                    offset: opcode_offset,
                });
            }

            let value = self.decode_value(desc.ser_type, desc.callback_bytes)?;
            return Some(Property {
                name: desc.name,
                value,
                offset: value_offset,
            });
        }

        // Unknown opcode — try lookahead to skip flag-like unknowns
        self.pos += 1;
        if self.pos < self.data.len() {
            let next = self.data[self.pos];
            if next == 0xFF || property_info(self.ctype, next).is_some() {
                let unknown_name: &'static str =
                    Box::leak(format!("?0x{opcode:02X}").into_boxed_str());
                return Some(Property {
                    name: unknown_name,
                    value: PropertyValue::Flag,
                    offset: opcode_offset,
                });
            }
        }
        None
    }
}

/// Determines the correct [`FormControlType`] for a form-level property stream.
///
/// The GUI entry type doesn't always match the actual form content in OCX files
/// (e.g., PropertyPage form data stored under UserControl GUI entries). This
/// function examines the stream content and project metadata to resolve the
/// correct type deterministically.
pub fn decode_form_type(
    gui_type: GuiObjectType,
    form_props: &[u8],
    project: &VbProject<'_>,
) -> FormControlType {
    match gui_type {
        GuiObjectType::PropertyPage => FormControlType::PropertyPage,
        GuiObjectType::UserControl => {
            // Check if this is actually a PropertyPage by matching the form
            // Name against project objects. The compiler writes using the
            // object's own TypeInfo, which may differ from the GUI entry.
            if form_props.len() > 3 && form_props[0] == 0x00 {
                let nlen = u16::from_le_bytes([form_props[1], form_props[2]]) as usize;
                if 3 + nlen <= form_props.len() {
                    let form_name = &form_props[3..3 + nlen];
                    for other_obj in project.objects() {
                        if let Ok(other_obj) = other_obj
                            && let Ok(n) = other_obj.name()
                            && n == form_name
                        {
                            let otype = other_obj.descriptor().object_type_raw();
                            // Designer objects (flag 0x02) that aren't UserControl
                            // (flag 0x20) are PropertyPages
                            if otype & 0x02 != 0 && otype & 0x20 == 0 {
                                return FormControlType::PropertyPage;
                            }
                            break;
                        }
                    }
                }
            }
            FormControlType::UserControl
        }
        // Form and MDIForm gui types. UserDocument also uses Form gui type
        // in practice — the Form table handles it correctly since the property
        // streams overlap at common indices. The UserDocument table has additional
        // document-specific properties at indices 76+ (ScrollBars, Viewport, etc.)
        // that are only emitted for real UserDocument streams.
        _ => FormControlType::Form,
    }
}

/// Build-time generated property lookup tables.
/// Source: `data/vb6_control_properties.csv`.
pub(crate) mod generated {
    include!(concat!(env!("OUT_DIR"), "/property_generated.rs"));
}
