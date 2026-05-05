//! VB6 form binary data parser.
//!
//! Parses the form design data blob at [`GuiTableEntry::form_data_va`](crate::vb::guitable::GuiTableEntry::form_data_va).
//! This blob contains the visual layout of a VB6 form: control hierarchy,
//! property values, embedded images, and menu definitions.
//!
//! # Format Overview
//!
//! ```text
//! [FormDataHeader]              — magic 0xCCFF, GUIDs, dimensions
//! [form property stream]        — opcode+value pairs, terminated by 0xFF
//! [hierarchy markers + child control records]
//!   0x01 [first child record]   — NEW marker
//!   0x03 [sibling record]       — SIB marker
//!   0x02                        — END marker
//! [0x05 menu section]           — optional
//! [0x04 form end]
//! ```
//!
//! # Control Type Authority
//!
//! The `cType` byte in each child record is the **authoritative** control
//! type identifier. The GUID in [`ControlInfo`](crate::vb::control::ControlInfo)
//! may contain IID variants that produce incorrect fuzzy matches (verified:
//! 8 of 12 controls misidentified by GUID in the vb_inject malware sample).
//!
//! See `data/vb6_form_format.md` for the complete format specification.

use std::{borrow::Cow, fmt};

use crate::{
    error::Error,
    util::{read_u16_le, read_u32_le},
    vb::control::Guid,
    vb::property::PropertyIter,
};

/// Magic marker at the start of form binary data (0xCCFF as u16 LE).
pub const FORM_DATA_MAGIC: u16 = 0xCCFF;

/// Version field following the magic (always 0x0031 = 49).
pub const FORM_DATA_VERSION: u16 = 0x0031;

/// VB6 control type code from the form binary data `cType` byte.
///
/// This is the **authoritative** control type identifier, more reliable
/// than GUID-based identification (which fails for malware samples).
///
/// The type codes are indices into the VB6 compiler's control lookup
/// table at `data_456C50` (from `sub_40F1AF` in VB6.EXE).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormControlType {
    /// PictureBox control (type 0).
    PictureBox,
    /// Label control (type 1).
    Label,
    /// TextBox control (type 2).
    TextBox,
    /// Frame container control (type 3).
    Frame,
    /// CommandButton control (type 4).
    CommandButton,
    /// CheckBox control (type 5).
    CheckBox,
    /// OptionButton control (type 6).
    OptionButton,
    /// ComboBox control (type 7).
    ComboBox,
    /// ListBox control (type 8).
    ListBox,
    /// Horizontal scrollbar (type 9).
    HScrollBar,
    /// Vertical scrollbar (type 10).
    VScrollBar,
    /// Timer control (type 11).
    Timer,
    /// Form (type 13).
    Form,
    /// DriveListBox control (type 16).
    DriveListBox,
    /// DirListBox control (type 17).
    DirListBox,
    /// FileListBox control (type 18).
    FileListBox,
    /// Menu item (type 19).
    Menu,
    /// MDI Form (type 20).
    MDIForm,
    /// Shape control (type 22).
    Shape,
    /// Line control (type 23).
    Line,
    /// Image control (type 24).
    Image,
    /// Data control (type 37).
    Data,
    /// OLE container (type 38).
    OLE,
    /// UserControl (type 40).
    UserControl,
    /// PropertyPage (type 41).
    PropertyPage,
    /// UserDocument (type 42).
    UserDocument,
    /// Unknown control type.
    Unknown(u8),
}

impl FormControlType {
    /// Converts a raw `cType` byte to a [`FormControlType`].
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::PictureBox,
            1 => Self::Label,
            2 => Self::TextBox,
            3 => Self::Frame,
            4 => Self::CommandButton,
            5 => Self::CheckBox,
            6 => Self::OptionButton,
            7 => Self::ComboBox,
            8 => Self::ListBox,
            9 => Self::HScrollBar,
            10 => Self::VScrollBar,
            11 => Self::Timer,
            13 => Self::Form,
            16 => Self::DriveListBox,
            17 => Self::DirListBox,
            18 => Self::FileListBox,
            19 => Self::Menu,
            20 => Self::MDIForm,
            22 => Self::Shape,
            23 => Self::Line,
            24 => Self::Image,
            37 => Self::Data,
            38 => Self::OLE,
            40 => Self::UserControl,
            41 => Self::PropertyPage,
            42 => Self::UserDocument,
            n => Self::Unknown(n),
        }
    }

    /// Converts a [`FormControlType`] back to its raw `cType` byte.
    pub fn to_u8(&self) -> u8 {
        match self {
            Self::PictureBox => 0,
            Self::Label => 1,
            Self::TextBox => 2,
            Self::Frame => 3,
            Self::CommandButton => 4,
            Self::CheckBox => 5,
            Self::OptionButton => 6,
            Self::ComboBox => 7,
            Self::ListBox => 8,
            Self::HScrollBar => 9,
            Self::VScrollBar => 10,
            Self::Timer => 11,
            Self::Form => 13,
            Self::DriveListBox => 16,
            Self::DirListBox => 17,
            Self::FileListBox => 18,
            Self::Menu => 19,
            Self::MDIForm => 20,
            Self::Shape => 22,
            Self::Line => 23,
            Self::Image => 24,
            Self::Data => 37,
            Self::OLE => 38,
            Self::UserControl => 40,
            Self::PropertyPage => 41,
            Self::UserDocument => 42,
            Self::Unknown(n) => *n,
        }
    }

    /// Converts a control class name to a [`FormControlType`].
    ///
    /// Accepts the names returned by [`Guid::control_class_name()`](crate::vb::control::Guid::control_class_name)
    /// and [`FormControlType::name()`].
    pub fn from_class_name(name: &str) -> Option<Self> {
        match name {
            "PictureBox" => Some(Self::PictureBox),
            "Label" => Some(Self::Label),
            "TextBox" => Some(Self::TextBox),
            "Frame" => Some(Self::Frame),
            "CommandButton" => Some(Self::CommandButton),
            "CheckBox" => Some(Self::CheckBox),
            "OptionButton" => Some(Self::OptionButton),
            "ComboBox" => Some(Self::ComboBox),
            "ListBox" => Some(Self::ListBox),
            "HScrollBar" => Some(Self::HScrollBar),
            "VScrollBar" => Some(Self::VScrollBar),
            "Timer" => Some(Self::Timer),
            "Form" => Some(Self::Form),
            "DriveListBox" => Some(Self::DriveListBox),
            "DirListBox" => Some(Self::DirListBox),
            "FileListBox" => Some(Self::FileListBox),
            "Menu" => Some(Self::Menu),
            "MDIForm" => Some(Self::MDIForm),
            "Shape" => Some(Self::Shape),
            "Line" => Some(Self::Line),
            "Image" => Some(Self::Image),
            "Data" => Some(Self::Data),
            "OLE" => Some(Self::OLE),
            "UserControl" => Some(Self::UserControl),
            "PropertyPage" => Some(Self::PropertyPage),
            "UserDocument" => Some(Self::UserDocument),
            _ => None,
        }
    }

    /// Returns the stable persistence string for this control type.
    ///
    /// These strings are part of the public API contract and are suitable
    /// for database storage. Unknown raw type codes return `"Unknown"`;
    /// use [`to_u8`](Self::to_u8) when the original numeric code must be
    /// preserved as well.
    pub fn name(&self) -> &'static str {
        match self {
            Self::PictureBox => "PictureBox",
            Self::Label => "Label",
            Self::TextBox => "TextBox",
            Self::Frame => "Frame",
            Self::CommandButton => "CommandButton",
            Self::CheckBox => "CheckBox",
            Self::OptionButton => "OptionButton",
            Self::ComboBox => "ComboBox",
            Self::ListBox => "ListBox",
            Self::HScrollBar => "HScrollBar",
            Self::VScrollBar => "VScrollBar",
            Self::Timer => "Timer",
            Self::Form => "Form",
            Self::DriveListBox => "DriveListBox",
            Self::DirListBox => "DirListBox",
            Self::FileListBox => "FileListBox",
            Self::Menu => "Menu",
            Self::MDIForm => "MDIForm",
            Self::Shape => "Shape",
            Self::Line => "Line",
            Self::Image => "Image",
            Self::Data => "Data",
            Self::OLE => "OLE",
            Self::UserControl => "UserControl",
            Self::PropertyPage => "PropertyPage",
            Self::UserDocument => "UserDocument",
            Self::Unknown(_) => "Unknown",
        }
    }

    /// Alias for [`name`](Self::name), matching other discriminator enums.
    pub fn as_str(&self) -> &'static str {
        self.name()
    }

    /// Returns `true` if this control type can contain child controls.
    pub fn is_container(&self) -> bool {
        matches!(self, Self::Frame | Self::PictureBox)
    }
}

impl fmt::Display for FormControlType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(n) => write!(f, "Unknown({n})"),
            _ => write!(f, "{}", self.name()),
        }
    }
}

/// Hierarchy marker byte in form binary data.
///
/// These are **single bytes** that appear after the `0xFF` property stream
/// terminator. They are NOT 2-byte values (the Semi-VBDecompiler convention
/// of `0x01FF` etc. includes the terminator byte).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormMarker {
    /// `0x01`: First child in a container group.
    NewChild,
    /// `0x02`: End of current child group.
    EndChildren,
    /// `0x03`: Next sibling at same level.
    Sibling,
    /// `0x04`: End of entire form data.
    FormEnd,
    /// `0x05`: Menu section begins.
    MenuStart,
}

impl FormMarker {
    /// Converts a raw byte to a [`FormMarker`], or `None` if not a marker.
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            0x01 => Some(Self::NewChild),
            0x02 => Some(Self::EndChildren),
            0x03 => Some(Self::Sibling),
            0x04 => Some(Self::FormEnd),
            0x05 => Some(Self::MenuStart),
            _ => None,
        }
    }
}

/// View over the form binary data header.
///
/// # Layout (0x61 bytes minimum)
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 2 | Magic (0xCCFF) |
/// | 0x02 | 2 | Version (0x0031) |
/// | 0x04 | 1 | Site count / flags |
/// | 0x05 | 16 | Form's own GUI GUID |
/// | 0x15 | 16 | Secondary GUID |
/// | 0x25 | 16 | Default control GUID |
/// | 0x35 | 36 | Reserved (zeros) |
/// | 0x59 | 4 | Form width (twips) |
/// | 0x5D | 4 | Form height (twips) |
#[derive(Clone, Copy, Debug)]
pub struct FormDataHeader<'a> {
    bytes: &'a [u8],
}

impl<'a> FormDataHeader<'a> {
    /// Minimum header size in bytes.
    pub const MIN_SIZE: usize = 0x61;

    /// Parses the form data header.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let bytes = data.get(..Self::MIN_SIZE).ok_or(Error::TooShort {
            expected: Self::MIN_SIZE,
            actual: data.len(),
            context: "FormDataHeader",
        })?;
        let magic = read_u16_le(bytes, 0x00)?;
        if magic != FORM_DATA_MAGIC {
            let got: [u8; 4] = bytes
                .get(..4)
                .and_then(|s| <[u8; 4]>::try_from(s).ok())
                .unwrap_or([0; 4]);
            return Err(Error::BadMagic {
                expected: "CCFF (form data)",
                got,
            });
        }
        Ok(Self { bytes })
    }

    /// Magic marker at offset 0x00 (should be 0xCCFF).
    #[inline]
    pub fn magic(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x00)
    }

    /// Version field at offset 0x02 (should be 0x0031).
    #[inline]
    pub fn version(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x02)
    }

    /// Site count or flags byte at offset 0x04.
    #[inline]
    pub fn site_flags(&self) -> u8 {
        self.bytes.get(0x04).copied().unwrap_or(0)
    }

    /// Form's own GUI GUID at offset 0x05 (16 bytes).
    pub fn form_guid(&self) -> Option<Guid> {
        Guid::from_bytes(self.bytes.get(0x05..0x15)?)
    }

    /// Secondary GUID at offset 0x15 (16 bytes).
    pub fn secondary_guid(&self) -> Option<Guid> {
        let data = self.bytes.get(0x15..0x25)?;
        if data.iter().all(|&b| b == 0) {
            return None;
        }
        Guid::from_bytes(data)
    }

    /// Default control GUID at offset 0x25 (16 bytes).
    pub fn default_control_guid(&self) -> Option<Guid> {
        Guid::from_bytes(self.bytes.get(0x25..0x35)?)
    }

    /// Form width in twips at offset 0x59.
    #[inline]
    pub fn width(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x59)
    }

    /// Form height in twips at offset 0x5D.
    #[inline]
    pub fn height(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x5D)
    }
}

/// A child control record parsed from form binary data.
///
/// # Record Layout
///
/// ```text
/// [u32 size]                    — total record size (bit 31 = has array index)
/// [u8 cId]                      — control ID (links to ControlInfo.index)
/// [u16_le name_len]             — name string length
/// [name_len + 1 bytes]          — name + null terminator
/// [u8 cType]                    — authoritative control type code
/// [property bytes...]           — opcode + value pairs
/// [0xFF]                        — property stream terminator
/// ```
///
/// For control array members (bit 31 of size set), a 2-byte array index
/// appears between cId and the name.
#[derive(Clone, Debug)]
pub struct FormControlRecord<'a> {
    /// Control ID (links to ControlInfo.index).
    cid: u8,
    /// Control array index, if present.
    array_index: Option<u16>,
    /// Control name (without null terminator).
    name: &'a [u8],
    /// Authoritative control type.
    ctype: FormControlType,
    /// Raw property stream bytes (between cType and 0xFF terminator).
    properties: &'a [u8],
    /// Total record size from the size field (bit 31 masked off).
    total_size: u32,
    /// Nesting depth (0 = top-level form child, 1 = inside a Frame, etc.).
    depth: u16,
    /// Byte offset of this record's size field within the form data blob.
    offset_in_blob: u32,
    /// Byte offset of the property stream within the form data blob.
    properties_offset_in_blob: u32,
    /// Index of the containing parent control in [`FormDataParser::controls`].
    parent_index: Option<usize>,
}

impl<'a> FormControlRecord<'a> {
    /// Parses a single control record starting at the given offset.
    ///
    /// `data` should point to the first byte of the record (the size field),
    /// NOT to the hierarchy marker byte before it.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < 8 {
            return Err(Error::TooShort {
                expected: 8,
                actual: data.len(),
                context: "FormControlRecord",
            });
        }

        let raw_size = read_u32_le(data, 0)?;
        let has_array_index = raw_size & 0x80000000 != 0;
        let total_size = raw_size & 0x7FFFFFFF;

        let record = data.get(..total_size as usize).ok_or(Error::TooShort {
            expected: total_size as usize,
            actual: data.len(),
            context: "FormControlRecord size",
        })?;
        if total_size < 8 {
            return Err(Error::TooShort {
                expected: 8,
                actual: total_size as usize,
                context: "FormControlRecord size",
            });
        }
        let mut pos: usize = 4; // past size field

        // cId
        let cid = *record.get(pos).ok_or(Error::TooShort {
            expected: pos.saturating_add(1),
            actual: record.len(),
            context: "FormControlRecord cId",
        })?;
        pos = pos.saturating_add(1);

        // Optional array index (if bit 31 was set)
        let array_index = if has_array_index {
            let idx = read_u16_le(record, pos)?;
            pos = pos.saturating_add(2);
            Some(idx)
        } else {
            None
        };

        // Name: [u16_le length] [string bytes + null]
        let name_len = read_u16_le(record, pos)? as usize;
        pos = pos.saturating_add(2);

        let name_end = pos.checked_add(name_len).ok_or(Error::ArithmeticOverflow {
            context: "FormControlRecord name end",
        })?;
        let name = record.get(pos..name_end).ok_or(Error::TooShort {
            expected: name_end.saturating_add(1),
            actual: record.len(),
            context: "FormControlRecord name",
        })?;
        pos = name_end.checked_add(1).ok_or(Error::ArithmeticOverflow {
            context: "FormControlRecord name terminator",
        })?; // skip null terminator

        // cType byte
        let ctype_byte = *record.get(pos).ok_or(Error::TooShort {
            expected: pos.saturating_add(1),
            actual: record.len(),
            context: "FormControlRecord cType",
        })?;
        let ctype = FormControlType::from_u8(ctype_byte);
        pos = pos.saturating_add(1);

        // Property stream: everything from here to the 0xFF terminator
        // The 0xFF should be the last byte of the record
        let tail = record.get(pos..).unwrap_or(&[]);
        let props_end = if let Some(ff_pos) = tail.iter().rposition(|&b| b == 0xFF) {
            pos.saturating_add(ff_pos)
        } else {
            record.len()
        };
        let properties = record.get(pos..props_end).unwrap_or(&[]);

        let properties_offset_local = pos as u32; // offset within this record

        Ok(Self {
            cid,
            array_index,
            name,
            ctype,
            properties,
            total_size,
            depth: 0,
            offset_in_blob: 0,
            properties_offset_in_blob: properties_offset_local,
            parent_index: None,
        })
    }

    /// Control ID (links to [`ControlInfo::index`](crate::vb::control::ControlInfo::index)).
    #[inline]
    pub fn cid(&self) -> u8 {
        self.cid
    }

    /// Control array index, if this is a control array member.
    #[inline]
    pub fn array_index(&self) -> Option<u16> {
        self.array_index
    }

    /// Control name as a lossy UTF-8 string (e.g., `"Timer1"`, `"Command1"`).
    ///
    /// Borrows when the underlying bytes are already valid UTF-8.
    /// Use [`name_bytes`](Self::name_bytes) for the raw bytes.
    #[inline]
    pub fn name(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.name)
    }

    /// Control name as raw bytes from the form binary.
    #[inline]
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }

    /// Authoritative control type from the form binary data.
    #[inline]
    pub fn control_type(&self) -> FormControlType {
        self.ctype
    }

    /// Raw property stream bytes (opcode+value pairs, excluding the 0xFF terminator).
    #[inline]
    pub fn raw_properties(&self) -> &'a [u8] {
        self.properties
    }

    /// Total record size in bytes (from the size field, bit 31 masked off).
    #[inline]
    pub fn total_size(&self) -> u32 {
        self.total_size
    }

    /// Nesting depth (0 = top-level form child, 1 = inside a Frame, etc.).
    #[inline]
    pub fn depth(&self) -> u16 {
        self.depth
    }

    /// Byte offset of this record's size field within the form data blob.
    ///
    /// Set by [`FormDataParser::parse`] during hierarchy walking.
    #[inline]
    pub fn offset_in_blob(&self) -> u32 {
        self.offset_in_blob
    }

    /// Byte offset of the property stream within the form data blob.
    ///
    /// Use with [`Property::offset`](crate::vb::property::Property::offset) to compute
    /// absolute offsets: `properties_offset_in_blob + prop.offset`.
    #[inline]
    pub fn properties_offset_in_blob(&self) -> u32 {
        self.properties_offset_in_blob
    }

    /// Index of this control's parent in [`FormDataParser::controls`].
    ///
    /// Returns `None` for top-level controls. The index is stable for the
    /// lifetime of the parsed [`FormDataParser`] and refers to the flat
    /// control slice returned by [`FormDataParser::controls`].
    #[inline]
    pub fn parent_index(&self) -> Option<usize> {
        self.parent_index
    }

    /// Decodes the property stream into an iterator of named property values.
    pub fn properties(&self) -> PropertyIter<'a> {
        PropertyIter::new(self.properties, self.ctype)
    }
}

/// Parsed form binary data with header and flat control list.
///
/// Use [`FormDataParser::parse`] to parse the blob at
/// [`GuiTableEntry::form_data_va`](crate::vb::guitable::GuiTableEntry::form_data_va).
pub struct FormDataParser<'a> {
    /// Parsed header.
    header: FormDataHeader<'a>,
    /// Flat list of child control records in parse order.
    controls: Vec<FormControlRecord<'a>>,
    /// Raw form data bytes.
    data: &'a [u8],
    /// Form-level property stream (between header and first child marker).
    form_properties: &'a [u8],
}

impl<'a> FormDataParser<'a> {
    /// Parses form binary data from the given byte slice.
    ///
    /// Returns the header and a flat list of child control records.
    /// The hierarchy (nesting, menus) is preserved in the record order
    /// and can be reconstructed from the marker sequence.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        let header = FormDataHeader::parse(data)?;
        let form_properties = Self::extract_form_properties(data);
        let controls = Self::parse_controls(data)?;

        Ok(Self {
            header,
            controls,
            data,
            form_properties,
        })
    }

    /// Returns the form data header.
    #[inline]
    pub fn header(&self) -> &FormDataHeader<'a> {
        &self.header
    }

    /// Returns the flat list of child control records.
    #[inline]
    pub fn controls(&self) -> &[FormControlRecord<'a>] {
        &self.controls
    }

    /// Returns the raw form data bytes.
    #[inline]
    pub fn raw_data(&self) -> &'a [u8] {
        self.data
    }

    /// Returns the form-level property stream bytes.
    ///
    /// This is the property stream between the header and the first child
    /// marker (or form end). Contains the form's own properties like Name,
    /// Caption, BackColor, Font, Icon, etc.
    #[inline]
    pub fn form_properties(&self) -> &'a [u8] {
        self.form_properties
    }

    /// Decodes the form-level property stream into an iterator of named values.
    ///
    /// `form_type` should be determined by [`decode_form_type`](crate::vb::property::decode_form_type) to handle
    /// OCX files where GUI entry types don't match actual form content.
    pub fn form_properties_decoded(&self, form_type: FormControlType) -> PropertyIter<'a> {
        PropertyIter::new(self.form_properties, form_type)
    }

    /// Finds a control record by cId.
    pub fn control_by_id(&self, cid: u8) -> Option<&FormControlRecord<'a>> {
        self.controls.iter().find(|c| c.cid() == cid)
    }

    /// Extracts the form-level property stream between header and first child marker.
    fn extract_form_properties(data: &'a [u8]) -> &'a [u8] {
        let start = FormDataHeader::MIN_SIZE;
        if start >= data.len() {
            return &[];
        }
        // The form property stream runs from after the header until we hit
        // 0xFF followed by a hierarchy marker (0x01-0x05). The 0xFF is the
        // property stream terminator.
        let mut pos = start;
        while pos.saturating_add(1) < data.len() {
            let cur = match data.get(pos).copied() {
                Some(b) => b,
                None => break,
            };
            let next = match data.get(pos.saturating_add(1)).copied() {
                Some(b) => b,
                None => break,
            };
            if cur == 0xFF && FormMarker::from_byte(next).is_some() {
                // Validate: for child markers (0x01, 0x03, 0x05), check
                // that what follows looks like a valid record size
                match next {
                    0x01 | 0x03 | 0x05 if pos.saturating_add(6) < data.len() => {
                        let size = read_u32_le(data, pos.saturating_add(2))
                            .map(|v| v & 0x7FFFFFFF)
                            .unwrap_or(0);
                        if (8..5000).contains(&size) {
                            return data.get(start..pos).unwrap_or(&[]);
                        }
                    }
                    0x04 | 0x02 => return data.get(start..pos).unwrap_or(&[]),
                    _ => {}
                }
            }
            pos = pos.saturating_add(1);
        }
        // No marker found — return everything after header
        let end = data.len().min(start.saturating_add(256));
        data.get(start..end).unwrap_or(&[])
    }

    /// Walks the form data after the header, finding child control records.
    fn parse_controls(data: &'a [u8]) -> Result<Vec<FormControlRecord<'a>>, Error> {
        let mut controls = Vec::new();

        // Find the first valid child marker by scanning for 0xFF followed
        // by a NEW (0x01) or FORM_END (0x04) marker, then validating
        // the record structure (reasonable size field).
        let mut pos = FormDataHeader::MIN_SIZE;
        let start = loop {
            if pos.saturating_add(6) >= data.len() {
                return Ok(controls); // no children found
            }
            let cur = data.get(pos).copied().unwrap_or(0);
            let next = data.get(pos.saturating_add(1)).copied().unwrap_or(0);
            if cur == 0xFF && next == 0x01 {
                // Validate: a NEW marker should be followed by a record
                // with a reasonable size (8..5000 bytes)
                let size = read_u32_le(data, pos.saturating_add(2))
                    .map(|v| v & 0x7FFFFFFF)
                    .unwrap_or(0);
                let end_check = (size as usize).saturating_add(pos.saturating_add(2));
                if (8..5000).contains(&size) && end_check <= data.len() {
                    break pos.saturating_add(1); // skip the 0xFF, start at marker
                }
            }
            if cur == 0xFF && next == 0x04 {
                return Ok(controls); // form end, no children
            }
            pos = pos.saturating_add(1);
        };

        // Now walk the marker sequence, tracking nesting depth
        pos = start;
        let mut depth: u16 = 0;
        let mut parent_stack: Vec<usize> = Vec::new();
        while pos < data.len() {
            let cur_byte = match data.get(pos).copied() {
                Some(b) => b,
                None => break,
            };
            let marker = match FormMarker::from_byte(cur_byte) {
                Some(m) => m,
                None => break,
            };
            pos = pos.saturating_add(1); // skip marker byte

            match marker {
                FormMarker::FormEnd => break,
                FormMarker::NewChild => {
                    if pos.saturating_add(4) > data.len() {
                        break;
                    }
                    let size = read_u32_le(data, pos).map(|v| v & 0x7FFFFFFF).unwrap_or(0);
                    let size_usize = size as usize;
                    let end = match pos.checked_add(size_usize) {
                        Some(e) if e <= data.len() => e,
                        _ => break,
                    };
                    if size < 8 {
                        break;
                    }
                    if let Some(slice) = data.get(pos..)
                        && let Ok(mut record) = FormControlRecord::parse(slice)
                    {
                        record.depth = depth;
                        let level = depth as usize;
                        record.parent_index = level
                            .checked_sub(1)
                            .and_then(|parent_level| parent_stack.get(parent_level).copied());
                        record.offset_in_blob = pos as u32;
                        record.properties_offset_in_blob =
                            record.properties_offset_in_blob.wrapping_add(pos as u32);
                        let record_index = controls.len();
                        parent_stack.truncate(level);
                        parent_stack.push(record_index);
                        controls.push(record);
                    }
                    pos = end;
                    // NEW marker opens a new nesting level for subsequent children
                    depth = depth.saturating_add(1);
                }
                FormMarker::Sibling | FormMarker::MenuStart => {
                    if pos.saturating_add(4) > data.len() {
                        break;
                    }
                    let size = read_u32_le(data, pos).map(|v| v & 0x7FFFFFFF).unwrap_or(0);
                    let size_usize = size as usize;
                    let end = match pos.checked_add(size_usize) {
                        Some(e) if e <= data.len() => e,
                        _ => break,
                    };
                    if size < 8 {
                        break;
                    }
                    if let Some(slice) = data.get(pos..)
                        && let Ok(mut record) = FormControlRecord::parse(slice)
                    {
                        let record_depth = depth.saturating_sub(1);
                        record.depth = record_depth;
                        let level = record_depth as usize;
                        record.parent_index = level
                            .checked_sub(1)
                            .and_then(|parent_level| parent_stack.get(parent_level).copied());
                        record.offset_in_blob = pos as u32;
                        record.properties_offset_in_blob =
                            record.properties_offset_in_blob.wrapping_add(pos as u32);
                        let record_index = controls.len();
                        parent_stack.truncate(level);
                        parent_stack.push(record_index);
                        controls.push(record);
                    }
                    pos = end;
                }
                FormMarker::EndChildren => {
                    depth = depth.saturating_sub(1);
                    parent_stack.truncate(depth as usize);
                }
            }
        }

        Ok(controls)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_form_control_type_from_u8() {
        assert_eq!(FormControlType::from_u8(0), FormControlType::PictureBox);
        assert_eq!(FormControlType::from_u8(1), FormControlType::Label);
        assert_eq!(FormControlType::from_u8(11), FormControlType::Timer);
        assert_eq!(FormControlType::from_u8(13), FormControlType::Form);
        assert_eq!(FormControlType::from_u8(19), FormControlType::Menu);
        assert_eq!(FormControlType::from_u8(42), FormControlType::UserDocument);
        assert_eq!(FormControlType::from_u8(99), FormControlType::Unknown(99));
    }

    #[test]
    fn test_form_control_type_name() {
        assert_eq!(FormControlType::Timer.name(), "Timer");
        assert_eq!(FormControlType::CommandButton.name(), "CommandButton");
        assert_eq!(FormControlType::Unknown(55).name(), "Unknown");
    }

    #[test]
    fn test_form_control_type_display() {
        assert_eq!(format!("{}", FormControlType::Label), "Label");
        assert_eq!(format!("{}", FormControlType::Unknown(99)), "Unknown(99)");
    }

    #[test]
    fn test_form_control_type_is_container() {
        assert!(FormControlType::Frame.is_container());
        assert!(FormControlType::PictureBox.is_container());
        assert!(!FormControlType::Timer.is_container());
        assert!(!FormControlType::Label.is_container());
    }

    #[test]
    fn test_form_marker_from_byte() {
        assert_eq!(FormMarker::from_byte(0x01), Some(FormMarker::NewChild));
        assert_eq!(FormMarker::from_byte(0x02), Some(FormMarker::EndChildren));
        assert_eq!(FormMarker::from_byte(0x03), Some(FormMarker::Sibling));
        assert_eq!(FormMarker::from_byte(0x04), Some(FormMarker::FormEnd));
        assert_eq!(FormMarker::from_byte(0x05), Some(FormMarker::MenuStart));
        assert_eq!(FormMarker::from_byte(0x00), None);
        assert_eq!(FormMarker::from_byte(0xFF), None);
    }

    // Real data: Timer1 from pe_x86_vb_loader (33 bytes, verified in spec)
    #[test]
    fn test_parse_timer_record() {
        let record: [u8; 33] = [
            0x21, 0x00, 0x00, 0x00, // size = 33
            0x01, // cId = 1
            0x06, 0x00, // name_len = 6
            0x54, 0x69, 0x6D, 0x65, 0x72, 0x31, 0x00, // "Timer1\0"
            0x0B, // cType = 11 (Timer)
            // Properties:
            0x02, 0x00, // prop[2]=Byte, value=0 (Enabled=False)
            0x03, 0x20, 0x4E, 0x00, 0x00, // prop[3]=Long, value=20000 (Interval)
            0x07, 0x78, 0x00, 0x00, 0x00, // prop[7]=Long, value=120 (Left)
            0x08, 0x78, 0x00, 0x00, 0x00, // prop[8]=Long, value=120 (Top)
            0xFF, // terminator
        ];

        let ctrl = FormControlRecord::parse(&record).unwrap();
        assert_eq!(ctrl.cid(), 1);
        assert_eq!(ctrl.array_index(), None);
        assert_eq!(ctrl.name_bytes(), b"Timer1");
        assert_eq!(ctrl.name(), "Timer1");
        assert_eq!(ctrl.control_type(), FormControlType::Timer);
        assert_eq!(ctrl.total_size(), 33);
        assert_eq!(ctrl.raw_properties().len(), 17); // 33 - 15 (header) - 1 (0xFF)
    }

    #[test]
    fn test_parse_control_array_record() {
        // Simulated control array member (bit 31 set, array_index present)
        let record: [u8; 16] = [
            0x10, 0x00, 0x00, 0x80, // size = 16 | 0x80000000
            0x05, // cId = 5
            0x03, 0x00, // array_index = 3
            0x03, 0x00, // name_len = 3
            0x42, 0x74, 0x6E, 0x00, // "Btn\0"
            0x04, // cType = 4 (CommandButton)
            0x02, // property data
            0xFF, // terminator
        ];

        let ctrl = FormControlRecord::parse(&record).unwrap();
        assert_eq!(ctrl.cid(), 5);
        assert_eq!(ctrl.array_index(), Some(3));
        assert_eq!(ctrl.name_bytes(), b"Btn");
        assert_eq!(ctrl.name(), "Btn");
        assert_eq!(ctrl.control_type(), FormControlType::CommandButton);
    }
}
