//! Bitflag newtypes for VB6 structure flag fields.

use std::fmt;

/// Object type flags from `PublicObjectDescriptor.fObjectType` (u32).
///
/// The **low byte** encodes the base object type via bit patterns.
/// Higher bytes contain linker/compiler modifiers.
///
/// # Low Byte Patterns (verified across 104 samples + ComCt332.ocx)
///
/// | Low byte | Meaning |
/// |----------|---------|
/// | `0x01` | Standard module (.bas) |
/// | `0x03` | Class module (.cls) or COM class |
/// | `0x83` | Form (.frm) or UserDocument (.dob) |
///
/// # Full u32 Examples
///
/// | Raw value | Meaning |
/// |-----------|---------|
/// | `0x00018001` | Standard module (.bas) |
/// | `0x00118003` | Class module (.cls) |
/// | `0x00118803` | Class with ActiveX flag (in OCX) |
/// | `0x00018083` | Form (.frm) |
/// | `0x001DE803` | UserControl (CoolBar in ComCt332.ocx) |
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ObjectTypeFlags(pub u32);

impl ObjectTypeFlags {
    /// Optional info structure is present (bit 0, always set in compiled binaries).
    pub const HAS_OPTIONAL_INFO: u32 = 0x01;
    /// Object has COM interface — set for classes and forms, NOT for modules (bit 1).
    pub const HAS_COM_INTERFACE: u32 = 0x02;
    /// Object is visual / has a form designer (bit 7).
    pub const IS_VISUAL: u32 = 0x80;
    /// ActiveX control/server flag (bit 11, 0x800).
    pub const ACTIVEX: u32 = 0x800;

    /// Tests whether the given flag bit(s) are set.
    #[inline]
    pub fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Returns `true` if the optional info structure is present.
    #[inline]
    pub fn has_optional_info(self) -> bool {
        self.has(Self::HAS_OPTIONAL_INFO)
    }

    /// Returns `true` if this is a class module or COM class.
    ///
    /// Matches low byte `0x03`: `HAS_COM_INTERFACE` set, `IS_VISUAL` clear.
    #[inline]
    pub fn is_class(self) -> bool {
        self.0 & 0x82 == 0x02
    }

    /// Returns `true` if this is a form or UserDocument.
    ///
    /// Matches low byte `0x83`: both `HAS_COM_INTERFACE` and `IS_VISUAL` set.
    #[inline]
    pub fn is_form(self) -> bool {
        self.0 & 0x82 == 0x82
    }

    /// Returns `true` if this is a standard module (.bas).
    ///
    /// Matches low byte `0x01`: neither `HAS_COM_INTERFACE` nor `IS_VISUAL`.
    #[inline]
    pub fn is_module(self) -> bool {
        self.0 & 0x82 == 0x00
    }

    /// Returns a human-readable kind string for this object type.
    ///
    /// Cannot distinguish UserControl from Class or UserDocument from Form
    /// using flags alone — those require project-level context.
    pub fn kind_name(self) -> &'static str {
        if self.is_form() {
            "Form"
        } else if self.is_class() {
            "Class"
        } else {
            "Module"
        }
    }
}

impl fmt::Debug for ObjectTypeFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ObjectTypeFlags(0x{:08X} {})", self.0, self.kind_name())
    }
}

impl fmt::Display for ObjectTypeFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Threading mode flags from `VbHeader.dwThreadFlags`.
///
/// These control the threading model of the VB6 application.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ThreadFlags(pub u32);

impl ThreadFlags {
    /// Apartment-model multithreading.
    pub const APARTMENT_MODEL: u32 = 0x01;
    /// Require license (OCX only).
    pub const REQUIRE_LICENSE: u32 = 0x02;
    /// Unattended execution (no GUI).
    pub const UNATTENDED: u32 = 0x04;
    /// Single-threaded.
    pub const SINGLE_THREADED: u32 = 0x08;
    /// Retained in memory.
    pub const RETAINED: u32 = 0x10;

    /// Tests whether the given flag bit(s) are set.
    #[inline]
    pub fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Returns `true` if apartment-model threading is enabled.
    #[inline]
    pub fn is_apartment_model(self) -> bool {
        self.has(Self::APARTMENT_MODEL)
    }

    /// Returns `true` if the application runs unattended (no GUI).
    #[inline]
    pub fn is_unattended(self) -> bool {
        self.has(Self::UNATTENDED)
    }

    /// Returns `true` if the application is single-threaded.
    #[inline]
    pub fn is_single_threaded(self) -> bool {
        self.has(Self::SINGLE_THREADED)
    }
}

impl fmt::Debug for ThreadFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ThreadFlags(0x{:02X}", self.0)?;
        let flags: &[(&str, u32)] = &[
            ("APARTMENT_MODEL", Self::APARTMENT_MODEL),
            ("REQUIRE_LICENSE", Self::REQUIRE_LICENSE),
            ("UNATTENDED", Self::UNATTENDED),
            ("SINGLE_THREADED", Self::SINGLE_THREADED),
            ("RETAINED", Self::RETAINED),
        ];
        let mut first = true;
        for &(name, val) in flags {
            if self.has(val) {
                if first {
                    write!(f, " ")?;
                    first = false;
                } else {
                    write!(f, " | ")?;
                }
                write!(f, "{name}")?;
            }
        }
        write!(f, ")")
    }
}

impl fmt::Display for ThreadFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Intrinsic control usage flags from `VBHeader.mdl_int_ctls` (+0x34).
///
/// Each bit indicates that the project uses a specific intrinsic VB6 control.
/// Bits 0-11 map directly to `FormControlType` cType values 0-11.
/// Bits 12-15 and 20-21 are always set (compiler/runtime internal).
///
/// A second u32 at `VBHeader.mdl_int_ctls2` (+0x38) covers higher control
/// type IDs (>= 32). Common value: `0xFFFFFF00` (bits 8-31 always set).
///
/// # Bit mapping (confirmed via 100-sample cross-reference)
///
/// | Bit | Control type |
/// |-----|-------------|
/// | 0 | PictureBox |
/// | 1 | Label |
/// | 2 | TextBox |
/// | 3 | Frame |
/// | 4 | CommandButton |
/// | 5 | CheckBox |
/// | 6 | OptionButton |
/// | 7 | ComboBox |
/// | 8 | ListBox |
/// | 9 | HScrollBar |
/// | 10 | VScrollBar |
/// | 11 | Timer |
/// | 12-15 | Always set (internal) |
/// | 16+ | Higher control types |
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct IntrinsicControlFlags(pub u32);

impl IntrinsicControlFlags {
    /// PictureBox control (bit 0, cType 0).
    pub const PICTURE_BOX: u32 = 1 << 0;
    /// Label control (bit 1, cType 1).
    pub const LABEL: u32 = 1 << 1;
    /// TextBox control (bit 2, cType 2).
    pub const TEXT_BOX: u32 = 1 << 2;
    /// Frame container control (bit 3, cType 3).
    pub const FRAME: u32 = 1 << 3;
    /// CommandButton control (bit 4, cType 4).
    pub const COMMAND_BUTTON: u32 = 1 << 4;
    /// CheckBox control (bit 5, cType 5).
    pub const CHECK_BOX: u32 = 1 << 5;
    /// OptionButton control (bit 6, cType 6).
    pub const OPTION_BUTTON: u32 = 1 << 6;
    /// ComboBox control (bit 7, cType 7).
    pub const COMBO_BOX: u32 = 1 << 7;
    /// ListBox control (bit 8, cType 8).
    pub const LIST_BOX: u32 = 1 << 8;
    /// HScrollBar control (bit 9, cType 9).
    pub const HSCROLL_BAR: u32 = 1 << 9;
    /// VScrollBar control (bit 10, cType 10).
    pub const VSCROLL_BAR: u32 = 1 << 10;
    /// Timer control (bit 11, cType 11).
    pub const TIMER: u32 = 1 << 11;

    /// Names for bits 0-11, indexed by bit position.
    const CONTROL_NAMES: [&str; 12] = [
        "PictureBox",
        "Label",
        "TextBox",
        "Frame",
        "CommandButton",
        "CheckBox",
        "OptionButton",
        "ComboBox",
        "ListBox",
        "HScrollBar",
        "VScrollBar",
        "Timer",
    ];

    /// Tests whether the given flag bit(s) are set.
    #[inline]
    pub fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Returns the names of all intrinsic controls used (bits 0-11 only).
    pub fn used_controls(self) -> Vec<&'static str> {
        Self::CONTROL_NAMES
            .iter()
            .enumerate()
            .filter(|(i, _)| self.0 & (1 << i) != 0)
            .map(|(_, name)| *name)
            .collect()
    }
}

impl fmt::Debug for IntrinsicControlFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "IntrinsicControlFlags(0x{:08X}", self.0)?;
        let controls = self.used_controls();
        if !controls.is_empty() {
            write!(f, " {}", controls.join(", "))?;
        }
        write!(f, ")")
    }
}

impl fmt::Display for IntrinsicControlFlags {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_object_type_real_module() {
        let flags = ObjectTypeFlags(0x00018001);
        assert!(flags.has_optional_info());
        assert!(flags.is_module());
        assert!(!flags.is_class());
        assert!(!flags.is_form());
        assert_eq!(flags.kind_name(), "Module");
    }

    #[test]
    fn test_object_type_real_class() {
        let flags = ObjectTypeFlags(0x00118003);
        assert!(flags.has_optional_info());
        assert!(flags.is_class());
        assert!(!flags.is_module());
        assert!(!flags.is_form());
        assert_eq!(flags.kind_name(), "Class");
    }

    #[test]
    fn test_object_type_real_form() {
        let flags = ObjectTypeFlags(0x00018083);
        assert!(flags.has_optional_info());
        assert!(flags.is_form());
        assert!(!flags.is_module());
        assert!(!flags.is_class());
        assert_eq!(flags.kind_name(), "Form");
    }

    #[test]
    fn test_object_type_low_byte_patterns() {
        // Low byte is the authoritative type indicator
        assert!(ObjectTypeFlags(0x01).is_module());
        assert!(ObjectTypeFlags(0x03).is_class());
        assert!(ObjectTypeFlags(0x83).is_form());
    }

    #[test]
    fn test_object_type_ocx_class() {
        // ActiveX OCX class (Band in ComCt332.ocx)
        let flags = ObjectTypeFlags(0x00118803);
        assert!(flags.is_class());
        assert!(flags.has(ObjectTypeFlags::ACTIVEX));
    }

    #[test]
    fn test_object_type_debug_format() {
        let flags = ObjectTypeFlags(0x00018083);
        let s = format!("{flags:?}");
        assert!(s.contains("Form"));
        assert!(s.contains("00018083"));
    }

    #[test]
    fn test_thread_flags() {
        let flags = ThreadFlags(0x05); // APARTMENT_MODEL | UNATTENDED
        assert!(flags.is_apartment_model());
        assert!(flags.is_unattended());
        assert!(!flags.is_single_threaded());
    }

    #[test]
    fn test_thread_flags_debug() {
        let flags = ThreadFlags(0x05);
        let s = format!("{flags:?}");
        assert!(s.contains("APARTMENT_MODEL"));
        assert!(s.contains("UNATTENDED"));
    }

    #[test]
    fn test_thread_flags_display() {
        let flags = ThreadFlags(0x05);
        let s = format!("{flags}");
        assert!(s.contains("APARTMENT_MODEL"));
        assert!(s.contains("UNATTENDED"));
    }

    #[test]
    fn test_flags_copy_eq() {
        let f1 = ObjectTypeFlags(0x00018001);
        let f2 = f1;
        assert_eq!(f1, f2);
    }

    #[test]
    fn test_intrinsic_control_flags() {
        // Real sample: 0x0030F80F = bits 0,1,2,3,11 + always-set 12-15,20-21
        let flags = IntrinsicControlFlags(0x0030F80F);
        assert!(flags.has(IntrinsicControlFlags::PICTURE_BOX));
        assert!(flags.has(IntrinsicControlFlags::LABEL));
        assert!(flags.has(IntrinsicControlFlags::TEXT_BOX));
        assert!(flags.has(IntrinsicControlFlags::FRAME));
        assert!(flags.has(IntrinsicControlFlags::TIMER));
        assert!(!flags.has(IntrinsicControlFlags::CHECK_BOX));

        let controls = flags.used_controls();
        assert!(controls.contains(&"PictureBox"));
        assert!(controls.contains(&"Timer"));
        assert!(!controls.contains(&"CheckBox"));
    }

    #[test]
    fn test_intrinsic_control_flags_none() {
        // Sample with no intrinsic controls: 0x0030F000 = only always-set bits
        let flags = IntrinsicControlFlags(0x0030F000);
        assert!(flags.used_controls().is_empty());
    }

    #[test]
    fn test_intrinsic_control_flags_debug() {
        let flags = IntrinsicControlFlags(0x0030F80F);
        let s = format!("{flags:?}");
        assert!(s.contains("PictureBox"));
        assert!(s.contains("Timer"));
    }
}
