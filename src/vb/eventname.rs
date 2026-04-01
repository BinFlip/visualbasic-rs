//! Event name template for VB6 intrinsic control event sink vtables.
//!
//! Most VB6 intrinsic controls share a standard 24-event template that
//! defines the slot ordering in the [`EventSinkVtable`](crate::vb::events::EventSinkVtable).
//! The template was extracted from the MSVBVM60.DLL runtime descriptor at
//! 0x660165F8.
//!
//! The event templates and lookup tables are generated at build time from
//! `data/vb6_events.csv`.

use crate::vb::{control::generated, formdata::FormControlType};

/// Returns the event name for a given slot index and control type.
///
/// Most controls use the standard 24-event template. Exceptions:
/// - **Timer**: slot 0 = "Timer" (not "Click")
/// - **Form/MDIForm/UserDocument**: uses form lifecycle events
///
/// Returns `None` if the slot is out of range for the control type.
pub fn event_name(slot: u16, ctype: FormControlType) -> Option<&'static str> {
    match ctype {
        FormControlType::Timer => {
            // Check timer-specific overrides first
            for &(s, name) in generated::TIMER_EVENTS {
                if s == slot as usize {
                    return Some(name);
                }
            }
            // Fall back to standard template
            generated::STANDARD_EVENTS.get(slot as usize).copied()
        }
        FormControlType::Form | FormControlType::MDIForm | FormControlType::UserDocument => {
            generated::FORM_EVENTS.get(slot as usize).copied()
        }
        FormControlType::UserControl => {
            // Slots 0-23 use the standard template, 24+ use UserControl extras
            if (slot as usize) < generated::STANDARD_EVENTS.len() {
                generated::STANDARD_EVENTS.get(slot as usize).copied()
            } else {
                let extra_slot = slot as usize - generated::STANDARD_EVENTS.len();
                generated::USERCONTROL_EVENTS.get(extra_slot).copied()
            }
        }
        _ => generated::STANDARD_EVENTS.get(slot as usize).copied(),
    }
}

/// Returns a standard event name for a slot without requiring a control type.
///
/// Uses the standard 24-event template shared by all intrinsic controls.
/// This is a best-effort fallback for when the [`FormControlType`] cannot
/// be determined (GUID unrecognized, no form binary data).
///
/// Note: this will produce incorrect names for Timer slot 0 ("Click" instead
/// of "Timer") and for Form/MDIForm lifecycle events. Prefer [`event_name`]
/// when the control type is known.
///
/// Returns `None` if the slot is out of range (>= 24).
pub fn standard_event_name(slot: u16) -> Option<&'static str> {
    generated::STANDARD_EVENTS.get(slot as usize).copied()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_template_click() {
        assert_eq!(event_name(0, FormControlType::CommandButton), Some("Click"));
    }

    #[test]
    fn test_standard_template_keypress() {
        assert_eq!(event_name(6, FormControlType::TextBox), Some("KeyPress"));
    }

    #[test]
    fn test_timer_exception() {
        assert_eq!(event_name(0, FormControlType::Timer), Some("Timer"));
        // Timer slot 1+ falls back to standard template
        assert_eq!(event_name(1, FormControlType::Timer), Some("DblClick"));
    }

    #[test]
    fn test_form_lifecycle() {
        assert_eq!(event_name(0, FormControlType::Form), Some("Activate"));
        assert_eq!(event_name(4, FormControlType::Form), Some("Load"));
        assert_eq!(event_name(7, FormControlType::Form), Some("Unload"));
    }

    #[test]
    fn test_usercontrol_standard_slots() {
        assert_eq!(event_name(0, FormControlType::UserControl), Some("Click"));
        assert_eq!(
            event_name(6, FormControlType::UserControl),
            Some("KeyPress")
        );
    }

    #[test]
    fn test_usercontrol_extra_slots() {
        assert_eq!(
            event_name(24, FormControlType::UserControl),
            Some("ReadProperties")
        );
        assert_eq!(
            event_name(29, FormControlType::UserControl),
            Some("AmbientChanged")
        );
        assert_eq!(
            event_name(32, FormControlType::UserControl),
            Some("AccessKeyPress")
        );
        assert_eq!(
            event_name(36, FormControlType::UserControl),
            Some("AsyncReadProgress")
        );
    }

    #[test]
    fn test_out_of_range() {
        assert_eq!(event_name(24, FormControlType::Label), None);
        assert_eq!(event_name(8, FormControlType::Form), None);
        assert_eq!(event_name(37, FormControlType::UserControl), None);
    }

    #[test]
    fn test_standard_event_name_fallback() {
        assert_eq!(standard_event_name(0), Some("Click"));
        assert_eq!(standard_event_name(6), Some("KeyPress"));
        assert_eq!(standard_event_name(24), None);
    }
}
