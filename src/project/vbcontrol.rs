//! GUI control representation with resolved metadata.
//!
//! In VB6, controls are GUI elements placed on forms (buttons, text boxes,
//! list boxes, etc.). Each control has a [`ControlInfo`](crate::vb::control::ControlInfo)
//! structure in the binary that stores its type, event count, name VA, GUID VA,
//! and event handler table VA.
//!
//! [`VbControl`] wraps a raw `ControlInfo` with resolved name, GUID, class
//! identification, and event handler VAs for convenient access.

use std::borrow::Cow;

use crate::{
    addressmap::AddressMap,
    error::Error,
    util::{read_cstr, read_u32_le},
    vb::{
        control::{ControlInfo, Guid},
        events::EventSinkVtable,
        formdata::{FormControlType, FormDataParser},
    },
};

/// A GUI control on a VB6 form with resolved metadata.
///
/// Constructed by [`ControlEntryIterator`], which resolves the raw
/// [`ControlInfo`] pointers into usable name, GUID, and event table slices.
#[derive(Debug)]
pub struct VbControl<'a> {
    /// Underlying raw ControlInfo structure.
    info: ControlInfo<'a>,
    /// Null-terminated control name (e.g., `"Command1"`).
    name: &'a [u8],
    /// COM CLSID identifying the control class; `None` if the GUID VA was
    /// null or could not be resolved.
    guid: Option<Guid>,
    /// Raw byte slice over the event handler VA table (4 bytes per event).
    /// Empty if the control has no events or the table VA was null.
    event_handler_vas: &'a [u8],
    /// Authoritative control type from form binary data (`cType` byte).
    ///
    /// When available, this is more reliable than GUID-based identification
    /// (GUID fuzzy matching fails for malware samples — 8/12 controls
    /// misidentified in the vb_inject sample).
    form_control_type: Option<FormControlType>,
}

impl<'a> VbControl<'a> {
    /// Returns the underlying [`ControlInfo`] structure.
    #[inline]
    pub fn info(&self) -> &ControlInfo<'a> {
        &self.info
    }

    /// The control's name as a lossy UTF-8 string (e.g., `"Command1"`,
    /// `"txtName"`).
    ///
    /// Borrows when the underlying bytes are already valid UTF-8 (the
    /// common case). Use [`name_bytes`](Self::name_bytes) for the raw
    /// bytes.
    #[inline]
    pub fn name(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.name)
    }

    /// The control's name as raw bytes from the PE image.
    #[inline]
    pub fn name_bytes(&self) -> &'a [u8] {
        self.name
    }

    /// Control type flags.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying ControlInfo field cannot be read.
    #[inline]
    pub fn control_type(&self) -> Result<u32, Error> {
        self.info.control_type()
    }

    /// Number of event handler slots on this control.
    ///
    /// This is the number of entries in the event sink vtable at +0x18,
    /// NOT the dispatch_offset at +0x04 (which is a byte offset, not a count).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying ControlInfo field cannot be read.
    #[inline]
    pub fn event_count(&self) -> Result<u16, Error> {
        self.info.event_handler_slots()
    }

    /// Control index within the form.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying ControlInfo field cannot be read.
    #[inline]
    pub fn index(&self) -> Result<u16, Error> {
        self.info.index()
    }

    /// The control's COM CLSID, if the GUID VA could be resolved.
    #[inline]
    pub fn guid(&self) -> Option<&Guid> {
        self.guid.as_ref()
    }

    /// Returns the authoritative control type from form binary data.
    ///
    /// This is the most reliable type identification, derived from the
    /// `cType` byte in the form binary data. Returns `None` when form
    /// data is not available (e.g., native-compiled modules without forms).
    #[inline]
    pub fn form_control_type(&self) -> Option<FormControlType> {
        self.form_control_type
    }

    /// Returns the control class name (e.g., `"CommandButton"`, `"TextBox"`).
    ///
    /// Resolution order:
    /// 1. Form binary data `cType` (authoritative, from [`form_control_type`](Self::form_control_type))
    /// 2. GUID fuzzy matching (fallback, unreliable for malware)
    /// 3. `None` for unidentifiable controls
    pub fn class_name(&self) -> Option<&'static str> {
        if let Some(fct) = self.form_control_type {
            return Some(fct.name());
        }
        self.guid.as_ref().and_then(|g| g.control_class_name())
    }

    /// Returns the VA of the event handler at `event_index`.
    ///
    /// A return value of `0` means the event is not handled.
    /// A non-zero VA points to the handler stub (P-Code or native).
    pub fn event_handler_va(&self, event_index: u16) -> Option<u32> {
        let offset = (event_index as usize).checked_mul(4)?;
        let end = offset.checked_add(4)?;
        if end > self.event_handler_vas.len() {
            return None;
        }
        read_u32_le(self.event_handler_vas, offset).ok()
    }

    /// Resolves and returns the control's [`EventSinkVtable`].
    ///
    /// The event sink vtable contains back-pointers, IUnknown thunks,
    /// and per-event handler VAs. Returns `None` if the vtable VA is
    /// null or cannot be resolved.
    pub fn event_sink<'p>(&self, map: &'p AddressMap<'a>) -> Option<EventSinkVtable<'a>> {
        let va = self.info.event_sink_vtable_va().ok()?;
        if va == 0 {
            return None;
        }
        let slots = self.info.event_handler_slots().ok()?;
        let size = EventSinkVtable::HEADER_SIZE.checked_add((slots as usize).checked_mul(4)?)?;
        let data = map.slice_from_va(va, size).ok()?;
        EventSinkVtable::parse(data, slots).ok()
    }

    /// Returns the number of events with handler VAs connected.
    ///
    /// # Errors
    ///
    /// Returns an error if the event handler slot count cannot be read.
    pub fn connected_event_count(&self) -> Result<u16, Error> {
        let mut count: u16 = 0;
        for i in 0..self.event_count()? {
            if self.event_handler_va(i).is_some_and(|va| va != 0) {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }
}

/// Iterator over controls on a VB6 object (form).
///
/// Walks the control array starting at `controls_va` from the
/// [`OptionalObjectInfo`](crate::vb::object::OptionalObjectInfo), resolving
/// each entry into a [`VbControl`] with name, GUID, and event handler table.
///
/// When form binary data is available (via [`with_form_data`](Self::with_form_data)),
/// each control's [`form_control_type`](VbControl::form_control_type) is populated
/// with the authoritative `cType` byte from the form data.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ControlEntryIterator<'a, 'p> {
    /// Address map for VA resolution.
    map: &'p AddressMap<'a>,
    /// Base VA of the control array.
    controls_va: u32,
    /// Current zero-based position in the array.
    index: u32,
    /// Total number of controls on the form.
    total: u32,
    /// Optional form data for authoritative control type identification.
    form_data: Option<&'p FormDataParser<'a>>,
}

impl<'a, 'p> ControlEntryIterator<'a, 'p> {
    /// Creates a new iterator over controls starting at `controls_va`.
    pub fn new(map: &'p AddressMap<'a>, controls_va: u32, total: u32) -> Self {
        Self {
            map,
            controls_va,
            index: 0,
            total,
            form_data: None,
        }
    }

    /// Attaches parsed form binary data for authoritative control type resolution.
    ///
    /// When set, each yielded [`VbControl`] will have its
    /// [`form_control_type`](VbControl::form_control_type) populated by matching
    /// `ControlInfo.index` to `FormControlRecord.cid`.
    pub fn with_form_data(mut self, form_data: &'p FormDataParser<'a>) -> Self {
        self.form_data = Some(form_data);
        self
    }
}

impl<'a, 'p> Iterator for ControlEntryIterator<'a, 'p> {
    type Item = Result<VbControl<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.total || self.controls_va == 0 {
            return None;
        }

        let offset = self.index.saturating_mul(ControlInfo::MIN_SIZE as u32);
        let entry_va = self.controls_va.wrapping_add(offset);
        self.index = self.index.saturating_add(1);

        let data = match self.map.slice_from_va(entry_va, ControlInfo::MIN_SIZE) {
            Ok(d) => d,
            Err(e) => return Some(Err(e)),
        };

        let info = match ControlInfo::parse(data) {
            Ok(c) => c,
            Err(e) => return Some(Err(e)),
        };

        let name_va = match info.name_va() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let name: &[u8] = if name_va != 0 {
            let off = match self.map.va_to_offset(name_va) {
                Ok(o) => o,
                Err(e) => return Some(Err(e)),
            };
            match read_cstr(self.map.file(), off) {
                Ok(s) => s,
                Err(e) => return Some(Err(e)),
            }
        } else {
            b""
        };

        let guid_va = match info.guid_va() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let guid = if guid_va != 0 {
            self.map
                .slice_from_va(guid_va, 16)
                .ok()
                .and_then(Guid::from_bytes)
        } else {
            None
        };

        let dispid_va = match info.dispid_count_or_zero() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let slots = match info.event_handler_slots() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };
        let event_handler_vas: &[u8] = if dispid_va != 0 && slots > 0 {
            let size = (slots as usize).saturating_mul(4);
            self.map.slice_from_va(dispid_va, size).unwrap_or(b"")
        } else {
            b""
        };

        let info_index = match info.index() {
            Ok(v) => v,
            Err(e) => return Some(Err(e)),
        };

        // Look up authoritative control type from form data
        let form_control_type = self.form_data.and_then(|fd| {
            fd.control_by_id(info_index as u8)
                .map(|fc| fc.control_type())
        });

        Some(Ok(VbControl {
            info,
            name,
            guid,
            event_handler_vas,
            form_control_type,
        }))
    }
}
