//! COM registration data (tagREGDATA) parser.
//!
//! The COM registration data is pointed to by `VBHeader.lpComRegisterData`
//! (+0x54). It contains the project's TypeLib GUID, version, and a linked
//! list of per-object COM registration records with CLSIDs, ProgIDs,
//! interface GUIDs, and registry metadata.
//!
//! All offsets within this structure are **self-relative** — add the
//! offset value to the structure's base VA to resolve.
//!
//! # Layout verified against
//!
//! - MSVBVM60.DLL `sub_66030AC0` (COM registration orchestrator)
//! - MSVBVM60.DLL `sub_660BC263` (per-object CLSID/ProgID registration)

use std::str;

use crate::{
    addressmap::AddressMap,
    error::Error,
    util::{read_cstr, read_u16_le, read_u32_le},
    vb::control::Guid,
};

/// COM registration data header (0x30 bytes minimum, followed by strings).
///
/// # Header Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `bFirstObject` (self-relative offset to first [`ComRegObject`]; 0 = none) |
/// | 0x04 | 4 | `bszProjectName` (self-relative offset to project name string) |
/// | 0x08 | 4 | `bszHelpDir` (self-relative offset to help directory; 0 = none) |
/// | 0x0C | 4 | `bszDescription` (self-relative offset to app description; 0 = none) |
/// | 0x10 | 16 | `uuidProject` (project/TypeLib GUID) |
/// | 0x20 | 4 | `dwLcid` (TypeLib locale ID) |
/// | 0x24 | 2 | `wRegFlags` (TypeLib registration flags) |
/// | 0x26 | 2 | `wMajorVer` (TypeLib major version) |
/// | 0x28 | 2 | `wMinorVer` (TypeLib minor version) |
#[derive(Clone, Copy, Debug)]
pub struct ComRegData<'a> {
    bytes: &'a [u8],
    base_va: u32,
}

impl<'a> ComRegData<'a> {
    /// Minimum header size in bytes.
    pub const HEADER_SIZE: usize = 0x2A;

    /// Parses the COM registration data header.
    ///
    /// `base_va` is the VA of the structure in the PE image (needed for
    /// resolving self-relative offsets via the address map).
    pub fn parse(data: &'a [u8], base_va: u32) -> Result<Self, Error> {
        if data.len() < Self::HEADER_SIZE {
            return Err(Error::TooShort {
                expected: Self::HEADER_SIZE,
                actual: data.len(),
                context: "ComRegData",
            });
        }
        Ok(Self {
            bytes: data,
            base_va,
        })
    }

    /// Self-relative offset to the first per-object registration record.
    ///
    /// Returns 0 if there are no COM objects to register (common for EXE
    /// files; ActiveX DLLs/OCXs will have non-zero offsets).
    #[inline]
    pub fn first_object_offset(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x00)
    }

    /// Self-relative offset to the project name string.
    #[inline]
    pub fn project_name_offset(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x04)
    }

    /// Self-relative offset to the help directory string (0 = none).
    ///
    /// Used by the compiler for the `\HELPDIR = ...` registry entry.
    #[inline]
    pub fn help_dir_offset(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x08)
    }

    /// Self-relative offset to the app description string (0 = none).
    ///
    /// Used by the compiler for the `APPDESCRIPTION=...` entry.
    #[inline]
    pub fn description_offset(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x0C)
    }

    /// Project/TypeLib GUID at offset 0x10.
    pub fn project_guid(&self) -> Option<Guid> {
        Guid::from_bytes(self.bytes.get(0x10..0x20)?)
    }

    /// TypeLib locale ID at offset 0x20.
    #[inline]
    pub fn lcid(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x20)
    }

    /// TypeLib registration flags at offset 0x24.
    ///
    /// Passed through to TypeLib registration APIs in `sub_66030AC0`. Maps to
    /// `TLIBATTR.wLibFlags` semantics from COM:
    ///
    /// | Value | COM constant | Meaning |
    /// |-------|-------------|---------|
    /// | 0x01 | `LIBFLAG_FRESTRICTED` | Type library is restricted |
    /// | 0x02 | `LIBFLAG_FCONTROL` | Library describes controls |
    /// | 0x04 | `LIBFLAG_FHIDDEN` | Library should not be displayed |
    #[inline]
    pub fn reg_flags(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x24)
    }

    /// TypeLib major version at offset 0x26.
    #[inline]
    pub fn major_version(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x26)
    }

    /// TypeLib minor version at offset 0x28.
    #[inline]
    pub fn minor_version(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x28)
    }

    /// Reads the project name string (resolved from self-relative offset).
    pub fn project_name(&self, map: &AddressMap<'a>) -> Option<&'a str> {
        let off = self.project_name_offset().ok()?;
        if off == 0 {
            return None;
        }
        let data = map
            .slice_from_va(self.base_va.wrapping_add(off), 256)
            .ok()?;
        let name = read_cstr(data, 0).ok()?;
        if name.is_empty() {
            return None;
        }
        str::from_utf8(name).ok()
    }

    /// Reads the help directory string (resolved from self-relative offset).
    ///
    /// This is the HELPDIR value used for TypeLib registration.
    pub fn help_dir(&self, map: &AddressMap<'a>) -> Option<&'a str> {
        let off = self.help_dir_offset().ok()?;
        if off == 0 {
            return None;
        }
        let data = map
            .slice_from_va(self.base_va.wrapping_add(off), 256)
            .ok()?;
        let name = read_cstr(data, 0).ok()?;
        if name.is_empty() {
            return None;
        }
        str::from_utf8(name).ok()
    }

    /// Base VA of the structure in the PE image.
    #[inline]
    pub fn base_va(&self) -> u32 {
        self.base_va
    }

    /// Computes the total extent of the COM registration blob.
    ///
    /// The blob is one contiguous allocation containing the header, inline
    /// strings (project name, help file, help dir), ComRegObject records,
    /// their strings, and GUID arrays. All offsets are self-relative from
    /// [`base_va`](Self::base_va).
    ///
    /// This method scans all self-relative offsets to find the highest
    /// referenced address and returns the total size from the base.
    pub fn total_size(&self, map: &AddressMap<'a>) -> Result<usize, Error> {
        let mut max_end = Self::HEADER_SIZE as u32;

        // ComRegData string offsets
        for off in [
            self.project_name_offset()?,
            self.help_dir_offset()?,
            self.description_offset()?,
        ] {
            if off != 0 {
                // Read the string to determine its length
                let str_end = map
                    .slice_from_va(self.base_va.wrapping_add(off), 256)
                    .ok()
                    .map(|d| {
                        let len = d.iter().position(|&b| b == 0).unwrap_or(0) as u32;
                        off.wrapping_add(len).wrapping_add(1)
                    })
                    .unwrap_or(off.wrapping_add(1));
                max_end = max_end.max(str_end);
            }
        }

        // Walk ComRegObject records
        for obj in self.objects(map)? {
            let obj_end = obj
                .va()
                .wrapping_sub(self.base_va)
                .wrapping_add(ComRegObject::SIZE as u32);
            max_end = max_end.max(obj_end);

            // Object strings
            for off in [obj.object_name_offset()?, obj.description_offset()?] {
                if off != 0 {
                    let str_end = map
                        .slice_from_va(self.base_va.wrapping_add(off), 256)
                        .ok()
                        .map(|d| {
                            let len = d.iter().position(|&b| b == 0).unwrap_or(0) as u32;
                            off.wrapping_add(len).wrapping_add(1)
                        })
                        .unwrap_or(off.wrapping_add(1));
                    max_end = max_end.max(str_end);
                }
            }

            // GUID arrays
            let di_off = obj.default_iface_guids_offset()?;
            if di_off != 0 {
                max_end =
                    max_end.max(di_off.wrapping_add(obj.default_iface_count()?.wrapping_mul(16)));
            }
            let si_off = obj.source_iface_guids_offset()?;
            if si_off != 0 {
                max_end =
                    max_end.max(si_off.wrapping_add(obj.source_iface_count()?.wrapping_mul(16)));
            }
        }

        Ok(max_end as usize)
    }

    /// Returns `true` if there are per-object COM registration records.
    #[inline]
    pub fn has_objects(&self) -> Result<bool, Error> {
        Ok(self.first_object_offset()? != 0)
    }

    /// Returns an iterator over per-object COM registration records.
    ///
    /// # Errors
    ///
    /// Returns an error if the first-object offset header field cannot be
    /// read from the backing buffer.
    pub fn objects(&self, map: &'a AddressMap<'a>) -> Result<ComRegObjectIter<'a>, Error> {
        Ok(ComRegObjectIter {
            map,
            base_va: self.base_va,
            next_offset: self.first_object_offset()?,
        })
    }
}

/// Per-object COM registration record (0x40 bytes minimum).
///
/// Forms a linked list via self-relative offsets. Each record describes
/// one COM-creatable class with its CLSID, ProgID components, interface
/// GUIDs, and registry flags.
///
/// # Layout
///
/// | Offset | Size | Field |
/// |--------|------|-------|
/// | 0x00 | 4 | `bNextObject` (self-relative offset to next record; 0 = last) |
/// | 0x04 | 4 | `bszObjectName` (self-relative offset to class name for ProgID) |
/// | 0x08 | 4 | `bszDescription` (self-relative offset to display name; 0 = use ProgID) |
/// | 0x0C | 4 | `dwRegFlag` (non-zero = register InprocServer32/LocalServer32) |
/// | 0x10 | 4 | Reserved |
/// | 0x14 | 16 | `uuidObject` (CLSID of this COM class) |
/// | 0x24 | 4 | `dwDefaultIfaceCount` (number of default interface GUIDs) |
/// | 0x28 | 4 | `bDefaultIfaceGuids` (self-relative offset to GUID array) |
/// | 0x2C | 4 | `bSourceIfaceGuids` (self-relative offset to event interface GUID array) |
/// | 0x30 | 4 | `dwSourceIfaceCount` (number of event interface GUIDs) |
/// | 0x34 | 4 | `dwMiscStatus` (OLE MiscStatus value for DVASPECT\_CONTENT) |
/// | 0x38 | 2 | `wObjectFlags` (registration flags — see [`ComRegObject::object_flags`]) |
/// | 0x3A | 2 | `wToolboxBitmap32` (resource ID for ToolboxBitmap32) |
/// | 0x3C | 2 | `wDefaultIcon` (resource ID for DefaultIcon) |
/// | 0x3E | 2 | `wExtendedFlags` (bit 0 = has designer data at +0x40) |
/// | 0x40 | 4 | `bDesignerData` (self-relative offset; only if extended flag bit 0) |
#[derive(Clone, Copy, Debug)]
pub struct ComRegObject<'a> {
    bytes: &'a [u8],
    base_va: u32,
    /// VA of this record in the PE image.
    va: u32,
}

impl<'a> ComRegObject<'a> {
    /// Record size in bytes (0x40).
    ///
    /// The runtime reads all fields through `+0x3E` (wExtendedFlags).
    /// For non-ActiveX objects, fields like `dwMiscStatus` at +0x34 may
    /// contain residual string data from the linker, but the struct size
    /// is fixed at 0x40. The +0x40 `bDesignerData` field is conditional
    /// (present only when `wExtendedFlags & 1`).
    pub const SIZE: usize = 0x40;

    /// Parses a per-object registration record.
    pub fn parse(data: &'a [u8], base_va: u32, va: u32) -> Result<Self, Error> {
        if data.len() < Self::SIZE {
            return Err(Error::TooShort {
                expected: Self::SIZE,
                actual: data.len(),
                context: "ComRegObject",
            });
        }
        Ok(Self {
            bytes: data,
            base_va,
            va,
        })
    }

    /// VA of this record in the PE image.
    #[inline]
    pub fn va(&self) -> u32 {
        self.va
    }

    /// Self-relative offset to next record (0 = last).
    #[inline]
    pub fn next_offset(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x00)
    }

    /// Self-relative offset to the object name string at +0x04.
    #[inline]
    pub fn object_name_offset(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x04)
    }

    /// Self-relative offset to the description string at +0x08.
    #[inline]
    pub fn description_offset(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x08)
    }

    /// Reads the object/class name (second component of ProgID = `Project.ClassName`).
    pub fn object_name(&self, map: &AddressMap<'a>) -> Option<&'a str> {
        let off = self.object_name_offset().ok()?;
        if off == 0 {
            return None;
        }
        let data = map
            .slice_from_va(self.base_va.wrapping_add(off), 256)
            .ok()?;
        let name = read_cstr(data, 0).ok()?;
        if name.is_empty() {
            return None;
        }
        str::from_utf8(name).ok()
    }

    /// Reads the description/display name string.
    pub fn description(&self, map: &AddressMap<'a>) -> Option<&'a str> {
        let off = self.description_offset().ok()?;
        if off == 0 {
            return None;
        }
        let data = map
            .slice_from_va(self.base_va.wrapping_add(off), 256)
            .ok()?;
        let name = read_cstr(data, 0).ok()?;
        if name.is_empty() {
            return None;
        }
        str::from_utf8(name).ok()
    }

    /// Registration flag at offset 0x0C.
    ///
    /// Non-zero = create `InprocServer32`/`LocalServer32` subkey.
    /// Zero = delete the server subkey (unregistration).
    #[inline]
    pub fn reg_flag(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x0C)
    }

    /// Object CLSID at offset 0x14 (16-byte GUID).
    pub fn clsid(&self) -> Option<Guid> {
        Guid::from_bytes(self.bytes.get(0x14..0x24)?)
    }

    /// Number of default interface GUIDs at offset 0x24.
    #[inline]
    pub fn default_iface_count(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x24)
    }

    /// Self-relative offset to the default interface GUID array at offset 0x28.
    ///
    /// Each entry is a 16-byte GUID. Use [`default_iface_count`](Self::default_iface_count)
    /// for the array length.
    #[inline]
    pub fn default_iface_guids_offset(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x28)
    }

    /// Self-relative offset to the source/event interface GUID array at offset 0x2C.
    #[inline]
    pub fn source_iface_guids_offset(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x2C)
    }

    /// Number of source/event interface GUIDs at offset 0x30.
    #[inline]
    pub fn source_iface_count(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x30)
    }

    /// OLE MiscStatus value at offset 0x34.
    ///
    /// Written as decimal to `CLSID\{...}\MiscStatus\1` registry key.
    #[inline]
    pub fn misc_status(&self) -> Result<u32, Error> {
        read_u32_le(self.bytes, 0x34)
    }

    /// Object registration flags at offset 0x38.
    ///
    /// Controls which registry keys are written during COM registration
    /// (`sub_660BC263` in MSVBVM60.DLL). The runtime reads both the low and
    /// high bytes of this u16:
    ///
    /// | Bit | Mask | Registry action |
    /// |-----|------|----------------|
    /// | 0 | `0x0001` | Skip registration (return immediately) |
    /// | 1 | `0x0002` | Register `IPersistPropertyBag` CATID |
    /// | 2 | `0x0004` | Register safe-for-scripting CATID |
    /// | 5 | `0x0020` | Control — `Control` subkey, `ToolboxBitmap32` |
    /// | 7 | `0x0080` | DocObject — `DocObject`, `DefaultIcon`, `InprocHandler32`, `BrowserFlags`, `EditFlags` |
    ///
    /// Composite masks used by the runtime:
    /// - `0x00B2` (bits 1,4,5,7): Automatable — `ProgID`, `TypeLib`, `VERSION`, interface registration
    /// - `0x00A0` (bits 5,7): Control or DocObject — `MiscStatus`, `MiscStatus\1`
    #[inline]
    pub fn object_flags(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x38)
    }

    /// ToolboxBitmap32 resource ID at offset 0x3A.
    ///
    /// Written as `"module.dll, <id>"` to the `ToolboxBitmap32` subkey.
    #[inline]
    pub fn toolbox_bitmap_id(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x3A)
    }

    /// DefaultIcon resource ID at offset 0x3C.
    ///
    /// Written as `"module.dll, <id>"` to the `DefaultIcon` subkey.
    #[inline]
    pub fn default_icon_id(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x3C)
    }

    /// Extended flags at offset 0x3E.
    ///
    /// Bit 0 = has designer data at +0x40 (only if `VBHeader+0x22 >= 8`).
    #[inline]
    pub fn extended_flags(&self) -> Result<u16, Error> {
        read_u16_le(self.bytes, 0x3E)
    }

    /// Returns `true` if this is marked as a Control (flag bit 5).
    #[inline]
    pub fn is_control(&self) -> Result<bool, Error> {
        Ok(self.object_flags()? & 0x0020 != 0)
    }

    /// Returns `true` if this is a DocObject (flag bit 7).
    #[inline]
    pub fn is_doc_object(&self) -> Result<bool, Error> {
        Ok(self.object_flags()? & 0x0080 != 0)
    }

    /// Returns `true` if this object registers a ProgID and interfaces (flags & 0xB2).
    #[inline]
    pub fn is_automatable(&self) -> Result<bool, Error> {
        Ok(self.object_flags()? & 0x00B2 != 0)
    }

    /// Reads default interface GUIDs from the GUID array.
    ///
    /// # Errors
    ///
    /// Returns an error if the count or offset header fields cannot be read.
    pub fn default_iface_guids(&self, map: &AddressMap<'a>) -> Result<Vec<Guid>, Error> {
        Ok(self.read_guid_array(
            map,
            self.default_iface_guids_offset()?,
            self.default_iface_count()?,
        ))
    }

    /// Reads source/event interface GUIDs from the GUID array.
    ///
    /// # Errors
    ///
    /// Returns an error if the count or offset header fields cannot be read.
    pub fn source_iface_guids(&self, map: &AddressMap<'a>) -> Result<Vec<Guid>, Error> {
        Ok(self.read_guid_array(
            map,
            self.source_iface_guids_offset()?,
            self.source_iface_count()?,
        ))
    }

    fn read_guid_array(&self, map: &AddressMap<'a>, offset: u32, count: u32) -> Vec<Guid> {
        if offset == 0 || count == 0 {
            return Vec::new();
        }
        let va = self.base_va.wrapping_add(offset);
        let size = (count as usize).saturating_mul(16);
        let Ok(data) = map.slice_from_va(va, size) else {
            return Vec::new();
        };
        (0..count as usize)
            .filter_map(|i| {
                let start = i.saturating_mul(16);
                let end = start.saturating_add(16);
                Guid::from_bytes(data.get(start..end)?)
            })
            .collect()
    }
}

/// Iterator over per-object COM registration records.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ComRegObjectIter<'a> {
    map: &'a AddressMap<'a>,
    base_va: u32,
    next_offset: u32,
}

impl<'a> Iterator for ComRegObjectIter<'a> {
    type Item = ComRegObject<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_offset == 0 {
            return None;
        }
        let va = self.base_va.wrapping_add(self.next_offset);
        let data = self.map.slice_from_va(va, ComRegObject::SIZE).ok()?;
        let obj = ComRegObject::parse(data, self.base_va, va).ok()?;
        self.next_offset = obj.next_offset().ok()?;
        Some(obj)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_header() {
        let mut data = vec![0u8; 0x30];
        // bFirstObject = 0 (no objects)
        // bszProjectName = 0x30
        data[0x04..0x08].copy_from_slice(&0x30u32.to_le_bytes());
        // project GUID
        data[0x10..0x20].copy_from_slice(&[
            0x98, 0xF0, 0xDD, 0x2C, 0xC0, 0x58, 0xA4, 0x43, 0xBE, 0xB7, 0x64, 0xB3, 0x61, 0x53,
            0x57, 0x36,
        ]);
        // major version = 1
        data[0x26..0x28].copy_from_slice(&1u16.to_le_bytes());
        let reg = ComRegData::parse(&data, 0x00401000).unwrap();
        assert!(!reg.has_objects().unwrap());
        assert_eq!(reg.major_version().unwrap(), 1);
        assert_eq!(reg.minor_version().unwrap(), 0);
        assert!(reg.project_guid().is_some());
    }

    #[test]
    fn test_parse_too_short() {
        let data = vec![0u8; ComRegData::HEADER_SIZE - 1];
        assert!(matches!(
            ComRegData::parse(&data, 0),
            Err(Error::TooShort { .. })
        ));
    }
}
