//! Top-level VB6 project entry point.
//!
//! [`VbProject`] is the primary entry point for the library. It chains
//! together PE parsing, VB structure navigation, and P-Code access into
//! a single convenient type with lifetime `'a` tied to the file buffer.

use crate::{
    addressmap::AddressMap,
    entrypoint,
    error::Error,
    project::VbObject,
    util::read_cstr,
    vb::{
        external::{ExternalComponentIter, ExternalTableEntry},
        guitable::GuiTableIter,
        header::VbHeader,
        objecttable::ObjectTable,
        projectdata::ProjectData,
    },
};

/// A parsed VB6 project, borrowing from the original file bytes.
///
/// This is the primary entry point for the library. It provides typed,
/// access to all structures within a VB6 executable.
///
/// The `'a` lifetime ties the project to the underlying file buffer.
/// All data remains in the original buffer; no copies are made.
///
/// # Example
///
/// ```ignore
/// let data = std::fs::read("sample.exe")?;
/// let project = VbProject::from_bytes(&data)?;
///
/// for obj in project.objects() {
///     let obj = obj?;
///     println!("Object: {:?}", obj.name()?);
///     for method in obj.pcode_methods() {
///         let method = method?;
///         for insn in method.instructions() {
///             println!("  {}", insn?);
///         }
///     }
/// }
/// ```
#[derive(Debug)]
pub struct VbProject<'a> {
    /// VA-to-file-offset resolver built from PE section headers.
    map: AddressMap<'a>,
    /// VA of the VbHeader in the PE image.
    vb_header_va: u32,
    /// Root VBHeader (EXEPROJECTINFO) parsed from the entry point.
    vb_header: VbHeader<'a>,
    /// ProjectData structure referenced by the VBHeader.
    project_data: ProjectData<'a>,
    /// ObjectTable containing the array of public object descriptors.
    object_table: ObjectTable<'a>,
}

impl<'a> VbProject<'a> {
    /// Parses a VB6 executable from raw file bytes.
    ///
    /// Internally uses `goblin` to parse PE headers, then walks the
    /// VB6 structure chain from entry point through ObjectTable.
    ///
    /// # Arguments
    ///
    /// * `file` - The complete PE file contents as a byte slice.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The file is not a valid PE32 executable
    /// - The entry point does not match the VB6 pattern
    /// - The VB5! magic signature is not found
    ///
    /// Both P-Code and native-compiled VB6 binaries are accepted.
    /// Use [`is_pcode`](Self::is_pcode) to check which kind you have.
    pub fn from_bytes(file: &'a [u8]) -> Result<Self, Error> {
        let pe = goblin::pe::PE::parse(file)?;
        Self::from_goblin(file, &pe)
    }

    /// Parses a VB6 executable from a pre-parsed goblin PE.
    ///
    /// Use this when you already have a `goblin::pe::PE` from a larger
    /// analysis pipeline and want to avoid re-parsing the PE headers.
    ///
    /// # Arguments
    ///
    /// * `file` - The complete PE file contents as a byte slice.
    /// * `pe` - A reference to a goblin-parsed PE.
    ///
    /// # Errors
    ///
    /// Same as [`from_bytes`](Self::from_bytes), except PE parsing errors
    /// are not possible since the PE is already parsed.
    pub fn from_goblin(file: &'a [u8], pe: &goblin::pe::PE<'_>) -> Result<Self, Error> {
        let map = AddressMap::from_goblin(file, pe)?;

        // Extract VBHeader VA from the entry point
        let entry_rva = pe
            .header
            .optional_header
            .as_ref()
            .ok_or(Error::TooShort {
                expected: 1,
                actual: 0,
                context: "PE optional header",
            })?
            .standard_fields
            .address_of_entry_point;

        let vb_header_va = entrypoint::extract_vb_header_va(&map, entry_rva).or_else(|_| {
            entrypoint::extract_vb_header_va_from_exports(&map, &pe.exports)
                .ok_or(Error::VbHeaderNotFound)
        })?;

        // Parse VBHeader
        let vb_header_data = map.slice_from_va(vb_header_va, VbHeader::SIZE)?;
        let vb_header = VbHeader::parse(vb_header_data)?;

        // Parse ProjectData
        let pd_data = map.slice_from_va(vb_header.project_data_va(), ProjectData::SIZE)?;
        let project_data = ProjectData::parse(pd_data)?;

        // Parse ObjectTable
        let ot_data = map.slice_from_va(project_data.object_table_va(), ObjectTable::SIZE)?;
        let object_table = ObjectTable::parse(ot_data)?;

        Ok(Self {
            map,
            vb_header_va,
            vb_header,
            project_data,
            object_table,
        })
    }

    /// Returns the VA of the [`VbHeader`] structure in the PE image.
    #[inline]
    pub fn vb_header_va(&self) -> u32 {
        self.vb_header_va
    }

    /// Returns a reference to the [`VbHeader`] (EXEPROJECTINFO).
    #[inline]
    pub fn vb_header(&self) -> &VbHeader<'a> {
        &self.vb_header
    }

    /// Returns a reference to the [`ProjectData`] structure.
    #[inline]
    pub fn project_data(&self) -> &ProjectData<'a> {
        &self.project_data
    }

    /// Returns a reference to the [`ObjectTable`].
    #[inline]
    pub fn object_table(&self) -> &ObjectTable<'a> {
        &self.object_table
    }

    /// Returns a reference to the [`AddressMap`] for manual VA resolution.
    #[inline]
    pub fn address_map(&self) -> &AddressMap<'a> {
        &self.map
    }

    /// Returns `true` if the binary is P-Code compiled.
    ///
    /// When `false`, the binary is native x86 compiled and P-Code
    /// method iteration will yield no instructions, but all VB6
    /// metadata structures are still accessible.
    #[inline]
    pub fn is_pcode(&self) -> bool {
        self.project_data.is_pcode()
    }

    /// Reads the project name from the ObjectTable.
    ///
    /// # Errors
    ///
    /// Returns an error if the project name VA cannot be resolved.
    pub fn project_name(&self) -> Result<&'a [u8], Error> {
        self.read_string_at_va(self.object_table.project_name_va())
    }

    /// Returns the total number of objects in the project.
    #[inline]
    pub fn object_count(&self) -> u16 {
        self.object_table.total_objects()
    }

    /// Returns an iterator over all objects in the project.
    ///
    /// Each item is a `Result<VbObject<'a>, Error>` because resolving
    /// each object requires VA translation that can fail.
    pub fn objects(&self) -> ObjectIterator<'a, '_> {
        ObjectIterator {
            project: self,
            index: 0,
            total: self.object_table.total_objects(),
        }
    }

    /// Returns an iterator over external component references.
    ///
    /// External components are COM/OCX libraries referenced by the project,
    /// listed in `ProjectData.external_table_va()`.
    pub fn externals(&self) -> ExternalIterator<'a, '_> {
        ExternalIterator {
            map: &self.map,
            table_va: self.project_data.external_table_va(),
            index: 0,
            total: self.project_data.external_count(),
        }
    }

    /// Returns an iterator over OCX/ActiveX component entries.
    ///
    /// These are variable-length entries from `VBHeader.external_table_va`
    /// describing referenced OCX controls (e.g., Tabctl32.ocx SSTab,
    /// Comctl32.ocx StatusBar). Each entry has the OCX filename, ProgID,
    /// class name, and event handler names.
    ///
    /// This is separate from [`externals()`](Self::externals) which iterates
    /// Declare function imports from `ProjectData.external_table_va`.
    pub fn components(&self) -> ExternalComponentIter<'a> {
        let table_va = self.vb_header.external_table_va();
        let count = self.vb_header.external_count();
        if table_va == 0 || count == 0 {
            return ExternalComponentIter::new(&[], 0);
        }
        // Read enough data for the full table (estimate max entry size)
        let max_size = count as usize * 0x400; // 1KB per entry max estimate
        let data = self.map.slice_from_va(table_va, max_size).unwrap_or(&[]);
        ExternalComponentIter::new(data, count)
    }

    /// Iterates over GUI table entries (one per form/UserControl/MDIForm).
    ///
    /// The GUI table is pointed to by `VBHeader.lpGuiTable` (+0x4C) with
    /// `VBHeader.wFormCount` (+0x44) entries.
    pub fn gui_entries(&self) -> GuiTableIter<'_> {
        GuiTableIter::new(
            &self.map,
            self.vb_header.gui_table_va(),
            self.vb_header.form_count(),
        )
    }

    /// Reads a null-terminated string at the given VA.
    ///
    /// # Errors
    ///
    /// Returns an error if the VA cannot be translated.
    pub fn read_string_at_va(&self, va: u32) -> Result<&'a [u8], Error> {
        if va == 0 {
            return Ok(b"");
        }
        let offset = self.map.va_to_offset(va)?;
        Ok(read_cstr(self.map.file(), offset))
    }
}

/// Iterator over external component table entries.
///
/// Yields one [`ExternalTableEntry`] per COM/OCX library referenced by the
/// project, walking the table starting at `ProjectData.external_table_va()`.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ExternalIterator<'a, 'p> {
    /// Address map for VA resolution.
    map: &'p AddressMap<'a>,
    /// Base VA of the external component table.
    table_va: u32,
    /// Current zero-based position in the table.
    index: u32,
    /// Total number of entries in the table.
    total: u32,
}

impl<'a, 'p> Iterator for ExternalIterator<'a, 'p> {
    type Item = Result<ExternalTableEntry<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.total || self.table_va == 0 {
            return None;
        }
        let offset = self.index * ExternalTableEntry::SIZE as u32;
        let entry_va = self.table_va.wrapping_add(offset);
        self.index += 1;
        let data = match self.map.slice_from_va(entry_va, ExternalTableEntry::SIZE) {
            Ok(d) => d,
            Err(e) => return Some(Err(e)),
        };
        Some(ExternalTableEntry::parse(data))
    }
}

/// Iterator over VB6 objects in a project.
///
/// Yields one [`VbObject`] per entry in the ObjectTable's object array.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct ObjectIterator<'a, 'p> {
    /// Parent project providing the address map and object table.
    project: &'p VbProject<'a>,
    /// Current zero-based position in the object array.
    index: u16,
    /// Total number of objects declared in the ObjectTable.
    total: u16,
}

impl<'a, 'p: 'a> Iterator for ObjectIterator<'a, 'p> {
    type Item = Result<VbObject<'a, 'p>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.total {
            return None;
        }
        let i = self.index;
        self.index += 1;
        Some(VbObject::parse(self.project, i))
    }
}
