//! Top-level VB6 project entry point.
//!
//! [`VbProject`] is the primary entry point for the library. It chains
//! together PE parsing, VB structure navigation, and P-Code access into
//! a single convenient type with lifetime `'a` tied to the file buffer.

use std::borrow::Cow;

use goblin::{
    options::ParseMode,
    pe::{PE, options::ParseOptions},
};

use crate::{
    addressmap::AddressMap,
    entrypoint,
    error::Error,
    project::{CodeEntryKind, PCodeMethod, VbObject},
    util::read_cstr,
    vb::{
        external::{ExternalComponentIter, ExternalTableEntry},
        formdata::FormDataParser,
        guitable::{GuiTableEntry, GuiTableIter},
        header::VbHeader,
        objecttable::ObjectTable,
        projectdata::ProjectData,
    },
};

/// Kind tag for [`CodeEntrypoint`].
///
/// Used by [`VbProject::code_entrypoints`] to label what kind of code
/// each VA points to. New variants may be added in future versions
/// (this enum is `non_exhaustive`); consumers should always handle
/// unknown kinds gracefully.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EntrypointKind {
    /// P-Code procedure stub (`mov edx, <RTMI>; call ProcCallEngine` or
    /// the leaner `xor eax,eax; mov edx, <RTMI>` variant). The VA points
    /// at the stub; the procedure descriptor lives just past the P-Code
    /// byte stream.
    PCodeStub,
    /// Native-compiled method body in the PE `.text` section.
    NativeProc,
    /// Native method discovered via a method-link JMP thunk (used by
    /// native-compiled classes whose `methods_va` points into MSVBVM60).
    NativeThunk,
    /// Event handler connected to a control's event sink vtable.
    EventHandler,
    /// `Sub Main` entry procedure pointed to by `VbHeader.sub_main_va`
    /// (offset +0x2C). At most one of these per project.
    SubMain,
}

impl From<CodeEntryKind> for EntrypointKind {
    fn from(k: CodeEntryKind) -> Self {
        match k {
            CodeEntryKind::PCode => Self::PCodeStub,
            CodeEntryKind::Native => Self::NativeProc,
            CodeEntryKind::NativeThunk => Self::NativeThunk,
            CodeEntryKind::EventHandler => Self::EventHandler,
        }
    }
}

/// A code entry point discovered anywhere in the project.
///
/// Returned by [`VbProject::code_entrypoints`]. Carries a tagged
/// [`EntrypointKind`] plus enough optional fields to drive disassembler
/// labelling consistently across method dispatch entries, native thunks,
/// event handlers, and `Sub Main`. Unused fields are `None`.
#[derive(Debug, Clone)]
pub struct CodeEntrypoint<'a> {
    /// Virtual address of the entry point.
    pub va: u32,
    /// What kind of entry this is.
    pub kind: EntrypointKind,
    /// Human-readable label (method name, `"ControlName_EventName"`, or
    /// `"Sub Main"`). Empty when no name could be resolved — the kind
    /// and `object_index` / `method_index` are still authoritative.
    pub name_hint: Cow<'a, str>,
    /// Index of the owning object (form/class/module) in the object
    /// table, or `None` for project-level entries. For
    /// [`EntrypointKind::SubMain`] this is resolved to the owning module
    /// when `lpSubMain` matches a known method entry, else `None`.
    pub object_index: Option<u16>,
    /// Method-table slot within the owning object, or `None` for
    /// non-method entries (event handlers, native thunks without a
    /// corresponding dispatch slot). Resolved for [`EntrypointKind::SubMain`]
    /// when its target matches a known method entry.
    pub method_index: Option<u16>,
    /// `true` if this entry's code is P-Code. Always `true` for
    /// [`EntrypointKind::PCodeStub`]; also `true` for a
    /// [`EntrypointKind::SubMain`] whose target resolves to a P-Code method.
    pub is_pcode: bool,
    /// Constant-pool base VA (`ObjectInfo.lpConstants`). Present for
    /// P-Code entries ([`EntrypointKind::PCodeStub`], or a P-Code `Sub Main`).
    pub data_const_va: Option<u32>,
    /// VA of the P-Code call stub. Present for P-Code entries
    /// ([`EntrypointKind::PCodeStub`], or a P-Code `Sub Main`).
    pub stub_va: Option<u32>,
    /// Size of the P-Code byte stream. Present for P-Code entries
    /// ([`EntrypointKind::PCodeStub`], or a P-Code `Sub Main`).
    pub pcode_size: Option<u16>,
}

/// Severity classification for a [`ParseDiagnostic`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DiagnosticSeverity {
    /// Routine/expected condition — surfaced for completeness, not a problem.
    /// Example: a standard `.bas` module legitimately has no
    /// `OptionalObjectInfo`; reporting that absence is informational.
    Info,
    /// Anomaly worth attention but recoverable. Example:
    /// `methods_va == constants_va` — the method table overlaps the
    /// constants pool, so method iteration will yield nothing useful, but
    /// the rest of the object can still be inspected.
    Warning,
    /// Structural error — the affected substructure was unparseable and
    /// a downstream walker dropped it. Example: a control-table parse
    /// failure that stops the controls iterator early.
    Error,
}

/// What kind of finding a [`ParseDiagnostic`] records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DiagnosticKind {
    /// An optional structure was not present at the expected location.
    /// May or may not be a problem depending on object type.
    AbsentOptional,
    /// A structure parsed but contains a known-anomaly pattern.
    Quirk,
    /// A structure was present but failed to parse.
    Malformed,
}

/// A single diagnostic from [`VbProject::diagnostics`].
///
/// Carries enough context for a UI "parse health" badge: which kind of
/// issue, where it was found (project-level vs per-object), the severity,
/// and a short human-readable explanation.
#[derive(Debug, Clone)]
pub struct ParseDiagnostic {
    /// What kind of finding this is.
    pub kind: DiagnosticKind,
    /// How important the finding is.
    pub severity: DiagnosticSeverity,
    /// Object index when the finding is per-object, `None` for
    /// project-level findings.
    pub object_index: Option<u16>,
    /// Short human-readable identifier for the affected structure
    /// (`"OptionalObjectInfo"`, `"PrivateObjectDescriptor"`,
    /// `"method_table"`, `"sub_main"`).
    pub site: &'static str,
    /// One-line description of the finding.
    pub message: Cow<'static, str>,
}

/// Whether a VB6 binary is P-Code, native, or mixed.
///
/// Returned by [`VbProject::compilation_mode`]. Combines the project-level
/// `lpNativeCode` flag with a per-object scan, so mixed-mode binaries
/// (where the project header disagrees with at least one object) are
/// surfaced explicitly rather than misclassified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompilationMode {
    /// Project flag indicates P-Code AND every object with methods uses
    /// P-Code dispatch.
    Pcode,
    /// Project flag indicates native AND no object holds P-Code methods.
    Native,
    /// The project flag and per-object scan disagree — e.g. a P-Code
    /// project with native-compiled classes, or a native project where
    /// individual objects still carry P-Code dispatch entries. Treat
    /// each object's [`has_pcode`](crate::project::VbObject::has_pcode)
    /// as authoritative for that object.
    Mixed,
}

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
///
/// See [`compilation_mode`](VbProject::compilation_mode) and
/// [`CompilationMode`] for classifying P-Code-vs-native-vs-mixed binaries.
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
    /// Returns an [`Error`] whose [`recognition_failure`](Error::recognition_failure)
    /// classifies the failure mode:
    ///
    /// - [`RecognitionFailure::UnrecognizedFormat`](crate::error::RecognitionFailure::UnrecognizedFormat) —
    ///   not a valid PE32 container at all (or PE32+ which VB6 doesn't use).
    /// - [`RecognitionFailure::NotRecognized`](crate::error::RecognitionFailure::NotRecognized) —
    ///   PE walked OK but no VB6 marker (entry point or DLL-export pattern).
    /// - [`RecognitionFailure::TruncatedContainer`](crate::error::RecognitionFailure::TruncatedContainer) —
    ///   recognized as VB6 but a header/structure read overran the buffer.
    ///
    /// Consumers tagging files as "VB6 or not" should match on
    /// `recognition_failure()` to silently skip non-VB6 files and only
    /// log the truncation cases.
    ///
    /// Both P-Code and native-compiled VB6 binaries are accepted.
    /// Use [`is_pcode`](Self::is_pcode) to check which kind you have.
    pub fn from_bytes(file: &'a [u8]) -> Result<Self, Error> {
        // VB6 parsing navigates structures through the address map and never
        // needs the PE resource directory. Skip resource parsing so that a
        // malformed `.rsrc` (common in packed / anti-analysis samples, which
        // can make goblin's strict parser reject the whole file) does not sink
        // an otherwise-parseable VB6 binary.
        let opts = ParseOptions::default()
            .with_parse_resources(false)
            .with_parse_imports(false)
            .with_parse_mode(ParseMode::Permissive);
        let pe = PE::parse_with_opts(file, &opts).map_err(|e| Error::UnrecognizedFormat {
            reason: format!("goblin: {e}"),
        })?;
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
                .ok_or(Error::NotRecognized)
        })?;

        // Parse VBHeader. Truncation here is reclassified as
        // `TruncatedContainer` so consumers can distinguish "valid VB6
        // file but truncated at top of structure chain" from generic
        // mid-walk truncation.
        let vb_header_data = map
            .slice_from_va(vb_header_va, VbHeader::SIZE)
            .map_err(|_| Error::TruncatedContainer {
                context: "VbHeader",
            })?;
        let vb_header = VbHeader::parse(vb_header_data).map_err(|_| Error::TruncatedContainer {
            context: "VbHeader",
        })?;

        // Parse ProjectData
        let pd_va = vb_header
            .project_data_va()
            .map_err(|_| Error::TruncatedContainer {
                context: "VbHeader.project_data_va",
            })?;
        let pd_data =
            map.slice_from_va(pd_va, ProjectData::SIZE)
                .map_err(|_| Error::TruncatedContainer {
                    context: "ProjectData",
                })?;
        let project_data = ProjectData::parse(pd_data).map_err(|_| Error::TruncatedContainer {
            context: "ProjectData",
        })?;

        // Parse ObjectTable
        let ot_va = project_data
            .object_table_va()
            .map_err(|_| Error::TruncatedContainer {
                context: "ProjectData.object_table_va",
            })?;
        let ot_data =
            map.slice_from_va(ot_va, ObjectTable::SIZE)
                .map_err(|_| Error::TruncatedContainer {
                    context: "ObjectTable",
                })?;
        let object_table = ObjectTable::parse(ot_data).map_err(|_| Error::TruncatedContainer {
            context: "ObjectTable",
        })?;

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

    /// Converts a VA in this PE image to an RVA.
    ///
    /// Returns `None` when the VA is below the image base. The returned
    /// value is a stable `u64` for consumers that store RVAs in database
    /// columns shared with 64-bit parsers.
    #[inline]
    pub fn va_to_rva(&self, va: u32) -> Option<u64> {
        va.checked_sub(self.map.image_base()).map(u64::from)
    }

    /// Returns the RVA of a P-Code method's callable entry stub.
    ///
    /// This converts [`PCodeMethod::stub_va`] using the PE image base held
    /// by this project, so callers do not need to thread `image_base`
    /// through their VB6 parser path.
    #[inline]
    pub fn pcode_method_rva(&self, method: &PCodeMethod<'_>) -> Option<u64> {
        self.va_to_rva(method.stub_va())
    }

    /// Returns the RVA of a discovered code entry point.
    ///
    /// This converts [`CodeEntrypoint::va`] using the PE image base held by
    /// this project, so callers can pass the result directly to tools that
    /// consume RVAs.
    #[inline]
    pub fn code_entrypoint_rva(&self, entrypoint: &CodeEntrypoint<'_>) -> Option<u64> {
        self.va_to_rva(entrypoint.va)
    }

    /// Returns `true` if the binary is P-Code compiled.
    ///
    /// When `false`, the binary is native x86 compiled and P-Code
    /// method iteration will yield no instructions, but all VB6
    /// metadata structures are still accessible.
    ///
    /// Note: this reflects only the project-level `lpNativeCode` field. Some
    /// VB6 binaries are **mixed** — the project-level flag says "native" but
    /// individual classes/forms still hold P-Code methods (or vice versa).
    /// Use [`compilation_mode`](Self::compilation_mode) for the
    /// per-object-aware classification.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying ProjectData field cannot be read.
    #[inline]
    pub fn is_pcode(&self) -> Result<bool, Error> {
        self.project_data.is_pcode()
    }

    /// Classifies the binary's compilation mode by combining the project-level
    /// `lpNativeCode` flag with a per-object scan for P-Code methods.
    ///
    /// - [`CompilationMode::Pcode`] — project flag says P-Code AND every
    ///   object that has methods has P-Code methods (no native objects).
    /// - [`CompilationMode::Native`] — project flag says native AND no
    ///   object holds P-Code methods.
    /// - [`CompilationMode::Mixed`] — the two signals disagree, e.g. a
    ///   P-Code project with some native-compiled classes, or a native
    ///   project where some objects still carry P-Code dispatch entries.
    ///
    /// This is the signal to use when deciding whether to expect P-Code in
    /// a given object — `is_pcode()` alone misclassifies mixed-mode binaries.
    ///
    /// # Errors
    ///
    /// Returns an error if the project-level flag or any object's
    /// optional info cannot be read.
    pub fn compilation_mode(&self) -> Result<CompilationMode, Error> {
        let project_pcode = self.is_pcode()?;
        let mut any_pcode = false;
        for obj in self.objects()? {
            let obj = obj?;
            if obj.has_pcode()? {
                any_pcode = true;
                break;
            }
        }
        Ok(match (project_pcode, any_pcode) {
            (true, true) => CompilationMode::Pcode,
            (false, false) => CompilationMode::Native,
            _ => CompilationMode::Mixed,
        })
    }

    /// Reads the project name as a lossy UTF-8 string.
    ///
    /// Borrows when the underlying bytes are already valid UTF-8.
    /// Use [`project_name_bytes`](Self::project_name_bytes) for the
    /// raw bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the project name VA cannot be resolved.
    pub fn project_name(&self) -> Result<Cow<'a, str>, Error> {
        Ok(String::from_utf8_lossy(self.project_name_bytes()?))
    }

    /// Reads the project name as raw bytes from the PE image.
    ///
    /// # Errors
    ///
    /// Returns an error if the project name VA cannot be resolved.
    pub fn project_name_bytes(&self) -> Result<&'a [u8], Error> {
        self.read_string_at_va(self.object_table.project_name_va()?)
    }

    /// Returns the total number of objects in the project.
    ///
    /// # Errors
    ///
    /// Returns an error if the ObjectTable's `total_objects` field cannot be read.
    #[inline]
    pub fn object_count(&self) -> Result<u16, Error> {
        self.object_table.total_objects()
    }

    /// Returns an iterator over all objects in the project.
    ///
    /// Each item is a `Result<VbObject<'a>, Error>` because resolving
    /// each object requires VA translation that can fail.
    ///
    /// # Errors
    ///
    /// Returns an error if the object count cannot be read.
    pub fn objects(&self) -> Result<ObjectIterator<'a, '_>, Error> {
        Ok(ObjectIterator {
            project: self,
            index: 0,
            total: self.object_table.total_objects()?,
        })
    }

    /// Returns an iterator over external component references.
    ///
    /// External components are COM/OCX libraries referenced by the project,
    /// listed in `ProjectData.external_table_va()`.
    ///
    /// # Errors
    ///
    /// Returns an error if the external table VA or count cannot be read.
    pub fn externals(&self) -> Result<ExternalIterator<'a, '_>, Error> {
        Ok(ExternalIterator {
            map: &self.map,
            table_va: self.project_data.external_table_va()?,
            index: 0,
            total: self.project_data.external_count()?,
        })
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
    ///
    /// # Errors
    ///
    /// Returns an error if the VB header's external table VA or count
    /// cannot be read.
    pub fn components(&self) -> Result<ExternalComponentIter<'a>, Error> {
        let table_va = self.vb_header.external_table_va()?;
        let count = self.vb_header.external_count()?;
        if table_va == 0 || count == 0 {
            return Ok(ExternalComponentIter::new(&[], 0));
        }
        // Read enough data for the full table (estimate max entry size)
        let max_size = (count as usize).saturating_mul(0x400); // 1KB per entry max estimate
        let data = self.map.slice_from_va(table_va, max_size).unwrap_or(&[]);
        Ok(ExternalComponentIter::new(data, count))
    }

    /// Iterates over GUI table entries (one per form/UserControl/MDIForm).
    ///
    /// The GUI table is pointed to by `VBHeader.lpGuiTable` (+0x4C) with
    /// `VBHeader.wFormCount` (+0x44) entries.
    ///
    /// # Errors
    ///
    /// Returns an error if the GUI table VA or form count cannot be read.
    pub fn gui_entries(&self) -> Result<GuiTableIter<'_>, Error> {
        Ok(GuiTableIter::new(
            &self.map,
            self.vb_header.gui_table_va()?,
            self.vb_header.form_count()?,
        ))
    }

    /// Collects structured findings about the project's parse state.
    ///
    /// Walks the optional substructures and reports which were absent,
    /// which were present but anomalous, and which failed to parse.
    /// Intended as a "parse health" probe for analyst UIs — a
    /// zero-element vec means everything the crate looked at is in
    /// expected shape.
    ///
    /// Findings are emitted in roughly walk order:
    /// 1. Project-level: `Sub Main` presence, mixed compilation mode.
    /// 2. Per-object: missing `OptionalObjectInfo` (suspicious for
    ///    forms/classes; expected for modules), missing
    ///    `PrivateObjectDescriptor` (expected for modules), method-table
    ///    overlap (`methods_va == constants_va`).
    ///
    /// This is a **best-effort** snapshot — it deliberately does not
    /// surface every possible quirk. New findings may be added in
    /// future versions; consumers should match on
    /// [`DiagnosticKind`] / [`DiagnosticSeverity`] using non-exhaustive
    /// patterns.
    ///
    /// # Errors
    ///
    /// Propagates any error from walking the object table or the
    /// project header. A diagnostics call that errors out should be
    /// treated as the most-severe possible finding.
    pub fn diagnostics(&self) -> Result<Vec<ParseDiagnostic>, Error> {
        let mut out: Vec<ParseDiagnostic> = Vec::new();

        // Project-level: Sub Main presence.
        let sub_main = self.vb_header.sub_main_va()?;
        if sub_main == 0 {
            out.push(ParseDiagnostic {
                kind: DiagnosticKind::AbsentOptional,
                severity: DiagnosticSeverity::Info,
                object_index: None,
                site: "sub_main",
                message: Cow::Borrowed(
                    "no Sub Main entry point declared (VbHeader.sub_main_va == 0)",
                ),
            });
        } else if !self.map.is_va_in_image(sub_main) {
            out.push(ParseDiagnostic {
                kind: DiagnosticKind::Quirk,
                severity: DiagnosticSeverity::Warning,
                object_index: None,
                site: "sub_main",
                message: Cow::Borrowed(
                    "Sub Main VA is non-zero but does not resolve inside the PE image",
                ),
            });
        }

        // Project-level: compilation mode.
        if let Ok(mode) = self.compilation_mode()
            && mode == CompilationMode::Mixed
        {
            out.push(ParseDiagnostic {
                kind: DiagnosticKind::Quirk,
                severity: DiagnosticSeverity::Warning,
                object_index: None,
                site: "compilation_mode",
                message: Cow::Borrowed(
                    "project flag and per-object scan disagree — treat each object's has_pcode() as authoritative",
                ),
            });
        }

        // Per-object scan.
        for (i, obj_result) in self.objects()?.enumerate() {
            let obj = obj_result?;
            let object_index = u16::try_from(i).ok();
            let kind = obj.object_kind()?;

            // OptionalObjectInfo: expected absent for modules, suspicious for forms/classes.
            if obj.optional_info().is_none() && kind != "Module" {
                out.push(ParseDiagnostic {
                    kind: DiagnosticKind::AbsentOptional,
                    severity: DiagnosticSeverity::Warning,
                    object_index,
                    site: "OptionalObjectInfo",
                    message: Cow::Borrowed(
                        "OptionalObjectInfo missing for non-module object — controls/event sinks unavailable",
                    ),
                });
            }

            // PrivateObjectDescriptor: expected absent for modules, suspicious for classes.
            if obj.private_object().is_none() && kind == "Class" {
                out.push(ParseDiagnostic {
                    kind: DiagnosticKind::AbsentOptional,
                    severity: DiagnosticSeverity::Warning,
                    object_index,
                    site: "PrivateObjectDescriptor",
                    message: Cow::Borrowed(
                        "PrivateObjectDescriptor missing for class object — function type descriptors unavailable",
                    ),
                });
            }

            // Method table overlapping constants: marker for "no real method table".
            if !obj.has_method_table()? {
                let info = obj.info();
                let methods_va = info.methods_va()?;
                let constants_va = info.constants_va()?;
                if methods_va != 0 && methods_va == constants_va {
                    out.push(ParseDiagnostic {
                        kind: DiagnosticKind::Quirk,
                        severity: DiagnosticSeverity::Info,
                        object_index,
                        site: "method_table",
                        message: Cow::Borrowed(
                            "methods_va == constants_va — no method dispatch table for this object",
                        ),
                    });
                }
            }
        }

        Ok(out)
    }

    /// Returns every code entry point the crate can confidently label.
    ///
    /// Aggregates four sources into a single tagged stream:
    ///
    /// 1. **Per-object method dispatch** — P-Code stubs and native methods
    ///    from each object's [`code_entries`](crate::project::VbObject::code_entries).
    /// 2. **Native method-link thunks** — JMP thunks that bridge COM vtable
    ///    dispatch to native code bodies (also via `code_entries`).
    /// 3. **Event handlers** — connected control event handler VAs.
    /// 4. **`Sub Main`** — the project-level entry procedure from
    ///    [`VbHeader::sub_main_va`], when non-zero.
    ///
    /// Each entry carries a tagged [`EntrypointKind`] so consumers can
    /// drive disassembler labelling in lockstep without missing a kind
    /// when a new one is added in a future release. Compared to walking
    /// objects → methods → events by hand, this collapses ~5 separate
    /// loops into one stream and guarantees consistent name resolution.
    ///
    /// # Form-data resolution
    ///
    /// Event-handler names use the standard 24-event template (slot 0 =
    /// `Click`, etc.) without form-data context. For richer names that
    /// account for control-type-specific overrides (e.g. `Timer1.Timer`
    /// instead of `Timer1.Click`), call
    /// [`VbObject::code_entries`](crate::project::VbObject::code_entries)
    /// per object with form data from
    /// [`gui_entries_with_form_data`](Self::gui_entries_with_form_data).
    ///
    /// # Errors
    ///
    /// Returns an error if the object iterator, header, or any per-object
    /// code-entry resolution fails.
    pub fn code_entrypoints(&self) -> Result<Vec<CodeEntrypoint<'a>>, Error> {
        let mut out: Vec<CodeEntrypoint<'a>> = Vec::new();

        // 1-3. Per-object dispatch + thunks + events.
        for (obj_index, obj_result) in self.objects()?.enumerate() {
            let obj = obj_result?;
            let object_index = u16::try_from(obj_index).ok();
            for entry in obj.code_entries(None)? {
                out.push(CodeEntrypoint {
                    va: entry.va,
                    kind: EntrypointKind::from(entry.kind),
                    name_hint: entry.name.map(Cow::Owned).unwrap_or(Cow::Borrowed("")),
                    object_index,
                    method_index: entry.method_index,
                    is_pcode: matches!(entry.kind, CodeEntryKind::PCode),
                    data_const_va: entry.data_const_va,
                    stub_va: entry.stub_va,
                    pcode_size: entry.pcode_size,
                });
            }
        }

        // 4. Sub Main. `lpSubMain` (VbHeader +0x2C) is the *callable* address
        //    the runtime invokes — for a P-Code module that is the dispatch
        //    stub VA, for a native module the procedure VA. Both were already
        //    collected as per-object entries above, so resolve the target by
        //    matching that address rather than re-implementing stub detection:
        //    a P-Code method's `stub_va` is the callable trampoline, while a
        //    native entry has no stub and is reached at its `va`.
        let sub_main = self.vb_header.sub_main_va()?;
        if sub_main != 0 && self.map.is_va_in_image(sub_main) {
            let matched = out
                .iter()
                .find(|e| e.stub_va == Some(sub_main) || (e.stub_va.is_none() && e.va == sub_main));
            let entry = match matched {
                Some(e) => CodeEntrypoint {
                    va: sub_main,
                    kind: EntrypointKind::SubMain,
                    name_hint: Cow::Borrowed("Sub Main"),
                    object_index: e.object_index,
                    method_index: e.method_index,
                    is_pcode: e.is_pcode,
                    data_const_va: e.data_const_va,
                    stub_va: e.stub_va,
                    pcode_size: e.pcode_size,
                },
                None => CodeEntrypoint {
                    va: sub_main,
                    kind: EntrypointKind::SubMain,
                    name_hint: Cow::Borrowed("Sub Main"),
                    object_index: None,
                    method_index: None,
                    is_pcode: false,
                    data_const_va: None,
                    stub_va: None,
                    pcode_size: None,
                },
            };
            out.push(entry);
        }

        Ok(out)
    }

    /// Iterates GUI table entries paired with their parsed form binary data.
    ///
    /// For each [`GuiTableEntry`] yielded by [`gui_entries`](Self::gui_entries),
    /// attempts to parse the form binary at the entry's
    /// [`form_data_va`](crate::vb::guitable::GuiTableEntry::form_data_va).
    /// The pair's [`form_data`](GuiEntryWithFormData::form_data) is `None`
    /// when the entry has no form data (`form_data_va == 0` or `size == 0`)
    /// and `Some(parser)` when the form binary parses successfully.
    /// Parse errors silently degrade to `None` — use
    /// [`form_data_from_gui_entry`](crate::project::VbObject::form_data_from_gui_entry)
    /// directly if you need the parse error.
    ///
    /// This collapses what consumers otherwise do by hand: walking
    /// `gui_entries()`, then for each one calling
    /// `obj.form_data_from_gui_entry(&entry)` and pairing the result.
    ///
    /// # Errors
    ///
    /// Returns an error if the GUI table VA or form count cannot be read
    /// (same conditions as [`gui_entries`](Self::gui_entries)).
    pub fn gui_entries_with_form_data(&self) -> Result<GuiEntriesWithFormData<'a, '_>, Error> {
        Ok(GuiEntriesWithFormData {
            inner: self.gui_entries()?,
            map: &self.map,
        })
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
        read_cstr(self.map.file(), offset)
    }
}

/// Iterator over external component table entries.
///
/// Yields one [`ExternalTableEntry`] per COM/OCX library referenced by the
/// project, walking the table starting at `ProjectData.external_table_va()?`.
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
        let offset = self.index.saturating_mul(ExternalTableEntry::SIZE as u32);
        let entry_va = self.table_va.wrapping_add(offset);
        self.index = self.index.saturating_add(1);
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
        self.index = self.index.saturating_add(1);
        Some(VbObject::parse(self.project, i))
    }
}

/// A [`GuiTableEntry`] paired with its parsed form binary, if any.
///
/// Yielded by [`VbProject::gui_entries_with_form_data`]. The
/// [`form_data`](Self::form_data) field is `None` when the entry has no
/// form binary (`form_data_va == 0` or `size == 0`) or when parsing
/// failed; otherwise it is the [`FormDataParser`] for that form's
/// control hierarchy and property values.
pub struct GuiEntryWithFormData<'a> {
    /// The raw GUI table entry (form/UserControl/MDIForm metadata).
    pub entry: GuiTableEntry<'a>,
    /// Parsed form binary, or `None` if absent or unparseable.
    pub form_data: Option<FormDataParser<'a>>,
}

/// Iterator over GUI entries paired with their parsed form binary data.
///
/// Created by [`VbProject::gui_entries_with_form_data`]. Each item is a
/// [`Result`] because the underlying [`GuiTableIter`] does not surface
/// per-entry parse errors as `Err` (it stops on first failure); the
/// `Result` here propagates address-translation errors when fetching
/// the form binary slice. The form-binary parse itself is best-effort
/// and degrades to `None` on failure.
#[must_use = "iterators are lazy and do nothing unless consumed"]
pub struct GuiEntriesWithFormData<'a, 'p> {
    inner: GuiTableIter<'p>,
    map: &'p AddressMap<'a>,
}

impl<'a, 'p: 'a> Iterator for GuiEntriesWithFormData<'a, 'p> {
    type Item = Result<GuiEntryWithFormData<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let entry = self.inner.next()?;
        // Resolve the form binary slice, if any.
        let form_data = match (entry.form_data_va(), entry.form_data_size()) {
            (Ok(va), Ok(size)) if va != 0 && size != 0 => {
                match self.map.slice_from_va(va, size as usize) {
                    Ok(data) => FormDataParser::parse(data).ok(),
                    Err(_) => None,
                }
            }
            _ => None,
        };
        Some(Ok(GuiEntryWithFormData { entry, form_data }))
    }
}
