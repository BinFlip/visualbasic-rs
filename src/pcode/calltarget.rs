//! Call target resolution for P-Code call operands.
//!
//! Resolves `%v` (VTableRef), `%x` (ExternalCall), and `%c` (ControlIndex)
//! operands to human-readable call target names like `"kernel32!CreateFileA"`
//! or `"Timer1"` with vtable offset.
//!
//! Two resolver types are provided:
//! - [`ImportResolver`]: Lightweight — needs only an [`AddressMap`] and the
//!   external table VA/count. Resolves `%x` imports without a full
//!   [`VbProject`].
//! - [`CallResolver`]: Full — wraps [`ImportResolver`] and adds `%v`/`%c`
//!   resolution that requires project context.

use crate::{
    addressmap::AddressMap,
    project::{VbObject, VbProject},
    vb::external::ExternalTableEntry,
};

/// Resolved call target information.
#[derive(Debug, Clone)]
pub enum CallTarget {
    /// External DLL API call (Declare function).
    Api {
        /// DLL library name (e.g., `"kernel32"`).
        library: String,
        /// API function name (e.g., `"CreateFileA"`).
        function: String,
    },
    /// COM vtable method call on a control or object.
    VTableMethod {
        /// Control name if resolved (e.g., `"Timer1"`).
        control_name: Option<String>,
        /// Raw vtable byte offset.
        vtable_offset: u16,
    },
    /// Resolved import/control name from `%c` operand.
    ImportRef {
        /// Resolved name of the referenced item.
        name: Option<String>,
    },
    /// Could not resolve the call target.
    Unknown,
}

/// Lightweight import resolver for `%x` (ExternalCall) operands.
///
/// Resolves import indices to `CallTarget::Api` entries using only the
/// address map and external table location — no [`VbProject`] required.
///
/// Construct from [`AddressMap`] + external table VA + count (available
/// from [`ProjectData`](crate::vb::projectdata::ProjectData)), or from
/// an existing [`VbProject`] via [`ImportResolver::from_project`].
pub struct ImportResolver<'a> {
    map: &'a AddressMap<'a>,
    externals: Vec<ExternalTableEntry<'a>>,
}

impl<'a> ImportResolver<'a> {
    /// Creates an import resolver from raw external table parameters.
    ///
    /// # Arguments
    ///
    /// * `map` - Address map for VA-to-offset resolution.
    /// * `external_table_va` - Base VA of the external table
    ///   (from [`ProjectData::external_table_va`](crate::vb::projectdata::ProjectData::external_table_va)).
    /// * `external_count` - Number of entries in the table
    ///   (from [`ProjectData::external_count`](crate::vb::projectdata::ProjectData::external_count)).
    pub fn new(map: &'a AddressMap<'a>, external_table_va: u32, external_count: u32) -> Self {
        let mut externals = Vec::new();
        if external_table_va != 0 {
            let entry_size = ExternalTableEntry::SIZE as u32;
            for i in 0..external_count {
                // Bounded by external_count loop; saturating prevents wrap on hostile counts.
                let offset = i.saturating_mul(entry_size);
                let entry_va = external_table_va.wrapping_add(offset);
                if let Ok(data) = map.slice_from_va(entry_va, ExternalTableEntry::SIZE)
                    && let Ok(entry) = ExternalTableEntry::parse(data)
                {
                    externals.push(entry);
                }
            }
        }
        Self { map, externals }
    }

    /// Creates an import resolver from an existing [`VbProject`].
    pub fn from_project(project: &'a VbProject<'a>) -> Self {
        let externals: Vec<_> = project
            .externals()
            .into_iter()
            .flatten()
            .filter_map(|r| match r {
                Ok(e) => Some(e),
                Err(e) => {
                    crate::trace::warn_drop!("import_resolver.externals", error = ?e);
                    None
                }
            })
            .collect();
        Self {
            map: project.address_map(),
            externals,
        }
    }

    /// Resolves an ExternalCall operand (`%x`).
    ///
    /// The `import` field indexes into the external table from
    /// `ProjectData.external_table_va`. For `Declare` functions,
    /// returns `Api { library, function }`.
    pub fn resolve_external(&self, import: u16) -> CallTarget {
        if let Some(entry) = self.externals.get(import as usize)
            && let Some(decl) = entry.as_declare(self.map)
        {
            let library = decl.library_name(self.map).unwrap_or("").to_string();
            let function = decl.function_name(self.map).unwrap_or("").to_string();
            if !library.is_empty() || !function.is_empty() {
                return CallTarget::Api { library, function };
            }
        }
        CallTarget::Unknown
    }

    /// Resolves a ControlIndex operand (`%c`) to a name.
    ///
    /// For `ImpAdCall*` opcodes the `%c` operand identifies the import.
    /// This method tries to resolve it via the external table.
    pub fn resolve_import_index(&self, index: u16) -> CallTarget {
        let target = self.resolve_external(index);
        match target {
            CallTarget::Unknown => CallTarget::ImportRef { name: None },
            other => other,
        }
    }

    /// Returns the underlying address map.
    pub fn address_map(&self) -> &AddressMap<'a> {
        self.map
    }
}

/// Resolves call-related P-Code operands to human-readable targets.
///
/// Wraps [`ImportResolver`] and adds `%v` (VTableRef) resolution that
/// requires project context for control name lookup.
pub struct CallResolver<'a> {
    project: &'a VbProject<'a>,
    imports: ImportResolver<'a>,
}

impl<'a> CallResolver<'a> {
    /// Creates a resolver, caching the project's external table.
    pub fn new(project: &'a VbProject<'a>) -> Self {
        let imports = ImportResolver::from_project(project);
        Self { project, imports }
    }

    /// Returns the underlying [`ImportResolver`].
    pub fn import_resolver(&self) -> &ImportResolver<'a> {
        &self.imports
    }

    /// Resolves an ExternalCall operand (`%x`).
    ///
    /// The `import` field indexes into the external table from
    /// `ProjectData.external_table_va`. For `Declare` functions,
    /// returns `Api { library, function }`.
    pub fn resolve_external(&self, import: u16) -> CallTarget {
        self.imports.resolve_external(import)
    }

    /// Resolves a VTableRef operand (`%v`).
    ///
    /// The `control` field indexes into the object's control array.
    /// The `vtable_offset` is a byte offset into the control's COM vtable.
    pub fn resolve_vtable(
        &self,
        vtable_offset: u16,
        control_index: u16,
        object: &VbObject<'a, '_>,
    ) -> CallTarget {
        let controls: Vec<_> = object
            .controls()
            .into_iter()
            .flatten()
            .filter_map(|r| match r {
                Ok(c) => Some(c),
                Err(e) => {
                    crate::trace::warn_drop!("call_resolver.vtable_controls", error = ?e);
                    None
                }
            })
            .collect();

        let control_name = controls.get(control_index as usize).and_then(|ctrl| {
            let name = ctrl.name();
            if name.is_empty() {
                None
            } else {
                Some(name.into_owned())
            }
        });

        CallTarget::VTableMethod {
            control_name,
            vtable_offset,
        }
    }

    /// Resolves a ControlIndex operand (`%c`) to a name.
    ///
    /// For `ImpAdCall*` opcodes the `%c` operand identifies the import.
    /// This method tries to resolve it via the external table.
    pub fn resolve_import_index(&self, index: u16) -> CallTarget {
        self.imports.resolve_import_index(index)
    }

    /// Returns the underlying address map for custom resolution.
    pub fn address_map(&self) -> &AddressMap<'a> {
        self.project.address_map()
    }
}

/// Formats as `LIB!Func` for API calls, `ctrl.vtbl+0xOFFSET` for vtable
/// methods, or the import name for import references.
impl core::fmt::Display for CallTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Api { library, function } => write!(f, "{library}!{function}"),
            Self::VTableMethod {
                control_name,
                vtable_offset,
            } => {
                if let Some(name) = control_name {
                    write!(f, "{name}.vtbl+0x{vtable_offset:04X}")
                } else {
                    write!(f, "vtbl+0x{vtable_offset:04X}")
                }
            }
            Self::ImportRef { name: Some(n) } => write!(f, "{n}"),
            Self::ImportRef { name: None } => write!(f, "<import>"),
            Self::Unknown => write!(f, "<unknown>"),
        }
    }
}
