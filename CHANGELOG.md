# Changelog

All notable changes to this crate are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] — 2026-06-09

### Added

- `CallApiStub::ordinal()`, `flags()`, and `is_by_ordinal()` — the
  `DllFunctionCall` descriptor is 16 bytes (not 8), carrying an import ordinal
  and a by-ordinal flag (bit 1) after the name pointers. Verified against
  MSVBVM60.DLL `sub_660315de`. By-ordinal imports omit the API name from the
  binary, a name-hiding signal for triage.
- `ExternalDeclareInfo::api_stub()` resolves a `Declare`'s native stub to its
  `CallApiStub`, exposing ordinal / by-ordinal state for declared imports
  (e.g. `Declare ... Alias "#123"`).
- `controlprop::CleanupAction` plus `ControlPropertyType::cleanup_action()`
  and `is_reference()` — the runtime resource-release classification
  (`FreeString` / `FreeVariant` / `ReleaseObject` / `DestroyArray` /
  `UnlockArray` / `DestructRecord`) for each class/form instance member,
  recovered from `CleanupSingleEntry` (0x66016AAA).
- `decoder::ErrorFlow` plus `Instruction::error_flow()` — classifies a
  `Resume` / `OnErrorGoto` instruction's signed operand into its source-level
  construct (`Resume`, `Resume Next`, `Resume <label>`, `On Error GoTo <label>`,
  `On Error Resume Next`, `On Error GoTo 0`). Verified against `op_Lead2_Resume`
  and `op_OnErrorGoto`.
- `Instruction::is_bos()` / `bos_distance()`, `OpcodeInfo::is_bos()`,
  `OpcodeSemantics::Bos`, and `PCodeMethod::statement_markers()` returning
  `StatementMarker { offset, distance }` — `LargeBos` is now modelled as a
  beginning-of-statement marker whose `u8` operand is the byte distance to the
  next statement boundary (`0` = last). This partitions a procedure's P-Code
  into source statements.
- `code_entrypoints()` now resolves the `Sub Main` target: a P-Code `Sub Main`
  carries `is_pcode = true` plus `stub_va` / `data_const_va` / `pcode_size`, and
  the entry is attributed to its owning module via `object_index` /
  `method_index` (by matching `lpSubMain` against the collected method entries).

### Changed

- **(breaking)** `ControlPropertyType` variants now reflect the runtime
  cleanup dispatcher rather than the size buckets: nibble 1 = `String`
  (was `Short`), 2 = `Variant` (was `Integer`), 3 = `Object` (was `Long`),
  4 = `FixedString`, 5 = `Array` (was `SafeArray`), 6 = `FixedArray`
  (was `Variant`), 9 = `Udt` (was `Object`); inline value nibbles collapse to
  `Value(u8)`. The previous names came from `CalcPropertyDataSize` alone, which
  cannot distinguish a 4-byte BSTR pointer from a 4-byte `Long`.
- **(breaking)** `LargeBos` is reclassified from `OpcodeSemantics::Nop` to
  `OpcodeSemantics::Bos`, and its operand is documented as the distance to the
  next statement boundary rather than a "line number."

### Fixed

- `Resume` and `OnErrorGoto` no longer disassemble their sentinel operands as
  bogus jump targets (`loc_FFFF` / `loc_FFFE`). They now render as
  `Resume Next`, `Resume`, `On Error Resume Next`, and `On Error GoTo 0` per the
  signed-operand encoding.

- Class/form instance property entry stride: `ControlPropertyEntry::total_size()`
  is now a faithful port of `CalcPropertyDataSize` and no longer adds an extra
  4-byte header to non-array entries. The previous `header + base` model
  over-counted nibbles 1/2/3/6/8/9/0xB by 4 bytes, which would desync the entry
  iterator on multi-member class tables.
- Parser robustness: `VbProject::from_bytes` now parses the PE with resources and
  imports skipped and goblin's permissive mode. VB6 navigation never needs
  goblin's resource/import tables, and packed / anti-analysis samples frequently
  carry malformed `.rsrc` or import data that made goblin's strict parser reject
  the whole file.
- P-Code decoder no longer reports spurious `UnexpectedEndOfPCode` errors on the
  zero-byte alignment padding VB6 appends to each procedure (proc size is padded
  to a 4-byte boundary). A lone trailing `0x00` previously looked like a
  truncated `LargeBos`; the iterator now ends cleanly at an all-zero tail.

## [0.2.1] — 2026-05-04

Patch release focused on parser integration ergonomics and stable
persistence surfaces.

### Added

- `VbProject::va_to_rva()`, `VbProject::pcode_method_rva()`, and
  `VbProject::code_entrypoint_rva()` so consumers can convert VB6 VAs
  without threading `image_base` through caller code.
- Stable `as_str()` discriminator helpers for `ExternalKind`,
  `PropertyValue`, `FormControlType`, and the new `IidKind`.
- `PropertyValue::picture_bytes()` and `PictureData::bytes()` for direct
  access to embedded BMP/ICO payload bytes.
- `PropertyValue::display_truncated(limit)` for char-boundary-safe display
  truncation.
- `ComRegData::MIN_BUFFER_SIZE` for callers that pre-slice COM registration
  data before parsing.
- `OptionalObjectInfo::typed_iids()` with `IidKind` and `TypedIidIter` to
  iterate GUI, default, and event IIDs through one typed stream.
- `FormControlRecord::parent_index()` exposing stable parent-control linkage
  in the parsed form-control list.

### Documentation

- Documented `OptionalObjectInfo` and `PrivateObjectDescriptor` accessor
  fallibility semantics.
- Documented the `PCodeMethod::instructions()` upper bound from the on-disk
  `u16` procedure-size field.

## [0.2.0] — 2026-04-26

A breaking-change release focused on adversarial-input safety, richer
typed walkers, and a tagged stream of code entry points. Verified
against runtime reverse-engineering of `MSVBVM60.DLL` (v6.00.9848)
and `VB6.EXE` (v6.00.8176).

### Added

#### Adversarial-input hardening

- Crate-wide lint denial of `clippy::unwrap_used`, `clippy::expect_used`,
  `clippy::panic`, `clippy::arithmetic_side_effects`, and
  `clippy::indexing_slicing`. Tests are exempt via `cfg(test)` allow.
- `Error::Truncated { needed, available }` for byte-level OOB reads.
- `Error::ArithmeticOverflow { context }` for offset/length wrap.
- All low-level byte readers in `crate::util` are panic-free (use
  `.get(...)` + `<[u8; N]>::try_from`); offset arithmetic uses
  `checked_add` / `wrapping_add` / `saturating_add` per semantics.
- Static `Send + Sync` assertion on `VbProject<'static>` and
  `PCodeMethod<'static>` so a future non-Send field breaks compilation
  here, not silently at a downstream `.await`.

#### Predicates and forward-compat aliases

- `OpcodeInfo::is_terminator()` and `OpcodeInfo::is_call()` —
  convenience predicates for CFG-style basic-block splitting.
- `CompilationMode { Pcode, Native, Mixed }` enum and
  `VbProject::compilation_mode()` — combines the project-level
  `lpNativeCode` flag with a per-object `has_pcode()` scan, so
  mixed-mode binaries surface explicitly.
- `PCodeMethod::cleanup_entries()` — re-export of the cleanup-table
  iterator on `ProcDscInfo` for ergonomic consumer access.
- `ConstantPool::entries_with_hints()` — reserved signature aliasing
  `entries()` for forward compatibility with future hint-enriched entries.
- `VbObject::form_designer_data()` — reserved signature aliasing
  `form_data_from_gui_entry()`.

#### Joined walkers and aggregators

- `VbObject::events()` and `VbObject::events_all_slots()` returning
  `Vec<EventBinding>` — joined walker over controls × event sink slots ×
  per-control-type event-name templates.
- `EventBinding { control_index, control_name, control_type, event_slot,
  event_name, handler_va }` with `is_connected()` and `label()` helpers.
- `VbProject::gui_entries_with_form_data()` returning
  `GuiEntriesWithFormData` iterator yielding `GuiEntryWithFormData
  { entry, form_data }` pairs — pre-pairs each form metadata entry with
  its parsed form binary.
- `VbProject::code_entrypoints()` — single-call aggregator returning
  `Vec<CodeEntrypoint>` over per-object dispatch + thunks + events +
  `Sub Main`. Each carries an `EntrypointKind` tag.
- `EntrypointKind { PCodeStub, NativeProc, NativeThunk, EventHandler,
  SubMain }` (`#[non_exhaustive]`).
- `InterfaceMetadata::typelib_path_va()` and
  `InterfaceMetadata::data_slot_va()` — raw VA accessors for the +0x10
  and +0x18 fields, with explicit "purpose undocumented" doc on +0x18.

#### Operand and constant pool typed accessors

- `Instruction::data_type()` — exposes the parent opcode's
  `PCodeDataType` for the instruction's stack result.
- `Instruction::operand_type(idx)` — per-slot inferred type, validated
  against operand presence.
- `ConstantPool::string_at(index)` — indexed BSTR accessor returning
  `Result<Option<BStr>, Error>`.
- `ConstantPool::api_stub_at(index)` — indexed `CallApiStub` resolution
  returning `Result<Option<CallApiStub>, Error>`.

#### Diagnostics and optional tracing

- Optional `tracing` cargo feature (`--features tracing`) — emits
  `target = "visualbasic::dropped"` `warn` events at silent fail-soft
  sites (`code_entries`, `events_inner`, `ImportResolver`,
  `CallResolver`). Default builds carry zero `tracing` dependency
  weight; helpers compile to no-ops.
- `VbProject::diagnostics()` returning `Vec<ParseDiagnostic>` — eager
  parse-health probe flagging missing `Sub Main`, mixed compilation
  mode, suspicious-absent `OptionalObjectInfo`/`PrivateObjectDescriptor`,
  and method-table overlap.
- `ParseDiagnostic`, `DiagnosticKind`, `DiagnosticSeverity` (all
  `#[non_exhaustive]`).

#### Recognition error discrimination

- `Error::NotRecognized` — valid PE container but no VB6 marker.
- `Error::TruncatedContainer { context }` — recognized as VB6 but a
  structure read overran the buffer.
- `Error::UnrecognizedFormat { reason }` — not a recognizable PE
  container at all (or PE32+).
- `RecognitionFailure { NotRecognized, TruncatedContainer,
  UnrecognizedFormat, CompressedAndOpaque }` (`#[non_exhaustive]`)
  with `Error::recognition_failure() -> Option<RecognitionFailure>`
  classifier — lets consumers silently deny non-VB6 files and only
  warn on truncation cases. `CompressedAndOpaque` is reserved for a
  future heuristic and not yet emitted.

#### Documentation

- `# Robustness contract` section in the crate root documenting the
  three behavioural categories (fail-loud primitives, skip-and-continue
  iterators, fail-soft high-level joins) plus the recognition-time
  `Error::recognition_failure` classification.
- `# Adversarial input invariants` section documenting the lint set
  guarantees.

### Changed (breaking)

#### `Result`-cascading accessors

Every fixed-offset accessor that reads from a backing byte slice now
returns `Result<T, Error>` instead of a panicking primitive. Affected
APIs include all `Vb*::*_va`, `*::frame_size`, `*::method_count`, etc.
across `src/vb/*` and `src/project/*`.

```rust
// Before:
let frame = method.frame_size();
let v = obj.method_count();

// After:
let frame = method.frame_size()?;
let v = obj.method_count()?;
```

The fallible signatures match the malware-analysis posture — every
read can now surface `Error::Truncated` rather than panicking on a
short slice.

#### `name()` returns `Cow<'a, str>`

For `VbObject`, `VbProject::project_name`, `VbControl::name`,
`FormControlRecord::name`, `ExternalComponentEntry::ocx_filename` /
`prog_id` / `class_name`, and `CallApiStub::library_name` /
`function_name`:

- The string accessor returns `Cow<'a, str>` (lossy UTF-8) — borrows
  for valid UTF-8 (the common case for ASCII identifiers), allocates
  only on U+FFFD substitution.
- The byte form is preserved as `*_bytes()`.

```rust
// Before:
let name = String::from_utf8_lossy(&obj.name()?);

// After:
let name = obj.name()?;            // Cow<'a, str>
let raw  = obj.name_bytes()?;      // &'a [u8]
```

`MethodNameResult::as_str()` added alongside `as_bytes()`.
`EventBinding::control_name` is `Cow<'a, str>` rather than `&'a [u8]`.

#### `Error::VbHeaderNotFound` removed

Replaced by the three discriminated variants `NotRecognized`,
`TruncatedContainer`, and `UnrecognizedFormat` documented in the
*Added → Recognition error discrimination* section above.
`VbProject::from_bytes` now classifies goblin parse failures as
`UnrecognizedFormat` and structural truncation during recognition
as `TruncatedContainer`, leaving `NotRecognized` for the
"no VB6 marker" case.

#### `u16` widening uses `From` instead of `as`

Internal cleanup: 17 sites where `index as u32` were mechanically
converted to `u32::from(index)`. No runtime change; cleaner code.
Affects `vbobject.rs`, `pcodemethod.rs`, `methodlink.rs`,
`methodentry.rs`, `constantpool.rs`, `functype.rs`.

### Removed

- `Error::VbHeaderNotFound` — superseded by the discriminated variants
  above. Match on `Error::recognition_failure()` to map old
  `VbHeaderNotFound` semantics to the new
  `RecognitionFailure::NotRecognized`.

### Fixed

- The constant-pool resolver is no longer single-threaded behind a
  panicking accessor; downstream code can run parses across threads
  thanks to the new `Send + Sync` assertion plus the elimination of
  panicking byte reads.

### Security

- The full crate parse path was audited under
  `clippy::{unwrap_used, expect_used, panic, arithmetic_side_effects,
  indexing_slicing}` — **no input byte sequence can panic the parser.**
  ~538 lint sites in the library and ~215 in `build.rs` were converted
  to checked alternatives. `build.rs` runs at compile time on
  CSV input from `data/` and is exempt from the per-byte lints.

### Reverse-engineering notes

- Verified `ProcCallEngine_Body` (0x66108C00) and `op_Lead2_Resume`
  (0x6610F212) in MSVBVM60: only `+0x06`, `+0x0C`, `+0x10`, `+0x18`,
  `+0x1C` of `ProcDscInfo` are read by the runtime. There is **no**
  `wLocalsNameTableOffset` field — per-procedure local-variable names
  are not recoverable from compiled binaries (documented in `TODO.md`).
- Verified `EbLoadRunTime` (0x6602F6CE): `PublicVarTable` entries
  carry only `frame_offset + type_code`. Variable names are
  recoverable indirectly via the trailing `var_count` entries of the
  FuncTypDesc array (`PrivateObjectDescriptor.func_type_descs_va`);
  static defaults don't exist in compiled binaries (documented in
  `TODO.md`).

## [0.1.0] — 2026-03-31

Initial public release.

[Unreleased]: https://github.com/BinFlip/visualbasic-rs/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/BinFlip/visualbasic-rs/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/BinFlip/visualbasic-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/BinFlip/visualbasic-rs/releases/tag/v0.1.0
