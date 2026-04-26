# visualbasic

Parse and inspect Visual Basic 6 compiled binaries.

This crate provides typed access to all internal structures within a VB6
compiled executable, from the PE entry point down to individual P-Code
bytecode instructions.

## Quick start

```rust
use visualbasic::{VbProject, RecognitionFailure};

let file_bytes = std::fs::read("sample.exe")?;

let project = match VbProject::from_bytes(&file_bytes) {
    Ok(p) => p,
    Err(e) => match e.recognition_failure() {
        Some(RecognitionFailure::NotRecognized | RecognitionFailure::UnrecognizedFormat) => {
            // Quietly skip non-VB6 files.
            return Ok(());
        }
        Some(RecognitionFailure::TruncatedContainer) => {
            eprintln!("warn: looks VB6 but truncated: {e}");
            return Ok(());
        }
        _ => return Err(e.into()),
    },
};

println!("Project: {}", project.project_name()?);
println!("Objects: {}", project.object_count()?);

for obj in project.objects()? {
    let obj = obj?;
    println!("  {} ({})", obj.name()?, obj.object_kind()?);

    for method in obj.pcode_methods()? {
        let method = method?;
        for insn in method.instructions()? {
            println!("    {}", insn?);
        }
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

## What it parses

- **PE entry point** detection (EXE push-stub and DLL export patterns)
- **VBHeader**, **ProjectData**, **ObjectTable** and the full structure chain
- **PublicObjectDescriptor**, **ObjectInfo**, **OptionalObjectInfo**, **PrivateObjectDescriptor**
- **P-Code bytecode**: opcode tables, operand decoding, streaming instruction iterator
- **Controls**: ControlInfo, event sink vtables, event handler thunks
- **COM metadata**: GUIDs, TypeLib registration, external component tables
- **Form binary data**: control trees, property streams, font/picture resources
- **MSVBVM60.DLL exports**: 169 runtime function signatures with parameter types

## High-level walkers

For consumer code that wants a single tagged stream rather than walking
each substructure by hand:

- [`VbProject::code_entrypoints()`] — every code VA in the project
  (P-Code stubs, native procs, native thunks, event handlers, `Sub Main`)
  in one `Vec<CodeEntrypoint>`.
- [`VbObject::events()`] — joined `(control, event_slot, handler_va)`
  bindings for a form, with per-control-type event-name resolution.
- [`VbProject::gui_entries_with_form_data()`] — pairs each GUI table
  entry with its parsed form binary in one iterator.
- [`VbProject::compilation_mode()`] — distinguishes `Pcode` / `Native` /
  `Mixed` binaries (combines the project flag with a per-object scan).
- [`VbProject::diagnostics()`] — eager parse-health probe surfacing
  missing optional structures and known-anomaly patterns.

## Cargo features

| Feature | Default | Effect |
|---|---|---|
| `tracing` | off | Emits structured `tracing::warn!` events at silent fail-soft sites. No effect when disabled — the helpers compile to no-ops. |

## Example tool

The included `dump` example produces an ildasm-style text dump of a VB6 executable:

```sh
cargo run --example dump -- path/to/sample.exe
```

## Disclaimer

The VB6 compiled binary format was never officially or publicly documented by
Microsoft. All structure layouts, field semantics, and P-Code opcode definitions
in this crate have been reverse engineered from MSVBVM60.DLL (6.00.9848) and
VB6.EXE (6.00.8176) by humans and AI. While the results have been cross-verified
against runtime behavior, errors and inaccuracies are possible.

## License

Apache-2.0
