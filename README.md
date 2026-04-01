# visualbasic

Parse and inspect Visual Basic 6 compiled binaries.

This crate provides typed access to all internal structures within a VB6
compiled executable, from the PE entry point down to individual P-Code
bytecode instructions.

## Quick start

```rust
use visualbasic::VbProject;

let file_bytes = std::fs::read("sample.exe").unwrap();
let project = VbProject::from_bytes(&file_bytes).unwrap();

println!("Project: {:?}", project.project_name());
println!("Objects: {}", project.object_count());

for obj in project.objects() {
    let obj = obj.unwrap();
    println!("  {} ({})", String::from_utf8_lossy(obj.name().unwrap()), obj.object_kind());

    for method in obj.pcode_methods() {
        let method = method.unwrap();
        for insn in method.instructions() {
            println!("    {}", insn.unwrap());
        }
    }
}
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
