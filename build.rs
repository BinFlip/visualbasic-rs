//! Build script: generates static lookup tables from CSV data files.
//!
//! Reads CSVs at build time and produces:
//! - `opcode_generated.rs` — 6 static `[OpcodeInfo; 256]` opcode arrays
//! - `vb6_data_generated.rs` — control GUIDs, event templates, VB6 constants

use std::collections::HashMap;
use std::env;
use std::fs;
use std::io::Write;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=data/opcodes.csv");
    println!("cargo:rerun-if-changed=data/vb6_control_guids.csv");
    println!("cargo:rerun-if-changed=data/vb6_events.csv");
    println!("cargo:rerun-if-changed=data/vb6_constants.csv");
    println!("cargo:rerun-if-changed=data/vb6_control_properties.csv");
    println!("cargo:rerun-if-changed=data/msvbvm60_exports.csv");

    let csv_path = Path::new("data/opcodes.csv");
    let csv_content = fs::read_to_string(csv_path).expect("Failed to read data/opcodes.csv");

    // Parse CSV into (table, opcode) -> OpcodeEntry
    #[derive(Clone)]
    struct OpcodeEntry {
        size: i8,
        mnemonic: String,
        operand_format: String,
        pops: i8,
        pushes: i8,
        fpu_pops: u8,
        fpu_push: u8,
        mem_read: u8,
        mem_write: u8,
        category: String,
    }

    let mut entries: HashMap<(u8, u8), OpcodeEntry> = HashMap::new();

    for (line_num, line) in csv_content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Skip the header line
        if line.starts_with("table,") {
            continue;
        }

        // Parse: table,opcode,size,mnemonic,operand_format,pops,pushes,fpu_pops,fpu_push,mem_read,mem_write,category,handler,notes
        let parts: Vec<&str> = line.splitn(14, ',').collect();
        if parts.len() < 5 {
            panic!("too few columns at line {}", line_num + 1);
        }

        let table: u8 = parts[0]
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("bad table at line {}", line_num + 1));
        let opcode_str = parts[1].trim();
        let opcode: u8 = u8::from_str_radix(opcode_str.trim_start_matches("0x"), 16)
            .unwrap_or_else(|_| panic!("bad opcode '{}' at line {}", opcode_str, line_num + 1));
        let size: i8 = parts[2]
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("bad size at line {}", line_num + 1));
        let mnemonic = parts[3].trim().trim_end_matches('=').to_string();
        let operand_format = normalize_operand_format(parts[4].trim());

        // Parse semantics columns (may be empty for InvalidExcode/Unknown)
        let pops: i8 = parts
            .get(5)
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let pushes: i8 = parts
            .get(6)
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let fpu_pops: u8 = parts
            .get(7)
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let fpu_push: u8 = parts
            .get(8)
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let mem_read: u8 = parts
            .get(9)
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let mem_write: u8 = parts
            .get(10)
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0);
        let category = parts
            .get(11)
            .map(|s| s.trim().to_string())
            .unwrap_or_default();

        entries.insert(
            (table, opcode),
            OpcodeEntry {
                size,
                mnemonic,
                operand_format,
                pops,
                pushes,
                fpu_pops,
                fpu_push,
                mem_read,
                mem_write,
                category,
            },
        );
    }

    // Generate the Rust source
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir).join("opcode_generated.rs");
    let mut out = fs::File::create(&out_path).expect("Failed to create opcode_generated.rs");

    // Import semantic types used in the generated table initializers
    writeln!(out, "use super::semantics::{{PCodeDataType, OpcodeSemantics, LoadSource, StoreTarget, ArithOp, CallKind}};").unwrap();
    writeln!(out).unwrap();

    // Write the 6 table arrays
    let table_names = [
        "PRIMARY_TABLE",
        "LEAD0_TABLE",
        "LEAD1_TABLE",
        "LEAD2_TABLE",
        "LEAD3_TABLE",
        "LEAD4_TABLE",
    ];
    let table_variants = [
        "DispatchTable::Primary",
        "DispatchTable::Lead0",
        "DispatchTable::Lead1",
        "DispatchTable::Lead2",
        "DispatchTable::Lead3",
        "DispatchTable::Lead4",
    ];

    for (table_idx, (name, variant)) in table_names.iter().zip(table_variants.iter()).enumerate() {
        writeln!(
            out,
            "/// Opcode table for {} (table index {}).",
            name, table_idx
        )
        .unwrap();
        writeln!(out, "pub static {}: [OpcodeInfo; 256] = [", name).unwrap();

        for opcode in 0..=255u8 {
            let default = OpcodeEntry {
                size: 0,
                mnemonic: "Unknown".to_string(),
                operand_format: String::new(),
                pops: 0,
                pushes: 0,
                fpu_pops: 0,
                fpu_push: 0,
                mem_read: 0,
                mem_write: 0,
                category: String::new(),
            };
            let entry = entries.get(&(table_idx as u8, opcode)).unwrap_or(&default);

            let semantics_str = classify_semantics(&entry.mnemonic, &entry.category);
            let data_type_str = classify_data_type(&entry.mnemonic);
            let fpu_inplace = classify_fpu_inplace(
                &entry.mnemonic,
                &entry.category,
                entry.fpu_pops,
                entry.fpu_push,
            );

            writeln!(
                out,
                "    OpcodeInfo {{ table: {}, index: 0x{:02X}, size: {}, mnemonic: {:?}, operand_format: {:?}, pops: {}, pushes: {}, fpu_pops: {}, fpu_push: {}, fpu_inplace: {}, mem_read: {}, mem_write: {}, category: {:?}, semantics: {}, data_type: {} }},",
                variant, opcode, entry.size, entry.mnemonic, entry.operand_format,
                entry.pops, entry.pushes, entry.fpu_pops, entry.fpu_push, fpu_inplace,
                entry.mem_read, entry.mem_write, entry.category,
                semantics_str, data_type_str
            )
            .unwrap();
        }

        writeln!(out, "];").unwrap();
        writeln!(out).unwrap();
    }

    // Write the lookup function
    writeln!(
        out,
        "/// Looks up an opcode from the first 1-2 bytes of the instruction stream."
    )
    .unwrap();
    writeln!(out, "///").unwrap();
    writeln!(out, "/// # Arguments").unwrap();
    writeln!(out, "///").unwrap();
    writeln!(
        out,
        "/// * `first_byte` - The first byte of the instruction."
    )
    .unwrap();
    writeln!(
        out,
        "/// * `next_byte` - The second byte, needed if `first_byte` is a lead byte."
    )
    .unwrap();
    writeln!(out, "///").unwrap();
    writeln!(out, "/// # Returns").unwrap();
    writeln!(out, "///").unwrap();
    writeln!(
        out,
        "/// A tuple of `(opcode_info, bytes_consumed)` where `bytes_consumed` is"
    )
    .unwrap();
    writeln!(
        out,
        "/// 1 for primary table opcodes and 2 for extended (lead byte) opcodes."
    )
    .unwrap();
    writeln!(
        out,
        "pub fn lookup(first_byte: u8, next_byte: Option<u8>) -> (&'static OpcodeInfo, usize) {{"
    )
    .unwrap();
    writeln!(out, "    match first_byte {{").unwrap();
    writeln!(out, "        0xFB => {{").unwrap();
    writeln!(
        out,
        "            let idx = next_byte.unwrap_or(0) as usize;"
    )
    .unwrap();
    writeln!(out, "            (&LEAD0_TABLE[idx], 2)").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "        0xFC => {{").unwrap();
    writeln!(
        out,
        "            let idx = next_byte.unwrap_or(0) as usize;"
    )
    .unwrap();
    writeln!(out, "            (&LEAD1_TABLE[idx], 2)").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "        0xFD => {{").unwrap();
    writeln!(
        out,
        "            let idx = next_byte.unwrap_or(0) as usize;"
    )
    .unwrap();
    writeln!(out, "            (&LEAD2_TABLE[idx], 2)").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "        0xFE => {{").unwrap();
    writeln!(
        out,
        "            let idx = next_byte.unwrap_or(0) as usize;"
    )
    .unwrap();
    writeln!(out, "            (&LEAD3_TABLE[idx], 2)").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "        0xFF => {{").unwrap();
    writeln!(
        out,
        "            let idx = next_byte.unwrap_or(0) as usize;"
    )
    .unwrap();
    writeln!(out, "            (&LEAD4_TABLE[idx], 2)").unwrap();
    writeln!(out, "        }}").unwrap();
    writeln!(out, "        b => (&PRIMARY_TABLE[b as usize], 1),").unwrap();
    writeln!(out, "    }}").unwrap();
    writeln!(out, "}}").unwrap();

    generate_vb6_data(&out_dir);
    generate_control_properties(&out_dir);
    generate_msvbvm60_exports(&out_dir);
}

/// Generates `vb6_data_generated.rs` containing control GUIDs, event templates,
/// and constant name tables.
fn generate_vb6_data(out_dir: &str) {
    let out_path = Path::new(out_dir).join("vb6_data_generated.rs");
    let mut out = fs::File::create(&out_path).expect("Failed to create vb6_data_generated.rs");

    generate_control_guids(&mut out);
    generate_event_templates(&mut out);
    generate_vb6_constants(&mut out);
}

/// Generates exact CLSID-to-name lookup for VB6 intrinsic controls.
fn generate_control_guids(out: &mut fs::File) {
    let guid_csv = fs::read_to_string("data/vb6_control_guids.csv")
        .expect("Failed to read data/vb6_control_guids.csv");

    writeln!(
        out,
        "/// Exact CLSID-to-name lookup for VB6 intrinsic controls."
    )
    .unwrap();
    writeln!(out, "/// Generated from data/vb6_control_guids.csv.").unwrap();
    writeln!(
        out,
        "pub fn lookup_control_name(guid_bytes: &[u8; 16]) -> Option<&'static str> {{"
    )
    .unwrap();
    writeln!(out, "    static TABLE: &[([u8; 16], &str)] = &[").unwrap();

    for (i, line) in guid_csv.lines().enumerate() {
        if i == 0 || line.trim().is_empty() {
            continue;
        }
        let mut parts = line.splitn(2, ',');
        let clsid_str = parts.next().expect("missing clsid").trim();
        let name = parts.next().expect("missing name").trim();

        // Parse GUID string: "33AD4ED0-6699-11CF-B70C-00AA0060D393"
        let guid_bytes = parse_guid_string(clsid_str);
        writeln!(
            out,
            "        ([{}], {:?}),",
            guid_bytes
                .iter()
                .map(|b| format!("0x{b:02X}"))
                .collect::<Vec<_>>()
                .join(", "),
            name
        )
        .unwrap();
    }

    writeln!(out, "    ];").unwrap();
    writeln!(
        out,
        "    TABLE.iter().find(|(g, _)| g == guid_bytes).map(|(_, n)| *n)"
    )
    .unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();
}

/// Generates event template arrays for intrinsic controls.
fn generate_event_templates(out: &mut fs::File) {
    let events_csv =
        fs::read_to_string("data/vb6_events.csv").expect("Failed to read data/vb6_events.csv");

    let mut standard_events: Vec<(usize, String)> = Vec::new();
    let mut form_events: Vec<(usize, String)> = Vec::new();
    let mut timer_events: Vec<(usize, String)> = Vec::new();
    let mut usercontrol_events: Vec<(usize, String)> = Vec::new();

    for (i, line) in events_csv.lines().enumerate() {
        if i == 0 || line.trim().is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, ',');
        let template = parts.next().expect("missing template").trim();
        let slot: usize = parts
            .next()
            .expect("missing slot")
            .trim()
            .parse()
            .expect("bad slot");
        let name = parts.next().expect("missing name").trim().to_string();

        match template {
            "standard" => standard_events.push((slot, name)),
            "form" => form_events.push((slot, name)),
            "timer" => timer_events.push((slot, name)),
            "usercontrol" => usercontrol_events.push((slot, name)),
            _ => panic!("unknown event template: {template}"),
        }
    }

    standard_events.sort_by_key(|(s, _)| *s);
    form_events.sort_by_key(|(s, _)| *s);
    timer_events.sort_by_key(|(s, _)| *s);
    usercontrol_events.sort_by_key(|(s, _)| *s);

    writeln!(
        out,
        "/// Standard 24-event template for intrinsic controls."
    )
    .unwrap();
    writeln!(out, "/// Generated from data/vb6_events.csv.").unwrap();
    writeln!(
        out,
        "pub static STANDARD_EVENTS: [&str; {}] = [",
        standard_events.len()
    )
    .unwrap();
    for (_, name) in &standard_events {
        writeln!(out, "    {:?},", name).unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();

    writeln!(out, "/// Form lifecycle event template.").unwrap();
    writeln!(
        out,
        "pub static FORM_EVENTS: [&str; {}] = [",
        form_events.len()
    )
    .unwrap();
    for (_, name) in &form_events {
        writeln!(out, "    {:?},", name).unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();

    // Timer overrides: slot 0 = "Timer" instead of "Click"
    writeln!(out, "/// Timer event overrides (slot, name).").unwrap();
    writeln!(out, "pub static TIMER_EVENTS: &[(usize, &str)] = &[",).unwrap();
    for (slot, name) in &timer_events {
        writeln!(out, "    ({}, {:?}),", slot, name).unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();

    // UserControl extra events (slots 24+ beyond standard template)
    writeln!(
        out,
        "/// UserControl extra events beyond the standard 24-event template."
    )
    .unwrap();
    writeln!(
        out,
        "/// Slot numbers are relative (0 = slot 24 in the vtable)."
    )
    .unwrap();
    writeln!(
        out,
        "pub static USERCONTROL_EVENTS: [&str; {}] = [",
        usercontrol_events.len()
    )
    .unwrap();
    for (_, name) in &usercontrol_events {
        writeln!(out, "    {:?},", name).unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();
}

/// Generates VB6 constant name lookup from typelib data.
fn generate_vb6_constants(out: &mut fs::File) {
    let consts_csv = fs::read_to_string("data/vb6_constants.csv")
        .expect("Failed to read data/vb6_constants.csv");

    writeln!(out, "/// VB6 constant name lookup by integer value.").unwrap();
    writeln!(
        out,
        "/// Generated from data/vb6_constants.csv ({} typelib entries).",
        { consts_csv.lines().count() - 1 }
    )
    .unwrap();
    writeln!(
        out,
        "pub fn lookup_constant_name(value: i64) -> Option<&'static str> {{"
    )
    .unwrap();
    writeln!(out, "    static TABLE: &[(i64, &str)] = &[").unwrap();

    let mut const_entries: Vec<(i64, String)> = Vec::new();
    for (i, line) in consts_csv.lines().enumerate() {
        if i == 0 || line.trim().is_empty() {
            continue;
        }
        let mut parts = line.splitn(3, ',');
        let _enum_name = parts.next().expect("missing enum");
        let const_name = parts.next().expect("missing name").trim().to_string();
        let value: i64 = parts
            .next()
            .expect("missing value")
            .trim()
            .parse()
            .expect("bad value");
        const_entries.push((value, const_name));
    }
    const_entries.sort_by_key(|(v, _)| *v);

    for (value, name) in &const_entries {
        writeln!(out, "        ({}, {:?}),", value, name).unwrap();
    }

    writeln!(out, "    ];").unwrap();
    writeln!(
        out,
        "    TABLE.iter().find(|(v, _)| *v == value).map(|(_, n)| *n)"
    )
    .unwrap();
    writeln!(out, "}}").unwrap();
}

/// Parses a GUID string like "33AD4ED0-6699-11CF-B70C-00AA0060D393" into 16 LE bytes.
fn parse_guid_string(s: &str) -> [u8; 16] {
    let parts: Vec<&str> = s.split('-').collect();
    assert_eq!(parts.len(), 5, "bad GUID format: {s}");

    let d1 = u32::from_str_radix(parts[0], 16).expect("bad GUID d1");
    let d2 = u16::from_str_radix(parts[1], 16).expect("bad GUID d2");
    let d3 = u16::from_str_radix(parts[2], 16).expect("bad GUID d3");
    let d4_hi = u16::from_str_radix(parts[3], 16).expect("bad GUID d4_hi");
    let d4_lo = u64::from_str_radix(parts[4], 16).expect("bad GUID d4_lo");

    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&d1.to_le_bytes());
    bytes[4..6].copy_from_slice(&d2.to_le_bytes());
    bytes[6..8].copy_from_slice(&d3.to_le_bytes());
    bytes[8] = (d4_hi >> 8) as u8;
    bytes[9] = d4_hi as u8;
    bytes[10..16].copy_from_slice(&d4_lo.to_be_bytes()[2..8]);
    bytes
}

/// Normalize operand format strings from the modPCode.bas format to clean specifiers.
///
/// The CSV may contain display hints like `::call %c(%a)` or `"SR,%a"`.
/// We extract only the `%X` format specifiers relevant for decoding.
fn normalize_operand_format(raw: &str) -> String {
    // Remove surrounding quotes if present
    let raw = raw.trim_matches('"');

    // If empty, return empty
    if raw.is_empty() {
        return String::new();
    }

    // Extract format specifiers: sequences starting with % followed by
    // a single character that is a known specifier
    let mut result = Vec::new();
    let chars: Vec<char> = raw.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' && i + 1 < chars.len() {
            let spec = chars[i + 1];
            match spec {
                '1' | '2' | '4' | 'a' | 's' | 'l' | 'c' | 'v' | 'x' | '}' => {
                    result.push(format!("%{}", spec));
                    i += 2;
                    continue;
                }
                _ => {}
            }
        }
        i += 1;
    }

    result.join(" ")
}

/// Generates property lookup tables from `data/vb6_control_properties.csv`.
///
/// A parsed row from `vb6_control_properties.csv`.
struct PropEntry {
    index: u8,
    name: String,
    prop_type: String,
    ser_type: u8,
    callback_bytes: i8,
}

/// Generates per-control property descriptor tables from `vb6_control_properties.csv`.
fn generate_control_properties(out_dir: &str) {
    let csv_content = fs::read_to_string("data/vb6_control_properties.csv")
        .expect("Failed to read data/vb6_control_properties.csv");

    let out_path = Path::new(out_dir).join("property_generated.rs");
    let mut out = fs::File::create(&out_path).expect("Failed to create property_generated.rs");

    // Parse CSV: collect active+fontsub entries per control type
    let mut control_props: HashMap<String, Vec<PropEntry>> = HashMap::new();

    for line in csv_content.lines() {
        if line.starts_with('#') || line.starts_with("control_type") || line.trim().is_empty() {
            continue;
        }
        let cols: Vec<&str> = line.splitn(7, ',').collect();
        if cols.len() < 6 {
            continue;
        }
        let control_type = cols[0].trim();
        let index: u8 = cols[1].trim().parse().expect("bad index");
        let name = cols[2].trim();
        let ser_type: u8 = cols[3].trim().parse().expect("bad ser_type");
        let callback_bytes: i8 = cols[4].trim().parse().expect("bad callback_bytes");
        let status = cols[5].trim();

        // Only generate entries for active and flag properties
        // (flag = bits 16+17 clear in descriptor flags, opcode emitted with no value)
        if status != "active" && status != "flag" {
            continue;
        }

        // Map (status, ser_type, callback_bytes) to PropType variant name.
        // Flag entries have no value data regardless of ser_type.
        let prop_type = if status == "flag" {
            "Flag"
        } else {
            match (ser_type, callback_bytes) {
                (0, _) => "Flag",
                (1, _) => "Str",
                (2, _) => "Int16",
                (3, 0) => "Long",
                (4, 0) => "Byte",
                (5, 0) => "Long",                              // OLE_COLOR
                (6, 0) => "Byte",                              // Enum
                (6, 3) => "Long",                              // Byte + 3B callback (ScaleMode)
                (7, 0) => "Long",                              // Single
                (8, 0) | (9, 0) | (10, 0) | (11, 0) => "Long", // Twips
                (8, 4) => "LongPair",                          // Left + Top callback
                (8, 12) => "Size16",                           // ClientSize + 12B callback
                (13, 0) => "TagStr",
                (20, _) => "Font", // 11B + nameLen callback
                (21, 0) => "Picture",
                (22, 0) => "DataFormat", // StdDataFormat IPersistStream blob
                (33, 0) => "Str",        // DataMember: ASCII string, same as ser_type 1
                _ => "Byte",             // fallback
            }
        };

        control_props
            .entry(control_type.to_string())
            .or_default()
            .push(PropEntry {
                index,
                name: name.to_string(),
                prop_type: prop_type.to_string(),
                ser_type,
                callback_bytes,
            });
    }

    // Sort each control's properties by index
    for props in control_props.values_mut() {
        props.sort_by_key(|e| e.index);
    }

    // Write the PropertyDesc struct
    writeln!(
        out,
        "/// Property descriptor for a form binary property opcode."
    )
    .unwrap();
    writeln!(out, "/// Generated from data/vb6_control_properties.csv.").unwrap();
    writeln!(out, "#[derive(Debug, Clone, Copy)]").unwrap();
    writeln!(out, "pub struct PropertyDesc {{").unwrap();
    writeln!(out, "    /// Property name.").unwrap();
    writeln!(out, "    pub name: &'static str,").unwrap();
    writeln!(out, "    /// Serialized value type.").unwrap();
    writeln!(out, "    pub prop_type: super::PropType,").unwrap();
    writeln!(
        out,
        "    /// Serialization type from descriptor flags & 0x3F."
    )
    .unwrap();
    writeln!(out, "    pub ser_type: u8,").unwrap();
    writeln!(out, "    /// Extra callback bytes (0=none, 3=ScaleMode, 4=LeftTop, 12=ClientSize, -1=Font nameLen).").unwrap();
    writeln!(out, "    pub callback_bytes: i8,").unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // Write per-control static slices
    let mut control_table_names: Vec<(String, String)> = Vec::new();

    for (ctrl, props) in control_props.iter() {
        let table_name = format!("{}_PROPS", ctrl.to_uppercase());
        writeln!(
            out,
            "/// Property table for {} ({} active entries).",
            ctrl,
            props.len()
        )
        .unwrap();
        writeln!(out, "static {}: &[(u8, PropertyDesc)] = &[", table_name).unwrap();
        for PropEntry {
            index: idx,
            name,
            prop_type,
            ser_type,
            callback_bytes,
        } in props
        {
            writeln!(
                out,
                "    ({}, PropertyDesc {{ name: {:?}, prop_type: super::PropType::{}, ser_type: {}, callback_bytes: {} }}),",
                idx, name, prop_type, ser_type, callback_bytes
            )
            .unwrap();
        }
        writeln!(out, "];").unwrap();
        writeln!(out).unwrap();
        control_table_names.push((ctrl.clone(), table_name));
    }

    // Write lookup function
    writeln!(
        out,
        "/// Looks up a property by control type ID and opcode."
    )
    .unwrap();
    writeln!(out, "///").unwrap();
    writeln!(
        out,
        "/// `ctype_id` is the raw FormControlType byte value (e.g., 0=PictureBox, 11=Timer)."
    )
    .unwrap();
    writeln!(
        out,
        "/// Returns `None` for unknown opcodes or control types."
    )
    .unwrap();
    writeln!(
        out,
        "pub fn lookup_property(ctype_id: u8, opcode: u8) -> Option<&'static PropertyDesc> {{"
    )
    .unwrap();
    writeln!(
        out,
        "    let table: &[(u8, PropertyDesc)] = match ctype_id {{"
    )
    .unwrap();

    // Map FormControlType raw values to table names
    let ctype_map = [
        ("PictureBox", 0),
        ("Label", 1),
        ("TextBox", 2),
        ("Frame", 3),
        ("CommandButton", 4),
        ("CheckBox", 5),
        ("OptionButton", 6),
        ("ComboBox", 7),
        ("ListBox", 8),
        ("HScrollBar", 9),
        ("VScrollBar", 10),
        ("Timer", 11),
        ("Form", 13),
        ("DriveListBox", 16),
        ("DirListBox", 17),
        ("FileListBox", 18),
        ("Menu", 19),
        ("MDIForm", 20),
        ("Shape", 22),
        ("Line", 23),
        ("Image", 24),
        ("Data", 37),
        ("OLE", 38),
        ("UserControl", 40),
        ("PropertyPage", 41),
        ("UserDocument", 42),
    ];

    for (ctrl_name, ctype_id) in &ctype_map {
        let table_name = format!("{}_PROPS", ctrl_name.to_uppercase());
        if control_props.contains_key(*ctrl_name) {
            writeln!(out, "        {} => {},", ctype_id, table_name).unwrap();
        }
    }

    writeln!(out, "        _ => return None,").unwrap();
    writeln!(out, "    }};").unwrap();
    writeln!(
        out,
        "    table.binary_search_by_key(&opcode, |(op, _)| *op).ok().map(|i| &table[i].1)"
    )
    .unwrap();
    writeln!(out, "}}").unwrap();
}

/// Extracts the `PCodeDataType` from an opcode mnemonic suffix.
/// Returns a Rust expression string like `Some(PCodeDataType::I4)` or `None`.
/// Returns `true` if this opcode modifies the FPU TOS in place
/// (reads ST(0), writes result back to ST(0), net depth unchanged).
///
/// Detected via: unary category + FPU data type suffix + no explicit
/// fpu push/pop (the push/pop are implicit, cancelling out).
fn classify_fpu_inplace(mnemonic: &str, category: &str, fpu_pops: u8, fpu_push: u8) -> bool {
    // Only unary and arithmetic categories can modify TOS in place
    if category != "unary" && category != "arith" {
        return false;
    }
    // Must not have explicit FPU push/pop (those are stack-changing)
    if fpu_pops != 0 || fpu_push != 0 {
        return false;
    }
    // Must operate on an FPU data type
    let dt = extract_data_type_suffix(mnemonic);
    matches!(dt, Some("R4" | "R8" | "FPR4" | "FPR8" | "Date"))
}

fn classify_data_type(mnemonic: &str) -> String {
    let dt = extract_data_type_suffix(mnemonic);
    match dt {
        Some(s) => format!("Some(PCodeDataType::{})", s),
        None => "None".to_string(),
    }
}

/// Returns the PCodeDataType variant name for a mnemonic suffix, or None.
fn extract_data_type_suffix(mnemonic: &str) -> Option<&'static str> {
    // 4-char suffixes (longest first to avoid ambiguity)
    if mnemonic.ends_with("FPR4") {
        return Some("FPR4");
    }
    if mnemonic.ends_with("FPR8") {
        return Some("FPR8");
    }
    if mnemonic.ends_with("Varg") {
        return Some("Varg");
    }
    if mnemonic.ends_with("Bool") {
        return Some("Bool");
    }
    if mnemonic.ends_with("Date") {
        return Some("Date");
    }

    // 3-char suffixes
    if mnemonic.ends_with("UI1") {
        return Some("UI1");
    }
    if mnemonic.ends_with("Var") {
        // Exclude false matches like "LitVar_TRUE" (underscore + non-type tail)
        if mnemonic.contains('_')
            && !mnemonic.starts_with("CVar")
            && !mnemonic.ends_with("LdVar")
            && !mnemonic.ends_with("StVar")
            && !mnemonic.ends_with("RefVar")
            && !mnemonic.ends_with("VarCopy")
            && !mnemonic.ends_with("VarAd")
            && !mnemonic.ends_with("VarUnk")
            && !mnemonic.ends_with("VarObj")
            && !mnemonic.ends_with("VarZero")
            && !mnemonic.ends_with("VarFree")
            && !mnemonic.ends_with("VarNull")
            && !mnemonic.ends_with("VarVal")
            && !mnemonic.ends_with("VarLock")
        {
            return None;
        }
        return Some("Var");
    }
    if mnemonic.ends_with("Str") {
        return Some("Str");
    }

    // 2-char suffixes
    if mnemonic.ends_with("I2") {
        return Some("I2");
    }
    if mnemonic.ends_with("I4") {
        return Some("I4");
    }
    if mnemonic.ends_with("R4") {
        return Some("R4");
    }
    if mnemonic.ends_with("R8") {
        return Some("R8");
    }
    if mnemonic.ends_with("Cy") {
        return Some("Cy");
    }
    if mnemonic.ends_with("Ad") {
        return Some("Ad");
    }

    None
}

/// Classifies an opcode into an `OpcodeSemantics` variant.
/// Returns a Rust expression string for code generation.
fn classify_semantics(mnemonic: &str, category: &str) -> String {
    match category {
        "load_frame" => "OpcodeSemantics::Load { source: LoadSource::Frame }".to_string(),
        "load_lit" => "OpcodeSemantics::Load { source: LoadSource::Literal }".to_string(),
        "load_mem" => "OpcodeSemantics::Load { source: LoadSource::Memory }".to_string(),
        "load_ind" => "OpcodeSemantics::Load { source: LoadSource::Indirect }".to_string(),
        "store_frame" => "OpcodeSemantics::Store { target: StoreTarget::Frame }".to_string(),
        "store_mem" => "OpcodeSemantics::Store { target: StoreTarget::Memory }".to_string(),
        "store_ind" => "OpcodeSemantics::Store { target: StoreTarget::Indirect }".to_string(),
        "arith" => {
            let op = classify_arith_op(mnemonic);
            format!("OpcodeSemantics::Arithmetic {{ op: ArithOp::{} }}", op)
        }
        "unary" => {
            let op = classify_unary_op(mnemonic);
            format!("OpcodeSemantics::Unary {{ op: ArithOp::{} }}", op)
        }
        "compare" => "OpcodeSemantics::Compare".to_string(),
        "convert" => {
            let (from, to) = classify_convert_types(mnemonic);
            format!("OpcodeSemantics::Convert {{ from: {}, to: {} }}", from, to)
        }
        "branch" => {
            let conditional = mnemonic.contains("BranchF")
                || mnemonic.contains("BranchT")
                || mnemonic.starts_with("Next")
                || mnemonic.starts_with("For")
                || mnemonic.starts_with("ExitFor")
                || mnemonic.starts_with("On");
            format!("OpcodeSemantics::Branch {{ conditional: {} }}", conditional)
        }
        "call" => {
            let kind = if mnemonic.starts_with("ThisVCall") {
                "ThisVCall"
            } else if mnemonic.starts_with("VCall") {
                "VCall"
            } else if mnemonic.starts_with("ImpAdCall") {
                "ImpAdCall"
            } else if mnemonic.starts_with("Late") {
                "LateCall"
            } else {
                "Other"
            };
            format!("OpcodeSemantics::Call {{ kind: CallKind::{} }}", kind)
        }
        "return" => "OpcodeSemantics::Return".to_string(),
        "stack" => "OpcodeSemantics::Stack".to_string(),
        "nop" => "OpcodeSemantics::Nop".to_string(),
        "io" => "OpcodeSemantics::Io".to_string(),
        _ => "OpcodeSemantics::Unclassified".to_string(),
    }
}

fn classify_arith_op(mnemonic: &str) -> &'static str {
    if mnemonic.starts_with("Add") {
        return "Add";
    }
    if mnemonic.starts_with("Sub") {
        return "Sub";
    }
    if mnemonic.starts_with("Mul") {
        return "Mul";
    }
    if mnemonic.starts_with("Div") {
        return "Div";
    }
    if mnemonic.starts_with("IDv") {
        return "IDiv";
    }
    if mnemonic.starts_with("Mod") {
        return "Mod";
    }
    if mnemonic.starts_with("Pow") {
        return "Pow";
    }
    if mnemonic.starts_with("Concat") {
        return "Concat";
    }
    if mnemonic.starts_with("And") {
        return "And";
    }
    if mnemonic.starts_with("Or") {
        return "Or";
    }
    if mnemonic.starts_with("Xor") {
        return "Xor";
    }
    if mnemonic.starts_with("Eqv") {
        return "Eqv";
    }
    if mnemonic.starts_with("Imp") && !mnemonic.starts_with("ImpAd") {
        return "Imp";
    }
    "Other"
}

fn classify_unary_op(mnemonic: &str) -> &'static str {
    if mnemonic.starts_with("Not") {
        return "Not";
    }
    if mnemonic.starts_with("UMi") {
        return "Neg";
    }
    if mnemonic.starts_with("FnAbs") {
        return "Abs";
    }
    "Other"
}

/// Parses convert mnemonic `C{Target}{Source}` or `FnC{Target}{Source}`.
/// Returns (from_expr, to_expr) as Rust expression strings.
fn classify_convert_types(mnemonic: &str) -> (String, String) {
    let name = if let Some(s) = mnemonic.strip_prefix("FnC") {
        s
    } else if let Some(s) = mnemonic.strip_prefix('C') {
        s
    } else {
        return ("None".into(), "None".into());
    };

    // Known target prefixes (longest first), then the remainder is source
    let targets: &[(&str, &str)] = &[
        ("UI1", "UI1"),
        ("Bool", "Bool"),
        ("Date", "Date"),
        ("Byte", "UI1"),
        ("Int", "I2"),
        ("Lng", "I4"),
        ("Sng", "R4"),
        ("Dbl", "R8"),
        ("Cur", "Cy"),
        ("Str", "Str"),
        ("Var", "Var"),
        ("I2", "I2"),
        ("I4", "I4"),
        ("R4", "R4"),
        ("R8", "R8"),
        ("Cy", "Cy"),
        ("Ad", "Ad"),
    ];

    for &(prefix, target_dt) in targets {
        if let Some(rest) = name.strip_prefix(prefix) {
            let source = suffix_to_data_type(rest);
            let to = format!("Some(PCodeDataType::{})", target_dt);
            return (source, to);
        }
    }

    ("None".into(), "None".into())
}

/// Maps a raw suffix string to a `Some(PCodeDataType::X)` expression or `None`.
fn suffix_to_data_type(s: &str) -> String {
    let dt = match s {
        "UI1" | "Byte" => "UI1",
        "I2" | "Int" => "I2",
        "I4" | "Lng" => "I4",
        "R4" | "Sng" => "R4",
        "R8" | "Dbl" => "R8",
        "Cy" | "Cur" => "Cy",
        "Str" => "Str",
        "Var" | "VarCopy" | "VarTmp" | "VarVal" | "VarNull" => "Var",
        "Bool" => "Bool",
        "Ad" | "Unk" | "UnkFunc" | "AdFunc" => "Ad",
        "Date" | "DateVar" => "Date",
        "FPR4" => "FPR4",
        "FPR8" => "FPR8",
        _ => return "None".to_string(),
    };
    format!("Some(PCodeDataType::{})", dt)
}

/// Map a CSV calling convention string to the Rust enum variant path.
fn map_calling_conv(s: &str) -> &'static str {
    match s {
        "fastcall" => "CallingConv::Fastcall",
        "stdcall" => "CallingConv::Stdcall",
        "cdecl" => "CallingConv::Cdecl",
        "special" => "CallingConv::Special",
        other => panic!("unknown calling convention: {other}"),
    }
}

/// Map a CSV parameter/return type string to the Rust enum variant path.
fn map_param_type(s: &str) -> &'static str {
    match s {
        "void" => "VbParamType::Void",
        "int16" => "VbParamType::Int16",
        "uint16" => "VbParamType::UInt16",
        "int32" => "VbParamType::Int32",
        "uint32" => "VbParamType::UInt32",
        "int64" => "VbParamType::Int64",
        "uint8" => "VbParamType::UInt8",
        "float" => "VbParamType::Float",
        "double" => "VbParamType::Double",
        "bool" => "VbParamType::Bool",
        "Bstr" => "VbParamType::Bstr",
        "BstrPtr" => "VbParamType::BstrPtr",
        "VariantPtr" => "VbParamType::VariantPtr",
        "SafeArrayPtr" => "VbParamType::SafeArrayPtr",
        "SafeArrayPtrPtr" => "VbParamType::SafeArrayPtrPtr",
        "IUnknownPtr" => "VbParamType::IUnknownPtr",
        "IUnknownPtrPtr" => "VbParamType::IUnknownPtrPtr",
        "IDispatchPtr" => "VbParamType::IDispatchPtr",
        "IDispatchPtrPtr" => "VbParamType::IDispatchPtrPtr",
        "Hresult" => "VbParamType::Hresult",
        "GuidPtr" => "VbParamType::GuidPtr",
        "VoidPtr" => "VbParamType::VoidPtr",
        "Int32Ptr" => "VbParamType::Int32Ptr",
        "Int16Ptr" => "VbParamType::Int16Ptr",
        "UInt8Ptr" => "VbParamType::UInt8Ptr",
        "Int64Ptr" => "VbParamType::Int64Ptr",
        other => panic!("unknown param type: {other}"),
    }
}

/// Generates the MSVBVM60 export signature lookup tables.
fn generate_msvbvm60_exports(out_dir: &str) {
    let csv_content = fs::read_to_string("data/msvbvm60_exports.csv")
        .expect("Failed to read data/msvbvm60_exports.csv");

    let out_path = Path::new(out_dir).join("msvbvm60_exports_generated.rs");
    let mut out =
        fs::File::create(&out_path).expect("Failed to create msvbvm60_exports_generated.rs");

    writeln!(
        out,
        "use super::{{CallingConv, VbParamType, ExportParam, ExportSignature}};"
    )
    .unwrap();
    writeln!(out).unwrap();

    // Parse CSV rows
    struct ExportEntry {
        name: String,
        ordinal: u16,
        cc: String,
        ret_type: String,
        variadic: bool,
        params: Vec<(String, String)>, // (type, name)
        category: String,
    }

    let mut entries: Vec<ExportEntry> = Vec::new();

    for (line_num, line) in csv_content.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with("name,") {
            continue;
        }

        // name,ordinal,calling_convention,return_type,variadic,params,category,notes
        let parts: Vec<&str> = line.splitn(8, ',').collect();
        if parts.len() < 7 {
            panic!("too few columns at line {}", line_num + 1);
        }

        let name = parts[0].trim().to_string();
        let ordinal: u16 = parts[1]
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("bad ordinal at line {}", line_num + 1));
        let cc = parts[2].trim().to_string();
        let ret_type = parts[3].trim().to_string();
        let variadic = parts[4].trim() == "1";
        let params_str = parts[5].trim();
        let category = parts[6].trim().to_string();

        // Validate calling convention and return type at build time
        map_calling_conv(&cc);
        map_param_type(&ret_type);

        // Parse params: "Type1 name1;Type2 name2;..."
        let params: Vec<(String, String)> = if params_str.is_empty() {
            Vec::new()
        } else {
            params_str
                .split(';')
                .map(|p| {
                    let p = p.trim();
                    let space = p
                        .find(' ')
                        .unwrap_or_else(|| panic!("bad param '{}' at line {}", p, line_num + 1));
                    let ty = p[..space].trim().to_string();
                    let nm = p[space + 1..].trim().to_string();
                    map_param_type(&ty); // validate
                    (ty, nm)
                })
                .collect()
        };

        entries.push(ExportEntry {
            name,
            ordinal,
            cc,
            ret_type,
            variadic,
            params,
            category,
        });
    }

    // Sort by name for binary search
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    // Generate per-export param arrays
    for (i, entry) in entries.iter().enumerate() {
        if !entry.params.is_empty() {
            writeln!(out, "static PARAMS_{i}: &[ExportParam] = &[").unwrap();
            for (ty, nm) in &entry.params {
                writeln!(
                    out,
                    "    ExportParam {{ ty: {}, name: {:?} }},",
                    map_param_type(ty),
                    nm
                )
                .unwrap();
            }
            writeln!(out, "];").unwrap();
        }
    }
    writeln!(out).unwrap();

    // Generate main sorted export table
    writeln!(out, "/// MSVBVM60 export signatures, sorted by name.").unwrap();
    writeln!(
        out,
        "/// Generated from data/msvbvm60_exports.csv ({} entries).",
        entries.len()
    )
    .unwrap();
    writeln!(out, "pub static EXPORTS: &[ExportSignature] = &[").unwrap();
    for (i, entry) in entries.iter().enumerate() {
        let params_ref = if entry.params.is_empty() {
            "&[]".to_string()
        } else {
            format!("PARAMS_{i}")
        };
        writeln!(
            out,
            "    ExportSignature {{ name: {:?}, ordinal: {}, calling_convention: {}, return_type: {}, variadic: {}, params: {}, category: {:?} }},",
            entry.name,
            entry.ordinal,
            map_calling_conv(&entry.cc),
            map_param_type(&entry.ret_type),
            entry.variadic,
            params_ref,
            entry.category,
        )
        .unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();

    // Generate name lookup via binary search
    writeln!(
        out,
        "/// Look up an export by name (binary search on sorted table)."
    )
    .unwrap();
    writeln!(
        out,
        "pub fn lookup_export_by_name(name: &str) -> Option<&'static ExportSignature> {{"
    )
    .unwrap();
    writeln!(
        out,
        "    EXPORTS.binary_search_by_key(&name, |e| e.name).ok().map(|i| &EXPORTS[i])"
    )
    .unwrap();
    writeln!(out, "}}").unwrap();
    writeln!(out).unwrap();

    // Generate ordinal lookup table (only entries with ordinal > 0)
    let ordinal_entries: Vec<(usize, u16)> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.ordinal > 0)
        .map(|(i, e)| (i, e.ordinal))
        .collect();

    writeln!(
        out,
        "/// Ordinal-to-index mapping for ordinal-only exports."
    )
    .unwrap();
    writeln!(out, "static ORDINAL_TABLE: &[(u16, usize)] = &[").unwrap();
    let mut sorted_ordinals = ordinal_entries.clone();
    sorted_ordinals.sort_by_key(|(_, o)| *o);
    for (idx, ord) in &sorted_ordinals {
        writeln!(out, "    ({ord}, {idx}),").unwrap();
    }
    writeln!(out, "];").unwrap();
    writeln!(out).unwrap();

    // Generate ordinal lookup function
    writeln!(
        out,
        "/// Look up an export by ordinal number (binary search)."
    )
    .unwrap();
    writeln!(
        out,
        "pub fn lookup_export_by_ordinal(ordinal: u16) -> Option<&'static ExportSignature> {{"
    )
    .unwrap();
    writeln!(
        out,
        "    ORDINAL_TABLE.binary_search_by_key(&ordinal, |(o, _)| *o).ok().map(|i| &EXPORTS[ORDINAL_TABLE[i].1])"
    )
    .unwrap();
    writeln!(out, "}}").unwrap();
}
