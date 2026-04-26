//! Full VB6 project dump — ildasm-style text output.
//!
//! Usage:
//!   cargo run --example dump -- <path-to-vb6-exe>

use std::collections::HashMap;
use std::error::Error as StdError;
use std::str;
use std::{env, fs, process};

use visualbasic::{
    MethodEntry, VbControl, VbObject, VbProject,
    pcode::operand::Operand,
    vb::{
        comreg::ComRegData,
        constants, eventname,
        external::ExternalKind,
        formdata::{FormControlType, FormDataParser},
        functype::FuncTypDesc,
        guitable::{GuiTableEntry, GuiTableIter},
        projectinfo2::{ControlTypeIter, ProjectInfo2, read_name_strings},
        property::{PropertyValue, decode_form_type},
        publicbytes::{ClassFormPublicBytes, PublicVarTable},
        varstub::VarStubIter,
    },
};

type DynResult<T> = Result<T, Box<dyn StdError>>;

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {}", e);
        process::exit(1);
    }
}

fn run() -> DynResult<()> {
    let path = env::args().nth(1).ok_or_else(|| -> Box<dyn StdError> {
        eprintln!("usage: dump <path-to-vb6-exe>");
        "missing argument".into()
    })?;

    let data = fs::read(&path)
        .map_err(|e| -> Box<dyn StdError> { format!("cannot read '{}': {}", path, e).into() })?;

    let project = VbProject::from_bytes(&data).map_err(|e| -> Box<dyn StdError> {
        format!("failed to parse VB6 project: {}", e).into()
    })?;

    print_asm(&project, &path)
}

/// Prints the full ildasm-style text dump for a VB6 project.
fn print_asm(project: &VbProject<'_>, path: &str) -> DynResult<()> {
    print_assembly_header(project, path)?;
    print_com_registration(project)?;
    print_gui_table(project)?;
    print_externals(project)?;
    print_components(project)?;
    print_control_types(project)?;

    let pi2_va = project.object_table().project_info2_va()?;

    // Collect GUI table entries for form data parsing (parallel index with objects)
    let map = project.address_map();
    let hdr = project.vb_header();
    let gui_va = hdr.gui_table_va()?;
    let form_count = hdr.form_count()?;
    let gui_entries: Vec<GuiTableEntry<'_>> = GuiTableIter::new(map, gui_va, form_count).collect();

    for (i, obj) in project.objects()?.enumerate() {
        let obj = obj.map_err(|e| -> Box<dyn StdError> {
            format!("failed to parse object {}: {}", i, e).into()
        })?;
        println!();
        let gui_entry = gui_entries.get(i);
        print_object(&obj, pi2_va, gui_entry)?;
    }
    Ok(())
}

/// Prints the project-level header: file path, VB header fields, project data,
/// and object table summary.
fn print_assembly_header(project: &VbProject<'_>, path: &str) -> DynResult<()> {
    let hdr = project.vb_header();
    let pd = project.project_data();
    let ot = project.object_table();
    let name = str_or(project.project_name(), "<unknown>");
    let mode = if project.is_pcode()? {
        "P-Code"
    } else {
        "Native"
    };

    let runtime_build = hdr.runtime_build()?;
    let runtime_revision = hdr.runtime_revision()?;
    let lcid = hdr.lcid()?;
    let object_count = project.object_count()?;
    let project_data_va = hdr.project_data_va()?;
    let sub_main_va = hdr.sub_main_va()?;

    println!("// VB6 Assembly: {}", path);
    println!(
        "// Runtime {}.{:02} | {} | LCID 0x{:04X} | {} objects",
        runtime_build, runtime_revision, mode, lcid, object_count
    );
    println!("// Language DLL: {}", lossy_cstr(hdr.lang_dll()?));
    println!("// Path: {}", lossy_cstr(pd.path_info()?));
    if sub_main_va != 0 {
        println!("// Entry: Sub Main (VA 0x{:08X})", sub_main_va);
    }
    println!("//");
    println!(
        "// VBHeader VA:     0x{:08X}  ProjectData VA: 0x{:08X}",
        project_data_va.wrapping_sub(0x30),
        project_data_va
    );
    println!(
        "// ObjectTable VA:  0x{:08X}  ObjectArray VA: 0x{:08X}",
        pd.object_table_va()?,
        ot.object_array_va()?
    );
    println!(
        "// Code VA range:   0x{:08X} - 0x{:08X}  Data size: 0x{:X}",
        pd.code_start_va()?,
        pd.code_end_va()?,
        pd.data_size()?
    );
    println!();
    println!(".assembly {} {{", name);
    println!("    .compilation {}", mode.to_lowercase());
    println!("    .version {}.{:02}", runtime_build, runtime_revision);
    println!("    .lcid 0x{:08X}", lcid);
    if let Some(guid) = visualbasic::vb::control::Guid::from_bytes(ot.uuid()?) {
        println!("    .uuid {}", guid);
    }
    println!(
        "    .forms {}  .externals {}  .thunks {}",
        hdr.form_count()?,
        hdr.external_count()?,
        hdr.thunk_count()?
    );
    println!("}}");
    Ok(())
}

/// Prints COM registration data (TypeLib GUIDs, version, help file).
fn print_com_registration(project: &VbProject<'_>) -> DynResult<()> {
    let map = project.address_map();
    let hdr = project.vb_header();
    let com_va = hdr.com_register_data_va()?;
    if com_va == 0 {
        return Ok(());
    }
    let Ok(data) = map.slice_from_va(com_va, 256) else {
        return Ok(());
    };
    let Ok(reg) = ComRegData::parse(data, com_va) else {
        return Ok(());
    };

    let proj_name = reg.project_name(map).unwrap_or("?");
    let guid = reg
        .project_guid()
        .map(|g| format!("{}", g))
        .unwrap_or_else(|| "?".into());

    println!();
    println!(
        "// COM TypeLib: {} v{}.{} LCID=0x{:04X}",
        guid,
        reg.major_version()?,
        reg.minor_version()?,
        reg.lcid()?
    );
    println!("// COM Project: {}", proj_name);

    if let Some(help) = reg.help_dir(map) {
        println!("// COM HelpDir: {}", help);
    }

    let Ok(objects) = reg.objects(map) else {
        return Ok(());
    };
    for obj in objects {
        let clsid = obj
            .clsid()
            .map(|g| format!("{}", g))
            .unwrap_or_else(|| "?".into());
        let name = obj.object_name(map).unwrap_or("?");
        let desc = obj.description(map);
        let prog_id = format!("{}.{}", proj_name, name);
        let object_flags = obj.object_flags()?;

        println!("//   .comclass {} {{", prog_id);
        println!("//       CLSID = {}", clsid);
        if let Some(d) = desc {
            println!("//       Description = \"{}\"", d);
        }
        println!(
            "//       Flags = 0x{:04X}{}",
            object_flags,
            format_obj_flags(object_flags)
        );
        let misc = obj.misc_status()?;
        if misc != 0 {
            println!("//       MiscStatus = {}", misc);
        }
        let toolbox = obj.toolbox_bitmap_id()?;
        if toolbox != 0 {
            println!("//       ToolboxBitmap32 = {}", toolbox);
        }
        let icon = obj.default_icon_id()?;
        if icon != 0 {
            println!("//       DefaultIcon = {}", icon);
        }
        if let Ok(default_iface_guids) = obj.default_iface_guids(map) {
            for guid in default_iface_guids {
                println!("//       DefaultIID = {}", guid);
            }
        }
        if let Ok(source_iface_guids) = obj.source_iface_guids(map) {
            for guid in source_iface_guids {
                println!("//       SourceIID  = {}", guid);
            }
        }
        println!("//   }}");
    }
    Ok(())
}

/// Prints the GUI table entries (form dimensions, scroll info, controls).
fn print_gui_table(project: &VbProject<'_>) -> DynResult<()> {
    let map = project.address_map();
    let hdr = project.vb_header();
    let gui_va = hdr.gui_table_va()?;
    let form_count = hdr.form_count()?;
    if gui_va == 0 || form_count == 0 {
        return Ok(());
    }

    println!();
    for (i, entry) in GuiTableIter::new(map, gui_va, form_count).enumerate() {
        let guid = entry
            .guid()
            .map(|g| format!("{g}"))
            .unwrap_or_else(|| "?".into());
        let otype = entry.object_type();
        let data_va = entry.form_data_va()?;
        let data_size = entry.form_data_size()?;
        let type_flags = entry.object_type_raw()?;
        print!(
            ".gui /*{:02}*/ {} {} data=0x{:08X} size=0x{:X}",
            i, otype, guid, data_va, data_size
        );
        if type_flags & 0xFFF0 != 0 {
            print!(" flags=0x{:X}", type_flags);
        }
        println!();
        if let Some(g2) = entry.secondary_guid() {
            println!("    // Secondary GUID: {g2}");
        }
        if let Some(iid) = entry.type_data_iid() {
            println!("    // Type IID: {iid}");
        }
    }
    Ok(())
}

/// Prints the external reference table (COM components, OCX, typelibs).
fn print_externals(project: &VbProject<'_>) -> DynResult<()> {
    let mut any = false;
    for (i, entry) in project.externals()?.enumerate() {
        if !any {
            println!();
            any = true;
        }
        match entry {
            Ok(ext) => {
                let desc = resolve_external(project, &ext);
                let kind_str = match ext.kind() {
                    Ok(k) => format!("{}", k),
                    Err(e) => format!("<error: {}>", e),
                };
                println!(".extern /*{:02}*/ {} // {}", i, desc, kind_str);
            }
            Err(e) => println!(".extern /*{:02}*/ // error: {}", i, e),
        }
    }
    Ok(())
}

/// Prints the VBHeader component table (OCX/ActiveX control registrations).
fn print_components(project: &VbProject<'_>) -> DynResult<()> {
    let mut any = false;
    for comp in project.components()? {
        if !any {
            println!();
            any = true;
        }
        let filename = comp.ocx_filename();
        let progid = comp.prog_id();
        let class = comp.class_name();
        print!(".component {filename}!{class} // {progid}");
        let events = comp.event_names();
        if !events.is_empty() {
            print!(" events=[{}]", events.join(", "));
        }
        println!();
    }
    Ok(())
}

/// Prints ProjectInfo2 control type entries (CLSIDs with instance names).
fn print_control_types(project: &VbProject<'_>) -> DynResult<()> {
    let map = project.address_map();
    let ot = project.object_table();
    let pi2_va = ot.project_info2_va()?;
    if pi2_va == 0 {
        return Ok(());
    }

    let Ok(_pi2_data) = map.slice_from_va(pi2_va, ProjectInfo2::HEADER_SIZE) else {
        return Ok(());
    };

    let entries: Vec<_> = ControlTypeIter::new(map, pi2_va).collect();
    if entries.is_empty() {
        return Ok(());
    }

    // Collect COM property names from trailing strings
    let prop_names = read_name_strings(map, pi2_va, entries.len() as u32);

    println!();
    println!(".controltypes {{");
    for entry in &entries {
        let guid_str = format_guid_entry(entry, map);
        let name_str = entry.control_name(map).unwrap_or("");
        if name_str.is_empty() {
            println!("    {}", guid_str);
        } else {
            println!("    {} \"{}\"", guid_str, name_str);
        }
    }
    if !prop_names.is_empty() {
        println!("    // COM properties: {}", prop_names.join(", "));
    }
    println!("}}");
    Ok(())
}

/// Formats object type flags as a human-readable parenthesized list.
fn format_obj_flags(flags: u16) -> String {
    let mut parts = Vec::new();
    if flags & 0x0020 != 0 {
        parts.push("Control");
    }
    if flags & 0x0080 != 0 {
        parts.push("DocObject");
    }
    if flags & 0x00B2 != 0 {
        parts.push("Automatable");
    }
    if flags & 0x0001 != 0 {
        parts.push("SkipReg");
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!(" ({})", parts.join(", "))
    }
}

/// Formats a ProjectInfo2 control type entry as `{GUID} (ClassName)`.
fn format_guid_entry(
    entry: &visualbasic::vb::projectinfo2::ControlTypeEntry,
    map: &visualbasic::addressmap::AddressMap<'_>,
) -> String {
    entry
        .control_guid(map)
        .map(|g| {
            let class = g.control_class_name().unwrap_or("");
            if class.is_empty() {
                format!("{}", g)
            } else {
                format!("{} ({})", g, class)
            }
        })
        .unwrap_or_else(|| "?".into())
}

/// Resolves an external table entry to a human-readable description string.
fn resolve_external(
    project: &VbProject<'_>,
    ext: &visualbasic::vb::external::ExternalTableEntry<'_>,
) -> String {
    let map = project.address_map();
    let obj_va = ext.external_object_va().unwrap_or(0);
    if obj_va == 0 {
        return "va=0x00000000".into();
    }

    let kind = match ext.kind() {
        Ok(k) => k,
        Err(_) => return format!("va=0x{obj_va:08X}"),
    };

    match kind {
        ExternalKind::DeclareFunction => {
            if let Some(decl) = ext.as_declare(map) {
                let lib = decl.library_name(map).unwrap_or("?");
                let func = decl.function_name(map).unwrap_or("?");
                format!("{lib}!{func}")
            } else {
                format!("va=0x{obj_va:08X}")
            }
        }
        ExternalKind::TypeLib => {
            if let Some(tlib) = ext.as_typelib(map)
                && let Some(guid) = tlib.typelib_guid(map)
            {
                format!("typelib {guid}")
            } else {
                format!("typelib va=0x{obj_va:08X}")
            }
        }
        ExternalKind::Unknown(t) => {
            format!("unknown(0x{t:08X}) va=0x{obj_va:08X}")
        }
    }
}

/// Prints a single VB6 object: descriptor, controls, method links, and
/// disassembled P-Code methods.
fn print_object(
    obj: &VbObject<'_, '_>,
    _pi2_va: u32,
    gui_entry: Option<&GuiTableEntry<'_>>,
) -> DynResult<()> {
    let name = str_or(obj.name(), "<unknown>");
    let kind = obj.object_kind()?;
    let desc = obj.descriptor();
    let info = obj.info();

    // Build VA -> method index+name map for event cross-referencing
    let mut va_to_method: HashMap<u32, (u16, String)> = HashMap::new();
    let methods_va_for_lookup = info.methods_va().unwrap_or(0);
    for (mi, entry) in obj.methods()?.enumerate() {
        let mname = obj
            .method_name(mi as u16)
            .ok()
            .and_then(|r| r.as_bytes())
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_else(|| format!("method_{:02X}", mi));

        if let Ok(ref me) = entry {
            let va = match me {
                MethodEntry::PCode(_) => {
                    let entry_va = methods_va_for_lookup.wrapping_add(mi as u32 * 4);
                    obj.project()
                        .address_map()
                        .slice_from_va(entry_va, 4)
                        .map(|d| u32::from_le_bytes([d[0], d[1], d[2], d[3]]))
                        .unwrap_or(0)
                }
                MethodEntry::Native { va } => *va,
                MethodEntry::Runtime { va } => *va,
                MethodEntry::Null => 0,
            };
            if va != 0 {
                va_to_method.insert(va, (mi as u16, mname.clone()));
            }
        }
    }

    println!(".object {} : {} {{", name, kind);
    println!("    // Object Type:     0x{:08X}", desc.object_type_raw()?);
    println!("    // ObjectInfo VA:   0x{:08X}", desc.object_info_va()?);
    println!("    // Object Name VA:  0x{:08X}", desc.object_name_va()?);
    println!(
        "    // Methods VA:      0x{:08X}  ({} methods)",
        info.methods_va()?,
        desc.method_count()?
    );
    println!("    // Constants VA:    0x{:08X}", info.constants_va()?);
    if let Some(opt) = obj.optional_info() {
        println!(
            "    // P-Code Count:    {}  Control Count: {}  Method Links: {}",
            opt.pcode_count()?,
            opt.control_count()?,
            opt.method_link_count()?
        );
        let map = obj.project().address_map();
        if let Some(g) = opt.resolve_clsid(map) {
            println!("    // Object CLSID:   {g}");
        }
        for (_, g) in opt.default_iids(map) {
            println!("    // Default IID:    {g}");
        }
        for (_, g) in opt.gui_guids(map) {
            println!("    // GUI GUID:       {g}");
        }
        for (_, g) in opt.events_iids(map) {
            println!("    // Event IID:      {g}");
        }
        let init_off = opt.initialize_event_offset()?;
        let term_off = opt.terminate_event_offset()?;
        let init_slot = init_off / 4;
        let term_slot = term_off / 4;
        println!(
            "    // Init/Term slots: {}/{} (offsets 0x{:04X}/0x{:04X})",
            init_slot, term_slot, init_off, term_off
        );
    }
    if let Some(priv_obj) = obj.private_object() {
        println!(
            "    // Public funcs:    {}  Public vars: {}  Flags: 0x{:04X}",
            priv_obj.func_count()?,
            priv_obj.var_count()?,
            priv_obj.flags()?
        );
        let ftd_va = priv_obj.func_type_descs_va()?;
        if ftd_va != 0 {
            println!("    // FuncTypDescs VA: 0x{:08X}", ftd_va);
        }
        let pn_va = priv_obj.param_names_va()?;
        if pn_va != 0 {
            println!("    // Param Names VA:  0x{:08X}", pn_va);
        }
    }

    // Build FuncTypDesc lookup table (needed for signatures and variable types)
    let func_descs = build_func_type_descs(obj);

    // PublicBytes has different formats per object type
    let pb_va = desc.public_bytes_va()?;
    if desc.is_module() {
        // Modules: PublicVarTable with variable descriptors
        print_public_vars(obj.project(), pb_va);
    } else {
        // Classes/Forms: instance size + control property init entries
        print_class_form_public_bytes(obj.project(), pb_va);
    }

    // Print variable implementation stubs (compiler metadata)
    if let Some(priv_obj) = obj.private_object() {
        let stubs_va = priv_obj.var_stubs_va()?;
        let var_count = priv_obj.var_count()?;
        if stubs_va != 0 && var_count > 0 {
            println!();
            for (i, stub) in
                VarStubIter::new(obj.project().address_map(), stubs_va, var_count).enumerate()
            {
                let name = stub.name();
                let name_str = if name.is_empty() { "?" } else { name };
                let pcount = stub.param_count().unwrap_or(0);
                let params = if pcount > 0 {
                    format!(" ({} params)", pcount)
                } else {
                    String::new()
                };
                println!("    .varimpl /*{:02}*/ {}{}", i, name_str, params);
            }
        }
    }

    // Parse form data for authoritative control types
    let form_data = gui_entry.and_then(|ge| {
        let map = obj.project().address_map();
        let va = ge.form_data_va().ok()?;
        let size = ge.form_data_size().ok()? as usize;
        if va == 0 || size == 0 {
            return None;
        }
        let data = map.slice_from_va(va, size).ok()?;
        FormDataParser::parse(data).ok()
    });

    // Show form data header and controls from form binary
    if let Some(ref fd) = form_data {
        let ge = gui_entry.ok_or("missing gui_entry while form_data is Some")?;
        let h = fd.header();
        let ge_data_va = ge.form_data_va()?;
        let ge_data_size = ge.form_data_size()?;
        println!();
        println!(
            "    .formdata va=0x{:08X} size=0x{:X} width={} height={} {{",
            ge_data_va,
            ge_data_size,
            h.width()?,
            h.height()?
        );

        // Decode form-level properties
        let form_props = fd.form_properties();
        if !form_props.is_empty() {
            let ge_otype = ge.object_type();
            let form_ctype = decode_form_type(ge_otype, form_props, obj.project());
            let decoded: Vec<String> = fd
                .form_properties_decoded(form_ctype)
                .map(|p| match &p.value {
                    PropertyValue::Flag => p.name.to_string(),
                    v => format!("{}={v}", p.name),
                })
                .collect();
            if !decoded.is_empty() {
                println!("        // {}", decoded.join(", "));
            }
        }

        for fc in fd.controls() {
            let fc_name = fc.name();
            let arr = fc
                .array_index()
                .map(|i| format!("({i})"))
                .unwrap_or_default();
            let props = fc.raw_properties();
            let indent = "    ".repeat(fc.depth() as usize);
            print!(
                "        {indent}[{:3}] {}{} As {}",
                fc.cid(),
                fc_name,
                arr,
                fc.control_type()
            );
            if !props.is_empty() {
                let decoded: Vec<String> = fc
                    .properties()
                    .map(|p| match &p.value {
                        PropertyValue::Flag => p.name.to_string(),
                        v => format!("{}={v}", p.name),
                    })
                    .collect();
                let decoded = decoded.join(", ");
                if !decoded.is_empty() {
                    if props.len() > 64 {
                        println!(" ({} bytes)", props.len());
                        println!("        {indent}              // {decoded}");
                    } else {
                        println!(" // {decoded}");
                    }
                } else {
                    println!();
                }
            } else {
                println!();
            }
        }
        println!("    }}");
    }

    // Print controls with event cross-referencing
    // Use form data for authoritative type identification when available
    let controls: Vec<VbControl<'_>> = if let Some(ref fd) = form_data {
        match obj.controls_with_form_data(fd) {
            Ok(it) => it.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    } else {
        match obj.controls() {
            Ok(it) => it.filter_map(|r| r.ok()).collect(),
            Err(_) => Vec::new(),
        }
    };

    if !controls.is_empty() {
        println!();
        for ctrl in &controls {
            let raw_name = ctrl.name();
            let ctrl_index = ctrl.index().unwrap_or(0);
            let ctrl_name = if raw_name.is_empty() {
                format!("control_{}", ctrl_index)
            } else {
                raw_name.into_owned()
            };
            // class_name() now prefers form_control_type (authoritative) over GUID
            let class = ctrl.class_name().unwrap_or("ActiveX");
            let guid_str = ctrl.guid().map(|g| format!(" {g}")).unwrap_or_default();

            println!("    .control {} As {}{}", ctrl_name, class, guid_str);

            // Show events from event_table_va (runtime-populated, rarely on disk)
            let event_count = ctrl.event_count().unwrap_or(0);
            for ei in 0..event_count {
                let handler_va = ctrl.event_handler_va(ei).unwrap_or(0);
                if handler_va == 0 {
                    continue;
                }
                if let Some((mi, mname)) = va_to_method.get(&handler_va) {
                    println!("        event[{:02}] -> /*{:02X}*/ {}", ei, mi, mname);
                } else {
                    println!("        event[{:02}] -> 0x{:08X}", ei, handler_va);
                }
            }

            // Show events from event sink vtable (on-disk connection point)
            let map = obj.project().address_map();
            if let Some(sink) = ctrl.event_sink(map) {
                for (slot, raw_va) in sink.connected_handlers() {
                    // Resolve event name from template
                    let ev_ctype = ctrl.form_control_type().unwrap_or_else(|| {
                        // Fallback: detect UserControl from class name or object kind
                        match ctrl.class_name() {
                            Some("UserControl") => FormControlType::UserControl,
                            _ if kind == "UserControl" => FormControlType::UserControl,
                            _ => FormControlType::Unknown(0xFF),
                        }
                    });
                    let ev_name = eventname::event_name(slot, ev_ctype).unwrap_or("?");

                    if let Some(thunk) = sink.resolve_handler_thunk(slot, map) {
                        let method_ref = va_to_method
                            .get(&thunk.method_entry_va)
                            .map(|(mi, mname)| format!("/*{mi:02X}*/ {mname}"))
                            .unwrap_or_else(|| format!("0x{:08X}", thunk.method_entry_va));
                        println!(
                            "        sink[{:02}] {ev_name} event_id={} -> {}",
                            slot, thunk.event_dispatch_id, method_ref
                        );
                    } else if let Some(native) = sink.resolve_native_thunk(slot, map) {
                        println!("        sink[{:02}] {ev_name} native {native}", slot);
                    } else {
                        println!("        sink[{:02}] {ev_name} -> 0x{:08X}", slot, raw_va);
                    }
                }
            }
        }
    }

    // Build remaining lookup tables for method info
    let links: HashMap<usize, _> = match obj.method_links() {
        Ok(it) => it
            .enumerate()
            .filter_map(|(i, r)| Some((i, r.ok()?)))
            .collect(),
        Err(_) => HashMap::new(),
    };
    let method_entries: Vec<_> = match obj.methods() {
        Ok(it) => it.collect(),
        Err(_) => Vec::new(),
    };

    // Determine total method count from all sources
    let descriptor_method_count = obj.descriptor().method_count().unwrap_or(0);
    let total = descriptor_method_count
        .max(method_entries.len() as u32)
        .max(links.keys().copied().max().map_or(0, |m| m as u32 + 1));

    // Print unified .method blocks
    for mi in 0..total as usize {
        let mname = obj
            .method_name(mi as u16)
            .ok()
            .and_then(|r| r.as_bytes())
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_else(|| format!("method_{mi:02X}"));

        let sig = func_descs.get(&mi).map(|ftd| {
            visualbasic::project::format_signature(ftd, &mname, obj.project().address_map())
        });
        let link = links.get(&mi);
        let entry = method_entries.get(mi);

        // Determine what we know about this method
        let header = sig.as_deref().unwrap_or(&mname);

        let has_real_entry = matches!(
            entry,
            Some(Ok(MethodEntry::PCode(_) | MethodEntry::Native { .. }))
        );
        let has_runtime = matches!(entry, Some(Ok(MethodEntry::Runtime { .. })));
        let has_name = mname != format!("method_{mi:02X}");

        // Skip methods where we have no useful information
        if sig.is_none() && link.is_none() && !has_real_entry && !has_name {
            if has_runtime {
                // Show runtime slots only if they have a real name
                continue;
            }
            continue;
        }

        println!();
        println!("    .method /*{:02X}*/ {} {{", mi, header);

        // Show optional parameter defaults (only if function has Optional args)
        if let Some(ftd) = func_descs.get(&mi) {
            let has_optional = ftd.arg_types().iter().any(|t| t.is_optional());
            if has_optional {
                let defaults = ftd.optional_defaults(obj.project().address_map());
                for (di, def) in defaults.iter().enumerate() {
                    println!("        // default[{}]: {} = {}", di, def.vt, def);
                }
            }
        }

        // Show implementation details
        match entry {
            Some(Ok(MethodEntry::Runtime { va })) => {
                let label = if *va >= 0x10000 { "runtime" } else { "data" };
                println!("        // {label} 0x{va:08X}");
            }
            Some(Ok(MethodEntry::Native { va })) => {
                println!("        // native VA 0x{va:08X}");
            }
            Some(Err(e)) => {
                println!("        // error: {e}");
            }
            _ => {}
        }

        // Show method link thunk if available
        if let Some(lnk) = link {
            let adjust = match lnk.this_adjust {
                Some(0xFFFF) => " this_adjust=default".to_string(),
                Some(a) => format!(" this_adjust=0x{a:02X}"),
                None => String::new(),
            };
            println!(
                "        // thunk 0x{:08X} -> code 0x{:08X}{adjust}",
                lnk.thunk_va, lnk.code_va
            );
        }

        // Show P-Code disassembly if available
        if let Some(Ok(MethodEntry::PCode(method))) = entry {
            let pdi = method.proc_dsc();
            let proc_size = method.proc_size()?;
            let pdi_va = method.pcode_va() + proc_size as u32;
            println!(
                "        // pcode_va=0x{:08X} proc_dsc=0x{:08X} frame=0x{:04X} pcode=0x{:04X} args={} cleanup={} opt_flags=0x{:04X} bos_skip=0x{:04X} actual_size=0x{:04X}",
                method.pcode_va(),
                pdi_va,
                method.frame_size()?,
                proc_size,
                pdi.arg_count()?,
                pdi.cleanup_count()?,
                pdi.proc_opt_flags_raw()?,
                pdi.bos_skip_table_offset()?,
                pdi.actual_size()?
            );
            for entry in method.proc_dsc().cleanup_entries() {
                let offset = entry.frame_offset()? as i16;
                println!(
                    "        // cleanup [ebp{:+}]: {}",
                    offset,
                    entry.property_type()
                );
            }
            for insn in method.instructions()? {
                match insn {
                    Ok(i) => {
                        // Annotate integer literals with VB6 constant names
                        let annotation = i.operands.iter().find_map(|op| match op {
                            Some(Operand::Int32(v)) => constants::constant_name(*v as i64),
                            Some(Operand::Int16(v)) => constants::constant_name(*v as i64),
                            _ => None,
                        });
                        if let Some(name) = annotation {
                            println!("        {} // {name}", i);
                        } else {
                            println!("        {}", i);
                        }
                    }
                    Err(e) => {
                        println!("        // decode error: {}", e);
                        break;
                    }
                }
            }
        }

        println!("    }}");
    }

    println!("}}");
    Ok(())
}

/// Converts a Cow string result to an owned string, using `fallback` on error.
fn str_or(result: Result<std::borrow::Cow<'_, str>, visualbasic::Error>, fallback: &str) -> String {
    result
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| fallback.into())
}

/// Prints public variable declarations from a module's PublicVarTable.
fn print_public_vars(project: &VbProject<'_>, pb_va: u32) {
    if pb_va == 0 {
        return;
    }
    let map = project.address_map();
    let Ok(header) = map.slice_from_va(pb_va, PublicVarTable::HEADER_SIZE) else {
        return;
    };
    let Ok(pvt_header) = PublicVarTable::parse(header) else {
        return;
    };
    let total_size = match pvt_header.total_size() {
        Ok(t) => t as usize,
        Err(_) => return,
    };
    let Ok(full_data) = map.slice_from_va(pb_va, total_size) else {
        return;
    };
    let Ok(pvt) = PublicVarTable::parse(full_data) else {
        return;
    };
    if pvt.var_count() == 0 {
        return;
    }
    println!();
    for entry in pvt.valid_vars() {
        println!(
            "    Public var_{:04X} As {} // offset=0x{:04X} type=0x{:04X}",
            entry.frame_offset,
            entry.type_name(),
            entry.frame_offset,
            entry.type_code
        );
    }
}

/// Prints class/form instance metadata (instance size, IIDs, control properties).
fn print_class_form_public_bytes(project: &VbProject<'_>, pb_va: u32) {
    if pb_va == 0 {
        return;
    }
    let map = project.address_map();
    // Read enough for header + potential GUID data
    let Ok(data) = map.slice_from_va(pb_va, 0x80) else {
        return;
    };
    let Ok(cfpb) = ClassFormPublicBytes::parse(data) else {
        return;
    };

    let instance_size = cfpb.instance_size().unwrap_or(0);
    println!(
        "    // instance_size=0x{:04X} ({} bytes)",
        instance_size, instance_size
    );

    if let Some(iid) = cfpb.default_iid() {
        println!("    // default_iid={}", iid);
    }
    if let Some(iid) = cfpb.events_iid() {
        println!("    // events_iid={}", iid);
    }

    if cfpb.has_controls() {
        println!(
            "    // control_props: {} entries ({} properties)",
            cfpb.control_count().unwrap_or(0),
            cfpb.property_count().unwrap_or(0)
        );
        for entry in cfpb.control_entries() {
            println!(
                "    //   +0x{:04X}: {} (type=0x{:02X} flags=0x{:02X})",
                entry.frame_offset().unwrap_or(0),
                entry.property_type(),
                entry.raw_type(),
                entry.flags()
            );
        }
    }
}

/// Converts a null-terminated byte slice to a lossy UTF-8 string.
fn lossy_cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Build a map of method_index -> FuncTypDesc from the PrivateObjectDescriptor.
fn build_func_type_descs<'a>(obj: &VbObject<'a, 'a>) -> HashMap<usize, FuncTypDesc<'a>> {
    let mut map = HashMap::new();
    let Some(priv_obj) = obj.private_object() else {
        return map;
    };
    let ftd_array_va = match priv_obj.func_type_descs_va() {
        Ok(v) => v,
        Err(_) => return map,
    };
    if ftd_array_va == 0 {
        return map;
    }

    // The FuncTypDesc pointer array has one entry per function+variable
    let func_count = priv_obj.func_count().unwrap_or(0) as u32;
    let var_count = priv_obj.var_count().unwrap_or(0) as u32;
    let total = func_count + var_count;
    let am = obj.project().address_map();

    for i in 0..total {
        // Read the VA of this FuncTypDesc entry
        let ptr_va = ftd_array_va.wrapping_add(i * 4);
        let Ok(ptr_data) = am.slice_from_va(ptr_va, 4) else {
            continue;
        };
        let desc_va = u32::from_le_bytes([ptr_data[0], ptr_data[1], ptr_data[2], ptr_data[3]]);
        if desc_va == 0 {
            continue;
        }

        // Read and parse the FuncTypDesc with extended data (arg types at +0x20)
        let Ok(desc_data) = am.slice_from_va(desc_va, 0x40) else {
            continue;
        };
        if let Ok(ftd) = FuncTypDesc::parse_extended(desc_data) {
            map.insert(i as usize, ftd);
        }
    }
    map
}
