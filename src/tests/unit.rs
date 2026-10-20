use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push(name);
    p
}

macro_rules! require_fixture {
    ($name:expr) => {
        if !fixture($name).exists() {
            eprintln!("skipped: fixture '{}' not present", $name);
            return;
        }
    };
}

#[test]
fn parse_kernel32_pe() {
    require_fixture!("kernel32.dll");
    let bin = crate::parser::parse_file(&fixture("kernel32.dll")).expect("parse kernel32");
    assert!(bin.format.starts_with("PE"));
    assert_eq!(bin.arch, "x86_64");
    assert!(bin.image_base >= 0x140000000);
    assert!(!bin.sections.is_empty());
    assert!(bin
        .sections
        .iter()
        .any(|s| s.name == ".text" && s.is_executable));
}

#[test]
fn kernel32_imports_are_virtual_addresses() {
    require_fixture!("kernel32.dll");
    let bin = crate::parser::parse_file(&fixture("kernel32.dll")).expect("parse kernel32");
    for imp in &bin.imports {
        assert!(
            imp.offset >= bin.image_base,
            "import {} at {:x} below image base",
            imp.name,
            imp.offset
        );
    }
    assert!(bin
        .imports
        .iter()
        .any(|i| i.name == "QueryPerformanceCounter"));
    assert!(bin
        .imports
        .iter()
        .any(|i| i.library.eq_ignore_ascii_case("kernelbase.dll")));
}

#[test]
fn kernel32_exports_have_ordinals() {
    require_fixture!("kernel32.dll");
    let bin = crate::parser::parse_file(&fixture("kernel32.dll")).expect("parse kernel32");
    assert!(!bin.exports.is_empty());
    let named = bin.exports.iter().filter(|e| e.forwarder.is_none()).count();
    assert!(named > 100, "expected many named exports, got {}", named);
    let with_ordinal = bin.exports.iter().filter(|e| e.ordinal != 0).count();
    assert!(
        with_ordinal > named / 2,
        "most named exports should carry ordinals"
    );
}

#[test]
fn kernel32_is_not_dotnet() {
    require_fixture!("kernel32.dll");
    let bin = crate::parser::parse_file(&fixture("kernel32.dll")).expect("parse kernel32");
    assert!(!crate::parser::dotnet::is_dotnet(&bin));
}

#[test]
fn parse_keygenme_x86() {
    require_fixture!("KeygenMe 1 by scherzo.exe");
    let bin =
        crate::parser::parse_file(&fixture("KeygenMe 1 by scherzo.exe")).expect("parse keygenme");
    assert!(bin.format.starts_with("PE"));
    assert_eq!(bin.arch, "x86");
    assert!(bin.sections.iter().any(|s| s.name == ".text"));
}

#[test]
fn parse_dll3s_dll() {
    require_fixture!("DLL3S_full-fix.dll");
    let bin = crate::parser::parse_file(&fixture("DLL3S_full-fix.dll")).expect("parse dll3s");
    assert!(bin.is_dll, "DLL3S must be flagged as a DLL");
    assert!(
        !crate::parser::dotnet::is_dotnet(&bin),
        "DLL3S is a native DLL, not .NET"
    );
}

#[test]
fn parse_zip_rejected() {
    assert!(crate::parser::parse_file(&fixture("KeygenMe_1_by_scherzo.zip")).is_err());
}

#[test]
fn parse_4cry_packed_detection() {
    require_fixture!("4CRY-inner.exe");
    let data = std::fs::read(fixture("4CRY-inner.exe")).expect("read 4cry");
    let bin =
        crate::parser::parse_raw_bytes(data.clone(), 0x140000000, "x86_64").expect("raw parse");
    let mz = data.windows(2).filter(|w| w == b"MZ").count();
    assert!(mz >= 2, "expected an embedded PE header, found {}", mz);
    assert!(!bin.sections.is_empty());
}

#[test]
fn disasm_kernel32_text() {
    require_fixture!("kernel32.dll");
    let bin = crate::parser::parse_file(&fixture("kernel32.dll")).expect("parse kernel32");
    let d = crate::disasm::disassemble_binary(&bin).expect("disasm kernel32");
    assert!(
        d.instructions.len() > 1000,
        "expected many instructions, got {}",
        d.instructions.len()
    );
    assert!(d
        .instructions
        .iter()
        .any(|i| i.mnemonic == "ret" || i.mnemonic == "retn"));
}

#[test]
fn disasm_skip_data_not_truncate() {
    require_fixture!("kernel32.dll");
    let bin = crate::parser::parse_file(&fixture("kernel32.dll")).expect("parse kernel32");
    let d = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let text = bin.sections.iter().find(|s| s.name == ".text").unwrap();
    let text_insns = d
        .instructions
        .iter()
        .filter(|i| i.address >= text.vaddr && i.address < text.vaddr + text.size)
        .count();
    assert!(
        text_insns > 500,
        "text section should decode past embedded data, got {}",
        text_insns
    );
}

#[test]
fn analyze_kernel32_pipeline() {
    require_fixture!("kernel32.dll");
    let bin = crate::parser::parse_file(&fixture("kernel32.dll")).expect("parse kernel32");
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let result = crate::analysis::auto_analyze(&disasm, &bin);
    assert!(!result.functions.is_empty(), "expected functions");
    assert!(!result.xrefs.all.is_empty(), "expected xrefs");
    assert!(
        !result.pseudocode.is_empty(),
        "expected decompiled functions"
    );
    for f in &result.functions {
        assert!(
            f.end >= f.entry,
            "function {:#x} has inverted range",
            f.entry
        );
    }
}

#[test]
fn analysis_noreturn_does_not_hang() {
    require_fixture!("4CRY-inner.exe");
    let data = std::fs::read(fixture("4CRY-inner.exe")).expect("read 4cry");
    let bin = crate::parser::parse_raw_bytes(data, 0x140000000, "x86_64").expect("raw parse");
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let funcs = crate::analysis::function::detect_functions(
        &disasm.instructions,
        bin.entry_point,
        &bin.symbols,
    );
    let mut an = crate::analysis::noreturn::NoReturnAnalyzer::new();
    an.analyze(&disasm.instructions, &bin.imports, &funcs, None);
    let _ = an.get_noreturn_functions().len();
}

#[test]
fn decompile_function_with_args() {
    require_fixture!("kernel32.dll");
    let bin = crate::parser::parse_file(&fixture("kernel32.dll")).expect("parse kernel32");
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let result = crate::analysis::auto_analyze(&disasm, &bin);
    let with_call_args = result
        .pseudocode
        .values()
        .filter(|pc| {
            pc.lines
                .iter()
                .any(|l| l.kind == crate::analysis::LineKind::Call && l.text.contains("("))
        })
        .count();
    assert!(
        with_call_args > 0,
        "decompiled output should contain calls with arguments"
    );
}

#[test]
fn type_manager_c_roundtrip() {
    let mut m = crate::type_system::DataTypeManager::new();
    let s = m.create_struct("PebLike").unwrap();
    m.add_field(
        s,
        "InheritedAddressSpace",
        crate::type_system::ID_UCHAR,
        Some(0),
        "",
    )
    .unwrap();
    m.add_field(
        s,
        "ReadImageFileExecOptions",
        crate::type_system::ID_UCHAR,
        Some(1),
        "",
    )
    .unwrap();
    m.add_field(
        s,
        "BeingDebugged",
        crate::type_system::ID_UCHAR,
        Some(2),
        "",
    )
    .unwrap();
    m.add_field(s, "BitField", crate::type_system::ID_UINT, Some(4), "")
        .unwrap();
    let decl = m.to_c_decl(s, 0);
    assert!(decl.contains("PebLike"));
    assert!(decl.contains("BeingDebugged"));
    let ptr = m.create_pointer(s).unwrap();
    assert_eq!(m.size_of(ptr), Some(8));
}

#[test]
fn assembler_roundtrip_through_iced() {
    let cases: &[(&str, &str)] = &[
        ("mov eax, 5", "mov"),
        ("mov rax, 0x1122334455667788", "mov"),
        ("xor eax, eax", "xor"),
        ("xor rax, rax", "xor"),
        ("push rbp", "push"),
        ("mov rbp, rsp", "mov"),
        ("sub rsp, 0x20", "sub"),
        ("mov r8, r9", "mov"),
        ("lea rax, [rip + 0x10]", "lea"),
        ("jmp 0x100000", "jmp"),
        ("je 0x100000", "je"),
        ("call 0x100000", "call"),
        ("cmp eax, 0x10", "cmp"),
        ("test rax, rax", "test"),
        ("ret", "ret"),
        ("nop", "nop"),
        ("int3", "int3"),
        ("mov qword ptr [rax + 0x8], rdx", "mov"),
        ("movzx eax, al", "movzx"),
        ("movsxd rax, eax", "movsxd"),
    ];
    for (line, expect_mnem) in cases {
        let bytes = crate::asm::assemble("x86_64", 0x1000, line)
            .unwrap_or_else(|e| panic!("{}: {}", line, e));
        let decoded = crate::disasm::disassemble_region(&bytes, 0x1000, "x86_64").expect("decode");
        assert!(!decoded.is_empty(), "{} did not decode", line);
        assert_eq!(
            decoded[0].mnemonic, *expect_mnem,
            "{} decoded as {:?}",
            line, decoded[0]
        );
    }
}

#[test]
fn kernel32_pe_resources_and_version_info() {
    require_fixture!("kernel32.dll");
    let bin = crate::parser::parse_file(&fixture("kernel32.dll")).expect("parse kernel32");
    let mut a = crate::analysis::pe_resources::PEResourceAnalyzer::new();
    a.analyze(&bin);
    assert!(
        a.get_resource_count() > 0,
        "expected resources in kernel32.dll"
    );
    let types = a.get_resources_by_type();
    assert!(
        types.contains_key(&crate::analysis::pe_resources::ResourceType::Version)
            || types.contains_key(&crate::analysis::pe_resources::ResourceType::Manifest)
            || types.contains_key(&crate::analysis::pe_resources::ResourceType::Icon),
        "expected version/manifest/icon resources, got {:?}",
        types.keys().map(|k| k.as_str()).collect::<Vec<_>>()
    );
    if let Some(vi) = &a.version_info {
        assert!(
            !vi.file_version.is_empty() || !vi.company_name.is_empty(),
            "version info should carry at least one field"
        );
    }
}

#[test]
fn import_stubs_resolve_names() {
    require_fixture!("kernel32.dll");
    let bin = crate::parser::parse_file(&fixture("kernel32.dll")).expect("parse kernel32");
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let funcs = crate::analysis::function::detect_functions(
        &disasm.instructions,
        bin.entry_point,
        &bin.symbols,
    );
    let stubs = crate::analysis::advanced::build_stub_map(&disasm.instructions, &funcs, &bin, None);
    let resolved = stubs
        .values()
        .filter(|s| {
            matches!(s.kind, crate::analysis::StubKind::ImportThunk)
                && (s.target_name.contains('!') || s.target_name.starts_with("jmp"))
        })
        .count();
    let thunks = stubs
        .values()
        .filter(|s| matches!(s.kind, crate::analysis::StubKind::ImportThunk))
        .count();
    assert!(
        thunks > 100,
        "expected many import thunks in kernel32, got {}",
        thunks
    );
    assert!(
        resolved > thunks / 2,
        "expected most thunks resolved to lib!name, got {}/{}",
        resolved,
        thunks
    );
}

#[test]
fn disassemble_bytes_tool_path() {
    let insns = crate::disasm::disassemble_region(
        &[0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11],
        0x1000,
        "x86_64",
    )
    .unwrap();
    assert_eq!(insns.len(), 1);
    assert_eq!(insns[0].mnemonic, "mov");
    assert_eq!(insns[0].bytes.len(), 10);
}

#[test]
fn decompiler_folds_constants_and_dce() {
    let mut bytes = Vec::new();
    let mut addr = 0x1000u64;
    for line in ["mov eax, 1", "add eax, 2", "mov ebx, eax", "ret"] {
        let b = crate::asm::assemble("x86_64", addr, line).unwrap();
        addr += b.len() as u64;
        bytes.extend(b);
    }
    let insns = crate::disasm::disassemble_region(&bytes, 0x1000, "x86_64").unwrap();
    let pinstrs = crate::analysis::pcode::lift_all(&insns);
    let cfg = crate::analysis::cfg::build_cfg(&insns, 0x1000, addr);
    let sf = crate::analysis::stack::analyze_stack(&pinstrs, 0x1000, addr, false, 0);
    let lookup = rustc_hash::FxHashMap::default();
    let pc = crate::analysis::decompiler::decompile(crate::analysis::decompiler::LiftInput {
        cfg: &cfg,
        pinstrs_in_func: &pinstrs,
        imap: &insns,
        stack: &sf,
        func_name: "test",
        func_lookup: &lookup,
        is64: true,
        is_win64: false,
        thunk_targets: &rustc_hash::FxHashMap::default(),
        imports: &rustc_hash::FxHashMap::default(),
        cancel: None,
        debug_types: None,
    });
    let text: String = pc
        .lines
        .iter()
        .map(|l| l.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains("return 3") || text.contains("= 3"),
        "expected folded 1+2, got:\n{}",
        text
    );
    assert!(
        !text.contains("ebx ="),
        "expected dead store removed, got:\n{}",
        text
    );
    assert!(
        text.contains("return"),
        "expected return with folded value:\n{}",
        text
    );
}

#[test]
fn type_reconstruction_multi_level_pointers() {
    let mut bytes = Vec::new();
    let mut addr = 0x1000u64;
    for line in [
        "mov rax, qword ptr [rbx + 0x8]",
        "mov rcx, qword ptr [rax + 0x10]",
        "mov rdx, qword ptr [rax + 0x18]",
        "ret",
    ] {
        let b = crate::asm::assemble("x86_64", addr, line).unwrap();
        addr += b.len() as u64;
        bytes.extend(b);
    }
    let insns = crate::disasm::disassemble_region(&bytes, 0x1000, "x86_64").unwrap();
    let pinstrs = crate::analysis::pcode::lift_all(&insns);
    let mut tr = crate::analysis::type_reconstruction::TypeReconstructor::new();
    tr.analyze_function(&pinstrs, 0x1000, addr);
    let types = tr.get_all_types();
    let rbx_struct = types
        .values()
        .find(|t| t.name == "struct_rbx")
        .expect("expected struct_rbx from provenance chaining");
    let offsets: Vec<i64> = rbx_struct.fields.iter().map(|f| f.offset).collect();
    assert!(
        offsets.contains(&0x18) && offsets.contains(&0x20),
        "expected chained fields at 0x18/0x20, got {:x?}",
        offsets
    );
    let field8 = rbx_struct
        .fields
        .iter()
        .find(|f| f.offset == 8)
        .expect("field at +8");
    assert!(
        matches!(types.get(&field8.type_id), Some(t) if matches!(t.kind, crate::analysis::type_reconstruction::TypeKind::Pointer { .. })),
        "field +8 should be a pointer type"
    );
}

#[test]
fn iced_rip_relative_format() {
    let insns =
        crate::disasm::disassemble_region(&[0xFF, 0x25, 0x34, 0x12, 0x00, 0x00], 0x1000, "x86_64")
            .unwrap();
    assert!(!insns.is_empty());
    assert!(
        insns[0].ops().contains("rip+0x1234") || insns[0].ops().contains("rip+1234h"),
        "unexpected rip-relative format: {}",
        insns[0].operands
    );
}

fn temp_source(name: &str) -> (std::path::PathBuf, String) {
    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let tmp_dir = std::env::temp_dir().join(format!("rdb_test_{}_{}", std::process::id(), uniq));
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let src = tmp_dir.join(name);
    std::fs::copy(fixture(name), &src).unwrap();
    let db = crate::project::db_path_for(src.to_str().unwrap());
    (src, db)
}

fn sample_program(
    src: &std::path::Path,
) -> (crate::gui::ProgramData, crate::analysis::AnalysisResult) {
    use crate::gui::ProgramData;
    let bin = crate::parser::parse_file(src).expect("parse");
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let analysis = crate::analysis::auto_analyze(&disasm, &bin);

    let mut program = ProgramData {
        binary: Some(bin),
        disasm: Some(disasm),
        analysis: Some(std::sync::Arc::new(analysis.clone())),
        current_program_name: "TestProj".into(),
        ..Default::default()
    };
    program.comments.insert(0x140001000, "hello comment".into());
    program.user_func_names.insert(0x140001234, "MyFunc".into());
    program.bookmarks.push(crate::gui::Bookmark {
        addr: 0x140002000,
        note: "bm".into(),
        kind: crate::gui::BookmarkKind::Note,
    });
    program.patch_seq = 7;
    program.user_labels.insert(0x140003000, "data_xyz".into());
    let mut tm = crate::type_system::DataTypeManager::new();
    let s = tm.create_struct("TestStruct").unwrap();
    tm.add_field(s, "a", crate::type_system::ID_INT, Some(0), "")
        .unwrap();
    program.types = tm;
    program.data_types_at.insert(0x140004000, s);
    (program, analysis)
}

#[test]
fn project_db_roundtrip() {
    require_fixture!("kernel32.dll");
    let (src, db) = temp_source("kernel32.dll");
    let (program, analysis) = sample_program(&src);

    crate::project::save_project_db(&program, &db).expect("save db");

    let snap = crate::project::load_project_db(&db).expect("load db");
    assert_eq!(snap.source_path, src.to_str().unwrap());
    assert_eq!(snap.project_name, "TestProj");
    assert_eq!(snap.disasm.arch, program.disasm.as_ref().unwrap().arch);

    let a = program.disasm.as_ref().unwrap();
    assert_eq!(snap.disasm.instructions.len(), a.instructions.len());
    assert_eq!(
        snap.disasm.instructions[0].address,
        a.instructions[0].address
    );
    assert_eq!(
        snap.disasm.instructions[0].mnemonic,
        a.instructions[0].mnemonic
    );
    assert_eq!(
        snap.disasm.instructions[0].bytes_slice(),
        a.instructions[0].bytes_slice()
    );
    assert_eq!(
        snap.disasm.instructions[100].operands,
        a.instructions[100].operands
    );

    assert_eq!(snap.analysis.functions.len(), analysis.functions.len());
    assert_eq!(snap.analysis.xrefs.all.len(), analysis.xrefs.all.len());
    assert_eq!(snap.analysis.cfgs.len(), analysis.cfgs.len());
    assert_eq!(
        snap.analysis.stack_frames.len(),
        analysis.stack_frames.len()
    );
    assert_eq!(
        snap.analysis.pseudocode.len(),
        0,
        "pseudocode cache must be dropped on load"
    );
    assert_eq!(snap.analysis.callers.len(), analysis.callers.len());
    assert_eq!(snap.analysis.stubs.len(), analysis.stubs.len());
    assert_eq!(
        snap.analysis.noreturn_functions,
        analysis.noreturn_functions
    );

    assert_eq!(
        snap.annotations.comments.get(&0x140001000).unwrap(),
        "hello comment"
    );
    assert_eq!(
        snap.annotations.user_func_names.get(&0x140001234).unwrap(),
        "MyFunc"
    );
    assert_eq!(snap.annotations.bookmarks.len(), 1);
    assert_eq!(snap.annotations.patch_seq, 7);
    assert_eq!(
        snap.annotations.user_labels.get(&0x140003000).unwrap(),
        "data_xyz"
    );
    let t = snap
        .annotations
        .types
        .find_by_name("TestStruct")
        .expect("struct restored");
    assert_eq!(snap.annotations.types.size_of(t), Some(4));
    assert_eq!(snap.annotations.data_types_at.get(&0x140004000), Some(&t));

    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(&src);
}

#[test]
fn project_db_stale_source_rejected() {
    require_fixture!("kernel32.dll");
    let (src, db) = temp_source("kernel32.dll");
    let (program, _) = sample_program(&src);
    crate::project::save_project_db(&program, &db).expect("save db");

    let f = std::fs::OpenOptions::new().append(true).open(&src).unwrap();
    f.set_modified(std::time::SystemTime::now()).unwrap();
    drop(f);

    assert!(
        crate::project::load_project_db(&db).is_none(),
        "stale DB must be rejected"
    );

    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(&src);
}

#[test]
fn project_db_corrupt_rejected() {
    require_fixture!("kernel32.dll");
    let (src, db) = temp_source("kernel32.dll");
    let (program, _) = sample_program(&src);
    crate::project::save_project_db(&program, &db).expect("save db");

    let mut bytes = std::fs::read(&db).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xFF;
    std::fs::write(&db, &bytes).unwrap();

    assert!(
        crate::project::load_project_db(&db).is_none(),
        "corrupt DB must be rejected"
    );

    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(&src);
}

#[test]
fn open_file_into_program_restores_from_db() {
    require_fixture!("kernel32.dll");
    let (src, db) = temp_source("kernel32.dll");
    let (program, _) = sample_program(&src);
    crate::project::save_project_db(&program, &db).expect("save db");

    let mut state = crate::gui::AppState::new();
    crate::gui::open_file_into_program(&mut state, src.to_str().unwrap(), None).expect("open");

    assert!(
        state.analysis.is_some(),
        "analysis should be restored from DB"
    );
    assert_eq!(state.current_program_name, "TestProj");
    let expected = program.disasm.as_ref().unwrap().instructions.len();
    assert_eq!(state.disasm.as_ref().unwrap().instructions.len(), expected);
    assert_eq!(state.comments.get(&0x140001000).unwrap(), "hello comment");

    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(&src);
}

#[test]
fn function_entry_expands_over_x86_prologue() {
    let base: u64 = 0x10000000;
    let func = base + 0x20;
    let join = func + 6;

    let mut buf: Vec<u8> = Vec::new();
    buf.push(0xE8);
    let rel = (join as i64 - (base + 5) as i64) as i32;
    buf.extend(rel.to_le_bytes());
    buf.push(0xC3);
    while buf.len() < 0x20 {
        buf.push(0xCC);
    }

    buf.extend([0x55, 0x89, 0xE5, 0x83, 0xEC, 0x14]);
    let body_off = buf.len();
    assert_eq!(body_off, 0x26, "join must land exactly at func+6");
    buf.extend([0x53, 0x8B, 0x45, 0x08, 0xC9, 0xC3]);

    let insns = crate::disasm::disassemble_region(&buf, base, "x86").unwrap();
    let funcs = crate::analysis::function::detect_functions(&insns, 0, &[]);
    let f = funcs
        .iter()
        .find(|f| f.entry == join || (join > f.entry && join < f.end))
        .expect("join point must be inside some detected function");
    assert_eq!(
        f.entry, func,
        "entry must expand back over the prologue to {:#x}, got {:#x}",
        func, f.entry
    );
    assert!(
        !funcs.iter().any(|f| f.entry == join),
        "no stub function at the join point"
    );
}

#[test]
fn decompiler_x86_renders_32bit_names_and_absolute_mem() {
    let code: &[u8] = &[0xA1, 0x00, 0x20, 0x00, 0x00, 0xC3];
    let insns = crate::disasm::disassemble_region(code, 0x1000, "x86").unwrap();
    let pinstrs = crate::analysis::pcode::lift_all(&insns);
    let cfg = crate::analysis::cfg::build_cfg(&insns, 0x1000, 0x1006);
    let sf = crate::analysis::stack::analyze_stack(&pinstrs, 0x1000, 0x1006, false, 0);
    let lookup = rustc_hash::FxHashMap::default();
    let pc = crate::analysis::decompiler::decompile(crate::analysis::decompiler::LiftInput {
        cfg: &cfg,
        pinstrs_in_func: &pinstrs,
        imap: &insns,
        stack: &sf,
        func_name: "t",
        func_lookup: &lookup,
        is64: false,
        is_win64: false,
        thunk_targets: &rustc_hash::FxHashMap::default(),
        imports: &rustc_hash::FxHashMap::default(),
        cancel: None,
        debug_types: None,
    });
    let text: String = pc
        .lines
        .iter()
        .map(|l| l.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        !text.contains("(0 + "),
        "absolute mem noise leaked: {}",
        text
    );
    assert!(
        text.contains("eax") || text.contains("DAT_"),
        "expected x86 naming: {}",
        text
    );
    assert!(
        text.contains("int32_t t("),
        "signature should be 32-bit: {}",
        text
    );
}

#[test]
fn sse_instructions_lift_without_unimplemented() {
    let code: &[u8] = &[
        0x0F, 0x57, 0xC0, 0xF3, 0x0F, 0x10, 0x4C, 0x24, 0x04, 0xF3, 0x0F, 0x59, 0xC1, 0xF3, 0x0F,
        0x5A, 0xC0, 0xC3,
    ];
    let base: u64 = 0x1000;
    let insns = crate::disasm::disassemble_region(code, base, "x86").unwrap();
    let pinstrs = crate::analysis::pcode::lift_all(&insns);
    let unimpl: Vec<&str> = pinstrs
        .iter()
        .flat_map(|p| p.ops.iter())
        .filter_map(|op| match op {
            crate::analysis::pcode::POp::Unimplemented(t) => Some(t.as_str()),
            _ => None,
        })
        .collect();
    assert!(unimpl.is_empty(), "unlifted: {:?}", unimpl);

    let end = base + code.len() as u64;
    let cfg = crate::analysis::cfg::build_cfg(&insns, base, end);
    assert!(!cfg.blocks.is_empty(), "cfg must have blocks");
    let sf = crate::analysis::stack::analyze_stack(&pinstrs, base, end, false, 0);
    let lookup = rustc_hash::FxHashMap::default();
    let pc = crate::analysis::decompiler::decompile(crate::analysis::decompiler::LiftInput {
        cfg: &cfg,
        pinstrs_in_func: &pinstrs,
        imap: &insns,
        stack: &sf,
        func_name: "t",
        func_lookup: &lookup,
        is64: false,
        is_win64: false,
        thunk_targets: &rustc_hash::FxHashMap::default(),
        imports: &rustc_hash::FxHashMap::default(),
        cancel: None,
        debug_types: None,
    });
    let text: String = pc
        .lines
        .iter()
        .map(|l| l.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        text.contains("xmm"),
        "expected xmm names in output: {}",
        text
    );
    assert!(
        !text.contains("not modeled"),
        "lifter gap leaked into output: {}",
        text
    );
}

#[test]
fn find_callsites_survives_incomplete_linear_disasm() {
    let np = std::path::PathBuf::from(r"C:\Windows\System32\notepad.exe");
    if !np.exists() {
        return;
    }
    let bin = crate::parser::parse_file(&np).expect("parse notepad");
    let d = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let imp = bin
        .imports
        .iter()
        .find(|i| i.name == "MessageBoxW")
        .expect("notepad imports MessageBoxW");
    let sites = crate::analysis::import_xref::find_callsites(&bin, &d, "MessageBoxW");
    assert!(
        !sites.is_empty(),
        "expected direct/thunked call sites to MessageBoxW"
    );
    let via_slot = crate::analysis::import_xref::find_callsites_at_slot(&d, imp.offset);
    let _ = via_slot;
    let qualified = format!("{}!{}", imp.library, imp.name);
    let sites_q = crate::analysis::import_xref::find_callsites(&bin, &d, &qualified);
    assert_eq!(
        sites.len(),
        sites_q.len(),
        "'DLL!name' and bare name forms must agree"
    );
    assert!(
        sites
            .iter()
            .zip(sites_q.iter())
            .all(|(a, b)| a.address == b.address && a.kind == b.kind),
        "'DLL!name' and bare name forms must agree"
    );
    assert!(
        crate::analysis::import_xref::find_callsites(&bin, &d, "DefinitelyNotAnImport_XYZ")
            .is_empty()
    );
}

#[test]
fn type_aliases_and_derived_forms_resolve() {
    use crate::type_system::{DataTypeManager, ID_UINT};
    let mut m = DataTypeManager::new();
    let uint_id = m.find_by_name("uint").unwrap();
    assert_eq!(m.resolve_type_name("dword").unwrap(), uint_id);
    assert_eq!(m.resolve_type_name("DWORD").unwrap(), uint_id);
    assert_eq!(m.resolve_type_name("uint32_t").unwrap(), ID_UINT);
    assert_eq!(m.resolve_type_name("u32").unwrap(), uint_id);
    assert_eq!(
        m.resolve_type_name("byte").unwrap(),
        m.find_by_name("uchar").unwrap()
    );
    let cp1 = m.resolve_type_name("char*").unwrap();
    let cp2 = m.resolve_type_name("char *").unwrap();
    assert_eq!(cp1, cp2, "pointer creation dedupes by target");
    assert_eq!(m.size_of(cp1), Some(8));
    let a1 = m.resolve_type_name("char[10]").unwrap();
    let a2 = m.resolve_type_name("char[10]").unwrap();
    assert_eq!(a1, a2, "array creation dedupes");
    assert_eq!(m.size_of(a1), Some(10));
    assert!(m.resolve_type_name("NotAType").is_err());
}

#[test]
fn multibyte_nop_encoding_round_trips() {
    let cases: Vec<(&str, &str, Vec<u8>)> = vec![
        ("x86_64", "nop", vec![0x90]),
        ("x86_64", "nop rax", vec![0x90]),
        ("x86", "nop dword ptr [eax]", vec![0x0F, 0x1F, 0x00]),
        ("x86_64", "nop qword ptr [rax]", vec![0x0F, 0x1F, 0x00]),
        (
            "x86_64",
            "nop dword ptr [rsp]",
            vec![0x0F, 0x1F, 0x44, 0x24, 0x00],
        ),
        (
            "x86_64",
            "nop dword ptr [rax+16]",
            vec![0x0F, 0x1F, 0x40, 0x10],
        ),
        ("x86", "nop word ptr [eax]", vec![0x66, 0x0F, 0x1F, 0x00]),
    ];
    for (arch, line, want) in cases {
        let got = crate::asm::assemble(arch, 0x1000, line)
            .unwrap_or_else(|e| panic!("{} failed to assemble: {}", line, e));
        assert_eq!(got, want, "{} encoded wrong", line);
    }
    assert!(
        crate::asm::assemble("x86_64", 0x1000, "nop ecx").is_err(),
        "nop <non-ax register> has no encoding and must be rejected"
    );
}

#[test]
fn switch_table_targets_must_be_executable() {
    require_fixture!("kernel32.dll");
    let np = std::path::PathBuf::from(r"C:\Windows\System32\notepad.exe");
    let path = if np.exists() {
        np
    } else {
        fixture("kernel32.dll")
    };
    let bin = crate::parser::parse_file(&path).expect("parse binary");
    let d = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let tables = crate::analysis::advanced::detect_switch_tables(&d.instructions, &bin, None);
    let exec_addrs: Vec<(u64, u64)> = bin
        .sections
        .iter()
        .filter(|s| s.is_executable)
        .map(|s| (s.vaddr, s.vaddr + s.size))
        .collect();
    for t in &tables {
        assert!(
            t.case_count >= 2,
            "table at {:#x} has {} cases",
            t.table_addr,
            t.case_count
        );
        assert!(!t.case_targets.is_empty());
        for target in &t.case_targets {
            assert!(
                exec_addrs
                    .iter()
                    .any(|(lo, hi)| *target >= *lo && *target < *hi),
                "table at {:#x} emitted non-executable target {:#x}",
                t.table_addr,
                target
            );
        }
    }
}

#[test]
fn import_thunk_functions_are_named_after_their_imports() {
    require_fixture!("kernel32.dll");
    let bin = crate::parser::parse_file(&fixture("kernel32.dll")).expect("parse kernel32");
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let result = crate::analysis::auto_analyze(&disasm, &bin);
    let stub_thunks: std::collections::HashSet<u64> = result
        .stubs
        .iter()
        .filter(|(_, s)| {
            matches!(s.kind, crate::analysis::StubKind::ImportThunk) && s.target_name.contains('!')
        })
        .map(|(addr, _)| *addr)
        .collect();
    let import_names: std::collections::HashSet<&str> = bin
        .imports
        .iter()
        .filter(|i| !i.name.is_empty())
        .map(|i| i.name.as_str())
        .collect();
    let renamed = result
        .functions
        .iter()
        .filter(|f| stub_thunks.contains(&f.entry) && import_names.contains(f.name.as_str()))
        .count();
    assert!(
        renamed > 50,
        "expected most resolved import thunks renamed, got {}",
        renamed
    );
    let mut user = rustc_hash::FxHashMap::default();
    let some_entry = result.functions[0].entry;
    user.insert(some_entry, "MyCustomName".to_string());
    let result2 = crate::analysis::auto_analyze_with_progress(
        &disasm,
        &bin,
        &user,
        &crate::analysis::function_id::FunctionIDMatcher::new(),
        &std::sync::atomic::AtomicBool::new(false),
        &|_, _, _, _| {},
    );
    let f2 = result2
        .functions
        .iter()
        .find(|f| f.entry == some_entry)
        .unwrap();
    assert_eq!(
        f2.name, "MyCustomName",
        "user rename must survive thunk renaming"
    );
}

#[test]
fn decompiler_renders_iat_calls_with_import_names() {
    let iat = 0x140029A78u64;
    let mut insns: Vec<crate::disasm::DisasmInstruction> = Vec::new();
    let mut addr = 0x1000u64;
    let disp1 = (iat as i64) - ((addr + 6) as i64);
    let mut b = vec![0xFF, 0x15];
    b.extend_from_slice(&(disp1 as i32).to_le_bytes());
    insns.push(crate::disasm::DisasmInstruction {
        address: addr,
        bytes: crate::disasm::InsnBytes::from_slice(&b),
        mnemonic: "call",
        operands: format!("qword ptr [rip + {:#x}]", disp1).into(),
    });
    addr += 6;
    insns.push(crate::disasm::DisasmInstruction {
        address: addr,
        bytes: crate::disasm::InsnBytes::from_slice(&[0xC3]),
        mnemonic: "ret",
        operands: "".into(),
    });
    addr += 1;

    let cfg = crate::analysis::cfg::build_cfg(&insns, 0x1000, addr);
    let pinstrs = crate::analysis::pcode::lift_func(&insns, 0x1000, addr);
    let sf = crate::analysis::stack::analyze_stack(&pinstrs, 0x1000, addr, false, 0);
    let lookup = rustc_hash::FxHashMap::default();
    let imports: rustc_hash::FxHashMap<u64, String> = [(iat, "MessageBoxW".to_string())]
        .into_iter()
        .collect::<rustc_hash::FxHashMap<u64, String>>();
    let pc = crate::analysis::decompiler::decompile(crate::analysis::decompiler::LiftInput {
        cfg: &cfg,
        pinstrs_in_func: &pinstrs,
        imap: &insns,
        stack: &sf,
        func_name: "t",
        func_lookup: &lookup,
        is64: true,
        is_win64: false,
        thunk_targets: &rustc_hash::FxHashMap::default(),
        imports: &imports,
        cancel: None,
        debug_types: None,
    });
    let text: String = pc.lines.iter().map(|l| format!("{}\n", l.text)).collect();
    eprintln!("pseudocode:\n{}", text);
    assert!(
        text.contains("MessageBoxW("),
        "IAT call must render by name:\n{}",
        text
    );
    assert!(
        !text.contains("DAT_"),
        "no raw DAT_ refs expected:\n{}",
        text
    );
}

fn build_synthetic_minidump() -> Vec<u8> {
    let mut d: Vec<u8> = Vec::new();
    d.extend_from_slice(b"MDMP");
    d.extend_from_slice(&4284u32.to_le_bytes());
    d.extend_from_slice(&3u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes());
    let dir_rva = 32u32;
    d.extend_from_slice(&[0u8; 36]);

    let mut streams: Vec<(u32, u32, u32)> = Vec::new();

    let mem_rva = d.len() as u32;
    let n_ranges = 2u64;
    let descriptors_len = 16 + 16 * 2;
    let base_rva = mem_rva + descriptors_len as u32;
    d.extend_from_slice(&n_ranges.to_le_bytes());
    d.extend_from_slice(&(base_rva as u64).to_le_bytes());
    let va_a = 0x7FF6_0000_0000u64;
    let va_b = 0x7FF7_0000_1000u64;
    d.extend_from_slice(&va_a.to_le_bytes());
    d.extend_from_slice(&0x100u64.to_le_bytes());
    d.extend_from_slice(&va_b.to_le_bytes());
    d.extend_from_slice(&0x40u64.to_le_bytes());
    debug_assert_eq!(d.len() as u32, base_rva);
    for i in 0..0x100 {
        d.push(i as u8);
    }
    for i in 0..0x40 {
        d.push(0xAA ^ i as u8);
    }
    streams.push((9, 16 + 16 * 2, mem_rva));

    let mod_rva = d.len() as u32;
    d.extend_from_slice(&1u32.to_le_bytes());
    let rec = d.len();
    d.extend_from_slice(&0x7FF7_0002_0000u64.to_le_bytes());
    d.extend_from_slice(&0x8000u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    let name_rva_slot = d.len() as u32;
    d.extend_from_slice(&0u32.to_le_bytes());
    for _ in 0..13 {
        d.extend_from_slice(&0u32.to_le_bytes());
    }
    d.extend_from_slice(&[0u8; 8]);
    d.extend_from_slice(&[0u8; 8]);
    d.extend_from_slice(&[0u8; 8]);
    d.extend_from_slice(&[0u8; 8]);
    debug_assert_eq!(d.len() - rec, 108);
    let name_rva = d.len() as u32;
    let wide: Vec<u8> = "target.dll"
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    d.extend_from_slice(&(wide.len() as u32).to_le_bytes());
    d.extend_from_slice(&wide);
    let name_end = d.len();
    d[name_rva_slot as usize..name_rva_slot as usize + 4].copy_from_slice(&name_rva.to_le_bytes());
    streams.push((4, (name_end - mod_rva as usize) as u32, mod_rva));

    let exc_rva = d.len() as u32;
    d.extend_from_slice(&1234u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0xC0000005u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u64.to_le_bytes());
    d.extend_from_slice(&va_a.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&0u32.to_le_bytes());
    d.extend_from_slice(&[0u8; 120]);
    streams.push((6, 160, exc_rva));

    for (i, (ty, sz, rva)) in streams.iter().enumerate() {
        let e = dir_rva as usize + i * 12;
        if e + 12 > d.len() {
            d.resize(e + 12, 0);
        }
        d[e..e + 4].copy_from_slice(&ty.to_le_bytes());
        d[e + 4..e + 8].copy_from_slice(&sz.to_le_bytes());
        d[e + 8..e + 12].copy_from_slice(&rva.to_le_bytes());
    }
    d[12..16].copy_from_slice(&dir_rva.to_le_bytes());
    d
}

#[test]
fn minidump_maps_ranges_at_real_vas() {
    let data = build_synthetic_minidump();
    assert!(crate::parser::minidump::looks_like_minidump(&data));
    let bin = crate::parser::minidump::parse_minidump_binary(data).expect("parse mdmp");
    assert_eq!(bin.format, "MINIDUMP");
    assert_eq!(bin.sections.len(), 2);
    assert_eq!(bin.sections[0].vaddr, 0x7FF6_0000_0000);
    assert_eq!(bin.sections[1].vaddr, 0x7FF7_0000_1000);
    let sec_a = &bin.sections[0];
    let off_a = sec_a.offset as usize + 5;
    assert_eq!(bin.data[off_a], 5);
    let sec_b = &bin.sections[1];
    assert_eq!(bin.data[sec_b.offset as usize], 0xAA);
    assert!(bin.symbols.iter().any(|s| s.name.contains("target.dll")));
    assert_eq!(bin.entry_point, 0x7FF6_0000_0000);
}

#[test]
fn minidump_adjacent_ranges_merge() {
    let mut d = build_synthetic_minidump();
    let dir_rva = u32_le(&d, 12) as usize;
    let mem_e = dir_rva;
    let mem_rva = u32_le(&d, mem_e + 8) as usize;
    let b_desc = mem_rva + 16 + 16;
    d[b_desc..b_desc + 8].copy_from_slice(&0x7FF6_0000_0100u64.to_le_bytes());
    let _ = mem_e;
    let bin = crate::parser::minidump::parse_minidump_binary(d).expect("parse");
    assert_eq!(
        bin.sections.len(),
        1,
        "adjacent VA+file-contiguous ranges should merge into one section"
    );
    assert_eq!(bin.sections[0].size, 0x140);
}

fn u32_le(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}

#[test]
fn rtti_scan_finds_validated_class_and_vftable() {
    use crate::parser::{ParsedBinary, Section};
    let base = 0x140000000u64;
    let rdata_va = base;
    let mut data = vec![0u8; 0x1000];
    let put = |d: &mut Vec<u8>, rva: usize, v: &[u8]| {
        d[rva..rva + v.len()].copy_from_slice(v);
    };
    let td_rva = 0x100usize;
    put(&mut data, td_rva, &0u64.to_le_bytes());
    put(&mut data, td_rva + 8, &0u64.to_le_bytes());
    put(&mut data, td_rva + 16, b".?AVFoo@Bar@@\0");
    let col_rva = 0x200usize;
    put(&mut data, col_rva, &1u32.to_le_bytes());
    put(&mut data, col_rva + 4, &0u32.to_le_bytes());
    put(&mut data, col_rva + 8, &0u32.to_le_bytes());
    put(&mut data, col_rva + 12, &(td_rva as u32).to_le_bytes());
    put(&mut data, col_rva + 16, &0x300u32.to_le_bytes());
    put(&mut data, col_rva + 20, &(col_rva as u32).to_le_bytes());
    let vftable_rva = 0x408usize;
    put(&mut data, 0x400, &(base + col_rva as u64).to_le_bytes());
    put(&mut data, vftable_rva, &(base + 0xF00).to_le_bytes());
    let bin = ParsedBinary {
        format: "PE".into(),
        arch: "x86_64".into(),
        entry_point: base,
        sections: vec![Section {
            name: ".rdata".into(),
            vaddr: rdata_va,
            size: data.len() as u64,
            offset: 0,
            is_executable: false,
            readable: true,
            writable: true,
            initialized: true,
        }],
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        data: std::sync::Arc::new(data),
        image_base: base,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: Vec::new(),
        delay_imports: Vec::new(),
        has_rich: false,
        libraries: Vec::new(),
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    let classes = crate::analysis::rtti::scan_msvc_rtti(&bin);
    assert!(!classes.is_empty(), "scanner found nothing");
    let hit = classes
        .iter()
        .find(|c| c.name == "Bar::Foo")
        .expect("class Bar::Foo not recovered");
    assert_eq!(hit.col, base + col_rva as u64);
    assert_eq!(hit.type_descriptor, base + td_rva as u64);
    assert_eq!(hit.vftable, Some(base + vftable_rva as u64));
    assert_eq!(hit.first_vfunc, Some(base + 0xF00));
}

#[test]
fn rtti_rejects_col_with_bad_self_pointer() {
    use crate::parser::{ParsedBinary, Section};
    let base = 0x140000000u64;
    let mut data = vec![0u8; 0x400];
    data[0x100..0x100 + 11].copy_from_slice(b".?AVFake@@\0");
    data[0x200..0x204].copy_from_slice(&1u32.to_le_bytes());
    data[0x20C..0x210].copy_from_slice(&0x100u32.to_le_bytes());
    data[0x214..0x218].copy_from_slice(&0xDEADu32.to_le_bytes());
    let bin = ParsedBinary {
        format: "PE".into(),
        arch: "x86_64".into(),
        entry_point: base,
        sections: vec![Section {
            name: ".rdata".into(),
            vaddr: base + 0x1000,
            size: data.len() as u64,
            offset: 0,
            is_executable: false,
            readable: true,
            writable: true,
            initialized: true,
        }],
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        data: std::sync::Arc::new(data),
        image_base: base,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: Vec::new(),
        delay_imports: Vec::new(),
        has_rich: false,
        libraries: Vec::new(),
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    assert!(
        crate::analysis::rtti::scan_msvc_rtti(&bin).is_empty(),
        "COL with invalid self-RVA must be rejected"
    );
}

#[test]
fn packer_fingerprint_names_byfron_and_tempest() {
    use crate::parser::{ParsedBinary, Section};
    let bin = ParsedBinary {
        format: "PE".into(),
        arch: "x86_64".into(),
        entry_point: 0x140001000,
        sections: vec![
            Section {
                name: ".byfron".into(),
                vaddr: 0x140001000,
                size: 0x1000,
                offset: 0,
                is_executable: true,
                readable: true,
                writable: false,
                initialized: true,
            },
            Section {
                name: "TEMPEST".into(),
                vaddr: 0x140002000,
                size: 0x1000,
                offset: 0x1000,
                is_executable: true,
                readable: true,
                writable: false,
                initialized: true,
            },
            Section {
                name: ".text".into(),
                vaddr: 0x140003000,
                size: 0x1000,
                offset: 0x2000,
                is_executable: true,
                readable: true,
                writable: false,
                initialized: true,
            },
        ],
        symbols: Vec::new(),
        imports: vec![
            crate::parser::Import {
                name: "x".into(),
                library: "k".into(),
                offset: 0,
            };
            10
        ],
        exports: Vec::new(),
        strings: Vec::new(),
        data: std::sync::Arc::new(vec![0u8; 0x40000]),
        image_base: 0x140000000,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: Vec::new(),
        delay_imports: Vec::new(),
        has_rich: false,
        libraries: Vec::new(),
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    let findings = crate::analysis::detect::detect_packers(&bin);
    let ids: Vec<&str> = findings.iter().map(|f| f.id).collect();
    assert!(
        ids.contains(&"byfron"),
        "byfron section not detected: {:?}",
        ids
    );
    assert!(
        ids.contains(&"tempest"),
        "tempest section not detected (case-insensitive): {:?}",
        ids
    );
    assert!(
        !ids.contains(&"tiny_iat"),
        "10 imports must not trigger tiny-IAT heuristic"
    );
}

#[test]
fn exception_policy_lookup_overrides_global_flag() {
    use crate::debugger::{DebugState, ExceptionAction};
    let mut st = DebugState::new();
    assert_eq!(crate::debugger::policy_for(&st, 0xC0000005), None);
    st.exception_policy
        .push((0xC0000005, ExceptionAction::Pause));
    assert_eq!(
        crate::debugger::policy_for(&st, 0xC0000005),
        Some(ExceptionAction::Pause)
    );
    assert_eq!(
        crate::debugger::policy_for(&st, 0xC0000094),
        None,
        "unknown codes must fall through to global policy"
    );
}

#[test]
fn dwarf_types_import_structs_enums_typedefs() {
    require_fixture!("dwarf_sample.elf");
    let bin = crate::parser::parse_file(&fixture("dwarf_sample.elf")).expect("parse fixture");
    assert_eq!(bin.format, "ELF");
    assert!(
        crate::analysis::unwind::has_debug_info(&bin),
        "fixture must carry .debug_info"
    );

    let mut tm = crate::type_system::DataTypeManager::new();
    let before = tm.len();
    let stats = crate::analysis::dwarf_types::import_dwarf_types(&bin, &mut tm);

    assert!(stats.structs >= 2, "structs: {:?}", stats);
    assert!(stats.unions >= 1, "unions: {:?}", stats);
    assert!(stats.enums >= 1, "enums: {:?}", stats);
    assert!(stats.typedefs >= 1, "typedefs: {:?}", stats);
    assert!(tm.len() > before, "import must add types");

    let node = tm.find_by_name("Node").expect("struct Node imported");
    match tm.get(node) {
        Some(crate::type_system::types::DataType::Struct { fields, .. }) => {
            let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
            assert!(names.contains(&"id"), "Node fields: {:?}", names);
            assert!(names.contains(&"next"), "pointer-cycle member present");
            assert!(names.contains(&"pos"), "nested struct member present");
            assert_eq!(fields.iter().find(|f| f.name == "id").unwrap().offset, 0);
            assert_eq!(
                fields.iter().find(|f| f.name == "next").unwrap().offset,
                8,
                "int id at 0, pointer next at 8 (alignment)"
            );
        }
        other => panic!("Node is not a struct: {:?}", other),
    }

    let color = tm.find_by_name("Color").expect("enum Color imported");
    match tm.get(color) {
        Some(crate::type_system::types::DataType::Enum { variants, .. }) => {
            assert!(
                variants.contains(&("BLUE".to_string(), 255)),
                "variants: {:?}",
                variants
            );
        }
        other => panic!("Color is not an enum: {:?}", other),
    }

    let p = tm.find_by_name("Point").expect("typedef Point imported");
    let target = match tm.get(p) {
        Some(crate::type_system::types::DataType::Typedef { target, .. }) => *target,
        _ => p,
    };
    match tm.get(target) {
        Some(crate::type_system::types::DataType::Struct { fields, .. }) => {
            assert!(
                fields.iter().any(|f| f.name == "x"),
                "Point fields: {:?}",
                fields
            );
            assert!(fields.iter().any(|f| f.name == "y"));
        }
        other => panic!("Point target not a struct: {:?}", other),
    }
}

#[test]
fn dwarf_function_names_seed_discovery() {
    require_fixture!("dwarf_sample.elf");
    let bin = crate::parser::parse_file(&fixture("dwarf_sample.elf")).expect("parse fixture");
    let names = crate::analysis::dwarf_types::dwarf_function_names(&bin);
    assert!(
        names.iter().any(|(_, n)| n == "compute"),
        "names: {:?}",
        names
    );
    assert!(names.iter().any(|(_, n)| n == "main"), "names: {:?}", names);

    let dis = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let res = crate::analysis::auto_analyze(&dis, &bin);
    assert!(
        res.functions.iter().any(|f| f.name == "compute"),
        "compute must be named via DWARF: {:?}",
        res.functions
            .iter()
            .map(|f| f.name.clone())
            .collect::<Vec<_>>()
    );
}

#[test]
fn pe_pdb_function_names_are_applied() {
    
    
    if !fixture("pdb_sample.exe").exists() || !fixture("pdb_sample.pdb").exists() {
        eprintln!("skipped: pdb_sample fixtures not present");
        return;
    }
    let bin = crate::parser::parse_file(&fixture("pdb_sample.exe")).expect("parse exe");
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let never = std::sync::atomic::AtomicBool::new(false);
    let fid = crate::analysis::function_id::FunctionIDMatcher::new();
    let path = fixture("pdb_sample.exe");
    let result = crate::analysis::auto_analyze_with_source(
        &disasm,
        &bin,
        path.to_str(),
        &rustc_hash::FxHashMap::default(),
        &fid,
        &never,
        &|_, _, _, _| {},
    );
    let names: Vec<&str> = result.functions.iter().map(|f| f.name.as_str()).collect();
    assert!(
        names.contains(&"compute") && names.contains(&"main"),
        "PDB names missing, got: {:?}",
        names
    );
}

#[test]
fn pdb_debug_types_extract_signatures_and_fields() {
    if !fixture("pdb_sample.exe").exists() || !fixture("pdb_sample.pdb").exists() {
        eprintln!("skipped: pdb_sample fixtures not present");
        return;
    }
    let bin = crate::parser::parse_file(&fixture("pdb_sample.exe")).expect("parse exe");
    let path = fixture("pdb_sample.exe");
    let types = crate::analysis::symbols::debug_types::DebugTypes::load(&bin, path.to_str())
        .expect("PDB debug types");

    let node = types.struct_named("Node").expect("Node struct");
    assert_eq!(node.size, 16);
    assert_eq!(node.fields.iter().find(|f| f.name == "id").map(|f| f.offset), Some(0));
    let next = node.fields.iter().find(|f| f.name == "next").expect("Node.next");
    assert_eq!(next.offset, 8);
    assert!(next.type_name.contains("Node"), "next type: {}", next.type_name);

    let point = types.struct_named("Point").expect("Point struct");
    assert!(point.fields.iter().any(|f| f.name == "x" && f.offset == 0));
    assert!(point.fields.iter().any(|f| f.name == "y" && f.offset == 4));

    let compute = types
        .functions
        .values()
        .find(|f| f.name == "compute")
        .expect("compute signature");
    assert_eq!(compute.params.len(), 3);
    assert_eq!(compute.params[0].name, "n");
    assert_eq!(compute.params[1].name, "p");
    assert_eq!(compute.params[2].name, "c");
    assert!(compute.params[0].type_name.contains("Node"));
    assert_eq!(compute.params[0].struct_name.as_deref(), Some("Node"));
    assert!(compute.params[1].type_name.contains("Point"));
    assert_eq!(compute.params[1].struct_name.as_deref(), Some("Point"));
    assert!(compute.params[2].type_name.contains("Color"));
}

#[test]
fn dwarf_debug_types_extract_names_and_fields() {
    require_fixture!("dwarf_sample.elf");
    let bin = crate::parser::parse_file(&fixture("dwarf_sample.elf")).expect("parse elf");
    let types = crate::analysis::symbols::debug_types::DebugTypes::load(&bin, None)
        .expect("DWARF debug types");

    let node = types.struct_named("Node").expect("Node struct");
    assert!(node.fields.iter().any(|f| f.name == "id" && f.offset == 0));
    assert!(node.fields.iter().any(|f| f.name == "next" && f.offset == 8));
    assert!(node.fields.iter().any(|f| f.name == "pos" && f.offset == 16));

    let compute = types
        .functions
        .values()
        .find(|f| f.name == "compute")
        .expect("compute signature");
    assert_eq!(compute.params.len(), 1);
    assert_eq!(compute.params[0].name, "n");
    assert!(compute.params[0].type_name.contains("Node"));
    assert_eq!(compute.params[0].struct_name.as_deref(), Some("Node"));

    let add = types
        .functions
        .values()
        .find(|f| f.name == "add_points")
        .expect("add_points signature");
    assert_eq!(add.params.len(), 2);
    assert_eq!(add.params[0].name, "a");
    assert_eq!(add.params[1].name, "b");
    assert!(add.params.iter().all(|p| p.type_name.contains("Point")));
    assert!(
        add.params
            .iter()
            .all(|p| p.struct_name.as_deref() == Some("Point"))
    );

    let main = types
        .functions
        .values()
        .find(|f| f.name == "main")
        .expect("main signature");
    let n = main.locals.iter().find(|l| l.name == "n").expect("local n");
    assert_eq!(n.struct_name.as_deref(), Some("Node"));
    assert_eq!(n.base, crate::analysis::symbols::debug_types::DebugBase::Cfa);
    assert_eq!(n.offset, -48);
    let c = main.locals.iter().find(|l| l.name == "c").expect("local c");
    assert_eq!(c.offset, -52);
}

#[test]
fn debug_types_reach_eager_decompilation() {
    if !fixture("pdb_sample.exe").exists() || !fixture("pdb_sample.pdb").exists() {
        eprintln!("skipped: pdb_sample fixtures not present");
        return;
    }
    let path = fixture("pdb_sample.exe");
    let bin = crate::parser::parse_file(&path).expect("parse exe");
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let never = std::sync::atomic::AtomicBool::new(false);
    let fid = crate::analysis::function_id::FunctionIDMatcher::new();
    let result = crate::analysis::auto_analyze_with_source(
        &disasm,
        &bin,
        path.to_str(),
        &rustc_hash::FxHashMap::default(),
        &fid,
        &never,
        &|_, _, _, _| {},
    );
    assert!(result.debug_types.is_some(), "PDB types must be in AnalysisResult");
    let compute = result
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .expect("compute function");
    let text = result
        .pseudocode
        .get(&compute.entry)
        .expect("compute was eagerly decompiled")
        .lines
        .iter()
        .map(|l| l.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("Node * n"), "signature:\n{}", text);
    assert!(text.contains("n->id"), "member access:\n{}", text);
    assert!(text.contains("p.x"), "struct-by-value field:\n{}", text);

    let main = result
        .functions
        .iter()
        .find(|f| f.name == "main")
        .expect("main function");
    let main_text = result
        .pseudocode
        .get(&main.entry)
        .expect("main was eagerly decompiled")
        .lines
        .iter()
        .map(|l| l.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        main_text.contains("compute((rsp") && main_text.contains(", rax, 0xff)"),
        "Win64 call arguments:\n{}",
        main_text
    );
}

#[test]
fn dwarf_debug_types_reach_eager_decompilation() {
    require_fixture!("dwarf_sample.elf");
    let path = fixture("dwarf_sample.elf");
    let bin = crate::parser::parse_file(&path).expect("parse elf");
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let never = std::sync::atomic::AtomicBool::new(false);
    let fid = crate::analysis::function_id::FunctionIDMatcher::new();
    let result = crate::analysis::auto_analyze_with_source(
        &disasm,
        &bin,
        path.to_str(),
        &rustc_hash::FxHashMap::default(),
        &fid,
        &never,
        &|_, _, _, _| {},
    );
    assert!(result.debug_types.is_some(), "DWARF types must be in AnalysisResult");
    let compute = result
        .functions
        .iter()
        .find(|f| f.name == "compute")
        .expect("compute function");
    let text = result
        .pseudocode
        .get(&compute.entry)
        .expect("compute was eagerly decompiled")
        .lines
        .iter()
        .map(|l| l.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("Node * n"), "signature:\n{}", text);
    assert!(text.contains("n->id"), "member access:\n{}", text);
    assert!(text.contains("Mixed m;"), "union local:\n{}", text);
    assert!(text.contains("m.i = 7"), "union field:\n{}", text);

    let add = result
        .functions
        .iter()
        .find(|f| f.name == "add_points")
        .expect("add_points function");
    let add_text = result
        .pseudocode
        .get(&add.entry)
        .expect("add_points was eagerly decompiled")
        .lines
        .iter()
        .map(|l| l.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(add_text.contains("a.x"), "Point a field:\n{}", add_text);
    assert!(add_text.contains("b.y"), "Point b field:\n{}", add_text);
    assert!(
        text.contains("add_points(n->pos, rax)"),
        "two SysV call arguments:\n{}",
        text
    );

    let main = result
        .functions
        .iter()
        .find(|f| f.name == "main")
        .expect("main function");
    let main_text = result
        .pseudocode
        .get(&main.entry)
        .expect("main was eagerly decompiled")
        .lines
        .iter()
        .map(|l| l.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(main_text.contains("Node n;"), "Node local:\n{}", main_text);
    assert!(main_text.contains("Color c;"), "Color local:\n{}", main_text);
    assert!(main_text.contains("n.pos.x = 1"), "nested field x:\n{}", main_text);
    assert!(main_text.contains("n.pos.y = 2"), "nested field y:\n{}", main_text);
    assert!(
        main_text.contains("compute((rbp - 0x20))"),
        "SysV call argument:\n{}",
        main_text
    );
}

#[test]
fn pdb_regrel_types_and_locals_are_extracted() {
    if !fixture("pdb_locals_sample.exe").exists()
        || !fixture("pdb_locals_sample.pdb").exists()
    {
        eprintln!("skipped: pdb_locals_sample fixtures not present");
        return;
    }
    let bin = crate::parser::parse_file(&fixture("pdb_locals_sample.exe")).expect("parse exe");
    let path = fixture("pdb_locals_sample.exe");
    let types = crate::analysis::symbols::debug_types::DebugTypes::load(&bin, path.to_str())
        .expect("PDB debug types");

    let add = types
        .functions
        .values()
        .find(|f| f.name == "add_points")
        .expect("add_points signature");
    assert_eq!(add.params[0].name, "a");
    assert_eq!(add.params[1].name, "b");
    assert!(add.locals.iter().any(|l| l.name == "sum" && l.type_name == "int32_t"));

    let main = types
        .functions
        .values()
        .find(|f| f.name == "main")
        .expect("main signature");
    assert!(main.locals.iter().any(|l| l.name == "n" && l.struct_name.as_deref() == Some("Node")));
    assert!(main.locals.iter().any(|l| l.name == "p" && l.struct_name.as_deref() == Some("Point")));
    assert!(main.locals.iter().any(|l| l.name == "result"));
}

#[test]
fn pdb_regrel_locals_reach_eager_decompilation() {
    if !fixture("pdb_locals_sample.exe").exists()
        || !fixture("pdb_locals_sample.pdb").exists()
    {
        eprintln!("skipped: pdb_locals_sample fixtures not present");
        return;
    }
    let path = fixture("pdb_locals_sample.exe");
    let bin = crate::parser::parse_file(&path).expect("parse exe");
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let never = std::sync::atomic::AtomicBool::new(false);
    let fid = crate::analysis::function_id::FunctionIDMatcher::new();
    let result = crate::analysis::auto_analyze_with_source(
        &disasm,
        &bin,
        path.to_str(),
        &rustc_hash::FxHashMap::default(),
        &fid,
        &never,
        &|_, _, _, _| {},
    );
    let main = result
        .functions
        .iter()
        .find(|f| f.name == "main")
        .expect("main function");
    let text = result
        .pseudocode
        .get(&main.entry)
        .expect("main was eagerly decompiled")
        .lines
        .iter()
        .map(|l| l.text.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("Node n;"), "Node local:\n{}", text);
    assert!(text.contains("Point p;"), "Point local:\n{}", text);
    assert!(text.contains("int32_t result;"), "result local:\n{}", text);
    assert!(text.contains("n.id = 5"), "Node field write:\n{}", text);
    assert!(text.contains("add_points(p, p)"), "two arguments:\n{}", text);
}

#[test]
fn pdb_path_is_found_next_to_the_binary() {
    if !fixture("pdb_sample.exe").exists() || !fixture("pdb_sample.pdb").exists() {
        eprintln!("skipped: pdb_sample fixtures not present");
        return;
    }
    let bin = crate::parser::parse_file(&fixture("pdb_sample.exe")).expect("parse exe");
    let path = fixture("pdb_sample.exe");
    let found = crate::analysis::debug_symbols::find_pdb_path(&bin, path.to_str())
        .expect("sibling PDB must be located");
    assert_eq!(
        found.file_name().and_then(|n| n.to_str()),
        Some("pdb_sample.pdb"),
        "found: {:?}",
        found
    );
}

#[test]
fn elf_imports_point_into_the_image() {
    
    
    if !fixture("dwarf_sample.elf").exists() {
        eprintln!("skipped: dwarf_sample.elf not present");
        return;
    }
    let bin = crate::parser::parse_file(&fixture("dwarf_sample.elf")).expect("parse elf");
    assert!(!bin.imports.is_empty());
    let mut got = 0;
    for imp in &bin.imports {
        assert_ne!(
            imp.offset, bin.image_base,
            "import {} points at the image base",
            imp.name
        );
        let sec = bin
            .sections
            .iter()
            .find(|s| imp.offset >= s.vaddr && imp.offset < s.vaddr + s.size);
        assert!(
            sec.is_some(),
            "import {} at {:#x} is not inside any section",
            imp.name,
            imp.offset
        );
        got += 1;
    }
    let libc = bin
        .imports
        .iter()
        .find(|i| i.name == "__libc_start_main")
        .expect("__libc_start_main import");
    assert_ne!(libc.offset, 0x100000, "must resolve to the GOT slot");
    assert!(got >= 5);
}

#[test]
fn pdb_types_import_structs_unions_enums() {
    let path = fixture("pdb_sample.pdb");
    if !path.exists() {
        eprintln!("skipped: fixture 'pdb_sample.pdb' not present");
        return;
    }
    let mut tm = crate::type_system::DataTypeManager::new();
    let before = tm.len();
    let stats = crate::analysis::pdb_types::import_pdb_types(&path, &mut tm)
        .expect("pdb import must succeed");

    assert!(stats.structs >= 2, "structs: {:?}", stats);
    assert!(stats.unions >= 1, "unions: {:?}", stats);
    assert!(stats.enums >= 1, "enums: {:?}", stats);
    assert!(tm.len() > before, "import must add types");

    let node = tm.find_by_name("Node").expect("struct Node imported");
    match tm.get(node) {
        Some(crate::type_system::types::DataType::Struct { fields, .. }) => {
            let names: Vec<&str> = fields.iter().map(|f| f.name.as_str()).collect();
            assert!(
                names.contains(&"id") && names.contains(&"next"),
                "fields: {:?}",
                names
            );
            assert_eq!(fields.iter().find(|f| f.name == "next").unwrap().offset, 8);
        }
        other => panic!("Node not a struct: {:?}", other),
    }

    let color = tm.find_by_name("Color").expect("enum Color imported");
    match tm.get(color) {
        Some(crate::type_system::types::DataType::Enum { variants, .. }) => {
            assert!(
                variants.contains(&("BLUE".to_string(), 255)),
                "variants: {:?}",
                variants
            );
        }
        other => panic!("Color not an enum: {:?}", other),
    }

    let mixed = tm.find_by_name("Mixed").expect("union Mixed imported");
    match tm.get(mixed) {
        Some(crate::type_system::types::DataType::Union { fields, .. }) => {
            assert!(
                fields.iter().all(|f| f.offset == 0),
                "union fields at 0: {:?}",
                fields
            );
        }
        other => panic!("Mixed not a union: {:?}", other),
    }
}
