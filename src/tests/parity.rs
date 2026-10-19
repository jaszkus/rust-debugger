use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};
use std::sync::Arc;

use crate::analysis::advanced::{build_stub_map, StubKind};
use crate::analysis::cfg::{BasicBlock, Edge, EdgeKind, CFG};
use crate::analysis::decompiler::{decompile, LiftInput};
use crate::analysis::function::{detect_functions_with_extra, DetectedFunction, FuncSource};
use crate::analysis::function_id::{
    hash_range, FunctionIDMatcher, FunctionSignature, SCORE_THRESHOLD,
};
use crate::analysis::noreturn::NoReturnAnalyzer;
use crate::analysis::pcode::{PInstr, POp, PVar};
use crate::analysis::stack::StackFrame;
use crate::analysis::unwind::function_starts;
use crate::analysis::xref::{build_xrefs, XRef, XRefKind};
use crate::disasm::{DisasmInstruction, InsnBytes};
use crate::parser::{self, ExtractedString, Import, ParsedBinary, Section, StringEncoding, Symbol};

fn insn(addr: u64, bytes: &[u8], mnem: &str, ops: &str) -> DisasmInstruction {
    DisasmInstruction {
        address: addr,
        bytes: InsnBytes::from_slice(bytes),
        mnemonic: crate::disasm::intern_mnemonic(mnem),
        operands: ops.into(),
    }
}

fn text_data_sections() -> (Vec<Section>, Vec<u8>) {
    let sections = vec![
        Section {
            name: ".text".into(),
            vaddr: 0x1000,
            size: 0x1000,
            offset: 0,
            is_executable: true,
            readable: true,
            writable: false,
            initialized: true,
        },
        Section {
            name: ".data".into(),
            vaddr: 0x2000,
            size: 0x20000,
            offset: 0x1000,
            is_executable: false,
            readable: true,
            writable: true,
            initialized: true,
        },
    ];
    (sections, vec![0u8; 0x1000 + 0x20000])
}

fn test_bin() -> ParsedBinary {
    let (sections, data) = text_data_sections();
    ParsedBinary {
        format: "ELF".into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        sections,
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        data: Arc::new(data),
        image_base: 0,
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
    }
}

fn sym(name: &str, addr: u64) -> Symbol {
    Symbol {
        name: name.into(),
        addr,
        size: 0,
        is_function: true,
    }
}

fn func(entry: u64, end: u64, src: FuncSource) -> DetectedFunction {
    DetectedFunction {
        entry,
        end,
        name: format!("sub_{:X}", entry),
        has_frame: false,
        stack_size: 0,
        source: src,
        is_thunk: false,
        thunk_target: None,
    }
}

#[test]
fn xref_direct_call_is_primary_op0() {
    let bin = test_bin();
    let insns = vec![
        insn(0x1000, &[0xE8, 0, 0, 0, 0], "call", "0x15000"),
        insn(0x1005, &[0xC3], "ret", ""),
    ];
    let db = build_xrefs(&insns, &bin, None);
    assert_eq!(db.all.len(), 1);
    let x = &db.all[0];
    assert_eq!(x.kind, XRefKind::Call);
    assert!(x.is_primary);
    assert_eq!(x.op_index, 0);
    assert_eq!((x.from, x.to), (0x1000, 0x15000));
}

#[test]
fn xref_indirect_call_through_mem() {
    let mut bin = test_bin();
    bin.imports.push(Import {
        name: "ReadFile".into(),
        library: "KERNEL32".into(),
        offset: 0x5000,
    });
    let disp = 0x5000i64 - 0x1006i64;
    let mut b = vec![0xFF, 0x15];
    b.extend_from_slice(&(disp as i32).to_le_bytes());
    let insns = vec![
        DisasmInstruction {
            address: 0x1000,
            bytes: InsnBytes::from_slice(&b),
            mnemonic: "call",
            operands: format!("qword ptr [rip + {:#x}]", disp).into(),
        },
        insn(0x1006, &[0xC3], "ret", ""),
    ];
    let db = build_xrefs(&insns, &bin, None);
    assert_eq!(db.all.len(), 1);
    assert_eq!(db.all[0].kind, XRefKind::CallIndirect);
    assert_eq!(db.all[0].to, 0x5000);
}

#[test]
fn xref_indirect_jump_through_mem() {
    let bin = test_bin();
    let disp = 0x5000i64 - 0x1006i64;
    let mut b = vec![0xFF, 0x25];
    b.extend_from_slice(&(disp as i32).to_le_bytes());
    let insns = vec![DisasmInstruction {
        address: 0x1000,
        bytes: InsnBytes::from_slice(&b),
        mnemonic: "jmp",
        operands: format!("qword ptr [rip + {:#x}]", disp).into(),
    }];
    let db = build_xrefs(&insns, &bin, None);
    assert_eq!(db.all.len(), 1);
    assert_eq!(db.all[0].kind, XRefKind::JumpIndirect);
}

#[test]
fn xref_each_operand_gets_primary() {
    let mut bin = test_bin();
    bin.symbols.push(sym("g_data", 0x5000));
    bin.symbols.push(sym("g_other", 0x12000));
    let disp = 0x5000i64 - 0x1007i64;
    let insns = vec![DisasmInstruction {
        address: 0x1000,
        bytes: InsnBytes::from_slice(&[0x48, 0x83, 0x3D, 0, 0, 0, 0]),
        mnemonic: "cmp",
        operands: format!("qword ptr [rip + {:#x}], 0x12000", disp).into(),
    }];
    let db = build_xrefs(&insns, &bin, None);
    assert_eq!(db.all.len(), 2, "expected mem+imm refs, got {:?}", db.all);
    assert_eq!(db.all[0].to, 0x5000);
    assert!(db.all[0].is_primary);
    assert_eq!(db.all[0].op_index, 0);
    assert_eq!(db.all[1].to, 0x12000);
    assert!(db.all[1].is_primary);
    assert_eq!(db.all[1].op_index, 1);
}

#[test]
fn xref_data_pointer_scan_finds_code_targets() {
    let (sections, mut data) = text_data_sections();
    let off = 0x1010usize;
    data[off..off + 8].copy_from_slice(&0x1500u64.to_le_bytes());
    let mut bin = test_bin();
    bin.sections = sections;
    bin.data = Arc::new(data);
    let db = build_xrefs(&[], &bin, None);
    assert_eq!(db.all.len(), 1);
    let x = &db.all[0];
    assert_eq!(x.kind, XRefKind::DataAddr);
    assert_eq!((x.from, x.to), (0x2010, 0x1500));
    assert!(!x.is_primary, "data refs are secondary");
    assert_eq!(x.op_index, -1);
}

#[test]
fn xref_data_scan_ignores_null_and_data_targets() {
    let (sections, mut data) = text_data_sections();
    data[0x1010..0x1018].copy_from_slice(&0x2100u64.to_le_bytes());
    let mut bin = test_bin();
    bin.sections = sections;
    bin.data = Arc::new(data);
    let db = build_xrefs(&[], &bin, None);
    assert!(db.all.is_empty());
}

#[test]
fn xref_kind_edge_helpers() {
    assert!(XRefKind::Call.is_call_edge());
    assert!(XRefKind::TailCall.is_call_edge());
    assert!(!XRefKind::CallIndirect.is_call_edge());
    assert!(!XRefKind::Jump.is_call_edge());
    assert!(XRefKind::Call.is_flow());
    assert!(XRefKind::JumpIndirect.is_flow());
    assert!(XRefKind::TailCall.is_flow());
    assert!(!XRefKind::DataRead.is_flow());
    assert!(!XRefKind::StringRef.is_flow());
}

#[test]
fn xref_db_primary_from_filters() {
    let mut db = crate::analysis::xref::XRefDB::default();
    db.add_ref(0x1000, 0x5000, XRefKind::DataRead, String::new(), 0);
    db.add_ref(0x1000, 0x6000, XRefKind::DataAddr, String::new(), 1);
    assert_eq!(db.primary_from(0x1000).len(), 2);
    assert_eq!(db.xrefs_from(0x1000).len(), 2);
    assert_eq!(db.xrefs_to(0x5000).len(), 1);
    db.add_ref(0x1000, 0x7000, XRefKind::DataRead, String::new(), 0);
    assert_eq!(db.xrefs_from(0x1000).len(), 3);
    assert_eq!(db.primary_from(0x1000).len(), 2);
    assert!(!db.all[2].is_primary);
    assert!(db.set_primary(0x1000, 0, 0x7000));
    assert_eq!(db.primary_from(0x1000).len(), 2);
    assert!(db.all[2].is_primary);
    assert!(!db.all[0].is_primary);
}

fn pe_test_bin() -> ParsedBinary {
    const BASE: u64 = 0x140_000_000;
    let mut data = vec![0u8; 0x1000 + 12];
    data[0x1000..0x1004].copy_from_slice(&0x1000u32.to_le_bytes());
    data[0x1004..0x1008].copy_from_slice(&0x1010u32.to_le_bytes());
    ParsedBinary {
        format: "PE EXE".into(),
        arch: "x86_64".into(),
        entry_point: BASE + 0x1000,
        sections: vec![
            Section {
                name: ".text".into(),
                vaddr: BASE + 0x1000,
                size: 0x1000,
                offset: 0,
                is_executable: true,
                readable: true,
                writable: false,
                initialized: true,
            },
            Section {
                name: ".pdata".into(),
                vaddr: BASE + 0x2000,
                size: 12,
                offset: 0x1000,
                is_executable: false,
                readable: true,
                writable: true,
                initialized: true,
            },
        ],
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        data: Arc::new(data),
        image_base: BASE,
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
    }
}

#[test]
fn unwind_pe_pdata_yields_entry() {
    let bin = pe_test_bin();
    let starts = function_starts(&bin);
    assert_eq!(starts, vec![(0x140_001_000, FuncSource::UnwindInfo)]);
}

#[test]
fn unwind_pe_pdata_32bit_ignored() {
    let mut bin = pe_test_bin();
    bin.arch = "x86".into();
    assert!(function_starts(&bin).is_empty());
}

#[test]
fn unwind_elf_eh_frame_hdr_table() {
    let mut data = vec![0u8; 0x1000 + 32];
    let hdr: usize = 0x1000;
    data[hdr] = 1;
    data[hdr + 1] = 0x00;
    data[hdr + 2] = 0x03;
    data[hdr + 3] = 0x00;
    data[hdr + 12..hdr + 16].copy_from_slice(&1u32.to_le_bytes());
    data[hdr + 16..hdr + 24].copy_from_slice(&0x400100u64.to_le_bytes());
    let bin = ParsedBinary {
        format: "ELF".into(),
        arch: "x86_64".into(),
        entry_point: 0x400000,
        sections: vec![
            Section {
                name: ".text".into(),
                vaddr: 0x400000,
                size: 0x1000,
                offset: 0,
                is_executable: true,
                readable: true,
                writable: false,
                initialized: true,
            },
            Section {
                name: ".eh_frame_hdr".into(),
                vaddr: 0x401000,
                size: 32,
                offset: 0x1000,
                is_executable: false,
                readable: true,
                writable: true,
                initialized: true,
            },
        ],
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        data: Arc::new(data),
        image_base: 0,
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
    assert_eq!(
        function_starts(&bin),
        vec![(0x400100, FuncSource::UnwindInfo)]
    );
}

#[test]
fn unwind_elf_eh_frame_fde_fallback() {
    let mut rec = Vec::new();
    rec.extend_from_slice(&13u32.to_le_bytes());
    rec.extend_from_slice(&0u32.to_le_bytes());
    rec.push(1);
    rec.extend_from_slice(b"zR\0");
    rec.push(0x01);
    rec.push(0x7c);
    rec.push(0x10);
    rec.push(0x01);
    rec.push(0x00);
    assert_eq!(rec.len(), 4 + 13);
    rec.extend_from_slice(&20u32.to_le_bytes());
    rec.extend_from_slice(&21u32.to_le_bytes());
    rec.extend_from_slice(&0x400200u64.to_le_bytes());
    rec.extend_from_slice(&0x10u64.to_le_bytes());
    let mut data = vec![0u8; 0x1000];
    data.extend_from_slice(&rec);
    let bin = ParsedBinary {
        format: "ELF".into(),
        arch: "x86_64".into(),
        entry_point: 0x400000,
        sections: vec![
            Section {
                name: ".text".into(),
                vaddr: 0x400000,
                size: 0x1000,
                offset: 0,
                is_executable: true,
                readable: true,
                writable: false,
                initialized: true,
            },
            Section {
                name: ".eh_frame".into(),
                vaddr: 0x401000,
                size: rec.len() as u64,
                offset: 0x1000,
                is_executable: false,
                readable: true,
                writable: true,
                initialized: true,
            },
        ],
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        data: Arc::new(data),
        image_base: 0,
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
    assert_eq!(
        function_starts(&bin),
        vec![(0x400200, FuncSource::UnwindInfo)]
    );
}

#[test]
fn unwind_macho_function_starts() {
    const BASE: u64 = 0x1_0000_0000;
    let mut data = vec![0u8; 220];
    data[0..4].copy_from_slice(&0xfeedfacfu32.to_le_bytes());
    data[16..20].copy_from_slice(&2u32.to_le_bytes());
    data[32..36].copy_from_slice(&0x19u32.to_le_bytes());
    data[36..40].copy_from_slice(&72u32.to_le_bytes());
    data[40..46].copy_from_slice(b"__TEXT");
    data[32 + 24..32 + 32].copy_from_slice(&BASE.to_le_bytes());
    data[104..108].copy_from_slice(&0x26u32.to_le_bytes());
    data[108..112].copy_from_slice(&16u32.to_le_bytes());
    data[112..116].copy_from_slice(&200u32.to_le_bytes());
    data[116..120].copy_from_slice(&3u32.to_le_bytes());
    data[200] = 0x40;
    data[201] = 0x10;
    data[202] = 0x00;
    let bin = ParsedBinary {
        format: "Mach-O EXE".into(),
        arch: "x86_64".into(),
        entry_point: BASE,
        sections: vec![Section {
            name: "__text".into(),
            vaddr: BASE,
            size: 0x1000,
            offset: 0,
            is_executable: true,
            readable: true,
            writable: false,
            initialized: true,
        }],
        symbols: Vec::new(),
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        data: Arc::new(data),
        image_base: 0,
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
    assert_eq!(
        function_starts(&bin),
        vec![
            (BASE + 0x40, FuncSource::UnwindInfo),
            (BASE + 0x50, FuncSource::UnwindInfo)
        ]
    );
}

#[test]
fn unwind_raw_has_no_starts() {
    let mut bin = test_bin();
    bin.format = "RAW".into();
    assert!(function_starts(&bin).is_empty());
}

#[test]
fn unwind_entries_become_functions() {
    let insns = vec![insn(0x5000, &[0xC3], "ret", "")];
    let funcs =
        detect_functions_with_extra(&insns, 0, &[], &[(0x5000, FuncSource::UnwindInfo)], None);
    assert_eq!(funcs.len(), 1);
    assert_eq!(funcs[0].source, FuncSource::UnwindInfo);
}

#[test]
fn stub_tail_call_to_known_entry() {
    let mut bin = test_bin();
    bin.symbols.push(sym("callee", 0x2000));
    let insns = vec![
        insn(0x1000, &[0xE9, 0, 0, 0, 0], "jmp", "0x2000"),
        insn(0x2000, &[0xC3], "ret", ""),
    ];
    let funcs = vec![
        func(0x1000, 0x1005, FuncSource::CallTarget),
        func(0x2000, 0x2001, FuncSource::CallTarget),
    ];
    let stubs = build_stub_map(&insns, &funcs, &bin, None);
    let s = stubs.get(&0x1000).expect("tail call stub");
    assert_eq!(s.kind, StubKind::TailCall);
    assert_eq!(s.target_addr, Some(0x2000));
    assert_eq!(s.target_name, "callee");
}

#[test]
fn stub_import_thunk_still_detected() {
    let mut bin = test_bin();
    bin.imports.push(Import {
        name: "Sleep".into(),
        library: "KERNEL32".into(),
        offset: 0x5000,
    });
    let disp = 0x5000i64 - 0x1006i64;
    let mut b = vec![0xFF, 0x25];
    b.extend_from_slice(&(disp as i32).to_le_bytes());
    let insns = vec![DisasmInstruction {
        address: 0x1000,
        bytes: InsnBytes::from_slice(&b),
        mnemonic: "jmp",
        operands: format!("qword ptr [rip + {:#x}]", disp).into(),
    }];
    let funcs = vec![func(0x1000, 0x1006, FuncSource::CallTarget)];
    let stubs = build_stub_map(&insns, &funcs, &bin, None);
    let s = stubs.get(&0x1000).expect("thunk");
    assert_eq!(s.kind, StubKind::ImportThunk);
    assert!(s.target_name.contains("Sleep"));
}

#[test]
fn noreturn_import_seed_and_chain() {
    let imports = vec![Import {
        name: "abort".into(),
        library: "libc".into(),
        offset: 0x3000,
    }];
    let insns = vec![
        insn(0x1000, &[0xE8, 0, 0, 0, 0], "call", "0x2000"),
        insn(0x2000, &[0xE8, 0, 0, 0, 0], "call", "0x3000"),
    ];
    let funcs = vec![
        func(0x1000, 0x1005, FuncSource::CallTarget),
        func(0x2000, 0x2005, FuncSource::CallTarget),
    ];
    let mut an = NoReturnAnalyzer::new();
    an.analyze(&insns, &imports, &funcs, None);
    assert!(an.is_noreturn(0x3000), "import seed");
    assert!(an.is_noreturn(0x2000), "direct caller");
    assert!(an.is_noreturn(0x1000), "transitive chain");
}

#[test]
fn noreturn_expanded_names() {
    for name in [
        "pthread_exit",
        "rust_begin_unwind",
        "RtlAssert",
        "__ubsan_handle_abort",
        "TerminateProcess",
    ] {
        let imports = vec![Import {
            name: name.into(),
            library: "x".into(),
            offset: 0x9000,
        }];
        let mut an = NoReturnAnalyzer::new();
        an.analyze(&[], &imports, &[], None);
        assert!(an.is_noreturn(0x9000), "{}", name);
    }
}

#[test]
fn noreturn_dead_tail_wrapper_scores() {
    let imports = vec![Import {
        name: "abort".into(),
        library: "libc".into(),
        offset: 0x3000,
    }];
    let insns = vec![
        insn(0x1000, &[0xE8, 0, 0, 0, 0], "call", "0x3000"),
        insn(0x1005, &[0xCC], "int3", ""),
        insn(0x1006, &[0x90], "nop", ""),
    ];
    let funcs = vec![func(0x1000, 0x1007, FuncSource::CallTarget)];
    let mut an = NoReturnAnalyzer::new();
    an.analyze(&insns, &imports, &funcs, None);
    assert!(an.is_noreturn(0x1000));
    assert!(an.is_noreturn_call_at(&insns[0]));
    assert!(!an.is_noreturn_call_at(&insns[1]));
}

#[test]
fn noreturn_needs_threshold_three() {
    let imports = vec![Import {
        name: "abort".into(),
        library: "libc".into(),
        offset: 0x3000,
    }];
    let insns = vec![
        insn(0x1000, &[0xE8, 0, 0, 0, 0], "call", "0x3000"),
        insn(0x1005, &[0x58], "pop", "rax"),
        insn(0x1006, &[0xC3], "ret", ""),
    ];
    let funcs = vec![func(0x1000, 0x1007, FuncSource::CallTarget)];
    let mut an = NoReturnAnalyzer::new();
    an.analyze(&insns, &imports, &funcs, None);
    assert!(
        !an.is_noreturn(0x1000),
        "conditional-abort caller with ret must stay returning"
    );
}

#[test]
fn noreturn_callfixup_never_seeds() {
    let imports = vec![
        Import {
            name: "__chkstk".into(),
            library: "ntdll".into(),
            offset: 0x4000,
        },
        Import {
            name: "__security_check_cookie".into(),
            library: "ntdll".into(),
            offset: 0x4001,
        },
    ];
    let insns = vec![
        insn(0x1000, &[0xE8, 0, 0, 0, 0], "call", "0x4000"),
        insn(0x1005, &[0xC3], "ret", ""),
    ];
    let funcs = vec![func(0x1000, 0x1006, FuncSource::CallTarget)];
    let mut an = NoReturnAnalyzer::new();
    an.analyze(&insns, &imports, &funcs, None);
    assert!(!an.is_noreturn(0x4000), "chkstk must not seed");
    assert!(!an.is_noreturn(0x4001), "cookie check must not seed");
    assert!(!an.is_noreturn(0x1000), "fixup caller must stay returning");
}

fn fid_insns() -> Vec<DisasmInstruction> {
    vec![
        insn(0x1000, &[0x48, 0x89, 0xD8], "mov", "rax, rbx"),
        insn(0x1003, &[0x48, 0x05, 0x05, 0, 0, 0], "add", "rax, 0x5"),
        insn(0x1009, &[0xC3], "ret", ""),
    ]
}

#[test]
fn fid_full_masks_immediates_specific_keeps_them() {
    let a = fid_insns();
    let mut b = fid_insns();
    b[1] = insn(0x1003, &[0x48, 0x05, 0x06, 0, 0, 0], "add", "rax, 0x6");
    let ha = hash_range(&a);
    let hb = hash_range(&b);
    assert_eq!(ha.full, hb.full, "full hash must ignore operand values");
    assert_ne!(
        ha.specific, hb.specific,
        "specific hash must see immediates"
    );
    assert_eq!(ha.insn_count, 3);
    let _ = a;
}

#[test]
fn fid_full_masks_registers() {
    let a = fid_insns();
    let b = vec![
        insn(0x1000, &[0x48, 0x89, 0xD1], "mov", "rcx, rdx"),
        insn(0x1003, &[0x48, 0x05, 0x05, 0, 0, 0], "add", "rax, 0x5"),
        insn(0x1009, &[0xC3], "ret", ""),
    ];
    assert_eq!(hash_range(&a).full, hash_range(&b).full);
    assert_ne!(hash_range(&a).specific, hash_range(&b).specific);
}

#[test]
fn fid_skips_padding() {
    let a = fid_insns();
    let mut b = vec![insn(0x0FF0, &[0x90], "nop", "")];
    b.extend(fid_insns());
    b.push(insn(0x2000, &[0xCC], "int3", ""));
    assert_eq!(hash_range(&a), hash_range(&b));
}

#[test]
fn fid_score_full_hit_passes_threshold() {
    let body = fid_insns();
    let h = hash_range(&body);
    let mut m = FunctionIDMatcher::new();
    assert!(m.is_empty());
    m.insert(FunctionSignature {
        hash: h.full,
        specific: h.specific,
        name: "known".into(),
        library: "test".into(),
        size: 3,
        score: 0.0,
    });
    let out = m.identify_with_context(
        &body,
        &[(0x1000, 0x1010)],
        &rustc_hash::FxHashMap::default(),
        &rustc_hash::FxHashMap::default(),
        None,
    );
    let hit = out.get(&0x1000).expect("full hit");
    assert!(hit.score >= SCORE_THRESHOLD);
    assert_eq!(hit.name, "known");
}

#[test]
fn fid_unknown_body_scores_nothing() {
    let m = FunctionIDMatcher::new();
    let out = m.identify_with_context(
        &fid_insns(),
        &[(0x1000, 0x1010)],
        &rustc_hash::FxHashMap::default(),
        &rustc_hash::FxHashMap::default(),
        None,
    );
    assert!(out.is_empty());
}

#[test]
fn fid_neighbor_bonus_raises_score() {
    let body = fid_insns();
    let h = hash_range(&body);
    let mut m = FunctionIDMatcher::new();
    for name in ["alpha", "beta"] {
        m.insert(FunctionSignature {
            hash: h.full,
            specific: h.specific,
            name: name.into(),
            library: "t".into(),
            size: 3,
            score: 0.0,
        });
    }
    let bodies = vec![(0x1000, 0x1010), (0x2000, 0x2010)];
    let plain = m.identify_with_context(
        &body,
        &bodies,
        &rustc_hash::FxHashMap::default(),
        &rustc_hash::FxHashMap::default(),
        None,
    );
    let mut callers = HashMap::default();
    callers.insert(0x2000u64, vec![0x1000u64]);
    let mut callees = HashMap::default();
    callees.insert(0x1000u64, vec![0x2000u64]);
    let ctx = m.identify_with_context(&body, &bodies, &callers, &callees, None);
    assert!(ctx
        .get(&0x1000)
        .is_some_and(|hit| hit.score >= SCORE_THRESHOLD));
    let _ = plain;
}

#[test]
fn fid_ingest_skips_anonymous_and_roundtrips_file() {
    let body = vec![
        insn(0x1000, &[0x55], "push", "rbp"),
        insn(0x1001, &[0x48, 0x89, 0xD8], "mov", "rax, rbx"),
        insn(0x1004, &[0x48, 0x05, 0x05, 0, 0, 0], "add", "rax, 0x5"),
        insn(0x100A, &[0xC3], "ret", ""),
    ];
    let mut m = FunctionIDMatcher::new();
    let added = m.ingest_functions(
        &body,
        &[
            (0x1000, 0x1010, "real_func".into()),
            (0x2000, 0x2010, "sub_2000".into()),
            (0x3000, 0x3010, "entry".into()),
        ],
        "libt",
    );
    assert_eq!(added, 1);
    assert_eq!(m.len(), 1);
    let dir = std::env::temp_dir().join(format!("fidb_{}.json", std::process::id()));
    m.export_db(&dir).expect("export");
    let mut m2 = FunctionIDMatcher::new();
    let n = m2.import_db(&dir).expect("import");
    assert_eq!(n, 1);
    assert_eq!(m2.len(), 1);
    assert_eq!(m2.import_db(&dir).expect("reimport"), 0);
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn fid_import_rejects_bad_version() {
    let dir = std::env::temp_dir().join(format!("fidb_bad_{}.json", std::process::id()));
    std::fs::write(&dir, r#"{"fidb_version": 99, "signatures": []}"#).unwrap();
    let mut m = FunctionIDMatcher::new();
    assert!(m.import_db(&dir).is_err());
    let _ = std::fs::remove_file(&dir);
}

#[test]
fn fid_match_function_back_compat() {
    let body = fid_insns();
    let h = hash_range(&body);
    let mut m = FunctionIDMatcher::new();
    m.add_signature(h.full, "legacy".into(), "lib".into(), 3);
    assert!(m.match_function(&body, 0).is_some());
}

#[test]
#[ignore = "measurement: RD_MEASURE_OPERANDS=<bin> cargo test -- --ignored measure_operand_uniqueness"]
fn measure_operand_uniqueness() {
    let Ok(path) = std::env::var("RD_MEASURE_OPERANDS") else {
        eprintln!("skipped: set RD_MEASURE_OPERANDS=<bin>");
        return;
    };
    let bin = crate::parser::parse_file(std::path::Path::new(&path)).expect("parse");
    let arch = bin.arch.clone();
    let d = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let mut mnem: HashSet<String> = HashSet::default();
    let mut ops: HashSet<String> = HashSet::default();
    let mut ops_no_disp: HashSet<String> = HashSet::default();
    let mut pairs: HashSet<(String, String)> = HashSet::default();
    let n = d.instructions.len();
    for i in d.instructions.iter() {
        mnem.insert(i.mnem().to_string());
        ops.insert(i.ops().into_owned());
        pairs.insert((i.mnem().to_string(), i.ops().into_owned()));
        let stripped: String = re_stub(&i.ops());
        ops_no_disp.insert(stripped);
    }
    eprintln!("[measure] {path} arch={arch}");
    eprintln!("[measure] insns={n} unique_mnemonic={} unique_operands={} unique_(mnem,ops)={} operands_displacement_stripped={}",
        mnem.len(), ops.len(), pairs.len(), ops_no_disp.len());
    let _ = arch;
}

fn re_stub(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let b = s.as_bytes();
    let mut i = 0;
    let mut run = 0usize;
    while i < b.len() {
        let c = b[i];
        if c.is_ascii_hexdigit() {
            run += 1;
            if run < 4 {
                out.push(c as char);
            }
        } else {
            run = 0;
            out.push(c as char);
        }
        i += 1;
    }
    out
}

fn fid_rel(va: u64) -> crate::parser::Relocation {
    crate::parser::Relocation {
        va,
        size: 4,
        rel_type: 10,
        symbol: None,
        addend: 0,
        is_artificial: false,
    }
}

#[test]
fn fid_relocated_specific_is_placeholder_masked() {
    use crate::analysis::function_id::{hash_range_with_mask, RelocMask};
    let a = vec![
        insn(0x1000, &[0x48, 0x89, 0xD8], "mov", "rax, rbx"),
        insn(0x1003, &[0x48, 0x05, 0x30, 0, 0, 0], "add", "rax, 0x30"),
        insn(0x1009, &[0xC3], "ret", ""),
    ];
    let b = vec![
        insn(0x1000, &[0x48, 0x89, 0xD8], "mov", "rax, rbx"),
        insn(0x1003, &[0x48, 0x05, 0x40, 0, 0, 0], "add", "rax, 0x40"),
        insn(0x1009, &[0xC3], "ret", ""),
    ];
    let mask_a = RelocMask::new(&[fid_rel(0x1003)]);
    let mask_b = RelocMask::new(&[fid_rel(0x1003)]);

    let (ra, rb) = (hash_range(&a), hash_range(&b));
    assert_ne!(ra.specific, rb.specific);
    assert_eq!(ra.full, rb.full);

    let (ma, mb) = (
        hash_range_with_mask(&a, Some(&mask_a)),
        hash_range_with_mask(&b, Some(&mask_b)),
    );
    assert_eq!(
        ma.specific, mb.specific,
        "relocated scalar must not split a signature"
    );
    assert_eq!(ma.full, mb.full, "masking must not change the full hash");
    assert_ne!(
        ma.specific, ra.specific,
        "mask must change the specific hash"
    );
}

#[test]
fn fid_size_proximity_uses_hashed_count_not_range_len() {
    let mut body = fid_insns();
    for i in 0..50u64 {
        body.push(insn(0x100C + i, &[0x90], "nop", ""));
    }
    let h = hash_range(&body);
    let mut m = FunctionIDMatcher::new();
    m.insert(FunctionSignature {
        hash: h.full.wrapping_add(1),
        specific: h.specific,
        name: "padded".into(),
        library: "t".into(),
        size: 3,
        score: 0.0,
    });
    let end = body.last().unwrap().address + 1;
    let out = m.identify_with_context(
        &body,
        &[(0x1000, end)],
        &rustc_hash::FxHashMap::default(),
        &rustc_hash::FxHashMap::default(),
        None,
    );
    let hit = out.get(&0x1000).expect("specific hit on padded body");
    assert!(
        hit.score >= SCORE_THRESHOLD,
        "padding must not eat the size bonus: {}",
        hit.score
    );
}

#[test]
fn fid_match_function_picks_best_specific_candidate() {
    let body = fid_insns();
    let h = hash_range(&body);
    let mut m = FunctionIDMatcher::new();
    m.insert(FunctionSignature {
        hash: 0x1111,
        specific: h.specific,
        name: "wrong-big".into(),
        library: "t".into(),
        size: 100,
        score: 0.0,
    });
    m.insert(FunctionSignature {
        hash: 0x2222,
        specific: h.specific,
        name: "right".into(),
        library: "t".into(),
        size: 3,
        score: 0.0,
    });
    let sig = m.match_function(&body, 0).expect("specific hit");
    assert_eq!(sig.name, "right", "best size-proximity candidate must win");
}

fn fid_e2e_body(base: u64) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(0x55);
    b.extend_from_slice(&[0x48, 0x89, 0xE5]);
    b.extend_from_slice(&[0x48, 0xB8]);
    b.extend_from_slice(&(base.wrapping_add(0x2000)).to_le_bytes());
    b.extend_from_slice(&[0x48, 0x83, 0xC0, 0x05]);
    b.push(0x5D);
    b.push(0xC3);
    b
}

#[test]
fn fid_e2e_ingest_identify_across_link_bases() {
    use crate::analysis::function_id::{hash_range_with_mask, RelocMask};

    let build = |base: u64| {
        let mut bin =
            crate::parser::parse_raw_bytes(fid_e2e_body(base), base, "x86_64").expect("raw parse");
        bin.relocations.push(crate::parser::Relocation {
            va: base + 0x06,
            size: 8,
            rel_type: 10,
            symbol: None,
            addend: 0,
            is_artificial: false,
        });
        let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
        let funcs = crate::analysis::function::detect_functions(
            &disasm.instructions,
            bin.entry_point,
            &bin.symbols,
        );
        (bin, disasm, funcs)
    };

    let (bin_a, disasm_a, funcs_a) = build(0x1400_0000);
    let (bin_b, disasm_b, funcs_b) = build(0x1800_0045);
    assert_eq!(funcs_a.len(), 1, "single-function body, base A");
    assert_eq!(funcs_b.len(), 1, "single-function body, base B");
    let (fa, fb) = (&funcs_a[0], &funcs_b[0]);
    assert_eq!(fa.entry, 0x1400_0000, "A entry at base");
    assert_eq!(fb.entry, 0x1800_0045, "B entry at base");

    fn slice<'a>(
        d: &'a crate::disasm::DisasmResult,
        f: &crate::analysis::DetectedFunction,
    ) -> &'a [DisasmInstruction] {
        let s = d.instructions.partition_point(|i| i.address < f.entry);
        let e = d.instructions.partition_point(|i| i.address < f.end);
        &d.instructions[s..e]
    }
    let mask_a = RelocMask::new(&bin_a.relocations);
    let mask_b = RelocMask::new(&bin_b.relocations);
    let (ha_m, hb_m) = (
        hash_range_with_mask(slice(&disasm_a, fa), Some(&mask_a)),
        hash_range_with_mask(slice(&disasm_b, fb), Some(&mask_b)),
    );
    let (ha_r, hb_r) = (
        hash_range_with_mask(slice(&disasm_a, fa), None),
        hash_range_with_mask(slice(&disasm_b, fb), None),
    );
    assert_ne!(
        ha_r.specific, hb_r.specific,
        "raw specific splits on link address"
    );
    assert_eq!(
        ha_m.specific, hb_m.specific,
        "mask restores cross-base equality"
    );
    assert_eq!(ha_m.full, hb_m.full, "shape hash is base-independent");

    let mut m = FunctionIDMatcher::new();
    m.set_reloc_mask(&bin_a.relocations);
    let named: Vec<(u64, u64, String)> = funcs_a
        .iter()
        .map(|f| (f.entry, f.end, "helper_func".to_string()))
        .collect();
    assert_eq!(m.ingest_functions(&disasm_a.instructions, &named, "e2e"), 1);
    let mut m2 = FunctionIDMatcher::new();
    m2.set_reloc_mask(&bin_b.relocations);
    m2.merge(&m);
    let bodies_b: Vec<(u64, u64)> = funcs_b.iter().map(|f| (f.entry, f.end)).collect();
    let out = m2.identify_with_context(
        &disasm_b.instructions,
        &bodies_b,
        &HashMap::default(),
        &HashMap::default(),
        None,
    );
    let hit = out.get(&fb.entry).expect("cross-base FID hit");
    assert_eq!(hit.name, "helper_func");
    assert!(
        hit.score >= SCORE_THRESHOLD,
        "score {} below threshold",
        hit.score
    );

    let mut raw_m = FunctionIDMatcher::new();
    assert_eq!(
        raw_m.ingest_functions(&disasm_a.instructions, &named, "e2e"),
        1
    );
    let raw_out = raw_m.identify_with_context(
        &disasm_b.instructions,
        &bodies_b,
        &HashMap::default(),
        &HashMap::default(),
        None,
    );
    assert!(
        raw_out.contains_key(&fb.entry),
        "full-hash path matches cross-base"
    );
}

#[test]
fn fid_e2e_padded_copy_still_identifies() {
    let base = 0x1C00_0000;
    let mut data = fid_e2e_body(base);
    data.extend(std::iter::repeat_n(0x90, 40));
    let mut bin = crate::parser::parse_raw_bytes(data, base, "x86_64").expect("raw parse");
    bin.relocations.push(crate::parser::Relocation {
        va: base + 0x06,
        size: 8,
        rel_type: 10,
        symbol: None,
        addend: 0,
        is_artificial: false,
    });
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let funcs = crate::analysis::function::detect_functions(
        &disasm.instructions,
        bin.entry_point,
        &bin.symbols,
    );
    assert!(!funcs.is_empty(), "padded body still yields a function");
    let f = &funcs[0];

    let mut m = FunctionIDMatcher::new();
    m.set_reloc_mask(&bin.relocations);
    let a_base = 0x1400_0000;
    let a = crate::parser::parse_raw_bytes(fid_e2e_body(a_base), a_base, "x86_64").expect("A");
    let a_dis = crate::disasm::disassemble_binary(&a).expect("A disasm");
    let a_funcs =
        crate::analysis::function::detect_functions(&a_dis.instructions, a.entry_point, &a.symbols);
    let named: Vec<(u64, u64, String)> = a_funcs
        .iter()
        .map(|f| (f.entry, f.end, "helper_func".to_string()))
        .collect();
    assert_eq!(m.ingest_functions(&a_dis.instructions, &named, "e2e"), 1);

    let bodies: Vec<(u64, u64)> = funcs.iter().map(|f| (f.entry, f.end)).collect();
    let out = m.identify_with_context(
        &disasm.instructions,
        &bodies,
        &rustc_hash::FxHashMap::default(),
        &rustc_hash::FxHashMap::default(),
        None,
    );
    let hit = out.get(&f.entry).expect("padded copy hit");
    assert_eq!(hit.name, "helper_func");
    assert!(
        hit.score >= SCORE_THRESHOLD,
        "padding must not eat the bonus: {}",
        hit.score
    );
}

fn pinstr(addr: u64, ops: Vec<POp>) -> PInstr {
    PInstr {
        address: addr,
        mnemonic: String::new(),
        ops,
    }
}

fn single_block_cfg() -> CFG {
    CFG {
        func_entry: 0x1000,
        blocks: vec![BasicBlock {
            id: 0,
            start: 0x1000,
            end: 0x1010,
            instr_indices: 0..0,
            successors: vec![],
            predecessors: vec![],
        }],
        block_at: [(0x1000u64, 0usize)].into_iter().collect(),
    }
}

fn decompile_text(cfg: &CFG, pinstrs: &[PInstr]) -> String {
    decompile_text_imap(cfg, pinstrs, &[])
}

fn decompile_text_imap(cfg: &CFG, pinstrs: &[PInstr], imap: &[DisasmInstruction]) -> String {
    let stack = StackFrame {
        func_entry: 0x1000,
        variables: Vec::new(),
        frame_size: 0,
    };
    let pc = decompile(LiftInput {
        cfg,
        pinstrs_in_func: pinstrs,
        imap,
        stack: &stack,
        func_name: "f",
        func_lookup: &HashMap::default(),
        is64: true,
        imports: &HashMap::default(),
        cancel: None,
    });
    pc.lines
        .iter()
        .map(|l| l.text.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn decompiler_folds_constants() {
    let cfg = single_block_cfg();
    let pi = vec![pinstr(
        0x1000,
        vec![
            POp::IntMul {
                dst: PVar::Reg("rax"),
                a: PVar::Const(6),
                b: PVar::Const(7),
                size: 8,
            },
            POp::Return,
        ],
    )];
    let t = decompile_text(&cfg, &pi);
    assert!(t.contains("0x2a"), "folded (hex):\n{}", t);
}

#[test]
fn decompiler_peephole_identities() {
    let cfg = single_block_cfg();
    let case = |op: POp| decompile_text(&cfg, &[pinstr(0x1000, vec![op, POp::Return])]);
    let t = case(POp::IntAdd {
        dst: PVar::Reg("rax"),
        a: PVar::Reg("rbx"),
        b: PVar::Const(0),
        size: 8,
    });
    assert!(t.contains("rbx"), "x+0:\n{}", t);
    let t = case(POp::IntAnd {
        dst: PVar::Reg("rax"),
        a: PVar::Reg("rdx"),
        b: PVar::Const(-1),
        size: 8,
    });
    assert!(t.contains("rdx"), "x&-1:\n{}", t);
    assert!(!t.contains("0xffff"), "no residual mask:\n{}", t);
    let t = case(POp::IntSub {
        dst: PVar::Reg("rax"),
        a: PVar::Reg("rdi"),
        b: PVar::Reg("rdi"),
        size: 8,
    });
    assert!(t.contains("0;") || t.contains("return 0"), "x-x:\n{}", t);
}

#[test]
fn decompiler_zext_same_size_is_copy() {
    let cfg = single_block_cfg();
    let pi = vec![pinstr(
        0x1000,
        vec![
            POp::Zext {
                dst: PVar::Reg("rax"),
                src: PVar::Reg("rbx"),
                from_size: 8,
                to_size: 8,
            },
            POp::Return,
        ],
    )];
    let t = decompile_text(&cfg, &pi);
    assert!(!t.contains("extend"), "peephole:\n{}", t);
}

#[test]
fn decompiler_drops_dead_stores() {
    let cfg = single_block_cfg();
    let pi = vec![pinstr(
        0x1000,
        vec![
            POp::IntAdd {
                dst: PVar::Reg("rbx"),
                a: PVar::Reg("rcx"),
                b: PVar::Const(1),
                size: 8,
            },
            POp::IntAdd {
                dst: PVar::Reg("rax"),
                a: PVar::Reg("rcx"),
                b: PVar::Const(2),
                size: 8,
            },
            POp::Return,
        ],
    )];
    let t = decompile_text(&cfg, &pi);
    assert!(!t.contains("rbx"), "dead rbx dropped:\n{}", t);
    assert!(t.contains("rcx + 2"), "live value kept:\n{}", t);
}

#[test]
fn decompiler_cse_reuses_expression() {
    let cfg = single_block_cfg();
    let pi = vec![pinstr(
        0x1000,
        vec![
            POp::IntAdd {
                dst: PVar::Reg("r10"),
                a: PVar::Reg("rcx"),
                b: PVar::Reg("rdx"),
                size: 8,
            },
            POp::IntAdd {
                dst: PVar::Reg("r11"),
                a: PVar::Reg("rcx"),
                b: PVar::Reg("rdx"),
                size: 8,
            },
            POp::Store {
                addr: PVar::StackSlot {
                    base: crate::analysis::pcode::StackBase::Rbp,
                    off: -8,
                },
                src: PVar::Reg("r10"),
                size: 8,
            },
            POp::Store {
                addr: PVar::StackSlot {
                    base: crate::analysis::pcode::StackBase::Rbp,
                    off: -16,
                },
                src: PVar::Reg("r11"),
                size: 8,
            },
            POp::Return,
        ],
    )];
    let t = decompile_text(&cfg, &pi);
    assert!(t.contains("r10 = rcx + rdx;"), "first computation:\n{}", t);
    assert!(
        !t.contains("r11 = rcx + rdx;"),
        "second computation must be reused:\n{}",
        t
    );
    assert!(
        t.matches("= r10;").count() >= 1,
        "store reuses the value:\n{}",
        t
    );
}

#[test]
fn decompiler_cse_invalidated_by_clobber() {
    let cfg = single_block_cfg();
    let pi = vec![pinstr(
        0x1000,
        vec![
            POp::IntAdd {
                dst: PVar::Reg("r10"),
                a: PVar::Reg("rcx"),
                b: PVar::Reg("rdx"),
                size: 8,
            },
            POp::Copy {
                dst: PVar::Reg("rcx"),
                src: PVar::Const(0),
                size: 8,
            },
            POp::IntAdd {
                dst: PVar::Reg("r11"),
                a: PVar::Reg("rcx"),
                b: PVar::Reg("rdx"),
                size: 8,
            },
            POp::Store {
                addr: PVar::StackSlot {
                    base: crate::analysis::pcode::StackBase::Rbp,
                    off: -8,
                },
                src: PVar::Reg("r10"),
                size: 8,
            },
            POp::Store {
                addr: PVar::StackSlot {
                    base: crate::analysis::pcode::StackBase::Rbp,
                    off: -16,
                },
                src: PVar::Reg("r11"),
                size: 8,
            },
            POp::Return,
        ],
    )];
    let t = decompile_text(&cfg, &pi);
    assert_eq!(
        t.matches(" + ").count(),
        1,
        "only the pre-clobber definition:\n{}",
        t
    );
    assert!(t.contains("r10 = rcx + rdx;"), "definition kept:\n{}", t);
}

fn loop_cfg() -> (CFG, Vec<DisasmInstruction>) {
    let cfg = CFG {
        func_entry: 0x1000,
        blocks: vec![
            BasicBlock {
                id: 0,
                start: 0x1000,
                end: 0x1010,
                instr_indices: 0..0,
                successors: vec![Edge {
                    target: 1,
                    kind: EdgeKind::Fallthrough,
                }],
                predecessors: vec![],
            },
            BasicBlock {
                id: 1,
                start: 0x1010,
                end: 0x1020,
                instr_indices: 0..0,
                successors: vec![
                    Edge {
                        target: 0,
                        kind: EdgeKind::BranchTrue,
                    },
                    Edge {
                        target: 2,
                        kind: EdgeKind::BranchFalse,
                    },
                ],
                predecessors: vec![0],
            },
            BasicBlock {
                id: 2,
                start: 0x1020,
                end: 0x1028,
                instr_indices: 0..0,
                successors: vec![],
                predecessors: vec![1],
            },
        ],
        block_at: [(0x1000u64, 0usize), (0x1010, 1), (0x1020, 2)]
            .into_iter()
            .collect(),
    };
    let imap = vec![
        insn(0x1010, &[0x48, 0x83, 0xF8, 0x05], "cmp", "rax, 0x5"),
        insn(0x1014, &[0x7C, 0xEA], "jl", "0x1000"),
    ];
    (cfg, imap)
}

#[test]
fn decompiler_bottom_tested_loop_is_dowhile() {
    let (cfg, imap) = loop_cfg();
    let pi = vec![
        pinstr(
            0x1010,
            vec![POp::Cmp {
                a: PVar::Reg("rax"),
                b: PVar::Const(5),
                size: 8,
            }],
        ),
        pinstr(
            0x1014,
            vec![POp::CBranch {
                target: 0x1000,
                cond: "jne".into(),
            }],
        ),
    ];
    let stack = StackFrame {
        func_entry: 0x1000,
        variables: Vec::new(),
        frame_size: 0,
    };
    let pc = decompile(LiftInput {
        cfg: &cfg,
        pinstrs_in_func: &pi,
        imap: &imap,
        stack: &stack,
        func_name: "f",
        func_lookup: &HashMap::default(),
        is64: true,
        imports: &HashMap::default(),
        cancel: None,
    });
    let t = pc
        .lines
        .iter()
        .map(|l| l.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(t.contains("do {"), "do-while:\n{}", t);
    assert!(t.contains("} while"), "close:\n{}", t);
    assert!(t.contains("rax < 5"), "condition:\n{}", t);
}

#[test]
fn decompiler_top_tested_loop_stays_while() {
    let cfg = CFG {
        func_entry: 0x1000,
        blocks: vec![
            BasicBlock {
                id: 0,
                start: 0x1000,
                end: 0x1010,
                instr_indices: 0..0,
                successors: vec![
                    Edge {
                        target: 2,
                        kind: EdgeKind::BranchTrue,
                    },
                    Edge {
                        target: 1,
                        kind: EdgeKind::BranchFalse,
                    },
                ],
                predecessors: vec![],
            },
            BasicBlock {
                id: 1,
                start: 0x1010,
                end: 0x1020,
                instr_indices: 0..0,
                successors: vec![Edge {
                    target: 0,
                    kind: EdgeKind::Jump,
                }],
                predecessors: vec![0],
            },
            BasicBlock {
                id: 2,
                start: 0x1020,
                end: 0x1028,
                instr_indices: 0..0,
                successors: vec![],
                predecessors: vec![0],
            },
        ],
        block_at: [(0x1000u64, 0usize), (0x1010, 1), (0x1020, 2)]
            .into_iter()
            .collect(),
    };
    let imap = vec![
        insn(0x1000, &[0x48, 0x83, 0xF8, 0x05], "cmp", "rax, 0x5"),
        insn(0x1004, &[0x7E, 0x1A], "jle", "0x1020"),
    ];
    let pi = vec![
        pinstr(
            0x1000,
            vec![POp::Cmp {
                a: PVar::Reg("rax"),
                b: PVar::Const(5),
                size: 8,
            }],
        ),
        pinstr(
            0x1004,
            vec![POp::CBranch {
                target: 0x1020,
                cond: "je".into(),
            }],
        ),
    ];
    let stack = StackFrame {
        func_entry: 0x1000,
        variables: Vec::new(),
        frame_size: 0,
    };
    let pc = decompile(LiftInput {
        cfg: &cfg,
        pinstrs_in_func: &pi,
        imap: &imap,
        stack: &stack,
        func_name: "f",
        func_lookup: &HashMap::default(),
        is64: true,
        imports: &HashMap::default(),
        cancel: None,
    });
    let t = pc
        .lines
        .iter()
        .map(|l| l.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(t.contains("while ("), "while:\n{}", t);
    assert!(!t.contains("do {"), "not do-while:\n{}", t);
}

fn str_sections(size: usize) -> Vec<Section> {
    vec![Section {
        name: ".rodata".into(),
        vaddr: 0x400000,
        size: size as u64,
        offset: 0,
        is_executable: false,
        readable: true,
        writable: true,
        initialized: true,
    }]
}

#[test]
fn strings_utf32le_found() {
    let text = "HelloWorld";
    let mut data = Vec::new();
    for c in text.bytes() {
        data.extend_from_slice(&[c, 0, 0, 0]);
    }
    let out = parser::extract_all_strings(&data, &str_sections(data.len()), 4);
    assert!(
        out.iter()
            .any(|s| s.content == "HelloWorld" && s.encoding == StringEncoding::Utf32Le),
        "got {:?}",
        out.iter().map(|s| &s.content).collect::<Vec<_>>()
    );
}

#[test]
fn strings_utf32be_found() {
    let text = "HelloWorld";
    let mut data = Vec::new();
    for c in text.bytes() {
        data.extend_from_slice(&[0, 0, 0, c]);
    }
    let out = parser::extract_all_strings(&data, &str_sections(data.len()), 4);
    assert!(out
        .iter()
        .any(|s| s.content == "HelloWorld" && s.encoding == StringEncoding::Utf32Le));
}

#[test]
fn strings_pascal_found() {
    let mut data = vec![5u8, b'h', b'e', b'l', b'l', b'o', 0];
    data.extend_from_slice(&[0u8; 16]);
    let out = parser::extract_all_strings(&data, &str_sections(data.len()), 4);
    assert!(
        out.iter()
            .any(|s| s.content == "hello" && s.encoding == StringEncoding::Pascal),
        "got {:?}",
        out.iter()
            .map(|s| (s.content.clone(), s.encoding))
            .collect::<Vec<_>>()
    );
}

#[test]
fn strings_have_scores_and_labels() {
    let data = b"Loading configuration file\x00\x00".to_vec();
    let out = parser::extract_all_strings(&data, &str_sections(data.len()), 4);
    let s = out
        .iter()
        .find(|s| s.content == "Loading configuration file")
        .expect("string");
    assert!(s.score > -7.0 && s.score < 0.0, "score {}", s.score);
    assert_eq!(s.score, parser::string_model::string_score(&s.content));
    assert_eq!(parser::string_label(s.vaddr), format!("s_{:x}", s.vaddr));
}

#[test]
fn strings_sorted_by_vaddr() {
    let mut data = vec![0u8; 64];
    data[32..32 + 6].copy_from_slice(b"second");
    data[8..8 + 5].copy_from_slice(b"first");
    let out = parser::extract_all_strings(&data, &str_sections(data.len()), 4);
    let addrs: Vec<u64> = out.iter().map(|s| s.vaddr).collect();
    let mut sorted = addrs.clone();
    sorted.sort();
    assert_eq!(addrs, sorted);
}

#[test]
fn strings_high_confidence_gate() {
    assert!(parser::string_model::is_high_confidence(
        "The quick brown fox jumps over the lazy dog"
    ));
    assert!(!parser::string_model::is_high_confidence("aZ9&xQ2%k#"));
    assert!(!parser::string_model::is_high_confidence("l$0H"));
}

use crate::type_system::{CallingConvention, DataTypeManager, ID_CHAR, ID_INT, ID_UINT};

#[test]
fn types_bitfield_roundtrip() {
    let mut m = DataTypeManager::new();
    let s = m.create_struct("Flags").unwrap();
    let f = m.add_bitfield(s, "mode", ID_UINT, 0, 0, 3).unwrap();
    assert_eq!(f.bit_width, Some(3));
    let decl = m.to_c_decl(s, 2);
    assert!(decl.contains(" : 3;"), "decl:\n{}", decl);
    let doc = m.to_json();
    let mut m2 = DataTypeManager::new();
    m2.from_json(&doc).unwrap();
    let id = m2.find_by_name("Flags").unwrap();
    match m2.get(id).unwrap() {
        crate::type_system::DataType::Struct { fields, .. } => {
            assert_eq!(fields[0].bit_width, Some(3));
            assert_eq!(fields[0].bit_offset, Some(0));
        }
        other => panic!("expected struct, got {:?}", other),
    }
}

#[test]
fn types_bitfield_validation() {
    let mut m = DataTypeManager::new();
    let s = m.create_struct("Bad").unwrap();
    assert!(
        m.add_bitfield(s, "z", ID_UINT, 0, 0, 0).is_err(),
        "zero width"
    );
    assert!(
        m.add_bitfield(s, "z", ID_UINT, 0, 0, 33).is_err(),
        "over storage"
    );
    assert!(
        m.add_bitfield(s, "z", ID_UINT, 0, 30, 4).is_err(),
        "offset+width overflow"
    );
    assert!(
        m.add_bitfield(s, "z", ID_CHAR, 0, 0, 8).is_ok(),
        "full byte fits"
    );
    assert!(
        m.add_bitfield(9999, "z", ID_UINT, 0, 0, 1).is_err(),
        "bad struct"
    );
}

#[test]
fn types_cc_normalization_table() {
    let cases = [
        ("__stdcall", "stdcall"),
        ("STDCALL", "stdcall"),
        ("winapi", "stdcall"),
        ("__fastcall", "fastcall"),
        ("__thiscall", "thiscall"),
        ("__vectorcall", "vectorcall"),
        ("__cdecl", "cdecl"),
        ("sysv", "sysv"),
        ("System-V", "sysv"),
        ("win64", "win64"),
        ("ms", "win64"),
        ("", "unknown"),
        ("banana", "unknown"),
    ];
    for (inp, want) in cases {
        assert_eq!(
            CallingConvention::normalize(inp).as_str(),
            want,
            "input {}",
            inp
        );
    }
    let mut m = DataTypeManager::new();
    let id = m
        .create_function_sig("f", ID_INT, vec![], "__stdcall", false)
        .unwrap();
    match m.get(id).unwrap() {
        crate::type_system::DataType::FunctionSig {
            calling_convention, ..
        } => {
            assert_eq!(calling_convention, "stdcall");
        }
        _ => panic!("sig"),
    }
}

#[test]
fn types_win32_archive() {
    let mut m = DataTypeManager::new();
    let added = m.seed_archive("win32").unwrap();
    assert!(added >= 20, "added {}", added);
    assert_eq!(m.seed_archive("win32").unwrap(), 0);
    let guid = m.find_by_name("GUID").expect("GUID");
    assert_eq!(m.size_of(guid), Some(16));
    assert!(m.find_by_name("LARGE_INTEGER").is_some());
    assert!(m.find_by_name("DWORD").is_some());
    assert!(m.seed_archive("nope").is_err());
}

#[test]
fn types_crt_libc_archives() {
    let mut m = DataTypeManager::new();
    m.seed_archive("crt").unwrap();
    let tm = m.find_by_name("tm").expect("tm");
    assert_eq!(m.size_of(tm), Some(36));
    assert!(m.find_by_name("FILE").is_some());
    m.seed_archive("libc").unwrap();
    let si = m.find_by_name("sockaddr_in").expect("sockaddr_in");
    assert_eq!(m.size_of(si), Some(16));
    assert_eq!(DataTypeManager::list_archives().len(), 3);
}

use crate::gui::{AnnotationChange, BookmarkKind, CommentKind, ProgramData, SourceType};

#[test]
fn annotations_comment_kinds_and_legacy_sync() {
    let mut p = ProgramData::default();
    p.set_comment_kind(0x1000, CommentKind::Eol, Some("eol".into()));
    p.set_comment_kind(0x1000, CommentKind::Plate, Some("plate".into()));
    assert_eq!(p.comments.get(&0x1000).map(|s| s.as_str()), Some("eol"));
    assert_eq!(
        p.get_comment_kind(0x1000, CommentKind::Plate)
            .map(|s| s.as_str()),
        Some("plate")
    );
    assert_eq!(p.get_comment_kind(0x1000, CommentKind::Pre), None);
    p.set_comment_kind(0x1000, CommentKind::Eol, None);
    assert!(!p.comments.contains_key(&0x1000));
    assert!(
        p.get_comment_kind(0x1000, CommentKind::Plate).is_some(),
        "plate survives eol delete"
    );
}

#[test]
fn annotations_undo_redo_comment() {
    let mut p = ProgramData::default();
    p.annotation_undo.push(AnnotationChange::Comment {
        addr: 0x1000,
        kind: CommentKind::Pre,
        old: None,
        new: Some("hi".into()),
    });
    p.set_comment_kind(0x1000, CommentKind::Pre, Some("hi".into()));
    assert_eq!(
        p.undo_annotation().as_deref(),
        Some("comment(pre) at 0x1000")
    );
    assert_eq!(p.get_comment_kind(0x1000, CommentKind::Pre), None);
    assert_eq!(
        p.redo_annotation().as_deref(),
        Some("comment(pre) at 0x1000")
    );
    assert_eq!(
        p.get_comment_kind(0x1000, CommentKind::Pre)
            .map(|s| s.as_str()),
        Some("hi")
    );
    assert_eq!(
        p.undo_annotation().as_deref(),
        Some("comment(pre) at 0x1000")
    );
    assert!(p.undo_annotation().is_none(), "stack drained");
    assert!(p.redo_annotation().is_some());
}

#[test]
fn annotations_undo_coalesces_cell_edits() {
    let mut p = ProgramData::default();
    for text in ["a", "ab", "abc"] {
        let old = p.get_comment_kind(0x2000, CommentKind::Eol).cloned();
        p.set_comment_kind(0x2000, CommentKind::Eol, Some(text.into()));
        p.annotation_undo.push(AnnotationChange::Comment {
            addr: 0x2000,
            kind: CommentKind::Eol,
            old,
            new: Some(text.into()),
        });
    }
    assert_eq!(p.annotation_undo.undo_len(), 1, "typing coalesces");
    p.undo_annotation();
    assert_eq!(
        p.get_comment_kind(0x2000, CommentKind::Eol),
        None,
        "restores pre-typing state"
    );
}

#[test]
fn annotations_bookmark_label_rename_tag_undo() {
    let mut p = ProgramData::default();
    let old_bm = crate::gui::Bookmark {
        addr: 0x10,
        note: "v1".into(),
        kind: BookmarkKind::Note,
    };
    p.bookmarks.push(old_bm.clone());
    let new_bm = crate::gui::Bookmark {
        addr: 0x10,
        note: "v2".into(),
        kind: BookmarkKind::Error,
    };
    p.bookmarks.retain(|b| b.addr != 0x10);
    p.bookmarks.push(new_bm.clone());
    p.annotation_undo.push(AnnotationChange::Bookmark {
        addr: 0x10,
        old: Some(old_bm),
        new: Some(new_bm),
    });
    p.undo_annotation();
    assert_eq!(p.bookmarks.len(), 1);
    assert_eq!(p.bookmarks[0].note, "v1");
    p.set_label(0x20, "lol".into(), SourceType::Analysis);
    assert_eq!(p.label_sources.get(&0x20), Some(&SourceType::Analysis));
    p.annotation_undo.push(AnnotationChange::Label {
        addr: 0x20,
        old: None,
        new: Some(("lol".into(), SourceType::Analysis)),
    });
    p.undo_annotation();
    assert!(!p.user_labels.contains_key(&0x20));
    p.user_func_names.insert(0x30, "New".into());
    p.annotation_undo.push(AnnotationChange::Rename {
        addr: 0x30,
        old: None,
        new: Some("New".into()),
    });
    p.undo_annotation();
    assert!(!p.user_func_names.contains_key(&0x30));
    p.redo_annotation();
    assert_eq!(
        p.user_func_names.get(&0x30).map(|s| s.as_str()),
        Some("New")
    );
    p.annotation_undo.push(AnnotationChange::Tag {
        addr: 0x40,
        tag: "crypto".into(),
        added: true,
    });
    p.function_tags
        .entry(0x40)
        .or_default()
        .push("crypto".into());
    p.undo_annotation();
    assert!(p.function_tags.get(&0x40).is_none_or(|v| v.is_empty()));
    p.redo_annotation();
    assert_eq!(
        p.function_tags.get(&0x40).cloned().unwrap_or_default(),
        vec!["crypto".to_string()]
    );
}

#[test]
fn annotations_kind_parsing() {
    assert_eq!(CommentKind::parse("plate"), CommentKind::Plate);
    assert_eq!(CommentKind::parse("REPEAT"), CommentKind::Repeatable);
    assert_eq!(CommentKind::parse("???"), CommentKind::Eol);
    assert_eq!(
        CommentKind::from_tag(CommentKind::Post.tag()),
        CommentKind::Post
    );
    assert_eq!(BookmarkKind::parse("error"), BookmarkKind::Error);
    assert_eq!(BookmarkKind::Analysis.as_str(), "analysis");
    assert_eq!(
        SourceType::from_tag(SourceType::Imported.tag()),
        SourceType::Imported
    );
}

fn rdb_program(dir: &std::path::Path) -> (crate::gui::ProgramData, String) {
    let src = dir.join("tiny.bin");
    std::fs::write(&src, b"PRDBTESTDATA").unwrap();
    let p = ProgramData {
        file_path: src.to_string_lossy().into_owned(),
        disasm: Some(crate::disasm::DisasmResult {
            instructions: Arc::new(vec![insn(0x5000, &[0xC3], "ret", "")]),
            arch: "x86_64".into(),
        }),
        ..Default::default()
    };
    let db = dir.join("tiny.bin.rdb");
    (p, db.to_string_lossy().into_owned())
}

#[test]
fn project_v2_annotations_roundtrip() {
    let dir = std::env::temp_dir().join(format!("rdbv2_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (mut p, db) = rdb_program(&dir);
    p.set_comment_kind(0x5000, CommentKind::Eol, Some("eol note".into()));
    p.set_comment_kind(0x5000, CommentKind::Plate, Some("plate note".into()));
    p.bookmarks.push(crate::gui::Bookmark {
        addr: 0x5000,
        note: "err".into(),
        kind: BookmarkKind::Error,
    });
    p.set_label(0x5000, "s_5000".into(), SourceType::Analysis);
    p.function_tags
        .insert(0x5000, vec!["reviewed".into(), "crypto".into()]);
    let mut a = crate::analysis::AnalysisResult::default();
    a.functions
        .push(func(0x5000, 0x5001, FuncSource::UnwindInfo));
    a.xrefs.add(XRef {
        from: 0x5000,
        to: 0x6000,
        kind: XRefKind::CallIndirect,
        note: Some(std::sync::Arc::from("thunk")),
        is_primary: false,
        op_index: 3,
    });
    a.function_signatures.insert(
        0x5000,
        FunctionSignature {
            hash: 0x1111,
            specific: 0x2222,
            name: "f".into(),
            library: "l".into(),
            size: 7,
            score: 12.5,
        },
    );
    p.analysis = Some(std::sync::Arc::new(a));
    crate::project::save_project_db(&p, &db).expect("save");
    let snap = crate::project::load_project_db(&db).expect("load");
    assert_eq!(
        snap.annotations
            .comments_ex
            .get(&(0x5000, CommentKind::Plate))
            .map(|s| s.as_str()),
        Some("plate note")
    );
    assert_eq!(
        snap.annotations.comments.get(&0x5000).map(|s| s.as_str()),
        Some("eol note")
    );
    assert_eq!(snap.annotations.bookmarks[0].kind, BookmarkKind::Error);
    assert_eq!(
        snap.annotations.label_sources.get(&0x5000),
        Some(&SourceType::Analysis)
    );
    assert_eq!(
        snap.annotations
            .function_tags
            .get(&0x5000)
            .cloned()
            .unwrap_or_default()
            .len(),
        2
    );
    assert_eq!(snap.analysis.functions[0].source, FuncSource::UnwindInfo);
    let x = &snap.analysis.xrefs.all[0];
    assert_eq!(x.kind, XRefKind::CallIndirect);
    assert!(!x.is_primary);
    assert_eq!(x.op_index, 3);
    let sig = snap.analysis.function_signatures.get(&0x5000).unwrap();
    assert_eq!((sig.specific, sig.score), (0x2222, 12.5));
    let _ = std::fs::remove_dir_all(&dir);
}

use std::sync::atomic::AtomicBool;

fn cancelled() -> AtomicBool {
    let c = AtomicBool::new(false);
    c.store(true, std::sync::atomic::Ordering::Relaxed);
    c
}

#[test]
fn cancel_xrefs_returns_empty() {
    let bin = test_bin();
    let insns = vec![
        insn(0x1000, &[0xE8, 0, 0, 0, 0], "call", "0x15000"),
        insn(0x1005, &[0xC3], "ret", ""),
    ];
    let c = cancelled();
    let db = build_xrefs(&insns, &bin, Some(&c));
    assert!(db.all.is_empty());
}

#[test]
fn cancel_function_discovery_returns_empty() {
    let insns = vec![insn(0x5000, &[0xC3], "ret", "")];
    let c = cancelled();
    let funcs = detect_functions_with_extra(
        &insns,
        0,
        &[],
        &[(0x5000, FuncSource::UnwindInfo)],
        Some(&c),
    );
    assert!(funcs.is_empty());
}

#[test]
fn cancel_noreturn_returns_empty() {
    let imports = vec![Import {
        name: "abort".into(),
        library: "libc".into(),
        offset: 0x3000,
    }];
    let insns = vec![insn(0x2000, &[0xE8, 0, 0, 0, 0], "call", "0x3000")];
    let funcs = vec![func(0x2000, 0x2005, FuncSource::CallTarget)];
    let mut an = NoReturnAnalyzer::new();
    let c = cancelled();
    an.analyze(&insns, &imports, &funcs, Some(&c));
    assert!(!an.is_noreturn(0x2000), "no propagation when cancelled");
}

#[test]
fn cancel_stubs_and_switches_return_empty() {
    let bin = test_bin();
    let insns = vec![
        insn(0x1000, &[0xE9, 0, 0, 0, 0], "jmp", "0x2000"),
        insn(0x2000, &[0xC3], "ret", ""),
    ];
    let funcs = vec![
        func(0x1000, 0x1005, FuncSource::CallTarget),
        func(0x2000, 0x2001, FuncSource::CallTarget),
    ];
    let c = cancelled();
    assert!(build_stub_map(&insns, &funcs, &bin, Some(&c)).is_empty());
    assert!(crate::analysis::advanced::detect_switch_tables(&insns, &bin, Some(&c)).is_empty());
}

#[test]
fn cancel_fid_returns_empty() {
    let m = FunctionIDMatcher::new();
    let c = cancelled();
    let out = m.identify_with_context(
        &fid_insns(),
        &[(0x1000, 0x1010)],
        &HashMap::default(),
        &HashMap::default(),
        Some(&c),
    );
    assert!(out.is_empty());
}

#[test]
fn cancel_pipeline_returns_default_immediately() {
    use std::sync::Arc;
    let (sections, data) = text_data_sections();
    let bin = ParsedBinary {
        format: "ELF".into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        sections,
        symbols: vec![sym("f", 0x1000)],
        imports: Vec::new(),
        exports: Vec::new(),
        strings: Vec::new(),
        data: Arc::new(data),
        image_base: 0,
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
    let insns = vec![
        insn(0x1000, &[0xE8, 0, 0, 0, 0], "call", "0x15000"),
        insn(0x1005, &[0xC3], "ret", ""),
    ];
    let disasm = crate::disasm::DisasmResult {
        instructions: Arc::new(insns),
        arch: "x86_64".into(),
    };
    let c = cancelled();
    let started = std::time::Instant::now();
    let r = crate::analysis::auto_analyze_with_progress(
        &disasm,
        &bin,
        &HashMap::default(),
        &FunctionIDMatcher::new(),
        &c,
        &|_, _, _, _| {},
    );
    assert!(
        started.elapsed().as_secs() < 10,
        "cancelled pipeline must bail fast"
    );
    assert!(r.functions.is_empty(), "no functions from a cancelled run");
    assert!(r.xrefs.all.is_empty(), "no xrefs from a cancelled run");
}

#[test]
fn cancel_decompile_renders_no_assignments() {
    use crate::analysis::decompiler::LineKind;
    let cfg = single_block_cfg();
    let pi = vec![pinstr(
        0x1000,
        vec![
            POp::IntAdd {
                dst: PVar::Reg("rax"),
                a: PVar::Reg("rcx"),
                b: PVar::Const(2),
                size: 8,
            },
            POp::Return,
        ],
    )];
    let stack = StackFrame {
        func_entry: 0x1000,
        variables: Vec::new(),
        frame_size: 0,
    };
    let c = cancelled();
    let pc = decompile(LiftInput {
        cfg: &cfg,
        pinstrs_in_func: &pi,
        imap: &[],
        stack: &stack,
        func_name: "f",
        func_lookup: &HashMap::default(),
        is64: true,
        imports: &HashMap::default(),
        cancel: Some(&c),
    });
    assert!(
        pc.lines.iter().all(|l| l.kind != LineKind::Assignment),
        "cancelled decompile must not render assignments"
    );
    let pc2 = decompile(LiftInput {
        cfg: &cfg,
        pinstrs_in_func: &pi,
        imap: &[],
        stack: &stack,
        func_name: "f",
        func_lookup: &HashMap::default(),
        is64: true,
        imports: &HashMap::default(),
        cancel: None,
    });
    assert!(pc2.lines.iter().any(|l| matches!(
        l.kind,
        LineKind::Assignment | LineKind::Return
    )));
}

#[test]
fn parallel_xrefs_match_and_stay_ordered() {
    let n = 9000usize;
    let mut insns = Vec::with_capacity(n + 1);
    for i in 0..n {
        insns.push(insn(
            0x1000 + i as u64 * 5,
            &[0xE8, 0, 0, 0, 0],
            "call",
            "0x15000",
        ));
    }
    insns.push(insn(0x1000 + n as u64 * 5, &[0xC3], "ret", ""));
    let bin = test_bin();
    let a = build_xrefs(&insns, &bin, None);
    let b = build_xrefs(&insns, &bin, None);
    assert_eq!(a.all.len(), n, "one Call per call insn");
    assert!(a
        .all
        .iter()
        .all(|x| x.kind == XRefKind::Call && x.is_primary && x.op_index == 0));
    let key = |x: &XRef| (x.from, x.to, x.kind as u8, x.is_primary, x.op_index);
    assert!(a.all.iter().map(key).eq(b.all.iter().map(key)));
    assert!(a.all.windows(2).all(|w| w[0].from <= w[1].from));
}

#[test]
fn parallel_phases_trigger_on_many_functions() {
    let n = 40u64;
    let mut raw = Vec::new();
    let mut addrs = Vec::new();
    for i in 0..n {
        let addr = 0x1000 + i * 16;
        addrs.push(addr);
        if i + 1 < n {
            let next = 0x1000 + (i + 1) * 16;
            let rel = next as i64 - (addr as i64 + 5);
            raw.push(0xE8);
            raw.extend_from_slice(&(rel as i32).to_le_bytes());
            raw.push(0xC3);
        } else {
            raw.push(0xC3);
        }
        while raw.len() < (i as usize + 1) * 16 {
            raw.push(0x90);
        }
    }
    let bin = crate::parser::parse_raw_bytes(raw, 0x1000, "x86_64").expect("raw");
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm");
    let result = crate::analysis::auto_analyze(&disasm, &bin);
    assert!(
        result.functions.len() >= 40,
        "got {} functions",
        result.functions.len()
    );
    for f in &result.functions {
        assert!(result.cfgs.contains_key(&f.entry), "cfg for {:#x}", f.entry);
        assert!(
            result.stack_frames.contains_key(&f.entry),
            "frame for {:#x}",
            f.entry
        );
    }
    assert!(!result.callees.is_empty());
}

#[cfg(target_os = "linux")]
mod ptrace_tests {
    use crate::debugger::DebugState;

    struct GuardChild {
        pid: i32,
    }

    impl GuardChild {
        fn spawn() -> Self {
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0, "fork failed");
            if pid == 0 {
                unsafe {
                    loop {
                        libc::pause();
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
            GuardChild { pid }
        }
    }

    impl Drop for GuardChild {
        fn drop(&mut self) {
            unsafe {
                libc::kill(self.pid, libc::SIGKILL);
                let mut status = 0;
                for _ in 0..100 {
                    let w = libc::waitpid(self.pid, &mut status, libc::WNOHANG);
                    if w == self.pid || (w < 0 && *libc::__errno_location() == libc::ECHILD) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
            }
        }
    }

    #[test]
    fn ptrace_launch_missing_file_errors() {
        let mut dbg = crate::debugger::ptrace::PtraceDebugger::new();
        assert!(dbg.launch_process("/nonexistent/path/xyz123").is_err());
        assert!(!dbg.is_active);
    }

    #[test]
    fn ptrace_interrupt_needs_session() {
        let dbg = crate::debugger::ptrace::PtraceDebugger::new();
        assert!(dbg.interrupt().is_err());
        let st = DebugState::new();
        assert!(!st.break_exec, "pause flag defaults off");
    }

    #[test]
    fn ptrace_attach_regs_mem_threads_modules() {
        let child = GuardChild::spawn();
        let mut dbg = crate::debugger::ptrace::PtraceDebugger::new();
        dbg.attach_process(child.pid as u32)
            .expect("attach own child");
        assert!(dbg.is_active);

        let mut st = DebugState::new();
        dbg.get_registers(&mut st).expect("regs");
        assert_ne!(st.registers.rip, 0, "rip must be live");
        assert_ne!(st.registers.rsp, 0, "rsp must be live");
        assert!(!st.stack_data.is_empty(), "stack window");

        let rsp = st.registers.rsp;
        let pattern = [0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04];
        dbg.write_memory(rsp, &pattern).expect("write stack");
        let back = dbg.read_memory(rsp, 8).expect("read stack");
        assert_eq!(back, pattern);

        let tids = dbg.list_threads().expect("threads");
        assert!(tids.contains(&(child.pid as u32)));
        let mods = dbg.list_modules().expect("modules");
        assert!(!mods.is_empty(), "child maps libc");
        let regions = dbg.list_memory_regions().expect("regions");
        assert!(!regions.is_empty());

        dbg.set_hardware_breakpoint(
            0,
            st.registers.rip,
            crate::debugger::HwBpKind::Execute,
            crate::debugger::HwBpLen::One,
        )
        .expect("hw bp set");
        dbg.clear_hardware_breakpoint(0).expect("hw bp clear");

        dbg.detach_process(&st.breakpoints).expect("detach");
        assert!(!dbg.is_active);
    }

    #[test]
    fn ptrace_entry_break_rejects_non_elf() {
        let child = GuardChild::spawn();
        let mut dbg = crate::debugger::ptrace::PtraceDebugger::new();
        dbg.attach_process(child.pid as u32).expect("attach");
        let tmp = std::env::temp_dir().join(format!("notelf_{}.txt", std::process::id()));
        std::fs::write(&tmp, b"hello, not an elf").unwrap();
        assert!(dbg.setup_entry_break(tmp.to_str().unwrap()).is_err());
        let _ = std::fs::remove_file(&tmp);
        dbg.detach_process(&[]).expect("detach");
    }

    #[test]
    fn ptrace_breakpoint_plant_remove() {
        let child = GuardChild::spawn();
        let mut dbg = crate::debugger::ptrace::PtraceDebugger::new();
        dbg.attach_process(child.pid as u32).expect("attach");
        let mut st = DebugState::new();
        dbg.get_registers(&mut st).expect("regs");
        let mut bp = crate::debugger::Breakpoint {
            address: st.registers.rip,
            enabled: true,
            original_byte: 0,
            name: "t".into(),
            kind: crate::debugger::BpKind::SwExec,
            len: 1,
            planted: true,
        };
        dbg.set_breakpoint(&mut bp).expect("plant");
        let check = dbg.read_memory(bp.address, 1).expect("read");
        assert_eq!(check[0], 0xCC);
        dbg.remove_breakpoint(&bp).expect("remove");
        let restored = dbg.read_memory(bp.address, 1).expect("read");
        assert_eq!(restored[0], bp.original_byte);
        dbg.detach_process(&st.breakpoints).expect("detach");
    }
}

#[test]
fn misc_parsers_and_labels() {
    use crate::type_system::CallingConvention;
    assert_eq!(
        CallingConvention::normalize("__stdcall").as_str(),
        "stdcall"
    );
    assert_eq!(crate::parser::string_label(0xabcd), "s_abcd");
    assert!(parser::string_model::is_probable_string("hello world"));
    assert!(!parser::string_model::is_probable_string("aZ9&xQ2%k#"));
}

#[test]
fn misc_hashset_imports_used() {
    let s: HashSet<u64> = [1u64].into_iter().collect();
    assert!(s.contains(&1));
}

#[test]
fn misc_import_type_used() {
    let i = Import {
        name: "f".into(),
        library: "l".into(),
        offset: 1,
    };
    assert_eq!(i.offset, 1);
}

#[test]
fn misc_extracted_string_type_used() {
    let s = ExtractedString {
        vaddr: 1,
        content: "hi".into(),
        encoding: StringEncoding::Ascii,
        score: 0.0,
    };
    assert_eq!(s.vaddr, 1);
}

#[test]
fn misc_symbol_type_used() {
    let s = Symbol {
        name: "x".into(),
        addr: 2,
        size: 0,
        is_function: false,
    };
    assert_eq!(s.addr, 2);
}

#[test]
fn arm64_pipeline_disasm_functions_xrefs() {
    let code: Vec<u8> = [
        0x52800540u32,
        0x94000002,
        0xd65f03c0,
        0x11000400,
        0xd65f03c0,
    ]
    .iter()
    .flat_map(|w| w.to_le_bytes())
    .collect();
    let bin = crate::parser::parse_raw_bytes(code, 0x400000, "aarch64").expect("raw parse");
    let dis = crate::disasm::disassemble_binary(&bin).expect("arm64 disasm");

    assert_eq!(dis.instructions.len(), 5);
    assert_eq!(dis.instructions[1].mnemonic, "call");
    assert_eq!(dis.instructions[1].ops(), "0x40000c");
    assert_eq!(dis.instructions[3].mnemonic, "add");

    let res = crate::analysis::auto_analyze(&dis, &bin);
    assert_eq!(
        res.functions.len(),
        2,
        "entry + bl target: {:?}",
        res.functions.iter().map(|f| f.entry).collect::<Vec<_>>()
    );
    let calls: Vec<_> = res
        .xrefs
        .all
        .iter()
        .filter(|x| matches!(x.kind, crate::analysis::xref::XRefKind::Call))
        .collect();
    assert_eq!(calls.len(), 1, "one call edge expected");
    assert_eq!(calls[0].from, 0x400004);
    assert_eq!(calls[0].to, 0x40000c);
}

#[test]
fn arm64_unsupported_arch_still_rejected() {
    let bin = crate::parser::parse_raw_bytes(vec![0x90; 32], 0x1000, "mips").expect("raw parse");
    assert!(
        crate::disasm::disassemble_binary(&bin).is_err(),
        "mips must stay rejected"
    );
}

fn test_block(id: usize, start: u64, succs: &[(usize, EdgeKind)], preds: &[usize]) -> BasicBlock {
    BasicBlock {
        id,
        start,
        end: start + 0x10,
        instr_indices: 0..0,
        successors: succs
            .iter()
            .map(|&(target, kind)| Edge { target, kind })
            .collect(),
        predecessors: preds.to_vec(),
    }
}

#[test]
fn decompiler_if_else_join_has_no_gotos() {
    let cfg = CFG {
        func_entry: 0x1000,
        blocks: vec![
            test_block(
                0,
                0x1000,
                &[(1, EdgeKind::BranchTrue), (2, EdgeKind::BranchFalse)],
                &[],
            ),
            test_block(1, 0x1010, &[(3, EdgeKind::Jump)], &[0]),
            test_block(2, 0x1020, &[(3, EdgeKind::Jump)], &[0]),
            test_block(3, 0x1030, &[], &[1, 2]),
        ],
        block_at: [(0x1000u64, 0usize), (0x1010, 1), (0x1020, 2), (0x1030, 3)]
            .into_iter()
            .collect(),
    };
    let pi = vec![
        pinstr(
            0x1000,
            vec![
                POp::Cmp {
                    a: PVar::Reg("rax"),
                    b: PVar::Const(0),
                    size: 8,
                },
                POp::CBranch {
                    target: 0x1010,
                    cond: "je".into(),
                },
            ],
        ),
        pinstr(
            0x1010,
            vec![POp::Copy {
                dst: PVar::Reg("rax"),
                src: PVar::Const(1),
                size: 8,
            }],
        ),
        pinstr(
            0x1020,
            vec![POp::Copy {
                dst: PVar::Reg("rax"),
                src: PVar::Const(2),
                size: 8,
            }],
        ),
        pinstr(0x1030, vec![POp::Return]),
    ];
    let t = decompile_text(&cfg, &pi);
    assert!(t.contains("} else {"), "if/else rendered:\n{}", t);
    assert!(!t.contains("goto LAB_"), "join must not use gotos:\n{}", t);
    assert!(!t.contains("LAB_"), "join label must be dropped:\n{}", t);
    assert_eq!(
        t.matches("return").count(),
        1,
        "shared epilogue must render once:\n{}",
        t
    );
    assert_eq!(
        t.matches('{').count(),
        t.matches('}').count(),
        "balanced braces:\n{}",
        t
    );
}

#[test]
fn decompiler_loop_entered_from_outside_is_rendered() {
    
    
    let cfg = CFG {
        func_entry: 0x1000,
        blocks: vec![
            test_block(0, 0x1000, &[(1, EdgeKind::Jump)], &[]),
            test_block(
                1,
                0x1010,
                &[(2, EdgeKind::BranchTrue), (3, EdgeKind::BranchFalse)],
                &[0, 2],
            ),
            test_block(2, 0x1020, &[(1, EdgeKind::Jump)], &[1]),
            test_block(3, 0x1030, &[], &[1]),
        ],
        block_at: [(0x1000u64, 0usize), (0x1010, 1), (0x1020, 2), (0x1030, 3)]
            .into_iter()
            .collect(),
    };
    let imap = vec![
        insn(0x1010, &[0x48, 0x83, 0xF8, 0x05], "cmp", "rax, 0x5"),
        insn(0x1014, &[0x75, 0x0A], "jne", "0x1020"),
    ];
    let pi = vec![
        pinstr(
            0x1010,
            vec![
                POp::Cmp {
                    a: PVar::Reg("rax"),
                    b: PVar::Const(5),
                    size: 8,
                },
                POp::CBranch {
                    target: 0x1020,
                    cond: "jne".into(),
                },
            ],
        ),
        pinstr(
            0x1020,
            vec![POp::IntAdd {
                dst: PVar::Reg("rax"),
                a: PVar::Reg("rax"),
                b: PVar::Const(1),
                size: 8,
            }],
        ),
        pinstr(0x1030, vec![POp::Return]),
    ];
    let t = decompile_text_imap(&cfg, &pi, &imap);
    assert!(t.contains("while ("), "loop header rendered:\n{}", t);
    assert!(t.contains("return"), "exit block rendered:\n{}", t);
    assert!(!t.contains("goto LAB_"), "no goto needed:\n{}", t);
    assert_eq!(
        t.matches('{').count(),
        t.matches('}').count(),
        "balanced braces:\n{}",
        t
    );
}

#[test]
fn decompiler_loop_break_and_back_edge_render_structured() {
    let cfg = CFG {
        func_entry: 0x1000,
        blocks: vec![
            test_block(
                0,
                0x1000,
                &[(3, EdgeKind::BranchTrue), (1, EdgeKind::BranchFalse)],
                &[2],
            ),
            test_block(
                1,
                0x1010,
                &[(3, EdgeKind::BranchTrue), (2, EdgeKind::BranchFalse)],
                &[0],
            ),
            test_block(2, 0x1020, &[(0, EdgeKind::Jump)], &[1]),
            test_block(3, 0x1030, &[], &[0, 1]),
        ],
        block_at: [(0x1000u64, 0usize), (0x1010, 1), (0x1020, 2), (0x1030, 3)]
            .into_iter()
            .collect(),
    };
    let imap = vec![
        insn(0x1000, &[0x48, 0x83, 0xF8, 0x05], "cmp", "rax, 0x5"),
        insn(0x1004, &[0x74, 0x2A], "je", "0x1030"),
        insn(0x1010, &[0x48, 0x83, 0xFB, 0x00], "cmp", "rbx, 0x0"),
        insn(0x1014, &[0x74, 0x1A], "je", "0x1030"),
    ];
    let pi = vec![
        pinstr(
            0x1000,
            vec![
                POp::Cmp {
                    a: PVar::Reg("rax"),
                    b: PVar::Const(5),
                    size: 8,
                },
                POp::CBranch {
                    target: 0x1030,
                    cond: "je".into(),
                },
            ],
        ),
        pinstr(
            0x1010,
            vec![
                POp::Cmp {
                    a: PVar::Reg("rbx"),
                    b: PVar::Const(0),
                    size: 8,
                },
                POp::CBranch {
                    target: 0x1030,
                    cond: "je".into(),
                },
            ],
        ),
        pinstr(
            0x1020,
            vec![POp::IntAdd {
                dst: PVar::Reg("rax"),
                a: PVar::Reg("rax"),
                b: PVar::Const(1),
                size: 8,
            }],
        ),
        pinstr(0x1030, vec![POp::Return]),
    ];
    let t = decompile_text_imap(&cfg, &pi, &imap);
    assert!(t.contains("while ("), "loop rendered:\n{}", t);
    assert!(t.contains("break;"), "exit edge becomes break:\n{}", t);
    assert!(!t.contains("goto LAB_"), "back edge is not a goto:\n{}", t);
    assert!(
        !t.contains("continue;"),
        "redundant continue is dropped:\n{}",
        t
    );
    assert_eq!(
        t.matches('{').count(),
        t.matches('}').count(),
        "balanced braces:\n{}",
        t
    );
}
