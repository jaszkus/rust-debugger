use super::binary_codec::*;
use super::fnv1a64;
use super::snapshot::{load_project_db, save_project_db};
use crate::analysis::cfg::EdgeKind;
use crate::analysis::xref::XRefKind;
use crate::gui::{BookmarkKind, CommentKind, ProgramData, SourceType};

fn push_insn(w: &mut W, addr: u64, mnem: &str, ops: &str, bytes: &[u8]) {
    w.u64(addr);
    w.bytes(bytes);
    w.str(mnem);
    w.str(ops);
}

fn push_xref(w: &mut W, from: u64, to: u64, kind: u8, note: &str, v2: Option<(u8, i32)>) {
    w.u64(from);
    w.u64(to);
    w.u8(kind);
    w.str(note);
    if let Some((primary, op)) = v2 {
        w.u8(primary);
        w.i32(op);
    }
}

fn push_block(
    w: &mut W,
    id: usize,
    start: u64,
    end: u64,
    indices: &[u64],
    succs: &[(u64, u8)],
    preds: &[u64],
) {
    w.u32(id as u32);
    w.u64(start);
    w.u64(end);
    w.u32(indices.len() as u32);
    for &i in indices {
        w.u64(i);
    }
    w.u32(succs.len() as u32);
    for &(t, k) in succs {
        w.u64(t);
        w.u8(k);
    }
    w.u32(preds.len() as u32);
    for &p in preds {
        w.u64(p);
    }
}

fn push_cfg(w: &mut W, key: u64, func_entry: u64, blocks: impl FnOnce(&mut W)) {
    w.u64(key);
    w.u64(func_entry);
    w.u32(1);
    blocks(w);
    w.u32(0);
}

fn xref_index_maps(w: &mut W) {
    w.u32(1);
    w.u64(0x2000);
    w.u32(1);
    w.u32(0);
    w.u32(1);
    w.u64(0x1004);
    w.u32(1);
    w.u32(0);
}

fn write_analysis_v1(w: &mut W) {
    w.u32(1);
    w.u64(0x1000);
    w.u64(0x1100);
    w.str("fn_v1");
    w.u8(1);
    w.i64(0x40);
    w.u8(T_FUNC_ENTRY);

    w.u32(1);
    push_xref(
        w,
        0x1004,
        0x2000,
        T_XREF_CALL,
        "imp_Kernel32!CreateFileW",
        None,
    );
    xref_index_maps(w);

    w.u32(1);
    push_cfg(w, 0x1000, 0x1000, |w| {
        push_block(w, 0, 0x1000, 0x1100, &[0, 1], &[(1, T_EDGE_JMP)], &[]);
    });

    w.u32(1);
    w.u64(0x1000);
    w.u64(0x1000);
    w.i64(0x40);
    w.u32(1);
    w.i64(-8);
    w.u32(8);
    w.u32(3);
    w.u8(T_VAR_LOCAL);
    w.str("var_8");

    w.u32(1);
    w.u64(0x1000);
    w.u64(0x1000);
    w.str("fn_v1");
    w.u32(2);
    w.u32(0);
    w.str("void fn_v1(void)");
    w.u8(T_LINE_SIG);
    w.opt_u64(Some(0x1000));
    w.u32(0);
    w.str("return;");
    w.u8(T_LINE_RET);
    w.opt_u64(None);

    w.u32(0);
    w.u32(1);
    w.u64(0x1000);
    w.vec_u64(&[0x2000]);

    w.u32(1);
    w.u64(0x2000);
    w.u64(0x2000);
    w.u8(T_STUB_IMPORT);
    w.str("CreateFileW");

    w.u32(1);
    w.u64(0x1050);
    w.u64(0x3000);
    w.u32(2);
    w.vec_u64(&[0x1060, 0x1070]);

    w.u32(1);
    w.u64(0x4000);

    w.u32(1);
    w.u64(0x1000);
    w.u64(0xdeadbeef);
    w.str("CreateFileW");
    w.str("Kernel32.dll");
    w.u32(32);

    w.u32(1);
    w.u64(0x9001);
    w.str("V1Struct");
    w.u64(16);
    w.u8(T_RT_STRUCT);
    w.u32(1);
    w.str("f0");
    w.i64(0);
    w.u64(8);
    w.u64(6);
    w.u64(1);
}

fn write_analysis_v4(w: &mut W) {
    w.u32(1);
    w.u64(0x1000);
    w.u64(0x1100);
    w.str("fn_v4");
    w.u8(1);
    w.i64(0x40);
    w.u8(T_FUNC_ENTRY);
    w.u8(1);
    w.opt_u64(Some(0x2000));

    w.u32(1);
    push_xref(
        w,
        0x1004,
        0x2000,
        T_XREF_CALL,
        "imp_Kernel32!CreateFileW",
        Some((0, 1)),
    );
    xref_index_maps(w);

    w.u32(1);
    push_cfg(w, 0x1000, 0x1000, |w| {
        push_block(w, 0, 0x1000, 0x1100, &[1], &[(1, T_EDGE_FT)], &[0]);
    });

    w.u32(0);
    w.u32(0);
    w.u32(0);
    w.u32(0);

    w.u32(1);
    w.u64(0x2000);
    w.u64(0x2000);
    w.u8(T_STUB_TAIL);
    w.str("tail_fn");
    w.opt_u64(Some(0x5000));

    w.u32(0);
    w.u32(0);

    w.u32(1);
    w.u64(0x1000);
    w.u64(0xcafe);
    w.str("tail_fn");
    w.str("");
    w.u32(16);
    w.u64(0x1234);
    w.u64(0.75f64.to_bits());

    w.u32(0);
}

fn write_annotations_v1(w: &mut W) {
    w.u32(1);
    w.u64(0x1004);
    w.str("entry call");
    w.hashmap_u64_str(&std::collections::HashMap::new());
    w.u32(1);
    w.u64(0x1000);
    w.str("bookmark note");
    w.u32(0);
    w.u64(0);
    w.hashmap_u64_str(&std::collections::HashMap::new());
    w.u32(0);
    write_types_raw_json(w);
    w.u32(0);
}

fn write_annotations_v4(w: &mut W) {
    w.u32(1);
    w.u64(0x1004);
    w.str("entry call");
    w.u32(2);
    w.u64(0x1004);
    w.u8(1);
    w.str("pre-cmt");
    w.u64(0x1008);
    w.u8(4);
    w.str("rep-cmt");
    w.hashmap_u64_str(&std::collections::HashMap::new());
    w.u32(2);
    w.u64(0x1000);
    w.str("bm note");
    w.u8(0);
    w.u64(0x1004);
    w.str("bm analysis");
    w.u8(3);
    w.u32(1);
    w.u64(42);
    w.u64(0x10);
    w.u64(0x140001010);
    w.bytes(&[0x8d]);
    w.bytes(&[0x90]);
    w.str("nop out lea");
    w.u64(1_700_000_000);
    w.u64(43);
    w.hashmap_u64_str(&std::collections::HashMap::new());
    w.u32(2);
    w.u64(0x1000);
    w.u8(1);
    w.u64(0x1004);
    w.u8(0);
    w.u32(1);
    w.u64(0x1000);
    w.u32(2);
    w.str("crypto");
    w.str("winapi");
    w.u32(1);
    w.u64(0x1004);
    w.u64(0x2000);
    w.str("hand-made");
    w.str("Call");
    w.i32(0);
    write_types_raw_json(w);
    w.u32(0);
}

fn write_types_raw_json(w: &mut W) {
    let doc = serde_json::json!({
        "types": [
            { "id": 6, "name": "int", "kind": "primitive", "size": 4 },
            { "id": 100, "name": "MyStruct", "kind": "struct", "packed": false,
              "fields": [
                { "name": "a", "offset": 0, "type_id": 6, "comment": "", "bit_offset": 0, "bit_width": 0 },
                { "name": "b", "offset": 8, "type_id": 100, "comment": "", "bit_offset": 0, "bit_width": 0 }
              ] }
        ],
        "pointer_size": 8
    });
    w.str(&doc.to_string());
}

fn header_and_insns(
    w: &mut W,
    version: u32,
    source: &str,
    project: &str,
    src_len: u64,
    src_mtime: u64,
) {
    w.buf.extend_from_slice(super::MAGIC);
    w.u32(version);
    w.u64(1_700_000_000);
    w.str(source);
    w.str(project);
    w.u64(src_len);
    w.u64(src_mtime);
    w.str("x86");
    w.u32(2);
    push_insn(w, 0x1000, "mov", "eax,1", &[0xb8, 0x01, 0x00, 0x00, 0x00]);
    push_insn(w, 0x1004, "ret", "", &[0xc3]);
}

fn finish_raw(mut payload: Vec<u8>) -> Vec<u8> {
    let hash = fnv1a64(&payload);
    payload.extend_from_slice(&hash.to_le_bytes());
    payload
}

fn make_source(dir: &std::path::Path, tag: &str) -> (String, u64, u64) {
    let p = dir.join(format!("sample_{}.exe", tag));
    std::fs::write(&p, vec![0u8; 4096]).unwrap();
    let m = std::fs::metadata(&p).unwrap();
    let mtime = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (p.to_string_lossy().into_owned(), 4096, mtime)
}

fn fresh_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("rdbc_{}_{}", tag, std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_db(dir: &std::path::Path, tag: &str, bytes: &[u8]) -> String {
    let path = dir.join(format!("test_{}.rdb", tag));
    std::fs::write(&path, bytes).unwrap();
    path.to_string_lossy().into_owned()
}

#[test]
fn rddb_v1_loads_with_defaults() {
    let dir = fresh_dir("v1");
    let (src, len, mtime) = make_source(&dir, "v1");

    let mut w = W::new();
    header_and_insns(&mut w, 1, &src, "proj v1", len, mtime);
    write_analysis_v1(&mut w);
    write_annotations_v1(&mut w);

    let path = write_db(&dir, "v1", &finish_raw(w.buf));
    let snap = load_project_db(&path).expect("v1 file must load");

    assert_eq!(snap.project_name, "proj v1");
    assert_eq!(snap.disasm.instructions.len(), 2);
    assert_eq!(snap.disasm.instructions[0].mnemonic, "mov");

    assert_eq!(snap.analysis.functions.len(), 1);
    let f = &snap.analysis.functions[0];
    assert_eq!(f.name, "fn_v1");
    assert!(!f.is_thunk);
    assert!(f.thunk_target.is_none());

    assert_eq!(snap.analysis.xrefs.all.len(), 1);
    let x = &snap.analysis.xrefs.all[0];
    assert_eq!(x.kind, XRefKind::Call);
    assert!(x.is_primary);
    assert_eq!(x.op_index, 0);
    assert_eq!(x.note.as_deref(), Some("imp_Kernel32!CreateFileW"));

    let cfg = snap.analysis.cfgs.get(&0x1000).expect("cfg present");
    assert_eq!(cfg.blocks.len(), 1);
    assert_eq!(cfg.blocks[0].instr_indices, 0..2);
    assert_eq!(cfg.blocks[0].successors[0].kind, EdgeKind::Jump);

    let st = snap.analysis.stubs.get(&0x2000).unwrap();
    assert!(st.target_addr.is_none());

    let sig = snap.analysis.function_signatures.get(&0x1000).unwrap();
    assert_eq!(sig.specific, 0xdeadbeef);
    assert_eq!(sig.score, 0.0);

    assert_eq!(
        snap.annotations.comments.get(&0x1004).map(String::as_str),
        Some("entry call")
    );
    assert_eq!(
        snap.annotations
            .comments_ex
            .get(&(0x1004, CommentKind::Eol))
            .map(String::as_str),
        Some("entry call")
    );
    assert_eq!(snap.annotations.bookmarks[0].kind, BookmarkKind::Note);
    assert!(snap.annotations.label_sources.is_empty());
    assert!(snap.annotations.function_tags.is_empty());
    assert!(snap.annotations.types.find_by_name("MyStruct").is_some());
    assert_eq!(snap.analysis.pseudocode.len(), 0);

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rddb_v4_loads_with_ghidra_tags() {
    let dir = fresh_dir("v4");
    let (src, len, mtime) = make_source(&dir, "v4");

    let mut w = W::new();
    header_and_insns(&mut w, 4, &src, "proj v4", len, mtime);
    write_analysis_v4(&mut w);
    write_annotations_v4(&mut w);

    let path = write_db(&dir, "v4", &finish_raw(w.buf));
    let snap = load_project_db(&path).expect("v4 file must load");

    let f = &snap.analysis.functions[0];
    assert_eq!(f.name, "fn_v4");
    assert!(f.is_thunk);
    assert_eq!(f.thunk_target, Some(0x2000));

    let x = &snap.analysis.xrefs.all[0];
    assert!(!x.is_primary);
    assert_eq!(x.op_index, 1);
    assert_eq!(x.note.as_deref(), Some("imp_Kernel32!CreateFileW"));

    assert_eq!(
        snap.analysis.cfgs.get(&0x1000).unwrap().blocks[0].instr_indices,
        1..2
    );

    let st = snap.analysis.stubs.get(&0x2000).unwrap();
    assert_eq!(st.target_addr, Some(0x5000));
    assert_eq!(st.jump_addr, 0x2000);

    let sig = snap.analysis.function_signatures.get(&0x1000).unwrap();
    assert_eq!(sig.specific, 0x1234);
    assert!((sig.score - 0.75).abs() < 1e-9);

    assert_eq!(
        snap.annotations
            .comments_ex
            .get(&(0x1004, CommentKind::Pre))
            .map(String::as_str),
        Some("pre-cmt")
    );
    assert_eq!(
        snap.annotations
            .comments_ex
            .get(&(0x1008, CommentKind::Repeatable))
            .map(String::as_str),
        Some("rep-cmt")
    );
    assert_eq!(snap.annotations.bookmarks[1].kind, BookmarkKind::Analysis);
    assert_eq!(snap.annotations.patches.len(), 1);
    assert_eq!(snap.annotations.patches[0].original, vec![0x8d]);
    assert_eq!(snap.annotations.patches[0].new, vec![0x90]);
    assert_eq!(
        snap.annotations.label_sources.get(&0x1000),
        Some(&SourceType::User)
    );
    assert_eq!(
        snap.annotations.label_sources.get(&0x1004),
        Some(&SourceType::Analysis)
    );
    assert_eq!(
        snap.annotations.function_tags.get(&0x1000).unwrap(),
        &vec!["crypto".to_string(), "winapi".to_string()]
    );
    let ux = &snap.annotations.user_xrefs[0];
    assert_eq!(ux.kind, "Call");
    assert_eq!(ux.op_index, 0);
    assert_eq!(ux.note, "hand-made");
    assert!(snap.annotations.types.find_by_name("MyStruct").is_some());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rddb_v7_roundtrip_zstd_and_ranges() {
    let dir = fresh_dir("v6");
    let src = dir.join("sample_v7.exe");
    std::fs::write(&src, b"RDBV7ROUNDTRIPDATA").unwrap();

    let mut p = ProgramData {
        file_path: src.to_string_lossy().into_owned(),
        current_program_name: "v7 proj".into(),
        disasm: Some(crate::disasm::DisasmResult {
            instructions: std::sync::Arc::new(vec![crate::disasm::DisasmInstruction {
                address: 0x5000,
                bytes: crate::disasm::InsnBytes::from_slice(&[0xC3]),
                mnemonic: crate::disasm::intern_mnemonic("ret"),
                operands: "".into(),
            }]),
            arch: "x86".into(),
        }),
        ..Default::default()
    };
    p.comments.insert(0x5000, "hello v7".into());
    p.user_func_names.insert(0x5000, "tiny_fn".into());

    let mut a = crate::analysis::AnalysisResult::default();
    a.functions
        .push(crate::analysis::function::DetectedFunction {
            entry: 0x5000,
            end: 0x5001,
            name: "tiny".into(),
            has_frame: false,
            stack_size: 0,
            source: crate::analysis::function::FuncSource::EntryPoint,
            is_thunk: false,
            thunk_target: None,
        });
    let cfg = crate::analysis::cfg::CFG {
        func_entry: 0x5000,
        blocks: vec![crate::analysis::cfg::BasicBlock {
            id: 0,
            start: 0x5000,
            end: 0x5001,
            instr_indices: 0..1,
            successors: vec![],
            predecessors: vec![],
        }],
        block_at: Default::default(),
    };
    a.cfgs.insert(0x5000, cfg);
    a.debug_types = Some(std::sync::Arc::new(
        crate::analysis::symbols::debug_types::DebugTypes {
            structs: vec![crate::analysis::symbols::debug_types::DebugStruct {
                name: "Node".into(),
                size: 16,
                fields: vec![
                    crate::analysis::symbols::debug_types::DebugField {
                        name: "id".into(),
                        offset: 0,
                        type_name: "int32_t".into(),
                        size: 4,
                    },
                    crate::analysis::symbols::debug_types::DebugField {
                        name: "next".into(),
                        offset: 8,
                        type_name: "Node *".into(),
                        size: 8,
                    },
                ],
            }],
            functions: [(0x5000, crate::analysis::symbols::debug_types::DebugFunction {
                name: "tiny".into(),
                ret: "int32_t".into(),
                params: vec![crate::analysis::symbols::debug_types::DebugParam {
                    name: "node".into(),
                    type_name: "Node *".into(),
                    struct_name: Some("Node".into()),
                }],
                locals: vec![crate::analysis::symbols::debug_types::DebugLocal {
                    name: "n".into(),
                    type_name: "Node".into(),
                    struct_name: Some("Node".into()),
                    base: crate::analysis::symbols::debug_types::DebugBase::Cfa,
                    offset: -32,
                    size: 16,
                }],
            })]
            .into_iter()
            .collect(),
        },
    ));
    p.analysis = Some(std::sync::Arc::new(a));

    let db = dir.join("sample_v7.exe.rdb");
    let db_str = db.to_string_lossy().into_owned();
    save_project_db(&p, &db_str).expect("save");
    let raw = std::fs::read(&db).unwrap();
    assert_eq!(&raw[8..12], super::MAGIC_ZSTD, "v7 file is zstd framed");

    let snap = load_project_db(db.to_str().unwrap()).expect("v7 round trip");
    assert_eq!(snap.project_name, "v7 proj");
    assert_eq!(snap.analysis.functions[0].name, "tiny");
    assert_eq!(
        snap.analysis.cfgs.get(&0x5000).unwrap().blocks[0].instr_indices,
        0..1
    );
    assert_eq!(snap.disasm.instructions[0].mnemonic, "ret");
    let debug = snap.analysis.debug_types.as_ref().expect("debug types round trip");
    assert_eq!(debug.structs[0].name, "Node");
    assert_eq!(debug.structs[0].fields[1].name, "next");
    assert_eq!(debug.functions[&0x5000].params[0].struct_name.as_deref(), Some("Node"));
    let local = &debug.functions[&0x5000].locals[0];
    assert_eq!(local.name, "n");
    assert_eq!(local.base, crate::analysis::symbols::debug_types::DebugBase::Cfa);
    assert_eq!(local.offset, -32);
    assert_eq!(
        snap.annotations.comments.get(&0x5000).map(String::as_str),
        Some("hello v7")
    );
    assert_eq!(
        snap.annotations
            .user_func_names
            .get(&0x5000)
            .map(String::as_str),
        Some("tiny_fn")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rddb_rejects_bad_checksum() {
    let dir = fresh_dir("cksum");
    let (src, len, mtime) = make_source(&dir, "cksum");
    let mut w = W::new();
    header_and_insns(&mut w, 1, &src, "proj", len, mtime);
    write_analysis_v1(&mut w);
    write_annotations_v1(&mut w);
    let mut bytes = finish_raw(w.buf);
    let n = bytes.len();
    bytes[n - 1] ^= 0xff;
    let path = write_db(&dir, "cksum", &bytes);
    assert!(
        load_project_db(&path).is_none(),
        "checksum mismatch must reject"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rddb_rejects_future_version() {
    let dir = fresh_dir("fver");
    let (src, len, mtime) = make_source(&dir, "fver");
    let mut w = W::new();
    header_and_insns(&mut w, 999, &src, "proj", len, mtime);
    write_analysis_v1(&mut w);
    write_annotations_v1(&mut w);
    let path = write_db(&dir, "fver", &finish_raw(w.buf));
    assert!(
        load_project_db(&path).is_none(),
        "unknown version must reject"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rddb_rejects_corrupt_tag() {
    let dir = fresh_dir("ctag");
    let (src, len, mtime) = make_source(&dir, "ctag");
    let mut w = W::new();
    header_and_insns(&mut w, 1, &src, "proj", len, mtime);
    write_analysis_v1(&mut w);
    write_annotations_v1(&mut w);
    let mut bytes = finish_raw(w.buf);
    let mut off = 4 + 4 + 8;
    off += 4 + src.len();
    off += 4 + "proj".len();
    off += 8 + 8;
    off += 4 + "x86".len();
    off += 4;
    let insn0 = 8 + (4 + 5) + (4 + 3) + (4 + 5);
    let insn1 = 8 + (4 + 1) + (4 + 3) + 4;
    off += insn0 + insn1;
    off += 4 + 8 + 8 + (4 + "fn_v1".len()) + 1 + 8;
    assert_eq!(bytes[off], T_FUNC_ENTRY, "v1 function tag byte position");
    bytes[off] = 0x7f;
    let path = write_db(&dir, "ctag", &bytes);
    assert!(
        load_project_db(&path).is_none(),
        "unknown function tag must reject"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn rddb_rejects_stale_source() {
    let dir = fresh_dir("stale");
    let (src, len, mtime) = make_source(&dir, "stale");
    let mut w = W::new();
    header_and_insns(&mut w, 1, &src, "proj", len + 1, mtime);
    write_analysis_v1(&mut w);
    write_annotations_v1(&mut w);
    let path = write_db(&dir, "stale", &finish_raw(w.buf));
    assert!(load_project_db(&path).is_none(), "stale source must reject");
    let _ = std::fs::remove_dir_all(&dir);
}
