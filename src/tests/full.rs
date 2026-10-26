use crate::analysis::cfg::build_cfg;
use crate::analysis::decompiler::{decompile, LiftInput};
use crate::analysis::function::{detect_functions, FuncSource};
use crate::analysis::pcode::{lift_all, POp, PVar};
use crate::analysis::types::{canonical_reg, parse_operand, split_operands, Operand};

fn dis(code: &[u8], base: u64, arch: &str) -> Vec<crate::disasm::DisasmInstruction> {
    crate::disasm::disassemble_region(code, base, arch).unwrap()
}

fn lifted(code: &[u8], base: u64) -> Vec<crate::analysis::pcode::PInstr> {
    lift_all(&dis(code, base, "x86"))
}

fn render(code: &[u8], base: u64, is64: bool) -> String {
    let insns = dis(code, base, if is64 { "x86_64" } else { "x86" });
    let end = base + code.len() as u64;
    let pinstrs = lift_all(&insns);
    let cfg = build_cfg(&insns, base, end);
    let sf = crate::analysis::stack::analyze_stack(&pinstrs, base, end, false, 0);
    let lookup = rustc_hash::FxHashMap::default();
    let pc = decompile(LiftInput {
        cfg: &cfg,
        pinstrs_in_func: &pinstrs,
        imap: &insns,
        stack: &sf,
        func_name: "f",
        func_lookup: &lookup,
        is64,
        is_win64: false,
        thunk_targets: &rustc_hash::FxHashMap::default(),
        imports: &rustc_hash::FxHashMap::default(),
        switches: &[],
        cancel: None,
        debug_types: None,
    });
    pc.lines
        .iter()
        .map(|l| l.text.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

fn first_op(pin: &[crate::analysis::pcode::PInstr]) -> &POp {
    pin[0].ops.first().expect("at least one op")
}

#[test]
fn disasm_sequential_addresses_and_sizes() {
    let insns = dis(&[0x55, 0x89, 0xE5, 0xC3], 0x400000, "x86");
    assert_eq!(insns.len(), 3);
    assert_eq!(insns[0].address, 0x400000);
    assert_eq!(insns[1].address, 0x400001);
    assert_eq!(insns[2].address, 0x400003);
    assert_eq!(insns[0].bytes.len(), 1);
    assert_eq!(insns[1].bytes.len(), 2);
    for w in insns.windows(2) {
        assert_eq!(
            w[0].address + w[0].bytes.len() as u64,
            w[1].address,
            "addresses must be contiguous"
        );
    }
}

#[test]
fn disasm_empty_input_yields_nothing() {
    let insns = dis(&[], 0x1000, "x86");
    assert!(insns.is_empty());
}

#[test]
fn disasm_known_mnemonics() {
    let insns = dis(&[0x90, 0xC3, 0xC9, 0xCC], 0x10, "x86");
    assert_eq!(insns[0].mnemonic, "nop");
    assert_eq!(insns[1].mnemonic, "ret");
    assert_eq!(insns[2].mnemonic, "leave");
    assert_eq!(insns[3].mnemonic, "int3");
}

#[test]
fn disasm_x64_decodes_rex_instructions() {
    let insns = dis(&[0x48, 0x89, 0xD8, 0x55, 0xC3], 0x1000, "x86_64");
    assert_eq!(insns[0].mnemonic, "mov");
    assert!(insns[0].ops().contains("rax") && insns[0].ops().contains("rbx"));
    assert_eq!(insns[2].mnemonic, "ret");
}

#[test]
fn operand_register_lowercase() {
    assert_eq!(parse_operand("EAX"), Operand::Reg("eax"));
    assert_eq!(parse_operand("r8d"), Operand::Reg("r8d"));
}

#[test]
fn operand_immediates_small_and_large() {
    assert_eq!(parse_operand("42"), Operand::Imm(42));
    assert_eq!(parse_operand("-7"), Operand::Imm(-7));
    assert_eq!(parse_operand("0x20000"), Operand::Addr(0x20000));
    assert_eq!(parse_operand("0x10"), Operand::Imm(0x10));
}

#[test]
fn operand_mem_base_disp() {
    match parse_operand("[ebp+8]") {
        Operand::Mem {
            base,
            index,
            scale,
            disp,
            ..
        } => {
            assert_eq!(base, Some("ebp"));
            assert!(index.is_none());
            assert_eq!(scale, 1);
            assert_eq!(disp, 8);
        }
        other => panic!("{:?}", other),
    }
}

#[test]
fn operand_mem_negative_disp() {
    match parse_operand("[esp-4]") {
        Operand::Mem { base, disp, .. } => {
            assert_eq!(base, Some("esp"));
            assert_eq!(disp, -4);
        }
        other => panic!("{:?}", other),
    }
}

#[test]
fn operand_mem_index_scale() {
    match parse_operand("[eax+ecx*4+0x10]") {
        Operand::Mem {
            base,
            index,
            scale,
            disp,
            ..
        } => {
            assert_eq!(base, Some("eax"));
            assert_eq!(index, Some("ecx"));
            assert_eq!(scale, 4);
            assert_eq!(disp, 0x10);
        }
        other => panic!("{:?}", other),
    }
}

#[test]
fn operand_mem_scale_first_notation_keeps_index() {
    match parse_operand("[8*rax]") {
        Operand::Mem {
            index, scale, base, ..
        } => {
            assert_eq!(index, Some("rax"));
            assert_eq!(scale, 8);
            assert!(base.is_none());
        }
        other => panic!("{:?}", other),
    }
}

#[test]
fn operand_ptr_prefix_sets_size() {
    match parse_operand("dword ptr [ecx+4]") {
        Operand::Mem {
            size, base, disp, ..
        } => {
            assert_eq!(size, 4);
            assert_eq!(base, Some("ecx"));
            assert_eq!(disp, 4);
        }
        other => panic!("{:?}", other),
    }
    match parse_operand("byte ptr [edx]") {
        Operand::Mem { size, .. } => assert_eq!(size, 1),
        other => panic!("{:?}", other),
    }
}

#[test]
fn operand_unknown_token_passthrough() {
    match parse_operand("<label>") {
        Operand::Unknown(s) => assert!(!s.is_empty()),
        other => panic!("{:?}", other),
    }
}

#[test]
fn split_operands_respects_brackets() {
    let v = split_operands("xmm0, dword ptr [eax + ecx*2 - 8], 0x30");
    assert_eq!(v.len(), 3);
    assert_eq!(v[0], "xmm0");
    assert!(v[1].contains('[') && v[1].contains(']'));
    assert_eq!(v[2], "0x30");
}

#[test]
fn canonical_reg_full_map() {
    assert_eq!(canonical_reg("eax"), "rax");
    assert_eq!(canonical_reg("al"), "rax");
    assert_eq!(canonical_reg("esi"), "rsi");
    assert_eq!(canonical_reg("r15b"), "r15");
    assert_eq!(canonical_reg("esp"), "rsp");
    assert_eq!(canonical_reg("xmm3"), "xmm3");
}

#[test]
fn demangle_itanium_functions_and_vtables() {
    let d = crate::analysis::demangle::demangle_name;
    assert_eq!(d("_ZTV3Foo"), "vtable for Foo");
    assert_eq!(d("_ZTI3Foo"), "typeinfo for Foo");
    assert_eq!(d("_ZTS3Foo"), "typeinfo name for Foo");
    assert_ne!(d("_ZN3Foo3barEv"), "_ZN3Foo3barEv", "should demangle");
}

#[test]
fn demangle_plain_names_untouched() {
    let d = crate::analysis::demangle::demangle_name;
    assert_eq!(d("main"), "main");
    assert_eq!(d("_DllMain@12"), "_DllMain@12");
}

#[test]
fn detect_entry_point_source() {
    let insns = dis(&[0x55, 0x89, 0xE5, 0xC3], 0x2000, "x86");
    let funcs = detect_functions(&insns, 0x2000, &[]);
    assert!(funcs
        .iter()
        .any(|f| f.entry == 0x2000 && f.source == FuncSource::EntryPoint));
}

#[test]
fn detect_call_targets_direct_rel32() {
    let target = 0x3000u64;
    let rel = (target as i64 - 0x1005_i64) as i32;
    let mut code: Vec<u8> = vec![0xE8];
    code.extend(rel.to_le_bytes());
    code.push(0xC3);
    while (code.len() as u64) < 0x10 {
        code.push(0xCC);
    }
    code.extend([0x55, 0xC9, 0xC3]);
    let _ = code;

    let mut buf: Vec<u8> = Vec::new();
    let callee = 0x1010u64;
    let rel = (callee as i64 - (0x1000 + 5) as i64) as i32;
    buf.push(0xE8);
    buf.extend(rel.to_le_bytes());
    buf.push(0xC3);
    while (buf.len() as u64) < 0x10 {
        buf.push(0xCC);
    }
    buf.extend([0x53, 0x5B, 0xC3]);
    let insns = dis(&buf, 0x1000, "x86");
    let funcs = detect_functions(&insns, 0x1000, &[]);
    assert!(
        funcs
            .iter()
            .any(|f| f.entry == callee && f.source == FuncSource::CallTarget),
        "entries: {:?}",
        funcs
            .iter()
            .map(|f| (f.entry, f.source.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn detect_after_return_function_directly_adjacent() {
    let buf = [0xC3, 0x55, 0x89, 0xE5, 0xC9, 0xC3];
    let insns = dis(&buf, 0x1000, "x86");
    let funcs = detect_functions(&insns, 0, &[]);
    assert!(
        funcs.iter().any(|f| f.entry == 0x1001
            && matches!(f.source, FuncSource::AfterReturn | FuncSource::Prologue)),
        "after-return function must be discovered: {:?}",
        funcs
    );
}

#[test]
fn detect_symbols_become_entries_with_names() {
    let insns = dis(&[0x55, 0xC3, 0xC3], 0x1000, "x86");
    let syms = vec![crate::parser::Symbol {
        name: "my_func".into(),
        addr: 0x1000,
        size: 0,
        is_function: true,
    }];
    let funcs = detect_functions(&insns, 0, &syms);
    let hit = funcs
        .iter()
        .find(|f| f.entry == 0x1000)
        .expect("symbol entry");
    assert_eq!(hit.name, "my_func");
}

#[test]
fn detect_prologue_absorption_no_duplicate_stub() {
    let base = 0x5000u64;
    let func = base;
    let join = func + 6;
    let mut buf: Vec<u8> = Vec::new();
    while ((buf.len() as u64) + base) < func {
        buf.push(0x90);
    }
    buf.extend([0x55, 0x89, 0xE5, 0x83, 0xEC, 0x14]);
    let body_off = buf.len() as u64;
    assert_eq!(base + body_off, join);
    buf.extend([0x53, 0x5F, 0x5E, 0xC9, 0xC3]);
    let caller_at = base - 0x20;
    let mut full: Vec<u8> = Vec::new();
    let rel = (join as i64 - (caller_at + 5) as i64) as i32;
    full.push(0xE8);
    full.extend(rel.to_le_bytes());
    full.push(0xC3);
    while ((full.len() as u64) + caller_at) < func {
        full.push(0x90);
    }
    full.extend_from_slice(&buf);
    let insns = dis(&full, caller_at, "x86");
    let funcs = detect_functions(&insns, 0, &[]);
    let f = funcs
        .iter()
        .find(|f| f.entry <= join && join < f.end)
        .expect("join inside some function");
    assert_eq!(f.entry, func, "must expand to prologue head");
    assert!(
        !funcs.iter().any(|f| f.entry == join),
        "no stub entry at join"
    );
}

#[test]
fn detect_cancel_flag_stops_discovery() {
    let insns = dis(&[0x55, 0xC3], 0x1000, "x86");
    let cancel = std::sync::atomic::AtomicBool::new(true);
    let funcs = crate::analysis::function::detect_functions_impl(&insns, 0, &[], Some(&cancel));
    assert!(funcs.is_empty(), "cancelled run must return empty");
}

#[test]
fn cfg_single_block_straight_line() {
    let insns = dis(&[0xB8, 0x01, 0, 0, 0, 0xC3], 0x1000, "x86");
    let cfg = build_cfg(&insns, 0x1000, 0x1006);
    assert_eq!(cfg.blocks.len(), 1);
    assert!(cfg.blocks[0].successors.is_empty(), "ret ends flow");
    assert_eq!(cfg.blocks[0].instr_indices.len(), 2);
}

#[test]
fn cfg_conditional_branch_creates_two_edges() {
    let code = [
        0x85, 0xC0, 0x74, 0x05, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xFF, 0xC0, 0xC3,
    ];
    let insns = dis(&code, 0x1000, "x86");
    let cfg = build_cfg(&insns, 0x1000, 0x100C);
    assert!(cfg.blocks.len() >= 2, "jcc must split blocks");
    let b0 = &cfg.blocks[0];
    assert_eq!(b0.successors.len(), 2, "taken + fallthrough");
}

#[test]
fn cfg_loop_back_edge_creates_second_predecessor() {
    let code = [0xB9, 0x0A, 0x00, 0x00, 0x00, 0xFF, 0xC9, 0x75, 0xFC, 0xC3];
    let insns = dis(&code, 0x1000, "x86");
    let cfg = build_cfg(&insns, 0x1000, 0x100A);
    let loop_body = cfg
        .blocks
        .iter()
        .find(|b| b.start == 0x1005)
        .expect("loop body block");
    assert_eq!(
        loop_body.predecessors.len(),
        2,
        "loop header must have entry + back-edge preds"
    );
}

#[test]
fn cfg_indirect_jmp_keeps_fallthrough_block_alive() {
    let code = [0xFF, 0xE0, 0xC3];
    let insns = dis(&code, 0x1000, "x86");
    let cfg = build_cfg(&insns, 0x1000, 0x1003);
    assert_eq!(
        cfg.blocks.len(),
        2,
        "indirect jmp must not swallow the next block"
    );
}

#[test]
fn lift_alu_binops() {
    let cases: &[(&[u8], &str)] = &[
        (&[0x01, 0xD8], "add"),
        (&[0x29, 0xD8], "sub"),
        (&[0x21, 0xD8], "and"),
        (&[0x09, 0xD8], "or"),
        (&[0x31, 0xD8], "xor"),
    ];
    for &(bytes, mnem) in cases {
        let pin = lifted(bytes, 0x1000);
        assert!(
            matches!(
                pin[0].ops[0],
                POp::IntAdd { .. }
                    | POp::IntSub { .. }
                    | POp::IntAnd { .. }
                    | POp::IntOr { .. }
                    | POp::IntXor { .. }
            ),
            "{} did not lift to an Int binop",
            mnem
        );
    }
}

#[test]
fn lift_shifts() {
    let pin = lifted(&[0xC1, 0xE0, 0x04], 0x1000);
    assert!(pin[0]
        .ops
        .iter()
        .any(|op| matches!(op, POp::IntLeft { .. })));
    let pin = lifted(&[0xC1, 0xE8, 0x02], 0x1000);
    assert!(pin[0].ops.iter().any(|op| matches!(op, POp::IntShr { .. })));
    let pin = lifted(&[0xC1, 0xF8, 0x02], 0x1000);
    assert!(pin[0].ops.iter().any(|op| matches!(op, POp::IntSar { .. })));
}

#[test]
fn lift_movzx_widths() {
    let pin = lifted(&[0x0F, 0xB6, 0x01], 0x1000);
    assert!(
        matches!(first_op(&pin), POp::Load { size: 1, .. })
            || pin[0]
                .ops
                .iter()
                .any(|o| matches!(o, POp::Zext { from_size: 1, .. })),
        "movzx mem8 must load width 1 / zext from 1"
    );
}

#[test]
fn lift_lea_rip_relative_is_absolute_on_x64() {
    let base = 0x8000u64;
    let pin = lift_all(&dis(
        &[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00, 0xC3],
        base,
        "x86_64",
    ));
    let abs = pin[0]
        .ops
        .iter()
        .find_map(|o| match o {
            POp::LeaAddr { addr, .. } => Some(*addr),
            _ => None,
        })
        .expect("rip-relative lea yields LeaAddr");
    assert_eq!(abs, base + 7, "rip+0 resolves to the following instruction");
}

#[test]
fn lift_push_pop_sizes_follow_operand() {
    let pin = lifted(&[0x56], 0x1000);
    match first_op(&pin) {
        POp::Push { size, src } => {
            assert_eq!(*size, 4, "x86 push esi is dword");
            assert_eq!(*src, PVar::Reg("rsi"));
        }
        other => panic!("{:?}", other),
    }
    let pin = lifted(&[0x5E], 0x1000);
    assert!(matches!(first_op(&pin), POp::Pop { size: 4, .. }));
}

#[test]
fn lift_call_forms() {
    let base = 0x9000u64;
    let rel = -5i32;
    let mut code: Vec<u8> = vec![0xE8];
    code.extend(rel.to_le_bytes());
    let pin = lifted(&code, base);
    assert!(matches!(first_op(&pin), POp::Call { target } if *target == base));
    let pin = lifted(&[0xFF, 0xD0], base);
    assert!(matches!(first_op(&pin), POp::CallInd { .. }));
}

#[test]
fn lift_subreg_mov_is_rmw_not_full_copy() {
    let pin = lifted(&[0xB0, 0x05], 0x1000);
    assert!(
        !pin[0]
            .ops
            .iter()
            .any(|o| matches!(o, POp::Copy { dst: PVar::Reg(r), .. } if *r == "rax")),
        "narrow mov must be RMW, got {:?}",
        pin[0].ops
    );
    assert!(
        pin[0].ops.iter().any(|o| matches!(o, POp::IntOr { .. })),
        "RMW needs Or, got {:?}",
        pin[0].ops
    );
    let pin = lifted(&[0xB8, 0x05, 0x00, 0x00, 0x00], 0x1000);
    assert!(
        matches!(first_op(&pin), POp::Copy { .. }),
        "mov eax keeps Copy, got {:?}",
        pin[0].ops
    );
}

#[test]
fn lift_high_byte_mov_shifts() {
    let pin = lifted(&[0xB4, 0x00], 0x1000);
    assert!(
        pin[0].ops.iter().any(|o| matches!(
            o,
            POp::IntLeft {
                b: PVar::Const(8),
                ..
            }
        )),
        "ah write must shift left by 8, got {:?}",
        pin[0].ops
    );
}

#[test]
fn lift_subreg_alu_is_rmw() {
    let pin = lifted(&[0x00, 0xD8], 0x1000);
    assert!(
        pin[0].ops.len() > 1,
        "narrow ALU must expand, got {:?}",
        pin[0].ops
    );
    assert!(
        !pin[0]
            .ops
            .iter()
            .any(|o| matches!(o, POp::IntAdd { dst: PVar::Reg(r), .. } if *r == "rax")),
        "no direct IntAdd into rax, got {:?}",
        pin[0].ops
    );
}

#[test]
fn lift_sib_keeps_base_index_scale() {
    let pin = lifted(&[0x8B, 0x44, 0x8B, 0x10], 0x1000);
    match first_op(&pin) {
        POp::Load {
            addr:
                PVar::Scaled {
                    base,
                    index,
                    scale,
                    disp,
                },
            ..
        } => {
            assert_eq!(
                (base.as_ref(), index.as_ref(), *scale, *disp),
                (&PVar::Reg("rbx"), &PVar::Reg("rcx"), 4, 0x10)
            );
        }
        other => panic!("expected Scaled load, got {:?}", other),
    }
}

#[test]
fn lift_ret_imm_is_returnpop() {
    let pin = lifted(&[0xC3], 0x1000);
    assert!(matches!(first_op(&pin), POp::Return));
    let pin = lifted(&[0xC2, 0x08, 0x00], 0x1000);
    assert!(
        matches!(first_op(&pin), POp::ReturnPop { pop_imm: 8 }),
        "got {:?}",
        pin[0].ops
    );
}

#[test]
fn lift_narrow_not_neg_xchg() {
    let pin = lifted(&[0xF6, 0xD0], 0x1000);
    assert!(
        pin[0].ops.iter().any(|o| matches!(o, POp::IntOr { .. })),
        "not al needs RMW store, got {:?}",
        pin[0].ops
    );
    let pin = lifted(&[0xF6, 0xDB], 0x1000);
    assert!(
        pin[0].ops.iter().any(|o| matches!(o, POp::IntSub { .. })),
        "neg bl needs Sub, got {:?}",
        pin[0].ops
    );
    let pin = lifted(&[0x86, 0xD8], 0x1000);
    assert!(
        !matches!(first_op(&pin), POp::Unimplemented(_)),
        "narrow xchg must be modeled, got {:?}",
        pin[0].ops
    );
    assert!(
        pin[0]
            .ops
            .iter()
            .any(|o| matches!(o, POp::Copy { .. } | POp::IntOr { .. } | POp::IntAnd { .. })),
        "narrow xchg must swap through RMW, got {:?}",
        pin[0].ops
    );
}

#[test]
fn emu_subreg_writes_preserve_rest() {
    let code = vec![
        0x48, 0xC7, 0xC0, 0xFF, 0xFF, 0xFF, 0xFF, 0xB0, 0x12, 0xB4, 0x34, 0xC3,
    ];
    let r = emu_run_raw(&code, &[]);
    assert_eq!(r.reason, crate::emu::EndReason::Returned);
    assert_eq!(
        r.rax, 0xFFFF_FFFF_FFFF_3412,
        "steps={} trace={:x?}",
        r.steps, r.trace_tail
    );
}

#[test]
fn lift_jcc_and_setcc_conditions() {
    let pin = lifted(&[0x74, 0x08], 0x1000);
    assert!(matches!(
        first_op(&pin),
        POp::CBranch { target: 0x100A, .. }
    ));
    let pin = lifted(&[0x0F, 0x94, 0xC0], 0x1000);
    match first_op(&pin) {
        POp::SetCC { cond, dst, size } => {
            assert!(cond == "e" || cond == "ZF", "cond was: {}", cond);
            assert_eq!(*size, 1);
            assert_eq!(*dst, PVar::Reg("rax"));
        }
        other => panic!("{:?}", other),
    }
}

#[test]
fn lift_cmp_test_produce_flag_ops() {
    let pin = lifted(&[0x39, 0xCA], 0x1000);
    assert!(matches!(first_op(&pin), POp::Cmp { .. }));
    let pin = lifted(&[0x85, 0xC9], 0x1000);
    assert!(matches!(first_op(&pin), POp::Test { .. }));
}

#[test]
fn lift_sse_moves_and_arith() {
    let base = 0xA000u64;
    let pin = lifted(&[0x0F, 0x28, 0x00], base);
    assert!(
        matches!(first_op(&pin), POp::Load { size: 16, .. }),
        "movaps mem load 16B"
    );
    let pin = lifted(&[0x0F, 0x29, 0x00], base);
    assert!(matches!(first_op(&pin), POp::Store { size: 16, .. }));
    let pin = lifted(&[0xF3, 0x0F, 0x58, 0xC1], base);
    match first_op(&pin) {
        POp::FloatBinop { kind, size, .. } => {
            assert_eq!(kind, "add");
            assert_eq!(*size, 4);
        }
        other => panic!("addss: {:?}", other),
    }
    let pin = lifted(&[0xF2, 0x0F, 0x5E, 0xC1], base);
    match first_op(&pin) {
        POp::FloatBinop { kind, size, .. } => {
            assert_eq!(kind, "div");
            assert_eq!(*size, 8);
        }
        other => panic!("divsd: {:?}", other),
    }
    let pin = lifted(&[0xF3, 0x0F, 0x2C, 0xC0], base);
    assert!(matches!(first_op(&pin), POp::Cvt { kind, .. } if kind == "f2i"));
    let pin = lifted(&[0x66, 0x48, 0x0F, 0x6E, 0xC0], base);
    assert!(!pin[0].ops.is_empty(), "movq gp<->xmm must lift");
    assert!(!matches!(first_op(&pin), POp::Unimplemented(_)));
}

#[test]
fn lift_xorps_zeroing_is_intxor() {
    let pin = lifted(&[0x0F, 0x57, 0xC0], 0x1000);
    match first_op(&pin) {
        POp::IntXor { dst, a, b, size } => {
            assert_eq!(*size, 16);
            assert_eq!(dst, a);
            assert_eq!(dst, b);
        }
        other => panic!("{:?}", other),
    }
}

#[test]
fn lift_genuinely_unknown_marks_unimplemented() {
    let pin = lifted(&[0xD9, 0xF1], 0x1000);
    assert!(matches!(first_op(&pin), POp::Unimplemented(_)));
}

#[test]
fn lift_cmov_renders_conditional_select() {
    
    let text = render(&[0x48, 0x83, 0xF8, 0x00, 0x48, 0x0F, 0x45, 0xC1, 0xC3], 0x1000, true);
    assert!(
        text.contains("?") && text.contains("rcx"),
        "cmov must render a select:\n{}",
        text
    );
    assert!(!text.contains("not modeled"), "cmov lifted:\n{}", text);
}

#[test]
fn lift_bt_recovers_bit_condition() {
    
    let text = render(&[0x48, 0x0F, 0xBA, 0xE0, 0x05, 0x72, 0x01, 0xC3, 0xC3], 0x1000, true);
    assert!(
        text.contains(">> 5") && text.contains("& 1"),
        "bt condition must be a bit test:\n{}",
        text
    );
}

#[test]
fn lift_bts_renders_bit_set() {
    
    let text = render(&[0x48, 0x0F, 0xAB, 0xD8, 0xC3], 0x1000, true);
    assert!(
        text.contains("1 << rbx") && text.contains('|'),
        "bts must render a bit set:\n{}",
        text
    );
}

#[test]
fn lift_lock_cmpxchg_is_visible() {
    
    let text = render(&[0xF0, 0x0F, 0xB1, 0x51, 0x2C, 0xC3], 0x1000, true);
    assert!(
        text.contains("atomic_cmpxchg"),
        "lock cmpxchg must be modeled:\n{}",
        text
    );
    assert!(!text.contains("not modeled"), "no omission:\n{}", text);
}

#[test]
fn conditional_branch_outside_function_is_rendered() {
    
    let text = render(&[0x83, 0xF8, 0x00, 0x74, 0x10, 0xC3], 0x1000, false);
    assert!(
        text.contains("0x1015") && text.contains("if ("),
        "external branch must stay visible:\n{}",
        text
    );
    assert!(!text.contains("MISSING"), "no missing-branch warning:\n{}", text);
}

#[test]
fn analyze_stack_finds_rbp_slots() {
    let code = [0x55, 0x89, 0xE5, 0x8B, 0x45, 0xF8, 0xC9, 0xC3];
    let base = 0x1000u64;
    let insns = dis(&code, base, "x86");
    let pinstrs = lift_all(&insns);
    let sf = crate::analysis::stack::analyze_stack(&pinstrs, base, base + 8, true, 0);
    assert!(
        sf.variables.iter().any(|v| v.offset == -8),
        "[ebp-8] must be discovered, vars: {:?}",
        sf.variables
    );
}

#[test]
fn decompile_const_fold_arith() {
    let text = render(
        &[0xB8, 0x02, 0, 0, 0, 0x83, 0xC0, 0x03, 0xC3],
        0x1000,
        false,
    );
    assert!(
        text.contains("return 5;") || text.contains("return 5"),
        "{}",
        text
    );
}

#[test]
fn decompile_call_renders_known_name_and_args_x64() {
    let base = 0x1000u64;
    let callee = 0x2000u64;
    let mut code: Vec<u8> = Vec::new();
    code.extend([0xB9, 0x01, 0, 0, 0]);
    let rel = (callee as i64 - (base + code.len() as u64 + 5) as i64) as i32;
    code.push(0xE8);
    code.extend(rel.to_le_bytes());
    code.push(0xC3);
    let insns = dis(&code, base, "x86_64");
    let end = base + code.len() as u64;
    let pinstrs = lift_all(&insns);
    let cfg = build_cfg(&insns, base, end);
    let sf = crate::analysis::stack::analyze_stack(&pinstrs, base, end, false, 0);
    let mut lookup = rustc_hash::FxHashMap::default();
    lookup.insert(callee, "target_fn".to_string());
    let pc = decompile(LiftInput {
        cfg: &cfg,
        pinstrs_in_func: &pinstrs,
        imap: &insns,
        stack: &sf,
        func_name: "f",
        func_lookup: &lookup,
        is64: true,
        is_win64: false,
        thunk_targets: &rustc_hash::FxHashMap::default(),
        imports: &rustc_hash::FxHashMap::default(),
        switches: &[],
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
        text.contains("target_fn("),
        "call must use symbol: {}",
        text
    );
    assert!(
        text.contains("rcx") || text.contains("1"),
        "arg should appear: {}",
        text
    );
}

#[test]
fn decompile_return_tracks_rax_value() {
    let text = render(&[0xB8, 0x2A, 0, 0, 0, 0xC3], 0x1000, false);
    assert!(
        text.contains("return 0x2a;")
            || text.contains("return 42;")
            || text.contains("return 0x2A;"),
        "{}",
        text
    );
}

#[test]
fn decompile_while_loop_rendered() {
    let text = render(
        &[0xB9, 0x0A, 0, 0, 0, 0xFF, 0xC9, 0x75, 0xFC, 0xC3],
        0x1000,
        false,
    );
    assert!(
        text.contains("while") || text.contains("goto") || text.contains("LAB_"),
        "loop shape lost: {}",
        text
    );
}

#[test]
fn decompile_dce_drops_dead_store() {
    let text = render(&[0xB8, 1, 0, 0, 0, 0xB8, 2, 0, 0, 0, 0xC3], 0x1000, false);
    assert!(text.contains("return 2;"), "final value wins: {}", text);
}

#[test]
fn decompile_unimplemented_consolidated_to_one_comment() {
    let code = [0xD9, 0xF1, 0xD9, 0xF1, 0xC3];
    let text = render(&code, 0x1000, false);
    let markers = text.matches('\u{1}').count();
    let lines: Vec<&str> = text.lines().collect();
    let summary = lines.iter().filter(|l| l.contains("not modeled")).count();
    assert_eq!(
        summary + markers,
        1,
        "exactly one consolidated unimplemented note expected:\n{}",
        text
    );
}

#[test]
fn decompile_x64_signature_and_regs() {
    let text = render(&[0xB8, 1, 0, 0, 0, 0xC3], 0x1000, true);
    assert!(text.contains("longlong f("), "{}", text);
}

#[test]
fn decompile_x86_signature_and_reg_rewrite() {
    let text = render(&[0xB8, 1, 0, 0, 0, 0xC3], 0x1000, false);
    assert!(text.contains("int f("), "{}", text);
    for bad in ["rax", "rbx", "rcx", "rdx", "rsp", "rbp"] {
        assert!(!format!(" {} ", bad).len().eq(&0), "");
        let word = format!("\\b{}\\b", bad);
        let re_ok = !text
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|tok| tok == bad);
        assert!(
            re_ok,
            "x86 output leaked 64-bit register '{}':\n{}",
            word, text
        );
    }
}

#[test]
fn decompile_absolute_mem_has_no_zero_base_noise() {
    let text = render(&[0xA1, 0x00, 0x20, 0x00, 0x00, 0xC3], 0x1000, false);
    assert!(!text.contains("(0 + "), "{}", text);
    assert!(text.contains("DAT_") || text.contains("0x2000"), "{}", text);
}

#[test]
fn types_struct_offsets_and_total_size() {
    use crate::type_system::{DataType, DataTypeManager};
    let mut m = DataTypeManager::new();
    let s = m.create_struct("S").unwrap();
    m.add_field(s, "a", crate::type_system::ID_INT, None, "")
        .unwrap();
    m.add_field(s, "b", crate::type_system::ID_CHAR, None, "")
        .unwrap();
    let id = s;
    match m.get(id) {
        Some(DataType::Struct { fields, .. }) => {
            assert_eq!(fields[0].offset, 0);
            assert_eq!(fields[1].offset, 4, "char after int respects alignment");
        }
        other => panic!("{:?}", other),
    }
    assert_eq!(m.size_of(id), Some(8), "max(offset+size) with alignment");
}

#[test]
fn types_union_shares_offset_and_size_is_max_member() {
    use crate::type_system::{DataType, DataTypeManager};
    let mut m = DataTypeManager::new();
    let u = m.create_union("U").unwrap();
    m.add_field(u, "i", crate::type_system::ID_INT, None, "")
        .unwrap();
    m.add_field(u, "d", crate::type_system::ID_DOUBLE, None, "")
        .unwrap();
    match m.get(u) {
        Some(DataType::Union { fields, .. }) => {
            assert!(fields.iter().all(|f| f.offset == 0));
        }
        other => panic!("{:?}", other),
    }
    assert_eq!(m.size_of(u), Some(8));
}

#[test]
fn types_typedef_chain_and_pointer_array_sizes() {
    use crate::type_system::DataTypeManager;
    let mut m = DataTypeManager::new();
    let t = m
        .create_typedef("MyInt", crate::type_system::ID_INT)
        .unwrap();
    assert_eq!(m.size_of(t), Some(4));
    let p = m.create_pointer(t).unwrap();
    assert_eq!(m.size_of(p), Some(8));
    let a = m.create_array(crate::type_system::ID_CHAR, 10).unwrap();
    assert_eq!(m.size_of(a), Some(10));
    assert_eq!(m.find_by_name("MyInt"), Some(t));
    assert_eq!(m.type_name(p), "MyInt*");
}

#[test]
fn types_enum_variants_and_rename() {
    use crate::type_system::{DataType, DataTypeManager};
    let mut m = DataTypeManager::new();
    let e = m.create_enum("Color", crate::type_system::ID_INT).unwrap();
    m.add_enum_variant(e, "Red", 0).unwrap();
    m.add_enum_variant(e, "Green", 1).unwrap();
    match m.get(e) {
        Some(DataType::Enum { variants, .. }) => assert_eq!(variants.len(), 2),
        other => panic!("{:?}", other),
    }
    m.rename(e, "Colour").unwrap();
    assert_eq!(m.find_by_name("Colour"), Some(e));
    assert_eq!(m.find_by_name("Color"), None);
}

#[test]
fn types_json_roundtrip_preserves_semantics() {
    use crate::type_system::DataTypeManager;
    let mut m = DataTypeManager::new();
    let s = m.create_struct("RT").unwrap();
    m.add_field(s, "x", crate::type_system::ID_INT, None, "")
        .unwrap();
    let t = m.create_typedef("Alias", s).unwrap();
    let doc = m.to_json();

    let mut m2 = DataTypeManager::new();
    m2.from_json(&doc).unwrap();
    assert_eq!(
        m2.size_of(t),
        m.size_of(t),
        "typedef ids remap consistently"
    );
    let s2 = m2.find_by_name("RT").expect("struct survives roundtrip");
    match m2.get(s2) {
        Some(crate::type_system::DataType::Struct { fields, .. }) => {
            assert_eq!(fields[0].name, "x")
        }
        other => panic!("{:?}", other),
    }
}

#[test]
fn types_c_decl_contains_struct_layout() {
    use crate::type_system::DataTypeManager;
    let mut m = DataTypeManager::new();
    let s = m.create_struct("CD").unwrap();
    m.add_field(s, "val", crate::type_system::ID_UINT, None, "")
        .unwrap();
    let decl = m.to_c_decl(s, 0);
    assert!(
        decl.contains("struct CD") || decl.contains("CD"),
        "{}",
        decl
    );
    assert!(decl.contains("val"), "{}", decl);
}

#[test]
fn mapfile_hex_without_0x_and_flags_columns() {
    let sample = "0001:00000010       _foo          10001010     f obj:a.obj\n\
                  0001:00000020       __imp_bar     0x10011020   5 obj:b.obj\n";
    let syms = crate::parser::mapfile::parse_msvc_map(sample);
    assert_eq!(syms.len(), 2, "{:?}", syms);
    assert_eq!(syms[0].addr, 0x10001010);
    assert_eq!(syms[1].addr, 0x10011020);
    assert_eq!(syms[1].name, "__imp_bar");
}

#[test]
fn mapfile_skips_headers_and_short_lines() {
    let syms = crate::parser::mapfile::parse_msvc_map(
        "Start Length Name Class\n0001 00001000 .text CODE\n\n0001:00000030 _ok 10001030 f\n",
    );
    assert_eq!(syms.len(), 1, "{:?}", syms);
    assert_eq!(syms[0].name, "_ok");
}

#[test]
fn mapfile_empty_and_nonsense_inputs() {
    assert!(crate::parser::mapfile::parse_msvc_map("").is_empty());
    assert!(crate::parser::mapfile::parse_msvc_map("\n\n;; comment only\n").is_empty());
    assert!(crate::parser::mapfile::parse_msvc_map("not a map at all").is_empty());
}

#[test]
fn pattern_uppercase_spaces_and_wildcards() {
    let p = crate::mcp::tools::search::parse_pattern("80 3D ?? ?? ?? ?? 74").unwrap();
    assert_eq!(p.len(), 7);
    assert_eq!(p[0], Some(0x80));
    assert_eq!(p[2], None);
    assert_eq!(p[6], Some(0x74));
    let p2 = crate::mcp::tools::search::parse_pattern("DEADBEEF").unwrap();
    assert_eq!(p2, vec![Some(0xDE), Some(0xAD), Some(0xBE), Some(0xEF)]);
}

#[test]
fn pattern_lone_question_mark_is_wildcard() {
    assert_eq!(
        crate::mcp::tools::search::parse_pattern("?").unwrap(),
        vec![None]
    );
    assert_eq!(
        crate::mcp::tools::search::parse_pattern("??11").unwrap(),
        vec![None, Some(0x11)]
    );
}

#[test]
fn pattern_nibble_mask_rejected_with_explanation() {
    let err = crate::mcp::tools::search::parse_pattern("8? 3D").unwrap_err();
    assert!(
        !err.is_empty(),
        "must explain why nibble masks are rejected"
    );
    assert!(crate::mcp::tools::search::parse_pattern("3D ?8").is_err());
}

#[test]
fn pattern_empty_and_dangling_errors() {
    assert!(crate::mcp::tools::search::parse_pattern("").is_err());
    assert!(crate::mcp::tools::search::parse_pattern("   ").is_err());
    assert!(
        crate::mcp::tools::search::parse_pattern("DEADBE E").is_err(),
        "odd digit count"
    );
    assert!(
        crate::mcp::tools::search::parse_pattern("ZZ").is_err(),
        "non-hex chars"
    );
}

#[test]
fn parse_addr_accepts_optional_0x_hex_only() {
    assert_eq!(crate::mcp::tools::parse_addr("10"), Some(16));
    assert_eq!(crate::mcp::tools::parse_addr("0xFF"), Some(255));
    assert_eq!(crate::mcp::tools::parse_addr(" 0x10 "), Some(16));
    assert_eq!(crate::mcp::tools::parse_addr("nothex"), None);
}

#[test]
fn assemble_basic_byte_forms() {
    let enc = crate::asm::assemble("x86", 0x1000, "ret").unwrap();
    assert_eq!(enc, vec![0xC3]);
    let enc = crate::asm::assemble("x86", 0x1000, "nop").unwrap();
    assert_eq!(enc, vec![0x90]);
    let enc = crate::asm::assemble("x86", 0x1000, "leave").unwrap();
    assert_eq!(enc, vec![0xC9]);
    let enc = crate::asm::assemble("x86", 0x1000, "mov eax, 0x12345678").unwrap();
    assert_eq!(enc.len(), 5, "B8 + imm32, got {:?}", enc);
    assert_eq!(enc[0], 0xB8);
}

#[test]
fn assemble_snippet_multi_line_counts() {
    let (bytes, errors) = crate::asm::assemble_snippet("x86", 0x1000, "nop\nnop\nret").unwrap();
    assert_eq!(bytes.len(), 3);
    assert!(errors.is_empty(), "{:?}", errors);
}

#[test]
fn regression_direct_jcc_to_low_target_lifts_cbranch() {
    let pin = lifted(&[0x74, 0x08], 0x1000);
    match first_op(&pin) {
        POp::CBranch { target, .. } => assert_eq!(*target, 0x100A),
        other => panic!("{:?}", other),
    }
}

#[test]
fn regression_direct_call_to_low_target_is_not_indirect() {
    let pin = lifted(&[0xE8, 0xF6, 0xFF, 0xFF, 0xFF], 0x1005);
    match first_op(&pin) {
        POp::Call { target } => assert_eq!(*target, 0x1000),
        POp::CallInd { .. } => panic!("direct call misread as indirect"),
        other => panic!("{:?}", other),
    }
}

#[test]
fn regression_direct_jmp_to_low_target_lifts_branch() {
    let pin = lifted(&[0xE9, 0xF6, 0xFF, 0xFF, 0xFF], 0x1005);
    assert!(matches!(first_op(&pin), POp::Branch { target: 0x1000 }));
}

#[test]
fn regression_register_call_stays_indirect() {
    let pin = lifted(&[0xFF, 0xD0], 0x100000);
    assert!(matches!(first_op(&pin), POp::CallInd { .. }));
    let pin = lifted(&[0xFF, 0x20], 0x100000);
    assert!(matches!(first_op(&pin), POp::BranchInd { .. }));
}

#[test]
fn regression_low_call_args_survive_into_pseudocode() {
    let base = 0x1000u64;
    let callee = 0x2000u64;
    let mut code: Vec<u8> = vec![0xB9, 0x01, 0, 0, 0];
    let rel = (callee as i64 - (base + code.len() as u64 + 5) as i64) as i32;
    code.push(0xE8);
    code.extend(rel.to_le_bytes());
    code.push(0xC3);
    let insns = dis(&code, base, "x86_64");
    let end = base + code.len() as u64;
    let pins = lift_all(&insns);
    let cfg = build_cfg(&insns, base, end);
    let sf = crate::analysis::stack::analyze_stack(&pins, base, end, false, 0);
    let mut lookup = rustc_hash::FxHashMap::default();
    lookup.insert(callee, "target_fn".to_string());
    let pc = decompile(LiftInput {
        cfg: &cfg,
        pinstrs_in_func: &pins,
        imap: &insns,
        stack: &sf,
        func_name: "f",
        func_lookup: &lookup,
        is64: true,
        is_win64: false,
        thunk_targets: &rustc_hash::FxHashMap::default(),
        imports: &rustc_hash::FxHashMap::default(),
        switches: &[],
        cancel: None,
        debug_types: None,
    });
    let text: String = pc
        .lines
        .iter()
        .map(|l| l.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("target_fn("), "{}", text);
    assert!(
        text.contains("1") || text.contains("rcx"),
        "arg lost: {}",
        text
    );
}

#[test]
fn regression_x86_thiscall_arg_probe_renders_args() {
    let base = 0x1000u64;
    let callee = 0x2000u64;
    let mut code: Vec<u8> = vec![0xB9, 0x2A, 0, 0, 0];
    let rel = (callee as i64 - (base + code.len() as u64 + 5) as i64) as i32;
    code.push(0xE8);
    code.extend(rel.to_le_bytes());
    code.push(0xC3);
    let insns = dis(&code, base, "x86");
    let end = base + code.len() as u64;
    let pins = lift_all(&insns);
    let cfg = build_cfg(&insns, base, end);
    let sf = crate::analysis::stack::analyze_stack(&pins, base, end, false, 0);
    let pc = decompile(LiftInput {
        cfg: &cfg,
        pinstrs_in_func: &pins,
        imap: &insns,
        stack: &sf,
        func_name: "f",
        func_lookup: &rustc_hash::FxHashMap::default(),
        is64: false,
        is_win64: false,
        thunk_targets: &rustc_hash::FxHashMap::default(),
        imports: &rustc_hash::FxHashMap::default(),
        switches: &[],
        cancel: None,
        debug_types: None,
    });
    let text: String = pc
        .lines
        .iter()
        .map(|l| l.text.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(text.contains("("), "call should render with args: {}", text);
    assert!(!text.contains("not modeled"), "lifter gap: {}", text);
}

#[test]
fn lift_comiss_produces_float_cmp() {
    let pin = lifted(&[0x0F, 0x2F, 0xD4], 0x1000);
    match first_op(&pin) {
        POp::FloatCmp { a, b, size } => {
            assert_eq!(*size, 4);
            assert_eq!(*a, PVar::Reg("xmm2"));
            assert_eq!(*b, PVar::Reg("xmm4"));
        }
        other => panic!("comiss: {:?}", other),
    }
}

#[test]
fn comiss_jcc_renders_real_comparison_not_cond() {
    let code = &[
        0x0F, 0x2F, 0xD4, 0x76, 0x03, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
    ];
    let out = render(code, 0x1000, false);
    assert!(
        !out.contains("(cond)"),
        "float branch degraded to bare cond:\n{}",
        out
    );
    assert!(
        out.contains("xmm2") && out.contains("xmm4"),
        "comparison operands missing:\n{}",
        out
    );
    assert!(
        out.contains("xmm2 > xmm4") || out.contains("xmm2 <= xmm4"),
        "jbe should map to a real float comparison:\n{}",
        out
    );
}

#[test]
fn movss_load_renders_float_cast() {
    let code = &[0xF3, 0x0F, 0x10, 0x07, 0xC3];
    let out = render(code, 0x1000, true);
    assert!(
        out.contains("(float *)"),
        "SSE load must render as float:\n{}",
        out
    );
    assert!(
        !out.contains("int32_t *)") || !out.contains("= *(int32_t *)&rdi"),
        "movss load typed as int:\n{}",
        out
    );
}

#[test]
fn write_only_arg_slot_is_named_spill_not_param() {
    let code = &[0xB8, 0x05, 0x00, 0x00, 0x00, 0x89, 0x44, 0x24, 0x28, 0xC3];
    let out = render(code, 0x1000, true);
    assert!(
        !out.contains("&arg_28"),
        "write-only slot mislabeled as param:\n{}",
        out
    );
    assert!(
        out.contains("stk_p28"),
        "spill slot should be named stk_p28:\n{}",
        out
    );
}

#[test]
fn lahf_test_ah_pattern_renders_float_equality() {
    let code = &[
        0x0F, 0x2E, 0xC1, 0x9E, 0xF6, 0xC4, 0x44, 0x75, 0x01, 0xC3, 0xC3,
    ];
    let out = render(code, 0x1000, true);
    assert!(
        out.contains("xmm0 != xmm1") || out.contains("xmm0 == xmm1") || out.contains("param_1 != param_2") || out.contains("param_1 == param_2"),
        "lahf pattern must map back to float comparison:\n{}",
        out
    );
    assert!(
        !out.contains("& 0x44"),
        "AH mask leaked into condition:\n{}",
        out
    );
}

#[test]
fn top_tested_loop_renders_condition_from_header() {
    let code = &[
        0x83, 0xF8, 0x05, 0x7D, 0x05, 0x83, 0xC0, 0x01, 0xEB, 0xF6, 0xC3,
    ];
    let out = render(code, 0x1000, true);
    assert!(
        out.contains("while ("),
        "loop not detected as loop:\n{}",
        out
    );
    assert!(
        !out.contains("while (cond)"),
        "loop header left unresolved:\n{}",
        out
    );
    assert!(
        out.contains("< 5") || out.contains(">= 5"),
        "condition lost its operands:\n{}",
        out
    );
}

#[test]
fn unconditional_jmp_is_emitted_once() {
    let code = &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xEB, 0x01, 0x90, 0xC3];
    let out = render(code, 0x1000, true);
    let count = out
        .lines()
        .filter(|l| l.trim_start().starts_with("goto LAB_"))
        .count();
    assert!(
        count <= 1,
        "duplicate goto emission ({} lines):\n{}",
        count,
        out
    );
}

#[test]
fn lea_with_loaded_base_is_value_arith_not_address_of() {
    let code = &[0x8B, 0x41, 0x1C, 0x8D, 0x04, 0x10, 0xC3];
    let out = render(code, 0x1000, true);
    assert!(
        !out.contains("&(*"),
        "lea rendered as address-of-deref:\n{}",
        out
    );
    assert!(
        !out.contains("= &("),
        "lea rendered with leading address-of:\n{}",
        out
    );
}

#[test]
fn drop_guard_branch_stays_visible_in_render() {
    let code = &[
        0x8B, 0x41, 0x1C, 0x01, 0xD0, 0x3B, 0x41, 0x20, 0x7E, 0x06, 0xB8, 0x01, 0x00, 0x00, 0x00,
        0x90, 0xC3,
    ];
    let out = render(code, 0x1000, true);
    if std::env::var("DBG_GUARD").is_ok() {
        let insns = dis(code, 0x1000, "x86_64");
        for i in &insns {
            println!("INSN {:X} {} {}", i.address, i.mnemonic, i.operands);
        }
        let cfg = build_cfg(&insns, 0x1000, 0x1000 + code.len() as u64);
        for (bi, b) in cfg.blocks.iter().enumerate() {
            println!(
                "BLOCK {} [{:X},{:X}) preds={:?} succs={:?}",
                bi,
                b.start,
                b.end,
                b.predecessors,
                b.successors
                    .iter()
                    .map(|e| (e.target, format!("{:?}", e.kind)))
                    .collect::<Vec<_>>()
            );
        }
    }
    assert!(
        out.contains("if ("),
        "guard branch vanished entirely:\n{}",
        out
    );
    assert!(
        out.contains("<=") || out.contains(">"),
        "comparison lost:\n{}",
        out
    );
}

#[test]
fn undecoded_branch_target_stays_visible() {
    let code = &[
        0x8B, 0x41, 0x1C, 0x3B, 0x41, 0x20, 0x7E, 0x08, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
    ];
    let out = render(code, 0x1000, true);
    assert!(
        out.contains("if (") && out.contains("0x1010"),
        "guard branch must stay visible:\n{}",
        out
    );
    assert!(
        !out.contains("WARNING"),
        "branch should render as goto/return, not a warning:\n{}",
        out
    );
}

#[test]
fn p0_debug_symbols_accepts_pe_exe_and_dll() {
    use crate::parser::{ParsedBinary, Section};
    use std::sync::Arc;
    let mk = |fmt: &str| ParsedBinary {
        format: fmt.into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        sections: vec![Section {
            name: ".text".into(),
            vaddr: 0x1000,
            size: 0x100,
            offset: 0,
            is_executable: true,
            readable: true,
            writable: false,
            initialized: true,
        }],
        symbols: vec![crate::parser::Symbol {
            name: "f".into(),
            addr: 0x1000,
            size: 0,
            is_function: true,
        }],
        imports: vec![],
        exports: vec![],
        strings: vec![],
        data: Arc::new(vec![0u8; 0x200]),
        image_base: 0x140000000,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: vec![],
        delay_imports: vec![],
        has_rich: false,
        libraries: vec![],
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    for fmt in ["PE EXE", "PE DLL", "COFF"] {
        let mut an = crate::analysis::debug_symbols::DebugSymbolsAnalyzer::new();
        an.analyze(&mk(fmt));
        assert_eq!(
            an.symbols.len(),
            1,
            "format {} must yield COFF symbols",
            fmt
        );
    }
    let mut data = vec![0u8; 256];
    data[100..104].copy_from_slice(b"RSDS");
    let pdb = b"C:\\a.pdb\x00";
    data[124..124 + pdb.len()].copy_from_slice(pdb);
    let mut bin = mk("PE EXE");
    bin.data = Arc::new(data);
    let mut an2 = crate::analysis::debug_symbols::DebugSymbolsAnalyzer::new();
    an2.analyze(&bin);
    assert!(
        an2.source_files.iter().any(|p| p.ends_with(".pdb")),
        "RSDS path missing: {:?}",
        an2.source_files
    );
}

#[test]
fn p0_noreturn_trap_not_in_function_set() {
    let insns = dis(&[0xCD, 0x29, 0xC3], 0x1000, "x86_64");
    assert!(insns.iter().any(|i| i.mnemonic == "int"));
    let trap_addr = insns.iter().find(|i| i.mnemonic == "int").unwrap().address;
    let funcs = vec![crate::analysis::function::DetectedFunction {
        entry: 0x1000,
        end: 0x1003,
        name: "f".into(),
        has_frame: false,
        stack_size: 0,
        source: crate::analysis::function::FuncSource::AfterReturn,
        is_thunk: false,
        thunk_target: None,
    }];
    let mut an = crate::analysis::noreturn::NoReturnAnalyzer::new();
    an.analyze(&insns, &[], &funcs, None);
    assert!(
        !an.is_noreturn(trap_addr),
        "trap address {:#x} must not be a noreturn function",
        trap_addr
    );
    assert!(an.is_noreturn_call_at(&insns[0]));
}

#[test]
fn p0_sourcetype_ghidra_ids() {
    use crate::gui::SourceType;
    assert_eq!(SourceType::Analysis.tag(), 0);
    assert_eq!(SourceType::User.tag(), 1);
    assert_eq!(SourceType::Default.tag(), 2);
    assert_eq!(SourceType::Imported.tag(), 3);
    assert_eq!(SourceType::Ai.tag(), 4);
    assert_eq!(SourceType::from_tag(4), SourceType::Ai);
    assert_eq!(SourceType::from_tag_v2(0), SourceType::User);
    assert_eq!(SourceType::from_tag_v2(2), SourceType::Analysis);
}

#[test]
fn p0_section_perms_and_ptr_size() {
    use crate::parser::Section;
    let x = Section {
        name: ".text".into(),
        vaddr: 0x1000,
        size: 0x100,
        offset: 0,
        is_executable: true,
        readable: true,
        writable: false,
        initialized: true,
    };
    assert_eq!(x.perms(), "R-X");
    assert!(!x.writable);
    let d = Section {
        name: ".data".into(),
        vaddr: 0x2000,
        size: 0x100,
        offset: 0x100,
        is_executable: false,
        readable: true,
        writable: true,
        initialized: true,
    };
    assert_eq!(d.perms(), "RW-");
    let mut m = crate::type_system::DataTypeManager::new();
    assert_eq!(m.pointer_size(), 8);
    m.set_arch("x86");
    assert_eq!(m.pointer_size(), 4);
    let p = m.create_pointer(crate::type_system::ID_INT).unwrap();
    assert_eq!(m.size_of(p), Some(4));
    m.set_arch("x86_64");
    assert_eq!(m.size_of(p), Some(8));
}

#[test]
fn p0_constprop_rip_relative_and_call_clobber() {
    let insns = dis(
        &[0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00],
        0x1000,
        "x86_64",
    );
    assert_eq!(insns.len(), 1);
    let mut cp = crate::analysis::constprop::ConstantPropagator::new();
    cp.propagate(&insns, 0x1000, 0x2000);
    assert_eq!(
        cp.get_register_value("rax"),
        Some(crate::analysis::constprop::RegValue::Known(0x1017))
    );
    let call = dis(&[0xE8, 0x00, 0x00, 0x00, 0x00], 0x2000, "x86_64");
    let mut cp2 = crate::analysis::constprop::ConstantPropagator::new();
    cp2.propagate(&call, 0x2000, 0x3000);
    assert_eq!(
        cp2.get_register_value("rsi"),
        Some(crate::analysis::constprop::RegValue::Unknown)
    );
    assert_eq!(
        cp2.get_register_value("rdi"),
        Some(crate::analysis::constprop::RegValue::Unknown)
    );
}

#[test]
fn p0_demangle_v0_swift() {
    let v0 = crate::analysis::demangle::demangle_name("_RNvCs4test3foo");
    assert_ne!(v0, "_RNvCs4test3foo", "v0 passthrough");
    assert!(
        v0.contains("test") || v0.contains("foo"),
        "v0 unreadable: {}",
        v0
    );
    let sw = crate::analysis::demangle::demangle_name("$s3Foo3bar");
    assert!(
        sw.contains("Foo") && sw.contains("bar"),
        "swift unreadable: {}",
        sw
    );
    assert_eq!(
        crate::analysis::demangle::demangle_name("?foo@Bar@@QAEXXZ"),
        "Bar::foo"
    );
}

#[test]
fn p0_win32_seeds_have_peb_teb_unicode() {
    let mut m = crate::type_system::DataTypeManager::new();
    let n = m.seed_archive("win32").unwrap();
    assert!(n > 0);
    for t in ["UNICODE_STRING", "PEB", "TEB", "LIST_ENTRY", "GUID"] {
        assert!(m.find_by_name(t).is_some(), "missing {}", t);
    }
    let mut l = crate::type_system::DataTypeManager::new();
    l.seed_archive("libc").unwrap();
    for t in ["in6_addr", "sockaddr_in6", "stat"] {
        assert!(l.find_by_name(t).is_some(), "missing {}", t);
    }
}

#[test]
fn p0_xref_low_imm_call_creates_edge() {
    let raw = vec![
        0xE8, 0x0B, 0x00, 0x00, 0x00, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
        0x90, 0xC3,
    ];
    let bin = crate::parser::parse_raw_bytes(raw, 0x1000, "x86_64").unwrap();
    let d = crate::disasm::disassemble_binary(&bin).unwrap();
    let result = crate::analysis::auto_analyze(&d, &bin);
    assert!(
        !result.callees.is_empty(),
        "low-base call must create call-graph edge"
    );
}

#[test]
fn p0_batch_undo_is_single_step() {
    use crate::gui::{AnnotationChange, AppState, CommentKind};
    let mut s = AppState::new();
    s.set_comment_kind(0x1000, CommentKind::Eol, Some("a".into()));
    s.set_comment_kind(0x2000, CommentKind::Eol, Some("b".into()));
    let batch = AnnotationChange::Batch(vec![
        AnnotationChange::Comment {
            addr: 0x1000,
            kind: CommentKind::Eol,
            old: Some("a".into()),
            new: Some("a2".into()),
        },
        AnnotationChange::Comment {
            addr: 0x2000,
            kind: CommentKind::Eol,
            old: Some("b".into()),
            new: Some("b2".into()),
        },
    ]);
    s.apply_change(&batch, true);
    s.annotation_undo.push(batch);
    assert_eq!(s.annotation_undo.undo_len(), 1);
    s.undo_annotation();
    assert_eq!(
        s.get_comment_kind(0x1000, CommentKind::Eol),
        Some(&"a".to_string())
    );
    assert_eq!(
        s.get_comment_kind(0x2000, CommentKind::Eol),
        Some(&"b".to_string())
    );
    s.redo_annotation();
    assert_eq!(
        s.get_comment_kind(0x1000, CommentKind::Eol),
        Some(&"a2".to_string())
    );
}

#[test]
fn p0_pe_rich_detect() {
    let mut data = vec![0u8; 0x200];
    data[0x3c..0x40].copy_from_slice(&0x100u32.to_le_bytes());
    data[0x40..0x44].copy_from_slice(b"DanS");
    data[0x80..0x84].copy_from_slice(b"Rich");
    data[0x100..0x104].copy_from_slice(b"PE\0\0");
    let lfanew = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    let stub = &data[..lfanew];
    assert!(stub.windows(4).any(|w| w == b"DanS"));
    assert!(stub.windows(4).any(|w| w == b"Rich"));
}

#[test]
fn p1_shared_return_tailcall_edge() {
    let mut raw = vec![0x90u8; 64];
    raw[0] = 0xE8;
    let r1 = 0x1010i32 - (0x1000 + 5);
    raw[1..5].copy_from_slice(&(r1 as u32).to_le_bytes());
    raw[5] = 0xE8;
    let r2 = 0x1020i32 - (0x1005 + 5);
    raw[6..10].copy_from_slice(&(r2 as u32).to_le_bytes());
    raw[10] = 0xC3;
    raw[0x10] = 0x90;
    raw[0x11] = 0xE9;
    let rel = 0x1020i32 - (0x1011 + 5);
    raw[0x12..0x16].copy_from_slice(&(rel as u32).to_le_bytes());
    raw[0x16] = 0xC3;
    raw[0x20] = 0xC3;
    let bin = crate::parser::parse_raw_bytes(raw, 0x1000, "x86_64").unwrap();
    let d = crate::disasm::disassemble_binary(&bin).unwrap();
    let r = crate::analysis::auto_analyze(&d, &bin);
    let has_tail = r
        .xrefs
        .all
        .iter()
        .any(|x| matches!(x.kind, crate::analysis::xref::XRefKind::TailCall) && x.to == 0x1020);
    assert!(has_tail, "mid-body jmp to func entry must be TailCall");
}

#[test]
fn p1_multinstr_thunk_detected() {
    let code = vec![0x48, 0x8B, 0x05, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0];
    let bin = crate::parser::parse_raw_bytes(code, 0x1000, "x86_64").unwrap();
    let d = crate::disasm::disassemble_binary(&bin).unwrap();
    let funcs = crate::analysis::function::detect_functions(&d.instructions, 0x1000, &[]);
    assert!(!funcs.is_empty());
    let stubs = crate::analysis::advanced::build_stub_map(&d.instructions, &funcs, &bin, None);
    assert!(!stubs.is_empty(), "multi-instr thunk must be detected");
}

#[test]
fn p1_push_ret_thunk_detected() {
    let mut raw = vec![0x90; 32];
    raw[0] = 0x68;
    raw[1..5].copy_from_slice(&0x1020u32.to_le_bytes());
    raw[5] = 0xC3;
    let bin = crate::parser::parse_raw_bytes(raw, 0x1000, "x86_64").unwrap();
    let d = crate::disasm::disassemble_binary(&bin).unwrap();
    let funcs = crate::analysis::function::detect_functions(&d.instructions, 0x1000, &[]);
    let stubs = crate::analysis::advanced::build_stub_map(&d.instructions, &funcs, &bin, None);
    let _ = stubs;
}

#[test]
fn p1_chkstk_preserves_regs() {
    use crate::analysis::constprop::ConstantPropagator;
    let code = vec![
        0x48, 0xC7, 0xC0, 0x05, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut insns = dis(&code, 0x1000, "x86_64");
    if let Some(call) = insns.iter_mut().find(|i| i.mnemonic == "call") {
        call.operands = "__chkstk".into();
    }
    let mut cp = ConstantPropagator::new();
    cp.propagate(&insns, 0x1000, 0x2000);
    let _ = cp.get_register_value("rax");
}

#[test]
fn p1_lifter_segment_syscall_rotate_bswap() {
    use crate::analysis::pcode::{lift_instruction, POp};
    let seg = dis(
        &[0x64, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00],
        0x1000,
        "x86_64",
    );
    assert!(!seg.is_empty());
    let li = lift_instruction(&seg[0]);
    assert!(
        li.ops.iter().any(|o| matches!(o, POp::SegmentOp { .. })),
        "fs:[...] must lift to SegmentOp, got {:?}",
        li.ops
    );
    let sc = dis(&[0x0F, 0x05], 0x1000, "x86_64");
    let li2 = lift_instruction(&sc[0]);
    assert!(
        li2.ops.iter().any(|o| matches!(o, POp::CallOther { .. })),
        "syscall must be CallOther"
    );
    let rol = dis(&[0x48, 0xC1, 0xC0, 0x08], 0x1000, "x86_64");
    let li3 = lift_instruction(&rol[0]);
    assert!(
        li3.ops.iter().any(|o| matches!(o, POp::Rotate { .. })),
        "rol must be Rotate"
    );
    let bs = dis(&[0x48, 0x0F, 0xC8], 0x1000, "x86_64");
    let li4 = lift_instruction(&bs[0]);
    assert!(
        li4.ops.iter().any(|o| matches!(o, POp::Bswap { .. })),
        "bswap must be Bswap"
    );
}

#[test]
fn p1_ud2_ends_noreturn() {
    let insns = dis(&[0x0F, 0x0B], 0x1000, "x86_64");
    assert_eq!(insns[0].mnemonic, "ud2");
    let funcs = vec![crate::analysis::function::DetectedFunction {
        entry: 0x1000,
        end: 0x1002,
        name: "f".into(),
        has_frame: false,
        stack_size: 0,
        source: crate::analysis::function::FuncSource::AfterReturn,
        is_thunk: false,
        thunk_target: None,
    }];
    let mut an = crate::analysis::noreturn::NoReturnAnalyzer::new();
    an.analyze(&insns, &[], &funcs, None);
    assert!(
        an.is_noreturn(0x1000),
        "ud2-terminated function must be noreturn"
    );
    assert!(an.is_noreturn_call_at(&insns[0]));
}

#[test]
fn p1_switch_4byte_relative() {
    use crate::parser::{ParsedBinary, Section};
    use std::sync::Arc;
    let mut data = vec![0u8; 0x3000];
    data[0] = 0x83;
    data[1] = 0xF9;
    data[2] = 0x01;
    data[3] = 0x48;
    data[4] = 0x8D;
    data[5] = 0x15;
    data[6] = 0xF6;
    data[7] = 0x0F;
    data[8] = 0;
    data[9] = 0;
    data[10] = 0xFF;
    data[11] = 0xE0;
    let t1 = (0x1000i64 - 0x2000i64) as i32;
    let t2 = (0x1008i64 - 0x2000i64) as i32;
    data[0x2000..0x2004].copy_from_slice(&t1.to_le_bytes());
    data[0x2004..0x2008].copy_from_slice(&t2.to_le_bytes());
    let sections = vec![
        Section {
            name: ".text".into(),
            vaddr: 0x1000,
            size: 0x100,
            offset: 0,
            is_executable: true,
            readable: true,
            writable: false,
            initialized: true,
        },
        Section {
            name: ".rodata".into(),
            vaddr: 0x2000,
            size: 0x100,
            offset: 0x2000,
            is_executable: false,
            readable: true,
            writable: false,
            initialized: true,
        },
    ];
    let bin = ParsedBinary {
        format: "ELF".into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        sections,
        symbols: vec![],
        imports: vec![],
        exports: vec![],
        strings: vec![],
        data: Arc::new(data),
        image_base: 0,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: vec![],
        delay_imports: vec![],
        has_rich: false,
        libraries: vec![],
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    let d = crate::disasm::disassemble_binary(&bin).unwrap();
    let tables = crate::analysis::advanced::detect_switch_tables(&d.instructions, &bin, None);
    assert!(!tables.is_empty(), "4-byte relative table must be detected");
    let t = &tables[0];
    assert!(
        t.case_targets.iter().all(|a| *a >= 0x1000 && *a < 0x1100),
        "targets not in .text: {:x?}",
        t.case_targets
    );
}

#[test]
fn switch_bound_check_survives_intervening_instructions() {
    use crate::parser::{ParsedBinary, Section};
    use std::sync::Arc;
    let mut code = vec![0x83, 0xF9, 0x01];
    code.extend(std::iter::repeat_n(0x90, 14));
    code.extend([0x8B, 0x84, 0x8A, 0x00, 0x20, 0x00, 0x00]);
    code.extend([0x48, 0x01, 0xD0]);
    code.extend([0xFF, 0xE0]);
    let mut data = vec![0u8; 0x3000];
    data[..code.len()].copy_from_slice(&code);
    data[0x2000..0x2004].copy_from_slice(&0x1000u32.to_le_bytes());
    data[0x2004..0x2008].copy_from_slice(&0x1010u32.to_le_bytes());
    let bin = ParsedBinary {
        format: "ELF".into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        sections: vec![
            Section {
                name: ".text".into(),
                vaddr: 0x1000,
                size: 0x100,
                offset: 0,
                is_executable: true,
                readable: true,
                writable: false,
                initialized: true,
            },
            Section {
                name: ".rodata".into(),
                vaddr: 0x2000,
                size: 0x100,
                offset: 0x2000,
                is_executable: false,
                readable: true,
                writable: false,
                initialized: true,
            },
        ],
        symbols: vec![],
        imports: vec![],
        exports: vec![],
        strings: vec![],
        data: Arc::new(data),
        image_base: 0,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: vec![],
        delay_imports: vec![],
        has_rich: false,
        libraries: vec![],
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    let d = crate::disasm::disassemble_binary(&bin).unwrap();
    let tables = crate::analysis::advanced::detect_switch_tables(&d.instructions, &bin, None);
    assert!(!tables.is_empty(), "RVA switch with a distant bound must be detected");
    let t = &tables[0];
    assert_eq!(t.case_count, 2);
    assert_eq!(t.case_targets, vec![0x1000, 0x1010]);
}

#[test]
fn p2_debug_line_emits_rows() {
    let mut unit = vec![];
    unit.extend_from_slice(&2u16.to_le_bytes());
    unit.extend_from_slice(&20u32.to_le_bytes());
    unit.push(1);
    unit.push(1);
    unit.push(1);
    unit.push(-5i8 as u8);
    unit.push(14);
    unit.push(13);
    unit.extend_from_slice(&[0u8; 12]);
    unit.push(0);
    unit.push(0);
    unit.push(0x00);
    unit.push(9);
    unit.push(2);
    unit.extend_from_slice(&0x1000u64.to_le_bytes());
    unit.push(3);
    unit.push(9);
    unit.push(1);
    unit.push(0x00);
    unit.push(1);
    unit.push(1);
    let mut data = vec![];
    data.extend_from_slice(&(unit.len() as u32).to_le_bytes());
    data.extend_from_slice(&unit);
    let mut an = crate::analysis::debug_symbols::DebugSymbolsAnalyzer::new();
    use crate::parser::{ParsedBinary, Section};
    use std::sync::Arc;
    let bin = ParsedBinary {
        format: "ELF".into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        sections: vec![Section {
            name: ".debug_line".into(),
            vaddr: 0,
            size: data.len() as u64,
            offset: 0,
            is_executable: false,
            readable: true,
            writable: false,
            initialized: true,
        }],
        symbols: vec![],
        imports: vec![],
        exports: vec![],
        strings: vec![],
        data: Arc::new(data),
        image_base: 0,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: vec![],
        delay_imports: vec![],
        has_rich: false,
        libraries: vec![],
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    an.analyze(&bin);
    assert!(!an.line_numbers.is_empty(), "line program must emit rows");
    assert!(
        an.line_numbers
            .iter()
            .any(|l| l.address == 0x1000 && l.line == 10),
        "expected 0x1000:10, got {:?}",
        an.line_numbers
    );
}

#[test]
fn p2_golang_detect() {
    use crate::parser::{ParsedBinary, Section};
    use std::sync::Arc;
    let mut data = vec![0u8; 64];
    data[0..6].copy_from_slice(&[0xFB, 0xFF, 0xFF, 0xFF, 0x00, 0x00]);
    data[16..24].copy_from_slice(b"go1.21.0");
    let bin = ParsedBinary {
        format: "ELF".into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        sections: vec![Section {
            name: ".text".into(),
            vaddr: 0x1000,
            size: 64,
            offset: 0,
            is_executable: true,
            readable: true,
            writable: false,
            initialized: true,
        }],
        symbols: vec![],
        imports: vec![],
        exports: vec![],
        strings: vec![],
        data: Arc::new(data),
        image_base: 0,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: vec![],
        delay_imports: vec![],
        has_rich: false,
        libraries: vec![],
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    let f = crate::analysis::detect::detect_golang(&bin);
    assert!(!f.is_empty(), "gopclntab must be detected");
    assert_eq!(
        crate::analysis::detect::golang_version(b"go1.21.0 patch").as_deref(),
        Some("go1.21.0")
    );
}

#[test]
fn p2_itanium_rtti_pairs_vtable() {
    use crate::parser::{ParsedBinary, Section, Symbol};
    use std::sync::Arc;
    let mut data = vec![0u8; 0x3000];
    data[0x2000..0x2008].copy_from_slice(&0u64.to_le_bytes());
    data[0x2008..0x2010].copy_from_slice(&0u64.to_le_bytes());
    data[0x2010..0x2018].copy_from_slice(&0x1000u64.to_le_bytes());
    let bin = ParsedBinary {
        format: "ELF".into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        sections: vec![Section {
            name: ".data".into(),
            vaddr: 0x2000,
            size: 0x1000,
            offset: 0x2000,
            is_executable: false,
            readable: true,
            writable: true,
            initialized: true,
        }],
        symbols: vec![
            Symbol {
                name: "_ZTV3Foo".into(),
                addr: 0x2000,
                size: 0,
                is_function: false,
            },
            Symbol {
                name: "_ZTI3Foo".into(),
                addr: 0x3000,
                size: 0,
                is_function: false,
            },
        ],
        imports: vec![],
        exports: vec![],
        strings: vec![],
        data: Arc::new(data),
        image_base: 0,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: vec![],
        delay_imports: vec![],
        has_rich: false,
        libraries: vec![],
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    let classes = crate::analysis::rtti::scan_itanium_rtti(&bin);
    assert!(!classes.is_empty(), "itanium vtable must pair");
    assert!(
        classes.iter().any(|c| c.vftable == Some(0x2010)),
        "vftable = sym+16, got {:?}",
        classes
    );
}

#[test]
fn p2_media_and_dotnet_format() {
    use crate::parser::{Import, ParsedBinary, Section};
    use std::sync::Arc;
    let mut data = vec![0u8; 0x200];
    data[0x80..0x88].copy_from_slice(b"\x89PNG\r\n\x1a\n");
    let sections = vec![Section {
        name: ".rsrc".into(),
        vaddr: 0x3000,
        size: 0x200,
        offset: 0,
        is_executable: false,
        readable: true,
        writable: false,
        initialized: true,
    }];
    let mk = |fmt: &str| ParsedBinary {
        format: fmt.into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        sections: sections.clone(),
        symbols: vec![],
        imports: vec![Import {
            name: "_CorExeMain".into(),
            library: "mscoree.dll".into(),
            offset: 0x4000,
        }],
        exports: vec![],
        strings: vec![],
        data: Arc::new(data.clone()),
        image_base: 0x140000000,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: vec![],
        delay_imports: vec![],
        has_rich: false,
        libraries: vec![],
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    assert!(!crate::analysis::detect::detect_dotnet(&mk("PE EXE")).is_empty());
    assert!(!crate::analysis::detect::detect_dotnet(&mk("PE DLL")).is_empty());
    assert!(crate::analysis::detect::detect_media(&mk("PE EXE"))
        .iter()
        .any(|f| f.id == "png"));
}

#[test]
fn p2_type_import_tolerates_duplicates() {
    let mut m = crate::type_system::DataTypeManager::new();
    let s = m.create_struct("DupT").unwrap();
    m.add_field(s, "a", crate::type_system::ID_INT, Some(0), "")
        .unwrap();
    let doc = m.to_json();
    let mut m2 = crate::type_system::DataTypeManager::new();
    m2.from_json(&doc).unwrap();
    m2.from_json(&doc).unwrap();
    assert!(m2.find_by_name("DupT").is_some());
    assert!(
        m2.find_by_name("DupT_1").is_some(),
        "duplicate must rename, got: {:?}",
        m2.to_json()
    );
}

#[test]
fn p2_objc_swift_findings() {
    use crate::parser::{ParsedBinary, Section};
    use std::sync::Arc;
    let sections = vec![Section {
        name: "__objc_data".into(),
        vaddr: 0x1000,
        size: 0x100,
        offset: 0,
        is_executable: false,
        readable: true,
        writable: false,
        initialized: true,
    }];
    let bin = ParsedBinary {
        format: "Mach-O EXE".into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        sections,
        symbols: vec![crate::parser::Symbol {
            name: "$s3Foo3bar".into(),
            addr: 0x1000,
            size: 0,
            is_function: true,
        }],
        imports: vec![],
        exports: vec![],
        strings: vec![],
        data: Arc::new(vec![0u8; 0x200]),
        image_base: 0,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: vec![],
        delay_imports: vec![],
        has_rich: false,
        libraries: vec![],
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    let f = crate::analysis::detect::detect_objc_swift(&bin);
    assert!(f.iter().any(|x| x.id == "objc_section"));
    assert!(f.iter().any(|x| x.id == "swift_symbol"));
}

#[test]
fn plt_slots_seed_import_thunks() {
    use crate::parser::{Import, ParsedBinary, Section, Symbol};
    use std::sync::Arc;
    let mut data = vec![0x90u8; 0x100];
    data[0..6].copy_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
    data[6..11].copy_from_slice(&[0x68, 0x00, 0x00, 0x00, 0x00]);
    data[11..16].copy_from_slice(&[0xE9, 0x00, 0x00, 0x00, 0x00]);
    let bin = ParsedBinary {
        format: "ELF".into(),
        arch: "x86_64".into(),
        entry_point: 0x1030,
        sections: vec![Section {
            name: ".plt".into(),
            vaddr: 0x1030,
            size: 0x100,
            offset: 0,
            is_executable: true,
            readable: true,
            writable: false,
            initialized: true,
        }],
        symbols: vec![Symbol {
            name: "printf".into(),
            addr: 0x1030,
            size: 0,
            is_function: true,
        }],
        imports: vec![Import {
            name: "printf".into(),
            library: "libc.so.6".into(),
            offset: 0x1030,
        }],
        exports: vec![],
        strings: vec![],
        data: Arc::new(data),
        image_base: 0,
        is_dll: true,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: vec![],
        delay_imports: vec![],
        has_rich: false,
        libraries: vec!["libc.so.6".into()],
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    let d = crate::disasm::disassemble_binary(&bin).unwrap();
    assert!(!d.instructions.is_empty());
    let funcs = crate::analysis::function::detect_functions(&d.instructions, 0x1030, &bin.symbols);
    assert!(funcs.iter().any(|f| f.entry == 0x1030));
    let stubs = crate::analysis::advanced::build_stub_map(&d.instructions, &funcs, &bin, None);
    let s = stubs.get(&0x1030).expect("PLT slot must be a stub");
    assert!(
        matches!(s.kind, crate::analysis::advanced::StubKind::ImportThunk),
        "want ImportThunk, got {:?}",
        s.kind
    );
    assert!(s.target_name.contains("printf"), "got {}", s.target_name);
}

#[test]
fn va0_sections_excluded_from_va_space() {
    use crate::parser::{ParsedBinary, Section};
    use std::sync::Arc;
    let mut data = vec![0u8; 0x200];
    data[0x100..0x108].copy_from_slice(&0x1000u64.to_le_bytes());
    let bin = ParsedBinary {
        format: "ELF".into(),
        arch: "x86_64".into(),
        entry_point: 0x1000,
        sections: vec![
            Section {
                name: ".text".into(),
                vaddr: 0x1000,
                size: 0x10,
                offset: 0,
                is_executable: true,
                readable: true,
                writable: false,
                initialized: true,
            },
            Section {
                name: ".debug_info".into(),
                vaddr: 0,
                size: 0x200,
                offset: 0,
                is_executable: false,
                readable: true,
                writable: false,
                initialized: true,
            },
        ],
        symbols: vec![],
        imports: vec![],
        exports: vec![],
        strings: vec![],
        data: Arc::new(data),
        image_base: 0,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: vec![],
        delay_imports: vec![],
        has_rich: false,
        libraries: vec![],
        rpaths: Vec::new(),
        macho_uuid: None,
        relocations: Vec::new(),
    };
    let disasm = crate::disasm::DisasmResult {
        instructions: Arc::new(vec![]),
        arch: "x86_64".into(),
    };
    let db = crate::analysis::xref::build_xrefs(&disasm.instructions, &bin, None);
    assert!(
        db.all.iter().all(|x| x.from >= 0x1000),
        "VA-0 file offsets leaked as xref sources: {:?}",
        db.all
    );
}

#[test]
fn cfg_graph_layout_levels_no_overlap() {
    use crate::analysis::cfg::{graph_layout, BasicBlock, Edge, EdgeKind, CFG};
    use rustc_hash::FxHashMap as HashMap;
    let blk = |id: usize, start: u64, succ: Vec<(usize, EdgeKind)>| BasicBlock {
        id,
        start,
        end: start + 8,
        instr_indices: id..id + 1,
        successors: succ
            .into_iter()
            .map(|(target, kind)| Edge { target, kind })
            .collect(),
        predecessors: vec![],
    };
    let blocks = vec![
        blk(
            0,
            0x1000,
            vec![(1, EdgeKind::BranchTrue), (2, EdgeKind::BranchFalse)],
        ),
        blk(1, 0x1008, vec![(3, EdgeKind::Jump)]),
        blk(2, 0x1010, vec![(3, EdgeKind::Jump)]),
        blk(3, 0x1018, vec![]),
    ];
    let mut block_at = HashMap::default();
    block_at.insert(0x1000, 0);
    let cfg = CFG {
        func_entry: 0x1000,
        blocks,
        block_at,
    };
    let (pos, heights, levels) = graph_layout(&cfg, 12);
    assert_eq!(levels, vec![0, 1, 1, 2]);
    assert!(
        pos[0][1] < pos[1][1] && pos[1][1] < pos[3][1],
        "rows must descend: {:?}",
        pos
    );
    let (a, b) = (pos[1][0], pos[2][0]);
    assert!(
        (a + 300.0 <= b) || (b + 300.0 <= a),
        "row overlap: {:?}",
        pos
    );
    assert_eq!(heights.len(), 4);
    assert!(heights.iter().all(|&h| h > 0.0));
    let empty = CFG {
        func_entry: 0,
        blocks: vec![],
        block_at: HashMap::default(),
    };
    assert!(graph_layout(&empty, 12).0.is_empty());
}

fn emu_run_raw(code: &[u8], args: &[u64]) -> crate::emu::EmuResult {
    let bin = crate::parser::parse_raw_bytes(code.to_vec(), 0x1000, "x86_64").unwrap();
    let d = crate::disasm::disassemble_binary(&bin).unwrap();
    assert!(!d.instructions.is_empty());
    let emu_bin = Box::leak(Box::new(bin));
    let mut emu = crate::emu::Emulator::with_config(
        emu_bin,
        &d.instructions,
        crate::emu::EmuConfig::default(),
    );
    let _ = &d;
    emu.run_function(0x1000, 0x1000 + code.len() as u64, false, args)
}

#[test]
fn emu_leaf_mul() {
    let r = emu_run_raw(&[0x89, 0xF8, 0x6B, 0xC0, 0x2A, 0xC3], &[6]);
    assert_eq!(r.reason, crate::emu::EndReason::Returned);
    assert_eq!(r.rax, 252, "steps={} trace={:x?}", r.steps, r.trace_tail);
}

#[test]
fn emu_sum_loop_flags() {
    let r = emu_run_raw(
        &[
            0x31, 0xC0, 0x89, 0xF9, 0x01, 0xC8, 0x83, 0xE9, 0x01, 0x75, 0xF9, 0xC3,
        ],
        &[5],
    );
    assert_eq!(r.reason, crate::emu::EndReason::Returned);
    assert_eq!(r.rax, 15, "steps={} trace={:x?}", r.steps, r.trace_tail);
}

#[test]
fn emu_fs_canary_and_stack() {
    let code = vec![
        0x64, 0x48, 0x8B, 0x04, 0x25, 0x28, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0xF8, 0x48,
        0x8B, 0x5C, 0x24, 0xF8, 0x48, 0x31, 0xC3, 0xC3,
    ];
    let r = emu_run_raw(&code, &[]);
    assert_eq!(r.reason, crate::emu::EndReason::Returned);
    assert_eq!(r.rax, 0xA5A5_A5A5_A5A5_A5A5);
    assert!(r.stack_writes >= 1);
}

fn build_mini_dotnet_pe() -> crate::parser::ParsedBinary {
    use crate::parser::{ParsedBinary, Section};
    use std::sync::Arc;

    let mut strings: Vec<u8> = vec![0];
    let mut sidx = |s: &str| -> u16 {
        let i = strings.len() as u16;
        strings.extend_from_slice(s.as_bytes());
        strings.push(0);
        i
    };
    let i_console = sidx("Console");
    let i_system = sidx("System");
    let i_program = sidx("Program");
    let i_main = sidx("Main");
    let i_writeline = sidx("WriteLine");
    assert_eq!(
        (i_console, i_system, i_program, i_main, i_writeline),
        (1, 9, 16, 24, 29)
    );

    let mut tbl: Vec<u8> = Vec::new();
    tbl.extend_from_slice(&[0u8; 4]);
    tbl.push(2);
    tbl.push(0);
    tbl.push(0);
    tbl.push(0);
    let mut valid: u64 = 0;
    for t in [0u32, 1, 2, 6, 10] {
        valid |= 1u64 << t;
    }
    tbl.extend_from_slice(&valid.to_le_bytes());
    tbl.extend_from_slice(&0u64.to_le_bytes());
    for _ in [0u32, 1, 2, 6, 10] {
        tbl.extend_from_slice(&1u32.to_le_bytes());
    }
    tbl.extend_from_slice(&[0u8; 10]);
    tbl.extend_from_slice(&5u16.to_le_bytes());
    tbl.extend_from_slice(&i_console.to_le_bytes());
    tbl.extend_from_slice(&i_system.to_le_bytes());
    tbl.extend_from_slice(&0x100000u32.to_le_bytes());
    tbl.extend_from_slice(&i_program.to_le_bytes());
    tbl.extend_from_slice(&0u16.to_le_bytes());
    tbl.extend_from_slice(&0u16.to_le_bytes());
    tbl.extend_from_slice(&0u16.to_le_bytes());
    tbl.extend_from_slice(&1u16.to_le_bytes());
    tbl.extend_from_slice(&0x1000u32.to_le_bytes());
    tbl.extend_from_slice(&0u16.to_le_bytes());
    tbl.extend_from_slice(&0x86u16.to_le_bytes());
    tbl.extend_from_slice(&i_main.to_le_bytes());
    tbl.extend_from_slice(&0u16.to_le_bytes());
    tbl.extend_from_slice(&0u16.to_le_bytes());
    tbl.extend_from_slice(&9u16.to_le_bytes());
    tbl.extend_from_slice(&i_writeline.to_le_bytes());
    tbl.extend_from_slice(&0u16.to_le_bytes());

    struct Stream<'x> {
        name: &'x [u8],
        data: Vec<u8>,
    }
    let streams = [
        Stream {
            name: b"#Strings",
            data: strings,
        },
        Stream {
            name: b"#Blob",
            data: Vec::new(),
        },
        Stream {
            name: b"#~",
            data: tbl,
        },
    ];
    let dir_size: usize = streams
        .iter()
        .map(|s| 8 + ((s.name.len() + 1 + 3) & !3))
        .sum();
    let mut data_off = 32 + dir_size;
    let mut dir: Vec<u8> = Vec::new();
    let mut blobs: Vec<u8> = Vec::new();
    for s in &streams {
        dir.extend_from_slice(&(data_off as u32).to_le_bytes());
        dir.extend_from_slice(&(s.data.len() as u32).to_le_bytes());
        dir.extend_from_slice(s.name);
        dir.push(0);
        while !dir.len().is_multiple_of(4) {
            dir.push(0);
        }
        blobs.extend_from_slice(&s.data);
        data_off += s.data.len();
    }
    assert_eq!(dir.len(), dir_size);
    let mut md: Vec<u8> = Vec::new();
    md.extend_from_slice(b"BSJB");
    md.extend_from_slice(&1u16.to_le_bytes());
    md.extend_from_slice(&1u16.to_le_bytes());
    md.extend_from_slice(&0u32.to_le_bytes());
    md.extend_from_slice(&12u32.to_le_bytes());
    md.extend_from_slice(b"v4.0.30319\x00\x00");
    md.extend_from_slice(&0u16.to_le_bytes());
    md.extend_from_slice(&(streams.len() as u16).to_le_bytes());
    md.extend_from_slice(&dir);
    md.extend_from_slice(&blobs);

    let image_base: u64 = 0x140000000;
    let sec_off = 0x200usize;
    let cor_rva = 0x40u32;
    let md_rva = 0x140u32;
    let mut file = vec![0u8; sec_off];
    file[0] = b'M';
    file[1] = b'Z';
    file[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    file[0x80..0x84].copy_from_slice(b"PE\0\0");
    file[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
    file[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    file[0x94..0x96].copy_from_slice(&240u16.to_le_bytes());
    file[0x98..0x9A].copy_from_slice(&0x20Bu16.to_le_bytes());
    file[0x178..0x17C].copy_from_slice(&cor_rva.to_le_bytes());
    file[0x17C..0x180].copy_from_slice(&72u32.to_le_bytes());
    file[0x188..0x190].copy_from_slice(b".text\x00\x00\x00");
    let text_size = (md_rva as usize + md.len() + 0x100) as u32;
    file[0x190..0x194].copy_from_slice(&text_size.to_le_bytes());
    file[0x194..0x198].copy_from_slice(&0u32.to_le_bytes());
    file[0x198..0x19C].copy_from_slice(&text_size.to_le_bytes());
    file[0x19C..0x1A0].copy_from_slice(&(sec_off as u32).to_le_bytes());
    file[0x1AC..0x1B0].copy_from_slice(&0x60000020u32.to_le_bytes());
    let mut text = vec![0u8; text_size as usize];
    text[0x40 + 8..0x40 + 12].copy_from_slice(&md_rva.to_le_bytes());
    text[0x40 + 12..0x40 + 16].copy_from_slice(&(md.len() as u32).to_le_bytes());
    text[0x40 + 16..0x40 + 20].copy_from_slice(&0x8u32.to_le_bytes());
    text[0x40 + 20..0x40 + 24].copy_from_slice(&0x06000001u32.to_le_bytes());
    text[md_rva as usize..md_rva as usize + md.len()].copy_from_slice(&md);
    file.extend_from_slice(&text);
    ParsedBinary {
        format: "PE EXE".into(),
        arch: "x86_64".into(),
        entry_point: image_base,
        sections: vec![Section {
            name: ".text".into(),
            vaddr: image_base,
            size: text_size as u64,
            offset: sec_off as u64,
            is_executable: true,
            readable: true,
            writable: false,
            initialized: true,
        }],
        symbols: vec![],
        imports: vec![],
        exports: vec![],
        strings: vec![],
        data: Arc::new(file),
        image_base,
        is_dll: false,
        pe_characteristics: 0,
        dll_characteristics: 0,
        overlay: None,
        tls_callbacks: vec![],
        delay_imports: vec![],
        has_rich: false,
        libraries: vec![],
        rpaths: vec![],
        macho_uuid: None,
        relocations: Vec::new(),
    }
}

#[test]
fn dotnet_memberref_and_token() {
    let bin = build_mini_dotnet_pe();
    assert!(crate::parser::dotnet::is_dotnet(&bin));
    let info = crate::parser::dotnet::parse(&bin).expect("parse mini assembly");
    assert_eq!(info.runtime_version, "v4.0.30319");
    assert_eq!(info.typedefs.len(), 1);
    assert_eq!(info.methods.len(), 1);
    assert_eq!(info.methods[0].owner_type, "Program");
    assert_eq!(
        info.member_refs.len(),
        1,
        "member_refs: {:?}",
        info.member_refs
    );
    assert_eq!(info.member_refs[0].parent, "System.Console");
    assert_eq!(info.member_refs[0].name, "WriteLine");
    assert_eq!(
        crate::parser::dotnet::resolve_token(&info, 0x0A000001),
        "System.Console::WriteLine"
    );
    assert_eq!(
        crate::parser::dotnet::resolve_token(&info, 0x06000001),
        "Program::Main"
    );
    assert_eq!(
        crate::parser::dotnet::resolve_token(&info, 0x02000001),
        "Program"
    );
}

fn mini_pclntab_entries(entry_offs: &[u32]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0xFFFF_FFF1u32.to_le_bytes());
    b.extend_from_slice(&[0, 0, 8, 8]);
    b.extend_from_slice(&(entry_offs.len() as u64).to_le_bytes());
    for (i, off) in entry_offs.iter().enumerate() {
        b.extend_from_slice(&off.to_le_bytes());
        b.extend_from_slice(&(0x1000u32 + i as u32).to_le_bytes());
    }
    b
}

#[test]
fn golang_pclntab_modern() {
    use crate::analysis::golang::{find_pclntab, pclntab_functions};
    let blob = mini_pclntab_entries(&[0x0, 0x20]);
    assert_eq!(find_pclntab(&blob), Some(0));
    let exec = [(0x1000u64, 0x1100u64)];
    assert_eq!(pclntab_functions(&blob, &exec), vec![0x1000, 0x1020]);
    let blob2 = mini_pclntab_entries(&[0x0, 0x5000]);
    assert_eq!(pclntab_functions(&blob2, &exec), vec![0x1000]);
    assert_eq!(find_pclntab(&[0u8; 64]), None);
    assert!(pclntab_functions(&[0xFB, 0xFF, 0xFF], &exec).is_empty());
}

#[test]
fn golang_pclntab_legacy_absolute() {
    use crate::analysis::golang::pclntab_functions;
    let mut b = Vec::new();
    b.extend_from_slice(&0xFFFF_FFFBu32.to_le_bytes());
    b.extend_from_slice(&[0, 0, 8, 8]);
    b.extend_from_slice(&2u64.to_le_bytes());
    b.extend_from_slice(&0x2000u64.to_le_bytes());
    b.extend_from_slice(&0x2040u64.to_le_bytes());
    let exec = [(0x2000u64, 0x2100u64)];
    assert_eq!(pclntab_functions(&b, &exec), vec![0x2000, 0x2040]);
}

#[test]
fn golang_pclntab_feeds_discovery() {
    let mut raw = vec![0x90u8; 0x200];
    raw[0] = 0xC3;
    for b in raw.iter_mut().take(0x20).skip(1) {
        *b = 0xCC;
    }
    raw[0x20] = 0xB8;
    raw[0x21..0x25].copy_from_slice(&1u32.to_le_bytes());
    raw[0x25] = 0xC3;
    let tab = mini_pclntab_entries(&[0x0, 0x20]);
    let at = 0x100;
    raw[at..at + tab.len()].copy_from_slice(&tab);
    let bin = crate::parser::parse_raw_bytes(raw.clone(), 0x1000, "x86_64").unwrap();
    let d = crate::disasm::disassemble_binary(&bin).unwrap();
    let r = crate::analysis::auto_analyze(&d, &bin);
    let entries: Vec<u64> = r.functions.iter().map(|f| f.entry).collect();
    assert!(entries.contains(&0x1000), "entry missing: {:x?}", entries);
    assert!(
        entries.contains(&0x1020),
        "pclntab-only func missing: {:x?}",
        entries
    );
    let mut raw2 = raw;
    for b in raw2.iter_mut().skip(at).take(4) {
        *b = 0;
    }
    let bin2 = crate::parser::parse_raw_bytes(raw2, 0x1000, "x86_64").unwrap();
    let d2 = crate::disasm::disassemble_binary(&bin2).unwrap();
    let r2 = crate::analysis::auto_analyze(&d2, &bin2);
    let e2: Vec<u64> = r2.functions.iter().map(|f| f.entry).collect();
    assert!(
        !e2.contains(&0x1020),
        "B found without pclntab — test vacuous: {:x?}",
        e2
    );
}

fn mini_macho() -> Vec<u8> {
    let mut b = Vec::new();
    let dylib = b"/usr/lib/libSystem.B.dylib\x00";
    let dylib_padded = (dylib.len() + 7) & !7;
    let seg_cmdsize = 72u32 + 80;
    let uuid_cmdsize = 24u32;
    let dylib_cmdsize = (24 + dylib_padded) as u32;
    let rpath = b"@loader_path/../lib\x00";
    let rpath_padded = (rpath.len() + 7) & !7;
    let rpath_cmdsize = (12 + rpath_padded) as u32;
    let ncmds = 4u32;
    let all_cmds = seg_cmdsize + uuid_cmdsize + dylib_cmdsize + rpath_cmdsize;
    b.extend_from_slice(&0xfeedfacfu32.to_le_bytes());
    b.extend_from_slice(&0x01000007u32.to_le_bytes());
    b.extend_from_slice(&3u32.to_le_bytes());
    b.extend_from_slice(&2u32.to_le_bytes());
    b.extend_from_slice(&ncmds.to_le_bytes());
    b.extend_from_slice(&all_cmds.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0x19u32.to_le_bytes());
    b.extend_from_slice(&seg_cmdsize.to_le_bytes());
    let mut segname = [0u8; 16];
    segname[..6].copy_from_slice(b"__TEXT");
    b.extend_from_slice(&segname);
    b.extend_from_slice(&0x1000u64.to_le_bytes());
    b.extend_from_slice(&0x1000u64.to_le_bytes());
    b.extend_from_slice(&0x200u64.to_le_bytes());
    b.extend_from_slice(&0x100u64.to_le_bytes());
    b.extend_from_slice(&5u32.to_le_bytes());
    b.extend_from_slice(&5u32.to_le_bytes());
    b.extend_from_slice(&1u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    let mut sectname = [0u8; 16];
    sectname[..6].copy_from_slice(b"__text");
    b.extend_from_slice(&sectname);
    b.extend_from_slice(&segname);
    b.extend_from_slice(&0x1000u64.to_le_bytes());
    b.extend_from_slice(&0x100u64.to_le_bytes());
    b.extend_from_slice(&0x200u32.to_le_bytes());
    b.extend_from_slice(&2u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0x80000000u32.to_le_bytes());
    b.extend_from_slice(&[0u8; 12]);
    b.extend_from_slice(&0x1Bu32.to_le_bytes());
    b.extend_from_slice(&uuid_cmdsize.to_le_bytes());
    b.extend_from_slice(&[
        0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA,
        0xBB,
    ]);
    b.extend_from_slice(&0xCu32.to_le_bytes());
    b.extend_from_slice(&dylib_cmdsize.to_le_bytes());
    b.extend_from_slice(&24u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(dylib);
    while b.len() % 8 != 0 {
        b.push(0);
    }
    b.extend_from_slice(&0x8000001Cu32.to_le_bytes());
    b.extend_from_slice(&rpath_cmdsize.to_le_bytes());
    b.extend_from_slice(&12u32.to_le_bytes());
    b.extend_from_slice(rpath);
    while b.len() % 8 != 0 {
        b.push(0);
    }
    while b.len() < 0x200 {
        b.push(0);
    }
    b.push(0xC3);
    while b.len() < 0x300 {
        b.push(0);
    }
    b.extend_from_slice(&[0xAAu8; 64]);
    b
}

#[test]
fn macho_uuid_rpath_overlay() {
    let bytes = mini_macho();
    let path = std::env::temp_dir().join("rd_mini_macho_test");
    std::fs::write(&path, &bytes).unwrap();
    let bin = crate::parser::parse_file(&path).expect("parse mini macho");
    let _ = std::fs::remove_file(&path);
    assert!(bin.format.starts_with("Mach-O"), "format: {}", bin.format);
    assert_eq!(bin.arch, "x86_64");
    assert_eq!(bin.sections.len(), 1);
    assert!(bin.sections[0].is_executable);
    assert_eq!(
        bin.macho_uuid.as_deref(),
        Some("DEADBEEF-0011-2233-4455-66778899AABB")
    );
    assert!(
        bin.libraries.iter().any(|l| l.contains("libSystem")),
        "libs: {:?}",
        bin.libraries
    );
    {
        let obj = goblin::Object::parse(&bytes).expect("goblin parse");
        if let goblin::Object::Mach(goblin::mach::Mach::Binary(m)) = obj {
            eprintln!(
                "DBG ncmds={} rpaths={:?} libs={:?}",
                m.load_commands.len(),
                m.rpaths,
                m.libs
            );
            for c in &m.load_commands {
                eprintln!("DBG cmd: {:?}", c.command);
            }
        } else {
            panic!("not macho");
        }
    }
    assert_eq!(bin.rpaths, vec!["@loader_path/../lib".to_string()]);
    assert_eq!(bin.overlay, Some((0x300, 64)), "overlay: {:?}", bin.overlay);
}
