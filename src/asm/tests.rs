use super::*;

fn enc(arch: &str, addr: u64, line: &str) -> Vec<u8> {
    assemble(arch, addr, line).unwrap_or_else(|e| panic!("{}: {}", line, e))
}

#[test]
fn basics() {
    assert_eq!(enc("x86_64", 0x1000, "nop"), vec![0x90]);
    assert_eq!(enc("x86_64", 0x1000, "ret"), vec![0xC3]);
    assert_eq!(enc("x86_64", 0x1000, "int3"), vec![0xCC]);
    assert_eq!(enc("x86_64", 0x1000, "push rax"), vec![0x50]);
    assert_eq!(enc("x86_64", 0x1000, "pop rbx"), vec![0x5B]);
    assert_eq!(enc("x86_64", 0x1000, "push 0x20"), vec![0x6A, 0x20]);
    assert_eq!(
        enc("x86_64", 0x1000, "push 0x12345678"),
        vec![0x68, 0x78, 0x56, 0x34, 0x12]
    );
}

#[test]
fn mov_forms() {
    assert_eq!(
        enc("x86_64", 0x1000, "mov eax, 5"),
        vec![0xB8, 0x05, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov rax, 0x1122334455667788"),
        vec![0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov rax, rbx"),
        vec![0x48, 0x8B, 0xC3]
    );
    assert_eq!(enc("x86_64", 0x1000, "xor eax, eax"), vec![0x31, 0xC0]);
    assert_eq!(
        enc("x86_64", 0x1000, "xor rax, rax"),
        vec![0x48, 0x31, 0xC0]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov rax, qword ptr [rip + 0x10]"),
        vec![0x48, 0x8B, 0x05, 0x10, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov qword ptr [rax + 0x8], rdx"),
        vec![0x48, 0x89, 0x50, 0x08]
    );
}

#[test]
fn alu_and_branches() {
    assert_eq!(
        enc("x86_64", 0x1000, "add rax, 1"),
        vec![0x48, 0x83, 0xC0, 0x01]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "cmp eax, 0x10"),
        vec![0x83, 0xF8, 0x10]
    );
    assert_eq!(enc("x86_64", 0x1000, "jmp 0x1005"), vec![0xEB, 0x03]);
    assert_eq!(
        enc("x86_64", 0x1000, "jmp 0x2000"),
        vec![0xE9, 0xFB, 0x0F, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "call 0x2000"),
        vec![0xE8, 0xFB, 0x0F, 0x00, 0x00]
    );
    assert_eq!(enc("x86_64", 0x1000, "je 0x1007"), vec![0x74, 0x05]);
    assert_eq!(
        enc("x86_64", 0x1000, "je 0x2000"),
        vec![0x0F, 0x84, 0xFA, 0x0F, 0x00, 0x00]
    );
}

#[test]
fn x86_32_mode() {
    assert_eq!(
        enc("x86", 0x1000, "mov eax, 5"),
        vec![0xB8, 0x05, 0x00, 0x00, 0x00]
    );
    assert_eq!(enc("x86", 0x1000, "xor eax, eax"), vec![0x31, 0xC0]);
    assert_eq!(enc("x86", 0x1000, "mov eax, ebx"), vec![0x8B, 0xC3]);
}

#[test]
fn high_regs() {
    assert_eq!(enc("x86_64", 0x1000, "mov r8, r9"), vec![0x4D, 0x8B, 0xC1]);
    assert_eq!(
        enc("x86_64", 0x1000, "xor r8d, r8d"),
        vec![0x45, 0x31, 0xC0]
    );
}

#[test]
fn lea_rip() {
    assert_eq!(
        enc("x86_64", 0x1000, "lea rax, [rip + 0x20]"),
        vec![0x48, 0x8D, 0x05, 0x20, 0x00, 0x00, 0x00]
    );
}

#[test]
fn byte_and_word_forms() {
    assert_eq!(enc("x86_64", 0x1000, "mov al, bl"), vec![0x8A, 0xC3]);
    assert_eq!(enc("x86_64", 0x1000, "mov [rax], al"), vec![0x88, 0x00]);
    assert_eq!(
        enc("x86_64", 0x1000, "mov byte ptr [rax], 5"),
        vec![0xC6, 0x00, 0x05]
    );
    assert_eq!(enc("x86_64", 0x1000, "add al, 1"), vec![0x80, 0xC0, 0x01]);
    assert_eq!(
        enc("x86_64", 0x1000, "cmp byte ptr [rax], 5"),
        vec![0x80, 0x38, 0x05]
    );
    assert_eq!(enc("x86_64", 0x1000, "test al, bl"), vec![0x84, 0xD8]);
    assert_eq!(enc("x86_64", 0x1000, "inc al"), vec![0xFE, 0xC0]);
    assert_eq!(enc("x86_64", 0x1000, "dec dl"), vec![0xFE, 0xCA]);

    assert_eq!(
        enc("x86_64", 0x1000, "mov ax, bx"),
        [0x66, 0x8A, 0xC3]
            .iter()
            .map(|b| if *b == 0x8A { 0x8B } else { *b })
            .collect::<Vec<u8>>()
    );
    assert_eq!(
        enc("x86_64", 0x1000, "sub ax, 1"),
        vec![0x66, 0x83, 0xE8, 0x01]
    );

    assert_eq!(enc("x86_64", 0x1000, "mov eax, [rax]"), vec![0x8B, 0x00]);
    assert_eq!(
        enc("x86_64", 0x1000, "lea eax, [rbx + 1]"),
        vec![0x8D, 0x43, 0x01]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "movsx eax, bl"),
        vec![0x0F, 0xBE, 0xC3]
    );
}

#[test]
fn extended_byte_regs() {
    assert_eq!(enc("x86_64", 0x1000, "mov r8b, 1"), vec![0x41, 0xB0, 0x01]);
    assert_eq!(enc("x86_64", 0x1000, "mov spl, 1"), vec![0x40, 0xB4, 0x01]);
    assert_eq!(
        enc("x86_64", 0x1000, "mov r8d, 5"),
        vec![0x41, 0xB8, 0x05, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov r8w, 5"),
        vec![0x66, 0x41, 0xB8, 0x05, 0x00]
    );
    assert!(assemble("x86_64", 0x1000, "jmp some_label").is_err());
}

fn fails(arch: &str, line: &str) -> bool {
    assemble(arch, 0x1000, line).is_err()
}

#[test]
fn indirect_call_jmp() {
    assert_eq!(enc("x86_64", 0x1000, "call rax"), vec![0xFF, 0xD0]);
    assert_eq!(enc("x86_64", 0x1000, "jmp rax"), vec![0xFF, 0xE0]);
    assert_eq!(enc("x86_64", 0x1000, "call r8"), vec![0x41, 0xFF, 0xD0]);
    assert_eq!(
        enc("x86_64", 0x1000, "call qword ptr [rax]"),
        vec![0xFF, 0x10]
    );
    assert_eq!(enc("x86_64", 0x1000, "call [rax]"), vec![0xFF, 0x10]);
    assert_eq!(
        enc("x86_64", 0x1000, "jmp qword ptr [rip + 0x10]"),
        vec![0xFF, 0x25, 0x10, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "call qword ptr [rax + rbx*4 + 0x10]"),
        vec![0xFF, 0x54, 0x98, 0x10]
    );
    assert_eq!(enc("x86", 0x1000, "call eax"), vec![0xFF, 0xD0]);
    assert_eq!(enc("x86", 0x1000, "jmp ebx"), vec![0xFF, 0xE3]);
    assert!(fails("x86_64", "call eax"));
    assert!(fails("x86_64", "jmp dword ptr [rax]"));
    assert!(fails("x86_64", "je rax"));
}

#[test]
fn alu_reg_mem_and_mem_reg() {
    assert_eq!(enc("x86_64", 0x1000, "cmp eax, [rbx]"), vec![0x3B, 0x03]);
    assert_eq!(
        enc("x86_64", 0x1000, "add rax, [rbx + 8]"),
        vec![0x48, 0x03, 0x43, 0x08]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "sub [rax], rcx"),
        vec![0x48, 0x29, 0x08]
    );
    assert_eq!(enc("x86_64", 0x1000, "or al, [rax]"), vec![0x0A, 0x00]);
    assert_eq!(
        enc("x86_64", 0x1000, "cmp byte ptr [rax], bl"),
        vec![0x38, 0x18]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "add qword ptr [rax], 0x1000"),
        vec![0x48, 0x81, 0x00, 0x00, 0x10, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "xor r10b, r11b"),
        vec![0x45, 0x30, 0xDA]
    );
    assert!(fails("x86_64", "mov eax, qword ptr [rax]"));
    assert!(fails("x86_64", "add eax, byte ptr [rax]"));
}

#[test]
fn alu_immediate_forms() {
    assert_eq!(
        enc("x86_64", 0x1000, "add rcx, 0x1000"),
        vec![0x48, 0x81, 0xC1, 0x00, 0x10, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "add cx, 0x1234"),
        vec![0x66, 0x81, 0xC1, 0x34, 0x12]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "add cl, 0xff"),
        vec![0x80, 0xC1, 0xFF]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "add ecx, 0x80"),
        vec![0x81, 0xC1, 0x80, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "add ecx, -0x80"),
        vec![0x83, 0xC1, 0x80]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "and ecx, 0xfffffff0"),
        vec![0x83, 0xE1, 0xF0]
    );
    assert!(fails("x86_64", "add rax, 0x1122334455"));
    assert!(fails("x86_64", "add eax, 0x100000000"));
    assert!(fails("x86_64", "add ax, 0x12345"));
    assert!(fails("x86_64", "add al, 0x100"));
    assert!(fails("x86_64", "mov eax, 0x100000000"));
    assert!(fails("x86_64", "mov qword ptr [rax], 0x80000000"));
    assert!(fails("x86_64", "push 0x80000000"));
}

#[test]
fn test_forms() {
    assert_eq!(
        enc("x86_64", 0x1000, "test byte ptr [rax], 1"),
        vec![0xF6, 0x00, 0x01]
    );
    assert_eq!(enc("x86_64", 0x1000, "test [rax], ecx"), vec![0x85, 0x08]);
    assert_eq!(enc("x86_64", 0x1000, "test ecx, [rax]"), vec![0x85, 0x08]);
    assert_eq!(
        enc("x86_64", 0x1000, "test ecx, 0x1000"),
        vec![0xF7, 0xC1, 0x00, 0x10, 0x00, 0x00]
    );
    assert_eq!(enc("x86_64", 0x1000, "test ecx, edx"), vec![0x85, 0xD1]);
    assert!(fails("x86_64", "test [rax], 1"));
}

#[test]
fn extension_moves() {
    assert_eq!(
        enc("x86_64", 0x1000, "movzx ax, bl"),
        vec![0x66, 0x0F, 0xB6, 0xC3]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "movzx rax, word ptr [rbx]"),
        vec![0x48, 0x0F, 0xB7, 0x03]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "movzx eax, byte ptr [r8]"),
        vec![0x41, 0x0F, 0xB6, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "movsx rax, byte ptr [rax + 1]"),
        vec![0x48, 0x0F, 0xBE, 0x40, 0x01]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "movsxd rax, ecx"),
        vec![0x48, 0x63, 0xC1]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "movsxd rax, dword ptr [rbx + 4]"),
        vec![0x48, 0x63, 0x43, 0x04]
    );
    assert_eq!(enc("x86", 0x1000, "movzx eax, bl"), vec![0x0F, 0xB6, 0xC3]);
    assert!(fails("x86_64", "movzx eax, [rax]"));
    assert!(fails("x86_64", "movzx eax, ecx"));
    assert!(fails("x86", "movsxd eax, ebx"));
}

#[test]
fn addressing_modes() {
    assert_eq!(
        enc("x86_64", 0x1000, "mov rax, [rax*4 + 0x10]"),
        vec![0x48, 0x8B, 0x04, 0x85, 0x10, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov eax, [rax*2]"),
        vec![0x8B, 0x04, 0x45, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov eax, [4*rax]"),
        vec![0x8B, 0x04, 0x85, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov [0x1000], eax"),
        vec![0x89, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov eax, [0x1000]"),
        vec![0x8B, 0x04, 0x25, 0x00, 0x10, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov eax, [rbx + rcx*8]"),
        vec![0x8B, 0x04, 0xCB]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "lea rax, [rax + rax*2]"),
        vec![0x48, 0x8D, 0x04, 0x40]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov rax, [r12 + r13*2 + 0x100]"),
        vec![0x4B, 0x8B, 0x84, 0x6C, 0x00, 0x01, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov rax, [r12]"),
        vec![0x49, 0x8B, 0x04, 0x24]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov rax, [r13]"),
        vec![0x49, 0x8B, 0x45, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov rax, [rsp + 8]"),
        vec![0x48, 0x8B, 0x44, 0x24, 0x08]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov r9d, [rbp]"),
        vec![0x44, 0x8B, 0x4D, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov r9d, [rbp + 0x80]"),
        vec![0x44, 0x8B, 0x8D, 0x80, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov r9d, [rsp + 0x80]"),
        vec![0x44, 0x8B, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86", 0x1000, "mov eax, [ebx + ecx*2]"),
        vec![0x8B, 0x04, 0x4B]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov rax, [rbx - 8]"),
        enc("x86_64", 0x1000, "mov rax, [rbx + -8]")
    );
}

#[test]
fn bad_memory_operands_are_errors() {
    assert!(fails("x86_64", "mov rax, [rax*3]"));
    assert!(fails("x86_64", "mov rax, [rax + foo]"));
    assert!(fails("x86_64", "mov rax, [rsp*2]"));
    assert!(fails("x86_64", "mov rax, [rax*2 + rbx*2]"));
    assert!(fails("x86_64", "mov rax, [rax + rbx + rcx]"));
    assert!(fails("x86_64", "mov rax, [rax +]"));
    assert!(fails("x86_64", "mov rax, []"));
    assert!(fails("x86_64", "mov rax, [rax"));
    assert!(fails("x86_64", "mov rax, [rax] x"));
    assert!(fails("x86_64", "mov rax, [rax + 0x100000000]"));
    assert!(fails("x86_64", "mov rax, [rip + rax]"));
    assert!(fails("x86_64", "mov eax, [eax]"));
    assert!(fails("x86", "mov eax, [rax]"));
}

#[test]
fn rex_for_byte_memory_forms() {
    assert_eq!(
        enc("x86_64", 0x1000, "mov spl, [rax]"),
        vec![0x40, 0x8A, 0x20]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov [rax], sil"),
        vec![0x40, 0x88, 0x30]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "sete sil"),
        vec![0x40, 0x0F, 0x94, 0xC6]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov byte ptr [r8], 1"),
        vec![0x41, 0xC6, 0x00, 0x01]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov word ptr [rax], 0x1234"),
        vec![0x66, 0xC7, 0x00, 0x34, 0x12]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov qword ptr [rax], -1"),
        vec![0x48, 0xC7, 0x00, 0xFF, 0xFF, 0xFF, 0xFF]
    );
}

#[test]
fn push_pop_forms() {
    assert_eq!(enc("x86_64", 0x1000, "push r8"), vec![0x41, 0x50]);
    assert_eq!(enc("x86_64", 0x1000, "pop r15"), vec![0x41, 0x5F]);
    assert_eq!(enc("x86_64", 0x1000, "push ax"), vec![0x66, 0x50]);
    assert_eq!(enc("x86_64", 0x1000, "pop bx"), vec![0x66, 0x5B]);
    assert_eq!(enc("x86_64", 0x1000, "push -1"), vec![0x6A, 0xFF]);
    assert_eq!(
        enc("x86_64", 0x1000, "push 0x7fffffff"),
        vec![0x68, 0xFF, 0xFF, 0xFF, 0x7F]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "push qword ptr [rax]"),
        vec![0xFF, 0x30]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "pop qword ptr [rax]"),
        vec![0x8F, 0x00]
    );
    assert_eq!(enc("x86", 0x1000, "push eax"), vec![0x50]);
    assert_eq!(enc("x86", 0x1000, "push ax"), vec![0x66, 0x50]);
    assert_eq!(
        enc("x86", 0x1000, "push 0x1000"),
        vec![0x68, 0x00, 0x10, 0x00, 0x00]
    );
    assert!(fails("x86_64", "push eax"));
    assert!(fails("x86_64", "pop eax"));
    assert!(fails("x86", "push rax"));
    assert!(fails("x86", "push r8"));
}

#[test]
fn ret_cmov_setcc_misc() {
    assert_eq!(enc("x86_64", 0x1000, "ret 8"), vec![0xC2, 0x08, 0x00]);
    assert_eq!(enc("x86", 0x1000, "ret 4"), vec![0xC2, 0x04, 0x00]);
    assert!(fails("x86_64", "ret 0x10000"));
    assert!(fails("x86_64", "ret rax"));
    assert_eq!(
        enc("x86_64", 0x1000, "cmovne rax, rbx"),
        vec![0x48, 0x0F, 0x45, 0xC3]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "cmovl eax, [rbx]"),
        vec![0x0F, 0x4C, 0x03]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "cmove ax, bx"),
        vec![0x66, 0x0F, 0x44, 0xC3]
    );
    assert_eq!(enc("x86_64", 0x1000, "sete al"), vec![0x0F, 0x94, 0xC0]);
    assert_eq!(
        enc("x86_64", 0x1000, "sete byte ptr [rax]"),
        vec![0x0F, 0x94, 0x00]
    );
    assert!(fails("x86_64", "sete eax"));
    assert!(fails("x86_64", "sete dword ptr [rax]"));
    assert_eq!(enc("x86_64", 0x1000, "syscall"), vec![0x0F, 0x05]);
    assert_eq!(enc("x86_64", 0x1000, "hlt"), vec![0xF4]);
    assert_eq!(enc("x86_64", 0x1000, "cdq"), vec![0x99]);
    assert_eq!(enc("x86_64", 0x1000, "cqo"), vec![0x48, 0x99]);
    assert_eq!(enc("x86_64", 0x1000, "cdqe"), vec![0x48, 0x98]);
    assert_eq!(enc("x86_64", 0x1000, "ud2"), vec![0x0F, 0x0B]);
    assert_eq!(enc("x86_64", 0x1000, "pause"), vec![0xF3, 0x90]);
    assert!(fails("x86", "cqo"));
    assert!(fails("x86_64", "leave rax"));
    assert_eq!(
        enc("x86_64", 0x1000, "inc qword ptr [rax]"),
        vec![0x48, 0xFF, 0x00]
    );
    assert_eq!(enc("x86_64", 0x1000, "not ecx"), vec![0xF7, 0xD1]);
    assert_eq!(enc("x86_64", 0x1000, "neg r9"), vec![0x49, 0xF7, 0xD9]);
}

#[test]
fn mode_validation() {
    assert!(fails("x86", "mov r8d, 1"));
    assert!(fails("x86", "mov rax, 1"));
    assert!(fails("x86", "mov spl, 1"));
    assert!(fails("x86", "lea eax, [rip + 0x10]"));
    assert!(fails("x86", "mov qword ptr [eax], 1"));
    assert_eq!(enc("X86_64", 0x1000, "mov r8, r9"), vec![0x4D, 0x8B, 0xC1]);
    assert_eq!(enc("amd64", 0x1000, "mov r8, r9"), vec![0x4D, 0x8B, 0xC1]);
}

#[test]
fn branch_range_and_big_immediates() {
    assert!(fails("x86_64", "jmp 0x100000000000"));
    assert!(fails("x86_64", "call 0x100000000000"));
    assert!(fails("x86_64", "je 0x100000000000"));
    assert_eq!(
        enc("x86_64", 0x1000, "mov rax, 0xFFFFFFFFFFFFFFFF"),
        vec![0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "movabs rax, -1"),
        enc("x86_64", 0x1000, "mov rax, 0xFFFFFFFFFFFFFFFF")
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov eax, 0b101"),
        vec![0xB8, 0x05, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov eax, 0xdead_beef"),
        vec![0xB8, 0xEF, 0xBE, 0xAD, 0xDE]
    );
}

#[test]
fn operand_syntax_is_strict() {
    assert!(fails("x86_64", "mov eax,"));
    assert!(fails("x86_64", "mov eax,,ebx"));
    assert!(fails("x86_64", "mov dword ptr, 1"));
    assert!(fails("x86_64", "mov foo ptr [rax], 1"));
    assert_eq!(
        enc("x86_64", 0x1000, "MOV EAX, DWORD  PTR [RAX]"),
        vec![0x8B, 0x00]
    );
    assert_eq!(
        enc("x86_64", 0x1000, "mov byte [rax], 5"),
        vec![0xC6, 0x00, 0x05]
    );
}

#[test]
fn snippet_assembles_in_address_order() {
    let (bytes, errors) =
        assemble_snippet("x86_64", 0x1000, "xor eax, eax; jmp 0x1007\nnop\nret").unwrap();
    assert!(errors.is_empty(), "{:?}", errors);
    assert_eq!(bytes, vec![0x31, 0xC0, 0xEB, 0x03, 0x90, 0xC3]);
    let (_, errors) = assemble_snippet("x86_64", 0x1000, "nop\nbogus rax").unwrap();
    assert_eq!(errors.len(), 1);
}

#[test]
fn supported_list_is_recognised() {
    for m in supported_mnemonics() {
        for ops in ["", "rax", "rax, rbx", "0x10"] {
            if let Err(e) = assemble("x86_64", 0x1000, &format!("{} {}", m, ops)) {
                assert!(!e.contains("not supported"), "{} {}: {}", m, ops, e);
            }
        }
    }
}
