use std::path::PathBuf;

fn fixture(name: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let sample = root.join("samples").join(name);
    if sample.exists() {
        return sample;
    }
    root.join("tests").join(name)
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn mutated(data: &[u8], seed: u64, flips: usize) -> Vec<u8> {
    let mut rng = Rng(seed ^ 0x9E3779B97F4A7C15);
    let mut out = data.to_vec();
    if out.is_empty() {
        return out;
    }
    for _ in 0..flips {
        let i = rng.below(out.len());
        out[i] = rng.next() as u8;
    }
    out
}

fn exercise(data: &[u8], arch: &str, base: u64) -> Result<(), String> {
    let bin = crate::parser::parse_raw_bytes(data.to_vec(), base, arch)?;
    let disasm = crate::disasm::disassemble_binary(&bin)?;
    let funcs = crate::analysis::function::detect_functions(
        &disasm.instructions,
        bin.entry_point,
        &bin.symbols,
    );
    let _ = crate::analysis::xref::build_xrefs(&disasm.instructions, &bin, None);
    let mut nr = crate::analysis::noreturn::NoReturnAnalyzer::new();
    nr.analyze(&disasm.instructions, &bin.imports, &funcs, None);
    for f in funcs.iter().take(8) {
        let _ = crate::analysis::cfg::build_cfg(&disasm.instructions, f.entry, f.end);
    }
    Ok(())
}

fn exercise_full(data: &[u8]) {
    let bin = crate::parser::parse_raw_bytes(data.to_vec(), 0x140000000, "x86_64")
        .expect("raw parse of mutant");
    let disasm = crate::disasm::disassemble_binary(&bin).expect("disasm of mutant");
    let _ = crate::analysis::auto_analyze(&disasm, &bin);
}

#[test]
#[ignore = "heavy fuzz: run with cargo test --release -- --ignored fuzz"]
fn fuzz_mutated_pe_never_panics() {
    let bases: Vec<(PathBuf, &str, u64)> = vec![
        (fixture("4CRY-inner.exe"), "x86_64", 0x140000000),
        (fixture("DLL3S_full-fix.dll"), "x86", 0x10000000),
    ];
    let mut cases = 0usize;
    let started = std::time::Instant::now();
    for (path, arch, base) in &bases {
        let data = std::fs::read(path).expect("read fixture");
        for seed in 0..60u64 {
            let flips = if seed % 3 == 0 { 4 } else { 16 };
            let mut mutated = mutated(&data, seed, flips);
            if seed % 2 == 0 {
                let n = mutated.len().min(0x400);
                for b in mutated.iter_mut().take(seed as usize % n) {
                    *b = b.wrapping_add(0x80);
                }
            }
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                exercise(&mutated, arch, *base)
            }));
            match result {
                Ok(Ok(_)) | Ok(Err(_)) => {}
                Err(_) => panic!("PANIC on mutated {} seed {}", path.display(), seed),
            }
            cases += 1;
        }
    }
    assert!(
        started.elapsed().as_secs() < 300,
        "fuzz suite took too long"
    );
    assert!(
        cases >= 120,
        "expected at least 120 fuzz cases, ran {}",
        cases
    );
}

#[test]
#[ignore = "heavy fuzz: run with cargo test --release -- --ignored fuzz"]
fn fuzz_full_analysis_never_hangs_or_panics() {
    let data = std::fs::read(fixture("kernel32.dll")).expect("read kernel32");
    let started = std::time::Instant::now();
    for seed in 0..4u64 {
        let mutated = mutated(&data, seed * 7919 + 1, 8);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| exercise_full(&mutated)));
        assert!(r.is_ok(), "analysis panicked on seed {}", seed);
        assert!(
            started.elapsed().as_secs() < 240,
            "analysis hung on seed {}",
            seed
        );
    }
}

#[test]
#[ignore = "heavy fuzz: run with cargo test --release -- --ignored fuzz"]
fn fuzz_crafted_headers_no_panic() {
    let data = std::fs::read(fixture("kernel32.dll")).expect("read kernel32");
    let mut crafted = data.clone();
    crafted[0x3C..0x40].copy_from_slice(&0xFFFFFFF0u32.to_le_bytes());
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = crate::parser::parse_file(std::path::Path::new("nonexistent"));
        let _ = exercise(&crafted, "x86_64", 0x180000000);
    }));
    assert!(r.is_ok(), "crafted e_lfanew panicked");

    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let bin = crate::parser::parse_raw_bytes(crafted.clone(), u64::MAX - 0x10000, "x86_64")?;
        let disasm = crate::disasm::disassemble_binary(&bin)?;
        let funcs = crate::analysis::function::detect_functions(
            &disasm.instructions,
            bin.entry_point,
            &bin.symbols,
        );
        for f in funcs.iter().take(4) {
            let _ = crate::analysis::cfg::build_cfg(&disasm.instructions, f.entry, f.end);
        }
        Ok::<(), String>(())
    }));
    assert!(r.is_ok(), "huge image_base panicked");
}
