#![allow(dead_code)]


use rayon::prelude::*;
use std::sync::OnceLock;

static POOL: OnceLock<rayon::ThreadPool> = OnceLock::new();

pub const WORKER_STACK_BYTES: usize = 8 << 20;

const MAX_AUTO_WORKERS: usize = 32;
const MAX_ENV_WORKERS: usize = 256;
const FALLBACK_WORKERS: usize = 4;

#[derive(Debug, PartialEq, Eq)]
enum ThreadsSetting {
    Auto,
    Fixed(usize),
    Invalid,
}

fn parse_threads(v: &str) -> ThreadsSetting {
    let v = v.trim();
    if v.is_empty() || v.eq_ignore_ascii_case("auto") {
        return ThreadsSetting::Auto;
    }
    match v.parse::<usize>() {
        Ok(0) => ThreadsSetting::Auto,
        Ok(n) => ThreadsSetting::Fixed(n.min(MAX_ENV_WORKERS)),
        Err(_) => ThreadsSetting::Invalid,
    }
}

fn auto_workers() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get().min(MAX_AUTO_WORKERS))
        .unwrap_or(FALLBACK_WORKERS)
}

fn configured_workers() -> usize {
    static CONFIGURED: OnceLock<usize> = OnceLock::new();
    *CONFIGURED.get_or_init(|| {
        let setting = match std::env::var("RD_THREADS") {
            Ok(v) => parse_threads(&v),
            Err(std::env::VarError::NotPresent) => ThreadsSetting::Auto,
            Err(std::env::VarError::NotUnicode(_)) => ThreadsSetting::Invalid,
        };
        match setting {
            ThreadsSetting::Fixed(n) => n,
            ThreadsSetting::Auto => auto_workers(),
            ThreadsSetting::Invalid => {
                eprintln!(
                    "warning: ignoring invalid RD_THREADS (want a number, 0 or 'auto'); using auto"
                );
                auto_workers()
            }
        }
    })
}

pub fn pool() -> &'static rayon::ThreadPool {
    POOL.get_or_init(|| {
        let mut n = configured_workers();
        loop {
            match rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .stack_size(WORKER_STACK_BYTES)
                .thread_name(|i| format!("rd-analyzer-{}", i))
                .build()
            {
                Ok(p) => return p,
                Err(e) if n > 1 => {
                    let next = n / 2;
                    eprintln!(
                        "warning: could not start {n} analyzer threads ({e}); retrying with {next}"
                    );
                    n = next;
                }
                Err(e) => panic!("rayon pool: cannot start even one analyzer thread ({e})"),
            }
        }
    })
}

pub fn workers() -> usize {
    POOL.get()
        .map(|p| p.current_num_threads())
        .unwrap_or_else(configured_workers)
}

pub fn install<R: Send>(f: impl FnOnce() -> R + Send) -> R {
    pool().install(f)
}

pub fn join<A: Send, B: Send>(
    a: impl FnOnce() -> A + Send,
    b: impl FnOnce() -> B + Send,
) -> (A, B) {
    pool().join(a, b)
}

pub const PAR_FUNCS: usize = 16;
pub const PAR_INSNS: usize = 4096;
pub const PAR_SECTIONS: usize = 2;
pub const PAR_SECTION_BYTES: usize = 64 * 1024;

pub fn should_parallelize(len: usize, min_len: usize) -> bool {
    len >= min_len && workers() >= 2
}

pub fn should_parallelize_sections(n_sections: usize, total_bytes: usize) -> bool {
    n_sections >= PAR_SECTIONS && total_bytes > PAR_SECTION_BYTES && workers() >= 2
}

pub const BIG_SECTION_BYTES: usize = 512 * 1024;
pub const CHUNK_BYTES: usize = 64 * 1024;
pub const CHUNK_OVERLAP: usize = 15;

const CHUNK_STRIDE: usize = CHUNK_BYTES - CHUNK_OVERLAP;

const _: () = assert!(CHUNK_OVERLAP < CHUNK_BYTES);
const _: () = assert!(BIG_SECTION_BYTES >= CHUNK_BYTES);

pub fn split_exec_range(start: usize, end: usize, vaddr: u64) -> Vec<(usize, usize, u64)> {
    if end <= start || end - start <= BIG_SECTION_BYTES {
        return vec![(start, end.max(start), vaddr)];
    }
    let len = end - start;
    let mut out = Vec::with_capacity(len.saturating_sub(CHUNK_OVERLAP).div_ceil(CHUNK_STRIDE));
    let mut cs = start;
    while cs < end {
        let ce = cs.saturating_add(CHUNK_BYTES).min(end);
        out.push((cs, ce, vaddr.saturating_add((cs - start) as u64)));
        if ce >= end {
            break;
        }
        cs = ce.saturating_sub(CHUNK_OVERLAP).max(cs + 1);
    }
    out
}

pub fn exec_sections<T: Send>(
    jobs: &[(usize, usize, u64)],
    decode: impl Fn(usize, usize, u64) -> (Vec<T>, usize) + Sync,
) -> (Vec<T>, usize) {
    if jobs.is_empty() {
        return (Vec::new(), 0);
    }
    let parts: Vec<(Vec<T>, usize)> =
        install(|| jobs.par_iter().map(|&(s, e, v)| decode(s, e, v)).collect());
    let total: usize = parts.iter().map(|(v, _)| v.len()).sum();
    let conflicts: usize = parts.iter().map(|(_, c)| *c).sum();
    let mut it = parts.into_iter();
    let mut out = match it.next() {
        Some((first, _)) => first,
        None => return (Vec::new(), 0),
    };
    out.reserve(total - out.len());
    for (mut v, _) in it {
        out.append(&mut v);
    }
    (out, conflicts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_or_empty_range_is_single_job() {
        let end = 10 + BIG_SECTION_BYTES;
        assert_eq!(split_exec_range(10, end, 0x1000), vec![(10, end, 0x1000)]);
        assert_eq!(split_exec_range(5, 5, 0), vec![(5, 5, 0)]);
    }

    #[test]
    fn inverted_range_becomes_empty_job() {
        assert_eq!(split_exec_range(9, 3, 0), vec![(9, 9, 0)]);
    }

    #[test]
    fn big_range_chunks_cover_everything_with_overlap() {
        let start = 100usize;
        let end = start + 3 * BIG_SECTION_BYTES + 7;
        let vaddr = 0x40_0000u64;
        let jobs = split_exec_range(start, end, vaddr);
        assert!(jobs.len() > 1);
        assert_eq!(jobs[0].0, start);
        assert_eq!(jobs.last().unwrap().1, end);
        for w in jobs.windows(2) {
            assert_eq!(w[0].1 - w[1].0, CHUNK_OVERLAP, "consecutive chunks overlap");
        }
        for &(s, e, v) in &jobs {
            assert!(s < e && e <= end);
            assert!(e - s <= CHUNK_BYTES);
            assert_eq!(v, vaddr + (s - start) as u64);
        }
    }

    #[test]
    fn chunk_count_fits_the_capacity_estimate() {
        for extra in [1usize, 7, CHUNK_BYTES, 3 * BIG_SECTION_BYTES + 7, 64 << 20] {
            let len = BIG_SECTION_BYTES + extra;
            let jobs = split_exec_range(0, len, 0);
            assert!(jobs.len() <= len.saturating_sub(CHUNK_OVERLAP).div_ceil(CHUNK_STRIDE));
        }
    }

    #[test]
    fn chunk_vaddr_saturates_instead_of_overflowing() {
        let jobs = split_exec_range(0, 3 * BIG_SECTION_BYTES, u64::MAX - 10);
        assert!(jobs.len() > 1);
        assert_eq!(jobs.last().unwrap().2, u64::MAX);
    }

    #[test]
    fn exec_sections_preserves_job_order() {
        let jobs: Vec<(usize, usize, u64)> =
            (0..200).map(|i| (i * 10, i * 10 + 10, i as u64)).collect();
        let (out, conflicts) = exec_sections(&jobs, |s, e, v| {
            ((s..e).map(|x| (x, v)).collect::<Vec<_>>(), 1)
        });
        let expected: Vec<(usize, u64)> = jobs
            .iter()
            .flat_map(|&(s, e, v)| (s..e).map(move |x| (x, v)))
            .collect();
        assert_eq!(out, expected);
        assert_eq!(conflicts, jobs.len());
    }

    #[test]
    fn exec_sections_empty_input() {
        let none: [(usize, usize, u64); 0] = [];
        let (out, conflicts): (Vec<u8>, usize) = exec_sections(&none, |_, _, _| (Vec::new(), 0));
        assert!(out.is_empty());
        assert_eq!(conflicts, 0);
    }

    #[test]
    fn exec_sections_runs_on_the_analyzer_pool() {
        let jobs = [(0usize, 1usize, 0u64); 4];
        let (names, _) = exec_sections(&jobs, |_, _, _| {
            (vec![std::thread::current().name().map(str::to_owned)], 0)
        });
        assert_eq!(names.len(), 4);
        for n in names {
            assert!(n
                .expect("pool threads are named")
                .starts_with("rd-analyzer-"));
        }
    }

    #[test]
    fn install_and_join_return_values() {
        assert_eq!(install(|| 21 * 2), 42);
        assert_eq!(join(|| 1, || "two"), (1, "two"));
    }

    #[test]
    fn workers_matches_the_real_pool() {
        let real = pool().current_num_threads();
        assert!(real >= 1);
        assert_eq!(workers(), real);
    }

    #[test]
    fn gates() {
        assert!(!should_parallelize_sections(1, 10 * PAR_SECTION_BYTES));
        assert!(!should_parallelize_sections(8, PAR_SECTION_BYTES));
        assert_eq!(
            should_parallelize_sections(8, 10 * PAR_SECTION_BYTES),
            workers() >= 2
        );
        assert!(!should_parallelize(PAR_FUNCS - 1, PAR_FUNCS));
        assert_eq!(should_parallelize(PAR_FUNCS, PAR_FUNCS), workers() >= 2);
    }

    #[test]
    fn rd_threads_parsing() {
        assert_eq!(parse_threads("8"), ThreadsSetting::Fixed(8));
        assert_eq!(parse_threads(" 8 "), ThreadsSetting::Fixed(8));
        assert_eq!(
            parse_threads("1000"),
            ThreadsSetting::Fixed(MAX_ENV_WORKERS)
        );
        assert_eq!(parse_threads("0"), ThreadsSetting::Auto);
        assert_eq!(parse_threads("auto"), ThreadsSetting::Auto);
        assert_eq!(parse_threads("AUTO"), ThreadsSetting::Auto);
        assert_eq!(parse_threads(""), ThreadsSetting::Auto);
        assert_eq!(parse_threads("abc"), ThreadsSetting::Invalid);
        assert_eq!(parse_threads("-1"), ThreadsSetting::Invalid);
        assert_eq!(parse_threads("3.5"), ThreadsSetting::Invalid);
    }
}
