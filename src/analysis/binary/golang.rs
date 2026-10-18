const MAGIC_F0: u32 = 0xFFFF_FFF0;
const MAGIC_F1: u32 = 0xFFFF_FFF1;
const MAGIC_FA: u32 = 0xFFFF_FFFA;
const MAGIC_FB: u32 = 0xFFFF_FFFB;

pub fn find_pclntab(data: &[u8]) -> Option<usize> {
    let mut off = 0usize;
    while off + 8 <= data.len() {
        let m = u32::from_le_bytes(data[off..off + 4].try_into().unwrap());
        if matches!(m, MAGIC_F0 | MAGIC_F1 | MAGIC_FA | MAGIC_FB) {
            let ptr_size = data[off + 7] as usize;
            if ptr_size == 4 || ptr_size == 8 {
                let nfunc = read_ptr(data, off + 8, ptr_size);
                if nfunc > 0 && nfunc <= 2_000_000 {
                    return Some(off);
                }
            }
        }
        off += 4;
    }
    None
}

pub fn pclntab_functions(data: &[u8], exec: &[(u64, u64)]) -> Vec<u64> {
    let base = match find_pclntab(data) {
        Some(o) => o,
        None => return Vec::new(),
    };
    if exec.is_empty() {
        return Vec::new();
    }
    let magic = u32::from_le_bytes(data[base..base + 4].try_into().unwrap());
    let ptr_size = data[base + 7] as usize;
    if ptr_size != 4 && ptr_size != 8 {
        return Vec::new();
    }
    let nfunc = read_ptr(data, base + 8, ptr_size) as usize;
    if nfunc == 0 || nfunc > 200_000 {
        return Vec::new();
    }
    let min_exec = exec.iter().map(|(s, _)| *s).min().unwrap_or(0);
    let in_exec = |a: u64| exec.iter().any(|(s, e)| a >= *s && a < *e);

    let mut out = Vec::new();
    if magic == MAGIC_F0 || magic == MAGIC_F1 {
        let tab = base + 8 + ptr_size;
        for i in 0..nfunc {
            let e = tab + i * 8;
            if e + 8 > data.len() {
                break;
            }
            let entry_off = u32::from_le_bytes(data[e..e + 4].try_into().unwrap()) as u64;
            let va = min_exec.wrapping_add(entry_off);
            if in_exec(va) {
                out.push(va);
            }
            if out.len() > 200_000 {
                break;
            }
        }
    } else {
        let tab = base + 8 + ptr_size;
        let mut raw = Vec::with_capacity(nfunc.min(200_000));
        for i in 0..nfunc {
            let e = tab + i * ptr_size;
            if e + ptr_size > data.len() {
                break;
            }
            raw.push(read_ptr(data, e, ptr_size));
            if raw.len() > 200_000 {
                break;
            }
        }
        let mut direct = 0usize;
        for &a in &raw {
            if a != 0 && in_exec(a) {
                out.push(a);
                direct += 1;
            }
        }
        if direct == 0 {
            if let Some(&min_entry) = raw.iter().filter(|&&a| a != 0).min() {
                let slide = min_exec.wrapping_sub(min_entry);
                for &a in &raw {
                    if a == 0 {
                        continue;
                    }
                    let va = a.wrapping_add(slide);
                    if in_exec(va) {
                        out.push(va);
                    }
                    if out.len() > 200_000 {
                        break;
                    }
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn read_ptr(data: &[u8], off: usize, ptr_size: usize) -> u64 {
    if ptr_size == 8 {
        if off + 8 > data.len() {
            return 0;
        }
        u64::from_le_bytes(data[off..off + 8].try_into().unwrap())
    } else {
        if off + 4 > data.len() {
            return 0;
        }
        u32::from_le_bytes(data[off..off + 4].try_into().unwrap()) as u64
    }
}
