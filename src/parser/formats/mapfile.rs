use crate::parser::model::Symbol;

pub fn parse_msvc_map(text: &str) -> Vec<Symbol> {
    let mut out: Vec<Symbol> = Vec::new();
    let mut code_secs: Vec<u32> = Vec::new();
    let mut have_sec_table = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with(';') {
            continue;
        }
        let mut toks = line.split_whitespace();
        let first = match toks.next() {
            Some(t) => t,
            None => continue,
        };
        let (sec, off) = match first.split_once(':') {
            Some((s, o)) if s.len() == 4 && o.len() == 8 => (s, o),
            _ => continue,
        };
        let sec_no = match u32::from_str_radix(sec, 16) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if u32::from_str_radix(off, 16).is_err() {
            continue;
        }
        let name = match toks.next() {
            Some(n) => n.to_string(),
            None => continue,
        };
        if name.len() == 9
            && name.ends_with('H')
            && name[..name.len() - 1]
                .chars()
                .all(|c| c.is_ascii_hexdigit())
        {
            have_sec_table = true;
            let _sec_name = toks.next();
            if toks.next() == Some("CODE") && !code_secs.contains(&sec_no) {
                code_secs.push(sec_no);
            }
            continue;
        }
        let mut addr = 0u64;
        let mut depth: i32 = 0;
        for t in toks {
            let opens = t.matches('(').count() as i32;
            let closes = t.matches(')').count() as i32;
            let inside = depth > 0 || opens > 0;
            depth += opens - closes;
            if inside || t.starts_with('/') {
                continue;
            }
            let h = t.trim_start_matches("0x").trim_start_matches("0X");
            if h.len() >= 4 && h.chars().all(|c| c.is_ascii_hexdigit())
                && let Ok(v) = u64::from_str_radix(h, 16) {
                    addr = v;
                    break;
                }
        }
        if addr == 0 || name.is_empty() {
            continue;
        }
        let is_function = !have_sec_table || code_secs.contains(&sec_no);
        out.push(Symbol {
            name,
            addr,
            size: 0,
            is_function,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_map() {
        let sample = "\n Start         Length     Name  Class\n \
            0001:00000000       _DllMain@12  10001000     f obj:dllmain.obj\n \
            0001:00000120  ?run@@YAHXZ (int __cdecl run(void)) 0x10011010 f obj:x.obj\n \
            0002:00000000       __imp_foo    10020000     f obj:y.obj\n";
        let syms = parse_msvc_map(sample);
        assert_eq!(syms.len(), 3, "{:?}", syms);
        assert_eq!(syms[0].name, "_DllMain@12");
        assert_eq!(syms[0].addr, 0x10001000);
        assert_eq!(syms[1].name, "?run@@YAHXZ");
        assert_eq!(syms[1].addr, 0x10011010);
        assert!(syms.iter().all(|s| s.addr != 0));
    }

    #[test]
    fn hex_looking_words_in_annotation_are_skipped() {
        let sample =
            " 0001:00000010  ?f@@YAHXZ (int __cdecl f(class dead beef)) 10011010 f x.obj\n";
        let syms = parse_msvc_map(sample);
        assert_eq!(syms.len(), 1, "{:?}", syms);
        assert_eq!(syms[0].addr, 0x10011010);
    }

    #[test]
    fn code_vs_data_from_section_table() {
        let sample = " Start         Length     Name                   Class\n \
            0001:00000000 00001000H .text                  CODE\n \
            0002:00000000 00000200H .data                  DATA\n\n \
            0001:00000010       _main        10001010     f x.obj\n \
            0002:00000020       _g_counter   10002020       x.obj\n";
        let syms = parse_msvc_map(sample);
        assert_eq!(syms.len(), 2, "{:?}", syms);
        assert!(syms[0].is_function);
        assert!(!syms[1].is_function);
    }

    #[test]
    fn ignores_garbage_lines() {
        let syms = parse_msvc_map("random text\n1234:zzzz foo bar\n0001:00000001\n");
        assert!(syms.is_empty(), "{:?}", syms);
    }
}
