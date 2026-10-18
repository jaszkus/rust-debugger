pub fn demangle_name(name: &str) -> String {
    if name.starts_with("_R") || name.starts_with("__R") {
        let d = demangle_rust_v0(name);
        if d != name {
            return d;
        }
        return name.to_string();
    }
    if name.starts_with("_ZN") || name.starts_with("__ZN") {
        return demangle_rust(name);
    }

    if name.starts_with("$s") || name.starts_with("_T") {
        let d = demangle_swift(name);
        if d != name {
            return d;
        }
    }

    if (name.starts_with("-(")
        || name.starts_with("+(")
        || name.starts_with("-[")
        || name.starts_with("+["))
        && name.contains(' ')
    {
        return name.to_string();
    }

    if name.starts_with("?") {
        return demangle_msvc(name);
    }

    if name.starts_with("_Z") {
        for (prefix, label) in [
            ("_ZTV", "vtable"),
            ("_ZTT", "VTT"),
            ("_ZTI", "typeinfo"),
            ("_ZTS", "typeinfo name"),
        ] {
            if let Some(rest) = name.strip_prefix(prefix) {
                let inner = demangle_itanium(&format!("_Z{}", rest));
                if inner == rest {
                    return name.to_string();
                }
                return format!("{} for {}", label, inner);
            }
        }
        return demangle_itanium(name);
    }

    name.to_string()
}

fn demangle_rust(name: &str) -> String {
    let name = name
        .strip_prefix("__ZN")
        .or_else(|| name.strip_prefix("_ZN"))
        .unwrap_or(name);

    let mut result = String::new();
    let mut chars = name.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut len_str = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    len_str.push(d);
                    chars.next();
                } else {
                    break;
                }
            }

            let Ok(len) = len_str.parse::<usize>() else {
                break;
            };

            if chars.peek() == Some(&'h') && is_hash_suffix(&mut chars.clone(), len) {
                break;
            }

            let segment: String = chars.by_ref().take(len).collect();
            if segment.len() < len {
                break;
            }
            if !result.is_empty() {
                result.push_str("::");
            }
            result.push_str(&segment);
        } else if c == 'E' {
            break;
        } else {
            chars.next();
        }
    }

    if result.is_empty() {
        name.to_string()
    } else {
        result
    }
}

fn is_hash_suffix(chars: &mut std::iter::Peekable<std::str::Chars>, len: usize) -> bool {
    if chars.peek() != Some(&'h') {
        return false;
    }
    chars.next();
    let mut count = 0usize;
    while count < len.saturating_sub(1) {
        if let Some(&c) = chars.peek() {
            if c.is_ascii_hexdigit() {
                count += 1;
                chars.next();
            } else {
                break;
            }
        } else {
            break;
        }
    }
    count == len.saturating_sub(1) && (chars.peek().is_none() || chars.peek() == Some(&'E'))
}

fn demangle_itanium(name: &str) -> String {
    let name = name.strip_prefix("_Z").unwrap_or(name);

    let mut result = String::new();
    let mut chars = name.chars().peekable();

    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut len_str = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    len_str.push(d);
                    chars.next();
                } else {
                    break;
                }
            }

            let Ok(len) = len_str.parse::<usize>() else {
                break;
            };
            let segment: String = chars.by_ref().take(len).collect();
            if segment.len() < len {
                break;
            }
            if !result.is_empty() {
                result.push_str("::");
            }
            result.push_str(&segment);
        } else {
            break;
        }
    }

    if result.is_empty() {
        name.to_string()
    } else {
        result
    }
}

fn demangle_rust_v0(name: &str) -> String {
    let body = name
        .strip_prefix("__R")
        .or_else(|| name.strip_prefix("_R"))
        .unwrap_or(name);
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    for c in body.chars().chain(std::iter::once('\0')) {
        if c.is_ascii_alphanumeric() || c == '_' {
            cur.push(c);
        } else {
            if cur.len() >= 3 && cur.chars().any(|x| x.is_ascii_alphabetic()) {
                let mut s = cur.as_str();
                while s.len() > 3
                    && (s.starts_with('N')
                        || s.starts_with('C')
                        || s.starts_with('M')
                        || s.starts_with('X')
                        || s.starts_with('Y'))
                    && s.chars()
                        .nth(1)
                        .map(|c| c.is_ascii_lowercase())
                        .unwrap_or(false)
                {
                    s = &s[2..];
                    while s.starts_with(|c: char| c.is_ascii_digit()) {
                        s = &s[1..];
                    }
                    if s.is_empty() {
                        break;
                    }
                }
                if s.len() >= 2 {
                    parts.push(s.to_string());
                }
            }
            cur.clear();
        }
    }
    let mut seen = rustc_hash::FxHashSet::default();
    let mut uniq: Vec<String> = Vec::new();
    for p in parts {
        if seen.insert(p.clone()) {
            uniq.push(p);
        }
        if uniq.len() >= 6 {
            break;
        }
    }
    if uniq.is_empty() {
        name.to_string()
    } else {
        uniq.join("::")
    }
}

fn demangle_swift(name: &str) -> String {
    let body = name
        .strip_prefix("$s")
        .or_else(|| name.strip_prefix("_T"))
        .unwrap_or(name);
    let mut parts: Vec<String> = Vec::new();
    let mut cur = String::new();
    for c in body.chars().chain(std::iter::once('\0')) {
        if c.is_ascii_alphanumeric() || c == '_' {
            cur.push(c);
        } else {
            if cur.len() >= 2 && cur.chars().any(|x| x.is_ascii_alphabetic()) {
                parts.push(cur.clone());
            }
            cur.clear();
        }
    }
    if parts.is_empty() {
        return name.to_string();
    }
    let joined = parts.join("");
    let mut out: Vec<String> = Vec::new();
    let bytes = joined.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() && out.len() < 6 {
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_digit() {
            j += 1;
        }
        if j == i || j >= bytes.len() {
            break;
        }
        let len: usize = joined[i..j].parse().unwrap_or(0);
        if len == 0 || len > 64 || j + len > bytes.len() {
            break;
        }
        out.push(joined[j..j + len].to_string());
        i = j + len;
    }
    if out.len() >= 2 {
        out.join("::")
    } else if parts.len() >= 2 {
        parts[..parts.len().min(4)].join("::")
    } else {
        name.to_string()
    }
}

fn demangle_msvc(name: &str) -> String {
    let name = name.strip_prefix('?').unwrap_or(name);

    let parts: Vec<&str> = name.split('@').collect();
    if parts.is_empty() {
        return name.to_string();
    }

    let sym_name = parts[0];
    let mut scopes: Vec<&str> = Vec::new();
    for part in parts.iter().skip(1) {
        if part.is_empty() {
            break;
        }
        scopes.push(part);
    }
    let mut names: Vec<String> = Vec::new();
    let mut scope_chain = scopes;
    if sym_name.is_empty() {
        if let Some(first) = scope_chain.first() {
            names.push(first.to_string());
            scope_chain.remove(0);
        }
    } else {
        names.push(sym_name.to_string());
    }

    let mut out = Vec::new();
    for s in scope_chain.iter().rev() {
        out.push((*s).to_string());
    }
    out.extend(names);
    if out.is_empty() {
        return name.to_string();
    }
    out.join("::")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_demangle() {
        assert_eq!(
            demangle_name("_ZN4core3fmt5write17h1234567890abcdefE"),
            "core::fmt::write"
        );
        assert_eq!(
            demangle_name("_ZN3std2io5stdio6_print17h1234567890abcdefE"),
            "std::io::stdio::_print"
        );
        assert_eq!(
            demangle_name("_ZN4core5alloc6layout6Layout5clone17h1234567890abcdefE"),
            "core::alloc::layout::Layout::clone"
        );
    }

    #[test]
    fn test_cpp_demangle() {
        assert_eq!(demangle_name("_ZN3Foo3barEv"), "Foo::bar");
        assert_eq!(demangle_name("_ZN5Class6methodEi"), "Class::method");
    }

    #[test]
    fn test_msvc_demangle() {
        assert_eq!(demangle_name("?foo@Bar@@QAEXXZ"), "Bar::foo");
        assert_eq!(demangle_name("?method@Class@@QAEXXZ"), "Class::method");
        assert_eq!(demangle_name("?data@ns1@ns2@@3HA"), "ns2::ns1::data");
    }

    #[test]
    fn test_no_demangle() {
        assert_eq!(demangle_name("main"), "main");
        assert_eq!(demangle_name("printf"), "printf");
    }

    #[test]
    fn test_vtable_symbols() {
        assert_eq!(demangle_name("_ZTV3Foo"), "vtable for Foo");
        assert_eq!(demangle_name("_ZTI3Foo"), "typeinfo for Foo");
        assert_eq!(demangle_name("_ZTVq"), "_ZTVq");
    }
}
