



use std::collections::HashMap;
use std::path::PathBuf;

fn repo_file(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel)
}


fn unescaped_quote(s: &str) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return Some(i),
            _ => i += 1,
        }
    }
    None
}

/// Parse a `("name", "description", schema_handler),` line from registry.rs.
/// The description keeps its raw escape sequences (as the README rows do).
fn parse_registry_line(line: &str) -> Option<(String, String)> {
    let rest = line.trim_start().strip_prefix("(\"")?;
    let name_end = rest.find('"')?;
    let name = &rest[..name_end];
    if name.is_empty() {
        return None;
    }
    let rest = rest[name_end + 1..]
        .strip_prefix(',')?
        .trim_start()
        .strip_prefix('"')?;
    let desc_end = unescaped_quote(rest)?;
    let desc = &rest[..desc_end];
    let rest = rest[desc_end + 1..].strip_prefix(',')?.trim_start();
    let first = rest.chars().next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    let handler_len = rest
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .count();
    let tail = &rest[handler_len..];
    if !tail.starts_with("),") || !tail[2..].trim().is_empty() {
        return None;
    }
    Some((name.to_string(), desc.to_string()))
}

fn parse_registry(src: &str) -> Vec<(String, String)> {
    src.lines().filter_map(parse_registry_line).collect()
}


fn parse_readme_row(line: &str) -> Option<(String, String)> {
    let rest = line.strip_prefix("| `")?;
    let name_end = rest.find('`')?;
    let name = &rest[..name_end];
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    let rest = rest[name_end + 1..].strip_prefix(" | ")?;
    let desc = rest.strip_suffix(" |")?;
    Some((name.to_string(), desc.replace("\\|", "|")))
}

fn parse_readme_rows(readme: &str) -> Option<Vec<(String, String)>> {
    let lines: Vec<&str> = readme.lines().collect();
    let start = lines
        .iter()
        .position(|l| l.contains("Full tool reference"))?;
    let mut rows = Vec::new();
    for &line in &lines[start..] {
        if line.starts_with("## ") {
            break;
        }
        if let Some(row) = parse_readme_row(line) {
            rows.push(row);
        }
    }
    Some(rows)
}



fn normalize_description(s: &str) -> String {
    s.replace('`', "")
        .replace("\u{00e2}\u{20ac}\u{201d}", "\u{2014}")
        .replace("\u{00e2}\u{20ac}\u{201c}", "\u{2013}")
        .replace("\u{00e2}\u{2020}\u{201d}", "\u{2194}")
}

#[test]
fn readme_tool_table_matches_registry() {
    let registry =
        std::fs::read_to_string(repo_file("src/mcp/protocol/registry.rs")).expect("read registry.rs");
    let readme = std::fs::read_to_string(repo_file("README.md")).expect("read README.md");

    let code_tools = parse_registry(&registry);
    assert!(
        !code_tools.is_empty(),
        "no tools parsed from registry.rs (pattern broken?)"
    );
    let readme_tools =
        parse_readme_rows(&readme).expect("README has no 'Full tool reference' section");

    assert_eq!(
        readme_tools.len(),
        code_tools.len(),
        "README has duplicate or missing tool rows"
    );
    let code_by_name: HashMap<&str, String> = code_tools
        .iter()
        .map(|(n, d)| (n.as_str(), normalize_description(d)))
        .collect();
    let readme_by_name: HashMap<&str, String> = readme_tools
        .iter()
        .map(|(n, d)| (n.as_str(), normalize_description(d)))
        .collect();

    let mut problems = Vec::new();
    for name in code_by_name.keys() {
        if !readme_by_name.contains_key(name) {
            problems.push(format!("missing in README: {name}"));
        }
    }
    for name in readme_by_name.keys() {
        if !code_by_name.contains_key(name) {
            problems.push(format!("not in code: {name}"));
        }
    }
    for (name, desc) in &code_by_name {
        if let Some(readme_desc) = readme_by_name.get(name)
            && readme_desc != desc
        {
            problems.push(format!("description changed: {name}"));
        }
    }
    assert!(
        problems.is_empty(),
        "README tool table is out of sync with registry.rs:\n{}",
        problems.join("\n")
    );

    let mut code_names: Vec<&str> = code_tools.iter().map(|(n, _)| n.as_str()).collect();
    let mut readme_names: Vec<&str> = readme_tools.iter().map(|(n, _)| n.as_str()).collect();
    code_names.sort_unstable();
    readme_names.sort_unstable();
    assert_eq!(
        readme_names, code_names,
        "README rows are not the same set as registry.rs"
    );

    eprintln!(
        "OK: README tool table matches registry.rs ({} tools)",
        code_tools.len()
    );
}
