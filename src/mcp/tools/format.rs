use serde_json::{json, Value};

use crate::analysis::detect::{Finding, ProtectionsReport, Source};
use crate::disasm::DisasmInstruction;

pub fn instruction(insn: &DisasmInstruction) -> Value {
    let asm = if insn.ops().is_empty() {
        insn.mnemonic.to_string()
    } else {
        format!("{} {}", insn.mnemonic, insn.operands)
    };
    json!({
        "address": format!("{:#x}", insn.address),
        "asm": asm,
        "bytes": hex_string(&insn.bytes),
    })
}

#[allow(dead_code)]
pub fn instruction_with(insn: &DisasmInstruction, refs: Vec<String>, xrefs_to: usize) -> Value {
    let mut v = instruction(insn);
    let obj = v.as_object_mut().unwrap();
    if !refs.is_empty() {
        obj.insert(
            "refs".into(),
            Value::Array(refs.into_iter().map(Value::String).collect()),
        );
    }
    if xrefs_to > 0 {
        obj.insert("xrefs_to".into(), Value::from(xrefs_to));
    }
    v
}

pub fn hex_string(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

#[allow(dead_code)]
pub fn push_hex_string(out: &mut String, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.reserve(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
}

pub fn finding(f: &Finding) -> Value {
    let mut v = json!({
        "category": f.category.as_str(),
        "severity": f.severity.as_str(),
        "id": f.id,
        "description": f.description,
        "source": f.source.as_str(),
        "confidence": f.confidence,
    });
    let obj = v.as_object_mut().unwrap();
    if let Some(addr) = f.address {
        obj.insert("address".into(), Value::String(format!("{:#x}", addr)));
    }
    if let Some(ev) = &f.evidence {
        obj.insert("evidence".into(), Value::String(ev.clone()));
    }
    v
}

const MAX_REPORT_FINDINGS: usize = 300;

pub fn protections_report(r: &ProtectionsReport) -> Value {
    let mut by_cat: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    let mut by_sev: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for f in &r.findings {
        *by_cat.entry(f.category.as_str()).or_insert(0) += 1;
        *by_sev.entry(f.severity.as_str()).or_insert(0) += 1;
    }

    let mut sorted: Vec<&Finding> = r.findings.iter().collect();
    sorted.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .then_with(|| a.category.as_str().cmp(b.category.as_str()))
            .then_with(|| a.id.cmp(b.id))
            .then_with(|| a.address.cmp(&b.address))
    });

    let mut groups: Vec<(&Finding, usize, Vec<u64>, Vec<String>)> = Vec::new();
    for f in &sorted {
        if let Some(g) = groups.iter_mut().find(|g| {
            g.0.id == f.id
                && g.0.category == f.category
                && g.0.severity == f.severity
                && g.0.source == f.source
        }) {
            g.1 += 1;
            if let Some(a) = f.address
                && g.2.len() < 8 && !g.2.contains(&a) {
                    g.2.push(a);
                }
            if let Some(e) = &f.evidence
                && g.3.len() < 3 && !g.3.contains(e) {
                    g.3.push(e.clone());
                }
        } else {
            groups.push((
                f,
                1,
                f.address.into_iter().collect(),
                f.evidence.iter().cloned().collect(),
            ));
        }
    }
    let group_count = groups.len();
    let grouped: Vec<Value> = groups
        .iter()
        .map(|(f, count, addrs, ev)| {
            let mut v = finding(f);
            if let Some(obj) = v.as_object_mut() {
                obj.insert("count".into(), json!(count));
                if *count > 1 {
                    obj.remove("address");
                    obj.remove("evidence");
                    if !addrs.is_empty() {
                        obj.insert(
                            "addresses".into(),
                            json!(addrs.iter().map(|a| format!("{:#x}", a)).collect::<Vec<_>>()),
                        );
                    }
                    if !ev.is_empty() {
                        obj.insert("evidence_samples".into(), json!(ev));
                    }
                }
            }
            v
        })
        .collect();

    let truncated = sorted.len() > MAX_REPORT_FINDINGS;
    let findings: Vec<Value> = sorted
        .iter()
        .take(MAX_REPORT_FINDINGS)
        .map(|f| finding(f))
        .collect();

    let mut out = json!({
        "total": r.findings.len(),
        "group_count": group_count,
        "by_category": by_cat,
        "by_severity": by_sev,
        "grouped_findings": grouped,
        "returned_findings": findings.len(),
        "findings_truncated": truncated,
        "findings": findings,
    });
    if truncated {
        out["findings_truncated_note"] = json!(format!(
            "Only the {} highest-severity findings are listed individually; by_category/by_severity and grouped_findings cover all {} findings.",
            MAX_REPORT_FINDINGS,
            r.findings.len()
        ));
    }
    if r.findings.iter().any(|f| f.source == Source::Import) {
        out["note"] = json!(
            "Findings with source \"import\" only mean the API is imported - weak evidence. System libraries import the same NT APIs, so confirm with disassembly before treating them as protections."
        );
    }
    out
}

const MAX_TABLE_ROWS: usize = 50;
const MAX_INLINE_ARRAY: usize = 12;
const MAX_VALUE_CHARS: usize = 240;

pub fn pretty_with_raw(v: &Value, include_raw: bool) -> String {
    let mut out = String::new();
    render_top_level(&mut out, v);

    if include_raw {
        out.push_str("\n\n<details><summary>raw JSON</summary>\n\n```json\n");
        out.push_str(&serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()));
        out.push_str("\n```\n\n</details>");
    }
    out
}

fn render_top_level(out: &mut String, v: &Value) {
    match v {
        Value::Object(map) => render_object(out, map, 0),
        Value::Array(arr) => render_array(out, arr, 0),
        Value::String(s) => out.push_str(s),
        other => out.push_str(&other.to_string()),
    }
}

fn render_object(out: &mut String, map: &serde_json::Map<String, Value>, depth: usize) {
    let mut scalars: Vec<(&String, &Value)> = Vec::new();
    let mut nested_objects: Vec<(&String, &serde_json::Map<String, Value>)> = Vec::new();
    let mut nested_arrays: Vec<(&String, &Vec<Value>)> = Vec::new();

    for (k, v) in map {
        match v {
            Value::Array(arr) => nested_arrays.push((k, arr)),
            Value::Object(o) => nested_objects.push((k, o)),
            _ => scalars.push((k, v)),
        }
    }

    let indent = "  ".repeat(depth);
    for (k, v) in &scalars {
        out.push_str(&indent);
        out.push_str("- **");
        out.push_str(k);
        out.push_str("**: ");
        out.push_str(&format_scalar(v));
        out.push('\n');
    }

    for (k, o) in &nested_objects {
        out.push_str(&indent);
        out.push_str("- **");
        out.push_str(k);
        out.push_str("**:\n");
        render_object(out, o, depth + 1);
    }

    for (k, arr) in &nested_arrays {
        let all_scalars = arr
            .iter()
            .all(|x| !matches!(x, Value::Array(_) | Value::Object(_)));
        if all_scalars {
            out.push_str(&indent);
            out.push_str("- **");
            out.push_str(k);
            out.push_str("** (");
            out.push_str(&arr.len().to_string());
            out.push_str("): ");
            if arr.len() <= MAX_INLINE_ARRAY {
                let joined: Vec<String> = arr.iter().map(format_scalar).collect();
                out.push_str(&joined.join(", "));
            } else {
                let head: Vec<String> = arr
                    .iter()
                    .take(MAX_INLINE_ARRAY)
                    .map(format_scalar)
                    .collect();
                out.push_str(&head.join(", "));
                out.push_str(&format!(", … (+{})", arr.len() - MAX_INLINE_ARRAY));
            }
            out.push('\n');
            continue;
        }

        out.push('\n');
        out.push_str(&"#".repeat(depth + 2));
        out.push(' ');
        out.push_str(k);
        out.push_str(&format!(" ({})\n\n", arr.len()));
        render_objects_as_table(out, arr);
    }
}

fn render_objects_as_table(out: &mut String, arr: &[Value]) {
    let mut keys: Vec<String> = Vec::new();
    for item in arr {
        if let Value::Object(m) = item {
            for k in m.keys() {
                if !keys.contains(k) {
                    keys.push(k.clone());
                }
            }
        }
    }
    if keys.is_empty() {
        for item in arr.iter().take(MAX_TABLE_ROWS) {
            out.push_str("- ");
            out.push_str(&format_scalar(item));
            out.push('\n');
        }
        if arr.len() > MAX_TABLE_ROWS {
            out.push_str(&format!("- … (+{} more)\n", arr.len() - MAX_TABLE_ROWS));
        }
        return;
    }

    out.push_str("| ");
    out.push_str(&keys.join(" | "));
    out.push_str(" |\n|");
    for _ in &keys {
        out.push_str("---|");
    }
    out.push('\n');

    let visible = arr.len().min(MAX_TABLE_ROWS);
    for item in arr.iter().take(visible) {
        out.push_str("| ");
        if let Value::Object(m) = item {
            let cells: Vec<String> = keys
                .iter()
                .map(|k| match m.get(k) {
                    Some(v) => format_scalar(v).replace('|', "\\|").replace('\n', " "),
                    None => "".into(),
                })
                .collect();
            out.push_str(&cells.join(" | "));
        }
        out.push_str(" |\n");
    }
    if arr.len() > visible {
        out.push_str(&format!(
            "\n_… (+{} more rows; full data in raw JSON below)_\n",
            arr.len() - visible
        ));
    }
}

fn render_array(out: &mut String, arr: &[Value], _depth: usize) {
    if arr.is_empty() {
        out.push_str("_(empty list)_\n");
        return;
    }
    let all_scalars = arr
        .iter()
        .all(|x| !matches!(x, Value::Array(_) | Value::Object(_)));
    if all_scalars {
        let joined: Vec<String> = arr
            .iter()
            .take(MAX_INLINE_ARRAY)
            .map(format_scalar)
            .collect();
        out.push_str(&joined.join(", "));
        if arr.len() > MAX_INLINE_ARRAY {
            out.push_str(&format!(", … (+{})", arr.len() - MAX_INLINE_ARRAY));
        }
        out.push('\n');
    } else {
        render_objects_as_table(out, arr);
    }
}

fn format_scalar(v: &Value) -> String {
    let raw = match v {
        Value::Null => "null".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().take(6).map(format_scalar).collect();
            if arr.len() > 6 {
                format!("[{}, … (+{})]", inner.join(", "), arr.len() - 6)
            } else {
                format!("[{}]", inner.join(", "))
            }
        }
        Value::Object(o) => {
            let inner: Vec<String> = o
                .iter()
                .take(4)
                .map(|(k, v)| format!("{}={}", k, format_scalar(v)))
                .collect();
            if o.len() > 4 {
                format!("{{{}, … (+{})}}", inner.join(", "), o.len() - 4)
            } else {
                format!("{{{}}}", inner.join(", "))
            }
        }
    };
    if raw.chars().count() > MAX_VALUE_CHARS {
        let head: String = raw.chars().take(MAX_VALUE_CHARS).collect();
        format!(
            "{}… (+{} chars)",
            head,
            raw.chars().count() - MAX_VALUE_CHARS
        )
    } else {
        raw
    }
}
