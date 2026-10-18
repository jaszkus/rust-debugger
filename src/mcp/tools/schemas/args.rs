use serde_json::{json, Value};

pub fn arg_query(args: &Value) -> Result<String, String> {
    ["query", "pattern"]
        .iter()
        .filter_map(|k| args.get(*k).and_then(|v| v.as_str()))
        .find(|s| !s.trim().is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            "Missing required argument: query (alias: pattern; must not be empty)".to_string()
        })
}

pub fn arg_opt_alias(args: &Value, keys: &[&str]) -> Option<String> {
    keys.iter()
        .filter_map(|k| args.get(*k).and_then(|v| v.as_str()))
        .find(|s| !s.is_empty())
        .map(|s| s.to_string())
}

pub fn arg_str_alias(args: &Value, keys: &[&str]) -> Result<String, String> {
    arg_opt_alias(args, keys).ok_or_else(|| {
        if keys.len() > 1 {
            format!(
                "Missing required argument: {} (alias: {})",
                keys[0],
                keys[1..].join(", ")
            )
        } else {
            format!("Missing required argument: {}", keys[0])
        }
    })
}

pub fn arg_ranged(
    args: &Value,
    key: &str,
    default: i64,
    min: i64,
    max: i64,
) -> Result<(usize, Option<i64>), String> {
    let v = match args.get(key) {
        None | Some(Value::Null) => return Ok((default.clamp(min, max) as usize, None)),
        Some(v) => v,
    };
    let n = match (v.as_i64(), v.as_u64()) {
        (Some(n), _) => n,
        (None, Some(_)) => i64::MAX,
        _ => return Err(format!("Invalid params: {} must be integer", key)),
    };
    if n < min {
        return Err(format!(
            "Invalid params: {} must be between {} and {} (got {})",
            key, min, max, n
        ));
    }
    if n > max {
        return Ok((max as usize, Some(n)));
    }
    Ok((n as usize, None))
}

pub fn push_warning(out: &mut Value, msg: impl Into<String>) {
    if let Some(obj) = out.as_object_mut() {
        let w = obj.entry("warnings").or_insert_with(|| json!([]));
        if let Some(arr) = w.as_array_mut() {
            arr.push(Value::String(msg.into()));
        }
    }
}

pub fn hex_needle(q: &str) -> Option<String> {
    let t = q.trim();
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(t.to_ascii_lowercase())
}

pub fn parse_addr(s: &str) -> Option<u64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    if t.starts_with('-') || t.starts_with('+') {
        return None;
    }
    let hex = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if hex.is_empty() || hex.len() > 16 {
        return None;
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}
