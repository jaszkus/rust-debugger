use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

use crate::gui::AppState;

pub(crate) const MAX_BODY_BYTES: usize = 1 << 20;
pub(crate) const MAX_BATCH_ITEMS: usize = 64;
pub(crate) const MAX_RESPONSE_BYTES: usize = 1 << 20;

pub(crate) fn cap_response_size(resp: Value) -> Value {
    let s = match serde_json::to_string(&resp) {
        Ok(s) => s,
        Err(_) => return resp,
    };
    if s.len() <= MAX_RESPONSE_BYTES {
        return resp;
    }
    let id = resp.get("id").cloned().unwrap_or(Value::Null);
    rpc_error(
        id,
        -32600,
        &format!(
            "Response too large ({} bytes, max {}): narrow with limit/offset/filter or poll via run_async",
            s.len(),
            MAX_RESPONSE_BYTES
        ),
    )
}

pub(crate) fn respond_to_json(json_req: &Value, state: &Arc<Mutex<AppState>>) -> Value {
    match json_req {
        Value::Array(items) => {
            if items.is_empty() {
                return rpc_error(Value::Null, -32600, "Invalid Request: empty batch");
            }
            if items.len() > MAX_BATCH_ITEMS {
                return rpc_error(
                    Value::Null,
                    -32600,
                    &format!(
                        "Invalid Request: batch too large ({} > {})",
                        items.len(),
                        MAX_BATCH_ITEMS
                    ),
                );
            }
            let responses: Vec<Value> = items
                .iter()
                .filter_map(|item| {
                    let r = dispatch(item, state);
                    if r.is_null() {
                        None
                    } else {
                        Some(r)
                    }
                })
                .collect();
            if responses.is_empty() {
                Value::Null
            } else {
                Value::Array(responses)
            }
        }
        single => dispatch(single, state),
    }
}

pub(crate) fn dispatch(req: &Value, state: &Arc<Mutex<AppState>>) -> Value {
    match req.get("jsonrpc").and_then(|v| v.as_str()) {
        Some("2.0") => {}
        _ => {
            let id = req.get("id").cloned().unwrap_or(Value::Null);
            if req.get("id").is_none() && req.get("jsonrpc").is_none() {
                return Value::Null;
            }
            return rpc_error(id, -32600, "Invalid Request: jsonrpc must be \"2.0\"");
        }
    }
    let is_notification = req.get("id").is_none();
    let id = req.get("id").cloned().unwrap_or(Value::Null);
    let method = match req.get("method").and_then(|v| v.as_str()) {
        Some(m) => m,
        None => return rpc_error(id, -32600, "Invalid Request: missing method"),
    };

    if is_notification {
        match method {
            "notifications/initialized" => return Value::Null,
            _ => return Value::Null,
        }
    }

    match method {
        "initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": { "tools": {} },
                "serverInfo": {
                    "name": "rust-debugger",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }
        }),
        "notifications/initialized" => json!({ "jsonrpc": "2.0", "id": id, "result": null }),
        "tools/list" => {
            let all = crate::mcp::tools::list_descriptors();
            let total = all.len();
            let params = req.get("params");
            let start = params
                .and_then(|p| p.get("cursor"))
                .and_then(|c| c.as_str())
                .and_then(|c| c.parse::<usize>().ok())
                .unwrap_or(0)
                .min(total);
            let end = match params.and_then(|p| p.get("limit")).and_then(|l| l.as_u64()) {
                Some(l) => start.saturating_add((l as usize).clamp(1, 500)).min(total),
                None => total,
            };
            let page: Vec<Value> = all.into_iter().skip(start).take(end - start).collect();
            let mut result = json!({ "tools": page });
            if end < total {
                result["nextCursor"] = json!(end.to_string());
            }
            json!({ "jsonrpc": "2.0", "id": id, "result": result })
        }
        "tools/call" => {
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            if !params.is_object() && !params.is_null() {
                return rpc_error(id, -32602, "Invalid params: params must be an object");
            }
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if name.is_empty() {
                if params.get("name").is_some() {
                    return rpc_error(id, -32602, "Invalid params: name must be a string");
                }
                return rpc_error(id, -32602, "Invalid params: missing tool name");
            }
            let args = params.get("arguments").cloned().unwrap_or(json!({}));
            if !args.is_object() {
                return rpc_error(id, -32602, "Invalid params: arguments must be an object");
            }
            let meta = params.get("_meta").cloned().unwrap_or(Value::Null);
            let fmt = meta
                .get("format")
                .and_then(|v| v.as_str())
                .unwrap_or("json");
            let include_raw = meta
                .get("include_raw")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                crate::mcp::tools::envelope::call_enveloped(name, &args, state)
            }));

            match outcome {
                Ok(content) => {
                    let is_error = content.get("ok").and_then(|v| v.as_bool()) != Some(true);
                    let text = if fmt == "markdown" {
                        crate::mcp::tools::format::pretty_with_raw(&content, include_raw)
                    } else {
                        serde_json::to_string(&content).unwrap_or_else(|_| content.to_string())
                    };
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "result": {
                            "content": [{ "type": "text", "text": text }],
                            "structuredContent": content,
                            "isError": is_error
                        }
                    })
                }
                Err(_) => rpc_error(id, -32603, "Internal error: tool panicked"),
            }
        }
        "ping" => json!({ "jsonrpc": "2.0", "id": id, "result": {} }),
        _ => rpc_error(id, -32601, &format!("Method not found: {}", method)),
    }
}

pub(crate) fn rpc_error(id: Value, code: i32, msg: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": msg }
    })
}
