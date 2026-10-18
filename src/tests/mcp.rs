use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

fn rpc(port: u16, body: &str) -> serde_json::Value {
    let decoded = http_body(port, body);
    eprintln!(
        "  [rpc] >> {} << {}",
        &body[..body.len().min(60)],
        &decoded[..decoded.len().min(60)]
    );
    serde_json::from_str(&decoded).expect("parse response JSON")
}

fn http_body(port: u16, body: &str) -> String {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        port,
        body.len(),
        body
    );
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .expect("timeout");
    stream.write_all(req.as_bytes()).expect("write");
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).expect("read");
    let text = String::from_utf8_lossy(&buf);
    let body_part = text.split("\r\n\r\n").nth(1).unwrap_or(&text);
    if body_part.contains("\r\n")
        && body_part
            .split("\r\n")
            .next()
            .map(|l| l.chars().all(|c| c.is_ascii_hexdigit()))
            .unwrap_or(false)
    {
        dechunk(body_part)
    } else {
        body_part.to_string()
    }
}

fn dechunk(body: &str) -> String {
    let mut out = String::new();
    let mut rest = body;
    while let Some((size_line, tail)) = rest.split_once("\r\n") {
        let size = usize::from_str_radix(size_line.trim(), 16).unwrap_or(0);
        if size == 0 {
            break;
        }
        if tail.len() < size {
            break;
        }
        out.push_str(&tail[..size]);
        rest = &tail[size + 2..];
    }
    out
}

fn start_server() -> (u16, crate::mcp::McpServer, Arc<Mutex<crate::gui::AppState>>) {
    let state = Arc::new(Mutex::new(crate::gui::AppState::new()));
    let server =
        crate::mcp::McpServer::start(0, state.clone()).expect("start server on ephemeral port");
    let port = server.actual_port;
    eprintln!("  [start_server] bound port {}", port);
    for _ in 0..50 {
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    (port, server, state)
}

#[test]
fn mcp_tools_list_and_call_shape() {
    let (port, mut server, _state) = start_server();

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
    );
    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    let tools = resp["result"]["tools"].as_array().expect("tools array");
    assert!(
        tools.len() > 200,
        "expected 200+ tools, got {}",
        tools.len()
    );
    let names: Vec<&str> = tools.iter().filter_map(|t| t["name"].as_str()).collect();
    for required in [
        "create_struct",
        "apply_data_type",
        "assemble",
        "patch_asm",
        "open_program",
        "list_data_types",
    ] {
        assert!(names.contains(&required), "missing tool {}", required);
    }

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"int_convert","arguments":{"value":"255"}}}"#,
    );
    assert_eq!(resp["id"], 2);
    assert_eq!(resp["result"]["isError"], false);
    let text = resp["result"]["content"][0]["text"].as_str().expect("text");
    assert!(
        text.starts_with('{'),
        "text should be JSON object, got: {}",
        &text[..text.len().min(80)]
    );
    assert!(
        !text.contains("<details>"),
        "no HTML details in default output"
    );
    assert!(
        resp["result"]["structuredContent"].is_object(),
        "structuredContent must be the raw value"
    );
    assert_eq!(
        resp["result"]["structuredContent"]["hex"], "0xff",
        "int_convert result payload"
    );

    server.stop();
}

#[test]
fn mcp_errors_are_jsonrpc_compliant() {
    let (port, mut server, _state) = start_server();

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/nope","params":{}}"#,
    );
    assert_eq!(resp["error"]["code"], -32601);

    let raw = http_body(
        port,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    if !raw.trim().is_empty() {
        let resp: serde_json::Value =
            serde_json::from_str(&raw).expect("parse notification response");
        assert!(
            resp.get("error").is_none(),
            "notifications must not produce errors"
        );
    }

    let resp = rpc(port, r#"{not json"#);
    assert_eq!(resp["error"]["code"], -32700);

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"patch_bytes","arguments":{"address":"zzz","bytes":"90"}}}"#,
    );
    assert!(
        resp["result"]["isError"] == true || resp["error"]["code"] == -32603,
        "bad args must produce a clean error, got: {}",
        resp
    );
    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":5,"method":"ping","params":{}}"#,
    );
    assert_eq!(
        resp["result"],
        serde_json::json!({}),
        "server must still answer after a bad call"
    );

    server.stop();
}

#[test]
fn mcp_type_and_asm_roundtrip() {
    let (port, mut server, _state) = start_server();

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_struct","arguments":{"name":"FuzzT"}}}"#,
    );
    assert_eq!(resp["result"]["isError"], false);
    let id = resp["result"]["structuredContent"]["id"]
        .as_u64()
        .expect("type id");

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"add_struct_field","arguments":{"type":"FuzzT","field":"a","field_type":"int"}}}"#,
    );
    assert_eq!(
        resp["result"]["structuredContent"]["offset"], 0,
        "first field of an empty struct must land at offset 0 (old code put it at 4)"
    );

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_data_type","arguments":{"name":"FuzzT"}}}"#,
    );
    let decl = resp["result"]["structuredContent"]["decl"]
        .as_str()
        .expect("decl");
    assert!(
        decl.contains("int a"),
        "decl should contain field, got {}",
        decl
    );

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"assemble","arguments":{"line":"mov eax, 5","address":"0x1000"}}}"#,
    );
    assert_eq!(resp["result"]["structuredContent"]["bytes"], "b805000000");
    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"assemble","arguments":{"line":"frobnicate rax","address":"0x1000"}}}"#,
    );
    assert_eq!(
        resp["result"]["isError"], true,
        "unsupported mnemonic must error cleanly"
    );

    let _ = id;
    server.stop();
}

#[test]
fn mcp_markdown_mode_opt_in() {
    let (port, mut server, _state) = start_server();
    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"int_convert","arguments":{"value":"255"},"_meta":{"format":"markdown","include_raw":false}}}"#,
    );
    let text = resp["result"]["content"][0]["text"].as_str().expect("text");
    assert!(
        text.contains("- **"),
        "markdown mode should render bullets, got: {}",
        &text[..text.len().min(120)]
    );
    assert!(
        !text.contains("<details>"),
        "include_raw=false drops the details block"
    );
    server.stop();
}

#[test]
fn program_slots_roundtrip() {
    let k32 = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/kernel32.dll");
    if !k32.exists() {
        eprintln!("skipped: fixture kernel32.dll not present");
        return;
    }
    let mut state = crate::gui::AppState::new();
    let bin = crate::parser::parse_file(&k32).unwrap();
    state.program.binary = Some(bin);
    state.program.comments.insert(0x1234, "hello".into());
    state
        .program
        .user_func_names
        .insert(0x9999, "renamed".into());

    let idx = crate::gui::save_program_slot(&mut state, "progA".into());
    state.program = crate::gui::ProgramData::default();
    assert!(state.program.binary.is_none());
    crate::gui::restore_program_slot(&mut state, idx).unwrap();
    assert!(state.program.binary.is_some(), "binary restored");
    assert_eq!(
        state.program.comments.get(&0x1234).map(|s| s.as_str()),
        Some("hello")
    );
    assert_eq!(
        state
            .program
            .user_func_names
            .get(&0x9999)
            .map(|s| s.as_str()),
        Some("renamed")
    );
    assert_eq!(state.current_program_label(), "progA");
}

#[test]
fn mcp_server_survives_panicking_tool() {
    let (port, mut server, _state) = start_server();
    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_function_signature","arguments":{"address":"0xffffffffffffffff"}}}"#,
    );
    assert!(resp.get("error").is_some() || resp["result"]["isError"] == true);
    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":2,"method":"ping","params":{}}"#,
    );
    assert_eq!(resp["result"], serde_json::json!({}));
    server.stop();
}

#[test]
fn mcp_int_convert_edge_inputs() {
    let (port, mut server, _s) = start_server();
    let call = |body: &str| rpc(port, body);
    let r = call(
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"int_convert","arguments":{"value":"0xff"}}}"#,
    );
    assert_eq!(r["result"]["structuredContent"]["hex"], "0xff");
    let r = call(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"int_convert","arguments":{"value":"0"}}}"#,
    );
    assert_eq!(r["result"]["structuredContent"]["hex"], "0x0");
    let r = call(
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"int_convert","arguments":{"value":"-1"}}}"#,
    );
    assert!(
        !r["result"]["isError"].as_bool().unwrap_or(true),
        "-1 must convert"
    );
    let r = call(
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"int_convert","arguments":{"value":"banana"}}}"#,
    );
    assert_eq!(
        r["result"]["isError"], true,
        "unparseable number must surface as tool error"
    );
    server.stop();
}

#[test]
fn mcp_unknown_tool_and_missing_args() {
    let (port, mut server, _s) = start_server();
    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"definitely_not_a_tool","arguments":{}}}"#,
    );
    assert_eq!(r["result"]["isError"], true, "unknown tool -> isError");
    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_strings","arguments":{}}}"#,
    );
    assert_eq!(r["result"]["isError"], true, "missing query -> isError");
    server.stop();
}

#[test]
fn mcp_notification_gets_no_response_body() {
    let (port, _server, _state) = start_server();
    let body = http_body(
        port,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    );
    assert!(
        body.trim().is_empty(),
        "notification must not produce a body, got: {}",
        body
    );
}

#[test]
fn mcp_batch_requests_answered_in_one_array() {
    let (_port, mut server, _s) = start_server();
    let port = _port;
    let payload = r#"[{"jsonrpc":"2.0","id":10,"method":"tools/list","params":{}},{"jsonrpc":"2.0","method":"notifications/x"}]"#;
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
    let req = format!(
        "POST /mcp HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        port, payload.len(), payload
    );
    use std::io::Read;
    s.write_all(req.as_bytes()).expect("write");
    s.set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .unwrap();
    let mut buf = String::new();
    s.read_to_string(&mut buf).expect("read");
    let _start = buf.find('[').expect("batch response contains a JSON array");
    let _end = buf.rfind(']').unwrap() + 1;
    let body_part = buf.split("\r\n\r\n").nth(1).unwrap_or(&buf);
    let candidate = if body_part.contains("\r\n") {
        dechunk(body_part)
    } else {
        body_part.to_string()
    };
    let v: serde_json::Value = serde_json::from_str(candidate.trim()).expect("parse batch array");
    assert!(v.is_array(), "batch must be answered with an array");
    assert_eq!(
        v.as_array().unwrap().len(),
        1,
        "notification filtered out of batch"
    );
    server.stop();
}

#[test]
fn mcp_live_tools_error_cleanly_without_debugger() {
    let (port, mut server, _s) = start_server();
    for (i, tool) in [
        "read_process_memory",
        "write_process_memory",
        "search_process_memory",
        "list_modules_live",
    ]
    .iter()
    .enumerate()
    {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{"name":"{}","arguments":{{"address":"0x400000","size":16,"query":"90"}}}}}}"#,
            i + 1,
            tool
        );
        let r = rpc(port, &body);
        if r["result"]["isError"] == serde_json::Value::Bool(false) {
            let text = r["result"]["content"][0]["text"].as_str().unwrap_or("");
            assert!(
                text.contains("attached") || text.contains("debugger") || text.len() < 400,
                "{} returned unexpected success payload",
                tool
            );
        }
    }
    server.stop();
}

#[test]
fn mcp_analysis_gated_tools_report_required_state() {
    let (port, mut server, _s) = start_server();
    for (i, (tool, args)) in [
        ("decompile_function", r#"{"address":"0x401000"}"#),
        ("get_xrefs_to", r#"{"address":"0x401000"}"#),
        ("get_stack_frame", r#"{"address":"0x401000"}"#),
        ("rename_function", r#"{"address":"0x401000","name":"x"}"#),
        ("get_stack_frame", r#"{"address":"0x401000"}"#),
    ]
    .iter()
    .enumerate()
    {
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{"name":"{}","arguments":{}}}}}"#,
            i + 1,
            tool,
            args
        );
        let r = rpc(port, &body);
        let is_err = r["result"]["isError"].as_bool().unwrap_or(false);
        let text = r["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or("")
            .to_string();
        assert!(
            is_err,
            "{} without analysis must be an explicit error, got: {}",
            tool,
            &text[..text.len().min(120)]
        );
        let lowered = text.to_lowercase();
        assert!(
            lowered.contains("analysis")
                || lowered.contains("binary")
                || lowered.contains("program")
                || lowered.contains("loaded"),
            "{} error should say what's missing: {}",
            tool,
            &text[..text.len().min(160)]
        );
    }
    server.stop();
}

#[test]
fn mcp_run_analysis_blocks_until_fresh_result() {
    let (port, mut server, state) = start_server();
    let dir = std::env::temp_dir().join(format!("rdbg_blking_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dump = dir.join("dump.bin");
    std::fs::write(&dump, vec![0xC3; 64]).unwrap();
    let args = serde_json::json!({"path": dump.to_string_lossy(), "base_address": "0x1000"});
    let r = rpc(
        port,
        &format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"load_memory_dump","arguments":{}}}}}"#,
            args
        ),
    );
    assert_eq!(r["result"]["isError"], false, "dump load failed");

    let st = state.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(400));
        let mut s = st.lock().unwrap();
        s.analysis = Some(std::sync::Arc::new(
            crate::analysis::AnalysisResult::default(),
        ));
        s.analysis_seq = s.analysis_seq.wrapping_add(1);
    });
    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"run_analysis","arguments":{"timeout_ms":20000}}}"#,
    );
    assert_eq!(
        r["result"]["isError"], false,
        "blocking run failed: {}",
        r["result"]["content"][0]["text"]
    );
    assert_eq!(r["result"]["structuredContent"]["status"], "done");

    let t0 = std::time::Instant::now();
    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"run_analysis","arguments":{"timeout_ms":5000}}}"#,
    );
    assert_eq!(r["result"]["isError"], true, "expected timeout error");
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(9),
        "waited too long"
    );
    server.stop();
}

#[test]
fn mcs_load_map_file_requires_binary_then_imports() {
    let (port, mut server, state) = start_server();

    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"load_map_file","arguments":{"path":"Z:/nonexistent.map"}}}"#,
    );
    assert_eq!(
        r["result"]["isError"], true,
        "map import without binary must error"
    );

    let dir = std::env::temp_dir().join(format!("rdbg_map_{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dump = dir.join("dump.bin");
    std::fs::write(&dump, vec![0xC3; 64]).unwrap();
    let map = dir.join("dump.map");
    std::fs::write(
        &map,
        "0001:00000000       real_fn   10001000     f obj:a.obj\n\
                            0001:00000010       second_fn 10001010     f obj:a.obj\n",
    )
    .unwrap();

    let args = serde_json::json!({"path": dump.to_string_lossy(), "base_address": "0x1000"});
    let r = rpc(
        port,
        &format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"load_memory_dump","arguments":{}}}}}"#,
            args
        ),
    );
    assert_eq!(r["result"]["isError"], false, "raw dump load failed");

    let args = serde_json::json!({"path": map.to_string_lossy()});
    let r = rpc(
        port,
        &format!(
            r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"load_map_file","arguments":{}}}}}"#,
            args
        ),
    );
    assert_eq!(r["result"]["isError"], false, "map import failed");
    let sc = &r["result"]["structuredContent"];
    assert_eq!(sc["symbols_added"], 2, "two symbols imported");
    assert_eq!(sc["symbols_total"], 2);

    let s = state.lock().unwrap();
    let bin = s.binary.as_ref().expect("binary loaded");
    assert!(bin.symbols.iter().any(|sy| sy.name == "real_fn"));
    drop(s);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mcp_envelope_ok_state_and_compact_echo_stripping() {
    let (port, mut server, _state) = start_server();

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"int_convert","arguments":{"value":"48879"}}}"#,
    );
    let sc = &resp["result"]["structuredContent"];
    assert_eq!(sc["ok"], true, "every success must carry ok:true");
    assert!(
        sc.get("state").is_none(),
        "plain tools must not carry a state snapshot by default"
    );
    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"int_convert","arguments":{"value":"48879","_snapshot":true}}}"#,
    );
    let sc = &resp["result"]["structuredContent"];
    assert!(
        sc["state"].is_object(),
        "_snapshot=true must attach the state snapshot"
    );
    assert_eq!(sc["state"]["binary_loaded"], false);

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_struct","arguments":{"name":"EnvCompact"}}}"#,
    );
    let sc = &resp["result"]["structuredContent"];
    assert_eq!(sc["ok"], true);
    assert!(
        sc.get("name").is_none(),
        "echoed 'name' must be stripped in compact mode, got: {}",
        sc
    );

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"create_struct","arguments":{"name":"EnvVerbose","_verbose":true}}}"#,
    );
    let sc = &resp["result"]["structuredContent"];
    assert_eq!(sc["name"], "EnvVerbose", "_verbose must keep input echo");

    server.stop();
}

#[test]
fn mcp_errors_are_structured_with_repair_hint() {
    let (port, mut server, _state) = start_server();

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"decompile_function","arguments":{"address":"0x1000"}}}"#,
    );
    assert_eq!(
        resp["result"]["isError"], true,
        "tool errors surface as isError"
    );
    let sc = &resp["result"]["structuredContent"];
    assert_eq!(sc["ok"], false);
    let err = sc["error"].as_str().unwrap_or("");
    assert!(
        err.contains("No disassembly loaded"),
        "error message preserved, got: {}",
        err
    );
    let hint = sc["hint"].as_str().expect("repair hint present");
    assert!(
        hint.contains("load_binary"),
        "hint names the repair action, got: {}",
        hint
    );
    assert_eq!(sc["tool"], "decompile_function");

    assert_eq!(sc["state"]["binary_loaded"], false);

    server.stop();
}

#[test]
fn mcp_search_tools_finds_tools_by_intent() {
    let (port, mut server, _s) = start_server();

    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"search_tools","arguments":{"query":"entropy"}}}"#,
    );
    assert_eq!(r["result"]["isError"], false);
    let items = r["result"]["structuredContent"]["items"]
        .as_array()
        .expect("items array");
    let se = items
        .iter()
        .find(|t| t["tool_name"] == "section_entropy")
        .expect("section_entropy found by keyword");
    assert_eq!(
        se["async_eligible"], true,
        "section_entropy is on the async allowlist"
    );

    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"search_tools","arguments":{"query":"int_convert","include_schema":true}}}"#,
    );
    let items = r["result"]["structuredContent"]["items"]
        .as_array()
        .expect("items array");
    assert_eq!(
        items[0]["tool_name"], "int_convert",
        "exact name ranks first"
    );
    assert!(
        items[0]["inputSchema"].is_object(),
        "include_schema attaches the schema"
    );

    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_tools","arguments":{}}}"#,
    );
    assert!(
        r["result"]["structuredContent"]["categories"].is_object(),
        "categories listed for an empty query"
    );

    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search_tools","arguments":{"category":"patching","limit":100}}}"#,
    );
    let items = r["result"]["structuredContent"]["items"]
        .as_array()
        .expect("items array");
    assert!(!items.is_empty() && items.iter().all(|t| t["category"] == "patching"));

    server.stop();
}

#[test]
fn mcp_tools_list_supports_pagination_and_lists_search_tools_first() {
    let (port, mut server, _s) = start_server();

    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"limit":5}}"#,
    );
    let page1 = r["result"]["tools"].as_array().expect("page 1");
    assert_eq!(page1.len(), 5);
    assert_eq!(
        page1[0]["name"], "search_tools",
        "discovery tool must be first"
    );
    assert_eq!(r["result"]["nextCursor"], "5");

    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{"limit":5,"cursor":"5"}}"#,
    );
    let page2 = r["result"]["tools"].as_array().expect("page 2");
    assert_eq!(page2.len(), 5);
    assert_ne!(page1[0]["name"], page2[0]["name"]);

    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}}"#,
    );
    assert!(r["result"]["tools"].as_array().unwrap().len() > 200);
    assert!(r["result"].get("nextCursor").is_none());

    server.stop();
}

#[test]
fn mcp_open_program_does_not_duplicate_loaded_binary() {
    let k32 = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/kernel32.dll");
    if !k32.exists() {
        eprintln!("skipped: fixture kernel32.dll not present");
        return;
    }
    let (port, mut server, _s) = start_server();
    let args = serde_json::json!({ "path": k32.to_string_lossy() });

    let r = rpc(
        port,
        &format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"load_binary","arguments":{}}}}}"#,
            args
        ),
    );
    assert_eq!(r["result"]["structuredContent"]["ok"], true);
    assert_eq!(
        r["result"]["structuredContent"]["state"]["open_programs"],
        1
    );

    let r = rpc(
        port,
        &format!(
            r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"open_program","arguments":{}}}}}"#,
            args
        ),
    );
    let sc = &r["result"]["structuredContent"];
    assert_eq!(sc["already_open"], true);
    assert_eq!(sc["open_programs"], 1);

    let r = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_open_programs","arguments":{}}}"#,
    );
    assert_eq!(
        r["result"]["structuredContent"]["count"], 1,
        "list must not repeat the current program"
    );

    server.stop();
}

#[test]
fn mcp_composite_and_async_tools() {
    let k32 = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/kernel32.dll");
    if !k32.exists() {
        eprintln!("skipped: fixture kernel32.dll not present");
        return;
    }
    let (port, mut server, state) = start_server();

    let args = serde_json::json!({ "path": k32.to_string_lossy() });
    let resp = rpc(
        port,
        &format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"load_binary","arguments":{}}}}}"#,
            args
        ),
    );
    assert_eq!(
        resp["result"]["structuredContent"]["ok"], true,
        "kernel32 load failed"
    );

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_binary_overview","arguments":{}}}"#,
    );
    assert_eq!(
        resp["result"]["isError"], false,
        "overview failed: {}",
        resp["result"]["content"][0]["text"]
    );
    let ov = resp["result"]["structuredContent"].clone();
    assert_eq!(ov["format"], "PE DLL");
    assert_eq!(ov["arch"], "x86_64");
    assert!(ov["sections"]
        .as_array()
        .map(|a| !a.is_empty())
        .unwrap_or(false));
    assert!(
        ov["sections"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["entropy"].is_number() && s["verdict"].is_string()),
        "every section must carry entropy + verdict"
    );
    assert!(
        ov["entropy_summary"]["verdict"].is_string(),
        "entropy summary present"
    );
    assert!(
        ov["imports"]["total"].as_u64().unwrap_or(0) > 10,
        "import summary present"
    );

    {
        let mut s = state.lock().unwrap();
        let bin = s.binary.as_ref().expect("binary still loaded").clone();
        let dis = crate::disasm::disassemble_binary(&bin).expect("disasm");
        let result = crate::analysis::auto_analyze(&dis, &bin);
        s.analysis_version += 1;
        s.analysis = Some(std::sync::Arc::new(result));
        s.disasm = Some(dis);
    }

    let entry = ov["entry_point"]
        .as_str()
        .expect("entry point string")
        .to_string();
    let body = format!(
        r#"{{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{{"name":"get_call_context","arguments":{{"address":"{}"}}}}}}"#,
        entry
    );
    let resp = rpc(port, &body);
    assert_eq!(
        resp["result"]["isError"], false,
        "call_context failed: {}",
        resp["result"]["content"][0]["text"]
    );
    let ctx = resp["result"]["structuredContent"].clone();
    assert_eq!(
        ctx["resolved_function"],
        serde_json::Value::String(entry.clone()),
        "entry address resolves to itself as containing function"
    );
    assert!(ctx["decompiled"].is_string(), "decompilation included");

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"run_async","arguments":{"tool":"search_in_decompiled","arguments":{"query":"the","limit":5}}}}"#,
    );
    assert_eq!(resp["result"]["isError"], false, "run_async failed");
    let job_id = resp["result"]["structuredContent"]["job_id"]
        .as_str()
        .expect("job_id")
        .to_string();

    let mut done = false;
    for i in 0..150 {
        std::thread::sleep(std::time::Duration::from_millis(200));
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":{},"method":"tools/call","params":{{"name":"poll_job","arguments":{{"job_id":"{}"}}}}}}"#,
            100 + i,
            job_id
        );
        let resp = rpc(port, &body);
        if resp["result"]["structuredContent"]["done"] == true {
            let sc = &resp["result"]["structuredContent"];
            assert_eq!(sc["ok"], true, "job result ok");
            assert!(sc.get("hits").is_some(), "job carried the tool payload");
            done = true;
            break;
        }
    }
    assert!(done, "async job never completed");

    let resp = rpc(
        port,
        r#"{"jsonrpc":"2.0","id":250,"method":"tools/call","params":{"name":"run_async","arguments":{"tool":"patch_bytes"}}}"#,
    );
    let sc = &resp["result"]["structuredContent"];
    assert_eq!(sc["ok"], false, "mutating tools must not be async-eligible");

    server.stop();
}

fn dispatched_tool_names() -> std::collections::BTreeSet<String> {
    let src = include_str!("../mcp/protocol/dispatch.rs");
    let mut names = std::collections::BTreeSet::new();
    for line in src.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix('"') {
            if let Some(arrow) = rest.find("\" =>") {
                names.insert(rest[..arrow].to_string());
            }
        }
    }
    names
}

#[test]
fn registry_names_are_unique_and_schemaful() {
    let mut seen = std::collections::BTreeSet::new();
    for (name, desc, schema_fn) in crate::mcp::tools::ALL_TOOLS {
        assert!(seen.insert(*name), "duplicate tool registered: {}", name);
        assert!(!desc.trim().is_empty(), "{}: empty description", name);
        let schema = schema_fn();
        assert_eq!(
            schema["type"], "object",
            "{}: schema must be an object",
            name
        );
        assert!(
            schema.get("properties").is_some(),
            "{}: schema missing properties",
            name
        );
    }
    assert!(
        seen.len() > 200,
        "registry unexpectedly small: {}",
        seen.len()
    );
}

#[test]
fn every_registered_tool_is_dispatchable() {
    let dispatched = dispatched_tool_names();
    let registered: Vec<_> = crate::mcp::tools::ALL_TOOLS
        .iter()
        .map(|(n, _, _)| *n)
        .collect();
    let missing: Vec<_> = registered
        .iter()
        .filter(|n| !dispatched.contains(**n))
        .collect();
    assert!(
        missing.is_empty(),
        "registered in ALL_TOOLS but NOT dispatchable: {:?}",
        missing
    );
}

#[test]
fn every_dispatched_tool_is_registered() {
    let dispatched = dispatched_tool_names();
    let registered: std::collections::BTreeSet<_> = crate::mcp::tools::ALL_TOOLS
        .iter()
        .map(|(n, _, _)| *n)
        .collect();
    let orphans: Vec<_> = dispatched
        .iter()
        .filter(|n| !registered.contains(n.as_str()))
        .collect();
    assert!(
        orphans.is_empty(),
        "dispatchable but NOT in ALL_TOOLS (MCP clients would never see them): {:?}",
        orphans
    );
}

#[test]
fn async_allowlist_names_all_exist() {
    for name in crate::mcp::tools::envelope::JOB_ALLOWLIST {
        assert!(
            crate::mcp::tools::ALL_TOOLS
                .iter()
                .any(|(n, _, _)| n == name),
            "async allowlist references unknown tool: {}",
            name
        );
    }
}
