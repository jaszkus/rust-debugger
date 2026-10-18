use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

use crate::gui::AppState;

use super::protocol::router::{cap_response_size, respond_to_json, rpc_error, MAX_BODY_BYTES};

static AUTH_FAILS: std::sync::OnceLock<Mutex<Vec<std::time::Instant>>> = std::sync::OnceLock::new();
fn auth_fails() -> &'static Mutex<Vec<std::time::Instant>> {
    AUTH_FAILS.get_or_init(|| Mutex::new(Vec::new()))
}

#[derive(Clone)]
struct ServerState {
    app: Arc<Mutex<AppState>>,
    token: Arc<String>,
}

pub struct McpServer {
    #[allow(dead_code)]
    pub port: u16,
    pub actual_port: u16,
    stop_tx: Option<oneshot::Sender<()>>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl McpServer {
    pub fn start(port: u16, state: Arc<Mutex<AppState>>) -> Result<Self, String> {
        let std_listener = std::net::TcpListener::bind(format!("127.0.0.1:{}", port))
            .map_err(|e| format!("HTTP bind failed: {}", e))?;
        std_listener
            .set_nonblocking(true)
            .map_err(|e| format!("HTTP bind failed: {}", e))?;
        let actual_port = std_listener.local_addr().map(|a| a.port()).unwrap_or(port);

        let token: Arc<String> = Arc::new(std::env::var("RUST_DEBUGGER_TOKEN").unwrap_or_default());

        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("mcp-tokio")
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime: {}", e))?;

        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        let app = Router::new()
            .route("/", get(info_handler))
            .route(
                "/mcp",
                post(mcp_handler)
                    .get(fallback_404)
                    .put(fallback_404)
                    .delete(fallback_404)
                    .patch(fallback_404)
                    .head(fallback_404)
                    .options(fallback_404),
            )
            .fallback(fallback_404)
            .with_state(ServerState { app: state, token });

        let handle = std::thread::spawn(move || {
            let serve = async move {
                let listener = tokio::net::TcpListener::from_std(std_listener)
                    .expect("tokio listener from std");
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = stop_rx.await;
                    })
                    .await
            };
            let _ = rt.block_on(serve);
        });

        Ok(Self {
            port,
            actual_port,
            stop_tx: Some(stop_tx),
            handle: Some(handle),
        })
    }

    pub fn stop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
        let _ = self.handle.take();
    }
}

async fn info_handler() -> impl IntoResponse {
    Json(json!({
        "name": "rust-debugger",
        "version": env!("CARGO_PKG_VERSION"),
        "transport": "http",
        "endpoint": "POST /mcp",
        "tools": crate::mcp::tools::ALL_TOOLS.len(),
    }))
}

async fn fallback_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "Not Found")
}

fn loopback_host_ok(host: &str) -> bool {
    let h = host.trim();
    let no_port = if h.starts_with('[') {
        match h.find(']') {
            Some(end) => &h[1..end],
            None => h,
        }
    } else if h.matches(':').count() == 1 {
        h.rsplitn(2, ':').last().unwrap_or(h)
    } else if h.contains(':') && !h.contains('.') {
        h
    } else {
        h.rsplitn(2, ':').last().unwrap_or(h)
    };
    let no_port = no_port
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    no_port == "127.0.0.1" || no_port == "localhost" || no_port == "::1"
}

fn host_ok(headers: &HeaderMap) -> bool {
    match headers.get("host").and_then(|v| v.to_str().ok()) {
        Some(h) => loopback_host_ok(h),
        None => false,
    }
}

fn origin_ok(headers: &HeaderMap) -> bool {
    let Some(origin) = headers.get("origin") else {
        return true;
    };
    let origin = origin.to_str().unwrap_or("");
    let ok = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))
        .map(|rest| {
            let authority = rest.split('/').next().unwrap_or("");
            let host = authority.rsplitn(2, ':').last().unwrap_or("");
            let host = host.trim_start_matches('[').trim_end_matches(']');
            host == "127.0.0.1" || host == "localhost" || host == "::1"
        })
        .unwrap_or(false);
    ok
}

fn auth_ok(headers: &HeaderMap, token: &str) -> bool {
    if token.is_empty() {
        return true;
    }
    let header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    let expected = format!("Bearer {}", token);
    constant_time_eq(header.as_bytes(), expected.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = (a.len() ^ b.len()) as u8;
    diff |= ((a.len() ^ b.len()) >> 8) as u8;
    let max = a.len().max(b.len());
    for i in 0..max {
        let x = *a.get(i).unwrap_or(&0);
        let y = *b.get(i).unwrap_or(&0);
        diff |= x ^ y;
    }
    diff == 0
}

fn auth_rate_limited() -> bool {
    use std::time::Instant;
    let m = auth_fails();
    if let Ok(mut v) = m.lock() {
        let now = Instant::now();
        v.retain(|t| now.duration_since(*t).as_secs() < 10);
        return v.len() > 20;
    }
    false
}

fn note_auth_failure() {
    let m = auth_fails();
    if let Ok(mut v) = m.lock() {
        v.push(std::time::Instant::now());
        if v.len() > 64 {
            let excess = v.len() - 64;
            v.drain(..excess);
        }
    }
}

async fn mcp_handler(State(s): State<ServerState>, headers: HeaderMap, body: Bytes) -> Response {
    if !host_ok(&headers) {
        return (StatusCode::FORBIDDEN, "Forbidden: Host must be loopback").into_response();
    }
    if !origin_ok(&headers) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }
    if !auth_ok(&headers, &s.token) {
        note_auth_failure();
        if auth_rate_limited() {
            return (StatusCode::TOO_MANY_REQUESTS, "Too Many Requests").into_response();
        }
        return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    }
    let ctype = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ctype.to_ascii_lowercase().contains("application/json") {
        return Json(rpc_error(
            Value::Null,
            -32600,
            "Invalid Request: Content-Type must be application/json",
        ))
        .into_response();
    }
    if body.len() > MAX_BODY_BYTES {
        return Json(rpc_error(
            Value::Null,
            -32600,
            "Invalid Request: body exceeds 1 MiB",
        ))
        .into_response();
    }

    let json_req: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let err = json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": { "code": -32700, "message": format!("Parse error: {}", e) }
            });
            return Json(err).into_response();
        }
    };

    let state = s.app.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            respond_to_json(&json_req, &state)
        }))
    })
    .await;
    match outcome {
        Ok(Ok(response)) => {
            if response.is_null() {
                StatusCode::NO_CONTENT.into_response()
            } else {
                let capped = cap_response_size(response);
                Json(capped).into_response()
            }
        }
        Ok(Err(_)) | Err(_) => Json(rpc_error(
            Value::Null,
            -32603,
            "Internal error: request panicked",
        ))
        .into_response(),
    }
}
