// Axum-based static file server — the Rust port of the original serveb Node server.
// Serves the embedded browser UI, a JSON directory-listing API, and file downloads
// (with HTTP range support via tower-http, so videos stream/seek in the browser).
//
// - Binds dual-stack ([::] with IPV6_V6ONLY off) so it is reachable over both IPv6
//   and IPv4 on the LAN; falls back to IPv4-only if the OS refuses dual-stack.
// - Optional 4-digit PIN gate: when set, every request needs a valid session cookie,
//   obtained by submitting the PIN on the login page. Sessions live in the database
//   (one per device), so they survive restarts and can be logged out one by one.
// - Several "roots": id 0 is the main folder, the others are the public folders stored
//   in the database, so a phone can switch between them. Each root has a permission
//   level: view / + upload & new folder / + rename & delete (to the Recycle Bin).
// - Temporary share links (`/s/<token>`) with an optional 4-digit password live
//   outside the PIN gate; each one only exposes its own file/folder, read-only.

use crate::db::{self, Db, Link};
use crate::guard::{self, Lock, LoginGuard, Outcome};
use axum::{
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Path as UrlPath, Query, Request, State},
    http::{
        header::{CACHE_CONTROL, CONTENT_TYPE, COOKIE, RANGE, SET_COOKIE, USER_AGENT},
        HeaderMap, HeaderValue, StatusCode,
    },
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post, put},
    Form, Json, Router,
};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use socket2::{Domain, Protocol, Socket, Type};
use std::cmp::Ordering;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::sync::oneshot;
use tower::ServiceExt;
use tower_http::services::{ServeDir, ServeFile};

// The browser UI is embedded at compile time, so the shipped binary is self-contained.
const UI_HTML: &str = include_str!("../assets/browser.html");
const LOGIN_HTML: &str = include_str!("../assets/login.html");
const COOKIE_NAME: &str = "namsv_auth";

const GONE_HTML: &str = r#"<!DOCTYPE html><html lang="vi"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>namsv</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;padding:20px;box-sizing:border-box;background:radial-gradient(1200px 600px at 50% -10%,#171626,#0a0a0f);color:#e2e2f0;font-family:ui-monospace,'JetBrains Mono',monospace}
.card{max-width:340px;width:100%;text-align:center;background:#111118;border:1px solid #1e1e2e;border-radius:18px;padding:32px 26px;box-shadow:0 30px 70px rgba(0,0,0,.55)}
.big{font-size:44px}p{color:#6b6b8a;font-size:12px;line-height:1.7;margin:14px 0 0}</style></head>
<body><div class="card"><div class="big">🔗</div><p>{{MSG}}</p></div></body></html>"#;

/// Shared per-run context handed to every route + the auth middleware.
#[derive(Clone)]
struct AppCtx {
    /// Main folder (root id 0).
    root: PathBuf,
    pin: Option<String>,
    db: Arc<Db>,
    /// Wrong-PIN limiter; owned by the app so the control window can show/clear it.
    guard: Arc<LoginGuard>,
    notify: Notify,
}

/// Called with "links"/"logs"/"guard" whenever the server changes state the
/// control window shows, so it can refresh.
pub type Notify = Arc<dyn Fn(&str) + Send + Sync>;

impl AppCtx {
    /// Record an event and tell the control window its lists are stale.
    fn log(&self, ip: &str, action: &str, detail: &str) {
        self.db.log(ip, action, detail);
        (self.notify)("logs");
    }

    fn changed(&self, what: &str) {
        (self.notify)(what);
    }
}

fn client_ip(addr: &SocketAddr) -> String {
    // Dual-stack sockets report IPv4 clients as ::ffff:a.b.c.d — show them as plain IPv4.
    addr.ip().to_canonical().to_string()
}

#[derive(Serialize)]
struct Item {
    name: String,
    #[serde(rename = "isDir")]
    is_dir: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
}

#[derive(Serialize)]
struct ListResponse {
    path: String,
    items: Vec<Item>,
    /// db::PERM_* for this root (always view-only for share links).
    perm: u8,
}

#[derive(Deserialize)]
struct ListQuery {
    root: Option<i64>,
    path: Option<String>,
}

/// A handle to a running server. Dropping/`stop`-ing it shuts the server down gracefully.
pub struct RunningServer {
    shutdown: Option<oneshot::Sender<()>>,
    pub port: u16,
}

impl RunningServer {
    pub fn stop(mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

type HttpError = (StatusCode, String);

fn json_err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(serde_json::json!({ "error": msg.into() }))).into_response()
}

fn from_err((code, msg): HttpError) -> Response {
    json_err(code, msg)
}

fn no_store(mut resp: Response) -> Response {
    resp.headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    resp
}

fn cookie_get<'a>(header: &'a str, name: &str) -> Option<&'a str> {
    header.split(';').find_map(|kv| match kv.trim().split_once('=') {
        Some((k, v)) if k == name => Some(v),
        _ => None,
    })
}

fn cookie_has(header: &str, name: &str, val: &str) -> bool {
    cookie_get(header, name) == Some(val)
}

/// The login-session cookie sent with this request, if any.
fn session_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| cookie_get(c, COOKIE_NAME))
        .filter(|v| !v.is_empty())
}

fn with_cookie(mut resp: Response, cookie: String) -> Response {
    if let Ok(v) = cookie.parse() {
        resp.headers_mut().insert(SET_COOKIE, v);
    }
    resp
}

// ---------------- Authentication (optional 4-digit PIN) ----------------

#[derive(Deserialize)]
struct LoginForm {
    pin: String,
}

async fn login_page() -> Response {
    no_store(Html(LOGIN_HTML).into_response())
}

async fn login_submit(
    State(ctx): State<AppCtx>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Response {
    let ip = client_ip(&addr);

    // Checked before the PIN: while locked even the right PIN is refused, so the
    // lock actually slows guessing down.
    if let Err(lock) = ctx.guard.check(addr.ip()) {
        return Redirect::to(&lock_url(lock)).into_response();
    }

    if ctx.pin.as_deref() == Some(form.pin.trim()) {
        ctx.guard.success(addr.ip());
        let agent = headers
            .get(USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let session = match ctx.db.create_session(&ip, agent) {
            Ok(s) => s,
            Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e),
        };
        ctx.log(&ip, "login", "");
        ctx.changed("guard");
        ctx.changed("sessions");
        let cookie = format!(
            "{}={}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}",
            COOKIE_NAME,
            session.token,
            db::SESSION_SECS
        );
        return with_cookie(Redirect::to("/").into_response(), cookie);
    }

    ctx.log(&ip, "login_fail", "");
    let outcome = ctx.guard.failure(addr.ip());
    ctx.changed("guard");
    match outcome {
        Outcome::Retry { left } => Redirect::to(&format!("/__login?e=1&left={}", left)).into_response(),
        Outcome::Locked(lock) => {
            let who = if lock.global {
                "tất cả thiết bị".to_string()
            } else {
                guard::device_key(addr.ip())
            };
            ctx.log(&ip, "login_lock", &format!("{} · {} phút", who, lock.secs.div_ceil(60)));
            Redirect::to(&lock_url(lock)).into_response()
        }
    }
}

fn lock_url(lock: Lock) -> String {
    format!("/__login?e=lock&t={}&g={}", lock.secs, u8::from(lock.global))
}

/// `POST /__api/logout` — end this device's session.
async fn logout(
    State(ctx): State<AppCtx>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    if let Some(token) = session_cookie(&headers) {
        ctx.db.end_session(token);
        ctx.log(&client_ip(&addr), "logout", "");
        ctx.changed("sessions");
    }
    let target = if ctx.pin.is_some() { "/__login" } else { "/" };
    let cookie = format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0", COOKIE_NAME);
    with_cookie(Redirect::to(target).into_response(), cookie)
}

/// Gate every request behind the PIN when one is configured. Login routes are always
/// open; unauthenticated API calls get 401, everything else redirects to the login page.
async fn auth_mw(State(ctx): State<AppCtx>, req: Request, next: Next) -> Response {
    if ctx.pin.is_none() {
        return next.run(req).await;
    }
    let path = req.uri().path();
    if path == "/__login" || path == "/__api/login" {
        return next.run(req).await;
    }

    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| client_ip(&c.0))
        .unwrap_or_default();
    let authed = session_cookie(req.headers())
        .map(|token| ctx.db.session_valid(token, &ip))
        .unwrap_or(false);

    if authed {
        return next.run(req).await;
    }

    if path.starts_with("/__api/") {
        return json_err(StatusCode::UNAUTHORIZED, "unauthorized");
    }
    Redirect::to("/__login").into_response()
}

// ---------------- Path helpers ----------------

/// Resolve `rel` inside `base`, refusing anything that escapes it (`..`, absolute
/// paths, symlinks pointing outside). Returns the canonical path.
fn safe_join(base: &Path, rel: &str) -> Result<PathBuf, HttpError> {
    let base_c = std::fs::canonicalize(base)
        .map_err(|_| (StatusCode::NOT_FOUND, "Thư mục gốc không tồn tại".to_string()))?;
    let rel = rel.trim_start_matches(['/', '\\']);
    let full_c = std::fs::canonicalize(base_c.join(rel))
        .map_err(|_| (StatusCode::NOT_FOUND, "not found".to_string()))?;
    if !full_c.starts_with(&base_c) {
        return Err((StatusCode::FORBIDDEN, "Access denied".to_string()));
    }
    Ok(full_c)
}

fn read_items(dir: &Path) -> Result<Vec<Item>, HttpError> {
    let read = std::fs::read_dir(dir).map_err(|e| (StatusCode::NOT_FOUND, e.to_string()))?;

    let mut items: Vec<Item> = Vec::new();
    for entry in read {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let name = entry.file_name().to_string_lossy().to_string();
        let is_dir = entry.file_type().map(|t| t.is_dir()).unwrap_or(false);
        let size = if is_dir {
            None
        } else {
            entry.metadata().ok().map(|m| m.len())
        };
        items.push(Item { name, is_dir, size });
    }

    // Directories first, then case-insensitive alphabetical — matches the Node version.
    items.sort_by(|a, b| match (a.is_dir, b.is_dir) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
    });

    Ok(items)
}

/// Stream a single file (range requests, content-type, HEAD all handled by tower-http).
async fn serve_file(path: PathBuf, req: Request) -> Response {
    match ServeFile::new(path).oneshot(req).await {
        Ok(res) => res.map(Body::new),
        Err(never) => match never {},
    }
}

// ---------------- Roots (main folder + public folders) ----------------

struct Root {
    path: PathBuf,
    perm: u8,
}

impl Root {
    fn require(&self, perm: u8) -> Result<(), HttpError> {
        if self.perm >= perm {
            return Ok(());
        }
        let msg = if perm >= db::PERM_FULL {
            "Thư mục này không cho phép đổi tên hoặc xóa"
        } else {
            "Thư mục này chỉ cho xem"
        };
        Err((StatusCode::FORBIDDEN, msg.to_string()))
    }
}

fn root_of(ctx: &AppCtx, id: i64) -> Result<Root, HttpError> {
    if id == 0 {
        return Ok(Root {
            path: ctx.root.clone(),
            perm: ctx.db.main_perm(),
        });
    }
    ctx.db
        .folder(id)
        .map(|f| Root {
            path: PathBuf::from(f.path),
            perm: f.perm,
        })
        .ok_or((
            StatusCode::NOT_FOUND,
            "Thư mục này không còn được công khai".to_string(),
        ))
}

#[derive(Serialize)]
struct RootInfo {
    id: i64,
    name: String,
    perm: u8,
}

#[derive(Serialize)]
struct RootsResponse {
    /// Whether a PIN is required (the UI then offers "Đăng xuất").
    auth: bool,
    roots: Vec<RootInfo>,
}

async fn roots_handler(State(ctx): State<AppCtx>) -> Json<RootsResponse> {
    let mut roots = vec![RootInfo {
        id: 0,
        name: db::display_name(&ctx.root),
        perm: ctx.db.main_perm(),
    }];
    roots.extend(ctx.db.folders().into_iter().filter(|f| f.exists).map(|f| RootInfo {
        id: f.id,
        name: f.name,
        perm: f.perm,
    }));
    Json(RootsResponse {
        auth: ctx.pin.is_some(),
        roots,
    })
}

// ---------------- Handlers ----------------

async fn ui_handler() -> Response {
    no_store(Html(UI_HTML).into_response())
}

async fn list_handler(State(ctx): State<AppCtx>, Query(q): Query<ListQuery>) -> Response {
    let req_path = q.path.unwrap_or_else(|| "/".to_string());
    let result = root_of(&ctx, q.root.unwrap_or(0)).and_then(|root| {
        let dir = safe_join(&root.path, &req_path)?;
        Ok((read_items(&dir)?, root.perm))
    });
    match result {
        Ok((items, perm)) => Json(ListResponse {
            path: req_path,
            items,
            perm,
        })
        .into_response(),
        Err(e) => from_err(e),
    }
}

/// `GET /__f/<root>/<path>` — download/stream a file from any root.
async fn root_file_handler(
    State(ctx): State<AppCtx>,
    UrlPath((id, rel)): UrlPath<(i64, String)>,
    req: Request,
) -> Response {
    let path = match root_of(&ctx, id).and_then(|root| safe_join(&root.path, &rel)) {
        Ok(p) => p,
        Err(e) => return from_err(e),
    };
    if !path.is_file() {
        return json_err(StatusCode::NOT_FOUND, "not found");
    }
    serve_file(path, req).await
}

#[derive(Deserialize)]
struct UploadQuery {
    root: Option<i64>,
    path: Option<String>,
    name: String,
}

/// Streaming upload: `PUT /__api/upload?root=<id>&path=<dir>&name=<file>` with the raw
/// file bytes as the request body. The body is streamed straight to disk with a large
/// write buffer — no multipart parsing, no full-file buffering in memory — so a
/// single connection can saturate the link. Multiple files upload in parallel
/// from the client for maximum aggregate throughput.
async fn upload_handler(
    State(ctx): State<AppCtx>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<UploadQuery>,
    body: Body,
) -> Response {
    // Sanitize the filename — it must be a bare name, never a path.
    let name = match clean_name(&q.name) {
        Ok(n) => n,
        Err(e) => return from_err(e),
    };

    // Resolve the target directory and keep it inside the chosen root.
    let root = match root_of(&ctx, q.root.unwrap_or(0)) {
        Ok(r) => r,
        Err(e) => return from_err(e),
    };
    if let Err(e) = root.require(db::PERM_UPLOAD) {
        return from_err(e);
    }
    let dir_c = match safe_join(&root.path, q.path.as_deref().unwrap_or("/")) {
        Ok(p) if p.is_dir() => p,
        Ok(_) => return json_err(StatusCode::NOT_FOUND, "folder not found"),
        Err(e) => return from_err(e),
    };

    // Never clobber an existing file: pick "name (1).ext" etc. if needed.
    let dest = unique_path(&dir_c, &name);
    let final_name = dest
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| name.to_string());

    let file = match tokio::fs::File::create(&dest).await {
        Ok(f) => f,
        Err(e) => return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let mut writer = tokio::io::BufWriter::with_capacity(1 << 20, file);
    let mut stream = body.into_data_stream();
    let mut total: u64 = 0;

    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                if let Err(e) = writer.write_all(&bytes).await {
                    let _ = writer.flush().await;
                    let _ = tokio::fs::remove_file(&dest).await;
                    return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
                }
                total += bytes.len() as u64;
            }
            Err(e) => {
                // Client aborted or connection dropped — clean up the partial file.
                let _ = writer.flush().await;
                let _ = tokio::fs::remove_file(&dest).await;
                return json_err(StatusCode::BAD_REQUEST, e.to_string());
            }
        }
    }

    if let Err(e) = writer.flush().await {
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string());
    }

    ctx.log(&client_ip(&addr), "upload", &db::clean_path(&dest));

    (
        StatusCode::OK,
        Json(serde_json::json!({ "ok": true, "name": final_name, "size": total })),
    )
        .into_response()
}

/// Return a destination path inside `dir` that does not overwrite an existing file.
fn unique_path(dir: &Path, name: &str) -> PathBuf {
    let candidate = dir.join(name);
    if !candidate.exists() {
        return candidate;
    }
    let p = Path::new(name);
    let stem = p
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| name.to_string());
    let ext = p
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    for i in 1..100_000 {
        let cand = dir.join(format!("{} ({}){}", stem, i, ext));
        if !cand.exists() {
            return cand;
        }
    }
    candidate
}

// ---------------- File operations (new folder / rename / delete) ----------------

/// A bare file/folder name that is safe to create on Windows: no separators or
/// reserved characters (':' would even address an NTFS alternate stream), no device
/// names like CON/NUL, and no trailing dots/spaces (Windows silently strips them).
fn clean_name(raw: &str) -> Result<String, HttpError> {
    let bad = |m: &str| Err((StatusCode::BAD_REQUEST, m.to_string()));
    let name = raw.trim().trim_end_matches(['.', ' ']);
    if name.is_empty() {
        return bad("Tên không hợp lệ");
    }
    if name.chars().count() > 200 {
        return bad("Tên quá dài");
    }
    if name.chars().any(|c| c.is_control() || r#"<>:"/\|?*"#.contains(c)) {
        return bad(r#"Tên không được chứa các ký tự < > : " / \ | ? *"#);
    }
    const RESERVED: [&str; 22] = [
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7",
        "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = name.split('.').next().unwrap_or("").trim_end().to_ascii_uppercase();
    if RESERVED.contains(&stem.as_str()) {
        return bad("Tên này được Windows dành riêng, hãy chọn tên khác");
    }
    Ok(name.to_string())
}

/// Resolve an item for rename/delete; the root folder itself is off limits.
fn item_in(root: &Root, rel: &str) -> Result<PathBuf, HttpError> {
    let item = safe_join(&root.path, rel)?;
    if std::fs::canonicalize(&root.path).map(|r| r == item).unwrap_or(true) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Không thể đổi tên hoặc xóa thư mục gốc".to_string(),
        ));
    }
    Ok(item)
}

#[derive(Deserialize)]
struct NameReq {
    root: Option<i64>,
    /// mkdir: the parent folder; rename: the item to rename
    path: String,
    name: String,
}

#[derive(Deserialize)]
struct PathReq {
    root: Option<i64>,
    path: String,
}

fn do_mkdir(ctx: &AppCtx, req: &NameReq) -> Result<PathBuf, HttpError> {
    let root = root_of(ctx, req.root.unwrap_or(0))?;
    root.require(db::PERM_UPLOAD)?;
    let name = clean_name(&req.name)?;
    let parent = safe_join(&root.path, &req.path)?;
    if !parent.is_dir() {
        return Err((StatusCode::NOT_FOUND, "Không tìm thấy thư mục".to_string()));
    }
    let dest = parent.join(&name);
    if dest.exists() {
        return Err((
            StatusCode::CONFLICT,
            "Đã có file hoặc thư mục trùng tên".to_string(),
        ));
    }
    std::fs::create_dir(&dest)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Không tạo được: {}", e)))?;
    Ok(dest)
}

fn do_rename(ctx: &AppCtx, req: &NameReq) -> Result<(PathBuf, PathBuf), HttpError> {
    let root = root_of(ctx, req.root.unwrap_or(0))?;
    root.require(db::PERM_FULL)?;
    let name = clean_name(&req.name)?;
    let item = item_in(&root, &req.path)?;
    let dest = item
        .parent()
        .ok_or((StatusCode::BAD_REQUEST, "Không đổi tên được".to_string()))?
        .join(&name);
    if dest.exists() {
        // A case-only change ("a.txt" → "A.txt") resolves to the same file on Windows.
        let same_file = std::fs::canonicalize(&dest).map(|d| d == item).unwrap_or(false);
        if !same_file {
            return Err((
                StatusCode::CONFLICT,
                "Đã có file hoặc thư mục trùng tên".to_string(),
            ));
        }
    }
    std::fs::rename(&item, &dest)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Không đổi tên được: {}", e)))?;
    Ok((item, dest))
}

/// Move to the Recycle Bin so a slip of the finger on the phone can be undone.
#[cfg(not(test))]
fn move_to_trash(path: &Path) -> Result<(), String> {
    trash::delete(path).map_err(|e| e.to_string())
}

/// Tests must not fill the developer's Recycle Bin; see `trash_really_recycles`.
#[cfg(test)]
fn move_to_trash(path: &Path) -> Result<(), String> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    }
    .map_err(|e| e.to_string())
}

async fn mkdir_handler(
    State(ctx): State<AppCtx>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<NameReq>,
) -> Response {
    match do_mkdir(&ctx, &req) {
        Ok(dest) => {
            ctx.log(&client_ip(&addr), "mkdir", &db::clean_path(&dest));
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Err(e) => from_err(e),
    }
}

async fn rename_handler(
    State(ctx): State<AppCtx>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<NameReq>,
) -> Response {
    match do_rename(&ctx, &req) {
        Ok((from, to)) => {
            let detail = format!("{} → {}", db::clean_path(&from), db::display_name(&to));
            ctx.log(&client_ip(&addr), "rename", &detail);
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Err(e) => from_err(e),
    }
}

async fn delete_handler(
    State(ctx): State<AppCtx>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<PathReq>,
) -> Response {
    let target = match root_of(&ctx, req.root.unwrap_or(0)).and_then(|root| {
        root.require(db::PERM_FULL)?;
        item_in(&root, &req.path)
    }) {
        Ok(p) => p,
        Err(e) => return from_err(e),
    };
    // The shell's file operation is blocking COM work — keep it off the async workers.
    let t = target.clone();
    match tokio::task::spawn_blocking(move || move_to_trash(&t)).await {
        Ok(Ok(())) => {
            ctx.log(&client_ip(&addr), "delete", &db::clean_path(&target));
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, format!("Không xóa được: {}", e)),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

// ---------------- QR codes ----------------

/// SVG QR code for `text` — the LAN address or a share link, to scan with a phone.
pub fn qr_svg(text: &str) -> Option<String> {
    use qrcode::{render::svg, EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(240, 240)
            .quiet_zone(true)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .build(),
    )
}

#[derive(Deserialize)]
struct QrQuery {
    text: String,
}

async fn qr_handler(Query(q): Query<QrQuery>) -> Response {
    if q.text.is_empty() || q.text.len() > 1000 {
        return json_err(StatusCode::BAD_REQUEST, "invalid text");
    }
    match qr_svg(&q.text) {
        Some(svg) => (
            [(CONTENT_TYPE, "image/svg+xml"), (CACHE_CONTROL, "no-store")],
            svg,
        )
            .into_response(),
        None => json_err(StatusCode::BAD_REQUEST, "cannot encode"),
    }
}

// ---------------- Share-link management (behind the PIN gate) ----------------

#[derive(Deserialize)]
struct NewLinkReq {
    root: Option<i64>,
    path: String,
    hours: i64,
    pin: Option<String>,
}

async fn links_list(State(ctx): State<AppCtx>) -> Json<Vec<Link>> {
    Json(ctx.db.links())
}

async fn links_create(
    State(ctx): State<AppCtx>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(req): Json<NewLinkReq>,
) -> Response {
    let target = match root_of(&ctx, req.root.unwrap_or(0))
        .and_then(|root| safe_join(&root.path, &req.path))
    {
        Ok(p) => p,
        Err(e) => return from_err(e),
    };
    match ctx.db.create_link(&target, req.hours, req.pin) {
        Ok(link) => {
            ctx.log(&client_ip(&addr), "link_create", &link.name);
            ctx.changed("links");
            Json(link).into_response()
        }
        Err(e) => json_err(StatusCode::BAD_REQUEST, e),
    }
}

async fn links_delete(
    State(ctx): State<AppCtx>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    UrlPath(id): UrlPath<i64>,
) -> Response {
    match ctx.db.delete_link(id) {
        Some(link) => {
            ctx.log(&client_ip(&addr), "link_delete", &link.name);
            ctx.changed("links");
            Json(serde_json::json!({ "ok": true })).into_response()
        }
        None => json_err(StatusCode::NOT_FOUND, "not found"),
    }
}

// ---------------- Public share links: /s/<token> ----------------

enum Access {
    Granted(Link),
    NeedPin,
    Gone(&'static str),
}

fn share_cookie(token: &str) -> String {
    format!("ns_{}", token)
}

fn valid_token(t: &str) -> bool {
    !t.is_empty() && t.len() <= 64 && t.chars().all(|c| c.is_ascii_alphanumeric())
}

fn share_access(ctx: &AppCtx, token: &str, headers: &HeaderMap) -> Access {
    let link = match valid_token(token).then(|| ctx.db.link_by_token(token)).flatten() {
        Some(l) => l,
        None => return Access::Gone("Link không tồn tại hoặc đã bị thu hồi."),
    };
    if link.expired {
        return Access::Gone("Link này đã hết hạn.");
    }
    if link.pin.is_none() {
        return Access::Granted(link);
    }
    let cookie_ok = headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|c| cookie_has(c, &share_cookie(token), &link.secret))
        .unwrap_or(false);
    if cookie_ok {
        Access::Granted(link)
    } else {
        Access::NeedPin
    }
}

/// Resolve access for a share-link API call, or the error response to send.
fn share_api_access(ctx: &AppCtx, token: &str, headers: &HeaderMap) -> Result<Link, Response> {
    match share_access(ctx, token, headers) {
        Access::Granted(link) => Ok(link),
        Access::NeedPin => Err(json_err(StatusCode::UNAUTHORIZED, "unauthorized")),
        Access::Gone(msg) => Err(json_err(StatusCode::GONE, msg)),
    }
}

fn gone_page(msg: &str) -> Response {
    no_store((StatusCode::GONE, Html(GONE_HTML.replace("{{MSG}}", msg))).into_response())
}

async fn share_page(
    State(ctx): State<AppCtx>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    UrlPath(token): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    match share_access(&ctx, &token, &headers) {
        Access::Granted(link) => {
            ctx.db.link_opened(link.id);
            ctx.log(&client_ip(&addr), "link_open", &link.name);
            ctx.changed("links");
            no_store(Html(UI_HTML).into_response())
        }
        Access::NeedPin => no_store(Html(LOGIN_HTML).into_response()),
        Access::Gone(msg) => gone_page(msg),
    }
}

async fn share_login(
    State(ctx): State<AppCtx>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    UrlPath(token): UrlPath<String>,
    Form(form): Form<LoginForm>,
) -> Response {
    let link = match valid_token(&token).then(|| ctx.db.link_by_token(&token)).flatten() {
        Some(l) if !l.expired => l,
        _ => return gone_page("Link không tồn tại hoặc đã hết hạn."),
    };
    let base = format!("/s/{}", token);
    let Some(pin) = link.pin.as_deref() else {
        return Redirect::to(&base).into_response();
    };
    if link.locked {
        return Redirect::to(&format!("{}?e=lock", base)).into_response();
    }

    let ip = client_ip(&addr);
    if form.pin.trim() == pin {
        ctx.db.link_reset_fails(link.id);
        let max_age = (link.expires_at - db::now()).max(1);
        let cookie = format!(
            "{}={}; Path={}; HttpOnly; SameSite=Lax; Max-Age={}",
            share_cookie(&token),
            link.secret,
            base,
            max_age
        );
        return with_cookie(Redirect::to(&base).into_response(), cookie);
    }

    let fails = ctx.db.link_failed(link.id);
    ctx.log(&ip, "link_fail", &link.name);
    ctx.changed("links");
    if fails >= db::MAX_LINK_FAILS {
        ctx.log(&ip, "link_lock", &link.name);
        Redirect::to(&format!("{}?e=lock", base)).into_response()
    } else {
        Redirect::to(&format!("{}?e=1", base)).into_response()
    }
}

#[derive(Serialize)]
struct ShareInfo {
    name: String,
    kind: String,
    expires_at: i64,
}

async fn share_info(
    State(ctx): State<AppCtx>,
    UrlPath(token): UrlPath<String>,
    headers: HeaderMap,
) -> Response {
    match share_api_access(&ctx, &token, &headers) {
        Ok(link) => Json(ShareInfo {
            name: link.name,
            kind: link.kind,
            expires_at: link.expires_at,
        })
        .into_response(),
        Err(resp) => resp,
    }
}

async fn share_list(
    State(ctx): State<AppCtx>,
    UrlPath(token): UrlPath<String>,
    headers: HeaderMap,
    Query(q): Query<ListQuery>,
) -> Response {
    let link = match share_api_access(&ctx, &token, &headers) {
        Ok(l) => l,
        Err(resp) => return resp,
    };
    let req_path = q.path.unwrap_or_else(|| "/".to_string());

    // A file link is shown as a folder holding just that one file.
    let items = if link.kind == "file" {
        match std::fs::metadata(&link.target) {
            Ok(m) if m.is_file() => Ok(vec![Item {
                name: link.name.clone(),
                is_dir: false,
                size: Some(m.len()),
            }]),
            _ => Err((StatusCode::NOT_FOUND, "File không còn tồn tại".to_string())),
        }
    } else {
        safe_join(Path::new(&link.target), &req_path).and_then(|dir| read_items(&dir))
    };

    match items {
        Ok(items) => Json(ListResponse {
            path: req_path,
            items,
            perm: db::PERM_VIEW,
        })
        .into_response(),
        Err(e) => from_err(e),
    }
}

async fn share_file(
    State(ctx): State<AppCtx>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    UrlPath((token, rel)): UrlPath<(String, String)>,
    req: Request,
) -> Response {
    let link = match share_api_access(&ctx, &token, req.headers()) {
        Ok(l) => l,
        Err(resp) => return resp,
    };
    let path = if link.kind == "file" {
        PathBuf::from(&link.target)
    } else {
        match safe_join(Path::new(&link.target), &rel) {
            Ok(p) => p,
            Err(e) => return from_err(e),
        }
    };
    if !path.is_file() {
        return json_err(StatusCode::NOT_FOUND, "not found");
    }

    // Log each download once — media players follow up with many partial range requests.
    let first_fetch = req
        .headers()
        .get(RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|r| r.trim().starts_with("bytes=0-"))
        .unwrap_or(true);
    if first_fetch {
        ctx.db.link_touched(link.id);
        let detail = if link.kind == "file" {
            link.name.clone()
        } else {
            format!("{}/{}", link.name, rel.trim_start_matches('/'))
        };
        ctx.log(&client_ip(&addr), "link_download", &detail);
    }
    serve_file(path, req).await
}

// ---------------- Binding (dual-stack + auto port increment) ----------------

/// Bind a single port. Tries dual-stack IPv6 first (also serves IPv4 via mapped
/// addresses); if the platform rejects dual-stack it falls back to IPv4-only.
/// "Address in use" / "permission denied" are surfaced so the caller can try the
/// next port (Windows returns *permission denied* for exclusively-held ports).
fn bind_port(port: u16) -> std::io::Result<std::net::TcpListener> {
    match bind_dual_stack(port) {
        Ok(l) => Ok(l),
        Err(e) if e.kind() == ErrorKind::AddrInUse || e.kind() == ErrorKind::PermissionDenied => {
            Err(e)
        }
        Err(_) => {
            // Dual-stack unsupported on this host — IPv4 only.
            let l = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port))?;
            l.set_nonblocking(true)?;
            Ok(l)
        }
    }
}

fn bind_dual_stack(port: u16) -> std::io::Result<std::net::TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?; // accept IPv4-mapped connections too
    let addr: SocketAddr = (Ipv6Addr::UNSPECIFIED, port).into();
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    let listener: std::net::TcpListener = socket.into();
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Bind and start the server. Reachable over IPv6 and IPv4 on the LAN. If the port
/// is busy it tries the next few ports. A configured `pin` enables the login gate.
pub async fn start(
    dir: PathBuf,
    port: u16,
    pin: Option<String>,
    db: Arc<Db>,
    guard: Arc<LoginGuard>,
    notify: Notify,
) -> Result<RunningServer, String> {
    if !dir.is_dir() {
        return Err(format!("Folder does not exist: {}", dir.display()));
    }

    let mut p = port;
    let std_listener = loop {
        match bind_port(p) {
            Ok(l) => break l,
            Err(e)
                if (e.kind() == ErrorKind::AddrInUse
                    || e.kind() == ErrorKind::PermissionDenied)
                    && p < port.saturating_add(20) =>
            {
                p += 1;
                continue;
            }
            Err(e) => return Err(format!("Cannot bind port {}: {}", p, e)),
        }
    };

    let listener = tokio::net::TcpListener::from_std(std_listener).map_err(|e| e.to_string())?;

    let app = router(AppCtx {
        root: dir,
        pin,
        db,
        guard,
        notify,
    });

    let (tx, rx) = oneshot::channel::<()>();
    tauri::async_runtime::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = rx.await;
        })
        .await;
    });

    Ok(RunningServer {
        shutdown: Some(tx),
        port: p,
    })
}

fn router(ctx: AppCtx) -> Router {
    // Everything here (including the main-folder fallback) sits behind the PIN gate.
    let protected = Router::new()
        .route("/", get(ui_handler))
        .route("/__browse", get(ui_handler))
        .route("/__login", get(login_page))
        .route("/__api/login", post(login_submit))
        .route("/__api/logout", post(logout))
        .route("/__api/roots", get(roots_handler))
        .route("/__api/list", get(list_handler))
        .route("/__api/upload", put(upload_handler))
        .route("/__api/mkdir", post(mkdir_handler))
        .route("/__api/rename", post(rename_handler))
        .route("/__api/delete", post(delete_handler))
        .route("/__api/qr", get(qr_handler))
        .route("/__api/links", get(links_list).post(links_create))
        .route("/__api/links/:id", delete(links_delete))
        .route("/__f/:id/*path", get(root_file_handler))
        .fallback_service(ServeDir::new(&ctx.root))
        // Body limit inner; auth outermost so it runs before anything else.
        .layer(DefaultBodyLimit::disable())
        .layer(middleware::from_fn_with_state(ctx.clone(), auth_mw))
        .with_state(ctx.clone());

    // Share links carry their own (per-link) password, so they skip the PIN gate.
    let shares = Router::new()
        .route("/s/:token", get(share_page))
        .route("/s/:token/", get(share_page))
        .route("/s/:token/login", post(share_login))
        .route("/s/:token/__api/info", get(share_info))
        .route("/s/:token/__api/list", get(share_list))
        .route("/s/:token/f/*path", get(share_file))
        .with_state(ctx);

    shares.merge(protected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::{header, Method};

    const FORM: &str = "application/x-www-form-urlencoded";

    /// Temp tree: <base>/main (served root, with sub/ and s/abc/), <base>/pub, <base>/secret.txt
    fn setup(pin: Option<&str>) -> (PathBuf, Arc<Db>, Router) {
        let (base, db, _guard, app) = setup_full(pin);
        (base, db, app)
    }

    fn setup_full(pin: Option<&str>) -> (PathBuf, Arc<Db>, Arc<LoginGuard>, Router) {
        let base = std::env::temp_dir().join(format!("namsv-srv-{:x}", rand::random::<u64>()));
        let main = base.join("main");
        std::fs::create_dir_all(main.join("sub")).unwrap();
        std::fs::create_dir_all(main.join("s").join("abc")).unwrap();
        std::fs::create_dir_all(base.join("pub")).unwrap();
        std::fs::write(main.join("hello.txt"), "hello main").unwrap();
        std::fs::write(main.join("sub").join("deep.txt"), "deep").unwrap();
        std::fs::write(main.join("s").join("abc").join("x.txt"), "shadow").unwrap();
        std::fs::write(base.join("pub").join("movie.mp4"), "0123456789").unwrap();
        std::fs::write(base.join("secret.txt"), "top secret").unwrap();
        let db = Arc::new(Db::open_in_memory().unwrap());
        let guard = Arc::new(LoginGuard::default());
        let app = make_app(&main, pin, &db, &guard);
        (base, db, guard, app)
    }

    /// A server over `main` sharing `db` — build a second one to simulate a restart.
    fn make_app(main: &Path, pin: Option<&str>, db: &Arc<Db>, guard: &Arc<LoginGuard>) -> Router {
        router(AppCtx {
            root: main.to_path_buf(),
            pin: pin.map(String::from),
            db: db.clone(),
            guard: guard.clone(),
            notify: Arc::new(|_| {}),
        })
    }

    async fn post_json(app: &Router, uri: &str, json: &str) -> (StatusCode, String) {
        let (s, _, body) = send(app, Method::POST, uri, None, json, Some("application/json")).await;
        (s, body)
    }

    /// Log in with the PIN and return the session cookie ("namsv_auth=…").
    async fn login_cookie(app: &Router, pin: &str) -> String {
        let body = format!("pin={}", pin);
        let (_, h, _) = send(app, Method::POST, "/__api/login", None, &body, Some(FORM)).await;
        let set = h[header::SET_COOKIE].to_str().unwrap();
        assert!(set.starts_with("namsv_auth=") && set.contains("Max-Age=2592000"), "{}", set);
        set.split(';').next().unwrap().to_string()
    }

    async fn send(
        app: &Router,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        body: &str,
        ctype: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        send_from(app, "127.0.0.1", method, uri, cookie, body, ctype).await
    }

    async fn send_from(
        app: &Router,
        ip: &str,
        method: Method,
        uri: &str,
        cookie: Option<&str>,
        body: &str,
        ctype: Option<&str>,
    ) -> (StatusCode, HeaderMap, String) {
        let mut b = axum::http::Request::builder().method(method).uri(uri);
        if let Some(c) = cookie {
            b = b.header(header::COOKIE, c);
        }
        if let Some(t) = ctype {
            b = b.header(header::CONTENT_TYPE, t);
        }
        let mut req = b.body(Body::from(body.to_string())).unwrap();
        let ip: std::net::IpAddr = ip.parse().unwrap();
        req.extensions_mut().insert(ConnectInfo(SocketAddr::new(ip, 5555)));
        let res = app.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let bytes = to_bytes(res.into_body(), usize::MAX).await.unwrap();
        (status, headers, String::from_utf8_lossy(&bytes).to_string())
    }

    async fn get(app: &Router, uri: &str, cookie: Option<&str>) -> (StatusCode, HeaderMap, String) {
        send(app, Method::GET, uri, cookie, "", None).await
    }

    fn location(h: &HeaderMap) -> String {
        h[header::LOCATION].to_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn public_folders_listing_and_upload_permission() {
        let (base, db, app) = setup(None);
        let f = db.add_folder(&base.join("pub").to_string_lossy()).unwrap();

        let (s, _, body) = get(&app, "/__api/roots", None).await;
        assert_eq!(s, StatusCode::OK);
        let resp: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(resp["auth"], false);
        let roots = &resp["roots"];
        assert_eq!(roots.as_array().unwrap().len(), 2);
        assert_eq!((roots[0]["id"].as_i64(), roots[0]["perm"].as_u64()), (Some(0), Some(1)));
        assert_eq!(roots[1]["name"], "pub");
        assert_eq!(roots[1]["perm"], 0);

        let (s, _, body) = get(&app, &format!("/__api/list?root={}&path=/", f.id), None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(body.contains("movie.mp4") && body.contains("\"perm\":0"));

        let (s, _, body) = get(&app, &format!("/__f/{}/movie.mp4", f.id), None).await;
        assert_eq!((s, body.as_str()), (StatusCode::OK, "0123456789"));

        // Read-only folder refuses uploads until the owner allows them.
        let up = format!("/__api/upload?root={}&path=/&name=new.txt", f.id);
        let (s, _, _) = send(&app, Method::PUT, &up, None, "data", None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        db.update_folder(f.id, "Phim", db::PERM_UPLOAD).unwrap();
        let (s, _, _) = send(&app, Method::PUT, &up, None, "data", None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(std::fs::read_to_string(base.join("pub").join("new.txt")).unwrap(), "data");
        assert!(db.logs(10).iter().any(|l| l.action == "upload" && l.ip == "127.0.0.1"));

        // Main folder still uploads as before.
        let (s, _, _) =
            send(&app, Method::PUT, "/__api/upload?path=/sub/&name=m.txt", None, "m", None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(base.join("main").join("sub").join("m.txt").is_file());

        // Removed folder disappears.
        db.remove_folder(f.id);
        let (s, _, _) = get(&app, &format!("/__api/list?root={}&path=/", f.id), None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn traversal_is_blocked() {
        let (_base, _db, app) = setup(None);
        for uri in [
            "/__api/list?root=0&path=/../",
            "/__api/list?root=0&path=C:%5C",
            "/__f/0/../secret.txt",
            "/__f/0/..%2Fsecret.txt",
            "/__f/0/..%5Csecret.txt",
        ] {
            let (s, _, body) = get(&app, uri, None).await;
            assert_ne!(s, StatusCode::OK, "{} -> {}", uri, body);
            assert!(!body.contains("secret"), "{} -> {}", uri, body);
        }
        let (s, _, body) = get(&app, "/__f/0/sub/deep.txt", None).await;
        assert_eq!((s, body.as_str()), (StatusCode::OK, "deep"));
    }

    #[tokio::test]
    async fn pin_gate_still_covers_everything_but_share_routes() {
        let (_base, db, app) = setup(Some("1234"));
        let (s, _, _) = get(&app, "/__api/roots", None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let (s, h, _) = get(&app, "/__f/0/hello.txt", None).await;
        assert_eq!((s, location(&h).as_str()), (StatusCode::SEE_OTHER, "/__login"));
        // A main-folder subfolder named "s" must not slip through the share routes.
        let (s, _, body) = get(&app, "/s/abc/x.txt", None).await;
        assert!(!body.contains("shadow"), "{} {}", s, body);

        let (_, h, _) = send(&app, Method::POST, "/__api/login", None, "pin=0000", Some(FORM)).await;
        assert_eq!(location(&h), "/__login?e=1&left=4");
        let cookie = login_cookie(&app, "1234").await;
        let (s, _, body) = get(&app, "/hello.txt", Some(&cookie)).await;
        assert_eq!((s, body.as_str()), (StatusCode::OK, "hello main"));
        // A made-up cookie gets nowhere.
        let (s, _, _) = get(&app, "/__api/roots", Some("namsv_auth=forged")).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);

        let actions: Vec<String> = db.logs(10).into_iter().map(|l| l.action).collect();
        assert_eq!(actions, vec!["login", "login_fail"]);
    }

    #[tokio::test]
    async fn wrong_pins_lock_the_login() {
        let (_base, db, guard, app) = setup_full(Some("1234"));
        let login = |ip: &str, pin: &str| {
            let (app, ip, body) = (app.clone(), ip.to_string(), format!("pin={}", pin));
            async move {
                let (_, h, _) =
                    send_from(&app, &ip, Method::POST, "/__api/login", None, &body, Some(FORM)).await;
                (location(&h), h.get(header::SET_COOKIE).is_some())
            }
        };

        // One device: 4 counted-down retries, then a 5-minute lock.
        for left in (1..guard::DEVICE_MAX_FAILS).rev() {
            assert_eq!(login("192.168.1.50", "0000").await.0, format!("/__login?e=1&left={}", left));
        }
        assert_eq!(login("192.168.1.50", "0000").await.0, "/__login?e=lock&t=300&g=0");
        // Locked: even the right PIN is refused, and no cookie is handed out…
        let (loc, cookie) = login("192.168.1.50", "1234").await;
        assert!(loc.starts_with("/__login?e=lock&t=") && !cookie);
        // …but other devices can still log in.
        assert_eq!(login("192.168.1.51", "1234").await, ("/".to_string(), true));
        assert!(db.logs(20).iter().any(|l| l.action == "login_lock" && l.detail == "192.168.1.50 · 5 phút"));

        // Hopping across IPs (4 tries each, under the per-device limit) hits the global cap.
        guard.reset();
        let ips = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"];
        let mut last = String::new();
        for ip in ips {
            for _ in 1..guard::DEVICE_MAX_FAILS {
                last = login(ip, "0000").await.0;
            }
        }
        assert_eq!(last, "/__login?e=lock&t=900&g=1");
        assert_eq!(login("10.0.0.99", "1234").await, ("/__login?e=lock&t=900&g=1".to_string(), false));
        // IPv6 privacy addresses in one /64 count as one device.
        guard.reset();
        for i in 1..=guard::DEVICE_MAX_FAILS {
            login(&format!("2001:db8:1:2::{}", i), "0000").await;
        }
        assert!(login("2001:db8:1:2::77", "1234").await.0.contains("e=lock"));

        // The owner unlocks from the app → logins work again.
        guard.reset();
        assert_eq!(login("10.0.0.99", "1234").await, ("/".to_string(), true));
    }

    #[tokio::test]
    async fn file_link_with_password_and_lockout() {
        // Global PIN is on: share links must still work without it.
        let (base, db, app) = setup(Some("9999"));
        let link = db
            .create_link(&base.join("main").join("hello.txt"), 1, Some("4321".into()))
            .unwrap();
        let page = format!("/s/{}", link.token);

        let (s, _, body) = get(&app, &page, None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(body.contains("id=\"pins\""), "expected the password page");
        let (s, _, _) = get(&app, &format!("{}/__api/list?path=/", page), None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let (s, _, _) = get(&app, &format!("{}/f/hello.txt", page), None).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);

        let login = format!("{}/login", page);
        let (s, h, _) = send(&app, Method::POST, &login, None, "pin=4321", Some(FORM)).await;
        assert_eq!((s, location(&h)), (StatusCode::SEE_OTHER, page.clone()));
        let set = h[header::SET_COOKIE].to_str().unwrap().to_string();
        assert!(set.contains(&format!("Path={};", page)), "{}", set);
        let cookie = set.split(';').next().unwrap().to_string();

        let (s, _, body) = get(&app, &page, Some(&cookie)).await;
        assert!(s == StatusCode::OK && body.contains("File Browser"));
        let (_, _, body) = get(&app, &format!("{}/__api/info", page), Some(&cookie)).await;
        assert!(body.contains("\"kind\":\"file\"") && !body.contains("target"));
        let (_, _, body) = get(&app, &format!("{}/__api/list?path=/", page), Some(&cookie)).await;
        assert!(body.contains("hello.txt") && body.contains("\"perm\":0"));
        let (s, _, body) = get(&app, &format!("{}/f/hello.txt", page), Some(&cookie)).await;
        assert_eq!((s, body.as_str()), (StatusCode::OK, "hello main"));
        // The link cookie is no key to the rest of the server.
        let (s, _, _) = get(&app, "/__api/roots", Some(&cookie)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        assert_eq!(db.link_by_token(&link.token).unwrap().views, 1);

        // Wrong passwords lock the link…
        for i in 1..=db::MAX_LINK_FAILS {
            let (_, h, _) = send(&app, Method::POST, &login, None, "pin=0000", Some(FORM)).await;
            let want = if i < db::MAX_LINK_FAILS { "?e=1" } else { "?e=lock" };
            assert!(location(&h).ends_with(want), "attempt {} -> {}", i, location(&h));
        }
        // …after which even the right one is refused, while existing sessions keep working.
        let (_, h, _) = send(&app, Method::POST, &login, None, "pin=4321", Some(FORM)).await;
        assert!(location(&h).ends_with("?e=lock") && h.get(header::SET_COOKIE).is_none());
        let (s, _, _) = get(&app, &format!("{}/f/hello.txt", page), Some(&cookie)).await;
        assert_eq!(s, StatusCode::OK);
        db.link_reset_fails(link.id);
        let (_, h, _) = send(&app, Method::POST, &login, None, "pin=4321", Some(FORM)).await;
        assert!(h.get(header::SET_COOKIE).is_some());
    }

    #[tokio::test]
    async fn folder_link_is_scoped_and_expires() {
        let (base, db, app) = setup(None);
        let link = db.create_link(&base.join("main").join("sub"), 1, None).unwrap();
        let page = format!("/s/{}", link.token);

        // No password → open straight away, but only inside the shared folder.
        let (s, _, body) = get(&app, &format!("{}/__api/list?path=/", page), None).await;
        assert!(s == StatusCode::OK && body.contains("deep.txt") && !body.contains("hello.txt"));
        let (_, _, body) = get(&app, &format!("{}/f/deep.txt", page), None).await;
        assert_eq!(body, "deep");
        for uri in [
            format!("{}/f/..%2Fhello.txt", page),
            format!("{}/f/../hello.txt", page),
            format!("{}/__api/list?path=/../", page),
        ] {
            let (s, _, body) = get(&app, &uri, None).await;
            assert_ne!(s, StatusCode::OK, "{}", uri);
            assert!(!body.contains("hello"), "{} -> {}", uri, body);
        }
        assert!(db
            .logs(50)
            .iter()
            .any(|l| l.action == "link_download" && l.detail == "sub/deep.txt"));

        db.force_expire(link.id);
        let (s, _, body) = get(&app, &page, None).await;
        assert!(s == StatusCode::GONE && body.contains("hết hạn"));
        let (s, _, _) = get(&app, &format!("{}/f/deep.txt", page), None).await;
        assert_eq!(s, StatusCode::GONE);
        let (s, _, _) = get(&app, "/s/nope!", None).await;
        assert_eq!(s, StatusCode::GONE);
    }

    #[tokio::test]
    async fn links_api_creates_inside_roots_only() {
        let (_base, db, app) = setup(None);
        let json = Some("application/json");
        let (s, _, body) = send(&app, Method::POST, "/__api/links", None,
            r#"{"root":0,"path":"/sub/deep.txt","hours":24,"pin":"1111"}"#, json).await;
        assert_eq!(s, StatusCode::OK, "{}", body);
        let l: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!((l["name"].as_str(), l["pin"].as_str()), (Some("deep.txt"), Some("1111")));
        assert!(l.get("secret").is_none());

        let (s, _, _) = send(&app, Method::POST, "/__api/links", None,
            r#"{"root":0,"path":"/../secret.txt","hours":24,"pin":null}"#, json).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _, _) = send(&app, Method::POST, "/__api/links", None,
            r#"{"root":0,"path":"/","hours":24,"pin":"12"}"#, json).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        let (_, _, body) = get(&app, "/__api/links", None).await;
        let list: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(list.as_array().unwrap().len(), 1);
        let id = l["id"].as_i64().unwrap();
        let (s, _, _) =
            send(&app, Method::DELETE, &format!("/__api/links/{}", id), None, "", None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(db.links().is_empty());
    }

    #[tokio::test]
    async fn sessions_survive_restart_and_logout_is_per_device() {
        let (base, db, guard, app) = setup_full(Some("1234"));
        let phone = login_cookie(&app, "1234").await;
        let laptop = login_cookie(&app, "1234").await;
        assert_ne!(phone, laptop);
        assert_eq!(db.sessions().len(), 2);

        // "Restart" = a brand-new server on the same database: still logged in.
        let app2 = make_app(&base.join("main"), Some("1234"), &db, &guard);
        let (s, _, body) = get(&app2, "/__api/roots", Some(&phone)).await;
        assert_eq!(s, StatusCode::OK);
        assert!(body.contains("\"auth\":true"));

        // Logging the phone out leaves the laptop signed in.
        let (s, h, _) = send(&app2, Method::POST, "/__api/logout", Some(&phone), "", None).await;
        assert_eq!((s, location(&h).as_str()), (StatusCode::SEE_OTHER, "/__login"));
        assert!(h[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
        let (s, _, _) = get(&app2, "/__api/roots", Some(&phone)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let (s, _, _) = get(&app2, "/__api/roots", Some(&laptop)).await;
        assert_eq!(s, StatusCode::OK);

        // The owner revoking from the app ends it too.
        db.clear_sessions();
        let (s, _, _) = get(&app2, "/__api/roots", Some(&laptop)).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let actions: Vec<String> = db.logs(10).into_iter().map(|l| l.action).collect();
        assert!(actions.contains(&"logout".to_string()));
    }

    #[tokio::test]
    async fn file_operations_follow_folder_permission() {
        let (base, db, app) = setup(None);
        let main = base.join("main");

        // Default main-folder permission = upload: new folders yes, rename/delete no.
        let (s, body) = post_json(&app, "/__api/mkdir", r#"{"root":0,"path":"/","name":"Ảnh mới"}"#).await;
        assert_eq!(s, StatusCode::OK, "{}", body);
        assert!(main.join("Ảnh mới").is_dir());
        let (s, _) = post_json(&app, "/__api/mkdir", r#"{"root":0,"path":"/","name":"Ảnh mới"}"#).await;
        assert_eq!(s, StatusCode::CONFLICT);
        for bad in ["a/b", "a\\\\b", "x:y", "CON", "nul.txt", "..", "   ", "a?"] {
            let json = format!(r#"{{"root":0,"path":"/","name":"{}"}}"#, bad);
            let (s, body) = post_json(&app, "/__api/mkdir", &json).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{:?} -> {}", bad, body);
        }
        let (s, _) = post_json(&app, "/__api/rename", r#"{"root":0,"path":"/hello.txt","name":"x.txt"}"#).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _) = post_json(&app, "/__api/delete", r#"{"root":0,"path":"/hello.txt"}"#).await;
        assert_eq!(s, StatusCode::FORBIDDEN);

        // Full permission.
        db.set_main_perm(db::PERM_FULL).unwrap();
        let (s, body) = post_json(&app, "/__api/rename", r#"{"root":0,"path":"/hello.txt","name":"chào.txt"}"#).await;
        assert_eq!(s, StatusCode::OK, "{}", body);
        assert!(main.join("chào.txt").is_file() && !main.join("hello.txt").exists());
        // Case-only rename is allowed; clashing with another item is not.
        let (s, body) = post_json(&app, "/__api/rename", r#"{"root":0,"path":"/chào.txt","name":"Chào.txt"}"#).await;
        assert_eq!(s, StatusCode::OK, "{}", body);
        let (s, _) = post_json(&app, "/__api/rename", r#"{"root":0,"path":"/Chào.txt","name":"sub"}"#).await;
        assert_eq!(s, StatusCode::CONFLICT);
        // The root and anything outside it stay untouchable.
        let (s, _) = post_json(&app, "/__api/rename", r#"{"root":0,"path":"/","name":"x"}"#).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = post_json(&app, "/__api/delete", r#"{"root":0,"path":"/"}"#).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = post_json(&app, "/__api/delete", r#"{"root":0,"path":"/../secret.txt"}"#).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _) = post_json(&app, "/__api/rename", r#"{"root":0,"path":"/../secret.txt","name":"y"}"#).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        assert!(base.join("secret.txt").is_file());

        let (s, body) = post_json(&app, "/__api/delete", r#"{"root":0,"path":"/sub"}"#).await;
        assert_eq!(s, StatusCode::OK, "{}", body);
        assert!(!main.join("sub").exists());

        // A view-only public folder refuses everything.
        let f = db.add_folder(&base.join("pub").to_string_lossy()).unwrap();
        let json = format!(r#"{{"root":{},"path":"/","name":"new"}}"#, f.id);
        let (s, _) = post_json(&app, "/__api/mkdir", &json).await;
        assert_eq!(s, StatusCode::FORBIDDEN);

        // Uploads use the same name rules.
        let (s, _, _) = send(&app, Method::PUT, "/__api/upload?path=/&name=a%3Ab.txt", None, "x", None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);

        let actions: Vec<String> = db.logs(20).into_iter().map(|l| l.action).collect();
        for a in ["mkdir", "rename", "delete"] {
            assert!(actions.contains(&a.to_string()), "missing {} in {:?}", a, actions);
        }
    }

    #[tokio::test]
    async fn qr_endpoint_returns_svg() {
        let (_base, _db, app) = setup(None);
        let (s, h, body) = get(&app, "/__api/qr?text=http%3A%2F%2F192.168.1.10%3A3000%2Fs%2FAbC", None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(h[header::CONTENT_TYPE], "image/svg+xml");
        assert!(body.contains("<svg"));
        let (s, _, _) = get(&app, "/__api/qr?text=", None).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    /// The real Recycle Bin call (tests otherwise use a plain delete). Touches the
    /// machine's Recycle Bin, so it only runs on request:
    /// `cargo test trash_really_recycles -- --ignored`
    #[test]
    #[ignore]
    fn trash_really_recycles() {
        let dir = std::env::temp_dir().join(format!("namsv-trash-{:x}", rand::random::<u64>()));
        std::fs::create_dir_all(&dir).unwrap();
        let name = format!("namsv-trash-check-{:x}.txt", rand::random::<u32>());
        let file = dir.join(&name);
        std::fs::write(&file, "x").unwrap();

        trash::delete(&file).unwrap();
        assert!(!file.exists());
        // Match on the original folder: the shell may report the name without its
        // extension (Explorer's "hide extensions for known file types").
        let found: Vec<_> = trash::os_limited::list()
            .unwrap()
            .into_iter()
            .filter(|i| i.name.to_string_lossy().contains("namsv-trash-check"))
            .collect();
        let ours = found.iter().filter(|i| i.original_parent == dir).count();
        trash::os_limited::purge_all(found).unwrap();
        assert_eq!(ours, 1, "file should be in the Recycle Bin");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
