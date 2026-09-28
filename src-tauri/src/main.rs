// Prevent an extra console window on Windows in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod db;
mod guard;
mod server;

use db::Db;
use guard::LoginGuard;
use serde::{Deserialize, Serialize};
use server::RunningServer;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Emitter, Manager, State, WindowEvent,
};
use tauri_plugin_autostart::{ManagerExt, MacosLauncher};
use tauri_plugin_dialog::DialogExt;

// ---------- Persistent configuration ----------

#[derive(Serialize, Deserialize, Clone)]
struct Config {
    dir: String,
    port: u16,
    /// Start the file server automatically when the app launches.
    start_on_launch: bool,
    /// Folder used on launch (overrides `dir` at startup when it still exists).
    #[serde(default)]
    default_dir: Option<String>,
    /// Pinned favorite folders.
    #[serde(default)]
    favorites: Vec<String>,
    /// Recently served folders, most recent first.
    #[serde(default)]
    recents: Vec<String>,
    /// 4-digit login PIN. `None` = open access (no login required).
    #[serde(default)]
    pin: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        let home = std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_else(|_| ".".to_string());
        Config {
            dir: home,
            port: 3000,
            start_on_launch: true,
            default_dir: None,
            favorites: Vec::new(),
            recents: Vec::new(),
            pin: None,
        }
    }
}

/// Move `dir` to the front of the recents list (deduped, capped).
fn push_recent(cfg: &mut Config, dir: &str) {
    cfg.recents.retain(|d| d != dir);
    cfg.recents.insert(0, dir.to_string());
    cfg.recents.truncate(8);
}

struct AppState {
    server: Mutex<Option<RunningServer>>,
    config: Mutex<Config>,
    config_path: Mutex<PathBuf>,
    db: Arc<Db>,
    /// Wrong-PIN limiter; lives here (not in the server) so it survives restarts.
    guard: Arc<LoginGuard>,
}

fn load_config(path: &PathBuf) -> Config {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str::<Config>(&s).ok())
        .unwrap_or_default()
}

fn save_config(state: &AppState) {
    let cfg = state.config.lock().unwrap().clone();
    let path = state.config_path.lock().unwrap().clone();
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(&cfg) {
        let _ = std::fs::write(&path, json);
    }
}

// ---------- Status reporting ----------

#[derive(Serialize, Clone)]
struct UrlEntry {
    url: String,
    label: String,
}

#[derive(Serialize, Clone)]
struct Status {
    running: bool,
    port: u16,
    dir: String,
    urls: Vec<UrlEntry>,
    start_on_launch: bool,
    autostart: bool,
    favorites: Vec<String>,
    recents: Vec<String>,
    default_dir: Option<String>,
    is_favorite: bool,
    is_default: bool,
    pin: Option<String>,
    /// Current wrong-PIN locks (see guard.rs).
    login_lock: guard::GuardStatus,
}

fn ipv4_label(a: &std::net::Ipv4Addr) -> &'static str {
    let o = a.octets();
    if o[0] == 100 && (64..=127).contains(&o[1]) {
        "Tailscale" // 100.64.0.0/10 CGNAT range
    } else if (o[0] == 192 && o[1] == 168)
        || o[0] == 10
        || (o[0] == 172 && (16..=31).contains(&o[1]))
    {
        "Mạng LAN"
    } else {
        "IPv4"
    }
}

fn ipv6_label(a: &std::net::Ipv6Addr) -> &'static str {
    let s = a.segments();
    if s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0 {
        "Tailscale (IPv6)" // Tailscale ULA prefix fd7a:115c:a1e0::/48
    } else if (s[0] & 0xe000) == 0x2000 {
        "IPv6 công cộng" // 2000::/3 global unicast
    } else if (s[0] & 0xfe00) == 0xfc00 {
        "Mạng ảo (IPv6)" // fc00::/7 unique local
    } else {
        "IPv6"
    }
}

fn lan_urls(port: u16) -> Vec<UrlEntry> {
    use std::net::IpAddr;
    let mut v4: Vec<UrlEntry> = Vec::new();
    let mut v6: Vec<UrlEntry> = Vec::new();
    if let Ok(list) = local_ip_address::list_afinet_netifas() {
        for (_name, ip) in list {
            match ip {
                IpAddr::V4(a) => {
                    // Skip loopback (127.x) and APIPA link-local (169.254.x).
                    if !a.is_loopback() && !a.is_link_local() {
                        let e = UrlEntry {
                            url: format!("http://{}:{}", a, port),
                            label: ipv4_label(&a).to_string(),
                        };
                        if !v4.iter().any(|x| x.url == e.url) {
                            v4.push(e);
                        }
                    }
                }
                IpAddr::V6(a) => {
                    // Skip loopback (::1), unspecified, and link-local (fe80::/10,
                    // which needs a %zone id to be reachable from another device).
                    let link_local = (a.segments()[0] & 0xffc0) == 0xfe80;
                    if !a.is_loopback() && !a.is_unspecified() && !link_local {
                        let e = UrlEntry {
                            url: format!("http://[{}]:{}", a, port),
                            label: ipv6_label(&a).to_string(),
                        };
                        if !v6.iter().any(|x| x.url == e.url) {
                            v6.push(e);
                        }
                    }
                }
            }
        }
    }
    let mut urls = vec![UrlEntry {
        url: format!("http://localhost:{}", port),
        label: "Máy này".to_string(),
    }];
    urls.append(&mut v4);
    urls.append(&mut v6);
    urls
}

fn build_status(app: &AppHandle) -> Status {
    let state = app.state::<AppState>();
    let cfg = state.config.lock().unwrap().clone();
    let running_guard = state.server.lock().unwrap();
    let running = running_guard.is_some();
    let port = running_guard.as_ref().map(|s| s.port).unwrap_or(cfg.port);
    drop(running_guard);
    let autostart = app.autolaunch().is_enabled().unwrap_or(false);
    let is_favorite = cfg.favorites.iter().any(|d| d == &cfg.dir);
    let is_default = cfg.default_dir.as_deref() == Some(cfg.dir.as_str());
    Status {
        running,
        port,
        dir: cfg.dir,
        urls: lan_urls(port),
        start_on_launch: cfg.start_on_launch,
        autostart,
        favorites: cfg.favorites,
        recents: cfg.recents,
        default_dir: cfg.default_dir,
        is_favorite,
        is_default,
        pin: cfg.pin,
        login_lock: state.guard.status(),
    }
}

fn emit_status(app: &AppHandle) {
    let status = build_status(app);
    let _ = app.emit("status", status);
}

// ---------- Core start/stop (shared by commands and tray) ----------

async fn do_start(app: &AppHandle) -> Result<(), String> {
    let (dir, port, pin, db, guard) = {
        let state = app.state::<AppState>();
        let cfg = state.config.lock().unwrap();
        (
            PathBuf::from(&cfg.dir),
            cfg.port,
            cfg.pin.clone(),
            state.db.clone(),
            state.guard.clone(),
        )
    };

    // Already running? Nothing to do.
    {
        let state = app.state::<AppState>();
        if state.server.lock().unwrap().is_some() {
            return Ok(());
        }
    }

    let emitter = app.clone();
    let notify: server::Notify = Arc::new(move |what: &str| {
        if what == "guard" {
            emit_status(&emitter); // lock state is part of the status
        } else {
            let _ = emitter.emit("db-changed", what);
        }
    });
    let running = server::start(dir, port, pin, db, guard, notify).await?;
    {
        let state = app.state::<AppState>();
        *state.server.lock().unwrap() = Some(running);
    }
    Ok(())
}

fn do_stop(app: &AppHandle) {
    let state = app.state::<AppState>();
    let taken = state.server.lock().unwrap().take();
    if let Some(server) = taken {
        server.stop();
    }
}

/// If the server is running, restart it so a directory/port change takes effect.
async fn restart_if_running(app: &AppHandle) {
    let running = { app.state::<AppState>().server.lock().unwrap().is_some() };
    if running {
        do_stop(app);
        let _ = do_start(app).await;
    }
}

fn persist(app: &AppHandle) {
    save_config(&app.state::<AppState>());
}

// ---------- Tauri commands (called from the control window) ----------

#[tauri::command]
fn get_status(app: AppHandle) -> Status {
    build_status(&app)
}

#[tauri::command]
async fn start_server(app: AppHandle) -> Result<Status, String> {
    do_start(&app).await?;
    emit_status(&app);
    Ok(build_status(&app))
}

#[tauri::command]
fn stop_server(app: AppHandle) -> Status {
    do_stop(&app);
    emit_status(&app);
    build_status(&app)
}

#[tauri::command]
async fn pick_folder(app: AppHandle) -> Option<String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog().file().pick_folder(move |f| {
        let _ = tx.send(f);
    });
    let picked = rx.await.ok().flatten()?;
    let path = picked.into_path().ok()?;
    Some(path.to_string_lossy().to_string())
}

#[tauri::command]
async fn set_dir(app: AppHandle, dir: String) -> Result<Status, String> {
    {
        let state = app.state::<AppState>();
        let mut cfg = state.config.lock().unwrap();
        cfg.dir = dir.clone();
        push_recent(&mut cfg, &dir);
    }
    persist(&app);
    restart_if_running(&app).await; // switch the served folder live
    emit_status(&app);
    Ok(build_status(&app))
}

#[tauri::command]
async fn set_port(app: AppHandle, port: u16) -> Result<Status, String> {
    {
        let state = app.state::<AppState>();
        state.config.lock().unwrap().port = port;
    }
    persist(&app);
    restart_if_running(&app).await;
    emit_status(&app);
    Ok(build_status(&app))
}

#[tauri::command]
fn toggle_favorite(app: AppHandle, dir: String, state: State<AppState>) -> Status {
    {
        let mut cfg = state.config.lock().unwrap();
        if let Some(pos) = cfg.favorites.iter().position(|d| d == &dir) {
            cfg.favorites.remove(pos);
        } else {
            cfg.favorites.push(dir);
        }
    }
    save_config(&state);
    build_status(&app)
}

#[tauri::command]
fn remove_favorite(app: AppHandle, dir: String, state: State<AppState>) -> Status {
    state.config.lock().unwrap().favorites.retain(|d| d != &dir);
    save_config(&state);
    build_status(&app)
}

/// Set (or clear, with `dir = None`) the folder used on launch.
#[tauri::command]
fn set_default(app: AppHandle, dir: Option<String>, state: State<AppState>) -> Status {
    state.config.lock().unwrap().default_dir = dir;
    save_config(&state);
    build_status(&app)
}

/// Set the login PIN (exactly 4 digits) or clear it (`pin = None`/empty) for open access.
#[tauri::command]
async fn set_pin(app: AppHandle, pin: Option<String>) -> Result<Status, String> {
    let pin = pin.and_then(|p| {
        let t = p.trim().to_string();
        if t.is_empty() {
            None
        } else {
            Some(t)
        }
    });
    if let Some(ref p) = pin {
        if p.len() != 4 || !p.chars().all(|c| c.is_ascii_digit()) {
            return Err("PIN phải gồm đúng 4 chữ số".to_string());
        }
    }
    {
        let state = app.state::<AppState>();
        let mut cfg = state.config.lock().unwrap();
        if cfg.pin != pin {
            // A new PIN signs every device out (e.g. after the old one leaked).
            state.db.clear_sessions();
            let _ = app.emit("db-changed", "sessions");
        }
        cfg.pin = pin;
        state.guard.reset(); // guesses against the old PIN no longer matter
    }
    persist(&app);
    restart_if_running(&app).await; // apply the new PIN immediately
    emit_status(&app);
    Ok(build_status(&app))
}

/// Clear every wrong-PIN lock (the owner vouches for whoever is locked out).
#[tauri::command]
fn unlock_login(app: AppHandle, state: State<AppState>) -> Status {
    state.guard.reset();
    state.db.log(LOCAL_ACTOR, "login_unlock", "");
    let _ = app.emit("db-changed", "logs");
    build_status(&app)
}

#[tauri::command]
fn set_start_on_launch(app: AppHandle, enabled: bool, state: State<AppState>) -> Status {
    state.config.lock().unwrap().start_on_launch = enabled;
    save_config(&state);
    build_status(&app)
}

#[tauri::command]
fn set_autostart(app: AppHandle, enabled: bool) -> Result<Status, String> {
    let mgr = app.autolaunch();
    if enabled {
        mgr.enable().map_err(|e| e.to_string())?;
    } else {
        mgr.disable().map_err(|e| e.to_string())?;
    }
    Ok(build_status(&app))
}

#[tauri::command]
fn open_ui(app: AppHandle, url: Option<String>) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;
    // Open the requested URL if it's a valid http(s) one; otherwise fall back to the
    // first known address (localhost). Only http/https are allowed.
    let url = match url {
        Some(u) if u.starts_with("http://") || u.starts_with("https://") => u,
        _ => build_status(&app)
            .urls
            .first()
            .map(|e| e.url.clone())
            .unwrap_or_else(|| "http://localhost:3000".to_string()),
    };
    app.opener()
        .open_url(url, None::<&str>)
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn pick_file(app: AppHandle) -> Option<String> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    app.dialog().file().pick_file(move |f| {
        let _ = tx.send(f);
    });
    let picked = rx.await.ok().flatten()?;
    let path = picked.into_path().ok()?;
    Some(path.to_string_lossy().to_string())
}

// ---------- Public folders (database) ----------
// The server reads these per request, so changes apply without a restart.

/// Log label for actions taken from the control window rather than over HTTP.
const LOCAL_ACTOR: &str = "máy chủ";

/// Everything the "Công khai" tab shows: the main folder's permission + the list.
#[derive(Serialize)]
struct FoldersView {
    main_perm: u8,
    folders: Vec<db::Folder>,
}

fn folders_view(state: &AppState) -> FoldersView {
    FoldersView {
        main_perm: state.db.main_perm(),
        folders: state.db.folders(),
    }
}

#[tauri::command]
fn list_folders(state: State<AppState>) -> FoldersView {
    folders_view(&state)
}

#[tauri::command]
fn add_folder(dir: String, state: State<AppState>) -> Result<FoldersView, String> {
    state.db.add_folder(&dir)?;
    Ok(folders_view(&state))
}

#[tauri::command]
fn update_folder(
    id: i64,
    name: String,
    perm: u8,
    state: State<AppState>,
) -> Result<FoldersView, String> {
    state.db.update_folder(id, &name, perm)?;
    Ok(folders_view(&state))
}

#[tauri::command]
fn set_main_perm(perm: u8, state: State<AppState>) -> Result<FoldersView, String> {
    state.db.set_main_perm(perm)?;
    Ok(folders_view(&state))
}

#[tauri::command]
fn remove_folder(id: i64, state: State<AppState>) -> FoldersView {
    state.db.remove_folder(id);
    folders_view(&state)
}

// ---------- Logged-in devices (database) ----------

#[tauri::command]
fn list_sessions(state: State<AppState>) -> Vec<db::Session> {
    state.db.sessions()
}

#[tauri::command]
fn revoke_session(id: i64, state: State<AppState>) -> Vec<db::Session> {
    state.db.delete_session(id);
    state.db.log(LOCAL_ACTOR, "session_revoke", "1 thiết bị");
    state.db.sessions()
}

#[tauri::command]
fn revoke_all_sessions(state: State<AppState>) -> Vec<db::Session> {
    state.db.clear_sessions();
    state.db.log(LOCAL_ACTOR, "session_revoke", "tất cả thiết bị");
    Vec::new()
}

/// SVG QR code for an address or a share link.
#[tauri::command]
fn qr_svg(text: String) -> Result<String, String> {
    server::qr_svg(&text).ok_or_else(|| "Không tạo được mã QR".to_string())
}

// ---------- Temporary share links (database) ----------

#[tauri::command]
fn list_links(state: State<AppState>) -> Vec<db::Link> {
    state.db.links()
}

#[tauri::command]
fn create_link(
    path: String,
    hours: i64,
    pin: Option<String>,
    state: State<AppState>,
) -> Result<db::Link, String> {
    let link = state.db.create_link(Path::new(&path), hours, pin)?;
    state.db.log(LOCAL_ACTOR, "link_create", &link.name);
    Ok(link)
}

#[tauri::command]
fn delete_link(id: i64, state: State<AppState>) -> Vec<db::Link> {
    if let Some(link) = state.db.delete_link(id) {
        state.db.log(LOCAL_ACTOR, "link_delete", &link.name);
    }
    state.db.links()
}

#[tauri::command]
fn unlock_link(id: i64, state: State<AppState>) -> Vec<db::Link> {
    state.db.link_reset_fails(id);
    state.db.links()
}

#[tauri::command]
fn purge_links(state: State<AppState>) -> Vec<db::Link> {
    state.db.purge_links();
    state.db.links()
}

// ---------- Activity log (database) ----------

#[tauri::command]
fn list_logs(state: State<AppState>) -> Vec<db::LogEntry> {
    state.db.logs(300)
}

#[tauri::command]
fn clear_logs(state: State<AppState>) -> Vec<db::LogEntry> {
    state.db.clear_logs();
    Vec::new()
}

// ---------- Window helpers ----------

fn show_window(app: &AppHandle) {
    if let Some(win) = app.get_webview_window("main") {
        let _ = win.show();
        let _ = win.unminimize();
        let _ = win.set_focus();
    }
}

fn main() {
    let launched_minimized = std::env::args().any(|a| a == "--minimized");

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_autostart::init(
            MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .setup(move |app| {
            let handle = app.handle().clone();

            // Resolve config path and load saved settings.
            let config_path = app
                .path()
                .app_config_dir()
                .map(|d| d.join("config.json"))
                .unwrap_or_else(|_| PathBuf::from("namsv-config.json"));
            let mut config = load_config(&config_path);
            // Honour the default folder on launch when it still exists.
            if let Some(def) = config.default_dir.clone() {
                if std::path::Path::new(&def).is_dir() {
                    config.dir = def;
                }
            }
            let start_on_launch = config.start_on_launch;

            // Database lives next to config.json. If it can't be opened (locked, corrupt)
            // keep the app usable with an in-memory one rather than refusing to start.
            let db_path = config_path.with_file_name("namsv.db");
            let db = Db::open(&db_path)
                .or_else(|e| {
                    eprintln!("cannot open {}: {} — using in-memory DB", db_path.display(), e);
                    Db::open_in_memory()
                })
                .map_err(|e| format!("database init failed: {}", e))?;

            app.manage(AppState {
                server: Mutex::new(None),
                config: Mutex::new(config),
                config_path: Mutex::new(config_path),
                db: Arc::new(db),
                guard: Arc::new(LoginGuard::default()),
            });

            // ----- System tray -----
            let mi_open = MenuItem::with_id(app, "open", "Bảng điều khiển", true, None::<&str>)?;
            let mi_browser =
                MenuItem::with_id(app, "browser", "Mở trong trình duyệt", true, None::<&str>)?;
            let mi_toggle =
                MenuItem::with_id(app, "toggle", "Bật / Tắt server", true, None::<&str>)?;
            let mi_quit = MenuItem::with_id(app, "quit", "Thoát", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&mi_open, &mi_browser, &mi_toggle, &mi_quit])?;

            let _tray = TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().unwrap().clone())
                .tooltip("namsv — file bridge")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => show_window(app),
                    "browser" => {
                        let _ = open_ui(app.clone(), None);
                    }
                    "toggle" => {
                        let running = {
                            let state = app.state::<AppState>();
                            let g = state.server.lock().unwrap();
                            g.is_some()
                        };
                        if running {
                            do_stop(app);
                            emit_status(app);
                        } else {
                            let app2 = app.clone();
                            tauri::async_runtime::spawn(async move {
                                let _ = do_start(&app2).await;
                                emit_status(&app2);
                            });
                        }
                    }
                    "quit" => {
                        do_stop(app);
                        app.exit(0);
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_window(tray.app_handle());
                    }
                })
                .build(app)?;

            // Auto-start the server on launch if configured.
            if start_on_launch {
                let h = handle.clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = do_start(&h).await {
                        eprintln!("auto-start failed: {}", e);
                    }
                    emit_status(&h);
                });
            }

            // When launched at boot (--minimized), stay in the tray instead of popping the window.
            if launched_minimized {
                if let Some(win) = app.get_webview_window("main") {
                    let _ = win.hide();
                }
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides it to the tray; the server keeps running.
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            get_status,
            start_server,
            stop_server,
            pick_folder,
            set_dir,
            set_port,
            toggle_favorite,
            remove_favorite,
            set_default,
            set_pin,
            unlock_login,
            set_start_on_launch,
            set_autostart,
            open_ui,
            pick_file,
            list_folders,
            add_folder,
            update_folder,
            set_main_perm,
            remove_folder,
            list_sessions,
            revoke_session,
            revoke_all_sessions,
            qr_svg,
            list_links,
            create_link,
            delete_link,
            unlock_link,
            purge_links,
            list_logs,
            clear_logs
        ])
        .run(tauri::generate_context!())
        .expect("error while running namsv");
}
