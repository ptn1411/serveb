// SQLite store (bundled, one file next to config.json) for everything that is managed
// at runtime: public folders, temporary share links and the activity log.
// A single connection behind a mutex is plenty — every query here is tiny.

use rand::{distributions::Alphanumeric, Rng};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::Serialize;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

/// Wrong PIN attempts before a share link stops accepting new logins.
pub const MAX_LINK_FAILS: i64 = 5;
/// Longest allowed link lifetime (hours).
pub const MAX_LINK_HOURS: i64 = 24 * 365;
const MAX_LOG_ROWS: i64 = 2000;
/// Expired links are kept this long (for the list) before being cleaned up on launch.
const EXPIRED_KEEP_SECS: i64 = 7 * 24 * 3600;
/// How long a login stays valid on a device.
pub const SESSION_SECS: i64 = 30 * 24 * 3600;
/// `last_seen` is only rewritten when older than this, so streaming a video
/// doesn't turn every range request into a database write.
const SESSION_TOUCH_SECS: i64 = 60;

/// Folder permission levels (each includes the ones below it).
pub const PERM_VIEW: u8 = 0;
/// + upload files and create folders
pub const PERM_UPLOAD: u8 = 1;
/// + rename and delete (to the Recycle Bin)
pub const PERM_FULL: u8 = 2;

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Windows `canonicalize` returns verbatim paths (`\\?\C:\…`); strip that for storage/display.
pub fn clean_path(p: &Path) -> String {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", rest)
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s.to_string()
    }
}

/// Last path component, or the whole path for drive roots like `D:\`.
pub fn display_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| clean_path(p))
}

/// `None`/blank = no PIN; otherwise it must be exactly 4 digits.
pub fn normalize_pin(pin: Option<String>) -> Result<Option<String>, String> {
    match pin.map(|p| p.trim().to_string()) {
        None => Ok(None),
        Some(p) if p.is_empty() => Ok(None),
        Some(p) if p.len() == 4 && p.chars().all(|c| c.is_ascii_digit()) => Ok(Some(p)),
        Some(_) => Err("Mật khẩu phải gồm đúng 4 chữ số".to_string()),
    }
}

fn random_token(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

#[derive(Serialize, Clone)]
pub struct Folder {
    pub id: i64,
    pub name: String,
    pub path: String,
    /// PERM_VIEW / PERM_UPLOAD / PERM_FULL
    pub perm: u8,
    /// False when the folder was deleted/unplugged since it was added.
    pub exists: bool,
}

#[derive(Serialize, Clone)]
pub struct Link {
    pub id: i64,
    pub token: String,
    pub name: String,
    /// "file" or "dir"
    pub kind: String,
    pub target: String,
    pub pin: Option<String>,
    /// Cookie value proving the PIN was entered — never sent to clients.
    #[serde(skip)]
    pub secret: String,
    pub created_at: i64,
    pub expires_at: i64,
    pub views: i64,
    pub failed: i64,
    pub last_access: Option<i64>,
    pub expired: bool,
    pub locked: bool,
}

/// A device logged in with the PIN.
#[derive(Serialize, Clone)]
pub struct Session {
    pub id: i64,
    /// Cookie value — never sent to clients.
    #[serde(skip)]
    pub token: String,
    pub ip: String,
    pub agent: String,
    pub created_at: i64,
    pub last_seen: i64,
    pub expires_at: i64,
}

#[derive(Serialize, Clone)]
pub struct LogEntry {
    pub id: i64,
    pub ts: i64,
    pub ip: String,
    pub action: String,
    pub detail: String,
}

pub struct Db {
    conn: Mutex<Connection>,
}

fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    if version < 1 {
        conn.execute_batch(SCHEMA_V1)?;
    }
    if version < 2 {
        // Logins survive restarts; folders get 3 permission levels instead of an
        // upload on/off flag; a small key/value table for app-wide settings.
        conn.execute_batch(
            "BEGIN;
            CREATE TABLE IF NOT EXISTS sessions (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                token      TEXT    NOT NULL UNIQUE,
                ip         TEXT    NOT NULL,
                agent      TEXT    NOT NULL,
                created_at INTEGER NOT NULL,
                last_seen  INTEGER NOT NULL,
                expires_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS settings (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            ALTER TABLE folders ADD COLUMN perm INTEGER NOT NULL DEFAULT 0;
            UPDATE folders SET perm = allow_upload;
            ALTER TABLE folders DROP COLUMN allow_upload;
            PRAGMA user_version = 2;
            COMMIT;",
        )?;
    }
    Ok(())
}

const SCHEMA_V1: &str = "CREATE TABLE IF NOT EXISTS folders (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT    NOT NULL,
                path         TEXT    NOT NULL UNIQUE,
                allow_upload INTEGER NOT NULL DEFAULT 0,
                created_at   INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS links (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                token       TEXT    NOT NULL UNIQUE,
                name        TEXT    NOT NULL,
                kind        TEXT    NOT NULL,
                target      TEXT    NOT NULL,
                pin         TEXT,
                secret      TEXT    NOT NULL,
                created_at  INTEGER NOT NULL,
                expires_at  INTEGER NOT NULL,
                views       INTEGER NOT NULL DEFAULT 0,
                failed      INTEGER NOT NULL DEFAULT 0,
                last_access INTEGER
            );
            CREATE TABLE IF NOT EXISTS logs (
                id     INTEGER PRIMARY KEY AUTOINCREMENT,
                ts     INTEGER NOT NULL,
                ip     TEXT    NOT NULL,
                action TEXT    NOT NULL,
                detail TEXT    NOT NULL
            );
            PRAGMA user_version = 1;";

fn row_to_session(r: &Row) -> rusqlite::Result<Session> {
    Ok(Session {
        id: r.get("id")?,
        token: r.get("token")?,
        ip: r.get("ip")?,
        agent: r.get("agent")?,
        created_at: r.get("created_at")?,
        last_seen: r.get("last_seen")?,
        expires_at: r.get("expires_at")?,
    })
}

fn row_to_folder(r: &Row) -> rusqlite::Result<Folder> {
    let path: String = r.get("path")?;
    Ok(Folder {
        id: r.get("id")?,
        name: r.get("name")?,
        exists: Path::new(&path).is_dir(),
        path,
        perm: r.get::<_, i64>("perm")?.clamp(0, PERM_FULL as i64) as u8,
    })
}

fn row_to_link(r: &Row) -> rusqlite::Result<Link> {
    let expires_at: i64 = r.get("expires_at")?;
    let failed: i64 = r.get("failed")?;
    Ok(Link {
        id: r.get("id")?,
        token: r.get("token")?,
        name: r.get("name")?,
        kind: r.get("kind")?,
        target: r.get("target")?,
        pin: r.get("pin")?,
        secret: r.get("secret")?,
        created_at: r.get("created_at")?,
        expires_at,
        views: r.get("views")?,
        failed,
        last_access: r.get("last_access")?,
        expired: expires_at <= now(),
        locked: failed >= MAX_LINK_FAILS,
    })
}

fn db_err(e: rusqlite::Error) -> String {
    format!("Lỗi cơ sở dữ liệu: {}", e)
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Db> {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> rusqlite::Result<Db> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(conn: Connection) -> rusqlite::Result<Db> {
        conn.busy_timeout(std::time::Duration::from_secs(3))?;
        migrate(&conn)?;
        conn.execute(
            "DELETE FROM links WHERE expires_at < ?1",
            params![now() - EXPIRED_KEEP_SECS],
        )?;
        conn.execute("DELETE FROM sessions WHERE expires_at <= ?1", params![now()])?;
        Ok(Db {
            conn: Mutex::new(conn),
        })
    }

    fn c(&self) -> MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    // ---------------- Public folders ----------------

    pub fn folders(&self) -> Vec<Folder> {
        let conn = self.c();
        let mut stmt = match conn.prepare("SELECT * FROM folders ORDER BY id") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map([], row_to_folder)
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    pub fn folder(&self, id: i64) -> Option<Folder> {
        self.c()
            .query_row("SELECT * FROM folders WHERE id = ?1", params![id], row_to_folder)
            .optional()
            .ok()
            .flatten()
    }

    pub fn add_folder(&self, dir: &str) -> Result<Folder, String> {
        let path = Path::new(dir);
        if !path.is_dir() {
            return Err("Thư mục không tồn tại".to_string());
        }
        let conn = self.c();
        let exists: bool = conn
            .query_row("SELECT 1 FROM folders WHERE path = ?1", params![dir], |_| Ok(()))
            .optional()
            .map_err(db_err)?
            .is_some();
        if exists {
            return Err("Thư mục này đã có trong danh sách".to_string());
        }
        conn.execute(
            "INSERT INTO folders (name, path, perm, created_at) VALUES (?1, ?2, 0, ?3)",
            params![display_name(path), dir, now()],
        )
        .map_err(db_err)?;
        let id = conn.last_insert_rowid();
        conn.query_row("SELECT * FROM folders WHERE id = ?1", params![id], row_to_folder)
            .map_err(db_err)
    }

    pub fn update_folder(&self, id: i64, name: &str, perm: u8) -> Result<(), String> {
        let name = name.trim();
        if name.is_empty() {
            return Err("Tên không được để trống".to_string());
        }
        if perm > PERM_FULL {
            return Err("Quyền không hợp lệ".to_string());
        }
        let name: String = name.chars().take(60).collect();
        self.c()
            .execute(
                "UPDATE folders SET name = ?1, perm = ?2 WHERE id = ?3",
                params![name, perm, id],
            )
            .map_err(db_err)?;
        Ok(())
    }

    // ---------------- Settings ----------------

    fn setting(&self, key: &str) -> Option<String> {
        self.c()
            .query_row("SELECT value FROM settings WHERE key = ?1", params![key], |r| r.get(0))
            .optional()
            .ok()
            .flatten()
    }

    fn set_setting(&self, key: &str, value: &str) {
        let _ = self.c().execute(
            "INSERT INTO settings (key, value) VALUES (?1, ?2)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![key, value],
        );
    }

    /// Permission for the main folder (root 0). Defaults to upload, as before.
    pub fn main_perm(&self) -> u8 {
        self.setting("main_perm")
            .and_then(|v| v.parse::<u8>().ok())
            .filter(|p| *p <= PERM_FULL)
            .unwrap_or(PERM_UPLOAD)
    }

    pub fn set_main_perm(&self, perm: u8) -> Result<(), String> {
        if perm > PERM_FULL {
            return Err("Quyền không hợp lệ".to_string());
        }
        self.set_setting("main_perm", &perm.to_string());
        Ok(())
    }

    // ---------------- Login sessions ----------------

    /// Start a session for a device that just entered the right PIN.
    pub fn create_session(&self, ip: &str, agent: &str) -> Result<Session, String> {
        let now = now();
        let agent: String = agent.chars().take(300).collect();
        let conn = self.c();
        conn.execute(
            "INSERT INTO sessions (token, ip, agent, created_at, last_seen, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?4, ?5)",
            params![random_token(48), ip, agent, now, now + SESSION_SECS],
        )
        .map_err(db_err)?;
        let id = conn.last_insert_rowid();
        conn.query_row("SELECT * FROM sessions WHERE id = ?1", params![id], row_to_session)
            .map_err(db_err)
    }

    /// Is this cookie a live session? Also records that the device is active.
    pub fn session_valid(&self, token: &str, ip: &str) -> bool {
        let now = now();
        let conn = self.c();
        let found: Option<(i64, i64)> = conn
            .query_row(
                "SELECT id, last_seen FROM sessions WHERE token = ?1 AND expires_at > ?2",
                params![token, now],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .ok()
            .flatten();
        match found {
            Some((id, last_seen)) => {
                if now - last_seen >= SESSION_TOUCH_SECS {
                    let _ = conn.execute(
                        "UPDATE sessions SET last_seen = ?1, ip = ?2 WHERE id = ?3",
                        params![now, ip, id],
                    );
                }
                true
            }
            None => false,
        }
    }

    pub fn sessions(&self) -> Vec<Session> {
        let conn = self.c();
        let mut stmt = match conn
            .prepare("SELECT * FROM sessions WHERE expires_at > ?1 ORDER BY last_seen DESC")
        {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![now()], row_to_session)
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    /// Log out one device (by cookie).
    pub fn end_session(&self, token: &str) {
        let _ = self.c().execute("DELETE FROM sessions WHERE token = ?1", params![token]);
    }

    /// Log out one device (from the control window).
    pub fn delete_session(&self, id: i64) {
        let _ = self.c().execute("DELETE FROM sessions WHERE id = ?1", params![id]);
    }

    /// Log out every device.
    pub fn clear_sessions(&self) {
        let _ = self.c().execute("DELETE FROM sessions", []);
    }

    pub fn remove_folder(&self, id: i64) {
        let _ = self.c().execute("DELETE FROM folders WHERE id = ?1", params![id]);
    }

    // ---------------- Share links ----------------

    /// Create a temporary link to `target` (a file or a folder) valid for `hours`.
    pub fn create_link(&self, target: &Path, hours: i64, pin: Option<String>) -> Result<Link, String> {
        let pin = normalize_pin(pin)?;
        if !(1..=MAX_LINK_HOURS).contains(&hours) {
            return Err("Thời hạn không hợp lệ".to_string());
        }
        let target = std::fs::canonicalize(target)
            .map_err(|_| "Không tìm thấy file/thư mục".to_string())?;
        let kind = if target.is_dir() { "dir" } else { "file" };
        let created = now();
        let conn = self.c();
        conn.execute(
            "INSERT INTO links (token, name, kind, target, pin, secret, created_at, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                random_token(10),
                display_name(&target),
                kind,
                clean_path(&target),
                pin,
                random_token(40),
                created,
                created + hours * 3600
            ],
        )
        .map_err(db_err)?;
        let id = conn.last_insert_rowid();
        conn.query_row("SELECT * FROM links WHERE id = ?1", params![id], row_to_link)
            .map_err(db_err)
    }

    pub fn links(&self) -> Vec<Link> {
        let conn = self.c();
        let mut stmt = match conn.prepare("SELECT * FROM links ORDER BY id DESC") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map([], row_to_link)
            .map(|rows| rows.filter_map(Result::ok).collect())
            .unwrap_or_default()
    }

    pub fn link_by_token(&self, token: &str) -> Option<Link> {
        self.c()
            .query_row("SELECT * FROM links WHERE token = ?1", params![token], row_to_link)
            .optional()
            .ok()
            .flatten()
    }

    /// Delete (revoke) a link; returns it so the caller can log what was removed.
    pub fn delete_link(&self, id: i64) -> Option<Link> {
        let conn = self.c();
        let link = conn
            .query_row("SELECT * FROM links WHERE id = ?1", params![id], row_to_link)
            .optional()
            .ok()
            .flatten()?;
        let _ = conn.execute("DELETE FROM links WHERE id = ?1", params![id]);
        Some(link)
    }

    /// Remove every expired link.
    pub fn purge_links(&self) -> usize {
        self.c()
            .execute("DELETE FROM links WHERE expires_at <= ?1", params![now()])
            .unwrap_or(0)
    }

    pub fn link_opened(&self, id: i64) {
        let _ = self.c().execute(
            "UPDATE links SET views = views + 1, last_access = ?1 WHERE id = ?2",
            params![now(), id],
        );
    }

    pub fn link_touched(&self, id: i64) {
        let _ = self.c().execute(
            "UPDATE links SET last_access = ?1 WHERE id = ?2",
            params![now(), id],
        );
    }

    /// Record a wrong PIN; returns the new failure count.
    pub fn link_failed(&self, id: i64) -> i64 {
        let conn = self.c();
        let _ = conn.execute("UPDATE links SET failed = failed + 1 WHERE id = ?1", params![id]);
        conn.query_row("SELECT failed FROM links WHERE id = ?1", params![id], |r| r.get(0))
            .unwrap_or(MAX_LINK_FAILS)
    }

    /// Clear the failure counter (successful login, or the owner unlocking the link).
    pub fn link_reset_fails(&self, id: i64) {
        let _ = self.c().execute("UPDATE links SET failed = 0 WHERE id = ?1", params![id]);
    }

    // ---------------- Activity log ----------------

    pub fn log(&self, ip: &str, action: &str, detail: &str) {
        let conn = self.c();
        let _ = conn.execute(
            "INSERT INTO logs (ts, ip, action, detail) VALUES (?1, ?2, ?3, ?4)",
            params![now(), ip, action, detail],
        );
        let _ = conn.execute(
            "DELETE FROM logs WHERE id <= (SELECT MAX(id) FROM logs) - ?1",
            params![MAX_LOG_ROWS],
        );
    }

    pub fn logs(&self, limit: i64) -> Vec<LogEntry> {
        let conn = self.c();
        let mut stmt = match conn.prepare("SELECT * FROM logs ORDER BY id DESC LIMIT ?1") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };
        stmt.query_map(params![limit], |r| {
            Ok(LogEntry {
                id: r.get("id")?,
                ts: r.get("ts")?,
                ip: r.get("ip")?,
                action: r.get("action")?,
                detail: r.get("detail")?,
            })
        })
        .map(|rows| rows.filter_map(Result::ok).collect())
        .unwrap_or_default()
    }

    pub fn clear_logs(&self) {
        let _ = self.c().execute("DELETE FROM logs", []);
    }

    #[cfg(test)]
    pub fn force_expire(&self, id: i64) {
        self.c()
            .execute("UPDATE links SET expires_at = 1 WHERE id = ?1", params![id])
            .unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("namsv-test-{}-{}", tag, random_token(6)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn folders_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        let dir = tmp_dir("folders");
        let dir_s = dir.to_string_lossy().to_string();
        let f = db.add_folder(&dir_s).unwrap();
        assert!(f.perm == PERM_VIEW && f.exists);
        assert!(db.add_folder(&dir_s).is_err(), "duplicate path must be rejected");
        db.update_folder(f.id, "  Phim  ", PERM_FULL).unwrap();
        let f2 = db.folder(f.id).unwrap();
        assert_eq!(f2.name, "Phim");
        assert_eq!(f2.perm, PERM_FULL);
        assert!(db.update_folder(f.id, "   ", PERM_UPLOAD).is_err());
        assert!(db.update_folder(f.id, "x", 3).is_err());

        assert_eq!(db.main_perm(), PERM_UPLOAD);
        db.set_main_perm(PERM_FULL).unwrap();
        assert_eq!(db.main_perm(), PERM_FULL);
        assert!(db.set_main_perm(9).is_err());
        db.remove_folder(f.id);
        assert!(db.folders().is_empty());
        assert!(db.add_folder("Z:\\definitely\\missing\\dir").is_err());
    }

    #[test]
    fn links_pin_lockout_and_purge() {
        let db = Db::open_in_memory().unwrap();
        let dir = tmp_dir("links");
        let file = dir.join("a.txt");
        std::fs::write(&file, b"hi").unwrap();

        assert!(db.create_link(&file, 1, Some("12a4".into())).is_err());
        assert!(db.create_link(&file, 0, None).is_err());
        let l = db.create_link(&file, 24, Some("1234".into())).unwrap();
        assert_eq!(l.kind, "file");
        assert_eq!(l.name, "a.txt");
        assert_eq!(l.token.len(), 10);
        assert!(!l.expired && !l.locked);
        assert!(!l.target.starts_with(r"\\?\"));

        for i in 1..=MAX_LINK_FAILS {
            assert_eq!(db.link_failed(l.id), i);
        }
        assert!(db.link_by_token(&l.token).unwrap().locked);
        db.link_reset_fails(l.id);
        assert!(!db.link_by_token(&l.token).unwrap().locked);

        let d = db.create_link(&dir, 1, None).unwrap();
        assert_eq!(d.kind, "dir");
        assert!(d.pin.is_none());

        // Force-expire one link, then purge.
        db.force_expire(d.id);
        assert!(db.link_by_token(&d.token).unwrap().expired);
        assert_eq!(db.purge_links(), 1);
        assert_eq!(db.links().len(), 1);
        assert!(db.delete_link(l.id).is_some());
        assert!(db.link_by_token(&l.token).is_none());
    }

    #[test]
    fn migrates_v1_upload_flag_to_perm() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(SCHEMA_V1).unwrap();
        conn.execute_batch(
            "INSERT INTO folders (name, path, allow_upload, created_at) VALUES
                ('up', 'X:\\up', 1, 0), ('ro', 'X:\\ro', 0, 0);",
        )
        .unwrap();
        let db = Db::init(conn).unwrap();
        let perms: Vec<(String, u8)> = db.folders().into_iter().map(|f| (f.name, f.perm)).collect();
        assert_eq!(perms, vec![("up".into(), PERM_UPLOAD), ("ro".into(), PERM_VIEW)]);
        let v: i64 = db.c().query_row("PRAGMA user_version", [], |r| r.get(0)).unwrap();
        assert_eq!(v, 2);
    }

    #[test]
    fn sessions_roundtrip() {
        let db = Db::open_in_memory().unwrap();
        let a = db.create_session("192.168.1.5", "Mozilla/5.0 (iPhone)").unwrap();
        let b = db.create_session("192.168.1.6", "Mozilla/5.0 (Windows)").unwrap();
        assert_eq!(a.token.len(), 48);
        assert_ne!(a.token, b.token);
        assert!(!serde_json::to_string(&a).unwrap().contains(&a.token));
        assert!(db.session_valid(&a.token, "192.168.1.5"));
        assert!(!db.session_valid("nope", "192.168.1.5"));
        assert_eq!(db.sessions().len(), 2);

        db.end_session(&a.token);
        assert!(!db.session_valid(&a.token, "192.168.1.5"));
        db.delete_session(b.id);
        assert!(db.sessions().is_empty());

        let c = db.create_session("10.0.0.1", "x").unwrap();
        db.c()
            .execute("UPDATE sessions SET expires_at = 1 WHERE id = ?1", params![c.id])
            .unwrap();
        assert!(!db.session_valid(&c.token, "10.0.0.1"));
        assert!(db.sessions().is_empty());

        db.create_session("10.0.0.1", "x").unwrap();
        db.clear_sessions();
        assert!(db.sessions().is_empty());
    }

    #[test]
    fn logs_are_capped() {
        let db = Db::open_in_memory().unwrap();
        for i in 0..(MAX_LOG_ROWS + 25) {
            db.log("1.2.3.4", "upload", &i.to_string());
        }
        assert_eq!(db.logs(10_000).len() as i64, MAX_LOG_ROWS);
        assert_eq!(db.logs(1)[0].detail, (MAX_LOG_ROWS + 24).to_string());
        db.clear_logs();
        assert!(db.logs(10).is_empty());
    }
}
