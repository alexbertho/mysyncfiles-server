//! Local instance summary. Never initializes a database or changes enrollment.
use std::path::Path;

use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct InstanceInfo {
    pub server_name: String,
    /// The origin public key already pinned by clients; no separate identifier.
    pub server_id: String,
    pub public_url: Option<String>,
    pub approved_devices: u64,
    pub pending_invitations: u64,
    pub revoked_devices: u64,
    pub files: u64,
    pub file_bytes: u64,
    pub trash_files: u64,
    pub trash_bytes: u64,
    pub uploads: u64,
    pub upload_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_available_bytes: u64,
}

pub fn instance_info(data_dir: impl AsRef<Path>) -> Result<InstanceInfo> {
    let data_dir = data_dir.as_ref();
    let mut db = Connection::open_with_flags(
        data_dir.join("metadata.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .context("cannot read an initialized server database; check --data-dir")?;
    let tx = db.transaction()?;
    let setting = |key: &str| -> Result<Option<String>> {
        Ok(tx
            .query_row("SELECT value FROM auth_settings WHERE key=?1", [key], |r| {
                r.get(0)
            })
            .optional()?)
    };
    let server_name = setting("server_name")?.unwrap_or_else(|| "MySyncFiles".into());
    let public_url = setting("public_url")?;
    let server_id = hex::encode(super::origin::read_key(&tx)?.verifying_key().to_bytes());
    let (approved_devices, pending_invitations, revoked_devices) = tx.query_row(
        "SELECT
         (SELECT COUNT(*) FROM devices d WHERE d.revoked_at IS NULL AND EXISTS(
            SELECT 1 FROM device_enrollments e WHERE e.device_id=d.id AND e.approved_at IS NOT NULL)),
         (SELECT COUNT(*) FROM device_enrollments e JOIN devices d ON d.id=e.device_id
            WHERE e.approved_at IS NULL AND e.expires_at>?1 AND d.revoked_at IS NULL),
         (SELECT COUNT(*) FROM devices WHERE revoked_at IS NOT NULL)",
        [crate::auth_protocol::now()],
        |r| Ok((nonnegative(r, 0)?, nonnegative(r, 1)?, nonnegative(r, 2)?)),
    )?;
    let (files, file_bytes) = tx.query_row(
        "SELECT COUNT(*),COALESCE(SUM(size),0) FROM entries WHERE deleted=0",
        [],
        |r| Ok((nonnegative(r, 0)?, nonnegative(r, 1)?)),
    )?;
    let (trash_files, trash_bytes) = tx.query_row(
        "SELECT COUNT(*),COALESCE(SUM(size),0) FROM trash",
        [],
        |r| Ok((nonnegative(r, 0)?, nonnegative(r, 1)?)),
    )?;
    let (uploads, upload_bytes) = tx.query_row(
        "SELECT COUNT(*),COALESCE(SUM(received_size),0) FROM uploads",
        [],
        |r| Ok((nonnegative(r, 0)?, nonnegative(r, 1)?)),
    )?;
    tx.commit()?;
    let disk = rustix::fs::statvfs(data_dir)?;
    Ok(InstanceInfo {
        server_name,
        server_id,
        public_url,
        approved_devices,
        pending_invitations,
        revoked_devices,
        files,
        file_bytes,
        trash_files,
        trash_bytes,
        uploads,
        upload_bytes,
        disk_total_bytes: disk.f_blocks.saturating_mul(disk.f_frsize),
        disk_available_bytes: disk.f_bavail.saturating_mul(disk.f_frsize),
    })
}

fn nonnegative(row: &rusqlite::Row<'_>, column: usize) -> rusqlite::Result<u64> {
    let value: i64 = row.get(column)?;
    u64::try_from(value).map_err(|_| rusqlite::Error::IntegralValueOutOfRange(column, value))
}
