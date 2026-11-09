//! Browser uploads are create-only, bound to one cookie and one write grant.
use super::*;
use crate::{
    model::{Entry, UploadProgress},
    server,
};
use axum::{body::Bytes, extract::DefaultBodyLimit, routing::put};
use std::io::Write;

pub(super) fn router() -> Router<Arc<ServerState>> {
    Router::new()
        .route("/v1/web/files/write/challenges", post(challenge))
        .route("/v1/web/files/write/challenges/{id}", get(challenge_result))
        .route("/v1/web/files/write/session", get(write_session))
        .route("/v1/web/files/uploads", post(begin))
        .route(
            "/v1/web/files/uploads/{id}",
            put(append)
                .delete(cancel)
                .layer(DefaultBodyLimit::max(CHUNK_BYTES as usize)),
        )
        .route("/v1/web/files/uploads/{id}/commit", post(commit))
}

fn grant(db: &Connection, headers: &HeaderMap) -> Result<(String, String, i64), ApiError> {
    authorize(db, headers)?;
    let session = web_status::named_session(db, headers, COOKIE)?;
    let (id, device) = db
        .query_row(
            "SELECT w.challenge_id,r.device_id FROM web_file_write_grants w
         JOIN web_file_grants r ON r.session_hash=w.session_hash
         WHERE w.session_hash=?1 AND w.expires_at>?2",
            params![session.hash, now()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(ApiError::internal)?
        .ok_or_else(|| failure(StatusCode::FORBIDDEN, "files_write_required"))?;
    Ok((session.hash, id, device))
}

async fn write_session(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Json<FileSession>, ApiError> {
    browser(&state, &headers, false)?;
    let db = state.db.lock().unwrap();
    grant(&db, &headers)?;
    authorize(&db, &headers).map(Json)
}

async fn challenge(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<ChallengeResponse>, ApiError> {
    browser(&state, &headers, true)?;
    authorize(&state.db.lock().unwrap(), &headers)?;
    web_status::issue_challenge(&state, &headers, &body, COOKIE, "files.write").map(Json)
}

async fn challenge_result(
    State(state): State<Arc<ServerState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<FileSession>, ApiError> {
    browser(&state, &headers, false)?;
    let db = state.db.lock().unwrap();
    let session = web_status::named_session(&db, &headers, COOKIE).map_err(|_| expired())?;
    let pending: Option<(bool, i64)> = db
        .query_row(
            "SELECT result IS NULL,expires_at FROM web_status_challenges
         WHERE id=?1 AND session_hash=?2 AND scope='files.write'",
            params![id, session.hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(ApiError::internal)?;
    match pending {
        Some((false, _)) => {
            grant(&db, &headers)?;
            authorize(&db, &headers).map(Json)
        }
        Some((true, expires)) if expires > now() => Err(failure(StatusCode::ACCEPTED, "pending")),
        _ => Err(failure(StatusCode::GONE, "challenge_expired")),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewUpload {
    path: String,
    size: i64,
    sha256: String,
}

fn available(db: &Connection, path: &str) -> Result<i64, ApiError> {
    server::check_path_namespace(db, path)
        .map_err(|_| failure(StatusCode::CONFLICT, "path_conflict"))?;
    let entry = server::stored_entry(db, path).map_err(ApiError::internal)?;
    if entry.as_ref().is_some_and(|e| !e.public.deleted) {
        return Err(failure(StatusCode::CONFLICT, "file_exists"));
    }
    Ok(entry.map(|e| e.public.revision).unwrap_or(0))
}

async fn begin(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Json(input): Json<NewUpload>,
) -> Result<Json<UploadProgress>, ApiError> {
    browser(&state, &headers, true)?;
    state.blocking(move |state| {
        grant(&state.db.lock().unwrap(), &headers)?;
        server::purge_upload_sessions(&state).map_err(ApiError::internal)?;
        if !crate::model::valid_path(&input.path) || !(0..=DOWNLOAD_BYTES).contains(&input.size)
            || !valid_secret(&input.sha256) {
            return Err(failure(StatusCode::BAD_REQUEST, "invalid_upload"));
        }
        let mut db = state.db.lock().unwrap();
        let tx = db.transaction().map_err(ApiError::internal)?;
        let (session, grant_id, device) = grant(&tx, &headers)?;
        let base = available(&tx, &input.path)?;
        let pending: i64 = tx.query_row("SELECT COUNT(*) FROM uploads WHERE device_id=?1", [device], |r| r.get(0)).map_err(ApiError::internal)?;
        let local: i64 = tx.query_row("SELECT COUNT(*) FROM web_file_uploads WHERE session_hash=?1", [&session], |r| r.get(0)).map_err(ApiError::internal)?;
        if pending >= server::MAX_UPLOAD_SESSIONS_PER_DEVICE || local >= 4 {
            return Err(failure(StatusCode::TOO_MANY_REQUESTS, "upload_limit"));
        }
        let id = uuid::Uuid::new_v4().to_string();
        let temp = state.data_dir.join("tmp").join(&id);
        std::fs::OpenOptions::new().write(true).create_new(true).open(&temp)
            .and_then(|file| file.sync_all()).map_err(ApiError::internal)?;
        server::sync_directory(&state.data_dir.join("tmp")).map_err(ApiError::internal)?;
        let inserted = (|| -> Result<(), ApiError> {
            tx.execute("INSERT INTO uploads(id,device_id,path,base_revision,size,sha256,received_size,temp_name,touched_at)
                VALUES(?1,?2,?3,?4,?5,?6,0,?1,?7)",
                params![id, device, input.path, base, input.size, input.sha256, now()]).map_err(ApiError::internal)?;
            tx.execute("INSERT INTO web_file_uploads VALUES(?1,?2,?3)", params![id, session, grant_id]).map_err(ApiError::internal)?;
            tx.commit().map_err(ApiError::internal)
        })();
        // On an uncertain SQL commit, startup recovery removes unreferenced
        // temporary files without deleting data possibly referenced by SQL.
        inserted?;
        Ok(Json(UploadProgress { id, offset: 0 }))
    }).await
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Fixture, checked};
    use super::*;
    use anyhow::Result;

    async fn writer(f: &Fixture) -> Result<HeaderMap> {
        let headers = f.browser().await?;
        f.grant(&headers, "files.read").await?;
        f.grant(&headers, "files.write").await?;
        Ok(headers)
    }
    async fn start(
        f: &Fixture,
        headers: &HeaderMap,
        path: &str,
        content: &[u8],
    ) -> Result<UploadProgress, ApiError> {
        begin(
            State(f.state.clone()),
            headers.clone(),
            Json(NewUpload {
                path: path.into(),
                size: content.len() as i64,
                sha256: crate::auth_protocol::hash(content),
            }),
        )
        .await
        .map(|r| r.0)
    }
    async fn part(
        f: &Fixture,
        headers: &HeaderMap,
        id: &str,
        offset: i64,
        data: &[u8],
    ) -> Result<UploadProgress, ApiError> {
        append(
            State(f.state.clone()),
            Path(id.into()),
            headers.clone(),
            Query(Offset { offset }),
            Bytes::copy_from_slice(data),
        )
        .await
        .map(|r| r.0)
    }
    async fn finish(f: &Fixture, headers: &HeaderMap, id: &str) -> Result<Entry, ApiError> {
        commit(State(f.state.clone()), Path(id.into()), headers.clone())
            .await
            .map(|r| r.0)
    }

    #[tokio::test]
    async fn uploads_require_explicit_write_proof_and_remain_cookie_bound() -> Result<()> {
        let f = Fixture::new()?;
        let a = f.browser().await?;
        f.grant(&a, "files.read").await?;
        assert_eq!(
            start(&f, &a, "private.txt", b"x").await.unwrap_err().1,
            "files_write_required"
        );
        let read_expiry = checked(authorize(&f.state.db.lock().unwrap(), &a))?.expires_at;
        f.grant(&a, "files.write").await?;
        assert_eq!(
            checked(authorize(&f.state.db.lock().unwrap(), &a))?.expires_at,
            read_expiry
        );
        let id = checked(start(&f, &a, "private.txt", b"x").await)?.id;
        let b = writer(&f).await?;
        assert_eq!(
            part(&f, &b, &id, 0, b"x").await.unwrap_err().1,
            "upload_not_found"
        );
        assert!(finish(&f, &b, &id).await.is_err());
        assert!(
            cancel(State(f.state.clone()), Path(id.clone()), b)
                .await
                .is_err()
        );
        for name in ["origin", "x-mysync-web", "sec-fetch-site"] {
            let mut forged = a.clone();
            forged.insert(name, "forged".parse()?);
            assert!(start(&f, &forged, "forged.txt", b"x").await.is_err());
            assert!(part(&f, &forged, &id, 0, b"x").await.is_err());
            assert!(finish(&f, &forged, &id).await.is_err());
        }
        // Renewal on the same enrollment keeps the in-flight upload usable.
        f.grant(&a, "files.read").await?;
        f.grant(&a, "files.write").await?;
        checked(part(&f, &a, &id, 0, b"x").await)?;
        // Expired write authority cannot be resurrected by renewing read.
        f.state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE web_file_write_grants SET expires_at=1", [])?;
        f.grant(&a, "files.read").await?;
        assert_eq!(
            part(&f, &a, &id, 0, b"x").await.unwrap_err().1,
            "files_write_required"
        );
        f.grant(&a, "files.write").await?;
        assert_eq!(
            part(&f, &a, &id, 0, b"x").await.unwrap_err().1,
            "upload_not_found"
        );
        assert_eq!(server::purge_upload_sessions(&f.state)?, 1);
        Ok(())
    }

    #[tokio::test]
    async fn chunks_are_bounded_ordered_and_verified_before_publication() -> Result<()> {
        let f = Fixture::new()?;
        let a = writer(&f).await?;
        let data = vec![b'x'; CHUNK_BYTES as usize + 3];
        let id = checked(start(&f, &a, "Projets/data.bin", &data).await)?.id;
        assert_eq!(
            finish(&f, &a, &id).await.unwrap_err().1,
            "upload_incomplete"
        );
        assert_eq!(
            part(&f, &a, &id, 1, b"x").await.unwrap_err().1,
            "invalid_offset"
        );
        assert_eq!(
            part(&f, &a, &id, 0, b"").await.unwrap_err().1,
            "invalid_chunk"
        );
        assert_eq!(
            part(&f, &a, &id, 0, &data).await.unwrap_err().0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        checked(part(&f, &a, &id, 0, &data[..CHUNK_BYTES as usize]).await)?;
        assert_eq!(
            part(&f, &a, &id, 0, b"x").await.unwrap_err().1,
            "invalid_offset"
        );
        checked(part(&f, &a, &id, CHUNK_BYTES as i64, b"xxx").await)?;
        let entry = checked(finish(&f, &a, &id).await)?;
        assert_eq!(
            entry.sha256.as_deref(),
            Some(crate::auth_protocol::hash(&data).as_str())
        );
        {
            let db = f.state.db.lock().unwrap();
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM uploads", [], |r| r.get::<_, i64>(0))?,
                0
            );
            let blob = server::stored_entry(&db, &entry.path)?
                .unwrap()
                .blob
                .unwrap();
            assert_eq!(
                std::fs::read(f.state.data_dir.join("blobs").join(blob))?,
                data
            );
        }
        let empty = checked(start(&f, &a, "empty.txt", b"").await)?.id;
        assert_eq!(checked(finish(&f, &a, &empty).await)?.size, Some(0));
        let corrupt = checked(start(&f, &a, "corrupt.txt", b"good").await)?.id;
        checked(part(&f, &a, &corrupt, 0, b"evil").await)?;
        assert_eq!(
            finish(&f, &a, &corrupt).await.unwrap_err().1,
            "integrity_failed"
        );
        assert!(server::stored_entry(&f.state.db.lock().unwrap(), "corrupt.txt")?.is_none());
        assert_eq!(
            checked(cancel(State(f.state.clone()), Path(corrupt.clone()), a).await)?.0,
            serde_json::json!({})
        );
        assert!(!f.state.data_dir.join("tmp").join(corrupt).exists());
        Ok(())
    }

    #[tokio::test]
    async fn uploads_never_overwrite_existing_or_concurrent_versions() -> Result<()> {
        let f = Fixture::new()?;
        let a = writer(&f).await?;
        f.entry("existing.txt", b"keep")?;
        f.entry("directory/keep.txt", b"keep")?;
        assert_eq!(
            start(&f, &a, "existing.txt", b"replace")
                .await
                .unwrap_err()
                .1,
            "file_exists"
        );
        for name in ["directory", "existing.txt/child"] {
            assert_eq!(
                start(&f, &a, name, b"x").await.unwrap_err().1,
                "path_conflict"
            );
        }
        for name in [
            "../escape",
            "/absolute",
            "a//b",
            "a\\b",
            ".mysync-conflicts/file",
            ".mysync-staging/file",
        ] {
            assert_eq!(
                start(&f, &a, name, b"x").await.unwrap_err().1,
                "invalid_upload"
            );
        }
        let b = writer(&f).await?;
        let first = checked(start(&f, &a, "race.txt", b"first").await)?.id;
        let second = checked(start(&f, &b, "race.txt", b"second").await)?.id;
        checked(part(&f, &a, &first, 0, b"first").await)?;
        checked(part(&f, &b, &second, 0, b"second").await)?;
        checked(finish(&f, &a, &first).await)?;
        assert_eq!(finish(&f, &b, &second).await.unwrap_err().1, "file_exists");
        {
            let db = f.state.db.lock().unwrap();
            assert_eq!(
                server::stored_entry(&db, "race.txt")?
                    .unwrap()
                    .public
                    .sha256,
                Some(crate::auth_protocol::hash(b"first"))
            );
        }
        let late = checked(start(&f, &a, "later/file", b"later").await)?.id;
        checked(part(&f, &a, &late, 0, b"later").await)?;
        f.entry("later", b"new parent")?;
        assert_eq!(finish(&f, &a, &late).await.unwrap_err().1, "path_conflict");
        Ok(())
    }

    #[tokio::test]
    async fn expiry_logout_revocation_and_quotas_stop_pending_uploads() -> Result<()> {
        let f = Fixture::new()?;
        let a = writer(&f).await?;
        for index in 0..4 {
            checked(start(&f, &a, &format!("file-{index}"), b"").await)?;
        }
        assert_eq!(
            start(&f, &a, "too-many", b"").await.unwrap_err().1,
            "upload_limit"
        );
        f.state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE web_file_write_grants SET expires_at=1", [])?;
        assert_eq!(server::purge_upload_sessions(&f.state)?, 4);
        let b = writer(&f).await?;
        let id = checked(start(&f, &b, "logout.txt", b"").await)?.id;
        checked(super::super::logout(State(f.state.clone()), b.clone()).await)?;
        assert!(finish(&f, &b, &id).await.is_err());
        assert_eq!(server::purge_upload_sessions(&f.state)?, 1);
        let c = writer(&f).await?;
        let id = checked(start(&f, &c, "revoked.txt", b"x").await)?.id;
        checked(part(&f, &c, &id, 0, b"x").await)?;
        server::revoke_device(&f.state, "test-device")?;
        assert!(part(&f, &c, &id, 0, b"x").await.is_err());
        assert_eq!(finish(&f, &c, &id).await.unwrap_err().1, "session_expired");
        assert!(server::stored_entry(&f.state.db.lock().unwrap(), "revoked.txt")?.is_none());
        Ok(())
    }
}

fn owned(db: &Connection, headers: &HeaderMap, id: &str) -> Result<server::UploadRow, ApiError> {
    let (session, grant_id, device) = grant(db, headers)?;
    let exists: bool = db
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM web_file_uploads
        WHERE upload_id=?1 AND session_hash=?2 AND grant_id=?3)",
            params![id, session, grant_id],
            |r| r.get(0),
        )
        .map_err(ApiError::internal)?;
    if !exists {
        return Err(failure(StatusCode::NOT_FOUND, "upload_not_found"));
    }
    server::upload_row(db, id, device)
        .map_err(ApiError::internal)?
        .ok_or_else(|| failure(StatusCode::NOT_FOUND, "upload_not_found"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Offset {
    offset: i64,
}

async fn append(
    State(state): State<Arc<ServerState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Query(query): Query<Offset>,
    body: Bytes,
) -> Result<Json<UploadProgress>, ApiError> {
    browser(&state, &headers, true)?;
    state
        .blocking(move |state| {
            let _guard = server::lock_upload(&state, &id)?;
            let db = state.db.lock().unwrap();
            let upload = owned(&db, &headers, &id)?;
            if query.offset != upload.offset {
                return Err(failure(StatusCode::CONFLICT, "invalid_offset"));
            }
            if body.is_empty()
                || body.len() as u64 > CHUNK_BYTES
                || body.len() as i64 > upload.size - upload.offset
            {
                return Err(failure(StatusCode::PAYLOAD_TOO_LARGE, "invalid_chunk"));
            }
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .open(state.data_dir.join("tmp").join(&upload.temp_name))
                .map_err(ApiError::internal)?;
            file.set_len(upload.offset as u64)
                .map_err(ApiError::internal)?;
            file.seek(SeekFrom::Start(upload.offset as u64))
                .map_err(ApiError::internal)?;
            file.write_all(&body).map_err(ApiError::internal)?;
            file.sync_all().map_err(ApiError::internal)?;
            let offset = upload.offset + body.len() as i64;
            db.execute(
                "UPDATE uploads SET received_size=?2,touched_at=?3 WHERE id=?1",
                params![id, offset, now()],
            )
            .map_err(ApiError::internal)?;
            Ok(Json(UploadProgress { id, offset }))
        })
        .await
}

async fn cancel(
    State(state): State<Arc<ServerState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<serde_json::Value>, ApiError> {
    browser(&state, &headers, true)?;
    state
        .blocking(move |state| {
            let _guard = server::lock_upload(&state, &id)?;
            let db = state.db.lock().unwrap();
            let upload = owned(&db, &headers, &id)?;
            db.execute("DELETE FROM uploads WHERE id=?1", [&id])
                .map_err(ApiError::internal)?;
            let _ = std::fs::remove_file(state.data_dir.join("tmp").join(upload.temp_name));
            Ok(Json(serde_json::json!({})))
        })
        .await
}

async fn commit(
    State(state): State<Arc<ServerState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Entry>, ApiError> {
    browser(&state, &headers, true)?;
    state
        .blocking(move |state| {
            let _guard = server::lock_upload(&state, &id)?;
            let upload = owned(&state.db.lock().unwrap(), &headers, &id)?;
            if upload.offset != upload.size {
                return Err(failure(StatusCode::CONFLICT, "upload_incomplete"));
            }
            let temp = state.data_dir.join("tmp").join(&upload.temp_name);
            let (digest, size) = server::hash_upload(&temp).map_err(ApiError::internal)?;
            if digest != upload.sha256 || size != upload.size {
                return Err(failure(StatusCode::BAD_REQUEST, "integrity_failed"));
            }
            let result = server::commit_upload_checked(
                &state,
                &upload.path,
                upload.base_revision,
                &temp,
                digest,
                size,
                |db| {
                    owned(db, &headers, &id)?;
                    available(db, &upload.path)?;
                    // Delete ownership in the same transaction that publishes the file.
                    db.execute("DELETE FROM uploads WHERE id=?1", [&id])
                        .map_err(ApiError::internal)?;
                    Ok(())
                },
            );
            result.map(Json)
        })
        .await
}
