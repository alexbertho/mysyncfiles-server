//! Scoped browser access. Status, reading and uploading have separate authority.
mod directories;
pub(super) mod editor;
mod uploads;
use super::{ApiError, ServerState, web_assets, web_status};
use crate::{auth_protocol::now, web_status_protocol::*};
use axum::{
    Json, Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Seek, SeekFrom},
    sync::Arc,
};
use tokio::io::AsyncReadExt;
use tokio_util::io::ReaderStream;

const COOKIE: &str = "__Host-mysync-files";
const PAGE_SIZE: usize = 200;
const CHUNK_BYTES: u64 = 8 * 1024 * 1024;
const DOWNLOAD_BYTES: i64 = 256 * 1024 * 1024;

pub(super) fn router() -> Router<Arc<ServerState>> {
    Router::new()
        .route("/", get(page))
        .route("/index.html", get(page))
        .route("/files", get(page))
        .route("/editor", get(page))
        .route(
            "/v1/web/files/session",
            get(read_session).post(start_session),
        )
        .route("/v1/web/files/logout", post(logout))
        .route("/v1/web/files/challenges", post(challenge))
        .route("/v1/web/files/challenges/{id}", get(challenge_result))
        .route("/v1/web/files/entries", get(entries))
        .route("/v1/web/files/chunk", get(chunk))
        .route("/v1/web/files/pdf", get(pdf))
        .merge(uploads::router())
        .merge(directories::router())
        .merge(editor::router())
}

fn failure(status: StatusCode, code: &str) -> ApiError {
    ApiError(status, code.into())
}
fn expired() -> ApiError {
    failure(StatusCode::UNAUTHORIZED, "session_expired")
}

async fn page(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let html = web_assets::read(&state, "index.html").await?;
    web_status::page_response(
        &state,
        &headers,
        COOKIE,
        FILES_SESSION_SECONDS + SESSION_SECONDS,
        html,
    )
}

#[derive(Serialize)]
struct FileSession {
    device_name: String,
    expires_at: i64,
    download_limit: i64,
    chunk_bytes: u64,
    upload_limit: i64,
    manage_limit: usize,
}

/// Rechecks the specific enrollment and logical device on every metadata/chunk
/// request. Revocation does not wait for the 30-minute browser deadline.
fn authorize(db: &Connection, headers: &HeaderMap) -> Result<FileSession, ApiError> {
    let session = web_status::named_session(db, headers, COOKIE).map_err(|_| expired())?;
    db.query_row(
        "SELECT d.name,g.expires_at FROM web_file_grants g
        JOIN device_enrollments e ON e.id=g.enrollment_id AND e.device_id=g.device_id
        JOIN devices d ON d.id=g.device_id
        WHERE g.session_hash=?1 AND g.expires_at>?2 AND d.revoked_at IS NULL
        AND e.approved_at IS NOT NULL AND e.verified_at IS NOT NULL",
        params![session.hash, now()],
        |r| {
            Ok(FileSession {
                device_name: r.get(0)?,
                expires_at: r.get(1)?,
                download_limit: DOWNLOAD_BYTES,
                chunk_bytes: CHUNK_BYTES,
                upload_limit: DOWNLOAD_BYTES,
                manage_limit: directories::FILE_LIMIT,
            })
        },
    )
    .optional()
    .map_err(ApiError::internal)?
    .ok_or_else(expired)
}

fn browser(state: &ServerState, headers: &HeaderMap, write: bool) -> Result<(), ApiError> {
    web_status::browser_request(headers, &web_status::public_origin(state)?, write)
}

async fn start_session(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    browser(&state, &headers, true)?;
    let mut response = web_status::page_response(
        &state,
        &headers,
        COOKIE,
        FILES_SESSION_SECONDS + SESSION_SECONDS,
        "{}",
    )?;
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
    Ok(response)
}

async fn read_session(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    browser(&state, &headers, false)?;
    session_response(&state.db.lock().unwrap(), &headers)
}

fn session_response(db: &Connection, headers: &HeaderMap) -> Result<Response, ApiError> {
    let session = authorize(db, headers)?;
    let token = web_status::cookie_token(headers, COOKIE).ok_or_else(expired)?;
    let deadline: i64 = db.query_row(
        "SELECT MIN(expires_at) FROM (
        SELECT ?2 AS expires_at
        UNION ALL SELECT expires_at FROM web_file_write_grants WHERE session_hash=?1 AND expires_at>?3
        UNION ALL SELECT expires_at FROM web_file_manage_grants WHERE session_hash=?1 AND expires_at>?3
        UNION ALL SELECT expires_at FROM web_editor_grants WHERE session_hash=?1 AND expires_at>?3)",
        params![crate::auth_protocol::hash(token), session.expires_at, now()], |r| r.get(0),
    ).map_err(ApiError::internal)?;
    // Refresh transport lifetime after a proof or a lost acknowledgement.
    // Merely reading the session never extends its server-side authorization.
    let seconds = (session.expires_at - now()).max(0) + SESSION_SECONDS;
    #[derive(Serialize)]
    struct RenewableSession {
        #[serde(flatten)]
        session: FileSession,
        renew_at: i64,
    }
    let mut response = Json(RenewableSession {
        session,
        renew_at: deadline - SESSION_SECONDS,
    })
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        format!("{COOKIE}={token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age={seconds}")
            .parse()
            .unwrap(),
    );
    Ok(response)
}

async fn logout(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    browser(&state, &headers, true)?;
    if let Some(hash) = web_status::cookie_hash(&headers, COOKIE) {
        state
            .db
            .lock()
            .unwrap()
            .execute(
                "DELETE FROM web_status_sessions WHERE token_hash=?1",
                [hash],
            )
            .map_err(ApiError::internal)?;
    }
    Ok((
        [(
            header::SET_COOKIE,
            format!("{COOKIE}=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
        )],
        Json(serde_json::json!({})),
    )
        .into_response())
}

async fn challenge(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<ChallengeResponse>, ApiError> {
    web_status::issue_challenge(&state, &headers, &body, COOKIE, "files.read").map(Json)
}

async fn challenge_result(
    State(state): State<Arc<ServerState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    browser(&state, &headers, false)?;
    let db = state.db.lock().unwrap();
    let session = web_status::named_session(&db, &headers, COOKIE).map_err(|_| expired())?;
    let accepted: Option<(i64, bool)> = db
        .query_row(
            "SELECT expires_at,result IS NOT NULL FROM web_status_challenges
        WHERE id=?1 AND session_hash=?2 AND scope='files.read'",
            params![id, session.hash],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(ApiError::internal)?;
    let Some((expires_at, complete)) = accepted else {
        return Err(expired());
    };
    if !complete {
        return Err(if expires_at <= now() {
            failure(StatusCode::GONE, "challenge_expired")
        } else {
            failure(StatusCode::ACCEPTED, "pending")
        });
    }
    session_response(&db, &headers)
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListQuery {
    #[serde(default)]
    directory: String,
    #[serde(default)]
    search: String,
    #[serde(default)]
    after: String,
}
#[derive(Debug, Serialize)]
struct BrowserEntry {
    kind: String,
    path: String,
    size: Option<i64>,
    revision: Option<i64>,
    sha256: Option<String>,
    updated_at: Option<i64>,
}
#[derive(Serialize)]
struct Listing {
    entries: Vec<BrowserEntry>,
    next: Option<String>,
}

async fn entries(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Query(query): Query<ListQuery>,
) -> Result<Json<Listing>, ApiError> {
    browser(&state, &headers, false)?;
    state
        .blocking(move |state| {
            let db = state.db.lock().unwrap();
            authorize(&db, &headers)?;
            list(&db, query).map(Json)
        })
        .await
}

fn list(db: &Connection, query: ListQuery) -> Result<Listing, ApiError> {
    if (!query.directory.is_empty() && !crate::model::valid_path(&query.directory))
        || query.search.len() > 255
        || query.after.len() > 8194
    {
        return Err(failure(StatusCode::BAD_REQUEST, "invalid_request"));
    }
    let prefix = if query.directory.is_empty() {
        String::new()
    } else {
        format!("{}/", query.directory)
    };
    // The byte range [directory + '/', directory + '0') uses the path index
    // and preserves literal %, _, case and Linux path boundaries. The root
    // naturally covers every live entry. Sum existing metadata in the same
    // pass that groups folders, without reading blobs or querying each folder.
    let restriction = if prefix.is_empty() {
        ""
    } else {
        "AND path>=?1 AND path<?5"
    };
    let end = format!("{}0", query.directory);
    let limit = (PAGE_SIZE + 1) as i64;
    let bindings = params![prefix, query.search, query.after, limit, end];
    let bindings = &bindings[..if prefix.is_empty() { 4 } else { 5 }];
    let sql = format!(
        "WITH candidates AS (
        SELECT path,size,revision,sha256,updated_at,substr(path,length(?1)+1) AS relative FROM entries
        WHERE deleted=0 {restriction}
    ), items AS (
        SELECT 'directory' AS kind,?1 || substr(relative,1,instr(relative,'/')-1) AS path,
            SUM(size) AS size,NULL AS revision,NULL AS sha256,MAX(updated_at) AS updated_at FROM candidates
            WHERE ?2='' AND instr(relative,'/')>0 GROUP BY 2
        UNION ALL
        SELECT 'file',path,size,revision,sha256,updated_at FROM candidates
            WHERE (?2='' AND instr(relative,'/')=0) OR (?2<>'' AND instr(lower(path),lower(?2))>0)
    ) SELECT kind,path,size,revision,sha256,updated_at FROM items
        WHERE kind || ':' || path > ?3 ORDER BY kind || ':' || path LIMIT ?4"
    );
    let mut statement = db.prepare(&sql).map_err(ApiError::internal)?;
    let mut entries = statement
        .query_map(bindings, |r| {
            Ok(BrowserEntry {
                kind: r.get(0)?,
                path: r.get(1)?,
                size: r.get(2)?,
                revision: r.get(3)?,
                sha256: r.get(4)?,
                updated_at: r.get(5)?,
            })
        })
        .map_err(ApiError::internal)?
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(ApiError::internal)?;
    let next = if entries.len() > PAGE_SIZE {
        entries.pop();
        entries
            .last()
            .map(|entry| format!("{}:{}", entry.kind, entry.path))
    } else {
        None
    };
    Ok(Listing { entries, next })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChunkQuery {
    path: String,
    revision: i64,
    offset: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PdfQuery {
    path: String,
    revision: i64,
}

/// Native PDF navigation cannot attach the fetch-only X-MySync-Web header.
/// Keep the same scoped cookie authority and reject foreign browser origins.
async fn pdf(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Query(query): Query<PdfQuery>,
) -> Result<Response, ApiError> {
    let expected = web_status::public_origin(&state)?;
    if (headers.contains_key(header::ORIGIN)
        && web_status::single_header(&headers, "origin") != Some(expected.as_str()))
        || (headers.contains_key("sec-fetch-site")
            && !matches!(
                web_status::single_header(&headers, "sec-fetch-site"),
                Some("same-origin" | "none")
            ))
    {
        return Err(failure(StatusCode::FORBIDDEN, "authentication_refused"));
    }
    state
        .blocking(move |state| {
            let db = state.db.lock().unwrap();
            authorize(&db, &headers)?;
            super::validate_path(&query.path)?;
            if !query.path.to_ascii_lowercase().ends_with(".pdf") {
                return Err(failure(StatusCode::BAD_REQUEST, "invalid_request"));
            }
            let entry = super::stored_entry(&db, &query.path)
                .map_err(ApiError::internal)?
                .ok_or_else(|| failure(StatusCode::NOT_FOUND, "file_not_found"))?;
            if entry.public.deleted || entry.public.revision != query.revision {
                return Err(failure(StatusCode::CONFLICT, "revision_changed"));
            }
            let size = entry
                .public
                .size
                .ok_or_else(|| ApiError::internal("missing size"))?;
            if !(0..=DOWNLOAD_BYTES).contains(&size) {
                return Err(failure(StatusCode::PAYLOAD_TOO_LARGE, "download_too_large"));
            }
            let size = size as u64;
            let range = match pdf_range(&headers, size) {
                Ok(range) => range,
                Err(()) => {
                    return Response::builder()
                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header(header::CONTENT_RANGE, format!("bytes */{size}"))
                        .body(Body::empty())
                        .map_err(ApiError::internal);
                }
            };
            let blob = entry
                .blob
                .ok_or_else(|| ApiError::internal("missing blob"))?;
            let root = crate::local_fs::Mirror::open(&state.data_dir.join("blobs"))
                .map_err(ApiError::internal)?;
            let mut file = root
                .read(&blob)
                .map_err(ApiError::internal)?
                .ok_or_else(|| failure(StatusCode::NOT_FOUND, "file_not_found"))?;
            drop(db);
            let (offset, count) = range.unwrap_or((0, size));
            file.seek(SeekFrom::Start(offset))
                .map_err(ApiError::internal)?;
            let filename: String = query
                .path
                .rsplit('/')
                .next()
                .unwrap()
                .bytes()
                .map(|byte| format!("%{byte:02X}"))
                .collect();
            let mut response = Response::builder()
                .header(header::CONTENT_TYPE, "application/pdf")
                .header(
                    header::CONTENT_DISPOSITION,
                    format!("inline; filename*=UTF-8''{filename}"),
                )
                .header(header::CONTENT_LENGTH, count)
                .header(header::ACCEPT_RANGES, "bytes");
            if range.is_some() {
                response = response.status(StatusCode::PARTIAL_CONTENT).header(
                    header::CONTENT_RANGE,
                    format!("bytes {offset}-{}/{size}", offset + count - 1),
                );
            }
            response
                .body(Body::from_stream(ReaderStream::with_capacity(
                    tokio::fs::File::from_std(file).take(count),
                    super::FILE_STREAM_BUFFER_BYTES,
                )))
                .map_err(ApiError::internal)
        })
        .await
}

/// Support a single byte range (including open-ended and suffix ranges) used
/// by browser PDF readers. Reject multipart ranges rather than assembling them.
fn pdf_range(headers: &HeaderMap, size: u64) -> Result<Option<(u64, u64)>, ()> {
    if !headers.contains_key(header::RANGE) {
        return Ok(None);
    }
    let range = web_status::single_header(headers, "range")
        .and_then(|value| value.strip_prefix("bytes="))
        .ok_or(())?;
    let (start, end) = range.split_once('-').ok_or(())?;
    let number = |value: &str| {
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(());
        }
        value.parse::<u64>().map_err(|_| ())
    };
    if size == 0 {
        return Err(());
    }
    if start.is_empty() {
        let count = number(end)?.min(size);
        return if count == 0 {
            Err(())
        } else {
            Ok(Some((size - count, count)))
        };
    }
    let start = number(start)?;
    let end = if end.is_empty() {
        size - 1
    } else {
        number(end)?.min(size - 1)
    };
    if start > end {
        return Err(());
    }
    Ok(Some((start, end - start + 1)))
}

async fn chunk(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    Query(query): Query<ChunkQuery>,
) -> Result<Response, ApiError> {
    browser(&state, &headers, false)?;
    state
        .blocking(move |state| {
            let db = state.db.lock().unwrap();
            authorize(&db, &headers)?;
            super::validate_path(&query.path)?;
            let entry = super::stored_entry(&db, &query.path)
                .map_err(ApiError::internal)?
                .ok_or_else(|| failure(StatusCode::NOT_FOUND, "file_not_found"))?;
            if entry.public.deleted || entry.public.revision != query.revision {
                return Err(failure(StatusCode::CONFLICT, "revision_changed"));
            }
            let size = entry
                .public
                .size
                .ok_or_else(|| ApiError::internal("missing size"))?;
            if !(0..=DOWNLOAD_BYTES).contains(&size) {
                return Err(failure(StatusCode::PAYLOAD_TOO_LARGE, "download_too_large"));
            }
            if query.offset > size as u64 {
                return Err(failure(StatusCode::BAD_REQUEST, "invalid_offset"));
            }
            let blob = entry
                .blob
                .ok_or_else(|| ApiError::internal("missing blob"))?;
            let root = crate::local_fs::Mirror::open(&state.data_dir.join("blobs"))
                .map_err(ApiError::internal)?;
            let mut file = root
                .read(&blob)
                .map_err(ApiError::internal)?
                .ok_or_else(|| failure(StatusCode::NOT_FOUND, "file_not_found"))?;
            drop(db);
            let count = CHUNK_BYTES.min(size as u64 - query.offset);
            file.seek(SeekFrom::Start(query.offset))
                .map_err(ApiError::internal)?;
            let mut bytes = vec![0; count as usize];
            file.read_exact(&mut bytes).map_err(ApiError::internal)?;
            Response::builder()
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header(header::CONTENT_LENGTH, count)
                .header(header::CONTENT_DISPOSITION, "attachment")
                .body(Body::from(bytes))
                .map_err(ApiError::internal)
        })
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use axum::{Extension, body::to_bytes};
    pub(super) fn checked<T>(value: Result<T, ApiError>) -> Result<T> {
        value.map_err(|e| anyhow::anyhow!("{} {}", e.0, e.1))
    }
    pub(super) struct Fixture {
        _dir: tempfile::TempDir,
        pub(super) state: Arc<ServerState>,
    }
    impl Fixture {
        pub(super) fn new() -> Result<Self> {
            let dir = tempfile::tempdir()?;
            let state = crate::server::open(dir.path())?;
            {
                let db = state.db.lock().unwrap();
                db.execute(
                    "INSERT INTO auth_settings VALUES('public_url','https://sync.example.test')",
                    [],
                )?;
                db.execute(
                    "INSERT INTO devices(id,name,created_at) VALUES(1,'test-device',1)",
                    [],
                )?;
                db.execute("INSERT INTO device_enrollments(id,device_id,invitation_hash,expires_at,verified_at,approved_at) VALUES('enrollment',1,'invitation',9999999999,1,1)", [])?;
            }
            Ok(Self { _dir: dir, state })
        }
        pub(super) async fn browser(&self) -> Result<HeaderMap> {
            let response = checked(page(State(self.state.clone()), HeaderMap::new()).await)?;
            let cookie = response.headers()[header::SET_COOKIE]
                .to_str()?
                .split(';')
                .next()
                .unwrap();
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, cookie.parse()?);
            headers.insert("origin", "https://sync.example.test".parse()?);
            headers.insert("x-mysync-web", "1".parse()?);
            headers.insert("content-type", "application/json".parse()?);
            Ok(headers)
        }
        pub(super) async fn grant(&self, headers: &HeaderMap, scope: &str) -> Result<String> {
            let challenge = checked(web_status::issue_challenge(
                &self.state,
                headers,
                b"{}",
                COOKIE,
                scope,
            ))?;
            let proof = PresenceProof {
                ticket: challenge.ticket,
                observed_origin: "https://sync.example.test".into(),
                instance_id: "a".repeat(64),
                status: LocalStatus {
                    api_version: 1,
                    client_version: "0.3.9".into(),
                    daemon_state: DaemonState::Idle,
                    communication: CommunicationState::Authenticated,
                    observed_at: now(),
                    last_authenticated_at: Some(now()),
                    error: None,
                },
            };
            let accepted = checked(
                web_status::proof(
                    State(self.state.clone()),
                    Extension(1),
                    Extension("enrollment".into()),
                    serde_json::to_vec(&proof)?.into(),
                )
                .await,
            )?;
            assert_eq!(accepted.0.challenge_id, challenge.challenge_id);
            Ok(challenge.challenge_id)
        }
        pub(super) fn entry(&self, path: &str, contents: &[u8]) -> Result<()> {
            let blob = crate::auth_protocol::hash(contents);
            std::fs::write(self.state.data_dir.join("blobs").join(&blob), contents)?;
            self.state.db.lock().unwrap().execute(
                "INSERT INTO entries VALUES(?1,1,?2,?2,?3,0,1)",
                params![path, blob, contents.len() as i64],
            )?;
            Ok(())
        }
        async fn pdf(
            &self,
            headers: &HeaderMap,
            path: &str,
            revision: i64,
        ) -> Result<Response, ApiError> {
            pdf(
                State(self.state.clone()),
                headers.clone(),
                Query(PdfQuery {
                    path: path.into(),
                    revision,
                }),
            )
            .await
        }
    }
    #[tokio::test]
    async fn file_authority_is_scoped_cookie_bound_expiring_and_revocable() -> Result<()> {
        let f = Fixture::new()?;
        let a = f.browser().await?;
        let b = f.browser().await?;
        f.entry("private.txt", b"private")?;
        let denied = entries(
            State(f.state.clone()),
            a.clone(),
            Query(ListQuery::default()),
        )
        .await;
        assert_eq!(denied.err().unwrap().0, StatusCode::UNAUTHORIZED);
        f.grant(&a, "status.read").await?;
        assert!(
            read_session(State(f.state.clone()), a.clone())
                .await
                .is_err()
        );
        let id = f.grant(&a, "files.read").await?;
        let response =
            checked(challenge_result(State(f.state.clone()), Path(id.clone()), a.clone()).await)?;
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()?
                .contains("HttpOnly")
        );
        let session: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert!((now() + 1798..=now() + 1800).contains(&session["expires_at"].as_i64().unwrap()));
        assert!(
            challenge_result(State(f.state.clone()), Path(id), b.clone())
                .await
                .is_err()
        );
        assert!(
            entries(State(f.state.clone()), b, Query(ListQuery::default()))
                .await
                .is_err()
        );
        assert_eq!(
            checked(
                entries(
                    State(f.state.clone()),
                    a.clone(),
                    Query(ListQuery::default())
                )
                .await
            )?
            .0
            .entries
            .len(),
            1
        );
        for header in ["origin", "sec-fetch-site"] {
            let mut forged = a.clone();
            forged.insert(header, "https://attacker.example.test".parse()?);
            assert!(read_session(State(f.state.clone()), forged).await.is_err());
        }
        let mut no_header = a.clone();
        no_header.remove("x-mysync-web");
        assert!(
            read_session(State(f.state.clone()), no_header)
                .await
                .is_err()
        );
        f.state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE web_file_grants SET expires_at=1", [])?;
        assert!(
            read_session(State(f.state.clone()), a.clone())
                .await
                .is_err()
        );
        f.grant(&a, "files.read").await?;
        checked(logout(State(f.state.clone()), a.clone()).await)?;
        assert!(read_session(State(f.state.clone()), a).await.is_err());
        let c = f.browser().await?;
        f.grant(&c, "files.read").await?;
        crate::server::revoke_device(&f.state, "test-device")?;
        assert!(
            read_session(State(f.state.clone()), c.clone())
                .await
                .is_err()
        );
        assert!(
            chunk(
                State(f.state.clone()),
                c,
                Query(ChunkQuery {
                    path: "private.txt".into(),
                    revision: 1,
                    offset: 0
                })
            )
            .await
            .is_err()
        );
        Ok(())
    }
    #[tokio::test]
    async fn session_reads_refresh_only_cookie_lifetime_and_track_the_earliest_scope() -> Result<()>
    {
        let f = Fixture::new()?;
        let token = "a".repeat(64);
        let hash = crate::auth_protocol::hash(&token);
        let deadline = now() + 1000;
        let response = {
            let db = f.state.db.lock().unwrap();
            db.execute(
                "INSERT INTO web_status_sessions VALUES(?1,'binding',?2)",
                params![hash, deadline],
            )?;
            db.execute(
                "INSERT INTO web_file_grants VALUES(?1,'read',1,'enrollment',?2)",
                params![hash, deadline],
            )?;
            db.execute(
                "INSERT INTO web_file_write_grants VALUES(?1,'write',?2)",
                params![hash, deadline - 500],
            )?;
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, format!("{COOKIE}={token}").parse()?);
            let response = checked(session_response(&db, &headers))?;
            let cookie = response.headers()[header::SET_COOKIE].to_str()?;
            for flag in ["Secure", "HttpOnly", "SameSite=Strict", "Path=/"] {
                assert!(cookie.contains(flag));
            }
            let age: i64 = cookie.split("Max-Age=").nth(1).unwrap().parse()?;
            assert!((1298..=1300).contains(&age));
            assert_eq!(
                db.query_row("SELECT expires_at FROM web_file_grants", [], |r| r
                    .get::<_, i64>(0))?,
                deadline
            );
            assert_eq!(
                db.query_row("SELECT expires_at FROM web_status_sessions", [], |r| r
                    .get::<_, i64>(0))?,
                deadline
            );
            headers.append(header::COOKIE, format!("{COOKIE}={token}").parse()?);
            assert!(session_response(&db, &headers).is_err());
            response
        };
        let session: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?;
        assert_eq!(session["renew_at"], deadline - 500 - SESSION_SECONDS);
        Ok(())
    }

    #[test]
    fn folders_search_and_pagination_preserve_literal_path_boundaries() -> Result<()> {
        let f = Fixture::new()?;
        for (name, size) in [
            ("dir/a.txt", 7),
            ("dir/b.txt", 13),
            ("dir/nested/c.txt", 21),
            ("dir/nested/deep/empty.txt", 0),
            ("directory/other.txt", 5),
            ("dir0/outside.txt", 200),
            ("percent%_/value.txt", 2),
            ("unrelated.txt", 1),
            ("dir/deleted.txt", 100),
        ] {
            f.entry(name, &vec![b'x'; size])?;
        }
        f.state.db.lock().unwrap().execute(
            "UPDATE entries SET deleted=1 WHERE path='dir/deleted.txt'",
            [],
        )?;
        let db = f.state.db.lock().unwrap();
        db.execute(
            "UPDATE entries SET updated_at=CASE path
                WHEN 'dir/a.txt' THEN 100
                WHEN 'dir/b.txt' THEN 200
                WHEN 'dir/nested/c.txt' THEN 300
                WHEN 'dir/nested/deep/empty.txt' THEN 450
                WHEN 'dir/deleted.txt' THEN 900
                ELSE 50 END",
            [],
        )?;
        let root = checked(list(&db, ListQuery::default()))?;
        assert_eq!(
            root.entries
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            ["dir", "dir0", "directory", "percent%_", "unrelated.txt"]
        );
        assert_eq!(root.entries[0].size, Some(41));
        assert_eq!(root.entries[1].size, Some(200));
        assert_eq!(root.entries[3].size, Some(2));
        assert_eq!(root.entries[0].updated_at, Some(450));
        assert_eq!(root.entries[1].updated_at, Some(50));
        assert_eq!(serde_json::to_value(&root.entries[0])?["updated_at"], 450);
        assert!(root.entries[0].revision.is_none());
        assert!(root.entries[0].sha256.is_none());
        let nested = checked(list(
            &db,
            ListQuery {
                directory: "dir".into(),
                ..Default::default()
            },
        ))?;
        assert_eq!(
            nested
                .entries
                .iter()
                .map(|e| e.path.as_str())
                .collect::<Vec<_>>(),
            ["dir/nested", "dir/a.txt", "dir/b.txt"]
        );
        assert_eq!(nested.entries[0].size, Some(21));
        assert_eq!(nested.entries[1].size, Some(7));
        assert_eq!(nested.entries[2].size, Some(13));
        assert_eq!(nested.entries[0].updated_at, Some(450));
        assert_eq!(nested.entries[1].updated_at, Some(100));
        assert_eq!(nested.entries[2].updated_at, Some(200));
        let empty_folder = checked(list(
            &db,
            ListQuery {
                directory: "dir/nested".into(),
                ..Default::default()
            },
        ))?;
        assert_eq!(empty_folder.entries[0].path, "dir/nested/deep");
        assert_eq!(empty_folder.entries[0].size, Some(0));
        assert_eq!(empty_folder.entries[0].updated_at, Some(450));
        let escaped = checked(list(
            &db,
            ListQuery {
                directory: "percent%_".into(),
                ..Default::default()
            },
        ))?;
        assert_eq!(escaped.entries.len(), 1);
        assert_eq!(escaped.entries[0].size, Some(2));
        let literal = checked(list(
            &db,
            ListQuery {
                search: "%_".into(),
                ..Default::default()
            },
        ))?;
        assert_eq!(literal.entries.len(), 1);
        assert_eq!(literal.entries[0].path, "percent%_/value.txt");
        assert_eq!(literal.entries[0].updated_at, Some(50));
        assert!(
            list(
                &db,
                ListQuery {
                    directory: "../".into(),
                    ..Default::default()
                }
            )
            .is_err()
        );
        assert!(
            list(
                &db,
                ListQuery {
                    search: "a".repeat(256),
                    ..Default::default()
                }
            )
            .is_err()
        );
        drop(db);
        for i in 0..201 {
            f.entry(&format!("pages/file-{i:03}"), b"x")?;
        }
        let db = f.state.db.lock().unwrap();
        db.execute(
            "UPDATE entries SET updated_at=999 WHERE path='pages/file-200'",
            [],
        )?;
        let first = checked(list(
            &db,
            ListQuery {
                directory: "pages".into(),
                ..Default::default()
            },
        ))?;
        assert_eq!(first.entries.len(), 200);
        let second = checked(list(
            &db,
            ListQuery {
                directory: "pages".into(),
                after: first.next.unwrap(),
                ..Default::default()
            },
        ))?;
        assert_eq!(second.entries.len(), 1);
        assert_eq!(second.entries[0].path, "pages/file-200");
        assert_eq!(second.entries[0].updated_at, Some(999));
        assert!(second.next.is_none());
        let root = checked(list(&db, ListQuery::default()))?;
        assert_eq!(
            root.entries
                .iter()
                .find(|e| e.path == "pages")
                .unwrap()
                .size,
            Some(201)
        );
        assert_eq!(
            root.entries
                .iter()
                .find(|e| e.path == "pages")
                .unwrap()
                .updated_at,
            Some(999)
        );
        db.execute(
            "UPDATE entries SET size=9,updated_at=500 WHERE path='dir/a.txt'",
            [],
        )?;
        let root = checked(list(&db, ListQuery::default()))?;
        assert_eq!(root.entries[0].size, Some(43));
        assert_eq!(root.entries[0].updated_at, Some(500));
        Ok(())
    }
    #[tokio::test]
    async fn pdf_url_serves_inline_content_and_browser_byte_ranges() -> Result<()> {
        let f = Fixture::new()?;
        let mut headers = f.browser().await?;
        f.grant(&headers, "files.read").await?;
        headers.remove("x-mysync-web");
        headers.remove(header::ORIGIN);
        headers.insert("sec-fetch-site", "same-origin".parse()?);
        let content = b"%PDF-1.4\nPDF fixture\n%%EOF\n";
        let path = "Documents/rapport été #1.PDF";
        f.entry(path, content)?;

        // Exercise the actual URL and middleware, with navigation headers and
        // the session cookie rather than the custom fetch header.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}/v1/web/files/pdf", listener.local_addr()?);
        let state = f.state.clone();
        let task = tokio::spawn(async move {
            axum::serve(listener, super::super::router(state))
                .await
                .unwrap();
        });
        let client = reqwest::Client::builder().no_proxy().build()?;
        let response = client
            .get(&url)
            .headers(headers.clone())
            .query(&[("path", path), ("revision", "1")])
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
        let disposition = response.headers()[header::CONTENT_DISPOSITION].to_str()?;
        assert!(disposition.starts_with("inline; filename*=UTF-8''"));
        assert!(disposition.contains("%C3%A9"));
        assert!(disposition.contains("%23"));
        assert_eq!(
            response.headers()[header::CONTENT_LENGTH],
            content.len().to_string()
        );
        assert_eq!(response.headers()[header::ACCEPT_RANGES], "bytes");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert_eq!(response.headers()["x-content-type-options"], "nosniff");
        let csp = response.headers()["content-security-policy"].to_str()?;
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(
            !csp.contains("default-src 'none'"),
            "native PDF readers must be able to render"
        );
        assert_eq!(response.bytes().await?.as_ref(), content);

        for (range, start, end) in [
            ("bytes=0-4", 0, 4),
            ("bytes=5-", 5, content.len() - 1),
            ("bytes=-5", content.len() - 5, content.len() - 1),
            ("bytes=5-999", 5, content.len() - 1),
        ] {
            let response = client
                .get(&url)
                .headers(headers.clone())
                .header(header::RANGE, range)
                .query(&[("path", path), ("revision", "1")])
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
            assert_eq!(
                response.headers()[header::CONTENT_RANGE],
                format!("bytes {start}-{end}/{}", content.len())
            );
            assert_eq!(response.bytes().await?.as_ref(), &content[start..=end]);
        }
        for range in [
            "bytes=999-",
            "bytes=5-2",
            "bytes=-0",
            "bytes=0-1,3-4",
            "bytes=oops",
            "items=0-1",
        ] {
            let response = client
                .get(&url)
                .headers(headers.clone())
                .header(header::RANGE, range)
                .query(&[("path", path), ("revision", "1")])
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
            assert_eq!(
                response.headers()[header::CONTENT_RANGE],
                format!("bytes */{}", content.len())
            );
        }
        task.abort();
        Ok(())
    }

    #[tokio::test]
    async fn pdf_url_requires_scoped_session_and_rechecks_revocation() -> Result<()> {
        let f = Fixture::new()?;
        let mut headers = f.browser().await?;
        headers.remove("x-mysync-web");
        f.entry("private.pdf", b"%PDF-1.4\n")?;
        assert_eq!(
            f.pdf(&headers, "private.pdf", 1).await.err().unwrap().0,
            StatusCode::UNAUTHORIZED
        );
        let proof_headers = f.browser().await?;
        f.grant(&proof_headers, "status.read").await?;
        assert_eq!(
            f.pdf(&proof_headers, "private.pdf", 1)
                .await
                .err()
                .unwrap()
                .0,
            StatusCode::UNAUTHORIZED
        );
        headers.insert("x-mysync-web", "1".parse()?);
        f.grant(&headers, "files.read").await?;
        headers.remove("x-mysync-web");
        checked(f.pdf(&headers, "private.pdf", 1).await)?;
        let mut no_cookie = headers.clone();
        no_cookie.remove(header::COOKIE);
        assert_eq!(
            f.pdf(&no_cookie, "private.pdf", 1).await.err().unwrap().0,
            StatusCode::UNAUTHORIZED
        );
        for (name, value) in [
            ("origin", "https://foreign.example"),
            ("sec-fetch-site", "cross-site"),
            ("sec-fetch-site", "same-site"),
        ] {
            let mut foreign = headers.clone();
            foreign.insert(name, value.parse()?);
            assert_eq!(
                f.pdf(&foreign, "private.pdf", 1).await.err().unwrap().0,
                StatusCode::FORBIDDEN
            );
        }
        let mut direct = headers.clone();
        direct.remove(header::ORIGIN);
        direct.insert("sec-fetch-site", "none".parse()?);
        checked(f.pdf(&direct, "private.pdf", 1).await)?;
        direct.append("sec-fetch-site", "same-origin".parse()?);
        assert_eq!(
            f.pdf(&direct, "private.pdf", 1).await.err().unwrap().0,
            StatusCode::FORBIDDEN
        );
        for sql in [
            "UPDATE devices SET revoked_at=1",
            "UPDATE devices SET revoked_at=NULL; UPDATE device_enrollments SET approved_at=NULL",
            "UPDATE device_enrollments SET approved_at=1; UPDATE web_file_grants SET expires_at=1",
        ] {
            f.state.db.lock().unwrap().execute_batch(sql)?;
            assert_eq!(
                f.pdf(&headers, "private.pdf", 1).await.err().unwrap().0,
                StatusCode::UNAUTHORIZED
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn pdf_url_is_revision_pinned_bounded_and_confined() -> Result<()> {
        let f = Fixture::new()?;
        let headers = f.browser().await?;
        f.grant(&headers, "files.read").await?;
        f.entry("report.pdf", b"%PDF-1.4\n")?;
        for (path, revision, status) in [
            ("report.pdf", 2, StatusCode::CONFLICT),
            ("missing.pdf", 1, StatusCode::NOT_FOUND),
            ("../secret.pdf", 1, StatusCode::BAD_REQUEST),
            ("report.html", 1, StatusCode::BAD_REQUEST),
        ] {
            assert_eq!(
                f.pdf(&headers, path, revision).await.err().unwrap().0,
                status
            );
        }
        f.state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE entries SET deleted=1", [])?;
        assert_eq!(
            f.pdf(&headers, "report.pdf", 1).await.err().unwrap().0,
            StatusCode::CONFLICT
        );
        f.state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE entries SET deleted=0,size=?1", [DOWNLOAD_BYTES + 1])?;
        assert_eq!(
            f.pdf(&headers, "report.pdf", 1).await.err().unwrap().0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        f.entry("empty.pdf", b"")?;
        let response = checked(f.pdf(&headers, "empty.pdf", 1).await)?;
        assert!(to_bytes(response.into_body(), 1).await?.is_empty());
        let mut ranged = headers.clone();
        ranged.insert(header::RANGE, "bytes=0-0".parse()?);
        assert_eq!(
            checked(f.pdf(&ranged, "empty.pdf", 1).await)?.status(),
            StatusCode::RANGE_NOT_SATISFIABLE
        );
        ranged.append(header::RANGE, "bytes=1-1".parse()?);
        assert_eq!(
            checked(f.pdf(&ranged, "empty.pdf", 1).await)?.status(),
            StatusCode::RANGE_NOT_SATISFIABLE
        );
        let blob = f
            .state
            .data_dir
            .join("blobs")
            .join(crate::auth_protocol::hash(b""));
        std::fs::remove_file(&blob)?;
        std::os::unix::fs::symlink("/etc/passwd", blob)?;
        assert!(f.pdf(&headers, "empty.pdf", 1).await.is_err());
        Ok(())
    }

    #[tokio::test]
    async fn downloads_are_bounded_revision_pinned_and_refuse_symlinks() -> Result<()> {
        let f = Fixture::new()?;
        let headers = f.browser().await?;
        f.grant(&headers, "files.read").await?;
        let content = vec![23; CHUNK_BYTES as usize + 13];
        f.entry("large.bin", &content)?;
        for (offset, length) in [(0, CHUNK_BYTES as usize), (CHUNK_BYTES, 13)] {
            let response = checked(
                chunk(
                    State(f.state.clone()),
                    headers.clone(),
                    Query(ChunkQuery {
                        path: "large.bin".into(),
                        revision: 1,
                        offset,
                    }),
                )
                .await,
            )?;
            assert_eq!(
                response.headers()[header::CONTENT_DISPOSITION],
                "attachment"
            );
            let bytes = to_bytes(response.into_body(), CHUNK_BYTES as usize).await?;
            assert_eq!(bytes.len(), length);
            assert!(bytes.iter().all(|b| *b == 23));
        }
        for (path, revision, offset, status) in [
            ("large.bin", 2, 0, StatusCode::CONFLICT),
            ("large.bin", 1, CHUNK_BYTES + 14, StatusCode::BAD_REQUEST),
            ("../secret", 1, 0, StatusCode::BAD_REQUEST),
        ] {
            assert_eq!(
                chunk(
                    State(f.state.clone()),
                    headers.clone(),
                    Query(ChunkQuery {
                        path: path.into(),
                        revision,
                        offset
                    })
                )
                .await
                .err()
                .unwrap()
                .0,
                status
            );
        }
        f.entry("empty.txt", b"")?;
        let response = checked(
            chunk(
                State(f.state.clone()),
                headers.clone(),
                Query(ChunkQuery {
                    path: "empty.txt".into(),
                    revision: 1,
                    offset: 0,
                }),
            )
            .await,
        )?;
        assert!(to_bytes(response.into_body(), 1).await?.is_empty());
        f.state.db.lock().unwrap().execute(
            "UPDATE entries SET size=?1 WHERE path='large.bin'",
            [DOWNLOAD_BYTES + 1],
        )?;
        assert_eq!(
            chunk(
                State(f.state.clone()),
                headers.clone(),
                Query(ChunkQuery {
                    path: "large.bin".into(),
                    revision: 1,
                    offset: 0
                })
            )
            .await
            .err()
            .unwrap()
            .0,
            StatusCode::PAYLOAD_TOO_LARGE
        );
        let hash = crate::auth_protocol::hash(b"");
        std::fs::remove_file(f.state.data_dir.join("blobs").join(&hash))?;
        std::os::unix::fs::symlink("/etc/passwd", f.state.data_dir.join("blobs").join(hash))?;
        assert!(
            chunk(
                State(f.state.clone()),
                headers,
                Query(ChunkQuery {
                    path: "empty.txt".into(),
                    revision: 1,
                    offset: 0
                })
            )
            .await
            .is_err()
        );
        Ok(())
    }
}
