//! Browser challenges shared by presence and explicitly scoped file sessions.
use super::{ApiError, ServerState, web_assets};
use crate::{
    auth_protocol::{hash, now, random_secret},
    web_status_protocol::*,
};
use axum::{
    Extension, Json, Router,
    body::{Body, to_bytes},
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};
use serde::Deserialize;
use std::{sync::Arc, time::Duration};

const COOKIE: &str = "__Host-mysync-status";
const MAX_SESSIONS: i64 = 1024;
const MAX_PENDING: i64 = 4;
// Also bound retained rows and repeated issuance within each browser session.
const MAX_CHALLENGES: i64 = 32;
const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self' http://127.0.0.1:47831; base-uri 'none'; frame-ancestors 'none'; form-action 'none'";
// Browser PDF readers install their own privileged viewer document. The HTML
// shell's resource restrictions prevent Chromium from rendering that viewer.
const PDF_CSP: &str = "base-uri 'none'; frame-ancestors 'none'; form-action 'none'";

pub(super) fn initialize(db: &Connection) -> rusqlite::Result<()> {
    let tx = db.unchecked_transaction()?;
    let db = &tx;
    db.execute_batch("CREATE TABLE IF NOT EXISTS web_status_sessions(
        token_hash TEXT PRIMARY KEY, binding TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS web_status_sessions_expiry ON web_status_sessions(expires_at);
        CREATE TABLE IF NOT EXISTS web_status_challenges(
        id TEXT PRIMARY KEY, session_hash TEXT NOT NULL REFERENCES web_status_sessions(token_hash) ON DELETE CASCADE,
        ticket_hash TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
        expected_device_id INTEGER, enrollment_id TEXT, device_id INTEGER,
        result TEXT, presence_expires_at INTEGER);
        CREATE INDEX IF NOT EXISTS web_status_challenges_session ON web_status_challenges(session_hash);
        CREATE TABLE IF NOT EXISTS web_file_grants(
            session_hash TEXT PRIMARY KEY REFERENCES web_status_sessions(token_hash) ON DELETE CASCADE,
            challenge_id TEXT NOT NULL, device_id INTEGER NOT NULL, enrollment_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS web_file_write_grants(
            session_hash TEXT PRIMARY KEY REFERENCES web_file_grants(session_hash) ON DELETE CASCADE,
            challenge_id TEXT NOT NULL, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS web_file_manage_grants(
            session_hash TEXT PRIMARY KEY REFERENCES web_file_grants(session_hash) ON DELETE CASCADE,
            challenge_id TEXT NOT NULL, expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS web_file_uploads(
            upload_id TEXT PRIMARY KEY REFERENCES uploads(id) ON DELETE CASCADE,
            session_hash TEXT NOT NULL, grant_id TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS web_editor_grants(
            session_hash TEXT NOT NULL REFERENCES web_file_grants(session_hash) ON DELETE CASCADE,
            scope TEXT NOT NULL, challenge_id TEXT NOT NULL, instance_id TEXT NOT NULL,
            expires_at INTEGER NOT NULL, PRIMARY KEY(session_hash,scope));
        CREATE TABLE IF NOT EXISTS web_runner_tickets(
            ticket_hash TEXT PRIMARY KEY,
            session_hash TEXT NOT NULL REFERENCES web_file_grants(session_hash) ON DELETE CASCADE,
            grant_id TEXT NOT NULL, operation TEXT NOT NULL, expires_at INTEGER NOT NULL);")?;
    let has_scope = db
        .prepare("PRAGMA table_info(web_status_challenges)")?
        .query_map([], |r| r.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?
        .iter()
        .any(|name| name == "scope");
    if !has_scope {
        db.execute("ALTER TABLE web_status_challenges ADD COLUMN scope TEXT NOT NULL DEFAULT 'status.read'", [])?;
    }
    tx.commit()
}

pub(super) fn purge(db: &Connection) -> rusqlite::Result<()> {
    db.execute(
        "DELETE FROM web_status_sessions WHERE expires_at<=?1",
        [now()],
    )?;
    // File sessions can renew indefinitely. Keep recent challenges for rate
    // limits/presence and the proofs still referenced by active grants; prune
    // only expired challenges from authenticated file sessions.
    db.execute(
        "DELETE FROM web_status_challenges AS c WHERE expires_at<=?1 AND issued_at<=?1-60
        AND COALESCE(presence_expires_at,0)<=?1
        AND EXISTS(SELECT 1 FROM web_file_grants g WHERE g.session_hash=c.session_hash)
        AND NOT EXISTS(SELECT 1 FROM web_file_grants g WHERE g.session_hash=c.session_hash AND g.challenge_id=c.id)
        AND NOT EXISTS(SELECT 1 FROM web_file_write_grants g WHERE g.session_hash=c.session_hash AND g.challenge_id=c.id)
        AND NOT EXISTS(SELECT 1 FROM web_file_manage_grants g WHERE g.session_hash=c.session_hash AND g.challenge_id=c.id)
        AND NOT EXISTS(SELECT 1 FROM web_editor_grants g WHERE g.session_hash=c.session_hash AND g.challenge_id=c.id)",
        [now()],
    )?;
    Ok(())
}

fn error(status: StatusCode, code: &str) -> ApiError {
    ApiError(status, code.into())
}
fn denied() -> ApiError {
    error(StatusCode::FORBIDDEN, "authentication_refused")
}

pub(super) fn public_origin(state: &ServerState) -> Result<String, ApiError> {
    crate::device_auth::public_url(state)
        .and_then(|url| origin(&url))
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "server_unavailable"))
}

pub(super) fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

pub(super) fn browser_request(
    headers: &HeaderMap,
    expected: &str,
    require_origin: bool,
) -> Result<(), ApiError> {
    if single_header(headers, "x-mysync-web") != Some("1") {
        return Err(denied());
    }
    let supplied_origin = single_header(headers, "origin");
    if (require_origin || headers.contains_key("origin")) && supplied_origin != Some(expected) {
        return Err(denied());
    }
    if headers.contains_key("sec-fetch-site")
        && single_header(headers, "sec-fetch-site") != Some("same-origin")
    {
        return Err(denied());
    }
    Ok(())
}

pub(super) fn cookie_token<'a>(headers: &'a HeaderMap, cookie_name: &str) -> Option<&'a str> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        for cookie in value.to_str().ok()?.split(';') {
            if let Some((key, value)) = cookie.trim().split_once('=')
                && key == cookie_name
            {
                if found.is_some() || !valid_secret(value) {
                    return None;
                }
                found = Some(value);
            }
        }
    }
    found
}

pub(super) fn cookie_hash(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    cookie_token(headers, cookie_name).map(hash)
}

pub(super) struct BrowserSession {
    pub hash: String,
    pub binding: String,
    pub expires_at: i64,
}
fn session(db: &Connection, headers: &HeaderMap) -> Result<BrowserSession, ApiError> {
    named_session(db, headers, COOKIE)
}
pub(super) fn named_session(
    db: &Connection,
    headers: &HeaderMap,
    cookie_name: &str,
) -> Result<BrowserSession, ApiError> {
    let token_hash = cookie_hash(headers, cookie_name).ok_or_else(denied)?;
    let row: Option<(String, i64)> = db.query_row(
        "SELECT binding,expires_at FROM web_status_sessions WHERE token_hash=?1 AND expires_at>?2",
        params![token_hash, now()], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional().map_err(ApiError::internal)?;
    let (binding, expires_at) = row.ok_or_else(denied)?;
    Ok(BrowserSession {
        hash: token_hash,
        binding,
        expires_at,
    })
}

pub(super) fn router() -> Router<Arc<ServerState>> {
    Router::new()
        .route("/status", get(page))
        .route("/v1/web/status/challenges", post(create_challenge))
        .route("/v1/web/status/challenges/{id}", get(read_challenge))
}

/// Applies to browser routes and to machine proofs, including failed auth.
pub(super) async fn middleware(
    State(state): State<Arc<ServerState>>,
    request: Request,
    next: Next,
) -> Response {
    let pdf = request.uri().path() == "/v1/web/files/pdf";
    let result = async {
        let _permit = state
            .web_status_limit
            .try_acquire()
            .map_err(|_| error(StatusCode::TOO_MANY_REQUESTS, "status_busy"))?;
        let chunk = request.method() == axum::http::Method::PUT
            && request
                .uri()
                .path()
                .strip_prefix("/v1/web/files/uploads/")
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok());
        let directory = request.method() == axum::http::Method::POST
            && matches!(
                request.uri().path(),
                "/v1/web/files/directories/rename" | "/v1/web/files/directories/delete"
            );
        let edit = request.method() == axum::http::Method::PUT
            && request.uri().path() == "/v1/web/editor/file";
        let (parts, body) = request.into_parts();
        let bytes = to_bytes(
            body,
            if edit {
                crate::editor_protocol::JSON_BYTES
            } else if chunk {
                crate::model::UPLOAD_CHUNK_BYTES as usize
            } else if directory {
                32 * 1024
            } else {
                MAX_JSON_BYTES
            },
        )
        .await
        .map_err(|_| error(StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"))?;
        Ok::<_, ApiError>(
            next.run(Request::from_parts(parts, Body::from(bytes)))
                .await,
        )
    };
    let mut response = match tokio::time::timeout(Duration::from_secs(30), result).await {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => error.into_response(),
        Err(_) => error(StatusCode::REQUEST_TIMEOUT, "status_timeout").into_response(),
    };
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    let csp = if pdf
        && headers
            .get(header::CONTENT_TYPE)
            .is_some_and(|value| value == "application/pdf")
    {
        PDF_CSP
    } else {
        CSP
    };
    headers.insert("content-security-policy", csp.parse().unwrap());
    response
}

async fn page(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let html = web_assets::read(&state, "index.html").await?;
    page_response(&state, &headers, COOKIE, SESSION_SECONDS, html)
}

pub(super) fn page_response(
    state: &ServerState,
    headers: &HeaderMap,
    cookie_name: &str,
    cookie_seconds: i64,
    html: impl IntoResponse,
) -> Result<Response, ApiError> {
    public_origin(state)?;
    let mut db = state.db.lock().unwrap();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(ApiError::internal)?;
    purge(&tx).map_err(ApiError::internal)?;
    let mut response = ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response();
    if named_session(&tx, headers, cookie_name).is_err() {
        let count: i64 = tx
            .query_row("SELECT COUNT(*) FROM web_status_sessions", [], |r| r.get(0))
            .map_err(ApiError::internal)?;
        if count >= MAX_SESSIONS {
            return Err(error(StatusCode::TOO_MANY_REQUESTS, "status_busy"));
        }
        let token = random_secret().map_err(ApiError::internal)?;
        let binding = random_secret().map_err(ApiError::internal)?;
        tx.execute(
            "INSERT INTO web_status_sessions VALUES(?1,?2,?3)",
            params![hash(&token), binding, now() + SESSION_SECONDS],
        )
        .map_err(ApiError::internal)?;
        response.headers_mut().insert(header::SET_COOKIE,
            format!("{cookie_name}={token}; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age={cookie_seconds}").parse().unwrap());
    }
    tx.commit().map_err(ApiError::internal)?;
    Ok(response)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateChallenge {
    previous_challenge_id: Option<String>,
}

async fn create_challenge(
    State(state): State<Arc<ServerState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<ChallengeResponse>, ApiError> {
    issue_challenge(&state, &headers, &body, COOKIE, "status.read").map(Json)
}

pub(super) fn issue_challenge(
    state: &ServerState,
    headers: &HeaderMap,
    body: &[u8],
    cookie_name: &str,
    scope: &str,
) -> Result<ChallengeResponse, ApiError> {
    let audience = public_origin(state)?;
    browser_request(headers, &audience, true)?;
    if single_header(headers, "content-type") != Some("application/json") {
        return Err(denied());
    }
    let input: CreateChallenge = serde_json::from_slice(body)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid_request"))?;
    let mut db = state.db.lock().unwrap();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(ApiError::internal)?;
    purge(&tx).map_err(ApiError::internal)?;
    let session = named_session(&tx, headers, cookie_name)?;
    let mut expected_device_id = input
        .previous_challenge_id
        .as_deref()
        .map(|id| verified_result(&tx, &session, id).map(|p| p.device_id))
        .transpose()?;
    if scope == "files.read" {
        // Renewals stay on the original device, even when another local
        // profile starts answering on the bridge port.
        expected_device_id = tx
            .query_row(
                "SELECT device_id FROM web_file_grants WHERE session_hash=?1",
                [&session.hash],
                |r| r.get(0),
            )
            .optional()
            .map_err(ApiError::internal)?;
    }
    if matches!(
        scope,
        "files.write" | "files.manage" | "files.edit" | "code.run"
    ) {
        // A write challenge belongs to the device whose read grant is open.
        expected_device_id = Some(
            tx.query_row(
                "SELECT device_id FROM web_file_grants WHERE session_hash=?1 AND expires_at>?2",
                params![session.hash, now()],
                |r| r.get(0),
            )
            .optional()
            .map_err(ApiError::internal)?
            .ok_or_else(denied)?,
        );
    }
    let (pending, total, recent): (i64, i64, i64) = tx.query_row(
        "SELECT COALESCE(SUM(result IS NULL AND expires_at>?2),0),COUNT(*),COALESCE(SUM(issued_at>?2-60),0)
         FROM web_status_challenges WHERE session_hash=?1", params![session.hash, now()],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).map_err(ApiError::internal)?;
    if pending >= MAX_PENDING || total >= MAX_CHALLENGES || recent >= 12 {
        return Err(error(StatusCode::TOO_MANY_REQUESTS, "challenge_limit"));
    }
    let challenge = Challenge {
        version: 1,
        challenge_id: random_secret().map_err(ApiError::internal)?,
        session_binding: session.binding,
        origin: audience.clone(),
        audience,
        scope: scope.into(),
        issued_at: now(),
        expires_at: (now() + CHALLENGE_SECONDS).min(session.expires_at),
        expected_device_id,
    };
    let ticket = challenge
        .sign(&state.origin_key)
        .map_err(ApiError::internal)?;
    tx.execute("INSERT INTO web_status_challenges(id,session_hash,ticket_hash,issued_at,expires_at,expected_device_id,scope)
        VALUES(?1,?2,?3,?4,?5,?6,?7)", params![challenge.challenge_id, session.hash, hash(&ticket), challenge.issued_at, challenge.expires_at, expected_device_id, scope]).map_err(ApiError::internal)?;
    tx.commit().map_err(ApiError::internal)?;
    Ok(ChallengeResponse {
        challenge_id: challenge.challenge_id,
        ticket,
        expires_at: challenge.expires_at,
    })
}

/// Called only after machine authentication. Recheck approval and revocation in
/// the same write transaction that consumes the challenge (also across processes).
pub(super) async fn proof(
    State(state): State<Arc<ServerState>>,
    Extension(device_id): Extension<i64>,
    Extension(enrollment_id): Extension<String>,
    body: axum::body::Bytes,
) -> Result<Json<ProofAccepted>, ApiError> {
    let submission: PresenceProof = serde_json::from_slice(&body)
        .map_err(|_| error(StatusCode::BAD_REQUEST, "invalid_proof"))?;
    accept_proof(&state, device_id, &enrollment_id, submission).map(Json)
}

fn accept_proof(
    state: &ServerState,
    device_id: i64,
    enrollment_id: &str,
    submission: PresenceProof,
) -> Result<ProofAccepted, ApiError> {
    let audience = public_origin(state)?;
    let claims = Challenge::verify(
        &submission.ticket,
        &state.origin_key.verifying_key(),
        &audience,
        now(),
    )
    .map_err(|_| denied())?;
    if submission.observed_origin != claims.origin
        || !valid_secret(&submission.instance_id)
        || claims
            .expected_device_id
            .is_some_and(|expected| expected != device_id)
    {
        return Err(denied());
    }
    submission.status.validate(now()).map_err(|_| denied())?;
    let mut db = state.db.lock().unwrap();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(ApiError::internal)?;
    let name: Option<String> = tx.query_row("SELECT d.name FROM devices d JOIN device_enrollments e ON e.device_id=d.id
        WHERE d.id=?1 AND e.id=?2 AND e.approved_at IS NOT NULL AND e.verified_at IS NOT NULL AND d.revoked_at IS NULL",
        params![device_id,enrollment_id], |r| r.get(0)).optional().map_err(ApiError::internal)?;
    let name = name.ok_or_else(denied)?;
    let session_expiry: Option<i64> = tx.query_row("SELECT s.expires_at FROM web_status_sessions s JOIN web_status_challenges c ON c.session_hash=s.token_hash
        WHERE c.id=?1 AND s.binding=?2 AND s.expires_at>?3 AND c.expires_at>?3 AND c.result IS NULL AND c.ticket_hash=?4 AND c.scope=?5",
        params![claims.challenge_id,claims.session_binding,now(),hash(&submission.ticket),claims.scope], |r| r.get(0)).optional().map_err(ApiError::internal)?;
    let session_expiry = session_expiry.ok_or_else(denied)?;
    let result = VerifiedPresence {
        challenge_id: claims.challenge_id.clone(),
        device_id,
        device_name: name,
        instance_id: submission.instance_id,
        status: submission.status,
        verified_at: now(),
        presence_expires_at: (now() + PRESENCE_SECONDS).min(session_expiry),
    };
    let json = serde_json::to_string(&result).map_err(ApiError::internal)?;
    if json.len() > MAX_JSON_BYTES {
        return Err(error(StatusCode::BAD_REQUEST, "status_too_large"));
    }
    let updated = tx.execute("UPDATE web_status_challenges SET enrollment_id=?2,device_id=?3,result=?4,presence_expires_at=?5
        WHERE id=?1 AND result IS NULL", params![claims.challenge_id, enrollment_id, device_id, json, result.presence_expires_at]).map_err(ApiError::internal)?;
    if updated != 1 {
        return Err(denied());
    }
    if claims.scope == "files.read" {
        // Only a consumed files.read proof can extend a browser session. The
        // status cookie and status.read tickets never receive file authority.
        let expires = now() + FILES_SESSION_SECONDS;
        let existing: Option<(i64, String)> = tx
            .query_row(
                "SELECT g.device_id,g.enrollment_id FROM web_file_grants g
            JOIN web_status_challenges c ON c.session_hash=g.session_hash WHERE c.id=?1",
                [&claims.challenge_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(ApiError::internal)?;
        if existing.is_some_and(|(id, enrollment)| id != device_id || enrollment != enrollment_id) {
            return Err(denied());
        }
        // Retain outstanding uploads and editor ownership. A read proof never
        // extends any other scope: each needs its own fresh local consent.
        tx.execute("INSERT INTO web_file_grants(session_hash,challenge_id,device_id,enrollment_id,expires_at)
            SELECT session_hash,id,?2,?3,?4 FROM web_status_challenges WHERE id=?1
            ON CONFLICT(session_hash) DO UPDATE SET challenge_id=excluded.challenge_id,device_id=excluded.device_id,enrollment_id=excluded.enrollment_id,expires_at=excluded.expires_at",
            params![claims.challenge_id, device_id, enrollment_id, expires]).map_err(ApiError::internal)?;
        tx.execute(
            "UPDATE web_status_sessions SET expires_at=?2 WHERE binding=?1",
            params![claims.session_binding, expires],
        )
        .map_err(ApiError::internal)?;
    }
    if claims.scope == "files.write" {
        // Explicit write proof only; never extends the read session or allows
        // another enrollment to inherit its contents or outstanding uploads.
        let updated = tx.execute("INSERT INTO web_file_write_grants(session_hash,challenge_id,expires_at)
            SELECT g.session_hash,?1,g.expires_at FROM web_file_grants g
            JOIN web_status_challenges c ON c.session_hash=g.session_hash
            WHERE c.id=?1 AND g.device_id=?2 AND g.enrollment_id=?3 AND g.expires_at>?4
            ON CONFLICT(session_hash) DO UPDATE SET
            challenge_id=CASE WHEN web_file_write_grants.expires_at>?4 THEN web_file_write_grants.challenge_id ELSE excluded.challenge_id END,
            expires_at=excluded.expires_at",
            params![claims.challenge_id, device_id, enrollment_id, now()]).map_err(ApiError::internal)?;
        if updated != 1 {
            return Err(denied());
        }
    }
    if claims.scope == "files.manage" {
        let updated = tx.execute("INSERT INTO web_file_manage_grants(session_hash,challenge_id,expires_at)
            SELECT g.session_hash,?1,g.expires_at FROM web_file_grants g
            JOIN web_status_challenges c ON c.session_hash=g.session_hash
            WHERE c.id=?1 AND g.device_id=?2 AND g.enrollment_id=?3 AND g.expires_at>?4
            ON CONFLICT(session_hash) DO UPDATE SET challenge_id=excluded.challenge_id,expires_at=excluded.expires_at",
            params![claims.challenge_id, device_id, enrollment_id, now()]).map_err(ApiError::internal)?;
        if updated != 1 {
            return Err(denied());
        }
    }
    if matches!(claims.scope.as_str(), "files.edit" | "code.run") {
        let updated = tx.execute("INSERT INTO web_editor_grants(session_hash,scope,challenge_id,instance_id,expires_at)
            SELECT g.session_hash,?5,?1,?6,g.expires_at FROM web_file_grants g
            JOIN web_status_challenges c ON c.session_hash=g.session_hash
            WHERE c.id=?1 AND g.device_id=?2 AND g.enrollment_id=?3 AND g.expires_at>?4
            ON CONFLICT(session_hash,scope) DO UPDATE SET
            challenge_id=CASE WHEN web_editor_grants.expires_at>?4 AND web_editor_grants.instance_id=excluded.instance_id THEN web_editor_grants.challenge_id ELSE excluded.challenge_id END,
            instance_id=excluded.instance_id,expires_at=excluded.expires_at",
            params![claims.challenge_id, device_id, enrollment_id, now(), claims.scope, result.instance_id]).map_err(ApiError::internal)?;
        if updated != 1 {
            return Err(denied());
        }
    }
    tx.commit().map_err(ApiError::internal)?;
    Ok(ProofAccepted {
        challenge_id: claims.challenge_id,
    })
}

fn verified_result(
    db: &Connection,
    session: &BrowserSession,
    id: &str,
) -> Result<VerifiedPresence, ApiError> {
    if !valid_secret(id) {
        return Err(denied());
    }
    let row: Option<(Option<String>, i64, Option<i64>)> = db.query_row(
        "SELECT result,expires_at,presence_expires_at FROM web_status_challenges WHERE id=?1 AND session_hash=?2",
        params![id, session.hash], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional().map_err(ApiError::internal)?;
    let (result, expires_at, presence_expires_at) = row.ok_or_else(denied)?;
    let Some(result) = result else {
        return Err(if expires_at <= now() {
            error(StatusCode::GONE, "challenge_expired")
        } else {
            error(StatusCode::ACCEPTED, "pending")
        });
    };
    if presence_expires_at.is_none_or(|t| t <= now()) {
        return Err(error(StatusCode::GONE, "presence_expired"));
    }
    let active: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM web_status_challenges c
        JOIN device_enrollments e ON e.id=c.enrollment_id JOIN devices d ON d.id=e.device_id
        WHERE c.id=?1 AND c.device_id=d.id AND e.approved_at IS NOT NULL AND e.verified_at IS NOT NULL AND d.revoked_at IS NULL)",
        [id], |r| r.get(0)).map_err(ApiError::internal)?;
    if !active {
        return Err(denied());
    }
    serde_json::from_str(&result).map_err(ApiError::internal)
}

async fn read_challenge(
    State(state): State<Arc<ServerState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<VerifiedPresence>, ApiError> {
    browser_request(&headers, &public_origin(&state)?, false)?;
    let db = state.db.lock().unwrap();
    let session = session(&db, &headers)?;
    verified_result(&db, &session, &id).map(Json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;

    struct Fixture {
        _dir: tempfile::TempDir,
        state: Arc<ServerState>,
    }
    impl Fixture {
        fn new() -> Result<Self> {
            let dir = tempfile::tempdir()?;
            let state = crate::server::open(dir.path())?;
            {
                let db = state.db.lock().unwrap();
                db.execute(
                    "INSERT INTO auth_settings VALUES('public_url','https://sync.example.com')",
                    [],
                )?;
                for id in [1, 2] {
                    db.execute(
                        "INSERT INTO devices(id,name,created_at) VALUES(?1,?2,1)",
                        params![id, format!("device-{id}")],
                    )?;
                    db.execute("INSERT INTO device_enrollments(id,device_id,invitation_hash,expires_at,verified_at,approved_at)
                        VALUES(?1,?2,?1,9999999999,1,1)", params![format!("enrollment-{id}"),id])?;
                }
            }
            Ok(Self { _dir: dir, state })
        }
        async fn browser(&self) -> Result<HeaderMap> {
            let response = page(State(self.state.clone()), HeaderMap::new())
                .await
                .map_err(|e| anyhow::anyhow!(e.1))?;
            let cookie = response.headers()[header::SET_COOKIE].to_str()?;
            for flag in [
                "Secure",
                "HttpOnly",
                "SameSite=Strict",
                "Path=/",
                "Max-Age=300",
            ] {
                assert!(cookie.contains(flag));
            }
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, cookie.split(';').next().unwrap().parse()?);
            headers.insert("origin", "https://sync.example.com".parse()?);
            headers.insert("x-mysync-web", "1".parse()?);
            headers.insert("content-type", "application/json".parse()?);
            Ok(headers)
        }
        async fn challenge(
            &self,
            headers: &HeaderMap,
            previous: Option<&str>,
        ) -> Result<ChallengeResponse> {
            let body = serde_json::to_vec(&serde_json::json!({"previous_challenge_id":previous}))?;
            create_challenge(State(self.state.clone()), headers.clone(), body.into())
                .await
                .map(|j| j.0)
                .map_err(|e| anyhow::anyhow!("{} {}", e.0, e.1))
        }
        fn proof(&self, challenge: &ChallengeResponse) -> PresenceProof {
            PresenceProof {
                ticket: challenge.ticket.clone(),
                observed_origin: "https://sync.example.com".into(),
                instance_id: "c".repeat(64),
                status: LocalStatus {
                    api_version: 1,
                    client_version: "0.3.6".into(),
                    daemon_state: DaemonState::Idle,
                    communication: CommunicationState::Authenticated,
                    observed_at: now(),
                    last_authenticated_at: Some(now()),
                    error: None,
                },
            }
        }
    }

    #[tokio::test]
    async fn browser_sessions_isolate_results_and_renewals_pin_device() -> Result<()> {
        let f = Fixture::new()?;
        let a = f.browser().await?;
        let b = f.browser().await?;
        let challenge = f.challenge(&a, None).await?;
        let id = &challenge.challenge_id;
        let proof = f.proof(&challenge);
        assert_eq!(
            read_challenge(State(f.state.clone()), Path(id.clone()), a.clone())
                .await
                .err()
                .unwrap()
                .0,
            StatusCode::ACCEPTED
        );
        assert!(accept_proof(&f.state, 1, "enrollment-1", proof.clone()).is_ok());
        let result = read_challenge(State(f.state.clone()), Path(id.clone()), a.clone())
            .await
            .map_err(|e| anyhow::anyhow!(e.1))?
            .0;
        assert_eq!(result.device_id, 1);
        assert_eq!(result.device_name, "device-1");
        assert!(result.presence_expires_at <= now() + PRESENCE_SECONDS);
        assert!(
            read_challenge(State(f.state.clone()), Path(id.clone()), b.clone())
                .await
                .is_err()
        );
        assert!(f.challenge(&b, Some(id)).await.is_err());
        assert!(accept_proof(&f.state, 1, "enrollment-1", proof).is_err());
        let renewed = f.challenge(&a, Some(id)).await?;
        assert!(accept_proof(&f.state, 2, "enrollment-2", f.proof(&renewed)).is_err());
        assert!(accept_proof(&f.state, 1, "enrollment-1", f.proof(&renewed)).is_ok());
        // A separate tab's initial challenge recognizes another device without
        // replacing the result of the first tab.
        let other = f.challenge(&a, None).await?;
        assert!(accept_proof(&f.state, 2, "enrollment-2", f.proof(&other)).is_ok());
        assert!(crate::server::revoke_device(&f.state, "device-1")?);
        assert!(
            read_challenge(State(f.state.clone()), Path(id.clone()), a.clone())
                .await
                .is_err()
        );
        assert!(f.challenge(&a, Some(id)).await.is_err());
        assert_eq!(
            read_challenge(State(f.state.clone()), Path(other.challenge_id), a)
                .await
                .map_err(|e| anyhow::anyhow!(e.1))?
                .0
                .device_id,
            2
        );
        Ok(())
    }

    #[tokio::test]
    async fn consumption_is_atomic_persistent_and_rechecks_approval() -> Result<()> {
        let f = Fixture::new()?;
        let headers = f.browser().await?;
        let challenge = f.challenge(&headers, None).await?;
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let reopened = crate::server::open(f._dir.path()).unwrap();
                let proof = f.proof(&challenge);
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    accept_proof(&reopened, 1, "enrollment-1", proof).is_ok()
                })
            })
            .collect();
        assert_eq!(
            handles
                .into_iter()
                .map(|h| h.join().unwrap() as usize)
                .sum::<usize>(),
            1
        );
        let reopened = crate::server::open(f._dir.path())?;
        assert!(accept_proof(&reopened, 1, "enrollment-1", f.proof(&challenge)).is_err());
        for sql in [
            "UPDATE device_enrollments SET approved_at=NULL WHERE device_id=1",
            "UPDATE device_enrollments SET approved_at=1 WHERE device_id=1; UPDATE devices SET revoked_at=1 WHERE id=1",
        ] {
            let challenge = f.challenge(&headers, None).await?;
            f.state.db.lock().unwrap().execute_batch(sql)?;
            assert!(accept_proof(&f.state, 1, "enrollment-1", f.proof(&challenge)).is_err());
        }
        Ok(())
    }

    #[tokio::test]
    async fn file_renewals_preserve_ownership_but_require_each_scope_and_enrollment() -> Result<()>
    {
        let f = Fixture::new()?;
        let headers = f.browser().await?;
        let issue = |scope| {
            issue_challenge(&f.state, &headers, b"{}", COOKIE, scope)
                .map_err(|e| anyhow::anyhow!(e.1))
        };
        let read = issue("files.read")?;
        accept_proof(&f.state, 1, "enrollment-1", f.proof(&read))
            .map_err(|e| anyhow::anyhow!(e.1))?;
        let mut ids = Vec::new();
        for scope in ["files.write", "files.manage", "files.edit", "code.run"] {
            let challenge = issue(scope)?;
            accept_proof(&f.state, 1, "enrollment-1", f.proof(&challenge))
                .map_err(|e| anyhow::anyhow!(e.1))?;
            ids.push(challenge.challenge_id);
        }
        let old_expiry = now() + 60;
        {
            let db = f.state.db.lock().unwrap();
            for table in [
                "web_status_sessions",
                "web_file_grants",
                "web_file_write_grants",
                "web_file_manage_grants",
                "web_editor_grants",
            ] {
                db.execute(&format!("UPDATE {table} SET expires_at=?1"), [old_expiry])?;
            }
            db.execute("INSERT INTO device_enrollments(id,device_id,invitation_hash,expires_at,verified_at,approved_at)
                VALUES('replacement',1,'replacement',9999999999,1,1)", [])?;
        }
        let renewed = issue("files.read")?;
        let claims = Challenge::verify(
            &renewed.ticket,
            &f.state.origin_key.verifying_key(),
            "https://sync.example.com",
            now(),
        )?;
        assert_eq!(claims.expected_device_id, Some(1));
        assert!(accept_proof(&f.state, 2, "enrollment-2", f.proof(&renewed)).is_err());
        assert!(accept_proof(&f.state, 1, "replacement", f.proof(&renewed)).is_err());
        accept_proof(&f.state, 1, "enrollment-1", f.proof(&renewed))
            .map_err(|e| anyhow::anyhow!(e.1))?;
        assert!(accept_proof(&f.state, 1, "enrollment-1", f.proof(&renewed)).is_err());
        {
            let db = f.state.db.lock().unwrap();
            assert!(
                db.query_row("SELECT expires_at FROM web_file_grants", [], |r| r
                    .get::<_, i64>(0))?
                    > old_expiry
            );
            for table in [
                "web_file_write_grants",
                "web_file_manage_grants",
                "web_editor_grants",
            ] {
                assert_eq!(
                    db.query_row(&format!("SELECT MIN(expires_at) FROM {table}"), [], |r| r
                        .get::<_, i64>(
                        0
                    ))?,
                    old_expiry
                );
            }
        }
        for scope in ["files.write", "files.edit", "code.run"] {
            let challenge = issue(scope)?;
            accept_proof(&f.state, 1, "enrollment-1", f.proof(&challenge))
                .map_err(|e| anyhow::anyhow!(e.1))?;
        }
        {
            let db = f.state.db.lock().unwrap();
            let write: (String, i64) = db.query_row(
                "SELECT challenge_id,expires_at FROM web_file_write_grants",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            assert_eq!(write.0, ids[0]);
            assert!(write.1 > old_expiry);
            for (scope, id) in [("files.edit", &ids[2]), ("code.run", &ids[3])] {
                let grant: (String, i64) = db.query_row(
                    "SELECT challenge_id,expires_at FROM web_editor_grants WHERE scope=?1",
                    [scope],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                assert_eq!(&grant.0, id);
                assert!(grant.1 > old_expiry);
            }
        }
        // A restarted daemon must not inherit the old runner's ownership.
        let restarted = issue("code.run")?;
        let mut proof = f.proof(&restarted);
        proof.instance_id = "d".repeat(64);
        accept_proof(&f.state, 1, "enrollment-1", proof).map_err(|e| anyhow::anyhow!(e.1))?;
        assert_eq!(
            f.state.db.lock().unwrap().query_row(
                "SELECT challenge_id FROM web_editor_grants WHERE scope='code.run'",
                [],
                |r| r.get::<_, String>(0)
            )?,
            restarted.challenge_id
        );
        Ok(())
    }

    #[tokio::test]
    async fn file_renewals_outlive_the_challenge_quota_without_allowing_replay() -> Result<()> {
        let f = Fixture::new()?;
        let headers = f.browser().await?;
        let mut first = None;
        for _ in 0..64 {
            let challenge = issue_challenge(&f.state, &headers, b"{}", COOKIE, "files.read")
                .map_err(|e| anyhow::anyhow!(e.1))?;
            let proof = f.proof(&challenge);
            first.get_or_insert_with(|| proof.clone());
            accept_proof(&f.state, 1, "enrollment-1", proof).map_err(|e| anyhow::anyhow!(e.1))?;
            // Advance challenge retention/rate windows without sleeping.
            f.state.db.lock().unwrap().execute("UPDATE web_status_challenges SET issued_at=?1,expires_at=?1,presence_expires_at=?1", [now()-180])?;
        }
        let db = f.state.db.lock().unwrap();
        purge(&db)?;
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM web_status_challenges", [], |r| r
                .get::<_, i64>(0))?,
            1
        );
        drop(db);
        assert!(accept_proof(&f.state, 1, "enrollment-1", first.unwrap()).is_err());
        // Fresh challenges still obey the pending quota.
        for _ in 0..MAX_PENDING {
            assert!(issue_challenge(&f.state, &headers, b"{}", COOKIE, "files.read").is_ok());
        }
        assert_eq!(
            issue_challenge(&f.state, &headers, b"{}", COOKIE, "files.read")
                .err()
                .unwrap()
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        Ok(())
    }

    #[tokio::test]
    async fn forged_context_expiry_csrf_and_capacity_fail_closed() -> Result<()> {
        let f = Fixture::new()?;
        let headers = f.browser().await?;
        let challenge = f.challenge(&headers, None).await?;
        let mut wrong_origin = f.proof(&challenge);
        wrong_origin.observed_origin = "https://other.example.com".into();
        assert!(accept_proof(&f.state, 1, "enrollment-1", wrong_origin).is_err());
        let mut changed = f.proof(&challenge);
        changed.ticket.push('x');
        assert!(accept_proof(&f.state, 1, "enrollment-1", changed).is_err());
        for origin in [None, Some("null"), Some("https://other.example.com")] {
            let mut wrong = headers.clone();
            wrong.remove("origin");
            if let Some(origin) = origin {
                wrong.insert("origin", origin.parse()?);
            }
            assert!(f.challenge(&wrong, None).await.is_err());
        }
        let mut wrong = headers.clone();
        wrong.remove("x-mysync-web");
        assert!(f.challenge(&wrong, None).await.is_err());
        wrong = headers.clone();
        wrong.append("origin", "https://sync.example.com".parse()?);
        assert!(f.challenge(&wrong, None).await.is_err());
        // Ticket signature is necessary but not sufficient: DB expiration and
        // cookie binding are checked again in the consumption transaction.
        f.state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE web_status_challenges SET expires_at=1", [])?;
        assert!(accept_proof(&f.state, 1, "enrollment-1", f.proof(&challenge)).is_err());
        for _ in 0..MAX_PENDING {
            f.challenge(&headers, None).await?;
        }
        assert!(f.challenge(&headers, None).await.is_err());
        f.state
            .db
            .lock()
            .unwrap()
            .execute("UPDATE web_status_sessions SET expires_at=1", [])?;
        assert!(f.challenge(&headers, None).await.is_err());
        {
            let db = f.state.db.lock().unwrap();
            purge(&db)?;
            assert_eq!(
                db.query_row("SELECT COUNT(*) FROM web_status_challenges", [], |r| r
                    .get::<_, i64>(0))?,
                0
            );
            for i in 0..MAX_SESSIONS {
                db.execute(
                    "INSERT INTO web_status_sessions VALUES(?1,?1,?2)",
                    params![i.to_string(), now() + 300],
                )?;
            }
        }
        assert_eq!(
            page(State(f.state.clone()), HeaderMap::new())
                .await
                .err()
                .unwrap()
                .0,
            StatusCode::TOO_MANY_REQUESTS
        );
        Ok(())
    }
}
