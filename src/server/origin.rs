//! HTTP adaptation and persistence of the origin signing key.
use crate::{
    auth_protocol::{PROOF_HEADER, random_secret},
    origin_auth::{MAX_JSON_BYTES, RESPONSE_HEADER, ResponseProof},
    server::ServerState,
};
use anyhow::Result;
use axum::{
    body::{Body, to_bytes},
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use std::sync::Arc;
pub(crate) fn load_key(db: &Connection) -> Result<SigningKey> {
    // The key lives in the private database and is backed up with it. Atomic
    // INSERT avoids generating different keys in concurrent admin processes.
    db.execute(
        "INSERT OR IGNORE INTO auth_settings(key,value) VALUES('origin_signing_key',?1)",
        [random_secret()?],
    )?;
    read_key(db)
}

pub(crate) fn read_key(db: &Connection) -> Result<SigningKey> {
    let value: String = db.query_row(
        "SELECT value FROM auth_settings WHERE key='origin_signing_key'",
        [],
        |r| r.get(0),
    )?;
    let bytes: [u8; 32] = hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid stored origin key"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub async fn middleware(
    State(state): State<Arc<ServerState>>,
    request: Request,
    next: Next,
) -> Response {
    let request_proof = request
        .headers()
        .get(PROOF_HEADER)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    if request_proof.len() > 4096 {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let request_proof = request_proof.to_owned();
    let file = request.method() == "GET" && request.uri().path() == "/v1/file";
    let response = next.run(request).await;
    let (mut parts, body) = response.into_parts();
    let (body, signature) = if file && parts.status == StatusCode::OK {
        (
            body,
            ResponseProof::sign(
                &state.origin_key,
                &request_proof,
                parts.status.as_u16(),
                None,
            ),
        )
    } else {
        let bytes = match to_bytes(body, MAX_JSON_BYTES).await {
            Ok(bytes) => bytes,
            Err(_) => {
                parts.status = StatusCode::INTERNAL_SERVER_ERROR;
                parts.headers.remove("content-length");
                axum::body::Bytes::from_static(b"{\"error\":\"origin response exceeds limit\"}")
            }
        };
        let signature = ResponseProof::sign(
            &state.origin_key,
            &request_proof,
            parts.status.as_u16(),
            Some(&bytes),
        );
        (Body::from(bytes), signature)
    };
    match signature.and_then(|s| Ok(s.parse()?)) {
        Ok(value) => {
            parts.headers.insert(RESPONSE_HEADER, value);
        }
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
    Response::from_parts(parts, body)
}
