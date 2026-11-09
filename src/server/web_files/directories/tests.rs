use super::*;
use crate::server::web_files::tests::{Fixture, checked};
use anyhow::Result;

async fn fixture() -> Result<(Fixture, HeaderMap)> {
    let f = Fixture::new()?;
    let headers = f.browser().await?;
    f.grant(&headers, "files.read").await?;
    for (path, data) in [
        ("Docs/a.txt", &b"a"[..]),
        ("Docs/Sub/b.txt", &b"bb"[..]),
        ("Docs0/keep.txt", &b"keep"[..]),
    ] {
        f.entry(path, data)?;
    }
    f.state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE meta SET value=1 WHERE key='generation'", [])?;
    Ok((f, headers))
}
fn snapshot(f: &Fixture, path: &str) -> Result<String> {
    Ok(checked(info(&f.state.db.lock().unwrap(), path))?
        .snapshot
        .unwrap())
}
async fn move_to(
    f: &Fixture,
    headers: &HeaderMap,
    token: &str,
    name: &str,
) -> Result<Json<Changed>, ApiError> {
    rename(
        State(f.state.clone()),
        headers.clone(),
        Json(Rename {
            path: "Docs".into(),
            snapshot: token.into(),
            name: name.into(),
        }),
    )
    .await
}
async fn remove(
    f: &Fixture,
    headers: &HeaderMap,
    path: &str,
    token: &str,
) -> Result<Json<Changed>, ApiError> {
    delete(
        State(f.state.clone()),
        headers.clone(),
        Json(Mutation {
            path: path.into(),
            snapshot: token.into(),
        }),
    )
    .await
}

#[tokio::test]
async fn management_requires_its_own_cookie_bound_expiring_and_revocable_scope() -> Result<()> {
    let (f, headers) = fixture().await?;
    let token = snapshot(&f, "Docs")?;
    assert_eq!(
        remove(&f, &headers, "Docs", &token).await.unwrap_err().1,
        "files_manage_required"
    );
    f.grant(&headers, "files.write").await?;
    assert_eq!(
        move_to(&f, &headers, &token, "New").await.unwrap_err().1,
        "files_manage_required"
    );
    let expiry = checked(authorize(&f.state.db.lock().unwrap(), &headers))?.expires_at;
    f.grant(&headers, "files.manage").await?;
    assert_eq!(
        checked(grant(&f.state.db.lock().unwrap(), &headers))?.expires_at,
        expiry
    );
    let other = f.browser().await?;
    f.grant(&other, "files.read").await?;
    assert_eq!(
        remove(&f, &other, "Docs", &token).await.unwrap_err().1,
        "files_manage_required"
    );
    for name in ["origin", "x-mysync-web", "sec-fetch-site"] {
        let mut forged = headers.clone();
        forged.insert(name, "foreign".parse()?);
        assert!(remove(&f, &forged, "Docs", &token).await.is_err());
    }
    f.grant(&headers, "files.read").await?;
    assert!(grant(&f.state.db.lock().unwrap(), &headers).is_ok());
    f.grant(&headers, "files.manage").await?;
    f.state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE web_file_manage_grants SET expires_at=1", [])?;
    assert_eq!(
        remove(&f, &headers, "Docs", &token).await.unwrap_err().1,
        "files_manage_required"
    );
    f.grant(&headers, "files.manage").await?;
    f.state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE devices SET revoked_at=1", [])?;
    assert_eq!(
        remove(&f, &headers, "Docs", &token).await.unwrap_err().0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        checked(info(&f.state.db.lock().unwrap(), "Docs"))?.file_count,
        2
    );
    Ok(())
}

#[tokio::test]
async fn rename_preserves_blobs_nested_paths_and_revision_history_without_merging() -> Result<()> {
    let (f, headers) = fixture().await?;
    f.grant(&headers, "files.manage").await?;
    let token = snapshot(&f, "Docs")?;
    f.entry("Existing/file.txt", b"original")?;
    f.entry("Occupied", b"original")?;
    for name in ["Existing", "Docs0", "Occupied"] {
        assert_eq!(
            move_to(&f, &headers, &token, name).await.unwrap_err().1,
            "directory_exists"
        );
    }
    for name in [
        "..",
        "New/Child",
        ".mysync-conflicts",
        ".mysync-staging",
        "Docs",
    ] {
        assert_eq!(
            move_to(&f, &headers, &token, name).await.unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
    }
    f.entry("Nouveau%_/a.txt", b"old")?;
    f.state.db.lock().unwrap().execute(
        "UPDATE entries SET deleted=1 WHERE path='Nouveau%_/a.txt'",
        [],
    )?;
    let changed = checked(move_to(&f, &headers, &token, "Nouveau%_").await)?.0;
    assert_eq!(changed.file_count, 2);
    let db = f.state.db.lock().unwrap();
    for (old, new, bytes) in [
        ("Docs/a.txt", "Nouveau%_/a.txt", &b"a"[..]),
        ("Docs/Sub/b.txt", "Nouveau%_/Sub/b.txt", &b"bb"[..]),
    ] {
        let old = crate::server::stored_entry(&db, old)?.unwrap();
        let new = crate::server::stored_entry(&db, new)?.unwrap();
        assert!(old.public.deleted && old.public.revision > 1);
        assert!(new.public.revision > old.public.revision);
        assert_eq!(new.public.sha256, Some(crate::auth_protocol::hash(bytes)));
        assert_eq!(
            std::fs::read(f.state.data_dir.join("blobs").join(new.blob.unwrap()))?,
            bytes
        );
    }
    assert!(
        !crate::server::stored_entry(&db, "Docs0/keep.txt")?
            .unwrap()
            .public
            .deleted
    );
    Ok(())
}

#[tokio::test]
async fn failed_mutations_roll_back_files_trash_and_revision_generation() -> Result<()> {
    let (f, headers) = fixture().await?;
    f.grant(&headers, "files.manage").await?;
    let token = snapshot(&f, "Docs")?;
    f.state.db.lock().unwrap().execute_batch(
        "CREATE TEMP TRIGGER fail_second_file BEFORE UPDATE ON entries
         WHEN OLD.path='Docs/a.txt' BEGIN SELECT RAISE(ABORT, 'test failure'); END;",
    )?;
    for deleting in [false, true] {
        let error = if deleting {
            remove(&f, &headers, "Docs", &token).await.unwrap_err()
        } else {
            move_to(&f, &headers, &token, "Moved").await.unwrap_err()
        };
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        let db = f.state.db.lock().unwrap();
        assert_eq!(
            checked(info(&db, "Docs"))?.snapshot.as_deref(),
            Some(token.as_str())
        );
        assert_eq!(info(&db, "Moved").unwrap_err().0, StatusCode::NOT_FOUND);
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM trash", [], |r| r.get::<_, i64>(0))?,
            0
        );
        assert_eq!(
            db.query_row("SELECT value FROM meta WHERE key='generation'", [], |r| r
                .get::<_, i64>(
                0
            ))?,
            1
        );
    }
    f.state
        .db
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_second_file")?;
    assert_eq!(
        checked(remove(&f, &headers, "Docs", &token).await)?
            .0
            .file_count,
        2
    );
    Ok(())
}

#[tokio::test]
async fn deletion_keeps_recoverable_trash_and_refuses_stale_folder_snapshots() -> Result<()> {
    let (f, headers) = fixture().await?;
    f.grant(&headers, "files.manage").await?;
    let original = checked(info(&f.state.db.lock().unwrap(), "Docs"))?;
    assert_eq!((original.size, original.file_count), (3, 2));
    let token = original.snapshot.unwrap();
    f.entry("Docs/new.txt", b"new")?;
    assert_eq!(
        remove(&f, &headers, "Docs", &token).await.unwrap_err().1,
        "directory_changed"
    );
    assert_eq!(
        move_to(&f, &headers, &token, "New").await.unwrap_err().1,
        "directory_changed"
    );
    let token = snapshot(&f, "Docs")?;
    f.state.db.lock().unwrap().execute(
        "UPDATE entries SET revision=2 WHERE path='Docs/new.txt'",
        [],
    )?;
    assert_eq!(
        remove(&f, &headers, "Docs", &token).await.unwrap_err().1,
        "directory_changed"
    );
    f.state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE meta SET value=2 WHERE key='generation'", [])?;
    let token = snapshot(&f, "Docs")?;
    assert_eq!(
        checked(remove(&f, &headers, "Docs", &token).await)?
            .0
            .file_count,
        3
    );
    let db = f.state.db.lock().unwrap();
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM entries WHERE deleted=0", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    let mut query =
        db.prepare("SELECT path,blob,expires_at-deleted_at FROM trash ORDER BY path")?;
    let trash = query
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    assert_eq!(trash.len(), 3);
    for (path, blob, retention) in trash {
        assert!(path.starts_with("Docs/"));
        assert!(f.state.data_dir.join("blobs").join(blob).is_file());
        assert_eq!(retention, crate::server::RETENTION_SECONDS);
    }
    Ok(())
}

#[tokio::test]
async fn properties_use_literal_case_sensitive_paths_and_management_is_bounded() -> Result<()> {
    let (f, headers) = fixture().await?;
    f.grant(&headers, "files.manage").await?;
    f.entry("Docs%_/file.txt", b"literal")?;
    {
        let db = f.state.db.lock().unwrap();
        assert_eq!(checked(info(&db, "Docs%_"))?.size, 7);
        assert_eq!(info(&db, "docs").unwrap_err().0, StatusCode::NOT_FOUND);
        assert_eq!(info(&db, "../Docs").unwrap_err().0, StatusCode::BAD_REQUEST);
    }
    {
        let mut db = f.state.db.lock().unwrap();
        let tx = db.transaction()?;
        for index in 0..=FILE_LIMIT {
            tx.execute("INSERT INTO entries SELECT ?1,revision,blob,sha256,size,deleted,updated_at FROM entries WHERE path='Docs/a.txt'", [format!("Huge/{index}.txt")])?;
        }
        tx.commit()?;
    }
    assert!(
        checked(info(&f.state.db.lock().unwrap(), "Huge"))?
            .snapshot
            .is_none()
    );
    assert_eq!(
        remove(&f, &headers, "Huge", &"a".repeat(64))
            .await
            .unwrap_err()
            .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        checked(info(&f.state.db.lock().unwrap(), "Huge"))?.file_count,
        FILE_LIMIT + 1
    );
    Ok(())
}
