use super::super::tests::{Fixture, checked};
use super::*;
use anyhow::Result;

async fn editor(f: &Fixture) -> Result<HeaderMap> {
    let headers = f.browser().await?;
    f.grant(&headers, "files.read").await?;
    f.grant(&headers, "files.edit").await?;
    Ok(headers)
}
async fn edit(
    f: &Fixture,
    headers: &HeaderMap,
    path: &str,
    revision: i64,
    content: &str,
) -> Result<Entry, ApiError> {
    save(
        State(f.state.clone()),
        headers.clone(),
        Json(Edit {
            path: path.into(),
            base_revision: revision,
            content: content.into(),
        }),
    )
    .await
    .map(|v| v.0)
}

#[tokio::test]
async fn editing_is_separately_consented_cookie_bound_and_revocable() -> Result<()> {
    let f = Fixture::new()?;
    f.entry("source.py", b"print(1)")?;
    let a = f.browser().await?;
    f.grant(&a, "files.read").await?;
    f.grant(&a, "files.write").await?;
    assert_eq!(
        edit(&f, &a, "source.py", 1, "print(2)")
            .await
            .unwrap_err()
            .1,
        "files_edit_required"
    );
    f.grant(&a, "files.edit").await?;
    let b = f.browser().await?;
    f.grant(&b, "files.read").await?;
    assert_eq!(
        edit(&f, &b, "source.py", 1, "print(2)")
            .await
            .unwrap_err()
            .1,
        "files_edit_required"
    );
    for header in ["origin", "x-mysync-web", "sec-fetch-site"] {
        let mut forged = a.clone();
        forged.insert(header, "forged".parse()?);
        assert!(edit(&f, &forged, "source.py", 1, "print(2)").await.is_err());
    }
    f.state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE devices SET revoked_at=1", [])?;
    assert_eq!(
        edit(&f, &a, "source.py", 1, "print(2)")
            .await
            .unwrap_err()
            .1,
        "session_expired"
    );
    Ok(())
}

#[tokio::test]
async fn successive_edits_preserve_conflicts_and_refuse_deleted_or_unsafe_files() -> Result<()> {
    let f = Fixture::new()?;
    f.entry("project/source.py", b"print(1)")?;
    // Fixtures insert revision 1 directly; real servers allocate it from meta.
    f.state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE meta SET value=1 WHERE key='generation'", [])?;
    let h = editor(&f).await?;
    let saved = checked(edit(&f, &h, "project/source.py", 1, "print(2)").await)?;
    assert!(saved.revision > 1);
    let next = checked(edit(&f, &h, "project/source.py", saved.revision, "print(3)").await)?;
    assert!(next.revision > saved.revision);
    assert_eq!(
        edit(&f, &h, "project/source.py", saved.revision, "my draft")
            .await
            .unwrap_err()
            .1,
        "revision_changed"
    );
    let value = checked(
        read(
            State(f.state.clone()),
            h.clone(),
            Query(FileQuery {
                path: "project/source.py".into(),
            }),
        )
        .await,
    )?
    .0;
    assert_eq!(value.content, "print(3)");
    let mirror = crate::local_fs::Mirror::open(&f.state.data_dir)?;
    let mut drafts = Vec::new();
    assert!(
        mirror
            .visit_files(true, |path, mut file| {
                let mut value = String::new();
                file.read_to_string(&mut value)?;
                drafts.push((path, value));
                Ok(())
            })?
            .is_empty()
    );
    assert_eq!(drafts.len(), 1);
    assert!(
        drafts[0]
            .0
            .starts_with(".mysync-conflicts/web/project/source.py.conflict-")
    );
    assert_eq!(drafts[0].1, "my draft");
    for path in [
        "../escape.py",
        "/escape.py",
        ".mysync-conflicts/a.py",
        "folder/../a.py",
        "a.rs",
        "a.py/x",
    ] {
        assert!(edit(&f, &h, path, 1, "x").await.is_err());
    }
    assert!(
        edit(&f, &h, "project/source.py", next.revision, "\0")
            .await
            .is_err()
    );
    assert_eq!(
        edit(
            &f,
            &h,
            "project/source.py",
            next.revision,
            &"x".repeat(CODE_BYTES + 1)
        )
        .await
        .unwrap_err()
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    f.state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE entries SET deleted=1", [])?;
    assert_eq!(
        edit(&f, &h, "project/source.py", next.revision, "draft")
            .await
            .unwrap_err()
            .1,
        "revision_changed"
    );
    Ok(())
}

#[tokio::test]
async fn read_refuses_binary_large_and_symlink_blobs_and_conflicts_refuse_symlinks() -> Result<()> {
    use std::os::unix::fs::symlink;
    let f = Fixture::new()?;
    let h = editor(&f).await?;
    for (path, bytes) in [
        ("binary.py", vec![255]),
        ("nul.c", vec![0]),
        ("large.py", vec![1; CODE_BYTES + 1]),
    ] {
        f.entry(path, &bytes)?;
        assert!(
            read(
                State(f.state.clone()),
                h.clone(),
                Query(FileQuery { path: path.into() })
            )
            .await
            .is_err()
        );
    }
    f.entry("link.py", b"safe")?;
    let blob = f.state.data_dir.join("blobs").join(hash(b"safe"));
    std::fs::remove_file(&blob)?;
    symlink("/etc/passwd", &blob)?;
    assert!(
        read(
            State(f.state.clone()),
            h.clone(),
            Query(FileQuery {
                path: "link.py".into()
            })
        )
        .await
        .is_err()
    );
    let outside = tempfile::tempdir()?;
    symlink(outside.path(), f.state.data_dir.join(".mysync-conflicts"))?;
    assert!(edit(&f, &h, "link.py", 99, "draft").await.is_err());
    assert_eq!(std::fs::read_dir(outside.path())?.count(), 0);
    Ok(())
}

async fn runner_ticket(
    f: &Fixture,
    headers: &HeaderMap,
    operation: Operation,
) -> Result<String, ApiError> {
    ticket(State(f.state.clone()), headers.clone(), Json(operation))
        .await
        .map(|v| v.0["ticket"].as_str().unwrap().into())
}
async fn exchange(f: &Fixture, ticket: &str, instance: &str) -> Result<Authorization, ApiError> {
    runner_authorize(
        State(f.state.clone()),
        Extension(1),
        Extension("enrollment".into()),
        Json(AuthorizationRequest {
            ticket: ticket.into(),
            instance_id: instance.into(),
        }),
    )
    .await
    .map(|v| v.0)
}
#[tokio::test]
async fn runner_tickets_bind_content_instance_device_session_expiry_and_single_use() -> Result<()> {
    let f = Fixture::new()?;
    let h = editor(&f).await?;
    f.entry("source.py", b"print(1)")?;
    assert_eq!(
        runner_ticket(&f, &h, Operation::Tools).await.unwrap_err().1,
        "code_run_required"
    );
    f.grant(&h, "code.run").await?;
    let token = checked(runner_ticket(&f, &h, Operation::Tools).await)?;
    assert!(exchange(&f, &token, &"b".repeat(64)).await.is_err());
    let a = checked(exchange(&f, &token, &"a".repeat(64)).await)?;
    assert!(a.source.is_none());
    assert!(exchange(&f, &token, &"a".repeat(64)).await.is_err());
    let start = |revision, sha256| Operation::Start {
        path: "source.py".into(),
        revision,
        sha256,
        job_id: uuid::Uuid::new_v4().to_string(),
    };
    let token = checked(runner_ticket(&f, &h, start(1, hash(b"print(1)"))).await)?;
    let value = checked(exchange(&f, &token, &"a".repeat(64)).await)?;
    assert_eq!(value.source.as_deref(), Some("print(1)"));
    assert_eq!(a.owner, value.owner);
    for operation in [start(2, hash(b"print(1)")), start(1, hash(b"different"))] {
        let token = checked(runner_ticket(&f, &h, operation).await)?;
        assert_eq!(
            exchange(&f, &token, &"a".repeat(64)).await.unwrap_err().1,
            "revision_changed"
        );
    }
    let token = checked(runner_ticket(&f, &h, Operation::Tools).await)?;
    f.state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE web_runner_tickets SET expires_at=0", [])?;
    assert!(exchange(&f, &token, &"a".repeat(64)).await.is_err());
    let token = checked(runner_ticket(&f, &h, Operation::Tools).await)?;
    f.grant(&h, "files.read").await?;
    f.grant(&h, "code.run").await?;
    assert_eq!(
        checked(exchange(&f, &token, &"a".repeat(64)).await)?.owner,
        a.owner
    );
    let token = checked(runner_ticket(&f, &h, Operation::Tools).await)?;
    f.state
        .db
        .lock()
        .unwrap()
        .execute("UPDATE devices SET revoked_at=1", [])?;
    assert!(exchange(&f, &token, &"a".repeat(64)).await.is_err());
    Ok(())
}
