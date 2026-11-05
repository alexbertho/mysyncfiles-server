use anyhow::Result;
use mysyncfiles_server::{device_auth, server};
use rusqlite::Connection;

struct Fixture {
    _dir: tempfile::TempDir,
    state: std::sync::Arc<server::ServerState>,
    db: Connection,
}

impl Fixture {
    fn new() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let state = server::open(dir.path())?;
        let db = Connection::open(dir.path().join("metadata.sqlite3"))?;
        // Registration only checks that trust was configured. Real certificate
        // validation and TPM possession are covered by integration/tpm_flow.
        db.execute("INSERT INTO auth_settings VALUES('ek_roots','fixture')", [])?;
        Ok(Self {
            _dir: dir,
            state,
            db,
        })
    }
}

#[test]
fn same_code_resumes_and_a_different_code_reports_the_pending_invitation() -> Result<()> {
    let f = Fixture::new()?;
    let code = device_auth::pairing_code()?;
    let id = device_auth::register_pair(&f.state, "laptop", &code)?;
    let canonical = device_auth::normalize_pairing_code(&code)?.to_lowercase();
    assert_eq!(
        device_auth::register_pair(&f.state, "laptop", &canonical)?,
        id
    );
    assert!(device_auth::register_pair(&f.state, "other", &code).is_err());
    let error = device_auth::register_pair(&f.state, "laptop", &device_auth::pairing_code()?)
        .expect_err("a different code must not silently replace an invitation");
    let conflict = error
        .downcast_ref::<device_auth::EnrollmentConflict>()
        .unwrap();
    assert_eq!(conflict.id, id);
    assert_eq!(conflict.name, "laptop");
    assert!(!conflict.approved);
    assert!(error.to_string().contains("pending invitation"));
    assert_eq!(device_auth::list(&f.state)?.len(), 1);
    assert_eq!(
        device_auth::enrollment_by_id(&f.state, &id)?.status,
        "invited"
    );
    Ok(())
}

#[test]
fn confirmed_replacement_cancels_only_the_expected_pending_invitation() -> Result<()> {
    let f = Fixture::new()?;
    let old_code = device_auth::pairing_code()?;
    let old_id = device_auth::register_pair(&f.state, "laptop", &old_code)?;
    let new_code = device_auth::pairing_code()?;
    assert!(device_auth::replace_pending_pair(&f.state, "laptop", &new_code, "wrong-id").is_err());
    assert!(device_auth::replace_pending_pair(&f.state, "laptop", "invalid", &old_id).is_err());
    assert_eq!(
        device_auth::enrollment_by_id(&f.state, &old_id)?.status,
        "invited"
    );
    let new_id = device_auth::replace_pending_pair(&f.state, "laptop", &new_code, &old_id)?;
    assert_ne!(new_id, old_id);
    assert_eq!(
        device_auth::enrollment_by_id(&f.state, &old_id)?.status,
        "expired"
    );
    assert_eq!(
        device_auth::enrollment_by_id(&f.state, &new_id)?.status,
        "invited"
    );
    assert_eq!(
        device_auth::register_pair(&f.state, "laptop", &new_code)?,
        new_id
    );
    assert!(device_auth::register_pair(&f.state, "laptop", &old_code).is_err());
    assert!(
        device_auth::replace_pending_pair(
            &f.state,
            "laptop",
            &device_auth::pairing_code()?,
            &old_id
        )
        .is_err()
    );
    assert_eq!(
        device_auth::enrollment_by_id(&f.state, &new_id)?.status,
        "invited"
    );
    Ok(())
}

#[test]
fn failed_replacement_rolls_back_cancellation() -> Result<()> {
    let f = Fixture::new()?;
    let code = device_auth::pairing_code()?;
    let id = device_auth::register_pair(&f.state, "laptop", &code)?;
    f.db.execute_batch(
        "CREATE TRIGGER reject_new_enrollment BEFORE INSERT ON device_enrollments
         BEGIN SELECT RAISE(ABORT,'simulated registration failure'); END;",
    )?;
    assert!(
        device_auth::replace_pending_pair(&f.state, "laptop", &device_auth::pairing_code()?, &id)
            .is_err()
    );
    assert_eq!(
        device_auth::enrollment_by_id(&f.state, &id)?.status,
        "invited"
    );
    assert_eq!(device_auth::register_pair(&f.state, "laptop", &code)?, id);
    Ok(())
}

#[test]
fn approval_between_confirmation_and_replacement_preserves_the_device() -> Result<()> {
    let f = Fixture::new()?;
    let id = device_auth::register_pair(&f.state, "laptop", &device_auth::pairing_code()?)?;
    f.db.execute(
        "UPDATE device_enrollments SET verified_at=1,fingerprint='verified' WHERE id=?1",
        [&id],
    )?;
    device_auth::approve(&f.state, &id, "verified")?;
    f.db.execute(
        "INSERT INTO device_sessions(token_hash,enrollment_id,expires_at,public_key) VALUES('session',?1,9999999999,'public')",
        [&id],
    )?;
    let error =
        device_auth::replace_pending_pair(&f.state, "laptop", &device_auth::pairing_code()?, &id)
            .expect_err("an approved device must never be replaced by pairing");
    assert!(
        error
            .downcast_ref::<device_auth::EnrollmentConflict>()
            .unwrap()
            .approved
    );
    assert!(error.to_string().contains("already enrolled"));
    assert_eq!(
        device_auth::enrollment_by_id(&f.state, &id)?.status,
        "approved"
    );
    assert_eq!(
        f.db.query_row("SELECT COUNT(*) FROM device_sessions", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    assert!(device_auth::cancel(&f.state, &id).is_err());
    Ok(())
}

#[test]
fn expired_invitation_frees_the_name_and_revoked_device_cannot_resume() -> Result<()> {
    let f = Fixture::new()?;
    let old_code = device_auth::pairing_code()?;
    let old_id = device_auth::register_pair(&f.state, "laptop", &old_code)?;
    f.db.execute(
        "UPDATE device_enrollments SET expires_at=1 WHERE id=?1",
        [&old_id],
    )?;
    assert!(device_auth::register_pair(&f.state, "laptop", &old_code).is_err());
    let new_code = device_auth::pairing_code()?;
    let new_id = device_auth::register_pair(&f.state, "laptop", &new_code)?;
    assert_ne!(new_id, old_id);
    assert!(server::revoke_device(&f.state, "laptop")?);
    assert!(device_auth::register_pair(&f.state, "laptop", &new_code).is_err());
    assert!(device_auth::register_pair(&f.state, "laptop", &device_auth::pairing_code()?).is_err());
    assert_eq!(
        device_auth::enrollment_by_id(&f.state, &new_id)?.status,
        "revoked"
    );
    Ok(())
}

#[test]
fn interactive_pairing_preserves_declined_invitations_and_requires_fingerprint_approval()
-> Result<()> {
    let f = Fixture::new()?;
    let id = device_auth::register_pair(&f.state, "laptop", &device_auth::pairing_code()?)?;
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/pairing_cli.py"
        ))
        .arg(env!("CARGO_BIN_EXE_mysync-server"))
        .arg(f._dir.path())
        .arg(id)
        .arg(device_auth::pairing_code()?)
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}
