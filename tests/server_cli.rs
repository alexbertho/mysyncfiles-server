use anyhow::Result;
use mysyncfiles_server::server;
use std::process::Command;

#[test]
fn init_requires_and_persists_a_valid_display_name() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let run = |name: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_mysync-server"));
        command.args(["init", "--data-dir"]).arg(temp.path());
        if let Some(name) = name {
            command.args(["--name", name]);
        }
        command.stdin(std::process::Stdio::null()).output()
    };
    for name in [None, Some(" "), Some("line\nbreak")] {
        assert!(!run(name)?.status.success());
    }
    assert!(run(Some("  Home server  "))?.status.success());
    let state = server::open(temp.path())?;
    assert_eq!(
        mysyncfiles_server::device_auth::server_name(&state)?,
        "Home server"
    );
    Ok(())
}

#[test]
fn public_url_command_reads_the_administrator_setting() -> Result<()> {
    let temp = tempfile::tempdir()?;
    server::open(temp.path())?;

    let output = Command::new(env!("CARGO_BIN_EXE_mysync-server"))
        .args(["device", "public-url", "--data-dir"])
        .arg(temp.path())
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("public URL is not configured"));

    rusqlite::Connection::open(temp.path().join("metadata.sqlite3"))?.execute(
        "INSERT INTO auth_settings(key, value) VALUES('public_url', ?1)",
        ["https://sync.example.test"],
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_mysync-server"))
        .args(["device", "public-url", "--data-dir"])
        .arg(temp.path())
        .output()?;
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)?,
        "https://sync.example.test\n"
    );
    Ok(())
}

#[test]
fn info_reports_identity_device_states_and_storage_without_changing_the_instance() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let state = server::open(temp.path())?;
    let expected_key = state.public_key();
    let db = rusqlite::Connection::open(temp.path().join("metadata.sqlite3"))?;
    db.execute_batch(
        "INSERT INTO auth_settings VALUES('server_name','Maison'),('public_url','https://sync.example.test');
         INSERT INTO devices(id,name,created_at,revoked_at) VALUES
            (1,'active',1,NULL),(2,'pending',1,NULL),(3,'revoked',1,2),(4,'expired',1,NULL);
         INSERT INTO device_enrollments(id,device_id,invitation_hash,expires_at,approved_at) VALUES
            ('a',1,'a',1,1),('p',2,'p',9999999999,NULL),('r',3,'r',9999999999,1),('e',4,'e',1,NULL);
         INSERT INTO entries(path,revision,size,deleted,updated_at) VALUES
            ('a',1,5,0,1),('b',2,7,0,1),('empty',3,0,0,1),('deleted',4,9,1,1);
         INSERT INTO trash(path,blob,sha256,size,deleted_at,expires_at) VALUES
            ('old','blob1','hash1',4,1,1),('new','blob2','hash2',2,1,9999999999);
         INSERT INTO uploads(id,device_id,path,base_revision,size,sha256,received_size,temp_name,touched_at)
            VALUES('upload',1,'part',0,100,'hash',3,'temp',1);
         INSERT INTO web_status_sessions(token_hash,binding,expires_at) VALUES('expired','binding',1);",
    )?;
    let output = Command::new(env!("CARGO_BIN_EXE_mysync-server"))
        .args(["info", "--json", "--data-dir"])
        .arg(temp.path())
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let info: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(info["server_id"], expected_key);
    assert_eq!(info["server_name"], "Maison");
    assert_eq!(info["public_url"], "https://sync.example.test");
    for (key, expected) in [
        ("approved_devices", 1),
        ("pending_invitations", 1),
        ("revoked_devices", 1),
        ("files", 3),
        ("file_bytes", 12),
        ("trash_files", 2),
        ("trash_bytes", 6),
        ("uploads", 1),
        ("upload_bytes", 3),
    ] {
        assert_eq!(info[key], expected, "{key}");
    }
    assert!(info["disk_total_bytes"].as_u64().unwrap() > 0);
    assert!(
        info["disk_available_bytes"].as_u64().unwrap()
            <= info["disk_total_bytes"].as_u64().unwrap()
    );
    let private_key: String = db.query_row(
        "SELECT value FROM auth_settings WHERE key='origin_signing_key'",
        [],
        |r| r.get(0),
    )?;
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&private_key));
    // server::open purges expired browser sessions; info must not do that.
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM web_status_sessions", [], |r| r
            .get::<_, i64>(0))?,
        1
    );
    assert_eq!(
        db.query_row("SELECT COUNT(*) FROM device_enrollments", [], |r| r
            .get::<_, i64>(0))?,
        4
    );
    let output = Command::new(env!("CARGO_BIN_EXE_mysync-server"))
        .args(["info", "--data-dir"])
        .arg(temp.path())
        .output()?;
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout)?;
    assert!(text.contains(&format!("Server ID (public key): {expected_key}")));
    assert!(text.contains("Approved devices: 1"));
    assert!(text.contains("Files: 3 (12 bytes)"));
    Ok(())
}

#[test]
fn info_handles_an_empty_instance_and_never_initializes_a_missing_one() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let missing = temp.path().join("missing");
    assert!(server::instance_info(&missing).is_err());
    assert!(!missing.exists());
    server::open(temp.path())?;
    let info = server::instance_info(temp.path())?;
    assert!(info.public_url.is_none());
    assert_eq!(info.approved_devices, 0);
    assert_eq!(info.pending_invitations, 0);
    assert_eq!(info.revoked_devices, 0);
    assert_eq!(info.files, 0);
    assert_eq!(info.file_bytes, 0);
    assert_eq!(info.trash_files, 0);
    assert_eq!(info.uploads, 0);
    let db = rusqlite::Connection::open(temp.path().join("metadata.sqlite3"))?;
    db.execute(
        "DELETE FROM auth_settings WHERE key='origin_signing_key'",
        [],
    )?;
    assert!(server::instance_info(temp.path()).is_err());
    assert_eq!(
        db.query_row(
            "SELECT COUNT(*) FROM auth_settings WHERE key='origin_signing_key'",
            [],
            |r| r.get::<_, i64>(0)
        )?,
        0
    );
    Ok(())
}
