//! Real TPM commands against swtpm, with an ephemeral test-only EK CA. The
//! production verifier has no test bypass and never trusts these roots by default.
use anyhow::{Context, Result, ensure};
use mysyncfiles::{
    auth_protocol::*,
    client::{self, ClientConfig},
    device_auth, server,
    tpm::{self, Identity},
};
use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::{PKey, Private, Public},
    rsa::Rsa,
    x509::{
        X509, X509NameBuilder,
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage},
    },
};
use reqwest::{Client, Method, StatusCode};
use std::{
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

struct Simulator {
    process: Child,
    _dir: tempfile::TempDir,
    tcti: String,
}
impl Drop for Simulator {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
impl Simulator {
    fn start() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let (port, _first, _second) = loop {
            let first = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = first.local_addr()?.port();
            if port == 65535 {
                continue;
            }
            if let Ok(second) = std::net::TcpListener::bind(("127.0.0.1", port + 1)) {
                break (port, first, second);
            }
        };
        drop((_first, _second));
        let process = Command::new("swtpm")
            .args(["socket", "--tpm2", "--tpmstate"])
            .arg(format!("dir={}", dir.path().display()))
            .arg("--ctrl")
            .arg(format!("type=tcp,bindaddr=127.0.0.1,port={}", port + 1))
            .arg("--server")
            // TCTI opens one connection per command. Close the server end too,
            // so a socket inherited by another test's child cannot stall it.
            .arg(format!(
                "type=tcp,bindaddr=127.0.0.1,port={port},disconnect"
            ))
            .args(["--flags", "not-need-init,startup-clear"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("install swtpm and tpm2-tools, or run tests in deploy/Dockerfile.tpm-dev")?;
        let result = Self {
            process,
            _dir: dir,
            tcti: format!("swtpm:host=127.0.0.1,port={port}"),
        };
        for _ in 0..100 {
            if result.tool("tpm2_getcap", &["properties-fixed"]).is_ok() {
                return Ok(result);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        anyhow::bail!("simulator did not start")
    }
    fn tool(&self, name: &str, args: &[&str]) -> Result<()> {
        let output = Command::new(name)
            .arg("-T")
            .arg(&self.tcti)
            .args(args)
            .output()?;
        ensure!(
            output.status.success(),
            "{name}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(())
    }
    fn certify_ek(&self, ca: &Certificate, kind: &str) -> Result<Vec<u8>> {
        self.issue_ek(ca, kind, true)
    }
    fn issue_ek(&self, ca: &Certificate, kind: &str, install_nv: bool) -> Result<Vec<u8>> {
        let context = self._dir.path().join("ek.ctx");
        let pem = self._dir.path().join("ek.pem");
        self.tool(
            "tpm2_createek",
            &["-G", kind, "-c", context.to_str().unwrap()],
        )?;
        self.tool(
            "tpm2_readpublic",
            &[
                "-c",
                context.to_str().unwrap(),
                "-f",
                "pem",
                "-o",
                pem.to_str().unwrap(),
            ],
        )?;
        let key = PKey::public_key_from_pem(&std::fs::read(pem)?)?;
        let certificate = ca.sign_ek(&key, kind, false, true)?;
        let der = certificate.to_der()?;
        if install_nv {
            self.install_cert(&der, kind)?;
        }
        self.tool("tpm2_flushcontext", &["-t"])?;
        Ok(der)
    }
    fn install_cert(&self, der: &[u8], kind: &str) -> Result<()> {
        let path = self._dir.path().join("ek.der");
        std::fs::write(&path, der)?;
        let index = if kind == "rsa" {
            "0x01c00002"
        } else {
            "0x01c0000a"
        };
        self.tool(
            "tpm2_nvdefine",
            &[
                index,
                "-C",
                "o",
                "-s",
                &der.len().to_string(),
                "-a",
                "ownerread|ownerwrite|authread",
            ],
        )?;
        self.tool(
            "tpm2_nvwrite",
            &[index, "-C", "o", "-i", path.to_str().unwrap()],
        )?;
        Ok(())
    }
    fn install_chain(&self, certificates: &[Vec<u8>]) -> Result<()> {
        self.install_chain_parts(&[certificates.concat()])
    }
    fn install_chain_parts(&self, parts: &[Vec<u8>]) -> Result<()> {
        for (offset, bytes) in parts.iter().enumerate() {
            let path = self._dir.path().join(format!("ek-chain-{offset}.der"));
            std::fs::write(&path, bytes)?;
            let index = format!("0x{:08x}", 0x01c00100 + offset);
            self.tool(
                "tpm2_nvdefine",
                &[
                    &index,
                    "-C",
                    "o",
                    "-s",
                    &bytes.len().to_string(),
                    "-a",
                    "ownerread|ownerwrite|authread",
                ],
            )?;
            self.tool(
                "tpm2_nvwrite",
                &[&index, "-C", "o", "-i", path.to_str().unwrap()],
            )?;
        }
        Ok(())
    }
}

#[test]
fn doctor_requires_a_readable_ek_certificate() -> Result<()> {
    let simulator = Simulator::start()?;
    let error = tpm::doctor(&simulator.tcti).unwrap_err();
    assert!(error.to_string().contains("no readable"));
    let ca = Certificate::ca()?;
    simulator.certify_ek(&ca, "rsa")?;
    assert_eq!(tpm::doctor(&simulator.tcti)?, "rsa");
    Ok(())
}

#[test]
fn external_ek_certificate_must_match_this_tpm() -> Result<()> {
    let ca = Certificate::ca()?;
    let first = Simulator::start()?;
    let certificate = first.issue_ek(&ca, "rsa", false)?;
    assert!(tpm::doctor(&first.tcti).is_err());
    assert_eq!(
        tpm::doctor_with_certificate(&first.tcti, Some(&certificate))?,
        "rsa"
    );
    let (identity, returned) =
        Identity::create_with_certificate(&first.tcti, "rsa", Some(&certificate))?;
    assert_eq!(returned, certificate);
    assert_eq!(identity.ek_certificate_from(&certificate)?, certificate);

    let second = Simulator::start()?;
    assert!(tpm::doctor_with_certificate(&second.tcti, Some(&certificate)).is_err());
    assert!(Identity::create_with_certificate(&second.tcti, "rsa", Some(&certificate)).is_err());
    assert!(Identity::create_with_certificate(&first.tcti, "ecc", Some(&certificate)).is_err());
    assert!(identity.ek_certificate_from(b"not DER").is_err());

    let ecc = Simulator::start()?;
    let ecc_certificate = ecc.issue_ek(&ca, "ecc", false)?;
    assert_eq!(
        tpm::doctor_with_certificate(&ecc.tcti, Some(&ecc_certificate))?,
        "ecc"
    );
    let (ecc_identity, _) =
        Identity::create_with_certificate(&ecc.tcti, "ecc", Some(&ecc_certificate))?;
    assert_eq!(
        ecc_identity.ek_certificate_from(&ecc_certificate)?,
        ecc_certificate
    );
    Ok(())
}

#[test]
fn external_ek_certificate_file_is_bounded_and_der_only() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("ek.der");
    std::fs::write(&path, vec![0; 16 * 1024 + 1])?;
    assert!(tpm::read_ek_certificate(&path).is_err());
    std::fs::write(&path, b"not a DER certificate")?;
    assert!(tpm::read_ek_certificate(&path).is_err());
    let ca = Certificate::ca()?;
    let mut der = ca.certificate.to_der()?;
    der.extend_from_slice(b"trailing bytes");
    std::fs::write(&path, der)?;
    assert!(tpm::read_ek_certificate(&path).is_err());
    Ok(())
}

#[tokio::test]
async fn reusable_tpm_signer_keeps_request_proofs_fresh_and_bound() -> Result<()> {
    let simulator = Simulator::start()?;
    let ca = Certificate::ca()?;
    simulator.certify_ek(&ca, "rsa")?;
    let (mut identity, _) = Identity::create(&simulator.tcti, "rsa")?;
    identity.device = "test-device".into();
    let signer = tpm::RequestSigner::new(identity.clone())?;
    let url = "https://sync.example.org/v1/manifest";
    let token = "short-lived-session";

    let first = Proof::decode(
        &signer
            .proof(Claims::new(&identity.device, "GET", url, b"", token)?)
            .await?,
    )?;
    let second = Proof::decode(
        &signer
            .proof(Claims::new(&identity.device, "GET", url, b"", token)?)
            .await?,
    )?;
    first.verify(&identity.public, "GET", url, b"", token)?;
    second.verify(&identity.public, "GET", url, b"", token)?;
    assert_ne!(first.claims.nonce, second.claims.nonce);
    assert!(
        second
            .verify(&identity.public, "GET", url, b"", "wrong-session")
            .is_err()
    );
    assert!(
        second
            .verify(
                &identity.public,
                "GET",
                "https://other.example.org/",
                b"",
                token
            )
            .is_err()
    );
    Ok(())
}

struct Certificate {
    key: PKey<Private>,
    certificate: X509,
}
impl Certificate {
    fn ca() -> Result<Self> {
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "MySync ephemeral test CA")?;
        let name = name.build();
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        let serial = openssl::bn::BigNum::from_u32(1)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&key)?;
        let start = Asn1Time::days_from_now(0)?;
        let end = Asn1Time::days_from_now(2)?;
        builder.set_not_before(&start)?;
        builder.set_not_after(&end)?;
        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
        builder.sign(&key, MessageDigest::sha256())?;
        Ok(Self {
            key,
            certificate: builder.build(),
        })
    }
    fn intermediate(&self) -> Result<Self> {
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "MySync ephemeral intermediate CA")?;
        let name = name.build();
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        let serial = openssl::bn::BigNum::from_u32(3)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(self.certificate.subject_name())?;
        builder.set_pubkey(&key)?;
        let start = Asn1Time::days_from_now(0)?;
        let end = Asn1Time::days_from_now(2)?;
        builder.set_not_before(&start)?;
        builder.set_not_after(&end)?;
        builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        builder.append_extension(KeyUsage::new().critical().key_cert_sign().build()?)?;
        builder.sign(&self.key, MessageDigest::sha256())?;
        Ok(Self {
            key,
            certificate: builder.build(),
        })
    }
    fn sign_ek(&self, key: &PKey<Public>, kind: &str, expired: bool, eku: bool) -> Result<X509> {
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "Test TPM Endorsement Key")?;
        let name = name.build();
        let mut builder = X509::builder()?;
        builder.set_version(2)?;
        let serial = openssl::bn::BigNum::from_u32(2)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(self.certificate.subject_name())?;
        builder.set_pubkey(key)?;
        let start = Asn1Time::from_unix(now() - 3600)?;
        let end = Asn1Time::from_unix(if expired { now() - 1800 } else { now() + 86400 })?;
        builder.set_not_before(&start)?;
        builder.set_not_after(&end)?;
        builder.append_extension(BasicConstraints::new().critical().build()?)?;
        let mut usage = KeyUsage::new();
        usage.critical();
        if kind == "rsa" {
            usage.key_encipherment();
        } else {
            usage.key_agreement();
        }
        builder.append_extension(usage.build()?)?;
        if eku {
            builder.append_extension(ExtendedKeyUsage::new().other("2.23.133.8.1").build()?)?;
        }
        builder.sign(&self.key, MessageDigest::sha256())?;
        Ok(builder.build())
    }
}
struct Server {
    state: Arc<server::ServerState>,
    url: String,
    _dir: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Server {
    async fn start(ca: &Certificate) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let state = server::open(dir.path().join("data"))?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        let roots = dir.path().join("roots.pem");
        std::fs::write(&roots, ca.certificate.to_pem()?)?;
        device_auth::configure(&state, &url, &roots)?;
        let router = server::router(state.clone());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Ok(Self {
            state,
            url,
            _dir: dir,
            task,
        })
    }
    fn db(&self) -> Result<rusqlite::Connection> {
        Ok(rusqlite::Connection::open(
            self._dir.path().join("data/metadata.sqlite3"),
        )?)
    }
}
async fn start_enroll(
    http: &Client,
    server: &Server,
    token: &str,
    key: &Identity,
    cert: &[u8],
) -> Result<reqwest::Response> {
    Ok(http
        .post(format!("{}/v1/enroll/start", server.url))
        .json(&EnrollStart {
            invitation: token.into(),
            public: key.public.clone(),
            ek_chain: vec![hex::encode(cert)],
        })
        .send()
        .await?)
}
async fn enroll(
    http: &Client,
    server: &Server,
    token: &str,
    key: &mut Identity,
    cert: &[u8],
) -> Result<String> {
    let response = start_enroll(http, server, token, key, cert).await?;
    ensure!(
        response.status() == StatusCode::OK,
        "start failed: {}",
        response.text().await?
    );
    let challenge: EnrollChallenge = response.json().await?;
    let activation = key.activate(&challenge)?;
    key.device = challenge.id.clone();
    let response = http
        .post(format!("{}/v1/enroll/finish", server.url))
        .json(&EnrollFinish {
            id: challenge.id,
            activation,
        })
        .send()
        .await?;
    ensure!(
        response.status() == StatusCode::OK,
        "finish failed: {}",
        response.text().await?
    );
    let enrollment: Enrollment = response.json().await?;
    assert_eq!(enrollment.fingerprint, key.fingerprint()?);
    Ok(enrollment.fingerprint)
}

#[tokio::test]
async fn pairing_code_requires_local_registration_and_tpm_approval() -> Result<()> {
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    let cert = simulator.certify_ek(&ca, "rsa")?;
    let server = Server::start(&ca).await?;
    let http = Client::new();
    let code = device_auth::pairing_code()?;
    let canonical = device_auth::normalize_pairing_code(&code)?;
    assert_eq!(canonical.len(), 20);
    assert_eq!(code.matches('-').count(), 3);
    assert_eq!(
        device_auth::normalize_pairing_code("OOOOO-IIIII-LLLLL-00000")?,
        "00000111111111100000"
    );
    let ready = || {
        http.post(format!("{}/v1/enroll/ready", server.url))
            .json(&serde_json::json!({"code": code}))
            .send()
    };
    assert_eq!(ready().await?.status(), StatusCode::ACCEPTED);
    let (mut key, _) = Identity::create(&simulator.tcti, "rsa")?;
    assert_eq!(
        start_enroll(&http, &server, &canonical, &key, &cert)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let id = device_auth::register_pair(&server.state, "paired-client", &code)?;
    assert_eq!(
        device_auth::register_pair(&server.state, "paired-client", &canonical.to_lowercase())?,
        id
    );
    assert!(device_auth::register_pair(&server.state, "another-client", &code).is_err());
    assert_eq!(ready().await?.status(), StatusCode::NO_CONTENT);
    let fingerprint = enroll(&http, &server, &canonical, &mut key, &cert).await?;
    assert_eq!(
        device_auth::enrollment_by_id(&server.state, &id)?
            .fingerprint
            .as_deref(),
        Some(fingerprint.as_str())
    );
    assert!(session(&http, &server, &key).await.is_err());
    assert!(device_auth::approve(&server.state, &id, &"0".repeat(64)).is_err());
    device_auth::approve(&server.state, &id, &fingerprint)?;
    session(&http, &server, &key).await?;
    assert_eq!(ready().await?.status(), StatusCode::GONE);
    let cancelled_code = device_auth::pairing_code()?;
    let cancelled_id =
        device_auth::register_pair(&server.state, "cancelled-pair", &cancelled_code)?;
    device_auth::cancel(&server.state, &cancelled_id)?;
    assert_eq!(
        http.post(format!("{}/v1/enroll/ready", server.url))
            .json(&serde_json::json!({"code": cancelled_code}))
            .send()
            .await?
            .status(),
        StatusCode::GONE
    );
    let expired_code = device_auth::pairing_code()?;
    let expired_id = device_auth::register_pair(&server.state, "expired-pair", &expired_code)?;
    server.db()?.execute(
        "UPDATE device_enrollments SET expires_at=1 WHERE id=?1",
        [&expired_id],
    )?;
    assert_eq!(
        http.post(format!("{}/v1/enroll/ready", server.url))
            .json(&serde_json::json!({"code": expired_code}))
            .send()
            .await?
            .status(),
        StatusCode::GONE
    );
    Ok(())
}

#[tokio::test]
async fn replacing_a_pending_pair_requires_a_new_tpm_proof_and_approval() -> Result<()> {
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    let cert = simulator.certify_ek(&ca, "rsa")?;
    let server = Server::start(&ca).await?;
    let http = Client::new();
    let (mut key, _) = Identity::create(&simulator.tcti, "rsa")?;
    let old_code = device_auth::pairing_code()?;
    let old_id = device_auth::register_pair(&server.state, "laptop", &old_code)?;
    let fingerprint = enroll(
        &http,
        &server,
        &device_auth::normalize_pairing_code(&old_code)?,
        &mut key,
        &cert,
    )
    .await?;
    let new_code = device_auth::pairing_code()?;
    let new_id = device_auth::replace_pending_pair(&server.state, "laptop", &new_code, &old_id)?;
    assert!(device_auth::approve(&server.state, &old_id, &fingerprint).is_err());
    assert!(device_auth::approve(&server.state, &new_id, &fingerprint).is_err());
    assert_eq!(
        http.post(format!("{}/v1/enroll/ready", server.url))
            .json(&serde_json::json!({"code": old_code}))
            .send()
            .await?
            .status(),
        StatusCode::GONE
    );
    assert_eq!(
        http.post(format!("{}/v1/enroll/ready", server.url))
            .json(&serde_json::json!({"code": new_code}))
            .send()
            .await?
            .status(),
        StatusCode::NO_CONTENT
    );
    assert!(
        start_enroll(
            &http,
            &server,
            &device_auth::normalize_pairing_code(&old_code)?,
            &key,
            &cert
        )
        .await?
        .status()
        .is_client_error()
    );
    let fingerprint = enroll(
        &http,
        &server,
        &device_auth::normalize_pairing_code(&new_code)?,
        &mut key,
        &cert,
    )
    .await?;
    assert!(session(&http, &server, &key).await.is_err());
    device_auth::approve(&server.state, &new_id, &fingerprint)?;
    session(&http, &server, &key).await?;
    assert_eq!(
        server::instance_info(server._dir.path().join("data"))?.approved_devices,
        1
    );
    Ok(())
}

#[tokio::test]
async fn setup_waits_for_admin_then_syncs_and_is_resumable() -> Result<()> {
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    simulator.certify_ek(&ca, "rsa")?;
    let server = Server::start(&ca).await?;
    let local = tempfile::tempdir()?;
    let config = local.path().join("config.json");
    let root = local.path().join("mirror");
    std::fs::create_dir(&root)?;
    std::fs::write(root.join("hello.txt"), b"hello")?;
    let pending_config = config.clone();
    let pending_root = root.clone();
    let origin = server.url.clone();
    let origin_key = server.state.public_key();
    let tcti = simulator.tcti.clone();
    let setup = tokio::spawn(async move {
        client::setup_with_options(
            &pending_config,
            origin,
            origin_key,
            pending_root,
            client::SetupOptions {
                web_status_enabled: Some(false),
                tcti: Some(tcti),
                ..client::SetupOptions::default()
            },
        )
        .await
    });
    let pair_path = config.with_extension("pairing.json");
    let code = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(bytes) = std::fs::read(&pair_path) {
                let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                break Ok::<String, anyhow::Error>(value["code"].as_str().unwrap().to_owned());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let pairing: serde_json::Value = serde_json::from_slice(&std::fs::read(&pair_path)?)?;
    assert_eq!(pairing["web_status_enabled"], false);
    let id = device_auth::register_pair(&server.state, "setup-client", &code)?;
    let fingerprint = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let entry = device_auth::enrollment_by_id(&server.state, &id)?;
            if entry.status == "pending-approval" {
                break Ok::<String, anyhow::Error>(entry.fingerprint.unwrap());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let pending: serde_json::Value =
        serde_json::from_slice(&std::fs::read(config.with_extension("enrollment.json"))?)?;
    assert_eq!(pending["config"]["web_status_enabled"], false);
    // Resume without an explicit flag after the installer was interrupted.
    setup.abort();
    let _ = setup.await;
    let pending_config = config.clone();
    let pending_root = root.clone();
    let origin = server.url.clone();
    let origin_key = server.state.public_key();
    let tcti = simulator.tcti.clone();
    let setup = tokio::spawn(async move {
        client::setup_with_tcti(
            &pending_config,
            origin,
            origin_key,
            pending_root,
            None,
            None,
            tcti,
        )
        .await
    });
    device_auth::approve(&server.state, &id, &fingerprint)?;
    let outcome = tokio::time::timeout(Duration::from_secs(30), setup).await???;
    assert_eq!(outcome.report.uploaded, 1);
    assert_eq!(outcome.conflicts, 0);
    assert!(!pair_path.exists());
    assert!(config.exists());
    assert!(!client::load_config(&config)?.web_status_enabled);
    let conflict_dir = root.join(".mysync-conflicts");
    std::fs::create_dir(&conflict_dir)?;
    std::fs::write(conflict_dir.join("review.txt"), b"review this file")?;
    let resumed = client::setup_with_tcti(
        &config,
        server.url.clone(),
        server.state.public_key(),
        root.clone(),
        None,
        None,
        simulator.tcti.clone(),
    )
    .await?;
    assert_eq!(resumed.report.uploaded, 0);
    assert_eq!(resumed.conflicts, 1);
    assert!(!client::load_config(&config)?.web_status_enabled);
    std::fs::remove_file(conflict_dir.join("review.txt"))?;
    let cleared = client::setup_with_options(
        &config,
        server.url.clone(),
        server.state.public_key(),
        root,
        client::SetupOptions {
            web_status_enabled: Some(true),
            tcti: Some(simulator.tcti.clone()),
            ..client::SetupOptions::default()
        },
    )
    .await?;
    assert_eq!(cleared.conflicts, 0);
    let final_config = client::load_config(&config)?;
    assert!(final_config.web_status_enabled);
    assert_eq!(final_config.identity.unwrap().device, id);
    Ok(())
}

#[tokio::test]
async fn setup_replaces_an_expired_resumed_pairing_code_in_one_run() -> Result<()> {
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    simulator.certify_ek(&ca, "rsa")?;
    let server = Server::start(&ca).await?;
    let local = tempfile::tempdir()?;
    let config = local.path().join("config.json");
    let root = local.path().join("mirror");
    std::fs::create_dir(&root)?;
    let old_code = device_auth::pairing_code()?;
    let old_id = device_auth::register_pair(&server.state, "stale-client", &old_code)?;
    server.db()?.execute(
        "UPDATE device_enrollments SET expires_at=1 WHERE id=?1",
        [&old_id],
    )?;
    let pair_path = config.with_extension("pairing.json");
    std::fs::write(
        &pair_path,
        serde_json::to_vec(&serde_json::json!({
            "server": server.url,
            "server_public_key": server.state.public_key(),
            "root": root,
            "code": old_code,
        }))?,
    )?;
    let (identity, _) = Identity::create(&simulator.tcti, "rsa")?;
    std::fs::write(
        config.with_extension("enrollment.json"),
        serde_json::to_vec(&serde_json::json!({
            "config": ClientConfig {
                server: server.url.clone(),
                server_public_key: server.state.public_key(),
                identity: Some(identity),
                root: root.clone(),
                auto_update: true,
                web_status_enabled: false,
                web_files_enabled: false,
                web_uploads_enabled: false,
        web_management_enabled: false,
        web_edit_enabled: false,
        web_run_enabled: false,
                update_public_key: mysyncfiles::release::PUBLIC_KEY_HEX.trim().into(),
            },
            "challenge": null,
        }))?,
    )?;
    let origin = server.url.clone();
    let origin_key = server.state.public_key();
    let pending_config = config.clone();
    let pending_root = root.clone();
    let tcti = simulator.tcti.clone();
    let setup = tokio::spawn(async move {
        client::setup_with_tcti(
            &pending_config,
            origin,
            origin_key,
            pending_root,
            None,
            None,
            tcti,
        )
        .await
    });
    let new_code = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(bytes) = std::fs::read(&pair_path) {
                let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                let code = value["code"].as_str().unwrap();
                if code != old_code {
                    break Ok::<String, anyhow::Error>(code.to_owned());
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let new_id = device_auth::register_pair(&server.state, "resumed-client", &new_code)?;
    let fingerprint = tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let entry = device_auth::enrollment_by_id(&server.state, &new_id)?;
            if entry.status == "pending-approval" {
                break Ok::<String, anyhow::Error>(entry.fingerprint.unwrap());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    device_auth::approve(&server.state, &new_id, &fingerprint)?;
    let outcome = tokio::time::timeout(Duration::from_secs(30), setup).await???;
    assert_eq!(outcome.conflicts, 0);
    assert!(config.exists());
    assert!(!pair_path.exists());
    Ok(())
}

#[tokio::test]
async fn cancelled_pairing_discards_the_local_code() -> Result<()> {
    let ca = Certificate::ca()?;
    let server = Server::start(&ca).await?;
    let local = tempfile::tempdir()?;
    let config = local.path().join("config.json");
    let root = local.path().join("mirror");
    let pending_config = config.clone();
    let origin = server.url.clone();
    let origin_key = server.state.public_key();
    let setup = tokio::spawn(async move {
        client::setup_with_tcti(
            &pending_config,
            origin,
            origin_key,
            root,
            None,
            None,
            "unused".into(),
        )
        .await
    });
    let pair_path = config.with_extension("pairing.json");
    let code = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Ok(bytes) = std::fs::read(&pair_path) {
                let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                break Ok::<String, anyhow::Error>(value["code"].as_str().unwrap().to_owned());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await??;
    let id = device_auth::register_pair(&server.state, "cancel-setup", &code)?;
    device_auth::cancel(&server.state, &id)?;
    assert!(
        tokio::time::timeout(Duration::from_secs(10), setup)
            .await??
            .is_err()
    );
    assert!(!pair_path.exists());
    assert!(!config.exists());
    Ok(())
}
// Software session keys exist only in this test process; the TPM still signs
// every session creation and every browser authorization request.
fn session_keys()
-> &'static std::sync::Mutex<std::collections::HashMap<String, ed25519_dalek::SigningKey>> {
    static KEYS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, ed25519_dalek::SigningKey>>,
    > = std::sync::OnceLock::new();
    KEYS.get_or_init(Default::default)
}
fn session_proof(identity: &Identity, claims: Claims) -> Result<String> {
    let keys = session_keys().lock().unwrap();
    match keys.get(&claims.session_sha256) {
        Some(key) => mysyncfiles::auth_protocol::Proof::session(claims, key)?.encode(),
        None => identity.proof(claims),
    }
}

async fn signed(
    http: &Client,
    url: &str,
    method: Method,
    body: Vec<u8>,
    key: &Identity,
    token: &str,
) -> Result<reqwest::Request> {
    let claims = Claims::new(&key.device, method.as_str(), url, &body, token)?;
    let proof = if mysyncfiles::auth_protocol::requires_tpm(reqwest::Url::parse(url)?.path()) {
        key.proof(claims)?
    } else {
        session_proof(key, claims)?
    };
    let mut request = http
        .request(method, url)
        .body(body)
        .header(PROOF_HEADER, proof);
    if !token.is_empty() {
        request = request.header("authorization", format!("MySync {token}"));
    }
    Ok(request.build()?)
}
async fn session(http: &Client, server: &Server, key: &Identity) -> Result<Session> {
    let ephemeral = ed25519_dalek::SigningKey::from_bytes(
        &hex::decode(mysyncfiles::auth_protocol::random_secret()?)?
            .try_into()
            .unwrap(),
    );
    let body = serde_json::to_vec(&mysyncfiles::auth_protocol::SessionRequest {
        version: mysyncfiles::auth_protocol::PROTOCOL_VERSION,
        public_key: hex::encode(ephemeral.verifying_key().to_bytes()),
    })?;
    let mut request = signed(
        http,
        &format!("{}/v1/auth/session", server.url),
        Method::POST,
        body,
        key,
        "",
    )
    .await?;
    request
        .headers_mut()
        .insert("content-type", "application/json".parse()?);
    let session: Session = http
        .execute(request)
        .await?
        .error_for_status()?
        .json()
        .await?;
    session_keys()
        .lock()
        .unwrap()
        .insert(mysyncfiles::auth_protocol::hash(&session.token), ephemeral);
    Ok(session)
}

fn pending_body() -> reqwest::Body {
    reqwest::Body::wrap_stream(futures_util::stream::pending::<
        Result<Vec<u8>, std::io::Error>,
    >())
}

#[tokio::test]
async fn signed_requests_authenticate_before_buffering_and_bound_in_flight_bodies() -> Result<()> {
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    let cert = simulator.certify_ek(&ca, "rsa")?;
    let (mut key, _) = Identity::create(&simulator.tcti, "rsa")?;
    let server = Server::start(&ca).await?;
    let http = Client::new();
    let invitation = device_auth::invite(&server.state, "body-limits")?;
    let fingerprint = enroll(&http, &server, &invitation, &mut key, &cert).await?;
    device_auth::approve(&server.state, &key.device, &fingerprint)?;
    let active = session(&http, &server, &key).await?;
    let url = format!("{}/v1/file?path=probe&base_revision=0", server.url);
    for case in [
        "signature",
        "expired",
        "future",
        "session",
        "method",
        "query",
    ] {
        let token = if case == "session" {
            "nonexistent-session"
        } else {
            &active.token
        };
        let mut claims = Claims::new(&key.device, "PUT", &url, b"x", token)?;
        if case == "expired" {
            claims.issued_at = now() - 120;
        }
        if case == "future" {
            claims.issued_at = now() + 120;
        }
        let mut proof = Proof::decode(&session_proof(&key, claims)?)?;
        if case == "signature" {
            proof.signature = "00".repeat(64);
        }
        let mut request = http
            .put(&url)
            .header("authorization", format!("MySync {token}"))
            .header(PROOF_HEADER, proof.encode()?)
            .body(pending_body())
            .build()?;
        if case == "method" {
            *request.method_mut() = Method::POST;
        }
        if case == "query" {
            request
                .url_mut()
                .set_query(Some("path=other&base_revision=0"));
        }
        let response =
            tokio::time::timeout(Duration::from_secs(3), http.execute(request)).await??;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{case}");
    }
    let replay = signed(&http, &url, Method::PUT, b"x".to_vec(), &key, &active.token).await?;
    assert_eq!(
        http.execute(replay.try_clone().unwrap()).await?.status(),
        StatusCode::OK
    );
    let mut replay = replay;
    *replay.body_mut() = Some(pending_body());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), http.execute(replay))
            .await??
            .status(),
        StatusCode::UNAUTHORIZED
    );

    let mut tasks = tokio::task::JoinSet::new();
    let mut nonces = Vec::new();
    for _ in 0..8 {
        let mut request =
            signed(&http, &url, Method::PUT, b"x".to_vec(), &key, &active.token).await?;
        nonces.push(
            Proof::decode(request.headers()[PROOF_HEADER].to_str()?)?
                .claims
                .nonce,
        );
        *request.body_mut() = Some(pending_body());
        let http = http.clone();
        tasks.spawn(async move { http.execute(request).await });
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let db = server.db().unwrap();
            if nonces.iter().all(|nonce| {
                db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM proof_nonces WHERE nonce=?1)",
                    [nonce],
                    |r| r.get::<_, bool>(0),
                )
                .unwrap()
            }) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    let mut request = signed(&http, &url, Method::PUT, b"x".to_vec(), &key, &active.token).await?;
    *request.body_mut() = Some(pending_body());
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), http.execute(request))
            .await??
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    // A short burst waits for admission without reading another body. Once
    // existing handlers finish, this request succeeds without a client retry.
    let waiting = signed(
        &http,
        &format!("{}/v1/manifest", server.url),
        Method::GET,
        vec![],
        &key,
        &active.token,
    )
    .await?;
    let waiting_http = http.clone();
    let waiting = tokio::spawn(async move { waiting_http.execute(waiting).await });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !waiting.is_finished(),
        "burst was rejected before admission"
    );
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), waiting)
            .await???
            .status(),
        StatusCode::OK
    );
    // Cancellation releases admission slots; a new legitimate request works.
    let request = signed(
        &http,
        &format!("{}/v1/manifest", server.url),
        Method::GET,
        vec![],
        &key,
        &active.token,
    )
    .await?;
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let status = http.execute(request.try_clone().unwrap()).await?.status();
            if status == StatusCode::OK {
                break Ok::<_, anyhow::Error>(());
            }
            assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await??;

    // Revocation during an admitted body read is rechecked after EOF.
    use futures_util::StreamExt;
    let late_url = format!("{}/v1/file?path=revoked-upload&base_revision=0", server.url);
    let mut request = signed(
        &http,
        &late_url,
        Method::PUT,
        b"x".to_vec(),
        &key,
        &active.token,
    )
    .await?;
    let nonce = Proof::decode(request.headers()[PROOF_HEADER].to_str()?)?
        .claims
        .nonce;
    let (finish, done) = tokio::sync::oneshot::channel::<()>();
    let body = futures_util::stream::once(async { Ok::<_, std::io::Error>(vec![b'x']) }).chain(
        futures_util::stream::once(async {
            let _ = done.await;
            Ok(vec![])
        }),
    );
    *request.body_mut() = Some(reqwest::Body::wrap_stream(body));
    let http_task = http.clone();
    let upload = tokio::spawn(async move { http_task.execute(request).await });
    tokio::time::timeout(Duration::from_secs(3), async {
        while !server
            .db()
            .unwrap()
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM proof_nonces WHERE nonce=?1)",
                [&nonce],
                |r| r.get::<_, bool>(0),
            )
            .unwrap()
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await?;
    server::revoke_device(&server.state, "body-limits")?;
    finish.send(()).unwrap();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), upload)
            .await???
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(!server.db()?.query_row(
        "SELECT EXISTS(SELECT 1 FROM entries WHERE path='revoked-upload')",
        [],
        |r| r.get::<_, bool>(0)
    )?);
    Ok(())
}

#[tokio::test]
async fn tpm_enrollment_request_binding_replay_and_revocation() -> Result<()> {
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    let cert = simulator.certify_ek(&ca, "rsa")?;
    let (mut key, _) = Identity::create(&simulator.tcti, "rsa")?;
    let server = Server::start(&ca).await?;
    let http = Client::new();
    let invitation = device_auth::invite(&server.state, "device-a")?;
    let fingerprint = enroll(&http, &server, &invitation, &mut key, &cert).await?;
    assert!(session(&http, &server, &key).await.is_err());
    assert!(device_auth::approve(&server.state, &key.device, &"0".repeat(64)).is_err());
    device_auth::approve(&server.state, &key.device, &fingerprint)?;
    assert_eq!(
        http.get(format!("{}/v1/manifest", server.url))
            .bearer_auth("obsolete-device-key")
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let active = session(&http, &server, &key).await?;
    let url = format!("{}/v1/manifest", server.url);
    let request = signed(&http, &url, Method::GET, vec![], &key, &active.token).await?;
    let replay = request.try_clone().unwrap();
    assert_eq!(http.execute(request).await?.status(), StatusCode::OK);
    assert_eq!(
        http.execute(replay).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        http.get(&url)
            .header("authorization", format!("MySync {}", active.token))
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let file_url = format!("{}/v1/file?path=a&base_revision=0", server.url);
    for mutation in ["body", "query", "method", "token"] {
        let mut request = signed(
            &http,
            &file_url,
            Method::PUT,
            b"original".to_vec(),
            &key,
            &active.token,
        )
        .await?;
        match mutation {
            "body" => *request.body_mut() = Some("tampered".into()),
            "query" => request
                .url_mut()
                .set_query(Some("path=other&base_revision=0")),
            "method" => *request.method_mut() = Method::DELETE,
            _ => {
                request
                    .headers_mut()
                    .insert("authorization", "MySync other-token".parse()?);
            }
        }
        assert_eq!(
            http.execute(request).await?.status(),
            StatusCode::UNAUTHORIZED,
            "{mutation}"
        );
    }
    let mut expired = Claims::new(&key.device, "GET", &url, b"", &active.token)?;
    expired.issued_at = now() - 120;
    assert_eq!(
        http.get(&url)
            .header("authorization", format!("MySync {}", active.token))
            .header(PROOF_HEADER, session_proof(&key, expired)?)
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );

    // Exercise the real client, including a chunked signed upload and download.
    let local = tempfile::tempdir()?;
    let root = local.path().join("mirror");
    std::fs::create_dir(&root)?;
    let config = ClientConfig {
        server_public_key: server.state.public_key(),
        server: server.url.clone(),
        identity: Some(key.clone()),
        root: root.clone(),
        auto_update: false,
        web_status_enabled: false,
        web_files_enabled: false,
        web_uploads_enabled: false,
        web_management_enabled: false,
        web_edit_enabled: false,
        web_run_enabled: false,
        update_public_key: mysyncfiles::release::PUBLIC_KEY_HEX.trim().into(),
    };
    let config_path = local.path().join("config.json");
    std::fs::write(&config_path, serde_json::to_vec(&config)?)?;
    std::fs::write(root.join("small"), b"small file")?;
    let large = vec![7u8; mysyncfiles::model::UPLOAD_CHUNK_BYTES as usize + 1];
    std::fs::write(root.join("large"), &large)?;
    assert_eq!(client::sync(&config_path).await?.uploaded, 2);
    let download_root = local.path().join("download");
    std::fs::create_dir(&download_root)?;
    let mut download_config = config.clone();
    download_config.root = download_root.clone();
    let download_path = local.path().join("download.json");
    std::fs::write(&download_path, serde_json::to_vec(&download_config)?)?;
    assert_eq!(client::sync(&download_path).await?.downloaded, 2);
    assert_eq!(std::fs::read(download_root.join("large"))?, large);

    // Expiring a cached session must force a signed renewal, not a downgrade.
    let api = client::Api::new(&config)?;
    api.manifest().await?;
    let sessions_before: i64 =
        server
            .db()?
            .query_row("SELECT COUNT(*) FROM device_sessions", [], |row| row.get(0))?;
    api.manifest().await?;
    let sessions_after: i64 =
        server
            .db()?
            .query_row("SELECT COUNT(*) FROM device_sessions", [], |row| row.get(0))?;
    assert_eq!(sessions_before, sessions_after);
    server
        .db()?
        .execute("UPDATE device_sessions SET expires_at=1", [])?;
    let request = signed(&http, &url, Method::GET, vec![], &key, &active.token).await?;
    assert_eq!(
        http.execute(request).await?.status(),
        StatusCode::UNAUTHORIZED
    );
    api.manifest().await?;

    // A copied blob cannot sign on another TPM, even though it has all config data.
    let other = Simulator::start()?;
    let mut copied = key.clone();
    copied.tcti = other.tcti.clone();
    assert!(
        copied
            .proof(Claims::new(&key.device, "GET", &url, b"", &active.token)?)
            .is_err()
    );
    assert!(server::revoke_device(&server.state, "device-a")?);
    let request = signed(&http, &url, Method::GET, vec![], &key, &active.token).await?;
    assert_eq!(http.execute(request).await?.status(), StatusCode::FORBIDDEN);
    assert!(session(&http, &server, &key).await.is_err());
    Ok(())
}

#[tokio::test]
async fn tpm_attestation_requires_trusted_valid_ek_and_one_key_per_invitation() -> Result<()> {
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    let cert = simulator.certify_ek(&ca, "ecc")?;
    let (mut key, _) = Identity::create(&simulator.tcti, "ecc")?;
    let server = Server::start(&ca).await?;
    let http = Client::new();
    let token = device_auth::invite(&server.state, "device")?;
    let ek = X509::from_der(&cert)?.public_key()?;
    let untrusted = Certificate::ca()?
        .sign_ek(&ek, "ecc", false, true)?
        .to_der()?;
    let expired = ca.sign_ek(&ek, "ecc", true, true)?.to_der()?;
    let wrong_usage = ca.sign_ek(&ek, "ecc", false, false)?.to_der()?;
    for invalid in [&untrusted, &expired, &wrong_usage] {
        assert_eq!(
            start_enroll(&http, &server, &token, &key, invalid)
                .await?
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    assert_eq!(
        start_enroll(&http, &server, "bad invitation", &key, &cert)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let challenge: EnrollChallenge = start_enroll(&http, &server, &token, &key, &cert)
        .await?
        .error_for_status()?
        .json()
        .await?;
    let retry: EnrollChallenge = start_enroll(&http, &server, &token, &key, &cert)
        .await?
        .error_for_status()?
        .json()
        .await?;
    assert_eq!(retry.credential, challenge.credential);
    let (different, _) = Identity::create(&simulator.tcti, "ecc")?;
    assert_eq!(
        start_enroll(&http, &server, &token, &different, &cert)
            .await?
            .status(),
        StatusCode::CONFLICT
    );
    assert!(different.activate(&challenge).is_err());
    assert_eq!(
        http.post(format!("{}/v1/enroll/finish", server.url))
            .json(&EnrollFinish {
                id: challenge.id.clone(),
                activation: "00".repeat(32)
            })
            .send()
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let fingerprint = enroll(&http, &server, &token, &mut key, &cert).await?;
    assert!(
        device_auth::list(&server.state)?
            .iter()
            .any(|e| e.status == "pending-approval")
    );
    device_auth::approve(&server.state, &key.device, &fingerprint)?;
    session(&http, &server, &key).await?;
    let expired_token = device_auth::invite(&server.state, "expired")?;
    server.db()?.execute(
        "UPDATE device_enrollments SET expires_at=1 WHERE invitation_hash=?1",
        [hash(&expired_token)],
    )?;
    assert_eq!(
        start_enroll(&http, &server, &expired_token, &different, &cert)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let cancelled = device_auth::invite(&server.state, "cancelled")?;
    let entry = device_auth::list(&server.state)?
        .into_iter()
        .find(|e| e.name == "cancelled")
        .unwrap();
    device_auth::cancel(&server.state, &entry.id)?;
    assert_eq!(
        start_enroll(&http, &server, &cancelled, &different, &cert)
            .await?
            .status(),
        StatusCode::UNAUTHORIZED
    );
    device_auth::invite(&server.state, "cancelled")?;
    assert!(device_auth::cancel(&server.state, &key.device).is_err());
    Ok(())
}

#[tokio::test]
async fn client_enrolls_with_embedded_ek_intermediates() -> Result<()> {
    let root_ca = Certificate::ca()?;
    let issuing_ca = root_ca.intermediate()?;
    let simulator = Simulator::start()?;
    simulator.certify_ek(&issuing_ca, "rsa")?;
    let embedded = vec![
        issuing_ca.certificate.to_der()?,
        root_ca.certificate.to_der()?,
    ];
    simulator.install_chain(&embedded)?;
    let (identity, _) = Identity::create(&simulator.tcti, "rsa")?;
    assert_eq!(identity.ek_intermediates()?, embedded);

    let server = Server::start(&root_ca).await?;
    let local = tempfile::tempdir()?;
    let mirror = local.path().join("mirror");
    std::fs::create_dir(&mirror)?;
    let config = local.path().join("config.json");
    let invitation = device_auth::invite(&server.state, "embedded-chain")?;
    let enrolled = client::enroll_with_tcti(
        &config,
        server.url.clone(),
        server.state.public_key(),
        mirror,
        invitation,
        None,
        None,
        simulator.tcti.clone(),
    )
    .await?;
    assert_eq!(enrolled.status, "pending-approval");
    Ok(())
}

#[tokio::test]
async fn client_enrolls_with_ek_chain_split_across_nv_indices() -> Result<()> {
    let root_ca = Certificate::ca()?;
    let issuing_ca = root_ca.intermediate()?;
    let simulator = Simulator::start()?;
    simulator.certify_ek(&issuing_ca, "rsa")?;
    let root_der = root_ca.certificate.to_der()?;
    let issuer_der = issuing_ca.certificate.to_der()?;
    let split = issuer_der.len() / 2;
    let mut first_index = root_der.clone();
    first_index.extend_from_slice(&issuer_der[..split]);
    simulator.install_chain_parts(&[first_index, issuer_der[split..].to_vec()])?;
    let (identity, _) = Identity::create(&simulator.tcti, "rsa")?;
    assert_eq!(identity.ek_intermediates()?, vec![root_der, issuer_der]);

    let server = Server::start(&root_ca).await?;
    let local = tempfile::tempdir()?;
    let mirror = local.path().join("mirror");
    std::fs::create_dir(&mirror)?;
    let invitation = device_auth::invite(&server.state, "split-chain")?;
    let enrolled = client::enroll_with_tcti(
        &local.path().join("config.json"),
        server.url.clone(),
        server.state.public_key(),
        mirror,
        invitation,
        None,
        None,
        simulator.tcti.clone(),
    )
    .await?;
    assert_eq!(enrolled.status, "pending-approval");
    Ok(())
}

#[tokio::test]
async fn client_enrollment_is_resumable() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    simulator.certify_ek(&ca, "rsa")?;
    {
        let server = Server::start(&ca).await?;
        let local = tempfile::tempdir()?;
        let root = local.path().join("mirror");
        std::fs::create_dir(&root)?;
        std::fs::write(root.join("keep.txt"), b"keep local data")?;
        let path = local.path().join("config.json");
        let invitation = device_auth::invite(&server.state, "lifecycle")?;
        let mut fingerprint = String::new();
        let mut enrollment_id = String::new();
        for _ in 0..2 {
            let enrolled = client::enroll_with_tcti(
                &path,
                server.url.clone(),
                server.state.public_key(),
                root.clone(),
                invitation.clone(),
                None,
                None,
                simulator.tcti.clone(),
            )
            .await?;
            assert_eq!(enrolled.status, "pending-approval");
            if !fingerprint.is_empty() {
                assert_eq!(fingerprint, enrolled.fingerprint);
                assert_eq!(enrollment_id, enrolled.id);
            }
            fingerprint = enrolled.fingerprint;
            enrollment_id = enrolled.id;
            assert!(client::activate_enrollment(&path).await.is_err());
            assert!(!path.exists());
            assert_eq!(
                std::fs::metadata(path.with_extension("enrollment.json"))?
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        device_auth::approve(&server.state, &enrollment_id, &fingerprint)?;
        let report = client::activate_enrollment(&path).await?;
        assert_eq!(report.uploaded, 1);
        assert_eq!(report.conflicts, 0);
        assert!(!path.with_extension("enrollment.json").exists());
        let config = client::load_config(&path)?;
        assert_eq!(config.identity.as_ref().unwrap().device, enrollment_id);
        assert!(config.auto_update);
        assert!(config.web_status_enabled);
        assert_eq!(std::fs::read(root.join("keep.txt"))?, b"keep local data");
        assert_eq!(
            std::fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600
        );
    }
    Ok(())
}

#[tokio::test]
async fn client_enrolls_with_external_ek_certificate() -> Result<()> {
    let ca = Certificate::ca()?;
    let simulator = Simulator::start()?;
    let certificate = simulator.issue_ek(&ca, "rsa", false)?;
    let server = Server::start(&ca).await?;
    let local = tempfile::tempdir()?;
    let root = local.path().join("mirror");
    std::fs::create_dir(&root)?;
    std::fs::write(root.join("local.txt"), b"hello")?;
    let cert_path = local.path().join("ek.der");
    std::fs::write(&cert_path, certificate)?;
    let config = local.path().join("config.json");
    let invitation = device_auth::invite(&server.state, "external-ek")?;
    let untrusted_ca = Certificate::ca()?;
    let untrusted_certificate = simulator.issue_ek(&untrusted_ca, "rsa", false)?;
    let untrusted_path = local.path().join("untrusted.der");
    std::fs::write(&untrusted_path, untrusted_certificate)?;
    assert!(
        client::enroll_with_tcti(
            &config,
            server.url.clone(),
            server.state.public_key(),
            root.clone(),
            invitation.clone(),
            Some(untrusted_path),
            None,
            simulator.tcti.clone(),
        )
        .await
        .is_err()
    );
    let enrolled = client::enroll_with_tcti(
        &config,
        server.url.clone(),
        server.state.public_key(),
        root.clone(),
        invitation.clone(),
        Some(cert_path.clone()),
        None,
        simulator.tcti.clone(),
    )
    .await?;
    assert_eq!(enrolled.status, "pending-approval");
    let repeated = client::enroll_with_tcti(
        &config,
        server.url.clone(),
        server.state.public_key(),
        root.clone(),
        invitation,
        Some(cert_path),
        None,
        simulator.tcti.clone(),
    )
    .await?;
    assert_eq!(repeated.fingerprint, enrolled.fingerprint);
    device_auth::approve(&server.state, &enrolled.id, &enrolled.fingerprint)?;
    let report = client::activate_enrollment(&config).await?;
    assert_eq!(report.uploaded, 1);
    Ok(())
}

#[test]
fn unconfigured_server_rejects_invitations_without_overwriting_files() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let state = server::open(dir.path())?;
    let export = dir.path().join("invitation");
    assert!(device_auth::invite_to_file(&state, "unconfigured", &export).is_err());
    assert!(!export.exists());
    std::fs::write(&export, "existing secret")?;
    assert!(device_auth::invite_to_file(&state, "unconfigured", &export).is_err());
    assert_eq!(std::fs::read(export)?, b"existing secret");
    Ok(())
}

#[test]
fn obsolete_device_key_database_cannot_start() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db = rusqlite::Connection::open(dir.path().join("metadata.sqlite3"))?;
    db.execute_batch("CREATE TABLE devices(id INTEGER PRIMARY KEY, name TEXT NOT NULL, token_hash TEXT NOT NULL);")?;
    drop(db);
    assert!(
        server::open(dir.path())
            .err()
            .unwrap()
            .to_string()
            .contains("obsolete device-key database")
    );
    Ok(())
}

#[test]
fn old_bearer_client_profile_is_rejected() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("config.json");
    std::fs::write(
        &path,
        serde_json::to_vec(&serde_json::json!({
            "server": "http://127.0.0.1:8484",
            "root": dir.path(),
            "token": "obsolete-secret"
        }))?,
    )?;
    assert!(
        client::load_config(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("unknown field `token`")
    );
    Ok(())
}
