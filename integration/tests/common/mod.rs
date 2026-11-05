#![allow(dead_code)]

use anyhow::{Result, ensure};
use mysyncfiles::{
    auth_protocol::{
        Claims, EnrollChallenge, EnrollFinish, EnrollStart, Enrollment, PROOF_HEADER, Session, now,
    },
    client::{self, ClientConfig},
    device_auth, server,
    tpm::Identity,
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
use reqwest::Client;
use std::{
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::Arc,
    time::Duration,
};

pub struct Simulator {
    process: Child,
    dir: tempfile::TempDir,
    pub tcti: String,
}
impl Drop for Simulator {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}
impl Simulator {
    pub fn start() -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let port = loop {
            let first = std::net::TcpListener::bind("127.0.0.1:0")?;
            let port = first.local_addr()?.port();
            if port < 65535 && std::net::TcpListener::bind(("127.0.0.1", port + 1)).is_ok() {
                break port;
            }
        };
        let process = Command::new("swtpm")
            .args(["socket", "--tpm2", "--tpmstate"])
            .arg(format!("dir={}", dir.path().display()))
            .arg("--ctrl")
            .arg(format!("type=tcp,bindaddr=127.0.0.1,port={}", port + 1))
            .arg("--server")
            // TCTI uses one connection per command; inherited sockets in other
            // test children must not keep an idle connection alive here.
            .arg(format!(
                "type=tcp,bindaddr=127.0.0.1,port={port},disconnect"
            ))
            .args(["--flags", "not-need-init,startup-clear"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let simulator = Self {
            process,
            dir,
            tcti: format!("swtpm:host=127.0.0.1,port={port}"),
        };
        for _ in 0..100 {
            if simulator.tool("tpm2_getcap", &["properties-fixed"]).is_ok() {
                return Ok(simulator);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        anyhow::bail!("swtpm did not start")
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
    pub fn certify_ek(&self, ca: &Certificate) -> Result<Vec<u8>> {
        let context = self.dir.path().join("ek.ctx");
        let pem = self.dir.path().join("ek.pem");
        self.tool(
            "tpm2_createek",
            &["-G", "rsa", "-c", context.to_str().unwrap()],
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
        let der = ca.sign_ek(&key)?.to_der()?;
        let path = self.dir.path().join("ek.der");
        std::fs::write(&path, &der)?;
        self.tool(
            "tpm2_nvdefine",
            &[
                "0x01c00002",
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
            &["0x01c00002", "-C", "o", "-i", path.to_str().unwrap()],
        )?;
        self.tool("tpm2_flushcontext", &["-t"])?;
        Ok(der)
    }
}

pub struct Certificate {
    key: PKey<Private>,
    certificate: X509,
}
impl Certificate {
    pub fn ca() -> Result<Self> {
        let key = PKey::from_rsa(Rsa::generate(2048)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "MySync isolated test CA")?;
        let name = name.build();
        let mut b = X509::builder()?;
        b.set_version(2)?;
        let serial = openssl::bn::BigNum::from_u32(1)?.to_asn1_integer()?;
        b.set_serial_number(&serial)?;
        b.set_subject_name(&name)?;
        b.set_issuer_name(&name)?;
        b.set_pubkey(&key)?;
        let start = Asn1Time::days_from_now(0)?;
        let end = Asn1Time::days_from_now(2)?;
        b.set_not_before(&start)?;
        b.set_not_after(&end)?;
        b.append_extension(BasicConstraints::new().critical().ca().build()?)?;
        b.append_extension(
            KeyUsage::new()
                .critical()
                .key_cert_sign()
                .crl_sign()
                .build()?,
        )?;
        b.sign(&key, MessageDigest::sha256())?;
        Ok(Self {
            key,
            certificate: b.build(),
        })
    }
    fn sign_ek(&self, key: &PKey<Public>) -> Result<X509> {
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_text("CN", "Test TPM Endorsement Key")?;
        let mut b = X509::builder()?;
        b.set_version(2)?;
        let serial = openssl::bn::BigNum::from_u32(2)?.to_asn1_integer()?;
        b.set_serial_number(&serial)?;
        b.set_subject_name(&name.build())?;
        b.set_issuer_name(self.certificate.subject_name())?;
        b.set_pubkey(key)?;
        let start = Asn1Time::from_unix(now() - 3600)?;
        let end = Asn1Time::from_unix(now() + 86400)?;
        b.set_not_before(&start)?;
        b.set_not_after(&end)?;
        b.append_extension(BasicConstraints::new().critical().build()?)?;
        b.append_extension(KeyUsage::new().critical().key_encipherment().build()?)?;
        b.append_extension(ExtendedKeyUsage::new().other("2.23.133.8.1").build()?)?;
        b.sign(&self.key, MessageDigest::sha256())?;
        Ok(b.build())
    }
    pub fn pem(&self) -> Result<Vec<u8>> {
        Ok(self.certificate.to_pem()?)
    }
}

pub struct TestServer {
    pub state: Arc<server::ServerState>,
    pub url: String,
    pub task: tokio::task::JoinHandle<()>,
    _dir: tempfile::TempDir,
    _simulators: Vec<Simulator>,
    ca: Certificate,
}
impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl TestServer {
    pub async fn start(data: &Path) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let ca = Certificate::ca()?;
        let state = server::open(data)?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let url = format!("http://{}", listener.local_addr()?);
        register_origin(&url, state.public_key());
        let roots = dir.path().join("roots.pem");
        std::fs::write(&roots, ca.pem()?)?;
        device_auth::configure(&state, &url, &roots)?;
        let router = server::router(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(server::api_listener(listener), router)
                .await
                .unwrap()
        });
        Ok(Self {
            state,
            url,
            task,
            _dir: dir,
            _simulators: vec![],
            ca,
        })
    }
    pub async fn add_device(&mut self, name: &str) -> Result<Identity> {
        let simulator = Simulator::start()?;
        let cert = simulator.certify_ek(&self.ca)?;
        let (mut key, _) = Identity::create(&simulator.tcti, "rsa")?;
        let invitation = device_auth::invite(&self.state, name)?;
        let http = Client::new();
        let challenge: EnrollChallenge = http
            .post(format!("{}/v1/enroll/start", self.url))
            .json(&EnrollStart {
                invitation,
                public: key.public.clone(),
                ek_chain: vec![hex::encode(cert)],
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let activation = key.activate(&challenge)?;
        key.device = challenge.id.clone();
        let enrolled: Enrollment = http
            .post(format!("{}/v1/enroll/finish", self.url))
            .json(&EnrollFinish {
                id: challenge.id,
                activation,
            })
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        device_auth::approve(&self.state, &key.device, &enrolled.fingerprint)?;
        self._simulators.push(simulator);
        Ok(key)
    }
}

pub fn config(url: &str, root: &Path, identity: Identity) -> ClientConfig {
    ClientConfig {
        server: url.into(),
        server_public_key: origins()
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .unwrap_or_default(),
        identity: Some(identity),
        root: root.into(),
        auto_update: false,
        web_status_enabled: false,
        web_files_enabled: false,
        web_uploads_enabled: false,
        web_management_enabled: false,
        web_edit_enabled: false,
        web_run_enabled: false,
        update_public_key: mysyncfiles::release::PUBLIC_KEY_HEX.trim().into(),
    }
}

fn origins() -> &'static std::sync::Mutex<std::collections::HashMap<String, String>> {
    static ORIGINS: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<String, String>>,
    > = std::sync::OnceLock::new();
    ORIGINS.get_or_init(Default::default)
}

pub fn register_origin(url: &str, key: String) {
    origins().lock().unwrap().insert(url.into(), key);
}
pub async fn configure_client(
    path: &Path,
    url: &str,
    key: Identity,
    root: PathBuf,
) -> Result<client::SyncReport> {
    std::fs::create_dir_all(&root)?;
    std::fs::write(path, serde_json::to_vec(&config(url, &root, key))?)?;
    client::sync(path).await
}

pub async fn send_signed(
    builder: reqwest::RequestBuilder,
    key: &Identity,
) -> Result<reqwest::Response> {
    let http = Client::new();
    let mut request = builder.build()?;
    let mut session_url = request.url().clone();
    session_url.set_path("/v1/auth/session");
    session_url.set_query(None);
    let ephemeral = ed25519_dalek::SigningKey::from_bytes(
        &hex::decode(mysyncfiles::auth_protocol::random_secret()?)?
            .try_into()
            .unwrap(),
    );
    let mut session_request = http
        .post(session_url)
        .json(&mysyncfiles::auth_protocol::SessionRequest {
            version: mysyncfiles::auth_protocol::PROTOCOL_VERSION,
            public_key: hex::encode(ephemeral.verifying_key().to_bytes()),
        })
        .build()?;
    sign(&mut session_request, key, "")?;
    let session: Session = http
        .execute(session_request)
        .await?
        .error_for_status()?
        .json()
        .await?;
    if mysyncfiles::auth_protocol::requires_tpm(request.url().path()) {
        sign(&mut request, key, &session.token)?;
    } else {
        let body = request
            .body()
            .and_then(|b| b.as_bytes())
            .unwrap_or_default();
        let claims = Claims::new(
            &key.device,
            request.method().as_str(),
            request.url().as_str(),
            body,
            &session.token,
        )?;
        request.headers_mut().insert(
            PROOF_HEADER,
            mysyncfiles::auth_protocol::Proof::session(claims, &ephemeral)?
                .encode()?
                .parse()?,
        );
        request.headers_mut().insert(
            reqwest::header::AUTHORIZATION,
            format!("MySync {}", session.token).parse()?,
        );
    }
    Ok(http.execute(request).await?)
}
fn sign(request: &mut reqwest::Request, key: &Identity, token: &str) -> Result<()> {
    let body = request
        .body()
        .and_then(|b| b.as_bytes())
        .unwrap_or_default();
    let claims = Claims::new(
        &key.device,
        request.method().as_str(),
        request.url().as_str(),
        body,
        token,
    )?;
    request
        .headers_mut()
        .insert(PROOF_HEADER, key.proof(claims)?.parse()?);
    if !token.is_empty() {
        request.headers_mut().insert(
            reqwest::header::AUTHORIZATION,
            format!("MySync {token}").parse()?,
        );
    }
    Ok(())
}
