// HTTPS avec cert pinning SHA-256 via rustls.
// On implémente ServerCertVerifier sur mesure : vérifie uniquement l'empreinte,
// pas la chaîne de confiance. Un proxy d'interception ne suffit pas à casser le canal.
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};
use sha2::{Digest, Sha256};

use crate::config;

static USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36 Edg/129.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 \
     (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
];

pub struct Transport {
    host: String,
    port: u16,
    tls_config: Arc<ClientConfig>,
}

impl Transport {
    pub fn new(host: &str, port: u16) -> Result<Self> {
        let fingerprint = parse_fingerprint(config::FINGERPRINT)?;
        let verifier = Arc::new(PinnedVerifier { fingerprint });
        let tls_config = Arc::new(
            ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth(),
        );
        Ok(Self { host: host.to_string(), port, tls_config })
    }

    pub fn get(&self, path: &str) -> Result<Vec<u8>> {
        self.request("GET", path, None, "application/octet-stream")
    }

    pub fn post(&self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        self.request("POST", path, Some(body), "application/octet-stream")
    }

    pub fn post_json(&self, path: &str, body: &[u8]) -> Result<Vec<u8>> {
        self.request("POST", path, Some(body), "application/json")
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<&[u8]>,
        content_type: &str,
    ) -> Result<Vec<u8>> {
        let tcp = TcpStream::connect(format!("{}:{}", self.host, self.port))
            .context("connexion TCP")?;
        tcp.set_read_timeout(Some(Duration::from_secs(config::TIMEOUT_SECS)))?;
        tcp.set_write_timeout(Some(Duration::from_secs(config::TIMEOUT_SECS)))?;

        let server_name: ServerName<'static> = self
            .host
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("ServerName invalide"))?;

        let conn = ClientConnection::new(self.tls_config.clone(), server_name)
            .context("connexion TLS")?;
        let mut stream = StreamOwned::new(conn, tcp);

        let ua = USER_AGENTS[rand_index(USER_AGENTS.len())];
        let mut req = format!(
            "{} {} HTTP/1.1\r\nHost: {}:{}\r\nUser-Agent: {}\r\nConnection: close\r\n",
            method, path, self.host, self.port, ua
        );
        if let Some(b) = body {
            req.push_str(&format!(
                "Content-Type: {}\r\nContent-Length: {}\r\n",
                content_type,
                b.len()
            ));
        }
        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).context("écriture requête")?;
        if let Some(b) = body {
            stream.write_all(b).context("écriture corps")?;
        }

        let mut raw = Vec::new();
        stream.read_to_end(&mut raw).context("lecture réponse")?;
        parse_response(&raw)
    }
}

fn parse_response(data: &[u8]) -> Result<Vec<u8>> {
    let sep = b"\r\n\r\n";
    let pos = data
        .windows(4)
        .position(|w| w == sep)
        .ok_or_else(|| anyhow::anyhow!("réponse HTTP malformée"))?;

    let headers = &data[..pos];
    let status: u16 = std::str::from_utf8(headers)
        .unwrap_or("")
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    if status != 200 {
        bail!("HTTP {}", status);
    }
    Ok(data[pos + 4..].to_vec())
}

fn parse_fingerprint(hex_str: &str) -> Result<[u8; 32]> {
    if hex_str.is_empty() {
        // En développement, sans empreinte compilée : on accepte tout.
        return Ok([0u8; 32]);
    }
    let bytes = hex::decode(hex_str).context("empreinte invalide")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("empreinte : longueur ≠ 32 octets"))
}

fn rand_index(n: usize) -> usize {
    use rand::RngCore;
    (rand::rngs::OsRng.next_u64() as usize) % n
}

// -- cert pinning ------------------------------------------------------------

#[derive(Debug)]
struct PinnedVerifier {
    // Empreinte attendue. Tous-zéros = mode dev, accepte tout.
    fingerprint: [u8; 32],
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if self.fingerprint == [0u8; 32] {
            return Ok(ServerCertVerified::assertion());
        }
        let got: [u8; 32] = Sha256::digest(end_entity.as_ref()).into();
        if got == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "empreinte du certificat invalide".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let provider = rustls::crypto::ring::default_provider();
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
