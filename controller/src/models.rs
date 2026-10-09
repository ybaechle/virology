use serde::Deserialize;
use serde_json::json;

#[derive(Deserialize)]
pub struct SessionPayload {
    pub id: String,
    pub key: String,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub os: Option<String>,
    pub pid: Option<i64>,
    pub elevated: Option<bool>,
    pub arch: Option<String>,
}

#[allow(dead_code)]
#[derive(Deserialize)]
pub struct ResultPayload {
    pub task_id: i64,
    pub body: String,
}

pub fn beacon_config(interval: u32, jitter: f64) -> Vec<u8> {
    serde_json::to_vec(&json!({"interval": interval, "jitter": jitter})).unwrap()
}

pub fn nop() -> Vec<u8> {
    br#"{"t":"nop"}"#.to_vec()
}

pub fn task(id: i64, command: &str, args: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "t": "task",
        "id": id,
        "command": command,
        "args": args,
    }))
    .unwrap()
}

pub fn ack() -> Vec<u8> {
    br#"{"t":"ack"}"#.to_vec()
}
