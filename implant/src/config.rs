// Constantes compilées dans le binaire.
// Modifier avant le build avec les variables d'env, ou patcher directement.
//   C2_URL          = URL HTTPS du controller
//   C2_FINGERPRINT  = empreinte SHA-256 du certificat (hex 64 chars)

pub const C2_URL: &str = match option_env!("C2_URL") {
    Some(v) => v,
    None => "https://127.0.0.1:8443",
};

pub const FINGERPRINT: &str = match option_env!("C2_FINGERPRINT") {
    Some(v) => v,
    None => "",
};

pub const INTERVAL: u64 = 30;
pub const JITTER: f64 = 0.3;
pub const BACKOFF_START: u64 = 5;
pub const BACKOFF_MAX: u64 = 3600;
pub const TIMEOUT_SECS: u64 = 60;
