// Active ou désactive RDP (Windows uniquement).
pub fn run(args: &str) -> String {
    #[cfg(not(windows))]
    return "rdp disponible sur Windows uniquement".to_string();

    #[cfg(windows)]
    match args.trim() {
        "on" | "enable"   => set_rdp(true),
        "off" | "disable" => set_rdp(false),
        _                 => "usage: rdp <on|off>".to_string(),
    }
}

#[cfg(windows)]
fn set_rdp(enable: bool) -> String {
    use std::process::Command;
    use std::os::windows::process::CommandExt;

    let value = if enable { "0" } else { "1" }; // fDenyTSConnections
    let res = Command::new("reg")
        .args([
            "add",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
            "/v", "fDenyTSConnections",
            "/t", "REG_DWORD",
            "/d", value,
            "/f",
        ])
        .creation_flags(0x08000000)
        .output();

    if enable {
        // Ouvrir le port dans le pare-feu
        Command::new("netsh")
            .args(["advfirewall", "firewall", "add", "rule",
                   "name=RDP", "dir=in", "action=allow",
                   "protocol=TCP", "localport=3389"])
            .creation_flags(0x08000000)
            .output()
            .ok();
    }

    match res {
        Ok(out) if out.status.success() => {
            format!("RDP {}", if enable { "activé" } else { "désactivé" })
        }
        Ok(out) => format!("[erreur] {}", String::from_utf8_lossy(&out.stderr)),
        Err(e)  => format!("[erreur] {}", e),
    }
}
