// Commandes internes sans sous-processus : ls, ps, pwd, env, whoami.
// Zéro processus enfant = moins de bruit dans les journaux d'événements Windows.

pub fn run(args: &str) -> String {
    let mut parts = args.splitn(2, ' ');
    let cmd = parts.next().unwrap_or("").trim();
    let rest = parts.next().unwrap_or("").trim();

    match cmd {
        "ls" | "dir" => cmd_ls(if rest.is_empty() { "." } else { rest }),
        "ps"         => cmd_ps(),
        "pwd"        => cmd_pwd(),
        "env"        => cmd_env(),
        "whoami"     => cmd_whoami(),
        ""           => "bshell <ls|ps|pwd|env|whoami> [args]".to_string(),
        other        => format!("commande inconnue : {}", other),
    }
}

pub fn ps() -> String {
    cmd_ps()
}

fn cmd_ls(path: &str) -> String {
    match std::fs::read_dir(path) {
        Err(e) => format!("[erreur] {}", e),
        Ok(entries) => {
            let mut lines = Vec::new();
            for entry in entries.flatten() {
                let meta = entry.metadata();
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let kind = meta.map(|m| if m.is_dir() { 'd' } else { 'f' }).unwrap_or('?');
                lines.push(format!(
                    "{} {:>12}  {}",
                    kind,
                    size,
                    entry.file_name().to_string_lossy()
                ));
            }
            if lines.is_empty() {
                "(vide)".to_string()
            } else {
                lines.join("\n")
            }
        }
    }
}

fn cmd_ps() -> String {
    #[cfg(windows)]
    {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
            PROCESSENTRY32W, TH32CS_SNAPPROCESS,
        };

        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if snap == INVALID_HANDLE_VALUE {
                return "CreateToolhelp32Snapshot échoué".to_string();
            }
            let mut entry: PROCESSENTRY32W = std::mem::zeroed();
            entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
            let mut lines = Vec::new();
            lines.push(format!("{:>7}  {:>4}  {}", "PID", "THR", "NOM"));
            if Process32FirstW(snap, &mut entry) != 0 {
                loop {
                    let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
                    let name = String::from_utf16_lossy(&entry.szExeFile[..len]);
                    lines.push(format!(
                        "{:>7}  {:>4}  {}",
                        entry.th32ProcessID, entry.cntThreads, name
                    ));
                    if Process32NextW(snap, &mut entry) == 0 {
                        break;
                    }
                }
            }
            CloseHandle(snap);
            lines.join("\n")
        }
    }
    #[cfg(not(windows))]
    {
        std::fs::read_dir("/proc")
            .map(|entries| {
                entries
                    .flatten()
                    .filter_map(|e| {
                        let name = e.file_name();
                        let pid = name.to_str()?.parse::<u32>().ok()?;
                        let comm = std::fs::read_to_string(format!("/proc/{}/comm", pid))
                            .unwrap_or_default();
                        Some(format!("{:>7}  {}", pid, comm.trim()))
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_else(|_| "/proc illisible".to_string())
    }
}

fn cmd_pwd() -> String {
    std::env::current_dir()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "?".to_string())
}

fn cmd_env() -> String {
    std::env::vars()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join("\n")
}

fn cmd_whoami() -> String {
    crate::hostinfo::username()
}
