// Demande à Windows Defender de scanner un chemin.
// Utile pour tester si un payload sera détecté avant déploiement.
pub fn run(args: &str) -> String {
    #[cfg(not(windows))]
    return "avscan disponible sur Windows uniquement".to_string();

    #[cfg(windows)]
    {
        let path = args.trim();
        if path.is_empty() {
            return "usage: avscan <chemin>".to_string();
        }
        scan_windows(path)
    }
}

#[cfg(windows)]
fn scan_windows(path: &str) -> String {
    use std::process::Command;
    use std::os::windows::process::CommandExt;

    let mp_cmd = r"C:\Program Files\Windows Defender\MpCmdRun.exe";
    let out = Command::new(mp_cmd)
        .args(["-Scan", "-ScanType", "3", "-File", path])
        .creation_flags(0x08000000)
        .output();

    match out {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let stderr = String::from_utf8_lossy(&o.stderr);
            let code = o.status.code().unwrap_or(-1);
            format!(
                "code: {}\n{}\n{}",
                code,
                stdout.trim(),
                stderr.trim()
            )
            .trim()
            .to_string()
        }
        Err(e) => format!("[erreur] {} : {}", mp_cmd, e),
    }
}
