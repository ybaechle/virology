// Audit d'élévation de privilèges (Windows).
// Vérifie les vecteurs UAC classiques sans exécuter aucun exploit.
pub fn run(_args: &str) -> String {
    #[cfg(windows)]
    return audit_windows();
    #[cfg(not(windows))]
    audit_linux()
}

#[cfg(windows)]
fn audit_windows() -> String {
    use std::process::Command;
    use std::os::windows::process::CommandExt;

    let mut results = Vec::new();

    // 1. Niveau UAC
    let uac = Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
               "/v", "ConsentPromptBehaviorAdmin"])
        .creation_flags(0x08000000)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    results.push(format!("UAC ConsentPrompt:\n{}", uac.trim()));

    // 2. AlwaysInstallElevated
    for hive in &[r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer",
                  r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer"] {
        let out = Command::new("reg")
            .args(["query", hive, "/v", "AlwaysInstallElevated"])
            .creation_flags(0x08000000)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default();
        if !out.trim().is_empty() {
            results.push(format!("AlwaysInstallElevated ({}):\n{}", hive, out.trim()));
        }
    }

    // 3. Services avec chemin non quoté (via sc query + reg)
    let svcs = Command::new("powershell")
        .args(["-NoProfile", "-Command",
               "Get-WmiObject Win32_Service | Select-Object Name,PathName | Format-List"])
        .creation_flags(0x08000000)
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let unquoted: Vec<&str> = svcs.lines()
        .filter(|l| l.starts_with("PathName"))
        .filter(|l| {
            let path = l.splitn(2, ':').nth(1).unwrap_or("").trim();
            path.contains(' ') && !path.starts_with('"') && path.contains('\\')
        })
        .collect();
    if !unquoted.is_empty() {
        results.push(format!("Services chemin non quoté ({}) :", unquoted.len()));
        for s in &unquoted {
            results.push(format!("  {}", s.trim()));
        }
    }

    // 4. Exploitation AlwaysInstallElevated si disponible
    let hklm_aie = Command::new("reg")
        .args(["query", r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer",
               "/v", "AlwaysInstallElevated"])
        .creation_flags(0x08000000)
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("0x1"))
        .unwrap_or(false);
    let hkcu_aie = Command::new("reg")
        .args(["query", r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer",
               "/v", "AlwaysInstallElevated"])
        .creation_flags(0x08000000)
        .output()
        .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).contains("0x1"))
        .unwrap_or(false);
    if hklm_aie && hkcu_aie {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "implant.exe".to_string());
        let msi_path = std::env::temp_dir().join("update.msi");
        let msi_cmd = format!(
            "msiexec /quiet /qn /i \"{}\" TARGETDIR=\"C:\\Windows\\Temp\" CMD=\"{}\"",
            msi_path.display(), exe
        );
        results.push(format!(
            "[exploit] AlwaysInstallElevated actif !\nCommande : {}", msi_cmd
        ));
    }

    results.join("\n\n")
}

#[cfg(not(windows))]
fn audit_linux() -> String {
    use std::process::Command;
    let mut results = Vec::new();

    // SUID
    let suid = Command::new("find")
        .args(["/", "-perm", "-4000", "-type", "f", "-not", "-path", "/proc/*"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    results.push(format!("SUID :\n{}", suid.trim()));

    // sudo -l
    let sudo = Command::new("sudo")
        .args(["-n", "-l"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    results.push(format!("sudo -l :\n{}", sudo.trim()));

    results.join("\n\n")
}
