#[cfg(windows)]
pub fn download(url: &str) -> Result<Vec<u8>, ()> {
    use windows_sys::Win32::Networking::WinHttp::*;
    use windows_sys::Win32::Foundation::BOOL;

    // Parser l'URL manuellement : https://host/path
    let without_scheme = url.strip_prefix("https://").ok_or(())?;
    let slash = without_scheme.find('/').ok_or(())?;
    let host_port = &without_scheme[..slash];
    let path = &without_scheme[slash..];
    let (host, port) = if let Some((h, p)) = host_port.rsplit_once(':') {
        (h, p.parse::<u16>().unwrap_or(443))
    } else {
        (host_port, 443u16)
    };

    let host_w: Vec<u16> = host.encode_utf16().chain(std::iter::once(0)).collect();
    let path_w: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    // User-agent discret
    let agent_w: Vec<u16> = "Microsoft-WinHTTP-Autoproxy-Service/5.1"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    unsafe {
        let h_session = WinHttpOpen(
            agent_w.as_ptr(),
            WINHTTP_ACCESS_TYPE_NO_PROXY,
            std::ptr::null(),
            std::ptr::null(),
            0,
        );
        if h_session.is_null() {
            return Err(());
        }

        let h_connect = WinHttpConnect(h_session, host_w.as_ptr(), port, 0);
        if h_connect.is_null() {
            WinHttpCloseHandle(h_session);
            return Err(());
        }

        let verb_w: Vec<u16> = "GET\0".encode_utf16().collect();
        let h_request = WinHttpOpenRequest(
            h_connect,
            verb_w.as_ptr(),
            path_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            std::ptr::null(),
            WINHTTP_FLAG_SECURE,
        );
        if h_request.is_null() {
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err(());
        }

        let sent: BOOL = WinHttpSendRequest(
            h_request,
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
            0,
            0,
        );
        if sent == 0 {
            WinHttpCloseHandle(h_request);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err(());
        }

        let received: BOOL = WinHttpReceiveResponse(h_request, std::ptr::null_mut());
        if received == 0 {
            WinHttpCloseHandle(h_request);
            WinHttpCloseHandle(h_connect);
            WinHttpCloseHandle(h_session);
            return Err(());
        }

        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let mut bytes_read: u32 = 0;
            let ok: BOOL = WinHttpReadData(
                h_request,
                chunk.as_mut_ptr() as *mut _,
                chunk.len() as u32,
                &mut bytes_read,
            );
            if ok == 0 || bytes_read == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..bytes_read as usize]);
        }

        WinHttpCloseHandle(h_request);
        WinHttpCloseHandle(h_connect);
        WinHttpCloseHandle(h_session);

        if buf.is_empty() {
            Err(())
        } else {
            Ok(buf)
        }
    }
}

#[cfg(not(windows))]
pub fn download(_url: &str) -> Result<Vec<u8>, ()> {
    Err(())
}
