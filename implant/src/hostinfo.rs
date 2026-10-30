use std::net::UdpSocket;

pub fn os_version() -> String {
    std::env::consts::OS.to_string()
}

pub fn arch() -> String {
    std::env::consts::ARCH.to_string()
}

pub fn pid() -> u32 {
    std::process::id()
}

pub fn elevated() -> bool {
    #[cfg(windows)]
    {
        use windows_sys::Win32::UI::Shell::IsUserAnAdmin;
        unsafe { IsUserAnAdmin() != 0 }
    }
    #[cfg(not(windows))]
    {
        extern "C" {
            fn getuid() -> u32;
        }
        unsafe { getuid() == 0 }
    }
}

/// IP locale qui atteint target_host (aucun paquet envoyé, UDP vers port 9).
pub fn primary_ip(target_host: &str) -> String {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect(format!("{}:9", target_host))?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "0.0.0.0".to_string())
}

pub fn hostname() -> String {
    hostname_impl()
}

pub fn username() -> String {
    username_impl()
}

#[cfg(windows)]
fn hostname_impl() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "?".to_string())
}

#[cfg(not(windows))]
fn hostname_impl() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| {
            let mut buf = [0u8; 256];
            extern "C" {
                fn gethostname(name: *mut u8, len: usize) -> i32;
            }
            unsafe {
                if gethostname(buf.as_mut_ptr(), buf.len()) == 0 {
                    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
                    Ok(String::from_utf8_lossy(&buf[..end]).to_string())
                } else {
                    Err(std::env::VarError::NotPresent)
                }
            }
        })
        .unwrap_or_else(|_| "?".to_string())
}

#[cfg(windows)]
fn username_impl() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "?".to_string())
}

#[cfg(not(windows))]
fn username_impl() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| "?".to_string())
}
