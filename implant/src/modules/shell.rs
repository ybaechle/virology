use std::process::Command;

const MAX_OUTPUT: usize = 4 * 1024 * 1024;

pub fn run(command: &str) -> String {
    if command.trim().is_empty() {
        return "usage: shell <commande>".to_string();
    }

    #[cfg(windows)]
    let mut child = Command::new("cmd.exe");
    #[cfg(windows)]
    child.args(["/c", command]);

    #[cfg(not(windows))]
    let mut child = Command::new("/bin/sh");
    #[cfg(not(windows))]
    child.args(["-c", command]);

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        child.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }

    match child.output() {
        Err(e) => format!("[echec du lancement: {}]", e),
        Ok(out) => {
            let mut text = decode_output(&out.stdout) + &decode_output(&out.stderr);
            if !out.status.success() {
                if let Some(code) = out.status.code() {
                    text.push_str(&format!("\n[code de sortie {}]", code));
                }
            }
            if text.is_empty() {
                "(sans sortie)".to_string()
            } else {
                text.chars().take(MAX_OUTPUT).collect()
            }
        }
    }
}

fn decode_output(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
