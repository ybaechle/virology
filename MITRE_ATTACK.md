# Mapping MITRE ATT&CK

Correspondance entre les capacités de virology-rs et le framework [MITRE ATT&CK](https://attack.mitre.org/).

## Initial Access

| Technique | ID | Implémentation | Note blue team |
|-----------|-----|----------------|----------------|
| Phishing: Spearphishing Link | T1566.002 | Page Teams (`/update`) + ClickFix (`route_phish_post`) | Surveiller les requêtes vers des domaines inconnus avec formulaire de login. Les proxies web et filtres DNS détectent les pages de phishing par analyse du contenu HTML. |
| Drive-by Compromise | T1189 | Loader reflectif téléchargé via `/dl2` | Les solutions EDR détectent l'exécution de binaires téléchargés depuis des sources non signées. Surveiller les événements Sysmon EventID 1 (ProcessCreate) avec des binaires lancés depuis `%TEMP%`. |

## Execution

| Technique | ID | Implémentation | Note blue team |
|-----------|-----|----------------|----------------|
| Command and Scripting Interpreter: Windows Command Shell | T1059.003 | `shell.rs` — `cmd.exe /c` | Surveiller les EventID 4688 (Process Creation) pour les instances `cmd.exe` avec des lignes de commande inhabituelles. Sysmon EventID 1 avec `ParentImage` inattendu. |
| Native API | T1106 | `syscall.rs` — appel direct ntdll, `pe_loader.rs` — CreateThread | Les appels syscall directs contournent les hooks userland des EDR. Détectable par analyse des stacks d'appel (call stack non standard) ou par ETW (Event Tracing for Windows). |
| User Execution: Malicious File | T1204.002 | ClickFix social engineering | Formation des utilisateurs à ne pas exécuter de commandes copiées-collées depuis des pages web. Restreindre l'accès à `Win+R` via GPO. |
| Reflective Code Loading | T1620 | `pe_loader.rs` — chargement PE64 en mémoire | Surveiller les allocations mémoire RWX (VirtualAlloc avec PAGE_EXECUTE_READWRITE). Les EDR détectent les régions mémoire exécutables non mappées à un fichier sur disque. |

## Persistence

| Technique | ID | Implémentation | Note blue team |
|-----------|-----|----------------|----------------|
| Boot or Logon Autostart Execution: Registry Run Keys | T1547.001 | `persist.rs` — clé `HKCU\...\Run` | Surveiller les modifications de `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` via Sysmon EventID 13 (RegistryEvent). Alerter sur les nouvelles valeurs pointant vers des exécutables hors `Program Files`. |
| Scheduled Task/Job: Scheduled Task | T1053.005 | `persist.rs` — schtasks (tâche + watchdog) | Surveiller les EventID 4698 (Scheduled Task Created). Auditer régulièrement les tâches planifiées sous des chemins inhabituels (ex: `\Microsoft\Windows\WindowsTelemetry`). |
| Create or Modify System Process: Windows Service | T1543.003 | `persist.rs` — `sc.exe create` | Surveiller les EventID 7045 (Service Installed). Alerter sur les services avec des noms génériques (`WinTelemetrySvc`) pointant vers des binaires hors répertoires système. |

## Privilege Escalation

| Technique | ID | Implémentation | Note blue team |
|-----------|-----|----------------|----------------|
| Abuse Elevation Control Mechanism: Bypass UAC | T1548.002 | `privesc.rs` — audit UAC + AlwaysInstallElevated | Vérifier que `AlwaysInstallElevated` est désactivé (HKLM et HKCU). Configurer UAC au niveau maximum. Surveiller les EventID 4688 avec `msiexec.exe`. |
| Exploitation for Privilege Escalation | T1068 | `privesc.rs` — exploitation AlwaysInstallElevated via msiexec | Restreindre les privilèges d'installation MSI via GPO. Surveiller les installations MSI inattendues (EventID 1033/1034 dans Application). |
| Hijack Execution Flow: Unquoted Service Path | T1574.009 | `privesc.rs` — détection chemins non quotés | Auditer les services avec `Get-WmiObject Win32_Service` pour les chemins non quotés contenant des espaces. Corriger avec des guillemets. |

## Defense Evasion

| Technique | ID | Implémentation | Note blue team |
|-----------|-----|----------------|----------------|
| Obfuscated Files or Information | T1027 | `loader/main.rs` — XOR obfuscation URL/clé | L'analyse statique (IDA, Ghidra) révèle les patterns XOR simples. Les sandbox (Any.Run, Joe Sandbox) déchiffrent à l'exécution. YARA peut matcher les séquences XOR connues. |
| Impair Defenses: Disable or Modify Tools | T1562.001 | `syscall.rs` — patch AMSI (`AmsiScanBuffer`) | Surveiller les écritures mémoire dans `amsi.dll` via ETW (`Microsoft-Antimalware-Scan-Interface`). Les EDR modernes détectent le patch de `AmsiScanBuffer` via l'intégrité des pages mémoire. |
| Indicator Removal: Clear Windows Event Logs | T1070.001 | `logroll.rs` — suppression sélective d'événements | Centraliser les logs vers un SIEM (Splunk, ELK) avant qu'ils puissent être supprimés localement. Surveiller les EventID 1102 (Audit Log Cleared) et 104 (System Log Cleared). |
| Masquerading | T1036 | En-tête `Server: Microsoft-IIS/10.0`, noms discrets | Vérifier la cohérence des en-têtes HTTP avec l'infrastructure réelle. Un IIS qui répond sur un port non standard avec des endpoints `/api/v1/*` est suspect. |
| Virtualization/Sandbox Evasion | T1497 | `detect.rs` — vérification debugger, uptime, MAC VM | Les sandbox modernes masquent les artefacts VM (MAC, processus, uptime). Exécuter les échantillons suspects dans des sandbox avec anti-évasion (Cuckoo avec `anti-anti-vm`). |
| Direct System Calls | T1106 | `syscall.rs` — extraction SSN + invocation directe | Les syscall directs contournent les hooks ntdll classiques. Détectable via ETW kernel-level ou par instrumentation du hyperviseur. Vérifier les call stacks anormales (syscall depuis une région non-ntdll). |
| Process Injection: Reflective DLL Loading | T1055.001 | `pe_loader.rs` | Surveiller les allocations mémoire exécutables sans fichier disque associé. Les EDR détectent les threads démarrés dans des régions mémoire non mappées (unbacked memory). |

## Credential Access

| Technique | ID | Implémentation | Note blue team |
|-----------|-----|----------------|----------------|
| OS Credential Dumping: LSASS Memory | T1003.001 | `creds.rs` — MiniDumpWriteDump | Activer Credential Guard et PPL (Protected Process Light) pour LSASS. Surveiller les accès en lecture à `lsass.exe` via Sysmon EventID 10 (ProcessAccess). |
| OS Credential Dumping: Security Account Manager | T1003.002 | `creds.rs` — `reg save` SAM/SYSTEM | Surveiller les commandes `reg save` sur les ruches SAM et SYSTEM (EventID 4688). Restreindre les privilèges `SeBackupPrivilege`. |
| Brute Force: Password Cracking | T1110.002 | `crack.rs` — NTLM (MD4) + MD5 dictionnaire | Imposer des mots de passe longs (>14 caractères) pour résister au cassage. Désactiver le stockage LM hash via GPO. |
| Use Alternate Authentication Material: Pass the Hash | T1550.002 | `pth.rs` — NTLMv2 from-scratch | Désactiver NTLMv1, imposer NTLMv2. Activer « Restricted Admin Mode » pour RDP. Surveiller les EventID 4624 (Logon Type 9 — NewCredentials). |
| Input Capture: Keylogging | T1056.001 | `keylog.rs` — `WH_KEYBOARD_LL` | Surveiller les appels à `SetWindowsHookEx` via Sysmon EventID 12 ou les solutions EDR. Les hooks globaux clavier sont rares dans les applications légitimes. |

## Discovery

| Technique | ID | Implémentation | Note blue team |
|-----------|-----|----------------|----------------|
| System Information Discovery | T1082 | `hostinfo.rs`, `whatever.rs` | La collecte d'info système est légitime, mais un volume anormal d'appels `whoami`, `ipconfig`, `net user` en séquence est suspect (EventID 4688). |
| Process Discovery | T1057 | `shell_builtin.rs` — `CreateToolhelp32Snapshot` | L'API `CreateToolhelp32Snapshot` est légitime mais son appel fréquent depuis un processus non système est un indicateur. Corréler avec l'activité réseau du processus. |
| File and Directory Discovery | T1083 | `shell_builtin.rs` — `ls`, `loot.rs` — inventaire | Surveiller l'accès à des répertoires sensibles (`.ssh`, navigateurs, coffres-forts de mots de passe) depuis des processus inhabituels. |
| Remote System Discovery | T1018 | `propagate.rs` — scan TCP /24 | Détecter les scans de ports via l'analyse du trafic réseau (tentatives de connexion rapides vers de nombreuses IP). Les IDS/IPS (Snort, Suricata) détectent les patterns de scan. |
| Software Discovery: Security Software | T1518.001 | `detect.rs` — processus suspects, `avscan.rs` | La recherche de processus de sécurité est un indicateur fort de comportement malveillant. Alerter quand un processus non signé énumère les processus AV/EDR. |
| System Network Configuration Discovery | T1016 | `hostinfo.rs` — `primary_ip()` | L'accès à la configuration réseau est légitime. Corréler avec d'autres activités de reconnaissance pour identifier un pattern d'attaque. |

## Lateral Movement

| Technique | ID | Implémentation | Note blue team |
|-----------|-----|----------------|----------------|
| Remote Services: SMB/Windows Admin Shares | T1021.002 | `propagate.rs` — copie via `C$` | Restreindre l'accès aux partages administratifs (`C$`, `ADMIN$`). Surveiller les connexions SMB vers des partages admin (EventID 5140/5145). Désactiver les partages admin si non nécessaires. |
| Remote Services: Windows Remote Management | T1021.006 | `propagate.rs` — `Invoke-Command` WinRM | Restreindre WinRM aux hôtes de gestion via GPO. Surveiller les connexions WinRM (EventID 6 dans Microsoft-Windows-WinRM/Operational). |
| Lateral Tool Transfer | T1570 | `propagate.rs` — déploiement binaire | Surveiller les créations de fichiers exécutables sur les partages réseau. Alerter sur les binaires non signés copiés via SMB. |

## Collection

| Technique | ID | Implémentation | Note blue team |
|-----------|-----|----------------|----------------|
| Screen Capture | T1113 | `screenshot.rs` — GDI `BitBlt` | L'appel fréquent à `BitBlt` sur le DC écran depuis un processus non graphique est suspect. Surveiller via ETW ou les solutions EDR. |
| Data from Local System | T1005 | `loot.rs`, `transfer.rs` — download | Surveiller l'accès en lecture aux fichiers sensibles (clés SSH, bases KeePass, profils navigateurs) depuis des processus inhabituels (Sysmon EventID 11). |
| Input Capture: Keylogging | T1056.001 | `keylog.rs` | Voir la section Credential Access ci-dessus. |

## Command and Control

| Technique | ID | Implémentation | Note blue team |
|-----------|-----|----------------|----------------|
| Encrypted Channel: Asymmetric Cryptography | T1573.002 | RSA-OAEP-SHA256 (échange de clé) | Inspecter le trafic TLS avec un proxy d'interception (le cert pinning le bloque, mais un déploiement de CA d'entreprise sur les postes permet l'inspection). |
| Encrypted Channel: Symmetric Cryptography | T1573.001 | AES-256-GCM (toutes les frames) | Analyser les patterns de trafic (taille, fréquence, timing) même sans déchiffrer. Le beaconing régulier est détectable par analyse statistique (JA3/JA4 fingerprinting). |
| Application Layer Protocol: Web Protocols | T1071.001 | HTTPS, cert pinning | Surveiller les connexions HTTPS vers des IP sans résolution DNS, avec des certificats autosignés, ou vers des domaines récemment enregistrés. |
| Data Encoding: Standard Encoding | T1132.001 | Base64 pour les payloads | L'encodage base64 dans le corps HTTP est détectable par analyse de contenu. Les proxies applicatifs peuvent inspecter les payloads base64. |

## Exfiltration

| Technique | ID | Implémentation | Note blue team |
|-----------|-----|----------------|----------------|
| Exfiltration Over C2 Channel | T1041 | `transfer.rs` — download en base64 via le canal C2 | Surveiller les volumes de données anormaux en sortie (DLP). Alerter sur les requêtes POST avec un corps volumineux vers des destinations inhabituelles. |

## Lateral Movement (complément)

| Technique | ID | Implémentation | Note blue team |
|-----------|-----|----------------|----------------|
| Remote Services: Remote Desktop Protocol | T1021.001 | `rdp.rs` — activation RDP + règle firewall | Surveiller les modifications de `fDenyTSConnections` dans le registre (Sysmon EventID 13). Alerter sur les règles firewall ajoutées via `netsh`. Restreindre RDP aux seuls postes autorisés via GPO. |
