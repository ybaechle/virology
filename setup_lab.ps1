# setup_lab.ps1 - Configuration du lab C2 (à lancer une seule fois sur l'hôte Windows)
# Exécuter en tant qu'Administrateur

param(
    [string]$WslIp    = "127.0.0.1",
    [string]$ListenIp = "10.0.0.1",
    [int]$Port        = 7443
)

Write-Host "[*] Configuration portproxy $ListenIp`:$Port -> $WslIp`:$Port"
netsh interface portproxy add v4tov4 `
    listenport=$Port listenaddress=$ListenIp `
    connectport=$Port connectaddress=$WslIp

Write-Host "[*] Règle pare-feu entrante port $Port"
$existing = Get-NetFirewallRule -DisplayName "C2-Lab-$Port" -ErrorAction SilentlyContinue
if ($existing) { Remove-NetFirewallRule -DisplayName "C2-Lab-$Port" }
New-NetFirewallRule -DisplayName "C2-Lab-$Port" `
    -Direction Inbound -Protocol TCP -LocalPort $Port -Action Allow | Out-Null

Write-Host "[*] Vérification :"
netsh interface portproxy show all
Write-Host "[+] Lab prêt. Lance le controller Linux, puis la démo."
