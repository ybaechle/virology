# setup_attacker.ps1 — Configure l'hôte Windows pour recevoir les connexions C2.
# À lancer une seule fois en Administrateur sur la machine de l'attaquant.
# Pré-requis : WSL2 en mode miroir réseau (networkingMode=mirrored dans .wslconfig).

param(
    [string]$C2Port = "8443",
    [string]$AllowedSubnet = "10.0.0.0/24"
)

Write-Host "[*] Vérification du mode réseau WSL2..." -ForegroundColor Cyan
$wslconfig = "$env:USERPROFILE\.wslconfig"
if (Test-Path $wslconfig) {
    $content = Get-Content $wslconfig -Raw
    if ($content -match "networkingMode\s*=\s*mirrored") {
        Write-Host "  [ok] WSL2 en mode miroir — aucun portproxy nécessaire"
    } else {
        Write-Host "  [!] WSL2 PAS en mode miroir — ajouter networkingMode=mirrored dans $wslconfig" -ForegroundColor Yellow
    }
} else {
    Write-Host "  [!] .wslconfig introuvable — créer $wslconfig avec networkingMode=mirrored" -ForegroundColor Yellow
}

Write-Host "[*] Ajout règle firewall entrante TCP $C2Port (depuis $AllowedSubnet)..." -ForegroundColor Cyan
netsh advfirewall firewall delete rule name="s0P0wn3d-C2-$C2Port" 2>$null
netsh advfirewall firewall add rule `
    name="s0P0wn3d-C2-$C2Port" `
    dir=in `
    action=allow `
    protocol=TCP `
    localport=$C2Port `
    remoteip=$AllowedSubnet `
    profile=any

if ($LASTEXITCODE -eq 0) {
    Write-Host "  [ok] Règle firewall ajoutée : TCP $C2Port ← $AllowedSubnet" -ForegroundColor Green
} else {
    Write-Host "  [ko] Échec ajout règle firewall" -ForegroundColor Red
}

Write-Host ""
Write-Host "=== Résumé ===" -ForegroundColor Green
Write-Host "Controller C2 URL : https://10.0.0.1:$C2Port"
Write-Host "La VM (10.0.0.x) peut joindre le controller WSL2 directement."
Write-Host "Aucune action requise côté VM — l'implant se connecte seul."
