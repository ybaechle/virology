# cleanup_host.ps1 — Supprime toutes les traces réseau du labo sur l'hôte Windows.
# Lancer en tant qu'Administrateur.

Write-Host "[*] Nettoyage des règles portproxy..." -ForegroundColor Cyan
netsh interface portproxy reset

Write-Host "[*] Suppression des règles firewall du labo..." -ForegroundColor Cyan
$rules = @("Demo C2 8443", "C2-WSL2-7443", "C2-WSL2-4443", "s0p0wn3d")
foreach ($r in $rules) {
    $res = netsh advfirewall firewall delete rule name="$r" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  [ok] règle supprimée : $r"
    }
}

Write-Host "[*] Nettoyage des binaires implant dans Public..." -ForegroundColor Cyan
Remove-Item -Force -ErrorAction SilentlyContinue "C:\Users\Public\implant*.exe"
Remove-Item -Force -ErrorAction SilentlyContinue "C:\Users\Public\implant*.ps1"

Write-Host "[ok] Nettoyage terminé." -ForegroundColor Green
Write-Host ""
Write-Host "État portproxy :"
netsh interface portproxy show all
Write-Host ""
Write-Host "Règles firewall s0p0wn3d restantes :"
netsh advfirewall firewall show rule name=all | Select-String -Pattern "C2|7443|4443|8443|s0p0wn3d"
