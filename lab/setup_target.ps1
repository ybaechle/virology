# setup_target.ps1 — Prépare la VM cible pour le labo s0P0wn3d (Rust).
# Lancer une seule fois en Administrateur avant le snapshot « clean-target ».
# La VM n'a besoin d'aucune configuration réseau : l'implant se connecte seul.

$ErrorActionPreference = 'Stop'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Le script doit être exécuté en administrateur.'
}

# Compte de test stable (repris dans MANIFEST.md)
if (-not (Get-LocalUser -Name 'svc_backup' -ErrorAction SilentlyContinue)) {
    $pwd = ConvertTo-SecureString 'P@ssw0rd2024!' -AsPlainText -Force
    New-LocalUser -Name 'svc_backup' -Password $pwd -PasswordNeverExpires `
        -Description 'Compte de test s0P0wn3d'
    Add-LocalGroupMember -Group 'Utilisateurs du Bureau à distance' `
        -Member 'svc_backup' -ErrorAction SilentlyContinue
    Write-Host '[ok] Compte svc_backup créé'
}

# Journalisation des lignes de commande (utile blue team)
$auditKey = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $auditKey -Force | Out-Null
Set-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' -Value 1 -Type DWord

# TLS 1.2 activé (nécessaire pour le beacon HTTPS)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Write-Host ''
Write-Host '=== Prêt ===' -ForegroundColor Green
Write-Host "Prenez le snapshot « clean-target » avant tout déploiement de l'implant."
Write-Host "Vecteur d'infection : copier implant.exe dans C:\Users\Public\ et l'exécuter."
Write-Host "Aucune configuration réseau requise — l'implant joint 10.0.0.1:8443 directement."
