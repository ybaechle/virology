use anyhow::{Context, Result};
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, EncodePublicKey};
use sha2::Sha256;

pub fn load_private(pem: &[u8]) -> Result<RsaPrivateKey> {
    let s = std::str::from_utf8(pem).context("clé privée : UTF-8 invalide")?;
    RsaPrivateKey::from_pkcs8_pem(s).context("clé privée PKCS#8 invalide")
}

pub fn serialize_public(key: &RsaPublicKey) -> Result<Vec<u8>> {
    key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .context("sérialisation clé publique")
        .map(|s| s.into_bytes())
}

pub fn unwrap_session_key(private: &RsaPrivateKey, b64: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let cipher = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("décodage base64 de la clé de session")?;
    let plain = private
        .decrypt(Oaep::new::<Sha256>(), &cipher)
        .context("déchiffrement RSA-OAEP de la clé de session")?;
    plain
        .try_into()
        .map_err(|_| anyhow::anyhow!("longueur de clé de session invalide (attendu 32 octets)"))
}
