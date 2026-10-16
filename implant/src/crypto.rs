// AES-256-GCM pour les trames, RSA-OAEP-SHA256 pour l'échange de clé de session.
use anyhow::{Context, Result};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::RngCore;
use rsa::{Oaep, RsaPublicKey};
use rsa::pkcs8::DecodePublicKey;
use sha2::Sha256;

pub const SESSION_KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 12;

pub struct SessionKey([u8; SESSION_KEY_LEN]);

impl SessionKey {
    pub fn generate() -> Self {
        let mut key = [0u8; SESSION_KEY_LEN];
        rand::rngs::OsRng.fill_bytes(&mut key);
        Self(key)
    }

    pub fn seal(&self, nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Vec<u8> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
        cipher
            .encrypt(Nonce::from_slice(nonce), plaintext)
            .expect("chiffrement AES-GCM")
    }

    pub fn open(&self, nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&self.0));
        cipher
            .decrypt(Nonce::from_slice(nonce), ciphertext)
            .map_err(|_| anyhow::anyhow!("déchiffrement AES-GCM échoué"))
    }
}

/// Chiffrement RSA-OAEP-SHA256 de la clé de session avec la clé publique du controller.
pub fn wrap_session_key(public_pem: &str, session: &SessionKey) -> Result<Vec<u8>> {
    let public: RsaPublicKey = RsaPublicKey::from_public_key_pem(public_pem)
        .context("clé publique invalide")?;
    public
        .encrypt(&mut rand::rngs::OsRng, Oaep::new::<Sha256>(), &session.0)
        .context("chiffrement RSA-OAEP")
}

/// Identifiant stable de l'implant : MD5(hôte:utilisateur en minuscules).
pub fn implant_id(hostname: &str, username: &str) -> [u8; 16] {
    use md5::{Digest, Md5};
    let input = format!("{}:{}", hostname.to_lowercase(), username.to_lowercase());
    Md5::digest(input.as_bytes()).into()
}

