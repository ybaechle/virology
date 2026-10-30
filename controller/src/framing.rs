// Trame : [16 id][12 nonce][AES-256-GCM ciphertext+tag]
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use anyhow::{bail, Result};
use rand::RngCore;

const ID_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const HEADER: usize = ID_LEN + NONCE_LEN;

pub fn read_id(blob: &[u8]) -> Result<[u8; ID_LEN]> {
    if blob.len() < ID_LEN {
        bail!("trame trop courte");
    }
    Ok(blob[..ID_LEN].try_into().unwrap())
}

pub fn pack(id: &[u8; ID_LEN], session_key: &[u8; 32], plaintext: &[u8]) -> Vec<u8> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .expect("chiffrement AES-GCM");

    let mut frame = Vec::with_capacity(HEADER + ciphertext.len());
    frame.extend_from_slice(id);
    frame.extend_from_slice(&nonce_bytes);
    frame.extend_from_slice(&ciphertext);
    frame
}

pub fn unpack(blob: &[u8], session_key: &[u8; 32]) -> Result<([u8; ID_LEN], Vec<u8>)> {
    if blob.len() <= HEADER {
        bail!("trame trop courte");
    }
    let id: [u8; ID_LEN] = blob[..ID_LEN].try_into().unwrap();
    let nonce = &blob[ID_LEN..HEADER];
    let ciphertext = &blob[HEADER..];

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(session_key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow::anyhow!("déchiffrement AES-GCM échoué (tag invalide)"))?;

    Ok((id, plaintext))
}

pub fn id_hex(id: &[u8; ID_LEN]) -> String {
    hex::encode(id)
}

pub fn id_from_hex(s: &str) -> Result<[u8; ID_LEN]> {
    let bytes = hex::decode(s).map_err(|e| anyhow::anyhow!("identifiant invalide : {}", e))?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("identifiant invalide (longueur ≠ 16)"))
}
