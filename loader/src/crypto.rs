use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};

// Format du payload : nonce(12 bytes) || ciphertext
pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, ()> {
    if data.len() < 12 {
        return Err(());
    }
    let nonce = Nonce::from_slice(&data[..12]);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher.decrypt(nonce, &data[12..]).map_err(|_| ())
}
