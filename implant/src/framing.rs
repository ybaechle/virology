// Trame : [16 id][12 nonce][AES-256-GCM ciphertext+tag]
use anyhow::{bail, Result};
use rand::RngCore;

use crate::crypto::{SessionKey, NONCE_LEN};

const ID_LEN: usize = 16;
const HEADER: usize = ID_LEN + NONCE_LEN;

pub fn pack(id: &[u8; ID_LEN], session: &SessionKey, plaintext: &[u8]) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);

    let ciphertext = session.seal(&nonce, plaintext);
    let mut frame = Vec::with_capacity(HEADER + ciphertext.len());
    frame.extend_from_slice(id);
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&ciphertext);
    frame
}

pub fn unpack(blob: &[u8], session: &SessionKey) -> Result<Vec<u8>> {
    if blob.len() <= HEADER {
        bail!("trame trop courte");
    }
    let nonce: &[u8; NONCE_LEN] = blob[ID_LEN..HEADER].try_into().unwrap();
    session.open(nonce, &blob[HEADER..])
}
