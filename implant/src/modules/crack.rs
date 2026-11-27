// Cassage de hash hors ligne : MD4/NTLM et MD5 par dictionnaire.
// Aucun outil externe requis : implémenté en Rust pur.
use md5::{Digest, Md5};

pub fn run(args: &str) -> String {
    let mut parts = args.splitn(3, ' ');
    let hash_type = parts.next().unwrap_or("").trim();
    let hash_hex  = parts.next().unwrap_or("").trim();
    let wordlist  = parts.next().unwrap_or("").trim();

    if hash_type.is_empty() || hash_hex.is_empty() {
        return "usage: crack <ntlm|md5> <hash_hex> [chemin_wordlist]".to_string();
    }

    let words: Box<dyn Iterator<Item = String>> = if wordlist.is_empty() {
        Box::new(COMMON_PASSWORDS.iter().map(|s| s.to_string()))
    } else {
        match std::fs::read_to_string(wordlist) {
            Ok(content) => Box::new(content.lines().map(|l| l.to_string()).collect::<Vec<_>>().into_iter()),
            Err(e) => return format!("[erreur] lecture wordlist : {}", e),
        }
    };

    for word in words {
        let candidate = match hash_type {
            "ntlm" => ntlm_hash(word.trim()),
            "md5"  => md5_hash(word.trim()),
            other  => return format!("type de hash inconnu : {}", other),
        };
        if candidate.eq_ignore_ascii_case(hash_hex) {
            return format!("[+] trouvé : {}", word.trim());
        }
    }
    "[-] non trouvé dans la wordlist".to_string()
}

fn ntlm_hash(password: &str) -> String {
    // NTLM = MD4(UTF-16LE(password))
    let utf16: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();
    hex::encode(md4(&utf16))
}

fn md5_hash(password: &str) -> String {
    hex::encode(Md5::digest(password.as_bytes()))
}

/// MD4 implémenté en Rust pur (NTLM en a besoin).
fn md4(input: &[u8]) -> [u8; 16] {
    // RFC 1320
    let mut message = input.to_vec();
    let orig_len_bits = (input.len() as u64) * 8;
    message.push(0x80);
    while message.len() % 64 != 56 {
        message.push(0x00);
    }
    message.extend_from_slice(&orig_len_bits.to_le_bytes());

    let mut a: u32 = 0x6745_2301;
    let mut b: u32 = 0xEFCD_AB89;
    let mut c: u32 = 0x98BA_DCFE;
    let mut d: u32 = 0x1032_5476;

    for chunk in message.chunks_exact(64) {
        let x: Vec<u32> = chunk
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect();

        let (aa, bb, cc, dd) = (a, b, c, d);

        macro_rules! r1 { ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
            $a = ($a.wrapping_add(($b & $c) | (!$b & $d)).wrapping_add(x[$k])).rotate_left($s);
        }}
        macro_rules! r2 { ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
            $a = ($a.wrapping_add(($b & $c) | ($b & $d) | ($c & $d)).wrapping_add(x[$k]).wrapping_add(0x5A82_7999)).rotate_left($s);
        }}
        macro_rules! r3 { ($a:expr,$b:expr,$c:expr,$d:expr,$k:expr,$s:expr) => {
            $a = ($a.wrapping_add($b ^ $c ^ $d).wrapping_add(x[$k]).wrapping_add(0x6ED9_EBA1)).rotate_left($s);
        }}

        r1!(a,b,c,d,0,3); r1!(d,a,b,c,1,7); r1!(c,d,a,b,2,11); r1!(b,c,d,a,3,19);
        r1!(a,b,c,d,4,3); r1!(d,a,b,c,5,7); r1!(c,d,a,b,6,11); r1!(b,c,d,a,7,19);
        r1!(a,b,c,d,8,3); r1!(d,a,b,c,9,7); r1!(c,d,a,b,10,11); r1!(b,c,d,a,11,19);
        r1!(a,b,c,d,12,3); r1!(d,a,b,c,13,7); r1!(c,d,a,b,14,11); r1!(b,c,d,a,15,19);
        r2!(a,b,c,d,0,3); r2!(d,a,b,c,4,5); r2!(c,d,a,b,8,9); r2!(b,c,d,a,12,13);
        r2!(a,b,c,d,1,3); r2!(d,a,b,c,5,5); r2!(c,d,a,b,9,9); r2!(b,c,d,a,13,13);
        r2!(a,b,c,d,2,3); r2!(d,a,b,c,6,5); r2!(c,d,a,b,10,9); r2!(b,c,d,a,14,13);
        r2!(a,b,c,d,3,3); r2!(d,a,b,c,7,5); r2!(c,d,a,b,11,9); r2!(b,c,d,a,15,13);
        r3!(a,b,c,d,0,3); r3!(d,a,b,c,8,9); r3!(c,d,a,b,4,11); r3!(b,c,d,a,12,15);
        r3!(a,b,c,d,2,3); r3!(d,a,b,c,10,9); r3!(c,d,a,b,6,11); r3!(b,c,d,a,14,15);
        r3!(a,b,c,d,1,3); r3!(d,a,b,c,9,9); r3!(c,d,a,b,5,11); r3!(b,c,d,a,13,15);
        r3!(a,b,c,d,3,3); r3!(d,a,b,c,11,9); r3!(c,d,a,b,7,11); r3!(b,c,d,a,15,15);

        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }

    let mut out = [0u8; 16];
    out[..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..].copy_from_slice(&d.to_le_bytes());
    out
}

static COMMON_PASSWORDS: &[&str] = &[
    "password", "123456", "Password1", "qwerty", "letmein",
    "admin", "welcome", "monkey", "dragon", "1234567890",
    "password123", "P@ssw0rd", "azerty", "motdepasse",
];
