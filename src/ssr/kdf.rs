//! Key-derivation and MAC helpers shared by the SSR cipher and protocol layers.

use hmac::{Hmac, Mac};
use md5::{Digest, Md5};

type HmacMd5 = Hmac<Md5>;

/// OpenSSL's `EVP_BytesToKey` with MD5 and no salt / single iteration, exactly as
/// Shadowsocks(R) uses it to turn a UTF-8 password into a symmetric key.
///
/// `m[0] = MD5(password)`, `m[i] = MD5(m[i-1] || password)`, concatenated and
/// truncated to `key_len`.
pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&prev);
        hasher.update(password);
        prev = hasher.finalize().to_vec();
        key.extend_from_slice(&prev);
    }
    key.truncate(key_len);
    key
}

/// `MD5(data)` as a 16-byte array.
pub fn md5(data: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// First `n` bytes of `HMAC-MD5(key, data)`. SSR truncates these MACs to 2, 4 or
/// 6 bytes depending on the field.
pub fn hmac_md5_prefix(key: &[u8], data: &[u8], n: usize) -> Vec<u8> {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    full[..n].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evp_matches_known_vector() {
        // EVP_BytesToKey("password", md5, 16) — the canonical Shadowsocks key for
        // password "password". Verified against `openssl`'s KDF.
        let key = evp_bytes_to_key(b"password", 16);
        assert_eq!(
            hex::encode(key),
            "5f4dcc3b5aa765d61d8327deb882cf99"
        );
    }

    #[test]
    fn evp_extends_past_one_block() {
        // 32-byte key requires two MD5 rounds; first 16 bytes must equal the
        // 16-byte derivation (KDF is prefix-stable).
        let k16 = evp_bytes_to_key(b"hunter2", 16);
        let k32 = evp_bytes_to_key(b"hunter2", 32);
        assert_eq!(&k32[..16], &k16[..]);
        assert_eq!(k32.len(), 32);
    }

    #[test]
    fn md5_of_empty() {
        assert_eq!(hex::encode(md5(b"")), "d41d8cd98f00b204e9800998ecf8427e");
    }
}
