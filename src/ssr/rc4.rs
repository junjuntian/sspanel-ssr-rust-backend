//! `rc4-md5` stream cipher.
//!
//! Shadowsocks(R)'s `rc4-md5` is not plain RC4: the per-connection RC4 key is
//! `MD5(master_key || iv)`, where `master_key = EVP_BytesToKey(password, 16)` and
//! `iv` is a fresh random 16-byte value sent in the clear at the start of each
//! direction's stream. RC4 keystream is continuous for the life of the
//! connection, so each half (send / recv) keeps its own running state.

use crate::ssr::kdf::md5;

/// Plain RC4 keystream generator (RFC-less, the classic KSA + PRGA).
struct Rc4 {
    s: [u8; 256],
    i: u8,
    j: u8,
}

impl Rc4 {
    fn new(key: &[u8]) -> Self {
        let mut s = [0_u8; 256];
        for (idx, b) in s.iter_mut().enumerate() {
            *b = idx as u8;
        }
        let mut j: u8 = 0;
        for i in 0..256 {
            j = j
                .wrapping_add(s[i])
                .wrapping_add(key[i % key.len()]);
            s.swap(i, j as usize);
        }
        Self { s, i: 0, j: 0 }
    }

    /// XOR `data` in place with the next keystream bytes, advancing state.
    fn apply(&mut self, data: &mut [u8]) {
        for byte in data.iter_mut() {
            self.i = self.i.wrapping_add(1);
            self.j = self.j.wrapping_add(self.s[self.i as usize]);
            self.s.swap(self.i as usize, self.j as usize);
            let k = self.s[(self.s[self.i as usize].wrapping_add(self.s[self.j as usize])) as usize];
            *byte ^= k;
        }
    }
}

pub const IV_LEN: usize = 16;
pub const KEY_LEN: usize = 16;

/// One direction of an `rc4-md5` stream.
pub struct Rc4Md5 {
    rc4: Rc4,
}

impl Rc4Md5 {
    /// Build a cipher half from the connection master key and this direction's IV.
    pub fn new(master_key: &[u8], iv: &[u8]) -> Self {
        let mut seed = Vec::with_capacity(master_key.len() + iv.len());
        seed.extend_from_slice(master_key);
        seed.extend_from_slice(iv);
        let rc4_key = md5(&seed);
        Self {
            rc4: Rc4::new(&rc4_key),
        }
    }

    /// RC4 is symmetric: the same operation encrypts and decrypts.
    pub fn process(&mut self, data: &mut [u8]) {
        self.rc4.apply(data);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc4_known_answer() {
        // RFC 6229 / classic test vector: key "Key", plaintext "Plaintext".
        let mut rc4 = Rc4::new(b"Key");
        let mut data = b"Plaintext".to_vec();
        rc4.apply(&mut data);
        assert_eq!(hex::encode(&data), "bbf316e8d940af0ad3");
    }

    #[test]
    fn rc4_wikipedia_vector() {
        let mut rc4 = Rc4::new(b"Wiki");
        let mut data = b"pedia".to_vec();
        rc4.apply(&mut data);
        assert_eq!(hex::encode(&data), "1021bf0420");
    }

    #[test]
    fn rc4md5_roundtrip() {
        let master = crate::ssr::kdf::evp_bytes_to_key(b"secret", KEY_LEN);
        let iv = [7_u8; IV_LEN];
        let mut enc = Rc4Md5::new(&master, &iv);
        let mut dec = Rc4Md5::new(&master, &iv);
        let original = b"the quick brown fox jumps over the lazy dog".to_vec();
        let mut buf = original.clone();
        enc.process(&mut buf);
        assert_ne!(buf, original);
        dec.process(&mut buf);
        assert_eq!(buf, original);
    }
}
