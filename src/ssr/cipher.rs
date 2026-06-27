//! Stream-cipher selection for the SSR data plane.
//!
//! The node currently supports two `method`s, chosen at runtime from the carrier
//! port's `method` field (see [`crate::ssr::Profile`]):
//!
//! * `rc4-md5`        — 16-byte key, 16-byte IV, per-direction RC4 keyed by
//!                      `MD5(master_key || iv)`.
//! * `chacha20-ietf`  — 32-byte key, 12-byte nonce (IETF/RFC 8439), continuous
//!                      keystream. The master key *is* the cipher key and the IV
//!                      *is* the nonce, no extra mixing.
//!
//! The `auth_aes128_md5` protocol layer above this is cipher-agnostic — it only
//! needs the master key and this direction's IV at their correct lengths — so
//! adding a cipher is purely a matter of key/IV length plus keystream wiring.

use anyhow::{anyhow, Result};
use chacha20::cipher::{KeyIvInit, StreamCipher as _};
use chacha20::ChaCha20;

use crate::ssr::rc4::Rc4Md5;

/// Which stream cipher a connection uses. Cheap `Copy`; derived from the carrier
/// port `method` once per listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    Rc4Md5,
    Chacha20Ietf,
}

impl CipherKind {
    /// Map an SSR `method` string to a cipher. Only the two supported methods
    /// resolve; anything else is rejected rather than silently mishandled.
    pub fn from_method(method: &str) -> Result<Self> {
        match method.to_ascii_lowercase().as_str() {
            "rc4-md5" => Ok(Self::Rc4Md5),
            "chacha20-ietf" => Ok(Self::Chacha20Ietf),
            other => Err(anyhow!(
                "unsupported cipher method {other}; only rc4-md5 and chacha20-ietf are supported"
            )),
        }
    }

    /// `EVP_BytesToKey` output length for the master key.
    pub fn key_len(self) -> usize {
        match self {
            Self::Rc4Md5 => 16,
            Self::Chacha20Ietf => 32,
        }
    }

    /// Per-direction IV / nonce length sent in the clear at stream start.
    pub fn iv_len(self) -> usize {
        match self {
            Self::Rc4Md5 => 16,
            Self::Chacha20Ietf => 12,
        }
    }

    /// Instantiate one direction of the stream from the master key and this
    /// direction's IV. Lengths are guaranteed by construction (callers size IVs
    /// via [`CipherKind::iv_len`]), so the chacha key/nonce slice fit is infallible.
    pub fn new_stream(self, master_key: &[u8], iv: &[u8]) -> StreamCipher {
        match self {
            Self::Rc4Md5 => StreamCipher::Rc4(Rc4Md5::new(master_key, iv)),
            Self::Chacha20Ietf => {
                let cipher = ChaCha20::new_from_slices(master_key, iv)
                    .expect("chacha20-ietf key=32/nonce=12 lengths are enforced by CipherKind");
                StreamCipher::Chacha20(Box::new(cipher))
            }
        }
    }
}

/// One direction of a connection's stream cipher. `process` is symmetric for
/// both variants (XOR keystream), so the same call encrypts and decrypts.
pub enum StreamCipher {
    Rc4(Rc4Md5),
    Chacha20(Box<ChaCha20>),
}

impl StreamCipher {
    /// XOR `data` in place with the next keystream bytes, advancing state.
    pub fn process(&mut self, data: &mut [u8]) {
        match self {
            StreamCipher::Rc4(c) => c.process(data),
            StreamCipher::Chacha20(c) => c.apply_keystream(data),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_mapping_and_lengths() {
        let rc4 = CipherKind::from_method("rc4-md5").unwrap();
        assert_eq!((rc4.key_len(), rc4.iv_len()), (16, 16));
        let cc = CipherKind::from_method("CHACHA20-IETF").unwrap();
        assert_eq!((cc.key_len(), cc.iv_len()), (32, 12));
        assert!(CipherKind::from_method("aes-256-gcm").is_err());
    }

    #[test]
    fn chacha20_roundtrip_and_keystream() {
        let kind = CipherKind::Chacha20Ietf;
        let key = crate::ssr::kdf::evp_bytes_to_key(b"secret", kind.key_len());
        let iv = [7_u8; 12];
        let original = b"the quick brown fox jumps over the lazy dog".to_vec();
        let mut buf = original.clone();
        kind.new_stream(&key, &iv).process(&mut buf);
        assert_ne!(buf, original);
        // Fresh cipher with same key/iv decrypts (symmetric XOR keystream).
        kind.new_stream(&key, &iv).process(&mut buf);
        assert_eq!(buf, original);
    }
}
