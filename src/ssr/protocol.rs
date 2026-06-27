//! `auth_aes128_md5` protocol layer (server side).
//!
//! Ported byte-for-byte from shadowsocksr's `obfsplugin/auth.py`
//! (`auth_aes128_sha1` with `hashfunc = md5`). We only implement the server
//! receive (`server_post_decrypt`) and send (`server_pre_encrypt`) paths, and
//! for both ordinary port-per-user servers and SSPanel's protocol-style
//! single-port multi-user mode (`is_multi_user = 2`). In multi-user mode the
//! auth header carries a uid, and `user_key` is MD5(real user's password).
//!
//! We also drop two pieces of the reference that only obscure traffic shape or
//! defend a shared-port server, neither of which affects interop with a real
//! SSR client:
//!   * outbound random padding is fixed at the minimal 1 byte (`0x01`);
//!   * replay dedup (`client_queue`) and the timestamp window are not enforced.

use std::{collections::HashMap, sync::Arc};

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;

use crate::ssr::kdf::{evp_bytes_to_key, hmac_md5_prefix, md5};

const SALT: &[u8] = b"auth_aes128_md5";
const UNIT_LEN: usize = 8100;
const MAX_PACKET: usize = 8192;

pub struct AuthAes128Md5 {
    master_key: Vec<u8>,
    user_key: Vec<u8>,
    users: Arc<HashMap<u64, Vec<u8>>>,
    is_multi_user: i64,
    user_id: Option<u64>,
    /// AES key for the auth header block: `EVP_BytesToKey(base64(user_key)+salt, 16)`.
    aes_key: [u8; 16],
    /// `mac_key` prefix for the auth header = `recv_iv || master_key`.
    recv_iv: Vec<u8>,
    recv_buf: Vec<u8>,
    has_recv_header: bool,
    recv_id: u32,
    pack_id: u32,
}

impl AuthAes128Md5 {
    pub fn new(
        master_key: Vec<u8>,
        recv_iv: Vec<u8>,
        users: Arc<HashMap<u64, Vec<u8>>>,
        is_multi_user: i64,
    ) -> Self {
        let user_key = master_key.clone();
        let mut aes_seed = STANDARD.encode(&user_key).into_bytes();
        aes_seed.extend_from_slice(SALT);
        let aes_key_vec = evp_bytes_to_key(&aes_seed, 16);
        let mut aes_key = [0_u8; 16];
        aes_key.copy_from_slice(&aes_key_vec);
        Self {
            master_key,
            user_key,
            users,
            is_multi_user,
            user_id: None,
            aes_key,
            recv_iv,
            recv_buf: Vec::new(),
            has_recv_header: false,
            recv_id: 1,
            pack_id: 1,
        }
    }

    /// Decrypt cipher-plaintext (already past the rc4 layer) into application
    /// payload. May return empty if more bytes are needed to complete a packet.
    pub fn server_post_decrypt(&mut self, incoming: &[u8]) -> Result<Vec<u8>> {
        self.recv_buf.extend_from_slice(incoming);
        let mut out = Vec::new();

        if !self.has_recv_header {
            // Need the full 31-byte auth header before we can do anything.
            let mac_key = {
                let mut k = self.recv_iv.clone();
                k.extend_from_slice(&self.master_key);
                k
            };

            if self.recv_buf.len() >= 7 {
                let chk = hmac_md5_prefix(&mac_key, &self.recv_buf[..1], 6);
                if chk != self.recv_buf[1..7] {
                    bail!("auth_aes128_md5: check_head HMAC mismatch");
                }
            }
            if self.recv_buf.len() < 31 {
                return Ok(out);
            }

            let auth_hmac = hmac_md5_prefix(&mac_key, &self.recv_buf[7..27], 4);
            if auth_hmac != self.recv_buf[27..31] {
                bail!("auth_aes128_md5: auth header HMAC mismatch");
            }

            let uid = u32::from_le_bytes([
                self.recv_buf[7],
                self.recv_buf[8],
                self.recv_buf[9],
                self.recv_buf[10],
            ]) as u64;
            if let Some(user_key) = self.users.get(&uid) {
                self.user_id = Some(uid);
                self.user_key = user_key.clone();
                self.rebuild_aes_key();
            } else if self.is_multi_user == 2 {
                // Mirrors shadowsocksr: unknown user on protocol-style
                // single-port nodes uses recv_iv as key and will fail checksum.
                self.user_id = None;
                self.user_key = self.recv_iv.clone();
                self.rebuild_aes_key();
            }
            let head = self.aes_decrypt_block(&self.recv_buf[11..27]);
            let length = u16_le(&head[12..14]) as usize;
            if !(31..MAX_PACKET).contains(&length) {
                bail!("auth_aes128_md5: bad auth length {length}");
            }
            if self.recv_buf.len() < length {
                return Ok(out); // wait for the rest of the auth packet
            }
            let rnd_len = u16_le(&head[14..16]) as usize;

            let checksum = hmac_md5_prefix(&self.user_key, &self.recv_buf[..length - 4], 4);
            if checksum != self.recv_buf[length - 4..length] {
                bail!("auth_aes128_md5: auth packet checksum mismatch");
            }

            let payload_start = 31 + rnd_len;
            if payload_start > length - 4 {
                bail!("auth_aes128_md5: rnd_len {rnd_len} overruns packet");
            }
            out.extend_from_slice(&self.recv_buf[payload_start..length - 4]);
            self.recv_buf.drain(..length);
            self.has_recv_header = true;
        }

        // Streaming packets after the auth header.
        while self.recv_buf.len() > 4 {
            let mut mac_key = self.user_key.clone();
            mac_key.extend_from_slice(&self.recv_id.to_le_bytes());

            let mac = hmac_md5_prefix(&mac_key, &self.recv_buf[..2], 2);
            if mac != self.recv_buf[2..4] {
                bail!("auth_aes128_md5: data packet length HMAC mismatch");
            }
            let length = u16_le(&self.recv_buf[..2]) as usize;
            if !(7..MAX_PACKET).contains(&length) {
                bail!("auth_aes128_md5: bad data length {length}");
            }
            if length > self.recv_buf.len() {
                break; // wait for the rest of this packet
            }
            let checksum = hmac_md5_prefix(&mac_key, &self.recv_buf[..length - 4], 4);
            if checksum != self.recv_buf[length - 4..length] {
                bail!("auth_aes128_md5: data packet checksum mismatch");
            }
            self.recv_id = self.recv_id.wrapping_add(1);

            let pos_marker = self.recv_buf[4] as usize;
            let pos = if pos_marker < 255 {
                pos_marker + 4
            } else {
                u16_le(&self.recv_buf[5..7]) as usize + 4
            };
            if pos > length - 4 {
                bail!("auth_aes128_md5: data padding overruns packet");
            }
            out.extend_from_slice(&self.recv_buf[pos..length - 4]);
            self.recv_buf.drain(..length);
        }

        Ok(out)
    }

    pub fn user_id(&self) -> Option<u64> {
        self.user_id
    }

    /// Wrap application payload (server -> client) into one or more SSR packets.
    pub fn server_pre_encrypt(&mut self, plaintext: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut rest = plaintext;
        while rest.len() > UNIT_LEN {
            out.extend_from_slice(&self.pack_data(&rest[..UNIT_LEN]));
            rest = &rest[UNIT_LEN..];
        }
        out.extend_from_slice(&self.pack_data(rest));
        out
    }

    fn pack_data(&mut self, buf: &[u8]) -> Vec<u8> {
        // Minimal random data: a single 0x01 marker (rnd payload length 0).
        let mut data = Vec::with_capacity(buf.len() + 1);
        data.push(0x01);
        data.extend_from_slice(buf);

        let data_len = (data.len() + 8) as u16;
        let mut mac_key = self.user_key.clone();
        mac_key.extend_from_slice(&self.pack_id.to_le_bytes());

        let len_bytes = data_len.to_le_bytes();
        let mac = hmac_md5_prefix(&mac_key, &len_bytes, 2);

        let mut packet = Vec::with_capacity(data_len as usize);
        packet.extend_from_slice(&len_bytes);
        packet.extend_from_slice(&mac);
        packet.extend_from_slice(&data);
        let tail = hmac_md5_prefix(&mac_key, &packet, 4);
        packet.extend_from_slice(&tail);

        self.pack_id = self.pack_id.wrapping_add(1);
        packet
    }

    fn aes_decrypt_block(&self, block16: &[u8]) -> [u8; 16] {
        // CBC with a zero IV on the very first block is identical to ECB-decrypt.
        let cipher = Aes128::new_from_slice(&self.aes_key).expect("16-byte AES key");
        let mut block = [0_u8; 16];
        block.copy_from_slice(block16);
        cipher.decrypt_block((&mut block).into());
        block
    }

    fn rebuild_aes_key(&mut self) {
        let mut aes_seed = STANDARD.encode(&self.user_key).into_bytes();
        aes_seed.extend_from_slice(SALT);
        let aes_key_vec = evp_bytes_to_key(&aes_seed, 16);
        self.aes_key.copy_from_slice(&aes_key_vec);
    }
}

fn u16_le(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

/// `auth_aes128_md5` UDP receive (client -> server). Each datagram's plaintext
/// (already past the rc4 layer) ends with `uid(4) || HMAC-MD5(user_key, body)[:4]`.
/// On single-port multi-user nodes, `user_key` is MD5(real user's password).
/// Returns the payload with the trailing 8 bytes stripped plus the identified
/// real user id when present.
pub fn udp_server_post_decrypt(
    master_key: &[u8],
    users: &HashMap<u64, Vec<u8>>,
    is_multi_user: i64,
    recv_iv: &[u8],
    buf: &[u8],
) -> Result<(Vec<u8>, Option<u64>)> {
    if buf.len() < 8 {
        bail!("auth_aes128_md5 udp: packet too short ({} bytes)", buf.len());
    }
    let uid = u32::from_le_bytes([
        buf[buf.len() - 8],
        buf[buf.len() - 7],
        buf[buf.len() - 6],
        buf[buf.len() - 5],
    ]) as u64;
    let (user_key, user_id) = if let Some(user_key) = users.get(&uid) {
        (user_key.as_slice(), Some(uid))
    } else if is_multi_user == 0 {
        (master_key, None)
    } else {
        (recv_iv, None)
    };
    let body = &buf[..buf.len() - 4];
    let expected = hmac_md5_prefix(user_key, body, 4);
    if expected != buf[buf.len() - 4..] {
        bail!("auth_aes128_md5 udp: HMAC mismatch");
    }
    Ok((buf[..buf.len() - 8].to_vec(), user_id))
}

pub fn user_auth_key(password: &str) -> Vec<u8> {
    md5(password.as_bytes()).to_vec()
}

/// `auth_aes128_md5` UDP send (server -> client). Appends a 4-byte HMAC over the
/// (address-header + payload) buffer, keyed by `proto_key`. In single-port
/// multi-user mode this must be the authenticated user's key (`md5(password)`);
/// otherwise it is the carrier master key.
pub fn udp_server_pre_encrypt(proto_key: &[u8], buf: &[u8]) -> Vec<u8> {
    let mac = hmac_md5_prefix(proto_key, buf, 4);
    let mut out = Vec::with_capacity(buf.len() + 4);
    out.extend_from_slice(buf);
    out.extend_from_slice(&mac);
    out
}
