//! ShadowsocksR data-plane codec.
//!
//! Phase 1 supports exactly one profile: `method=rc4-md5`,
//! `protocol=auth_aes128_md5`, `obfs=plain`. The layers compose, on the server
//! receive path, as:
//!
//! ```text
//! tcp bytes -> obfs(plain, passthrough) -> rc4-md5 decrypt -> auth_aes128_md5
//!           -> SOCKS5 address header + application payload
//! ```
//!
//! and the reverse on send. `obfs=plain` is a no-op so it has no module of its
//! own; the cipher and protocol layers carry all the logic.

mod address;
mod kdf;
mod protocol;
mod rc4;

use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{anyhow, Result};

use crate::{config::NodeConfig, panel::PanelUser};

pub use address::{pack_socket_addr, parse as parse_address, Address};

use protocol::AuthAes128Md5;
use rc4::{Rc4Md5, IV_LEN, KEY_LEN};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    pub method: String,
    pub protocol: String,
    pub obfs: String,
    pub timeout: Duration,
}

impl Profile {
    pub fn new(method: String, protocol: String, obfs: String, timeout: Duration) -> Result<Self> {
        let profile = Self {
            method: method.to_ascii_lowercase(),
            protocol: protocol.to_ascii_lowercase(),
            obfs: obfs.to_ascii_lowercase(),
            timeout,
        };
        profile.ensure_supported()?;
        Ok(profile)
    }

    pub fn from_user(user: &PanelUser, node: &NodeConfig) -> Result<Self> {
        Self::new(
            user.method.clone().unwrap_or_else(|| node.method.clone()),
            user.protocol.clone().unwrap_or_else(|| node.protocol.clone()),
            user.obfs.clone().unwrap_or_else(|| node.obfs.clone()),
            node.timeout(),
        )
    }

    pub fn ensure_supported(&self) -> Result<()> {
        if self.method == "rc4-md5"
            && self.protocol == "auth_aes128_md5"
            && self.obfs == "plain"
        {
            return Ok(());
        }
        Err(anyhow!(
            "unsupported SSR profile method={} protocol={} obfs={}; phase 1 only supports rc4-md5/auth_aes128_md5/plain",
            self.method,
            self.protocol,
            self.obfs
        ))
    }
}

/// Derive the connection master key from a password (`EVP_BytesToKey`, 16 bytes).
pub fn derive_master_key(password: &str) -> Vec<u8> {
    kdf::evp_bytes_to_key(password.as_bytes(), KEY_LEN)
}

pub fn derive_user_auth_key(password: &str) -> Vec<u8> {
    protocol::user_auth_key(password)
}

/// Decode one inbound UDP datagram (client -> server) into the SOCKS5 address
/// header + payload. Each datagram is self-contained: leading 16-byte rc4-md5 IV,
/// RC4 body, then the `auth_aes128_md5` UDP trailer (`uid(4) || hmac(4)`).
pub fn udp_decrypt_packet(
    master_key: &[u8],
    users: &HashMap<u64, Vec<u8>>,
    is_multi_user: i64,
    packet: &[u8],
) -> Result<(Vec<u8>, Option<u64>)> {
    if packet.len() < IV_LEN {
        return Err(anyhow!("udp datagram shorter than the {IV_LEN}-byte IV"));
    }
    let iv = &packet[..IV_LEN];
    let mut body = packet[IV_LEN..].to_vec();
    Rc4Md5::new(master_key, iv).process(&mut body);
    protocol::udp_server_post_decrypt(master_key, users, is_multi_user, iv, &body)
}

/// Encode one outbound UDP datagram (server -> client). `header_and_payload` is
/// the response's origin address header followed by the response bytes. Appends
/// the protocol HMAC keyed by `proto_key`, then prepends a fresh random rc4-md5
/// IV produced from `master_key`.
///
/// `master_key` (carrier/node key) drives the rc4-md5 cipher layer, while
/// `proto_key` keys the `auth_aes128_md5` HMAC. They differ only in single-port
/// multi-user mode, where the response must be signed with the authenticated
/// user's key (`md5(user password)`) so that user's client accepts it; in
/// normal mode pass `master_key` for both.
pub fn udp_encrypt_packet(
    master_key: &[u8],
    proto_key: &[u8],
    header_and_payload: &[u8],
) -> Result<Vec<u8>> {
    let data = protocol::udp_server_pre_encrypt(proto_key, header_and_payload);
    let mut iv = [0_u8; IV_LEN];
    getrandom::getrandom(&mut iv).map_err(|err| anyhow!("failed to gather random IV: {err}"))?;
    let mut body = data;
    Rc4Md5::new(master_key, &iv).process(&mut body);
    let mut out = Vec::with_capacity(IV_LEN + body.len());
    out.extend_from_slice(&iv);
    out.extend_from_slice(&body);
    Ok(out)
}

/// One TCP connection's worth of SSR codec state for the server side.
///
/// Feed it raw client bytes with [`ServerSession::decrypt`]; it transparently
/// consumes the leading 16-byte rc4-md5 IV, runs the RC4 + auth layers, and
/// yields application payload. Wrap outbound payload with
/// [`ServerSession::encrypt`], which prepends this direction's IV on first use.
pub struct ServerSession {
    master_key: Vec<u8>,

    // Receive side.
    recv_iv_buf: Vec<u8>,
    decryptor: Option<Rc4Md5>,
    protocol: Option<AuthAes128Md5>,
    users: Arc<HashMap<u64, Vec<u8>>>,
    is_multi_user: i64,

    // Send side.
    send_iv: [u8; IV_LEN],
    encryptor: Rc4Md5,
    send_iv_emitted: bool,
}

impl ServerSession {
    pub fn new(
        password: &str,
        users: Arc<HashMap<u64, Vec<u8>>>,
        is_multi_user: i64,
    ) -> Result<Self> {
        let master_key = kdf::evp_bytes_to_key(password.as_bytes(), KEY_LEN);
        let mut send_iv = [0_u8; IV_LEN];
        getrandom::getrandom(&mut send_iv)
            .map_err(|err| anyhow!("failed to gather random IV: {err}"))?;
        let encryptor = Rc4Md5::new(&master_key, &send_iv);
        Ok(Self {
            master_key,
            recv_iv_buf: Vec::with_capacity(IV_LEN),
            decryptor: None,
            protocol: None,
            users,
            is_multi_user,
            send_iv,
            encryptor,
            send_iv_emitted: false,
        })
    }

    /// Decrypt raw client bytes into application payload. Returns an empty vec
    /// when more bytes are needed (e.g. the IV or an auth packet is incomplete).
    pub fn decrypt(&mut self, raw: &[u8]) -> Result<Vec<u8>> {
        let mut cipher_bytes: Vec<u8>;

        if self.decryptor.is_none() {
            self.recv_iv_buf.extend_from_slice(raw);
            if self.recv_iv_buf.len() < IV_LEN {
                return Ok(Vec::new());
            }
            let iv: Vec<u8> = self.recv_iv_buf[..IV_LEN].to_vec();
            let rest: Vec<u8> = self.recv_iv_buf[IV_LEN..].to_vec();
            self.recv_iv_buf = Vec::new();

            self.decryptor = Some(Rc4Md5::new(&self.master_key, &iv));
            self.protocol = Some(AuthAes128Md5::new(
                self.master_key.clone(),
                iv,
                self.users.clone(),
                self.is_multi_user,
            ));
            cipher_bytes = rest;
        } else {
            cipher_bytes = raw.to_vec();
        }

        if cipher_bytes.is_empty() {
            return Ok(Vec::new());
        }
        self.decryptor
            .as_mut()
            .expect("decryptor set above")
            .process(&mut cipher_bytes);
        self.protocol
            .as_mut()
            .expect("protocol set with decryptor")
            .server_post_decrypt(&cipher_bytes)
    }

    pub fn user_id(&self) -> Option<u64> {
        self.protocol.as_ref().and_then(AuthAes128Md5::user_id)
    }

    /// Wrap application payload destined for the client. The first call prepends
    /// the cleartext send IV.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let protocol = self
            .protocol
            .as_mut()
            .ok_or_else(|| anyhow!("cannot encrypt before the client handshake is received"))?;
        let mut body = protocol.server_pre_encrypt(plaintext);
        self.encryptor.process(&mut body);

        if self.send_iv_emitted {
            Ok(body)
        } else {
            self.send_iv_emitted = true;
            let mut out = Vec::with_capacity(IV_LEN + body.len());
            out.extend_from_slice(&self.send_iv);
            out.extend_from_slice(&body);
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_users() -> Arc<HashMap<u64, Vec<u8>>> {
        Arc::new(HashMap::new())
    }

    // Mirror of the client send path, used only to drive the server codec in
    // tests. Built straight from the same reference as the server side.
    struct ClientCodec {
        master_key: Vec<u8>,
        send_iv: [u8; IV_LEN],
        encryptor: Rc4Md5,
        sent_header: bool,
        pack_id: u32,
        recv_iv_buf: Vec<u8>,
        decryptor: Option<Rc4Md5>,
        recv_id: u32,
        user_key: Vec<u8>,
        recv_buf: Vec<u8>,
    }

    impl ClientCodec {
        fn new(password: &str) -> Self {
            let master_key = kdf::evp_bytes_to_key(password.as_bytes(), KEY_LEN);
            let send_iv = [0x42_u8; IV_LEN];
            let encryptor = Rc4Md5::new(&master_key, &send_iv);
            Self {
                user_key: master_key.clone(),
                master_key,
                send_iv,
                encryptor,
                sent_header: false,
                pack_id: 1,
                recv_iv_buf: Vec::new(),
                decryptor: None,
                recv_id: 1,
                recv_buf: Vec::new(),
            }
        }

        fn new_multi(carrier_password: &str, user_id: u32, user_password: &str) -> Self {
            let master_key = kdf::evp_bytes_to_key(carrier_password.as_bytes(), KEY_LEN);
            let send_iv = [0x42_u8; IV_LEN];
            let encryptor = Rc4Md5::new(&master_key, &send_iv);
            Self {
                user_key: derive_user_auth_key(user_password),
                master_key,
                send_iv,
                encryptor,
                sent_header: false,
                pack_id: 1,
                recv_iv_buf: Vec::new(),
                decryptor: None,
                recv_id: 1,
                recv_buf: Vec::new(),
            }
            .with_fixed_uid(user_id)
        }

        fn with_fixed_uid(mut self, user_id: u32) -> Self {
            self.recv_id = user_id;
            self
        }

        fn hmac(key: &[u8], data: &[u8], n: usize) -> Vec<u8> {
            kdf::hmac_md5_prefix(key, data, n)
        }

        // Build the auth header packet wrapping `buf` (no random padding).
        fn pack_auth(&mut self, buf: &[u8]) -> Vec<u8> {
            use aes::cipher::{BlockEncrypt, KeyInit};
            use aes::Aes128;
            use base64::{engine::general_purpose::STANDARD, Engine};

            let rnd_len = 0usize;
            // auth_data: 12 bytes (utc4 + client_id4 + connection_id4) — values
            // are not validated by our server, so zeros are fine.
            let mut data = vec![0_u8; 12];
            let data_len = (7 + 4 + 16 + 4 + buf.len() + rnd_len + 4) as u16;
            data.extend_from_slice(&data_len.to_le_bytes());
            data.extend_from_slice(&(rnd_len as u16).to_le_bytes());
            // data is now exactly 16 bytes.

            let salt = b"auth_aes128_md5";
            let mut aes_seed = STANDARD.encode(&self.user_key).into_bytes();
            aes_seed.extend_from_slice(salt);
            let aes_key = kdf::evp_bytes_to_key(&aes_seed, 16);
            // CBC with zero IV on the first (only) block == ECB encrypt.
            let cipher = Aes128::new_from_slice(&aes_key).unwrap();
            let mut block = [0_u8; 16];
            block.copy_from_slice(&data);
            cipher.encrypt_block((&mut block).into());

            let uid = if self.recv_id > 1 {
                self.recv_id.to_le_bytes()
            } else {
                [0_u8; 4]
            };
            let mut packet = Vec::new();
            packet.extend_from_slice(&uid);
            packet.extend_from_slice(&block);
            // auth hmac over uid+block, keyed by recv_iv(server)=send_iv(client) + key
            let mut mac_key = self.send_iv.to_vec();
            mac_key.extend_from_slice(&self.master_key);
            let auth_hmac = Self::hmac(&mac_key, &packet, 4);
            packet.extend_from_slice(&auth_hmac);

            // check_head: 1 random byte + 6-byte hmac, prepended.
            let check_byte = [0x11_u8];
            let mut head = check_byte.to_vec();
            head.extend_from_slice(&Self::hmac(&mac_key, &check_byte, 6));

            let mut full = head;
            full.extend_from_slice(&packet);
            // no random padding (rnd_len = 0)
            full.extend_from_slice(buf);
            // final checksum over everything so far, keyed by user_key
            let checksum = Self::hmac(&self.user_key, &full, 4);
            full.extend_from_slice(&checksum);
            full
        }

        fn pack_data(&mut self, buf: &[u8]) -> Vec<u8> {
            let mut data = vec![0x01_u8];
            data.extend_from_slice(buf);
            let data_len = (data.len() + 8) as u16;
            let mut mac_key = self.user_key.clone();
            mac_key.extend_from_slice(&self.pack_id.to_le_bytes());
            let len_bytes = data_len.to_le_bytes();
            let mac = Self::hmac(&mac_key, &len_bytes, 2);
            let mut packet = Vec::new();
            packet.extend_from_slice(&len_bytes);
            packet.extend_from_slice(&mac);
            packet.extend_from_slice(&data);
            let tail = Self::hmac(&mac_key, &packet, 4);
            packet.extend_from_slice(&tail);
            self.pack_id = self.pack_id.wrapping_add(1);
            packet
        }

        // Produce the full wire bytes (IV + rc4(auth+data)) for an initial buf.
        fn client_first_send(&mut self, payload: &[u8]) -> Vec<u8> {
            let proto = self.pack_auth(payload);
            self.sent_header = true;
            let mut body = proto;
            self.encryptor.process(&mut body);
            let mut out = self.send_iv.to_vec();
            out.extend_from_slice(&body);
            out
        }

        fn client_send(&mut self, payload: &[u8]) -> Vec<u8> {
            // assumes header already sent
            let mut body = self.pack_data(payload);
            self.encryptor.process(&mut body);
            body
        }

        // Decode server->client bytes back to plaintext.
        fn client_recv(&mut self, raw: &[u8]) -> Vec<u8> {
            let mut cipher_bytes;
            if self.decryptor.is_none() {
                self.recv_iv_buf.extend_from_slice(raw);
                if self.recv_iv_buf.len() < IV_LEN {
                    return Vec::new();
                }
                let iv = self.recv_iv_buf[..IV_LEN].to_vec();
                let rest = self.recv_iv_buf[IV_LEN..].to_vec();
                self.decryptor = Some(Rc4Md5::new(&self.master_key, &iv));
                cipher_bytes = rest;
            } else {
                cipher_bytes = raw.to_vec();
            }
            self.decryptor.as_mut().unwrap().process(&mut cipher_bytes);
            self.recv_buf.extend_from_slice(&cipher_bytes);

            let mut out = Vec::new();
            while self.recv_buf.len() > 4 {
                let mut mac_key = self.user_key.clone();
                mac_key.extend_from_slice(&self.recv_id.to_le_bytes());
                let length = u16::from_le_bytes([self.recv_buf[0], self.recv_buf[1]]) as usize;
                if length > self.recv_buf.len() {
                    break;
                }
                self.recv_id = self.recv_id.wrapping_add(1);
                let pos = self.recv_buf[4] as usize + 4;
                out.extend_from_slice(&self.recv_buf[pos..length - 4]);
                self.recv_buf.drain(..length);
            }
            out
        }
    }

    #[test]
    fn handshake_and_relay_roundtrip() {
        let password = "correct horse battery staple";
        let mut client = ClientCodec::new(password);
        let mut server = ServerSession::new(password, empty_users(), 0).unwrap();

        // Client sends an address header + initial payload in the first packet.
        let mut first_payload = vec![0x01, 93, 184, 216, 34, 0x01, 0xbb]; // 93.184.216.34:443
        first_payload.extend_from_slice(b"hello target");

        let wire = client.client_first_send(&first_payload);
        let decoded = server.decrypt(&wire).unwrap();
        assert_eq!(decoded, first_payload);

        // A second client data packet.
        let more = client.client_send(b"second chunk");
        let decoded2 = server.decrypt(&more).unwrap();
        assert_eq!(decoded2, b"second chunk");

        // Server -> client.
        let reply = server.encrypt(b"response bytes").unwrap();
        let got = client.client_recv(&reply);
        assert_eq!(got, b"response bytes");

        let reply2 = server.encrypt(b"more response").unwrap();
        let got2 = client.client_recv(&reply2);
        assert_eq!(got2, b"more response");
    }

    #[test]
    fn decrypt_handles_split_iv() {
        let password = "splitiv";
        let mut client = ClientCodec::new(password);
        let mut server = ServerSession::new(password, empty_users(), 0).unwrap();
        let payload = {
            let mut p = vec![0x01, 1, 1, 1, 1, 0x00, 0x50];
            p.extend_from_slice(b"data");
            p
        };
        let wire = client.client_first_send(&payload);
        // Feed one byte at a time; server should buffer until it can decode.
        let mut out = Vec::new();
        for byte in &wire {
            out.extend(server.decrypt(&[*byte]).unwrap());
        }
        assert_eq!(out, payload);
    }

    #[test]
    fn udp_roundtrip() {
        let pw = "udp-secret";
        let mkey = derive_master_key(pw);

        // Client builds a datagram for 8.8.8.8:53 with payload "ping".
        let mut plain = vec![0x01, 8, 8, 8, 8, 0x00, 0x35];
        plain.extend_from_slice(b"ping");
        plain.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]); // uid (ignored by server)
        let mac = kdf::hmac_md5_prefix(&mkey, &plain, 4);
        plain.extend_from_slice(&mac);
        let iv = [9_u8; IV_LEN];
        let mut body = plain.clone();
        Rc4Md5::new(&mkey, &iv).process(&mut body);
        let mut wire = iv.to_vec();
        wire.extend_from_slice(&body);

        // Server decodes -> address + payload.
        let (decoded, uid) = udp_decrypt_packet(&mkey, &HashMap::new(), 0, &wire).unwrap();
        assert_eq!(uid, None);
        let (addr, consumed) = parse_address(&decoded).unwrap().unwrap();
        assert_eq!(addr.host, "8.8.8.8");
        assert_eq!(addr.port, 53);
        assert_eq!(&decoded[consumed..], b"ping");

        // Server encodes a response from 8.8.8.8:53.
        let mut hp = pack_socket_addr("8.8.8.8".parse().unwrap(), 53);
        hp.extend_from_slice(b"pong");
        let pkt = udp_encrypt_packet(&mkey, &mkey, &hp).unwrap();

        // Client decrypts the response.
        let civ = &pkt[..IV_LEN];
        let mut cbody = pkt[IV_LEN..].to_vec();
        Rc4Md5::new(&mkey, civ).process(&mut cbody);
        let n = cbody.len();
        assert_eq!(kdf::hmac_md5_prefix(&mkey, &cbody[..n - 4], 4), cbody[n - 4..]);
        let resp_plain = &cbody[..n - 4];
        let (raddr, rconsumed) = parse_address(resp_plain).unwrap().unwrap();
        assert_eq!(raddr.host, "8.8.8.8");
        assert_eq!(&resp_plain[rconsumed..], b"pong");
    }

    #[test]
    fn udp_wrong_password_fails() {
        let mkey = derive_master_key("right");
        let mut plain = vec![0x01, 1, 1, 1, 1, 0x00, 0x35, b'x'];
        plain.extend_from_slice(&[0; 4]);
        let mac = kdf::hmac_md5_prefix(&mkey, &plain, 4);
        plain.extend_from_slice(&mac);
        let iv = [3_u8; IV_LEN];
        let mut body = plain.clone();
        Rc4Md5::new(&mkey, &iv).process(&mut body);
        let mut wire = iv.to_vec();
        wire.extend_from_slice(&body);

        let wrong = derive_master_key("wrong");
        assert!(udp_decrypt_packet(&wrong, &HashMap::new(), 0, &wire).is_err());
    }

    #[test]
    fn wrong_password_fails() {
        let mut client = ClientCodec::new("right");
        let mut server = ServerSession::new("wrong", empty_users(), 0).unwrap();
        let payload = vec![0x01, 1, 1, 1, 1, 0x00, 0x50, b'x'];
        let wire = client.client_first_send(&payload);
        assert!(server.decrypt(&wire).is_err());
    }

    #[test]
    fn multi_user_tcp_identifies_uid() {
        let carrier_password = "carrier";
        let user_id = 42_u32;
        let user_password = "real-user-password";
        let mut users = HashMap::new();
        users.insert(user_id as u64, derive_user_auth_key(user_password));

        let mut client = ClientCodec::new_multi(carrier_password, user_id, user_password);
        let mut server = ServerSession::new(carrier_password, Arc::new(users), 2).unwrap();
        let payload = vec![0x01, 1, 1, 1, 1, 0x00, 0x50, b'x'];
        let wire = client.client_first_send(&payload);
        let decoded = server.decrypt(&wire).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(server.user_id(), Some(user_id as u64));
    }

    #[test]
    fn multi_user_udp_identifies_uid() {
        let carrier_key = derive_master_key("carrier");
        let user_id = 77_u32;
        let user_password = "udp-real-user";
        let user_key = derive_user_auth_key(user_password);
        let mut users = HashMap::new();
        users.insert(user_id as u64, user_key.clone());

        let mut plain = vec![0x01, 8, 8, 4, 4, 0x00, 0x35];
        plain.extend_from_slice(b"query");
        plain.extend_from_slice(&user_id.to_le_bytes());
        let mac = kdf::hmac_md5_prefix(&user_key, &plain, 4);
        plain.extend_from_slice(&mac);

        let iv = [5_u8; IV_LEN];
        let mut body = plain;
        Rc4Md5::new(&carrier_key, &iv).process(&mut body);
        let mut wire = iv.to_vec();
        wire.extend_from_slice(&body);

        let (decoded, uid) = udp_decrypt_packet(&carrier_key, &users, 2, &wire).unwrap();
        assert_eq!(uid, Some(user_id as u64));
        let (addr, consumed) = parse_address(&decoded).unwrap().unwrap();
        assert_eq!(addr.host, "8.8.4.4");
        assert_eq!(&decoded[consumed..], b"query");

        // Server -> client response: rc4 keyed by the carrier key, but the
        // protocol HMAC keyed by the authenticated user's key. The client
        // verifies with its own user_key, so signing with the carrier key would
        // be rejected.
        let mut hp = pack_socket_addr("8.8.4.4".parse().unwrap(), 53);
        hp.extend_from_slice(b"answer");
        let pkt = udp_encrypt_packet(&carrier_key, &user_key, &hp).unwrap();
        let civ = &pkt[..IV_LEN];
        let mut cbody = pkt[IV_LEN..].to_vec();
        Rc4Md5::new(&carrier_key, civ).process(&mut cbody);
        let n = cbody.len();
        // HMAC must validate under the user's key, not the carrier key.
        assert_eq!(
            kdf::hmac_md5_prefix(&user_key, &cbody[..n - 4], 4),
            cbody[n - 4..]
        );
        assert_ne!(
            kdf::hmac_md5_prefix(&carrier_key, &cbody[..n - 4], 4),
            cbody[n - 4..]
        );
        let resp_plain = &cbody[..n - 4];
        let (raddr, rconsumed) = parse_address(resp_plain).unwrap().unwrap();
        assert_eq!(raddr.host, "8.8.4.4");
        assert_eq!(&resp_plain[rconsumed..], b"answer");
    }
}
