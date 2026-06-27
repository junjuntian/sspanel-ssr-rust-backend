//! Shadowsocks(R) target-address header parsing.
//!
//! After the protocol layer is stripped, the first bytes of the client stream are
//! a SOCKS5-style address: `ATYP || ADDR || PORT(be16)`, followed by the initial
//! payload destined for that target.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Result};

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub host: String,
    pub port: u16,
}

impl Address {
    pub fn connect_target(&self) -> (String, u16) {
        (self.host.clone(), self.port)
    }
}

/// Parse the address header at the front of `buf`. Returns the parsed address and
/// the number of header bytes consumed (the remainder of `buf` is initial
/// payload). Returns `Ok(None)` if `buf` does not yet hold the whole header.
pub fn parse(buf: &[u8]) -> Result<Option<(Address, usize)>> {
    if buf.is_empty() {
        return Ok(None);
    }
    // Bit 0x08 is the SSR "connect type" flag (TCP vs UDP); it never changes how
    // we relay, so mask it off before matching the address type.
    let atyp = buf[0] & !0x08;
    match atyp {
        ATYP_IPV4 => {
            let end = 1 + 4 + 2;
            if buf.len() < end {
                return Ok(None);
            }
            let ip = Ipv4Addr::new(buf[1], buf[2], buf[3], buf[4]);
            let port = u16::from_be_bytes([buf[5], buf[6]]);
            Ok(Some((Address { host: ip.to_string(), port }, end)))
        }
        ATYP_DOMAIN => {
            if buf.len() < 2 {
                return Ok(None);
            }
            let dlen = buf[1] as usize;
            let end = 2 + dlen + 2;
            if buf.len() < end {
                return Ok(None);
            }
            let host = std::str::from_utf8(&buf[2..2 + dlen])
                .map_err(|_| anyhow::anyhow!("ssr address: non-UTF8 domain"))?
                .to_owned();
            let port = u16::from_be_bytes([buf[2 + dlen], buf[2 + dlen + 1]]);
            Ok(Some((Address { host, port }, end)))
        }
        ATYP_IPV6 => {
            let end = 1 + 16 + 2;
            if buf.len() < end {
                return Ok(None);
            }
            let mut octets = [0_u8; 16];
            octets.copy_from_slice(&buf[1..17]);
            let ip = Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([buf[17], buf[18]]);
            Ok(Some((Address { host: ip.to_string(), port }, end)))
        }
        other => bail!("ssr address: unsupported ATYP 0x{other:02x}"),
    }
}

/// Build a SOCKS5 address header (`ATYP || ADDR || PORT(be16)`) for a concrete
/// socket address. Used to label UDP responses with their origin before they are
/// re-encrypted back to the client.
pub fn pack_socket_addr(ip: IpAddr, port: u16) -> Vec<u8> {
    let mut out = Vec::new();
    match ip {
        IpAddr::V4(v4) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4() {
        // 1.2.3.4:443 followed by "hi"
        let buf = [0x01, 1, 2, 3, 4, 0x01, 0xbb, b'h', b'i'];
        let (addr, consumed) = parse(&buf).unwrap().unwrap();
        assert_eq!(addr, Address { host: "1.2.3.4".into(), port: 443 });
        assert_eq!(consumed, 7);
        assert_eq!(&buf[consumed..], b"hi");
    }

    #[test]
    fn parse_domain() {
        let mut buf = vec![0x03, 11];
        buf.extend_from_slice(b"example.com");
        buf.extend_from_slice(&[0x00, 0x50]); // port 80
        buf.extend_from_slice(b"GET");
        let (addr, consumed) = parse(&buf).unwrap().unwrap();
        assert_eq!(addr, Address { host: "example.com".into(), port: 80 });
        assert_eq!(&buf[consumed..], b"GET");
    }

    #[test]
    fn partial_returns_none() {
        let buf = [0x03, 11, b'e', b'x']; // domain not fully arrived
        assert!(parse(&buf).unwrap().is_none());
    }

    #[test]
    fn bad_atyp_errors() {
        // 0x05 is not a valid ATYP even after masking the 0x08 connect-type flag.
        assert!(parse(&[0x05, 0, 0]).is_err());
    }

    #[test]
    fn parse_ipv4_with_connecttype_flag() {
        // 0x09 = IPv4 (0x01) | connecttype (0x08); must still parse as IPv4.
        let buf = [0x09, 1, 2, 3, 4, 0x01, 0xbb];
        let (addr, consumed) = parse(&buf).unwrap().unwrap();
        assert_eq!(addr, Address { host: "1.2.3.4".into(), port: 443 });
        assert_eq!(consumed, 7);
    }
}
