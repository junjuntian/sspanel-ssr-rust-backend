#!/usr/bin/env python3
"""Minimal SSR UDP client (single-port multi-user) — DNS query test.

Validates the server->client UDP response HMAC is keyed by the authenticated
user's key (md5(user_password)), NOT the carrier master key.

Usage: mu_udp_test.py <host> <port> <carrier_pw> <uid> <user_pw> <dns_ip> <qname>
"""
import sys, os, socket, hashlib, hmac, struct

def md5(b): return hashlib.md5(b).digest()

def evp_bytes_to_key(password, klen):
    d = b''; data = b''
    while len(d) < klen:
        data = md5(data + password); d += data
    return d[:klen]

def hmac_md5_n(key, data, n):
    return hmac.new(key, data, hashlib.md5).digest()[:n]

class RC4:
    def __init__(self, key):
        S = list(range(256)); j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) & 0xff
            S[i], S[j] = S[j], S[i]
        self.S = S; self.i = 0; self.j = 0
    def process(self, data):
        S = self.S; i = self.i; j = self.j; out = bytearray()
        for b in data:
            i = (i + 1) & 0xff; j = (j + S[i]) & 0xff
            S[i], S[j] = S[j], S[i]
            out.append(b ^ S[(S[i] + S[j]) & 0xff])
        self.i = i; self.j = j; return bytes(out)

def rc4md5(master_key, iv): return RC4(md5(master_key + iv))

def addr_header(host, port):
    hb = host.encode(); return bytes([0x03, len(hb)]) + hb + struct.pack('>H', port)

def dns_query(qname):
    q = bytearray(struct.pack('>HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0))
    for part in qname.split('.'):
        q.append(len(part)); q += part.encode()
    q.append(0); q += struct.pack('>HH', 1, 1)  # A, IN
    return bytes(q)

def main():
    host, port, carrier_pw, uid, user_pw, dns_ip, qname = (
        sys.argv[1], int(sys.argv[2]), sys.argv[3].encode(),
        int(sys.argv[4]), sys.argv[5].encode(), sys.argv[6], sys.argv[7])
    master_key = evp_bytes_to_key(carrier_pw, 16)
    user_key = md5(user_pw)

    body = addr_header(dns_ip, 53) + dns_query(qname) + struct.pack('<I', uid)
    body += hmac_md5_n(user_key, body, 4)
    iv = os.urandom(16)
    wire = iv + rc4md5(master_key, iv).process(body)

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(8)
    s.sendto(wire, (host, port))
    resp, _ = s.recvfrom(65536); s.close()
    if len(resp) < 16 + 4:
        print('FAIL: short udp response (%d)' % len(resp)); sys.exit(1)

    dec = rc4md5(master_key, resp[:16]).process(resp[16:])
    ok_user = hmac_md5_n(user_key, dec[:-4], 4) == dec[-4:]
    ok_carrier = hmac_md5_n(master_key, dec[:-4], 4) == dec[-4:]
    print('HMAC verifies under user_key  :', ok_user)
    print('HMAC verifies under carrier_key:', ok_carrier)
    if not ok_user:
        print('FAIL: response not signed with user_key (fix not effective)'); sys.exit(1)
    if ok_carrier:
        print('WARN: also verifies under carrier key (unexpected collision)')

    payload = dec[:-4]
    # strip response addr header (atyp 0x01 ipv4 => 1+4+2 = 7 bytes)
    off = 7 if payload[0] == 0x01 else (2 + payload[1] + 2)
    dnsr = payload[off:]
    txid, flags, qd, an = struct.unpack('>HHHH', dnsr[:8])
    print('DNS txid=0x%04x answers=%d' % (txid, an))
    if txid == 0x1234 and an >= 1:
        print('PASS: multi-user uid=%d UDP/DNS round-trip ok, %d answer(s)' % (uid, an))
    else:
        print('FAIL: DNS response invalid'); sys.exit(1)

if __name__ == '__main__':
    main()
