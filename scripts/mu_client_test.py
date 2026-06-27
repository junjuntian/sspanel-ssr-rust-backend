#!/usr/bin/env python3
"""Minimal SSR client for one TCP request, single-port multi-user mode.

Mirrors the proven ClientCodec in src/ssr/mod.rs tests:
  cipher  = rc4-md5  (key = EVP_BytesToKey(carrier_password))
  protocol= auth_aes128_md5  (uid plaintext, user_key = md5(user_password))
  obfs    = plain

Usage: mu_client_test.py <host> <port> <carrier_pw> <uid> <user_pw> <target_host> <target_port>
"""
import sys, os, socket, hashlib, hmac, struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def aes_ecb_encrypt(key, data):
    e = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return e.update(data) + e.finalize()

def md5(b): return hashlib.md5(b).digest()

def evp_bytes_to_key(password, klen):
    d = b''; data = b''
    while len(d) < klen:
        data = md5(data + password)
        d += data
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
        self.i = i; self.j = j
        return bytes(out)

def rc4md5_cipher(master_key, iv):
    return RC4(md5(master_key + iv))

def addr_header(host, port):
    hb = host.encode()
    return bytes([0x03, len(hb)]) + hb + struct.pack('>H', port)

def main():
    host, port, carrier_pw, uid, user_pw, thost, tport = (
        sys.argv[1], int(sys.argv[2]), sys.argv[3].encode(),
        int(sys.argv[4]), sys.argv[5].encode(), sys.argv[6], int(sys.argv[7]))

    master_key = evp_bytes_to_key(carrier_pw, 16)
    user_key = md5(user_pw)
    send_iv = os.urandom(16)
    enc = rc4md5_cipher(master_key, send_iv)

    payload = (b'GET / HTTP/1.0\r\nHost: ' + thost.encode() +
               b'\r\nUser-Agent: mu-test\r\nConnection: close\r\n\r\n')
    buf = addr_header(thost, tport) + payload

    # --- build auth header (no random padding) ---
    data = b'\x00' * 12
    data_len = 7 + 4 + 16 + 4 + len(buf) + 0 + 4
    data += struct.pack('<H', data_len) + struct.pack('<H', 0)  # 16 bytes
    aes_seed = __import__('base64').b64encode(user_key) + b'auth_aes128_md5'
    aes_key = evp_bytes_to_key(aes_seed, 16)
    block = aes_ecb_encrypt(aes_key, data)  # CBC zero-IV first block == ECB
    packet = struct.pack('<I', uid) + block
    mac_key = send_iv + master_key
    packet += hmac_md5_n(mac_key, packet, 4)
    chk = bytes([0x11])
    head = chk + hmac_md5_n(mac_key, chk, 6)
    full = head + packet + buf
    full += hmac_md5_n(user_key, full, 4)

    wire = send_iv + enc.process(full)

    s = socket.create_connection((host, port), timeout=10)
    s.sendall(wire)

    raw = b''
    s.settimeout(10)
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk: break
            raw += chunk
            if len(raw) > 65536: break
    except socket.timeout:
        pass
    s.close()

    if len(raw) < 16:
        print('FAIL: no/short response (%d bytes)' % len(raw)); sys.exit(1)
    recv_iv = raw[:16]
    dec = rc4md5_cipher(master_key, recv_iv).process(raw[16:])

    # unwrap auth_aes128_md5 data packets
    out = bytearray(); rb = dec
    while len(rb) > 4:
        length = struct.unpack('<H', rb[:2])[0]
        if length > len(rb): break
        pos = rb[4] + 4
        out += rb[pos:length - 4]
        rb = rb[length:]
    text = bytes(out)
    head_line = text.split(b'\r\n', 1)[0] if text else b''
    print('RESP %d wire bytes -> %d payload bytes' % (len(raw), len(text)))
    print('STATUS LINE:', head_line.decode('latin1'))
    if b'HTTP/1' in text:
        print('PASS: multi-user uid=%d relayed a real HTTP response' % uid)
    else:
        print('FAIL: no HTTP response decoded'); sys.exit(1)

if __name__ == '__main__':
    main()
