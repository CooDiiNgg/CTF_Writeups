#!/usr/bin/env python3
import os
import sys

# --------------------------------------------------------------------------- #
# GF(2^128) arithmetic, NIST SP 800-38D. 128-bit blocks as big-endian ints.
# --------------------------------------------------------------------------- #
_MASK = (1 << 128) - 1
_R = 0xE1000000000000000000000000000000  # reduction constant for x^128+x^7+x^2+x+1


def gmul(x, y):
    """Multiply two field elements (GCM bit convention)."""
    z, v = 0, y & _MASK
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        lsb = v & 1
        v >>= 1
        if lsb:
            v ^= _R
    return z & _MASK


def _gpow(a, e):
    r = 1 << 127  # multiplicative identity in this encoding
    while e:
        if e & 1:
            r = gmul(r, a)
        a = gmul(a, a)
        e >>= 1
    return r


def ginv(a):
    return _gpow(a, _MASK - 1)  # Fermat: a^(2^128 - 2)


def gsqrt(a):
    return _gpow(a, 1 << 127)  # a^(2^127); squaring is a bijection in char 2


def b2i(b):
    return int.from_bytes(b, "big")


def i2b(n):
    return int(n).to_bytes(16, "big")


def xor(a, b):
    return bytes(i ^ j for i, j in zip(a, b))


def ghash(h, blocks):
    """GHASH_H over a list of 16-byte blocks (caller appends the length block)."""
    x = 0
    for blk in blocks:
        x = gmul(x ^ b2i(blk), h)
    return i2b(x)


def recover_h(c1, c2, t1, t2):
    """Recover H from two tags over distinct single ciphertext blocks of equal
    length (empty AAD). For one block C and length block L:

        T = C*H^2 ^ L*H ^ E_K(J0)

    so T1 ^ T2 = (C1 ^ C2) * H^2, a solvable quadratic: H = sqrt(dT / dC)."""
    dc = b2i(c1) ^ b2i(c2)
    dt = b2i(t1) ^ b2i(t2)
    if dc == 0:
        raise ValueError("ciphertext blocks identical -- need distinct plaintexts")
    return gsqrt(gmul(dt, ginv(dc)))


# --------------------------------------------------------------------------- #
# The forge, independent of transport.
# --------------------------------------------------------------------------- #
def forge(register):
    """`register(tier) -> cookie_hex`. Returns the forged `flag` cookie hex."""
    main = bytes.fromhex(register("main"))
    test = bytes.fromhex(register("test"))
    ct1, tag1 = main[:-16], main[-16:]
    ct2, tag2 = test[:-16], test[-16:]

    # Both plaintexts are "sponsortier=" + 4 chars = exactly one 16-byte block.
    assert len(ct1) == 16 and len(ct2) == 16

    # 1) Constant keystream -> forge the ciphertext for "sponsortier=flag".
    keystream = xor(b"sponsortier=main", ct1)
    flag_ct = xor(keystream, b"sponsortier=flag")

    # 2) Recover H, then E_K(J0), then a valid tag for flag_ct.
    h = recover_h(ct1, ct2, tag1, tag2)
    length_block = (len(flag_ct) * 8).to_bytes(16, "big")  # = 128
    ek_j0 = xor(tag1, ghash(h, [ct1, length_block]))        # T1 ^ GHASH(C1)
    flag_tag = xor(ghash(h, [flag_ct, length_block]), ek_j0)

    return (flag_ct + flag_tag).hex()


# --------------------------------------------------------------------------- #
# Transports.
# --------------------------------------------------------------------------- #
def remote(base_url):
    import requests

    base = base_url.rstrip("/")

    def register(tier):
        s = requests.Session()
        s.post(f"{base}/register", data={"sponsortier": tier})
        return s.cookies.get("session")

    cookie = forge(register)
    s = requests.Session()
    s.cookies.set("session", cookie)
    print(s.get(f"{base}/flag").text)


def local():
    """In-process replica of app.py, to verify the attack with no network."""
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes

    key = get_random_bytes(32)
    flag = b"ECSC{local_test_flag}"

    def register(tier):
        pt = f"sponsortier={tier}".encode("ascii")
        ct, tag = AES.new(key, AES.MODE_GCM, key).encrypt_and_digest(pt)
        return (ct + tag).hex()

    cookie = forge(register)
    payload = bytes.fromhex(cookie)
    pt = AES.new(key, AES.MODE_GCM, key).decrypt_and_verify(payload[:-16], payload[-16:])
    assert pt == b"sponsortier=flag", pt
    print(flag.decode())


if __name__ == "__main__":
    if "--local" in sys.argv:
        local()
    else:
        base_url = os.environ.get("BASE_URL", "http://127.0.0.1:1337/")
        remote(base_url)
