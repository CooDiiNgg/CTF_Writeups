---
title: "sponsors_ecsc — forging an AES-GCM cookie when the key is the nonce"
date: 2026-10-23
event: "ECSC 2026 (Bochum, Germany)"
category: Crypto
difficulty: Medium
tags: [aes-gcm, nonce-reuse, forbidden-attack, ghash, authenticated-encryption]
summary: "The sponsor portal encrypts its session cookie with AES-256-GCM but reuses the AES key as the GCM nonce. A fixed nonce leaks the keystream and the GHASH subkey, letting us forge a valid cookie for the sold-out `flag` tier."
---

## Challenge

A small Flask "sponsor portal" hands you a session cookie when you register for a
sponsorship tier, and shows a different page per tier. One tier, `flag`, is
"already sold out" — registering for it is rejected outright — and the `/flag`
endpoint only returns the flag to a cookie that decrypts to exactly
`sponsortier=flag`.

The cookie is AES-256-GCM ciphertext plus tag, hex-encoded. GCM is an
authenticated cipher, so we cannot just flip bytes: any tampering should make
`decrypt_and_verify` reject the cookie. The whole challenge is getting a cookie
that both decrypts to `sponsortier=flag` **and** carries a tag the server
accepts, without ever being allowed to register that tier.

## Files

- [Challenge archive](attachments/sponsor-ecsc.zip) — `app.py`, templates, static assets, Dockerfile.
- [Solve script](solve.py) — self-contained; `--local` verifies the attack with no network.

## First observations

The entire weakness is in how the cipher is constructed. Here is the relevant
part of `app.py`:

```python
_AES_KEY = get_random_bytes(32)

def _encrypt_cookie(sponsortier: str) -> str:
    plaintext = f"sponsortier={sponsortier}".encode("ascii")
    cipher = AES.new(_AES_KEY, AES.MODE_GCM, _AES_KEY)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    payload = ciphertext + tag
    return payload.hex()
```

The third positional argument to `AES.new(..., AES.MODE_GCM, ...)` is the
**nonce**. So the nonce is `_AES_KEY` — the same 32 bytes as the key, and
crucially the **same value on every single call**. GCM's entire security
argument depends on the nonce being unique per key. Here it is constant.

Two more details make the rest clean:

- The plaintext is `sponsortier=` (12 bytes) followed by the tier name. For a
  4-character tier such as `main`, `test`, or `flag` that is exactly **16 bytes
  — one AES block**. No padding, no second block.
- There is no associated data, and the cookie layout is simply
  `ciphertext || tag` with a 16-byte tag.

The `/register` endpoint lets us encrypt any ASCII tier except the literal
`flag`, and `/flag` is our verification oracle. That is everything we need.

## The weakness

### How GCM produces a cookie

For a single 16-byte plaintext block $P$, GCM computes:

$$
C = P \oplus E_K(J_1), \qquad
T = \big(C \cdot H^2\big) \oplus \big(L \cdot H\big) \oplus E_K(J_0),
$$

where $H = E_K(0^{128})$ is the hash subkey, $J_0$ is the initial counter block
derived from the nonce, $J_1$ is the next counter, $L$ is the 128-bit block
encoding the ciphertext length (here $L = 128$, since one block is 128 bits),
and all multiplications are in $\mathrm{GF}(2^{128})$. The tag is just the
one-block GHASH of $C$, masked by $E_K(J_0)$.

Because the nonce is fixed, $H$, $E_K(J_0)$, and the keystream block $E_K(J_1)$
are **the same for every cookie the server issues**. That constancy is the
whole attack.

### Part 1 — forging the ciphertext

With a constant keystream $E_K(J_1)$, encryption is a one-time pad reused across
messages. Register for `main`, whose plaintext $P_{\text{main}} =
\texttt{sponsortier=main}$ is known, and recover the keystream directly:

$$
E_K(J_1) = C_{\text{main}} \oplus P_{\text{main}}.
$$

Then the ciphertext for our target plaintext $P_{\text{flag}} =
\texttt{sponsortier=flag}$ is simply:

$$
C_{\text{flag}} = E_K(J_1) \oplus P_{\text{flag}}
                = C_{\text{main}} \oplus P_{\text{main}} \oplus P_{\text{flag}}.
$$

That gives a ciphertext that decrypts to `sponsortier=flag` — but its tag is
still wrong, and GCM will reject it. We need the matching tag.

### Part 2 — recovering H (the "forbidden attack")

This is the classic GCM nonce-reuse forgery. Take two cookies over equal-length
single blocks — say `main` and `test` — giving $(C_1, T_1)$ and $(C_2, T_2)$.
Both share the same $H$, $E_K(J_0)$, and length block $L$, so subtracting
(XORing) the two tag equations cancels everything except one term:

$$
T_1 \oplus T_2 = (C_1 \oplus C_2)\cdot H^2.
$$

Everything there is known except $H$. Solve for $H^2$ and take a square root
(squaring is a bijection in characteristic 2, so the root is unique):

$$
H^2 = (T_1 \oplus T_2)\cdot(C_1 \oplus C_2)^{-1},
\qquad
H = \sqrt{H^2}.
$$

```python
def recover_h(c1, c2, t1, t2):
    dc = b2i(c1) ^ b2i(c2)
    dt = b2i(t1) ^ b2i(t2)
    return gsqrt(gmul(dt, ginv(dc)))   # H = sqrt( dT / dC )
```

### Part 3 — forging the tag

With $H$ known we peel off the key-dependent mask from a known tag. Define the
one-block GHASH (with the length block appended) as
$\mathrm{GH}(C) = (C\cdot H^2)\oplus(L\cdot H)$. Then from the `main` cookie:

$$
E_K(J_0) = T_1 \oplus \mathrm{GH}(C_1).
$$

Now forge the tag for our crafted ciphertext $C_{\text{flag}}$:

$$
T_{\text{flag}} = \mathrm{GH}(C_{\text{flag}}) \oplus E_K(J_0).
$$

The cookie `C_flag || T_flag` now decrypts **and** authenticates as
`sponsortier=flag`.

> This is where my first attempt failed. I had the `recover_h` step working, but
> then computed the tag as `GHASH(H, ciphertext)` over the *original* `main`
> ciphertext — with no length block and without removing the $E_K(J_0)$ mask. A
> raw GHASH is not a GCM tag. The fix is the three lines above: GHASH the
> *forged* ciphertext (plus the length block), and XOR in $E_K(J_0)$ recovered
> from a known good tag.

## Solve

The solver separates the maths from the transport. `forge(register)` takes any
"register a tier, get a cookie" callable and returns the forged `flag` cookie;
the remote mode wires that to HTTP, and `--local` wires it to an in-process copy
of the server so the chain can be verified offline.

```python
def forge(register):
    main = bytes.fromhex(register("main"))
    test = bytes.fromhex(register("test"))
    ct1, tag1 = main[:-16], main[-16:]
    ct2, tag2 = test[:-16], test[-16:]

    # 1) constant keystream -> ciphertext for "sponsortier=flag"
    keystream = xor(b"sponsortier=main", ct1)
    flag_ct = xor(keystream, b"sponsortier=flag")

    # 2) recover H, then E_K(J0), then a valid tag for flag_ct
    h = recover_h(ct1, ct2, tag1, tag2)
    length_block = (len(flag_ct) * 8).to_bytes(16, "big")   # = 128
    ek_j0 = xor(tag1, ghash(h, [ct1, length_block]))        # T1 ^ GHASH(C1)
    flag_tag = xor(ghash(h, [flag_ct, length_block]), ek_j0)

    return (flag_ct + flag_tag).hex()
```

Against a live instance:

```sh
BASE_URL=https://<instance-host>/ python3 _writeups/ecsc-2026-sponsors-ecsc/solve.py
```

To verify the full forge offline (reproduces the server's crypto in-process and
has PyCryptodome's real GCM accept the forged cookie):

```sh
python3 _writeups/ecsc-2026-sponsors-ecsc/solve.py --local
```

Expected output:

```text
ECSC{local_test_flag}
```

The `--local` run is the verification I actually ran here: it proves the forged
`ciphertext || tag` passes `decrypt_and_verify` and decrypts to
`sponsortier=flag`. The remote run uses the identical `forge()` and only swaps
the registration oracle for HTTP requests to the instance.

Dependencies: `pycryptodome` for the maths (and `--local`), and `requests` for
the remote mode.

## Flag

```text
ECSC{why_sh0uld_1_tr4nsm1t_a_n0nc3_wh3n_1_c4n_use_th3_k3y}
```

## Takeaway

AES-GCM is only secure while each (key, nonce) pair is used once. Here the nonce
was not merely repeated but hardwired to the key, which collapses two independent
guarantees at once:

- **Confidentiality** goes first — a fixed nonce reuses the keystream, so one
  known plaintext exposes it and lets you re-encrypt anything of that length.
- **Integrity** goes next — repeated nonces linearise the GHASH tag equations
  (the "forbidden attack"), leaking the subkey $H$ and then $E_K(J_0)$, which is
  enough to forge tags at will.

The practical lesson: never pass the key (or any fixed value) as a GCM nonce,
and never let an API's nonce be caller- or key-derived in a way that repeats.
If you must have deterministic encryption, use a misuse-resistant mode such as
AES-GCM-SIV instead of hand-fixing the nonce.

## References

- D. McGrew, J. Viega. *The Galois/Counter Mode of Operation (GCM)* / NIST SP 800-38D.
- A. Joux. *Authentication Failures in NIST version of GCM* — the original nonce-reuse ("forbidden") attack.
- S. Böck, A. Zauner, et al. *Nonce-Disrespecting Adversaries: Practical Forgery Attacks on GCM in TLS*, WOOT 2016.
