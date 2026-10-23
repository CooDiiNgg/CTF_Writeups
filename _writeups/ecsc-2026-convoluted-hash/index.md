---
title: "convoluted-hash — inverting a cyclic-convolution power with CRT roots"
date: 2026-10-23
event: "ECSC 2026 (Bochum, Germany)"
category: Crypto
difficulty: Medium
tags: [polynomial-rings, cyclic-convolution, crt, nth-roots, finite-fields]
summary: "The hash is the flag polynomial raised to a fixed power in GF(p)[x]/(x^32-1). Evaluating at x=1 recovers the character sum, and taking 8193-th roots in each CRT factor field reconstructs the flag."
---

## Challenge

We get a hashing script and the hash of the 32-character flag.

```python
p = 10**9 + 7

def enc(a, b):
    n = len(a)
    res = [0] * n
    for i in range(n):
        for j in range(n):
            res[(i + j) % n] = (res[(i + j) % n] + a[i] * b[j]) % p
    return res

def securehash(a):
    res = a
    for _ in range(8192):
        res = enc(res, a)
    return res

flag = [ord(c) for c in sys.argv[1]]   # len(flag) == 32
print(securehash(flag))
```

The flag is 32 characters, and we know it starts with `ECSC{` and ends with `}`.

## Files

- [Challenge archive](attachments/convoluted-hash.zip) — `hash.py`, `output.txt`.
- [Solve script](solve.sage) — SageMath.

## The structure

`enc(a, b)` indexes the output by `(i + j) % n`, which is exactly **cyclic
convolution** of length `n = 32`. Cyclic convolution is multiplication of
polynomials modulo $$x^{n} - 1$$: if we read a length-32 vector $$a$$ as the
polynomial $$a(x) = \sum_i a_i x^i$$, then

$$
\texttt{enc}(a, b) \;\equiv\; a(x)\cdot b(x) \pmod{x^{32} - 1},
$$

with all coefficients reduced mod $$p$$. So the whole computation lives in the
ring

$$
R = \mathrm{GF}(p)[x] \big/ (x^{32} - 1).
$$

`securehash` starts from `res = a` and multiplies by `a` another 8192 times, so

$$
\texttt{securehash}(a) = a(x)^{1 + 8192} = a(x)^{8193} \quad\text{in } R .
$$

The hash is just the flag polynomial raised to the power $$e = 8193$$. Recovering
the flag means taking an $$e$$-th root in $$R$$.

## Recovering the character sum

Evaluation at $$x = 1$$ is a ring homomorphism $$R \to \mathrm{GF}(p)$$, because
$$x^{32} - 1$$ vanishes at $$x = 1$$. Under it a polynomial maps to the sum of its
coefficients, so

$$
\sum_i H_i \;=\; H(1) \;=\; \big(\text{flag}(1)\big)^{8193}
            \;=\; \Big(\textstyle\sum_i \text{flag}_i\Big)^{8193} \pmod p .
$$

The character sum $$\sum_i \text{flag}_i$$ is at most $$32 \cdot 126 = 4032$$, so it
can be read straight back by trying each small value, or by taking an $$e$$-th
root in $$\mathrm{GF}(p)$$: since $$\gcd(8193,\, p - 1) = 1$$, that root is unique.
This confirms the model and gives a useful cross-check, but a single sum is one
equation in 32 unknowns — not enough on its own.

## Inverting the power with CRT

To get every coefficient we invert the power in the full ring. Since
$$\gcd(32, p) = 1$$, the modulus is squarefree and factors over $$\mathrm{GF}(p)$$:

$$
x^{32} - 1 = \prod_i f_i(x), \qquad
R \;\cong\; \prod_i \mathrm{GF}(p)[x]/(f_i) \;=\; \prod_i \mathrm{GF}(p^{d_i}),
$$

by the Chinese Remainder Theorem, where $$d_i = \deg f_i$$. Here the factors have
degrees $$1, 1$$ and then seven of degree $$2$$ and four of degree $$4$$.

In each component field $$K_i = \mathrm{GF}(p^{d_i})$$ the equation becomes a
plain power relation $$h_i = r_i^{\,8193}$$, which we solve with a field $$e$$-th
root. The number of roots in a component is $$\gcd(8193,\, p^{d_i} - 1)$$:

- $$d_i = 1$$: $$\gcd(8193,\, p - 1) = 1$$ — one root.
- $$d_i = 2, 4$$: $$\gcd(8193,\, p^{d_i} - 1) = 3$$ — three roots each.

The ambiguity is a single factor of $$3$$ (it comes from $$3 \mid p + 1$$, and
$$8193 = 3 \cdot 2731$$). With eleven components of degree $$2$$ or $$4$$, that is
$$3^{11} = 177147$$ candidate combinations. For each combination we CRT the
chosen residues back to a polynomial $$F(x) \in R$$ and keep the one that:

- has all 32 coefficients in printable ASCII range,
- matches the known `ECSC{` prefix and `}` suffix,
- satisfies $$F(x)^{8193} = H(x)$$ in $$R$$.

The prefix/suffix and range filters leave a single candidate almost immediately.

## Solve

```python
P = PolynomialRing(GF(p), 'x'); x = P.gen()
mod = x**32 - 1
H = P(H_coeffs)

root_lists = []
for f, _ in mod.factor():
    d = f.degree()
    hf = H % f
    if d == 1:
        hK = GF(p)(hf.constant_coefficient())
        roots = [P(r) for r in hK.nth_root(e, all=True)]
    else:
        K = GF(p**d, 'a', modulus=f)
        roots = [P(r.polynomial().list()) for r in hf(K.gen()).nth_root(e, all=True)]
    root_lists.append((f, roots))

mods = [f for f, _ in root_lists]
for combo in itertools.product(*[rl for _, rl in root_lists]):
    F = crt(list(combo), mods)
    c = [int(v) for v in F.list()] + [0] * (32 - F.degree() - 1)
    if c[:5] == prefix and c[31] == ord("}") and all(32 <= v <= 126 for v in c):
        if pow(F, e, mod) == H:
            print("".join(chr(v) for v in c))
            break
```

Run it from the repository root:

```sh
sage solve.sage
```

Expected output (about one second):

```text
ECSC{3_roots_4re_not_en0ugh????}
```

Verified against the original hasher: `python3 hash.py 'ECSC{3_roots_4re_not_en0ugh????}'` reproduces `output.txt` exactly.

## Flag

```text
ECSC{3_roots_4re_not_en0ugh????}
```

## Takeaway

A "hash" that is really a fixed power in a polynomial ring is invertible: factor
the modulus, take $$e$$-th roots in each CRT component, and recombine. The only
cost is the root multiplicity $$\gcd(e,\, p^{d}-1)$$ per component, which here is a
small, brute-forceable $$3^{11}$$.

## References

- [Chinese remainder theorem (polynomial / ring form)](https://en.wikipedia.org/wiki/Chinese_remainder_theorem#Over_univariate_polynomial_rings_and_Euclidean_domains)
