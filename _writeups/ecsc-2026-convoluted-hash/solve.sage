#!/usr/bin/env sage
import itertools

p = 10**9 + 7
e = 8193

H_coeffs = [403160923, 293253565, 33836461, 341933798, 578676274, 177411219, 287450491, 692942752, 592558930, 99586660, 621145624, 13093019, 80721975, 348693824, 477681186, 109423341, 907759570, 860054035, 857857159, 679379185, 88344655, 992937107, 843440688, 776295281, 44427169, 375765406, 518334641, 661523963, 301136230, 827376279, 635431929, 608662711]

P = PolynomialRing(GF(p), 'x')
x = P.gen()
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
        hK = hf(K.gen())
        roots = [P(r.polynomial().list()) for r in hK.nth_root(e, all=True)]
    root_lists.append((f, roots))

mods = [f for f, _ in root_lists]
prefix = [ord(c) for c in "ECSC{"]

for combo in itertools.product(*[rl for _, rl in root_lists]):
    F = crt(list(combo), mods)
    c = [int(v) for v in F.list()]
    c += [0] * (32 - len(c))
    if c[:5] != prefix or c[31] != ord("}"):
        continue
    if not all(32 <= v <= 126 for v in c):
        continue
    if pow(F, e, mod) == H:
        print("".join(chr(v) for v in c))
        break
