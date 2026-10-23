---
title: "A small shift — example writeup"
date: 2026-10-23
event: "Practice / Template"
category: Crypto
difficulty: Beginner
tags: [classical-ciphers, caesar]
summary: "An annotated template: recover a Caesar shift using a known flag prefix, then reproduce the solve."
template: true
---

> This is a deliberately small, original practice challenge. Copy this folder for a real writeup, replace the metadata and content, and remove `template: true`.

## Challenge

**Description:** Someone shifted every letter of the flag. Recover the original message.

We are given a ciphertext and know that flags start with `ctf{`. Letters use a single Caesar shift; punctuation is unchanged.

## Files

- [Challenge source](challenge.py)
- [Ciphertext](output.txt)
- [Solve script](solve.py)

Keep original attachments in this folder (or an `attachments/` subfolder). Use relative links so readers can download them from the article or browse them on GitHub.

## First observations

The ciphertext starts with `jam{`. Braces and underscores survived, so the transformation probably affects only letters. The known prefix gives us a quick way to identify the shift.

For longer challenges, explain the relevant source code and assumptions here. Include just the excerpt needed to understand the weakness.

## The weakness

A Caesar cipher adds a fixed value modulo 26. Numbering letters from zero:

$$
c_i = (m_i + k) \bmod 26.
$$

The first known letter is `c` (2), and the first encrypted letter is `j` (9), giving:

$$
k = (9 - 2) \bmod 26 = 7.
$$

Subtracting 7 recovers the plaintext. Even without a known prefix, there are only 26 possible shifts.

## Solve

The solver tries each shift and selects plaintexts with the expected flag prefix. It reads `output.txt` relative to its own location, so the command works from any directory. It needs Python 3 and no third-party packages.

```python
from pathlib import Path

ciphertext = Path(__file__).with_name("output.txt").read_text().strip()
for shift in range(26):
    plaintext = "".join(
        chr((ord(c) - ord("a") - shift) % 26 + ord("a"))
        if "a" <= c <= "z" else c
        for c in ciphertext
    )
    if plaintext.startswith("ctf{"):
        print(f"shift={shift}: {plaintext}")
```

From the repository root:

```sh
python3 _writeups/example-caesar/solve.py
```

Expected output:

```text
shift=7: ctf{small_shifts_big_lessons}
```

## Flag

```text
ctf{small_shifts_big_lessons}
```

## Takeaway

A small key space makes exhaustive search practical. A predictable plaintext prefix also exposes the key directly.

For real challenges, finish with the general lesson, the conditions required for the attack, and links to any papers, documentation, or techniques used. Distinguish verified results from ideas you have not tested.
