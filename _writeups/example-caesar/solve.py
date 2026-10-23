"""Recover the toy flag. Run with Python 3; no dependencies."""
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
