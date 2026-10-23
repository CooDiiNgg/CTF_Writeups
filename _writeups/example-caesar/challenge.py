"""Original toy challenge; Python 3, standard library only."""
FLAG = "ctf{small_shifts_big_lessons}"
SHIFT = 7


def encrypt(message, shift):
    return "".join(
        chr((ord(c) - ord("a") + shift) % 26 + ord("a"))
        if "a" <= c <= "z" else c
        for c in message
    )


if __name__ == "__main__":
    print(encrypt(FLAG, SHIFT))
