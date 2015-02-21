import time
from random import randint
from math import ceil

from mt19937 import init_mt19937, rand
from ..set1.fixed_xor import fixed_xor

def mt19937_stream_cipher_function(stream, seed):
    init_mt19937(seed)
    numbers_amount = int(ceil(len(stream) / 4.0))

    keystream = ""
    for _ in range(numbers_amount):
        prn = rand()
        keystream += chr((prn & 0xff000000) >> 24)
        keystream += chr((prn & 0x00ff0000) >> 16)
        keystream += chr((prn & 0x0000ff00) >> 8)
        keystream += chr(prn & 0x000000ff)
    keystream = keystream[:len(stream)]

    return fixed_xor(stream, keystream)


def crack_mt19937_stream_cipher(ciphertext):
    known_bytes = "A" * 14
    for seed in range(0xffff):
        plaintext = mt19937_stream_cipher_function(ciphertext, seed)
        if plaintext[-14:] == known_bytes:
            return seed
    return None


def gen_password_reset_token(given_time=-1):
    if given_time == -1:
        seed = int(time.time() * 1000.0)
    else:
        seed = given_time
    init_mt19937(seed)
    prn = rand()

    token = str(hex(prn))
    token = token[2:]
    token = token.upper()

    return seed, token[:4] + '-' + token[4:]


def check_password_reset_token(token, given_time):
    return gen_password_reset_token(given_time)[1] == token


# main block

if __name__ == "__main__":
    # stream cipher block
    seed = randint(0, 0xffff)
    print("Randomed seed: " + str(seed))

    plaintext = "A" * 14
    for _ in range(randint(10, 100)):
        plaintext = chr(randint(65, 122)) + plaintext
    print("Initial plaintext: " + plaintext)

    ciphertext = mt19937_stream_cipher_function(plaintext, seed)

    seed = crack_mt19937_stream_cipher(ciphertext)
    print("Cracked seed: " + str(seed))

    plaintext = mt19937_stream_cipher_function(ciphertext, seed)
    print("Cracked plaintext: " + plaintext)

    print("\n========================================\n")

    # password reset token block
    current_time, password_token = gen_password_reset_token()
    print(password_token)

    flag = check_password_reset_token(password_token, current_time)
    print("Password check: " + str(flag))
