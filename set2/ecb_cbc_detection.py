from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.algorithms import AES

from random import randint

from pkcs7_padding import pkcs7_pad
from pkcs7_padding_validation import validate_pkcs7
from ..set1.fixed_xor import fixed_xor
from ..set1.detect_aes_128_ecb import detect_aes_128_ecb

def rand_aes_128_block():
    key = ""
    for __ in range(0, 16):
        key += chr(randint(0, 255))
    return key


def append_random_bytes(message):
    before = randint(5, 10)
    after = randint(5, 10)
    for __ in range(0, before):
        message = chr(randint(0, 255)) + message
    for __ in range(0, after):
        message = message + chr(randint(0, 255))
    return message


def aes_128_cbc_encrypt(iv, message, key):
    if len(iv) != 16:
        return None

    message = pkcs7_pad(message, 16)

    aes_128 = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor = aes_128.encryptor()

    block_amount = len(message) // 16
    ciphertext = ""
    prev_block = iv
    for i in range(0, block_amount):
        curr_block = message[i * 16 : (i+1) * 16]
        curr_block = fixed_xor(curr_block, prev_block)
        prev_block = encryptor.update(curr_block)
        ciphertext += prev_block
    return ciphertext


def aes_128_ecb_encrypt(message, key):
    message = pkcs7_pad(message, 16)

    aes_128 = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor = aes_128.encryptor()

    block_amount = len(message) // 16
    ciphertext = ""
    for i in range(0, block_amount):
        curr_block = message[i * 16 : (i+1) * 16]
        ciphertext += encryptor.update(curr_block)
    return ciphertext


def aes_128_ecb_decrypt(message, key):
    if len(message) % 16 != 0 or len(key) != 16:
        return None

    aes_128 = Cipher(AES(key), modes.ECB(), backend=default_backend())
    decryptor = aes_128.decryptor()

    block_amount = len(message) // 16
    text = ""
    for i in range(0, block_amount):
        curr_block = message[i * 16 : (i+1) * 16]
        text += decryptor.update(curr_block)

    return validate_pkcs7(text, 16)


def encryption_oracle(message):
    key = rand_aes_128_block()
    message = append_random_bytes(message)

    ciphertext = ""
    block_mode = None
    choice = randint(0, 1)
    if choice == 0:
        iv = rand_aes_128_block()
        ciphertext = aes_128_cbc_encrypt(iv, message, key)
        block_mode = "CBC"
    else:
        ciphertext = aes_128_ecb_encrypt(message, key)
        block_mode = "ECB"

    return ciphertext, block_mode


# main block

if __name__ == "__main__":
    message = "m" * (16*16 - 5)

    ciphertext, mode_list = encryption_oracle(message)
    print("Encryption mode: " + mode_list)

    if detect_aes_128_ecb(ciphertext):
        print("Detected mode:   ECB")
    else:
        print("Detected mode:   CBC")
    