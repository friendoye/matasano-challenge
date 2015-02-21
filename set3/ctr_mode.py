from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.algorithms import AES

from math import ceil

from ..set1.hex_to_base64 import base64_to_text
from ..set1.fixed_xor import fixed_xor

def int64_to_string(number):
    mask = 0xff
    string = ""
    for shift in range(0, 16, 2):
        byte = (number & (mask << shift)) >> shift
        string += chr(byte)
    return string[::-1]


def ctr_function(nonce, stream, key):
    aes_128 = Cipher(AES(key), modes.ECB(), backend=default_backend())
    encryptor = aes_128.encryptor()

    transformed_stream = ""
    counter = 0
    nonce_string = int64_to_string(nonce)
    blocks_amount = int(ceil(len(stream) / 16.0))
    for i in range(blocks_amount):
        cipher_block = stream[i * 16 : (i+1) * 16]
        key_block = nonce_string + int64_to_string(counter)[::-1]
        key_block = encryptor.update(key_block)
        key_block = key_block[:len(cipher_block)]
        transformed_stream += fixed_xor(key_block, cipher_block)
        counter = counter + 1

    return transformed_stream


# main block

if __name__ == "__main__":
    nonce = 0
    key = "YELLOW SUBMARINE"
    ciphertext = base64_to_text("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY" + \
                                "/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")

    plaintext = ctr_function(nonce, ciphertext, key)
    print(plaintext)
