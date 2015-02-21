from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.algorithms import AES

import os

from hex_to_base64 import base64_to_text

KEY = "YELLOW SUBMARINE"

def aes_128_ecb_decrypt(cipher, key):
    if len(cipher) % 16 != 0:
        return None

    aes_128 = Cipher(AES(key), modes.ECB(), backend=default_backend())
    decryptor = aes_128.decryptor()

    return decryptor.update(cipher)


# main block

if __name__ == "__main__":
    path_to_dir = os.path.dirname(__file__) + "/aes_128_ecb_data/"
    input_file = open(path_to_dir + "ciphertext.txt")
    output_file = open(path_to_dir + "message.txt", "w")
    ciphertext = ""

    while True:
        base64_string = input_file.readline()
        base64_string = base64_string.rstrip()
        if base64_string == "":
            break
        ciphertext += base64_to_text(base64_string)

    message = aes_128_ecb_decrypt(ciphertext, KEY)
    output_file.write(message)

    print("Done.")

    input_file.close()
    output_file.close()
