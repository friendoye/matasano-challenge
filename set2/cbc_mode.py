from cryptography.hazmat.primitives.ciphers import Cipher, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.algorithms import AES

import os

from ..set1.hex_to_base64 import base64_to_text
from pkcs7_padding_validation import validate_pkcs7
from ..set1.fixed_xor import fixed_xor

def aes_128_cbc_decrypt(iv, cipher, key):
    if len(iv) != 16 or len(key) != 16:
        return None
    if len(cipher) % 16 != 0:
        return None

    aes_128 = Cipher(AES(key), modes.ECB(), backend=default_backend())
    decryptor = aes_128.decryptor()

    message = ""
    prev_encrypted_block = iv
    blocks_amount = len(cipher) // 16
    for i in range(0, blocks_amount):
        curr_encrypted_block = cipher[i*16:(i+1)*16]
        decrypted_block = decryptor.update(curr_encrypted_block)
        decrypted_block = fixed_xor(prev_encrypted_block, decrypted_block)
        message += decrypted_block
        prev_encrypted_block = curr_encrypted_block

    return validate_pkcs7(message, 16)


# main block

if __name__ == "__main__":
    path_to_dir = os.path.dirname(__file__) + "/cbc_mode_data/"
    input_file = open(path_to_dir + "ciphertext.txt")
    output_file = open(path_to_dir + "message.txt", "w")
    ciphertext = ""
    iv = '\x00' * 16

    for base64_string in input_file:
        ciphertext += base64_to_text(base64_string.rstrip())

    message = aes_128_cbc_decrypt(iv, ciphertext, "YELLOW SUBMARINE")
    output_file.write(message)

    print("Done.")

    input_file.close()
    output_file.close()
