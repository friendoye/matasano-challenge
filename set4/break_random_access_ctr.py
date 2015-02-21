import os
from random import randint

from ..set3.ctr_mode import ctr_function
from ..set2.ecb_cbc_detection import rand_aes_128_block
from ..set1.fixed_xor import fixed_xor

PATH = os.path.dirname(__file__) + \
       "\\..\\set1\\aes_128_ecb_data\\message.txt"
DELIMITER = 100

def edit(ciphertext, key, nonce, offset, text):
    plaintext = ctr_function(nonce, ciphertext, key)
    plaintext = plaintext[:offset] + \
                text + \
                plaintext[offset + len(text):]
    return ctr_function(nonce, plaintext, key)


# main block

if __name__ == "__main__":
    plaintext = ""
    with open(PATH) as input_file:
        plaintext += input_file.read()
    print("Original plaintext: {0} ...".format(plaintext[:DELIMITER]))

    key = rand_aes_128_block()
    nonce = randint(0, 2**64 - 1)
    ciphertext = ctr_function(nonce, plaintext, key)

    edit_without_key = lambda c, off, text: edit(c, key,
                                                 nonce, off, text)
    new_text = '\x00' * len(ciphertext)
    keystream = edit_without_key(ciphertext, 0, new_text)
    plaintext = fixed_xor(ciphertext, keystream)

    print("Recovered plaintext: {0} ...".format(plaintext[:DELIMITER]))
