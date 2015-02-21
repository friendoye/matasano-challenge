import os

from ctr_mode import ctr_function
from ..set2.ecb_cbc_detection import rand_aes_128_block
from ..set1.hex_to_base64 import base64_to_text
from ..set1.fixed_xor import fixed_xor
from ..set1.break_repeating_xor import find_key

def break_ctr_with_fixed_nonce(ciphertexts):
    min_length = len(min(ciphertexts, key=len))
    ciphertexts = [string[:min_length] for string in ciphertexts]

    repeating_xor_string = "".join(ciphertexts)
    keystream = find_key(repeating_xor_string, min_length)

    return [fixed_xor(keystream, string) for string in ciphertexts]


# main block

if __name__ == "__main__":
    ciphertexts = []
    nonce = 0
    key = rand_aes_128_block()
    path_to_dir = os.path.dirname(__file__) + \
                  "/break_fixed_nonce_ctr_stat_data/"
    with open(path_to_dir + "original_plaintexts.txt") as input_file:
        for base64_string in input_file:
            plaintext = base64_to_text(base64_string.rstrip())
            ciphertext = ctr_function(nonce, plaintext, key)
            ciphertexts.append(ciphertext)

    plaintexts = break_ctr_with_fixed_nonce(ciphertexts)

    with open(path_to_dir + "cracked_plaintexts.txt", "w") as output_file:
        for string in plaintexts:
            output_file.write(string + "\n")

    print("Done.")
