from ecb_cbc_detection import aes_128_ecb_encrypt, rand_aes_128_block
from ..set1.hex_to_base64 import base64_to_text
from ..set1.detect_aes_128_ecb import detect_aes_128_ecb

BASE64_STRING = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28" + \
                "gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IH" + \
                "dhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJI" + \
                "Gp1c3QgZHJvdmUgYnkK"

def one_byte_ecb_decryption(encryption_function, unknown_string, key):
    # discovering block size
    our_string = "A"
    ciphertext = encryption_function(our_string, key)
    block_size = len(ciphertext)
    while True:
        our_string += "A"
        ciphertext = encryption_function(our_string, key)
        if block_size != len(ciphertext):
            block_size = len(our_string)
            break

    if not detect_aes_128_ecb(our_string * 2):
        raise Exception("Encryption function doesn't use ECB.")

    # discovering length of encrypted plaintext
    our_string = ""
    ciphertext = encryption_function(unknown_string, key)
    unknown_length = len(ciphertext)
    while True:
        our_string += "A"
        ciphertext = encryption_function(our_string + unknown_string, key)
        if unknown_length != len(ciphertext):
            unknown_length -= len(our_string)
            break

    input_block = "A" * (block_size-1)

    # crafting cypher blocks for cracking
    ciphertexts = []
    for i in range(0, block_size):
        message = input_block[:block_size - (i+1)] + unknown_string
        ciphertexts.append(encryption_function(message, key))

    # cracking
    revealed_string = ""
    for i in range(0, unknown_length):
        j = i // block_size # position of byte in block
        i = i % block_size  # block's number
        blocks_dict = {}
        for b in range(0, 256):
            our_string = input_block + chr(b)
            cipher_block = encryption_function(our_string, key)
            cipher_block = cipher_block[0 : block_size]
            blocks_dict[cipher_block] = our_string
        retrieved_block = ciphertexts[i][j * block_size : (j+1) * block_size]
        unknown_char = blocks_dict[retrieved_block][-1]
        revealed_string += unknown_char
        input_block = input_block[1:] + unknown_char

    return revealed_string


# main block

if __name__ == "__main__":
    unknown_string = base64_to_text(BASE64_STRING)
    key = rand_aes_128_block()
    result = one_byte_ecb_decryption(aes_128_ecb_encrypt,
                                     unknown_string, key)
    print(result)
