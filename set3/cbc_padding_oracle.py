from random import randint

from ..set1.hex_to_base64 import base64_to_text
from ..set2.ecb_cbc_detection import (rand_aes_128_block, 
                                      aes_128_cbc_encrypt)
from ..set2.cbc_mode import aes_128_cbc_decrypt
from ..set1.fixed_xor import fixed_xor
from ..set2.pkcs7_padding_validation import validate_pkcs7

BASE64_STRINGS = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
                  "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRo" + \
                  "ZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
                  "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9p" + \
                  "bnQsIG5vIGZha2luZw==",
                  "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBi" + \
                  "YWNvbg==",
                  "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWlj" + \
                  "ayBhbmQgbmltYmxl",
                  "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJh" + \
                  "bA==",
                  "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1" + \
                  "cCB0ZW1wbw==",
                  "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdv" + \
                  "IHNvbG8=",
                  "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
                  "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWly" + \
                  "IGNhbiBibG93"]

# encr. and decr. functions

def cbc_padding_oracle_encrypt():
    index = randint(0, len(BASE64_STRINGS) - 1)
    message = base64_to_text(BASE64_STRINGS[index])
    iv = rand_aes_128_block()
    key = cbc_padding_oracle_encrypt.key

    ciphertext = aes_128_cbc_encrypt(iv, message, key)

    return iv, ciphertext


def cbc_padding_oracle_decrypt(iv, ciphertext):
    key = cbc_padding_oracle_decrypt.key
    try:
        aes_128_cbc_decrypt(iv, ciphertext, key)
    except:
        return False
    return True

cbc_padding_oracle_encrypt.key = rand_aes_128_block()
cbc_padding_oracle_decrypt.key = cbc_padding_oracle_encrypt.key

# attack function

def cbc_padding_oracle_attack(iv, ciphertext):
    if len(iv) != 16 or len(ciphertext) % 16 != 0:
        return None

    ciphertext = iv + ciphertext

    plaintext = ""
    blocks_amount = len(ciphertext) // 16
    for i in range(blocks_amount, 1, -1):
        plaintext_block = ""
        prev_block = ciphertext[(i-2) * 16 : (i-1) * 16]
        changable_block = ciphertext[(i-1) * 16 : i * 16]
        for j in range(1, 17):
            tale_string = fixed_xor(plaintext_block, chr(j) * (j-1))
            change_byte = True
            for b in range(1, 256):
                xor_block = '\x00' * (16-j) + chr(b) + tale_string
                fake_iv = fixed_xor(xor_block, prev_block)
                if cbc_padding_oracle_decrypt(fake_iv, changable_block):
                    plaintext_block = chr(j ^ b) + plaintext_block
                    change_byte = False
                    break
            if change_byte:
                plaintext_block = chr(j) + plaintext_block
        plaintext = plaintext_block + plaintext

    return validate_pkcs7(plaintext, 16)


# main block

if __name__ == "__main__":
    iv, ciphertext = cbc_padding_oracle_encrypt()
    plaintext = cbc_padding_oracle_attack(iv, ciphertext)
    print(plaintext)
