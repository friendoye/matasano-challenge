from ..set2.ecb_cbc_detection import (rand_aes_128_block, 
                                      aes_128_cbc_encrypt)
from ..set2.cbc_mode import aes_128_cbc_decrypt
from ..set1.hex_to_base64 import text_to_hex
from ..set1.fixed_xor import fixed_xor

# encr. and decr. functions

def ad_hoc_cbc_encrypt(plaintext):
    plaintext = plaintext.replace(";", "%25")
    plaintext = plaintext.replace("=", "%3d")
    plaintext = plaintext.replace(" ", "%20")
    plaintext = "comment1=cooking%20MCs;userdata=" + plaintext
    plaintext += ";comment2=%20like%20a%20pound%20of%20bacon"

    iv = ad_hoc_cbc_encrypt.iv
    key = ad_hoc_cbc_encrypt.key
    ciphertext = aes_128_cbc_encrypt(iv, plaintext, key)

    return ciphertext


def ad_hoc_cbc_decrypt(ciphertext):
    iv = ad_hoc_cbc_decrypt.iv
    key = ad_hoc_cbc_decrypt.key
    plaintext = aes_128_cbc_decrypt(iv, ciphertext, key)

    plaintext = plaintext.replace("%25", ";")
    plaintext = plaintext.replace("%3d", "=")
    plaintext = plaintext.replace("%20", " ")

    return plaintext

ad_hoc_cbc_encrypt.key = rand_aes_128_block()
ad_hoc_cbc_decrypt.key = ad_hoc_cbc_encrypt.key

ad_hoc_cbc_encrypt.iv = ad_hoc_cbc_encrypt.key
ad_hoc_cbc_decrypt.iv = ad_hoc_cbc_encrypt.iv

# functions for cracking

def crack_cbc_iv_key(ciphertext):
    if len(ciphertext) % 16 != 0 or len(ciphertext) // 16 < 3:
        raise Exception("Invalid ciphertext!")

    first_block = ciphertext[:16]
    ciphertext = first_block + '\x00' * 16 + \
                 first_block + ciphertext[48:]

    result = check_ascii_compliance(ciphertext)
    if result == "OK.":
        return None

    # get rid of unnecessary prefix
    result = result[29:]

    key = fixed_xor(result[:16], result[32:48])
    return key


def check_ascii_compliance(ciphertext):
    plaintext = ad_hoc_cbc_decrypt(ciphertext)
    for byte in plaintext:
        if byte > 0x7f:
            return "Error! Noncompliant message: " + plaintext
    return "OK."


# main block

if __name__ == "__main__":
    userdata = "i hope my userdata will not be cracked"
    ciphertext = ad_hoc_cbc_encrypt(userdata)

    print("Secret key is: " + text_to_hex(ad_hoc_cbc_encrypt.key))

    cracked_key = crack_cbc_iv_key(ciphertext)
    if cracked_key == None:
        print("Failed to crack key.")
    else:
        print("Cracked key is: " + text_to_hex(cracked_key))
    