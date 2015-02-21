from ecb_cbc_detection import rand_aes_128_block, aes_128_cbc_encrypt
from cbc_mode import aes_128_cbc_decrypt
from ..set1.fixed_xor import fixed_xor

def cbc_bitflip(ciphertext, changed_block):
    if len(changed_block) != 16:
        return None

    block_number = 2

    target_block = ciphertext[(block_number-2) * 16 : (block_number-1) * 16]
    next_block = ciphertext[(block_number-1) * 16 : block_number * 16]

    decr_next_block = "%20MCs;userdata="

    target_block = fixed_xor(target_block, decr_next_block)
    target_block = fixed_xor(target_block, changed_block)

    ciphertext = ciphertext[:(block_number-1) * 16] + \
                 target_block + next_block + \
                 ciphertext[(block_number-2) * 16:]

    return ciphertext

# encr. and decr. functions

def ad_hoc_cbc_encrypt(plaintext):
    plaintext = plaintext.replace(";", "%25")
    plaintext = plaintext.replace("=", "%3d")
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

    kv_list = plaintext.split(';')
    tokens = {}
    for kv in kv_list:
        key, value = kv.split('=')
        tokens[key] = value

    is_admin = tokens.has_key("admin") and tokens["admin"] == "true"

    return is_admin


ad_hoc_cbc_encrypt.key = rand_aes_128_block()
ad_hoc_cbc_decrypt.key = ad_hoc_cbc_encrypt.key

ad_hoc_cbc_encrypt.iv = rand_aes_128_block()
ad_hoc_cbc_decrypt.iv = ad_hoc_cbc_encrypt.iv


# main block

if __name__ == "__main__":
    userdata = "aha;admin=true"
    ciphertext = ad_hoc_cbc_encrypt(userdata)
    ciphertext = cbc_bitflip(ciphertext, ";admin=true;aha=")
    is_admin = ad_hoc_cbc_decrypt(ciphertext)
    print("Successful forgery: " + str(is_admin))
