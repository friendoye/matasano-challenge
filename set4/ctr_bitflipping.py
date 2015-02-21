from random import randint

from ..set2.ecb_cbc_detection import rand_aes_128_block
from ..set1.fixed_xor import fixed_xor
from ..set3.ctr_mode import ctr_function

def ctr_bitflip(ciphertext, old_text, new_text, offset):
    min_length = min(len(old_text), len(new_text))
    old_text = old_text[:min_length]
    new_text = new_text[:min_length]

    mask = fixed_xor(old_text, new_text)
    new_block = ciphertext[offset:]
    new_block = new_block[:min_length]
    new_block = fixed_xor(new_block, mask)

    ciphertext_length = len(ciphertext)
    try:
        ciphertext = ciphertext[:offset] + \
                     new_block + \
                     ciphertext[offset + min_length:]
    except:
        raise Exception("Incorrect parameters!")

    return ciphertext[:ciphertext_length]

# encr. and decr. functions

def ad_hoc_ctr_encrypt(plaintext):
    plaintext = plaintext.replace(";", "%25")
    plaintext = plaintext.replace("=", "%3d")
    plaintext = plaintext.replace(" ", "%20")
    plaintext = "comment1=cooking%20MCs;userdata=" + plaintext
    plaintext += ";comment2=%20like%20a%20pound%20of%20bacon"

    nonce = ad_hoc_ctr_encrypt.nonce
    key = ad_hoc_ctr_encrypt.key
    ciphertext = ctr_function(nonce, plaintext, key)

    return ciphertext


def ad_hoc_ctr_decrypt(ciphertext):
    nonce = ad_hoc_ctr_decrypt.nonce
    key = ad_hoc_ctr_decrypt.key
    plaintext = ctr_function(nonce, ciphertext, key)

    kv_list = plaintext.split(';')
    tokens_dict = {}
    for kv in kv_list:
        key, value = kv.split('=')
        value = value.replace("%25", ";")
        value = value.replace("%3d", "=")
        value = value.replace("%20", " ")
        tokens_dict[key] = value

    is_admin = (tokens_dict.has_key("admin") and 
                tokens_dict["admin"] == "true")

    return is_admin

ad_hoc_ctr_encrypt.key = rand_aes_128_block()
ad_hoc_ctr_decrypt.key = ad_hoc_ctr_encrypt.key

ad_hoc_ctr_encrypt.nonce = randint(0, 2**64 - 1)
ad_hoc_ctr_decrypt.nonce = ad_hoc_ctr_encrypt.nonce


# main block

if __name__ == "__main__":
    userdata = "aha;admin=true"
    ciphertext = ad_hoc_ctr_encrypt(userdata)

    is_admin = ad_hoc_ctr_decrypt(ciphertext)
    print("Successful attack with bad userdata: " + str(is_admin))

    old_text = ";comment2=%20like%20a%20pound%20of%20bacon"
    new_text = ";admin=true;comment2=%20like%20a%20driving"
    ciphertext = ctr_bitflip(ciphertext, old_text, new_text,
                             -1 * len(old_text))

    is_admin = ad_hoc_ctr_decrypt(ciphertext)
    print("Successful bitflipping: " + str(is_admin))
