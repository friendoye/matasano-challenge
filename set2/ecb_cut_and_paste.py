from random import randint

from ecb_cbc_detection import rand_aes_128_block, aes_128_cbc_encrypt
from cbc_mode import aes_128_cbc_decrypt

def parse_profile(profile):
    kv_list = profile.split('&')
    tokens = {}
    for kv in kv_list:
        key, value = kv.split('=')
        tokens[key] = value
    return tokens


def profile_for(email):
    if ('&' in email) or ('=' in email):
        raise Exception("Symbols '&' and '=' shouldn't present in email.")

    kv_list = []
    kv_list.append("email=" + email)
    kv_list.append("uid=" + str(randint(0, 0xffffffff)))
    kv_list.append("role=user")

    return "&".join(kv_list)


# main block

if __name__ == "__main__":
    profile = profile_for("example@cryptopals.com")
    key = rand_aes_128_block()
    print(profile)

    iv = rand_aes_128_block()
    ciphertext = aes_128_cbc_encrypt(iv, profile, key)

    profile = aes_128_cbc_decrypt(iv, ciphertext, key)
    tokens = parse_profile(profile)
    print(tokens)
