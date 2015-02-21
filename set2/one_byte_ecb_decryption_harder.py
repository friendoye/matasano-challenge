from random import randint

from one_byte_ecb_decryption_simple import one_byte_ecb_decryption
from ecb_cbc_detection import rand_aes_128_block, aes_128_ecb_encrypt


# main block

if __name__ == "__main__":
    target_bytes = "password=123456"
    attacker_controlled = "|backdoor|"
    random_prefix = ""
    for __ in range(3):
        random_prefix += rand_aes_128_block()
    random_prefix = random_prefix[:-1 * randint(0, 18)]

    key = rand_aes_128_block()
    unknown_string = random_prefix + attacker_controlled + target_bytes
    result = one_byte_ecb_decryption(aes_128_ecb_encrypt,
                                     unknown_string, key)

    index = result.find(attacker_controlled)
    result = result[index + len(attacker_controlled):]
    print("Cracked target-bytes: " + result)
