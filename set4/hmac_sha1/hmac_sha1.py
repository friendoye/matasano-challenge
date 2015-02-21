import time

from ..sha1_keyed_mac import sha1
from ...set1.fixed_xor import fixed_xor
from ...set1.hex_to_base64 import hex_to_text

def hmac_sha1(message, key):
    block_size = 64
    key = key[:block_size] + '\x00' * (block_size - len(key))

    ipad = '\x36' * block_size
    sha1_prefix = fixed_xor(key, ipad)
    first_sha1_digest = sha1(sha1_prefix + message)

    opad = '\x5c' * block_size
    sha1_prefix = fixed_xor(key, opad)
    first_sha1_digest = hex_to_text(first_sha1_digest)

    return sha1(sha1_prefix + first_sha1_digest)


def insecure_compare(signature1, signature2, sleep_time):
    if len(signature1) != len(signature2):
        return False
    for (byte1, byte2) in zip(signature1, signature2):
        if byte1 != byte2:
            return False
        time.sleep(sleep_time / 1000.0)
    return True


# main block

if __name__ == "__main__":
    secret_key = "\x70\x71\x72\x73\x74\x75\x76\x77\x78\x79" + \
                 "\x7a\x7b\x7c\x7d\x7e\x7f\x80\x81\x82\x83"
    signature = hmac_sha1("Hello World", secret_key)
    print("HMAC-SHA1: " + signature)
