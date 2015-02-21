from random import randint

from sha1_keyed_mac import sha1, sha1_pad, text_to_int, int32_to_hex

def sha1_length_extension_attack(md, get_digest_func,
                                 original_message,
                                 new_message):
    int32_dict = {}
    int32_dict["h0"] = int(md[0:8], 16)
    int32_dict["h1"] = int(md[8:16], 16)
    int32_dict["h2"] = int(md[16:24], 16)
    int32_dict["h3"] = int(md[24:32], 16)
    int32_dict["h4"] = int(md[32:40], 16)

    message = ""
    found_padding_key = False
    for t in range(100):
        message = "\x00" * t + original_message
        message = sha1_pad(message, len(message) * 8)
        pb_amount = len(message) // 64
        message = message[t:]

        hash1 = get_digest_func(message)
        hash2 = sha1_with_fixed_int32("", prev_blocks_amount=pb_amount,
                                      **int32_dict)

        if hash1 == hash2:
            found_padding_key = True
            break

    if not found_padding_key:
        raise Exception("Can't forge hash. Sorry.")

    forged_hash = get_digest_func(message + new_message)
    glue_padding = message[len(original_message):]

    return forged_hash, glue_padding


def sha1_with_fixed_int32(message, size=-1, prev_blocks_amount=0, **arg_dict):
    # size is measured in bits
    if size == -1 or size > len(message) * 8:
        size = len(message) * 8

    try:
        h0 = arg_dict["h0"]
        h1 = arg_dict["h1"]
        h2 = arg_dict["h2"]
        h3 = arg_dict["h3"]
        h4 = arg_dict["h4"]
    except:
        raise Exception("There are not all int32 values.")

    message = "\x00" * 64 * prev_blocks_amount + message
    size += prev_blocks_amount * 512

    message = sha1_pad(message, size)
    message = message[64 * prev_blocks_amount:]

    block_amount = len(message) // 64
    for i in range(block_amount):
        block = message[i * 64 : (i+1) * 64]
        W = []
        for t in range(16):
            W0 = text_to_int(block[t * 4 : (t+1) * 4])
            W.append(W0)
        for t in range(16, 80):
            W0 = W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]
            # cyclic shift to the left by 1
            W0 = ((W0 & 0x80000000) >> 31) + ((W0 << 1) & 0xffffffff)
            W.append(W0)

        a, b, c, d, e = h0, h1, h2, h3, h4

        for t in range(80):
            if t in range(20):
                f = (b & c) | (~b & d)
                k = 0x5a827999
            elif t in range(20, 40):
                f = b ^ c ^ d
                k = 0x6ed9eba1
            elif t in range(40, 60):
                f = (b & c) | (b & d) | (c & d)
                k = 0x8f1bbcdc
            elif t in range(60, 80):
                f = b ^ c ^ d
                k = 0xca62c1d6

            temp = ((a & 0xf8000000) >> 27) + ((a << 5) & 0xffffffff)
            temp += f + e + W[t] + k

            e = d
            d = c
            c = ((b & 0xfffffffc) >> 2) + ((b << 30) & 0xffffffff)
            b = a
            a = temp & 0xffffffff

        h0 += a
        h1 += b
        h2 += c
        h3 += d
        h4 += e

    hash = int32_to_hex(h0)
    hash += int32_to_hex(h1)
    hash += int32_to_hex(h2)
    hash += int32_to_hex(h3)
    hash += int32_to_hex(h4)

    return hash


# main block

if __name__ == "__main__":
    key = ""
    for __ in range(randint(0, 100)):
        key += chr(randint(0, 255))

    original_message = "comment1=cooking%20MCs;userdata=foo;" + \
                       "comment2=%20like%20a%20pound%20of%20bacon"
    new_message = ";admin=true"

    get_digest = lambda message: sha1(key + message)
    original_digest = get_digest(original_message)

    result = sha1_length_extension_attack(original_digest, get_digest,
                                          original_message,
                                          new_message)

    forged_hash, glue_padding = result
    right_hash = sha1(key + original_message + glue_padding + new_message)

    print("Right access hash: " + right_hash)
    print("Forged hash: " + forged_hash)
