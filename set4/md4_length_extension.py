from random import randint

from sha1_keyed_mac import int32_to_hex, int64_to_text, text_to_int

# md4 and friends

def md4_pad(message, size):
    message += '\x00'

    last_block_len = size % 512
    pos = size // 8
    shift = 8 - (size % 8)
    last_byte = ord(message[pos])

    last_byte &= 0xff << shift
    last_byte ^= 0x01 << (shift - 1)
    message = message[:pos] + chr(last_byte)

    last_block_len = (len(message) * 8) % 512
    if last_block_len <= 448:
        message += "\x00" * ((448 - last_block_len) // 8)
    else:
        message += "\x00" * ((448 + 512 - last_block_len) // 8)

    encoded_size = int64_to_text(size)
    message += encoded_size[::-1]

    return message


def convert_to_little_endian(number):
    result = 0x00
    while number > 0:
        result = (result << 8) + number % 256
        number /= 256
    return result


def md4(message, size=-1):
    # size is measured in bits
    if size == -1 or size > len(message) * 8:
        size = len(message) * 8

    h0 = 0x67452301
    h1 = 0xefcdab89
    h2 = 0x98badcfe
    h3 = 0x10325476

    message = md4_pad(message, size)
    block_amount = len(message) // 64
    for i in range(block_amount):
        block = message[i * 64 : (i+1) * 64]
        M = []
        for t in range(16):
            M0 = text_to_int(block[t * 4 : (t+1) * 4])
            M0 = convert_to_little_endian(M0)
            M.append(M0)

        a, b, c, d = h0, h1, h2, h3

        S = [3, 7, 11, 19]
        for i in range(16):
            t = i
            s = S[i % len(S)]
            # transform
            f = (b & c) | (~b & d)
            a = a + f + M[t]
            # cyclic shift to the left by s
            low_mask = 0xffffffff >> s
            high_mask = 0xffffffff ^ low_mask
            a = ((a & high_mask) >> (32 - s)) + ((a & low_mask) << s)
            # blocks shift
            b, c, d, a = a, b, c, d

        S = [3, 5, 9, 13]
        T = [0, 4, 8, 12,
             1, 5, 9, 13,
             2, 6, 10, 14,
             3, 7, 11, 15]
        for i in range(16):
            t = T[i]
            s = S[i % len(S)]
            # transform
            f = (b & c) | (b & d) | (c & d)
            a = a + f + M[t] + 0x5a827999
            # cyclic shift to the left by s
            low_mask = 0xffffffff >> s
            high_mask = 0xffffffff ^ low_mask
            a = ((a & high_mask) >> (32 - s)) + ((a & low_mask) << s)
            # blocks shift
            b, c, d, a = a, b, c, d

        S = [3, 9, 11, 15]
        T = [0, 8, 4, 12,
             2, 10, 6, 14,
             1, 9, 5, 13,
             3, 11, 7, 15]
        for i in range(16):
            t = T[i]
            s = S[i % len(S)]
            # transform
            f = b ^ c ^ d
            a = a + f + M[t] + 0x6ed9eba1
            # cyclic shift to the left by s
            low_mask = 0xffffffff >> s
            high_mask = 0xffffffff ^ low_mask
            a = ((a & high_mask) >> (32 - s)) + ((a & low_mask) << s)
            # blocks shift
            b, c, d, a = a, b, c, d

        h0 += a
        h1 += b
        h2 += c
        h3 += d

    hash = ""
    for h in [h0, h1, h2, h3]:
        h = convert_to_little_endian(h & 0xffffffff)
        hash += int32_to_hex(h)

    return hash

# md4 length extension attack func.

def md4_length_extension_attack(md, get_digest_func,
                                original_message,
                                new_message):
    int32_dict = {}
    int32_number = int(md[0:8], 16)
    int32_dict["h0"] = convert_to_little_endian(int32_number)
    int32_number = int(md[8:16], 16)
    int32_dict["h1"] = convert_to_little_endian(int32_number)
    int32_number = int(md[16:24], 16)
    int32_dict["h2"] = convert_to_little_endian(int32_number)
    int32_number = int(md[24:32], 16)
    int32_dict["h3"] = convert_to_little_endian(int32_number)

    message = ""
    found_padding_key = False
    for t in range(100):
        message = "\x00" * t + original_message
        message = md4_pad(message, len(message) * 8)
        pb_amount = len(message) // 64
        message = message[t:]

        hash1 = get_digest_func(message)
        hash2 = md4_with_fixed_int32("", prev_blocks_amount=pb_amount,
                                     **int32_dict)

        if hash1 == hash2:
            found_padding_key = True
            break

    if not found_padding_key:
        raise Exception("Can't forge hash. Sorry.")

    forged_hash = get_digest_func(message + new_message)
    glue_padding = message[len(original_message):]

    return forged_hash, glue_padding


def md4_with_fixed_int32(message, size=-1, prev_blocks_amount=0, **arg_dict):
    # size is measured in bits
    if size == -1 or size > len(message) * 8:
        size = len(message) * 8

    try:
        h0 = arg_dict["h0"]
        h1 = arg_dict["h1"]
        h2 = arg_dict["h2"]
        h3 = arg_dict["h3"]
    except:
        raise Exception("There are not all int32 values.")

    message = "\x00" * 64 * prev_blocks_amount + message
    size += prev_blocks_amount * 512

    message = md4_pad(message, size)
    message = message[64 * prev_blocks_amount:]

    block_amount = len(message) // 64
    for i in range(block_amount):
        block = message[i * 64 : (i+1) * 64]
        M = []
        for t in range(16):
            M0 = text_to_int(block[t * 4 : (t+1) * 4])
            M0 = convert_to_little_endian(M0)
            M.append(M0)

        a, b, c, d = h0, h1, h2, h3

        S = [3, 7, 11, 19]
        for i in range(16):
            t = i
            s = S[i % len(S)]
            # transform
            f = (b & c) | (~b & d)
            a = a + f + M[t]
            # cyclic shift to the left by s
            low_mask = 0xffffffff >> s
            high_mask = 0xffffffff ^ low_mask
            a = ((a & high_mask) >> (32 - s)) + ((a & low_mask) << s)
            # blocks shift
            b, c, d, a = a, b, c, d

        S = [3, 5, 9, 13]
        T = [0, 4, 8, 12,
             1, 5, 9, 13,
             2, 6, 10, 14,
             3, 7, 11, 15]
        for i in range(16):
            t = T[i]
            s = S[i % len(S)]
            # transform
            f = (b & c) | (b & d) | (c & d)
            a = a + f + M[t] + 0x5a827999
            # cyclic shift to the left by s
            low_mask = 0xffffffff >> s
            high_mask = 0xffffffff ^ low_mask
            a = ((a & high_mask) >> (32 - s)) + ((a & low_mask) << s)
            # blocks shift
            b, c, d, a = a, b, c, d

        S = [3, 9, 11, 15]
        T = [0, 8, 4, 12,
             2, 10, 6, 14,
             1, 9, 5, 13,
             3, 11, 7, 15]
        for i in range(16):
            t = T[i]
            s = S[i % len(S)]
            # transform
            f = b ^ c ^ d
            a = a + f + M[t] + 0x6ed9eba1
            # cyclic shift to the left by s
            low_mask = 0xffffffff >> s
            high_mask = 0xffffffff ^ low_mask
            a = ((a & high_mask) >> (32 - s)) + ((a & low_mask) << s)
            # blocks shift
            b, c, d, a = a, b, c, d

        h0 += a
        h1 += b
        h2 += c
        h3 += d

    hash = ""
    for h in [h0, h1, h2, h3]:
        h = convert_to_little_endian(h & 0xffffffff)
        hash += int32_to_hex(h)

    return hash


# main block

if __name__ == "__main__":
    key = ""
    for _ in range(randint(0, 100)):
        key += chr(randint(0, 255))

    original_message = "comment1=cooking%20MCs;userdata=foo;" + \
                       "comment2=%20like%20a%20pound%20of%20bacon"
    new_message = ";admin=true"

    get_digest = lambda message: md4(key + message)
    original_digest = get_digest(original_message)

    result = md4_length_extension_attack(original_digest, get_digest,
                                         original_message,
                                         new_message)

    forged_hash, glue_padding = result
    right_hash = md4(key + original_message + glue_padding + new_message)

    print("Right access hash: " + right_hash)
    print("Forged hash: " + forged_hash)
