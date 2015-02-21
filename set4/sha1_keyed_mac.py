from ..set2.ecb_cbc_detection import rand_aes_128_block

def text_to_int(string):
    number = 0x00
    for byte in string:
        byte = ord(byte)
        number = (number << 8) + byte
    return number


def int32_to_hex(number):
    hex_string = ""
    for __ in range(8):
        byte = number % 16
        hex_string = hex(byte)[2] + hex_string
        number /= 16
    return hex_string


def int64_to_text(number):
    string = ""
    for __ in range(8):
        byte = number % 256
        string = chr(byte) + string
        number /= 256
    return string


def sha1_pad(message, size):
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

    message += int64_to_text(size)

    return message


def sha1(message, size=-1):
    # size is measured in bits
    if size == -1 or size > len(message) * 8:
        size = len(message) * 8

    h0 = 0x67452301
    h1 = 0xefcdab89
    h2 = 0x98badcfe
    h3 = 0x10325476
    h4 = 0xc3d2e1f0

    message = sha1_pad(message, size)

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
    key = rand_aes_128_block()
    original_message = ""
    print("Message: \'{0}\'".format(original_message))
    sha1_hash = sha1(original_message)
    print("SHA-1: " + sha1_hash)
