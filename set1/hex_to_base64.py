INPUT_HEX_STRING = "49276d206b696c6c696e6720796f757220627261696e206c696" + \
                   "b65206120706f69736f6e6f7573206d757368726f6f6d"
RESULT = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

BASE64_SYMBOLS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0" + \
                 "123456789+/"
HEX_SYMBOLS = "0123456789abcdef"

def hex_to_base64(hex_string):
    if(len(hex_string) % 2 != 0):
        return None
    base64_string = ""
    for i in range(0, len(hex_string), 6):
        bits = 0x00000000
        for (shift, c) in enumerate(hex_string[i:i+6]):
            bits += (int(c, 16) << 4 * (5 - shift))                
        buffer = ""
        mask = 0b111111 << 18
        amount = len(hex_string[i : i+6]) // 2 + 1
        for pos in range(0, amount):
            pos = (bits & mask) / (mask / 0b111111)
            base64_string += BASE64_SYMBOLS[pos]
            mask >>= 6
        for pos in range(amount, 4):
            base64_string += "="
    return base64_string


def base64_to_text(base64_string):
    if len(base64_string) % 4 != 0:
        return None
    text = ""
    byte_amount = 3
    for i in range(0, len(base64_string), 4):
        slice = base64_string[i:i+4]
        bits = 0x00000000
        for (shift, c) in enumerate(slice):
            try:
                if c == '=':
                    byte_amount = slice.index(c) - 1
                    break
                else:
                    code = BASE64_SYMBOLS.index(c)
            except:
                return None
            bits += (code << 6 * (3 - shift))
        for shift in range(0, byte_amount):
            byte = bits & (0xff << (2 - shift) * 8)
            byte >>= (2 - shift) * 8
            text += chr(byte)
    return text


def text_to_hex(text):
    hex_string = ""
    for c in text:
        byte = ord(c)
        hex_string += HEX_SYMBOLS[(byte & 0xf0) >> 4]
        hex_string += HEX_SYMBOLS[byte & 0x0f]
    return hex_string


def hex_to_text(hex_string):
    if len(hex_string) % 2 != 0:
        return None
    text = ""
    for i in range(0, len(hex_string), 2):
        byte = 0
        byte += int(hex_string[i], 16) << 4
        byte += int(hex_string[i+1], 16)
        text += chr(byte)
    return text


# main block

if __name__ == '__main__':
    base64_string = hex_to_base64(INPUT_HEX_STRING)
    print("Program result: " + base64_string)
    print("Required result: " + RESULT)
