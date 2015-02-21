from hex_to_base64 import hex_to_text, text_to_hex

STRING1 = "1c0111001f010100061a024b53535009181c"
STRING2 = "686974207468652062756c6c277320657965"
RESULT = "746865206b696420646f6e277420706c6179"

def fixed_xor(string1, string2):
    if len(string1) != len(string2):
        return None
    xor_string = ""
    for (c1, c2) in zip(string1, string2):
        code = ord(c1) ^ ord(c2)
        xor_string += chr(code)
    return xor_string


# main block

if __name__ == '__main__':
    string1 = hex_to_text(STRING1)
    string2 = hex_to_text(STRING2)
    xor_string = fixed_xor(string1, string2)
    print("Program result: " + text_to_hex(xor_string))
    print("Required result: " + text_to_hex(xor_string))
    