import operator

from fixed_xor import fixed_xor
from hex_to_base64 import hex_to_text

FREQUENT_SYMBOLS = "etaoin shrdlu"
FREQUENT_BYTES = [ord(c) for c in FREQUENT_SYMBOLS]

def single_byte_xor(string):
    frequency_dict = {}
    for c in string:
        byte = ord(c)
        if byte in frequency_dict:
            frequency_dict[byte] += 1
        else:
            frequency_dict[byte] = 1
    frequency_list = sorted(frequency_dict.items(), \
                            key=operator.itemgetter(1), reverse=True)
    frequency_list = frequency_list[0:len(FREQUENT_BYTES)]
    byte_list = [pair[0] for pair in frequency_list]    

    xor_byte, best_score = 0, evaluate_encryption(byte_list, 0)
    for byte in range(1, 256):
        local_score = evaluate_encryption(byte_list, byte)
        if local_score > best_score:
            xor_byte, best_score = byte, local_score

    key = chr(xor_byte) * len(string)
    message = fixed_xor(string, key)

    return message, xor_byte


def evaluate_encryption(byte_list, xor_byte):
    byte_list = [byte ^ xor_byte for byte in byte_list]
    score = 0
    for i in range(0, len(byte_list)):
        byte = byte_list[i]
        if byte in FREQUENT_BYTES:
            score += abs(FREQUENT_BYTES.index(byte) - i)
        else:
            score += len(byte_list) - i
    return (-1) * score


# main block

if __name__ == '__main__':    
    cyphertext = "1b37373331363f78151b7f2b783431333d" + \
                 "78397828372d363c78373e783a393b3736"
    cyphertext = hex_to_text(cyphertext)
    message, xor_byte = single_byte_xor(cyphertext)
    print(message)
