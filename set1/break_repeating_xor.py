import operator
import os

from repeating_xor import repeating_xor
from hex_to_base64 import base64_to_text
from single_byte_xor import single_byte_xor

def evaluate_key_length(cypher):
    slices_amount = 4
    min_key_length = 2
    max_key_length = min(40, len(cypher) // slices_amount)
    max_key_length = 40
    hd_list = [] # hamming distance list
        
    if len(cypher) < slices_amount * min_key_length:
        return None

    pair_list = [(i, j) for i in range(0, slices_amount) 
                        for j in range(0, slices_amount) if i < j]

    for key_length in range(min_key_length, max_key_length + 1):
        slices = []
        for i in range(0, slices_amount):
            slices.append(cypher[i * key_length : (i+1) * key_length])
        distance = 0.0
        for (i, j) in pair_list:
            distance += hamming_distance(slices[i], slices[j])
        distance /= key_length
        hd_list.append((key_length, distance))

    hd_list = sorted(hd_list, key=operator.itemgetter(1))
    hd_list = hd_list[0:5]

    return [pair[0] for pair in hd_list]


def hamming_distance(string1, string2):
    d = 0.0
    for (c1, c2) in zip(string1, string2):
        value = ord(c1) ^ ord(c2)
        for shift in range(0, 8):
            d += value & 0x01
            value >>= 1
    return d


def find_key(cypher, key_length):
    key = ""
    for i in range(0, key_length):
        single_byte_cypher = ""
        for j in range(i, len(cypher), key_length):
            single_byte_cypher += cypher[j]
        message, xor_byte = single_byte_xor(single_byte_cypher)
        key += chr(xor_byte)
    return key


# main block

if __name__ == '__main__':
    path_to_dir = os.path.dirname(__file__) + \
                  "/break_repeating_xor_data/"
    input_file = open(path_to_dir + "cyphertext.txt")
    cyphertext = ""

    while True:
        base64_string = input_file.readline()
        base64_string = base64_string.rstrip()
        if base64_string == "":
            break
        cyphertext += base64_to_text(base64_string)
    
    key_length_list = evaluate_key_length(cyphertext)
    key_list = []
    for key_length in key_length_list:
        key_list.append(find_key(cyphertext, key_length))

    for i in range(0, len(key_list)):
        message = repeating_xor(cyphertext, key_list[i])
        print("Key {0}:'{1}'".format(i+1, key_list[i]))
        file_name = "message{0}.txt".format(i)
        output_file = open(path_to_dir + file_name, "w")
        try:
            output_file.write("Key: " + key_list[i] + "\n")
            output_file.write(message)
        except:
            output_file.close()
            output_file = open(file_name, "w")
            output_file.write("Incorrect message!")
        output_file.close()
