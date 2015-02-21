import os

from hex_to_base64 import text_to_hex

def repeating_xor(string, key):
    xor_string = ""
    key_length = len(key)
    j = 0
    for i in range(0, len(string)):
        byte = ord(string[i]) ^ ord(key[j])
        xor_string += chr(byte)
        if j + 1 == key_length:
            j = 0
        else:
            j = j + 1
    return xor_string


# main block

if __name__ == '__main__':
    path_to_dir = os.path.dirname(__file__) + "/repeating_xor_data/"
    input_file = open(path_to_dir + "input.txt")
    output_hex_file = open(path_to_dir + "hex_output.txt", "w")

    global_key = "ICE"
    buffer_size = 30
    
    while True:
        message = input_file.read(buffer_size)
        if message == "":
            break;
        cyphertext = repeating_xor(message, global_key)
        output_hex_file.write(text_to_hex(cyphertext) + "\n")
        
    print("Done.")

    input_file.close()
    output_hex_file.close()
