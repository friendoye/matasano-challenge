import os

from hex_to_base64 import hex_to_text

def detect_aes_128_ecb(string):
    block_size = 16
    blocks = []
    for i in range(0, len(string), block_size):
        blocks.append(string[i: i + block_size])    
    pair_list = [(i, j) for i in range(0, len(blocks)) 
                        for j in range(0, len(blocks)) if i < j]
    for (i, j) in pair_list:
        if blocks[i] == blocks[j]:
            return True
    return False


# main block

if __name__ == "__main__":
    path_to_dir = os.path.dirname(__file__) + \
                  "/detect_aes_128_ecb_data/"
    input_hex_file = open(path_to_dir + "ciphertexts.txt")
    output_hex_file = open(path_to_dir + "aes_ciphertexts.txt", "w")

    for hex_string in input_hex_file:
        string = hex_to_text(hex_string.rstrip())
        if detect_aes_128_ecb(string):
            output_hex_file.write(hex_string + "\n")

    print("Done.")

    input_hex_file.close()
    output_hex_file.close()
