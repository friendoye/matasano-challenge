import re
import os

from single_byte_xor import single_byte_xor, hex_to_text

# main block

if __name__ == '__main__':
    path_to_dir = os.path.dirname(__file__) + \
                  "/find_single_byte_xor_data/"
    input_file = open(path_to_dir + "cyphertexts.txt")
    output_file = open(path_to_dir + "messages.txt", "w")

    for hex_string in input_file:
        string = hex_to_text(hex_string.rstrip())
        message, xor_byte = single_byte_xor(string)
        if re.match("^[A-Za-z0-9 ]*$", message):
            output_file.write(message + "\n")
        else:
            output_file.write("=" * len(string) + "\n")

    print("Done.")

    input_file.close()
    output_file.close()
