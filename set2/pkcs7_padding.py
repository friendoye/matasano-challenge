
def pkcs7_pad(string, block_size):
    if block_size >= 32 or block_size < 1:
        raise Exception("Block size should be [1, 32] bytes.")
    padding_byte = len(string) % block_size - block_size
    padding_byte *= -1
    padding = chr(padding_byte) * padding_byte
    return string + padding


# main block

if __name__ == "__main__":
    plaintext = "YELLOW SUBMARINE"
    block_size = 20
    padded_plaintext = pkcs7_pad(plaintext, block_size)
    print("Padded plaintext:" + padded_plaintext)
