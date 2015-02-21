
def validate_pkcs7(string, block_size):
    if len(string) % block_size != 0:
        raise Exception("Bad padding.")
    
    padding_size = ord(string[-1])
    if padding_size not in range(1, block_size + 1):
        raise Exception("Bad padding.")

    padding = chr(padding_size) * padding_size
    if string[-padding_size:] != padding:
        raise Exception("Bad padding.")

    return string[:-padding_size]


# main block

if __name__ == "__main__":
    test_strings =["ICE ICE BABY\x04\x04\x04\x04",
                   "ICE ICE BABY\x05\x05\x05\x05",
                   "ICE ICE BABY\x01\x02\x03\x04"]

    for string in test_strings:
        try:
            print(validate_pkcs7(string, 16))
        except:
            print("String {0} has bad padding.".format(string))
    