from ctr_mode import ctr_function
from ..set2.ecb_cbc_detection import rand_aes_128_block
from ..set1.hex_to_base64 import base64_to_text
from ..set1.single_byte_xor import single_byte_xor

BASE64_PLAINTEXTS = ["SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
                     "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
                     "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
                     "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
                     "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
                     "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
                     "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
                     "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
                     "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
                     "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
                     "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
                     "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
                     "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
                     "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
                     "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
                     "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
                     "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
                     "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
                     "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
                     "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
                     "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
                     "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
                     "U2hlIHJvZGUgdG8gaGFycmllcnM/",
                     "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
                     "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
                     "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
                     "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
                     "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
                     "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
                     "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
                     "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
                     "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
                     "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
                     "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
                     "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
                     "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
                     "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
                     "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
                     "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
                     "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="]

def break_ctr_with_fixed_nonce(ciphertexts):
    plaintexts = ["" for __ in range(len(ciphertexts))]

    max_length = len(max(ciphertexts, key=len))
    for j in range(max_length):
        single_byte_xored_string = ""
        excepted_index = []
        for i in range(len(ciphertexts)):
            try:
                single_byte_xored_string += ciphertexts[i][j]
            except IndexError:
                excepted_index.append(i)
        
        result = single_byte_xor(single_byte_xored_string)
        message = result[0]

        counter = 0
        for i in range(len(ciphertexts)):
            if i not in excepted_index:
                plaintexts[i] += message[counter]
                counter = counter + 1

    return plaintexts


# main block

if __name__ == "__main__":
    ciphertexts = []
    nonce = 0
    key = rand_aes_128_block()
    for base64_string in BASE64_PLAINTEXTS:
        ciphertext = ctr_function(nonce, \
                                  base64_to_text(base64_string), key)
        ciphertexts.append(ciphertext)

    plaintexts = break_ctr_with_fixed_nonce(ciphertexts)
    for string in plaintexts:
        print(string)
