import httplib
import time
import sys
import urllib

HEX_SYMBOLS = "0123456789abcdef"

# main block

if __name__ == "__main__":
    target_url = "http://127.0.0.1:9000/test?file=foo&signature="
    signature = "0" * 40
    for pos in range(40):
        pairs = []
        for value1 in HEX_SYMBOLS:
            average_time = 0
            for _ in range(10):
                signature = signature[:pos] + \
                            value1 + \
                            signature[pos + 1:]
                
                before = time.time() * 1000.0
                code = urllib.urlopen(target_url + signature).getcode()
                after = time.time() * 1000.0
                average_time += after - before
                
                if code == 200:
                    print("Cracked signature(success): " + signature)
                    sys.exit()
            
            average_time /= 10.0
            pair = (value1, average_time)
            pairs.append(pair)
        
        optimal_value = max(pairs, key=lambda t: t[1])
        signature = signature[:pos] + \
                    optimal_value[0] + \
                    signature[pos + 1:]
        print("Position {0} was checked.".format(pos))

    print("Cracked signature(failure): " + signature)
