import time
from random import randint

from mt19937 import rand, init_mt19937

# time_interval is measured in milliseconds
def crack_mt19937_seed(expected_prn, time_interval):
    seed = int(time.time() * 1000.0)
    for t in range(time_interval):
        init_mt19937(seed - t)
        if expected_prn == rand():
            return seed - t
    return None


# main block

if __name__ == "__main__":
    time.sleep(randint(40, 1000) / 1000.0)
    seed = int(time.time() * 1000.0)
    print("Seed from built-in rand(): " + str(seed))
    init_mt19937(seed)

    time.sleep(randint(40, 1000) / 1000.0)
    first_prn = rand()
    seed = crack_mt19937_seed(first_prn, 5000)
    if seed == None:
        print("Can't crack MT19937 seed.")
    else:
        print("Cracked seed: " + str(seed))
