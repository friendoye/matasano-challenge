from mt19937 import *

def clone_mt19937_output(prns):
    if len(prns) != 624:
        raise Exception("There should be exactly 624 PRN!")

    mt_nums = []
    for i in range(624):
        prn = prns[i]

        # untempering
        prn ^= (prn >> 18)
        remaining_bits = (prn & 0x0007ffff)
        remaining_bits = (prn & 0x3fffffff) ^ ((remaining_bits << 15) & 0xefc60000)
        prn ^= (remaining_bits << 15) & 0xefc60000
        remaining_bits = (prn & 0x0000007f)
        remaining_bits = (prn & 0x00003fff) ^ ((remaining_bits << 7) & 0x9d2c5680)
        remaining_bits = (prn & 0x001fffff) ^ ((remaining_bits << 7) & 0x9d2c5680)
        remaining_bits = (prn & 0x0fffffff) ^ ((remaining_bits << 7) & 0x9d2c5680)
        prn ^= (remaining_bits << 7) & 0x9d2c5680
        remaining_bits = (prn ^ (prn >> 11)) & 0xfffffc00
        prn ^= (remaining_bits >> 11)

        # add to list with MT PRN
        mt_nums.append(prn)

    gen_random_numbers(mt_nums)

    for i in range(624):
        mt_nums[i] ^= (mt_nums[i] >> 11)
        mt_nums[i] ^= (mt_nums[i] << 7) & 0x9d2c5680
        mt_nums[i] ^= (mt_nums[i] << 15) & 0xefc60000
        mt_nums[i] ^= (mt_nums[i] >> 18)

    return mt_nums


# main block

if __name__ == "__main__":
    seed = int(time.time() * 1000.0)
    init_mt19937(seed)
    prns = []
    for i in range(624):
        prns.append(rand())
   
    clone_prns = clone_mt19937_output(prns)
    print(clone_prns)
   
    prns = []
    for i in range(624):
        prns.append(rand())
    print(prns)

    print("Are lists equal: " + str(clone_prns == prns))
