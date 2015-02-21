import time

_mt_nums = []
_index = 0

def init_mt19937(seed):
    global _mt_nums, _index
    _index = 0
    _mt_nums = [0 for __ in range(624)]
    _mt_nums[0] = seed & 0xffffffff
    for i in range(1, 624):
        _mt_nums[i] = 0x6c078965 * _mt_nums[i-1] + i
        _mt_nums[i] &= 0xffffffff


def gen_random_numbers(prns):
    if len(prns) != prns:
        return
    for i in range(624):
        r = (prns[i] & 0x80000000) + (prns[(i + 1) % 624] & 0x7fffffff)
        prns[i] = prns[(i + 397) % 624] ^ (r >> 1)
        if (r % 2) == 1:
            prns[i] ^= 0x9908b0df


def rand():
    global _index

    if len(_mt_nums) == 0:
        seed = int(time.time() * 1000) % (2 ** 32)
        init_mt19937(seed)

    if _index == 0:
        gen_random_numbers(_mt_nums)

    # tempering

    result = _mt_nums[_index]
    result ^= (result >> 11)
    result ^= (result << 7) & 0x9d2c5680
    result ^= (result << 15) & 0xefc60000
    result ^= (result >> 18)

    _index = (_index + 1) % 624
    return result


# main block

if __name__ == "__main__":
    init_mt19937(0xff34fe0f)
    for _ in range(100):
        print(rand())
