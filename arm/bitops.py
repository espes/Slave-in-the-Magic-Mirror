# Python ARMv7 Emulator
#
# Adapted from Javascript ARMv7 Emulator
#
# Copyright 2012, Ryota Ozaki
# Copyright 2014, espes
#
# Licensed under GPL Version 2 oe later
#

from utils import *
import display


def xor(x, y):
    return x ^ y
    #ret = x ^ y
    #if (ret >= 0):
    #    return ret
    #else:
    #    return ret + 0x100000000


def xor64(x, y):
    return x ^ y
    #xh = x // 0x100000000
    #yh = y // 0x100000000
    #xl = x % 0x100000000
    #yl = y % 0x100000000
    #return xor(xh, yh) * 0x100000000 + xor(xl, yl)


def and_(x, y):
    return x & y
    #ret = x & y
    #if (ret >= 0):
    #    return ret
    #else:
    #    return ret + 0x100000000


def and64(x, y):
    return x & y
    #xh = x // 0x100000000
    #yh = y // 0x100000000
    #xl = x % 0x100000000
    #yl = y % 0x100000000
    #return and_(xh, yh) * 0x100000000 + and_(xl, yl)


def or_(x, y):
    return x | y
    #ret = x | y
    #if (ret >= 0):
    #    return ret
    #else:
    #    return ret + 0x100000000


def or64(x, y):
    return x | y
    #xh = x // 0x100000000
    #yh = y // 0x100000000
    #xl = x % 0x100000000
    #yl = y % 0x100000000
    #return or_(xh, yh) * 0x100000000 + or_(xl, yl)


def not_(x):
    return (~x) & 0xffffffff
    #ret = ~x
    #if (ret >= 0):
    #    return ret
    #else:
    #    return ret + 0x100000000


def lowest_set_bit(val, len):
    pos = 0
    for i in xrange(len):
        if (val & 1 << i):
            return i
    
    return len


def bit_count(val, len):
    count = 0
    for i in xrange(len):
        if (val & (1 << i)):
            count += 1
    
    return count


def clear_bit(uint, pos):
    return uint & ~(1 << pos)
    # if (uint < 0x80000000 and pos < 31):
    #     return uint & ~(1 << pos)
    # if (pos < 31):
    #     ret = uint & ~(1 << pos)
    #     if (ret < 0):
    #         ret += 0x100000000
    #     return ret
    # else:
    #     if (uint >= 0x80000000):
    #         return uint - 0x80000000
    #     else:
    #         return uint
    
    """
    uints = toStringBin32(uint)
    ret = ""
    for i in xrange(32):
        if ((32-i-1) == pos):
            ret += "0"
        else:
            ret += uints[i]
    
    return parseInt(ret, 2)
    """


def clear_bits(uint, start, end):
    if (uint < 0x80000000 and start < 31):
        return uint & ~(((1 << (start+1)) - 1) & ~((1 << end) - 1))
    if (start < 31):
        ret = uint & ~(((1 << (start+1)) - 1) & ~((1 << end) - 1))
        if (ret < 0):
            ret += 0x100000000
        return ret
    
    uints = toStringBin32(uint)
    ret = ""
    for i in xrange(32):
        if ((32-i-1) <= start and (32-i-1) >= end):
            ret += "0"
        else:
            ret += uints[i]
    
    return int(ret, 2)


def set_bits(uint, start, end, val):
    return or_(clear_bits(uint, start, end), lsl(val, end))


def set_bit(uint, pos, val):
    if val:
        return uint | (val << pos)
    else:
        return uint & not_(1 << pos)
    # if (val):
    #     if (pos == 31):
    #         return or_(uint, 0x80000000)
    #     else:
    #         return or_(uint, val << pos)
    # else:
    #     if (pos == 31):
    #         return clear_bit(uint, 31)
    #     else:
    #         return and_(uint, not_(1 << pos))


def get_bit(uint, pos):
    return (uint >> pos) & 1
    #return (uint & (1 << pos)) >> pos


def get_bit64(ulong, pos):
    return (ulong >> pos) & 1
    # if (pos > 31):
    #     ulong_h = ulong // 0x100000000
    #     return get_bit(ulong_h, pos - 31)
    # else:
    #     ulong_l = ulong % 0x100000000
    #     return get_bit(ulong_l, pos)
    


def zero_extend(val, n):
    return val


def zero_extend64(val, n):
    return val


def get_bits(uint, start, end):
    #assert1(end != undefined, "get_bits: missing 3rd argument")
    if (start == 31):
        if (end != 0):
            return uint >> end
        if (uint > 0xffffffff):
            and_(uint, 0xffffffff)
        else:
            return uint
    
    #return and(uint >>> end, ((1 << (start - end + 1)) - 1))
    ret = (uint >> end) & ((1 << (start - end + 1)) - 1)
    if (ret >= 0x100000000):
        return ret - 0x100000000
    else:
        return ret


def get_bits64(ulong, start, end):
    #assert1(end != undefined, "get_bits64: missing 3rd argument")
    assert1(start != end, "get_bits64: start == end")
    #assert1(start < 32 and end < 32, "get_bits64: too high range")
    if (ulong < 0x80000000 and start < 31 and end < 31):
        get_bits(ulong, start, end)
    ulong_h = ulong // 0x100000000
    ulong_l = ulong % 0x100000000
    ret = 0
    if (start > 31):
        if (start == 32):
            ret += get_bit(ulong_h, 0) << (31 - end + 1)
        else:
            if (end > 31):
                ret += get_bits(ulong_h, start-32, end-32)
            else:
                ret += get_bits(ulong_h, start-31, 0) << (31 - end + 1)
        
    
    if (end <= 31):
        if (end == 31):
            ret += get_bit(ulong_l, 31)
        else:
            ret += get_bits(ulong_l, start if start < 31 else 31, end)
    
    return ret


def sign_extend(x, x_len, n):
    #assert1(n !== undefined)
    sign = get_bit(x, x_len - 1)
    if (sign):
        """
        extend = ""
        for (i=0; i < (n-x_len); i++)
            extend += "1"
        str = extend + toStringBin(x, x_len)
        return parseInt32(str, 2)
        """
        if (n == 32):
            tmp = 0xffffffff
        else:
            tmp = (1<<n)-1
        #return x | (tmp & ~((1 << x_len)-1))
        ret = x | (tmp & ~((1 << x_len)-1))
        if (ret < 0):
            return ret + 0x100000000
        else:
            return ret
    else:
        return x


def lsl(x, n):
    ret = x << n
    if (ret >= 0 and ret >= x):
        return ret
    else:
        return x * (2 ** n)
    


def lsr(x, n):
    return 0 if (n == 32) else (x >> n)


def asr(x, n):
    if (n == 32):
        return 0
    ret = x >> n
    #if (ret < 0):
    #    ret += 0x100000000
    return ret


def sint32(x):
    #return x & 0xffffffff
    x &= 0xffffffff
    if x >= 0x80000000:
        return x - 0x100000000
    return x


def uint32(x):
    return x & 0xffffffff
    #return and64(x, 0xffffffff)


def toUint32(x):
    return x & 0xffffffff
    # if (x < 0):
    #     if (x < (1 << 31)):
    #         #throw "toUint32: too small"
    #         x = x + 0x10000000000000000
    #     else:
    #         x = x + 0x100000000
        
    
    # return and64(x, 0xffffffff)


def copy_bits(dest, start, end, src):
    return set_bits(dest, start, end, get_bits(src, start, end))


def copy_bit(dest, pos, src):
    return set_bit(dest, pos, get_bit(src, pos))


def ror(value, amount):
    m = amount % 32
    #lo = get_bits(value, m-1, 0)
    #result = or(value >>> m, lsl(lo, (32-m)))
    lo = value & ((1 << m) - 1)
    result = (value >> m) + lsl(lo, (32-m))
    #assert1(result >= 0 and result <= 0xffffffff, "ror")
    return result


def count_leading_zero_bits(val):
    n = 0
    for i in xrange(31, -1, -1):
        if (get_bit(val, i)):
            break
        n += 1
    
    return n


def test():
    assert2(clear_bit(0xffffffff, 0), 0xfffffffe)
    assert2(clear_bit(0x13, 31), 0x13)
    assert2(clear_bit(0x13, 0), 0x12)

    assert2(clear_bits(0xffffffff, 31, 0), 0)
    assert2(clear_bits(0xffffffff, 31, 16), 0x0000ffff)
    assert2(clear_bits(0xffffffff, 15, 0), 0xffff0000)
    assert2(clear_bits(0xffffffff, 15, 12), 0xffff0fff)
    assert2(clear_bits(0x0fffffff, 15, 12), 0x0fff0fff)

    tmp = 0
    assert1(xor(0xffffffff, 0xffffffff) == 0)
    assert1(xor(0x11111111, 0x22222222) == 0x33333333)
    assert1(xor(0xf0000000, 0xf0000000) == 0)

    assert1(xor64(0xffffffff, 0xffffffff) == 0)
    assert1(xor64(0x11111111, 0x22222222) == 0x33333333)
    assert1(xor64(0xf0000000, 0xf0000000) == 0)
    assert1(xor64(0x1f0000000, 0xf0000000) == 0x100000000)

    assert1(not_(0xffffffff) == 0x00000000)
    assert1(not_(0x00000000) == 0xffffffff)
    assert1(not_(0x00000001) == 0xfffffffe)
    assert1(not_(0x80000000) == 0x7fffffff)

    assert1(or_(0x11111111, 0x22222222) == 0x33333333)
    assert1(or_(0xffffffff, 0x00000000) == 0xffffffff)
    assert1(or_(0xffffffff, 0xffffffff) == 0xffffffff)

    assert1(or64(0x11111111, 0x22222222) == 0x33333333)
    assert1(or64(0xffffffff, 0x00000000) == 0xffffffff)
    assert1(or64(0xffffffff, 0xffffffff) == 0xffffffff)
    assert1(or64(0xf00000000, 0x00000000) == 0xf00000000)
    assert1(or64(0xf00000000, 0x0000000f) == 0xf0000000f)

    assert1(and_(0x11111111, 0x22222222) == 0)
    assert1(and_(0xffffffff, 0) == 0)

    assert1(and64(0x11111111, 0x22222222) == 0)
    assert2(and64(0xffffffff, 0), 0)
    assert2(and64(0xffffffffffff, 0), 0)
    assert2(and64(0xffffffffffff, 0xffffffff), 0xffffffff)

    assert2(get_bit(0xffffffff, 31), 1)
    assert2(get_bit(0xffffffff, 0), 1)
    assert1(get_bit(0x80000000, 31) == 1)
    assert1(get_bit(0, 31) == 0)
    assert1(get_bit(0, 0) == 0)
    assert1(get_bit(0x7fffffff, 31) == 0)
    assert2(get_bit(0x80000000, 31), 1)

    assert1(get_bit64(0xffffffff, 31) == 1)
    assert2(get_bit64(0xffffffff, 0), 1)
    assert1(get_bit64(0x80000000, 31) == 1)
    assert1(get_bit64(0, 31) == 0)
    assert1(get_bit64(0, 0) == 0)
    assert1(get_bit64(0x7fffffff, 31) == 0)
    assert1(get_bit64(0xffffffffffff, 31) == 1)
    assert2(get_bit64(0xffffffffffff, 50), 0)

    assert1(get_bits(0xffffffff, 31, 0) == 0xffffffff)
    assert1(get_bits(0xffffffff, 31, 16) == 0xffff)
    assert1(get_bits(0, 31, 0) == 0)
    assert1(get_bits(0x13, 4, 0) == 0x13, get_bits(0x13, 4, 0))
    assert2(get_bits(0xf0000000, 31, 27), 0x1e)
    assert2(get_bits(0xc0000000, 31, 27), 0x18)

    assert2(get_bits64(0xffffffff, 31, 0), 0xffffffff)
    assert2(get_bits64(0xffffffff, 31, 16), 0xffff)
    assert2(get_bits64(0, 31, 0), 0)
    assert2(get_bits64(0x13, 4, 0), 0x13)
    assert2(get_bits64(0x100000000, 31, 0), 0)
    assert2(get_bits64(0x100000000, 31, 0), 0)
    assert2(get_bits64(0x100000000, 32, 31), 2)
    assert2(get_bits64(0x300000000, 32, 31), 2)
    assert2(get_bits64(0x180000000, 32, 31), 3)
    assert2(get_bits64(0xf00000000, 33, 32), 3)
    assert2(get_bits64(0xf00000000, 34, 33), 3)
    assert2(get_bits64(0x180000000, 34, 31), 3)
    assert2(get_bits64(0x180000000, 34, 30), 6)
    assert2(get_bits64(0x100000000, 51, 32), 1)

    assert1(set_bit(0xffffffff, 0, 0) == 0xfffffffe, set_bit(0xffffffff, 0, 0))
    assert1(set_bit(0xffffffff, 31, 0) == 0x7fffffff, set_bit(0xffffffff, 31, 0))
    assert1(set_bit(0xffffffff, 31, 1) == 0xffffffff, set_bit(0xffffffff, 31, 1))
    assert1(set_bit(0x13, 31, 0) == 0x13, set_bit(0x13, 31, 0))
    assert1(set_bit(0, 31, 1) == 0x80000000)
    assert1(set_bit(0, 0, 1) == 1)
    assert1(set_bit(0, 2, 1) == 4, set_bit(0, 2, 1))

    assert1(set_bits(0xffffffff, 31, 0, 0) == 0)
    assert1(set_bits(0xffffffff, 15, 0, 0) == 0xffff0000, set_bits(0xffffffff, 15, 0, 0))
    assert1(set_bits(0, 4, 0, 0x13) == 0x13)
    assert2(set_bits(0xf0000000, 31, 27, 0x1e), 0xf0000000)
    assert2(set_bits(0x00000000, 31, 27, 0x1e), 0xf0000000)
    assert2(set_bits(0xf0000000, 31, 27, 0x18), 0xc0000000)

    assert2(lsl(1, 1), 2)
    assert2(lsl(0xf0000000, 1), 0x1e0000000)
    assert2(lsl(0xffffffff, 1), 0x1fffffffe)
    assert2(lsl(0xf0f0f0f0, 4), 0xf0f0f0f00)
    assert2(lsl(0x100000000, 1), 0x200000000)

    assert2(lsr(1, 1), 0)
    assert2(lsr(0xf0000000, 1), 0x78000000)
    assert2(lsr(0xffffffff, 1), 0x7fffffff)
    assert2(lsr(0xf0f0f0f0, 4), 0x0f0f0f0f)
    assert2(lsr(0x80000000, 32), 0)
    assert2(lsr(0x80000000, 1), 0x40000000)

    assert2(lsr(1, 1), 0)
    assert2(lsr(0xf0000000, 1), 0x78000000)
    assert2(lsr(0xffffffff, 1), 0x7fffffff)
    assert2(lsr(0xf0f0f0f0, 4), 0x0f0f0f0f)
    assert2(lsr(0x80000000, 32), 0)
    assert2(lsr(0x80000000, 1), 0x40000000)

    assert2(sint32(0x00000000), 0x00000000)
    #assert2(sint32(0x80000000), 0x80000000 & 0xffffffff)
    assert2(sint32(0x80000000), -2147483648)
    assert2(sint32(0x100000000), 0x00000000)
    assert2(sint32(0xffffffff), -1)

    assert2(uint32(0x00000000),  0x00000000)
    assert2(uint32(0x80000000),  0x80000000)
    assert2(uint32(0x100000000), 0x00000000)
    assert2(uint32(0xffffffff),  0xffffffff)
    assert2(uint32(0xfffffffff), 0xffffffff)

    assert2(sign_extend(0, 26, 32), 0)
    #assert2(sign_extend(0, 1, 32), sint32(0))
    #assert2(sign_extend(1, 1, 32), sint32(0xffffffff))
    #assert2(sign_extend(0x0000ffff, 16, 32), sint32(0xffffffff))
    #assert2(sign_extend(0x00007fff, 16, 32), sint32(0x00007fff))
    assert2(sign_extend(0, 1, 32), 0)
    assert2(sign_extend(1, 1, 32), 0xffffffff)
    assert2(sign_extend(0x0000ffff, 16, 32), 0xffffffff)
    assert2(sign_extend(0x00007fff, 16, 32), 0x00007fff)
    assert2(sign_extend(0xffffe3 << 2, 26, 32), 0xffffff8c)

    assert2(copy_bits(0xf0000000, 31, 27, 0), 0)
    assert2(copy_bits(0xf0000000, 31, 27, 0xc0000000), 0xc0000000)

    assert2(copy_bit(0, 0, 1), 1)
    assert2(copy_bit(1, 0, 0), 0)
    assert2(copy_bit(0xffffffff, 0, 0), 0xfffffffe)
    assert2(copy_bit(0xffffffff, 31, 0), 0x7fffffff)

    assert2(ror(0x10000000, 1), 0x08000000)
    assert2(ror(0x10000001, 1), 0x88000000)
    assert2(ror(0xffffffff, 1), 0xffffffff)
    assert2(ror(0x0000ffff, 16), 0xffff0000)
    assert2(ror(0x000ffff0, 16), 0xfff0000f)

    assert2(count_leading_zero_bits(0), 32)
    assert2(count_leading_zero_bits(0x80000000), 0)
    assert2(count_leading_zero_bits(0x00008000), 16)

    display.log("All BitOps tests passed successfully")


if __name__ == "__main__":
    test()