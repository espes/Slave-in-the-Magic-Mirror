# Python ARMv7 Emulator
#
# Adapted from Javascript ARMv7 Emulator
#
# Copyright 2012, Ryota Ozaki
# Copyright 2014, espes
#
# Licensed under GPL Version 2 or later
#

import time
import bitops

def assert1(cond, val=None):
    if (not cond):
        if (isinstance(val, str)):
            raise Exception("Assertion failed: " + val)
        if (val):
            raise Exception("Assertion failed: " + hex(val) + "(" + bin(val) + ")")
        else:
            raise Exception("Assertion failed.")
    


def assert2(x, y, s=None):
    if (x != y):
        msg = ""
        if (s is None):
            raise Exception("Assertion failed: " + toStringNum(x) + " != " + toStringNum(y))
        else:
            raise Exception("Assertion failed(" + s + "): " + toStringNum(x) + " != " + toStringNum(y))


def toStringBinInst(inst):
    ret = ""
    b = bin(inst)[2:]
    b = b.rjust(32, "0")
    for i in xrange(32):
        ret += b[i]
        if ((i + 1) % 4 == 0 and i != 31):
            ret += " "

    return ret


def toStringBin(val, n):
    return bin(val)[2:].rjust(n, "0")

def toStringBin32(val):
    return toStringBin(val, 32)


def toStringBin64(val):
    return toStringBin(val, 64)


def toStringBin16(val):
    return toStringBin(val, 16)


def toStringHex32(ulong):
    if (not ulong):
        if (ulong is None):
            return "(null)"

    return "%08x"%ulong


def toStringNum(num):
    return str(num) + "(%x)" % num


def toStringInst(inst):
    return toStringHex32(inst) + "(" + toStringBinInst(inst) + ")"


def toStringAscii(uint):
    ret = ""
    for i in xrange(0, 32, 8):
        b = bitops.get_bits(uint, 32-1 - i, 32-1 - i - 7)
        if (b >= 32 and b <= 126):
            ret += chr(b)
        else:
            ret += '.'
    return ret


def abort(s):
    raise Exception(s)


def stringToLong(str):
    if (str.length != 4):
        abort("String.toLong: string too long: " + str.length + " > 4")
    ret = 0
    ret += str.charCodeAt(3) << 24
    ret += str.charCodeAt(2) << 16
    ret += str.charCodeAt(1) << 8
    ret += str.charCodeAt(0)
    return ret


def getCurrentTime():
    return time.time()*1000

