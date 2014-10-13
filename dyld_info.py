# dyld.py
#
# Adapted from EcaFretni
#
# Copyright 2010, KennyTM~ <kennytm@gmail.com>
# Copyright 2014, espes
#
# Licensed under GPL version 3 or later
#


BIND_TYPE_POINTER = 1
BIND_TYPE_TEXT_ABSOLUTE32 = 2
BIND_TYPE_TEXT_PCREL32 = 3

BIND_SPECIAL_DYLIB_SELF = 0
BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE = -1
BIND_SPECIAL_DYLIB_FLAT_LOOKUP = -2

BIND_SYMBOL_FLAGS_WEAK_IMPORT = 0x1
BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION = 0x8

BIND_OPCODE_MASK = 0xF0
BIND_IMMEDIATE_MASK = 0x0F
BIND_OPCODE_DONE = 0x00
BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10
BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20
BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30
BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40
BIND_OPCODE_SET_TYPE_IMM = 0x50
BIND_OPCODE_SET_ADDEND_SLEB = 0x60
BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70
BIND_OPCODE_ADD_ADDR_ULEB = 0x80
BIND_OPCODE_DO_BIND = 0x90
BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xA0
BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xB0
BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xC0


def readString(f):
    r = ""
    while True:
        c = f.read(1)
        if c == "\x00":
            break
        r += c
    return r


def readULeb128(f):
    """Read an unsigned little-endian base-128 integer"""
    
    res = 0
    bit = 0
    while True:
        c = ord(f.read(1))
        s = c & 0x7f
        res |= s << bit
        bit += 7
        if not (c & 0x80):
            break
    
    return res


def readSLeb128(f):
    """Read a signed little-endian base-128 integer """
    
    res = 0
    bit = 0
    while True:
        c = ord(f.read(1))
        s = c & 0x7f
        res |= s << bit
        bit += 7
        if not (c & 0x80):
            break
    if c & 0x40:
        res |= (-1) << bit
    
    return res



def read_binds(f, size, segs, ptrwidth=4):
    libord = 0
    sym = None
    addr = 0
    
    end = f.tell() + size
    
    symbols = []

    while f.tell() < end:
        c = ord(f.read(1))
        imm = c & BIND_IMMEDIATE_MASK
        opcode = c & BIND_OPCODE_MASK

        if opcode == BIND_OPCODE_DONE:
            pass
        elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_IMM:
            libord = imm
        elif opcode == BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB:
            libord = readULeb128(f)
        elif opcode == BIND_OPCODE_SET_DYLIB_SPECIAL_IMM:
            libord = (imm | 0xf0) if imm else 0

        elif opcode == BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM:
            sym = readString(f)

        elif opcode == BIND_OPCODE_SET_TYPE_IMM:
            pass

        elif opcode == BIND_OPCODE_SET_ADDEND_SLEB:
            readSLeb128(f)

        elif opcode == BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB:
            addr = segs[imm].vmaddr + readULeb128(f)

        elif opcode == BIND_OPCODE_ADD_ADDR_ULEB:
            addr = (addr + readULeb128(f)) % (2 ** 64)

        elif opcode == BIND_OPCODE_DO_BIND:
            symbols.append((sym, addr, libord))
            addr += ptrwidth

        elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB:
            symbols.append((sym, addr, libord))
            addr += ptrwidth + readULeb128(f)

        elif opcode == BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED:
            symbols.append((sym, addr, libord))
            addr += (imm+1) * ptrwidth

        elif opcode == BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB:
            count = readULeb128(f)
            skip = readULeb128(f)
            for i in range(count):
                symbols.append((sym, addr, libord))
                addr += skip + ptrwidth
        else:
            raise NotImplementedError

    return symbols


def walk_trie(f, start, cur, end, prefix, symbols):
    if cur >= end:
        return

    f.seek(cur)
    termSize = ord(f.read(1))
    if termSize:
        sym = prefix
        readULeb128(f)
        addr = readULeb128(f)
        symbols.append((sym, addr))
    f.seek(cur + termSize + 1)
    childCount = ord(f.read(1))
    for i in range(childCount):
        suffix = readString(f)
        offset = readULeb128(f)
        lastPos = f.tell()
        walk_trie(f, start, start + offset, end, prefix + suffix, symbols)
        f.seek(lastPos)

class DyldInfo(object):
    def __init__(self, filename, cmd, segs):
        with open(filename, "rb") as f:

            self.rebases = []
            self.binds = []
            self.week_binds = []
            self.lazy_binds = []
            self.exports = []

            if cmd.rebase_size:
                pass

            if cmd.bind_size:
                f.seek(cmd.bind_off)
                self.binds = read_binds(f, cmd.bind_size, segs)

            if cmd.weak_bind_size:
                f.seek(cmd.weak_bind_off)
                self.week_binds = read_binds(f, cmd.weak_bind_size, segs)

            if cmd.lazy_bind_size:
                f.seek(cmd.lazy_bind_off)
                self.lazy_binds = read_binds(f, cmd.lazy_bind_size, segs)

            if cmd.export_size:
                walk_trie(f, cmd.export_off, cmd.export_off,
                          cmd.export_off + cmd.export_size,
                          "", self.exports)

