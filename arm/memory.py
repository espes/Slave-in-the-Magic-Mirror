# Python ARMv7 Emulator
#
# Adapted from Javascript ARMv7 Emulator
#
# Copyright 2012, Ryota Ozaki
# Copyright 2014, espes
#
# Licensed under GPL Version 2 or later
#

import array

class BaseMemoryController(object):
    def ld_byte(self, addr):
        raise NotImplementedError

    def ld_byte_fast(self, addr):
        return self.ld_byte(addr)

    def st_byte(self, addr, onebyte):
        raise NotImplementedError

    def st_byte_fast(self, addr, onebyte):
        self.st_byte(addr, onebyte)

    def ld_halfword(self, addr):
        return (self.ld_byte(addr)
                | (self.ld_byte(addr+1) << 8))

    def ld_halfword_fast(self, addr):
        return self.ld_halfword(addr)

    def st_halfword(self, addr, halfword):
        self.st_byte(addr, halfword & 0xff)
        self.st_byte(addr+1, halfword >> 8)

    def st_halfword_fast(self, addr, halfword):
        self.st_halfword(addr, halfword)

    def ld_word(self, addr):
        return (self.ld_halfword(addr)
                | (self.ld_halfword(addr+2) << 16))

    def ld_word_fast(self, addr):
        return self.ld_word(addr)

    def st_word(self, addr, word):
        self.st_halfword(addr, word & 0xffff)
        self.st_halfword(addr+2, word >> 16)

    def st_word_fast(self, addr, word):
        self.st_word(addr, word)

    def st_word_unaligned(self, addr, word):
        self.st_byte(addr, word & 0xff);
        self.st_byte(addr+1, (word >> 8) & 0xff);
        self.st_byte(addr+2, (word >> 16) & 0xff);
        self.st_byte(addr+3, word >> 24);


class VirtualMemoryController(BaseMemoryController):
    def __init__(self, vm):
        self.vm = vm

    def ld_byte(self, addr):
        region, offset = self.vm.lookup(addr)
        return region.data[offset + addr % self.vm.page_size]

    def st_byte(self, addr, onebyte):
        region, offset = self.vm.lookup(addr)
        region.data[offset + addr % self.vm.page_size] = onebyte



class VMRegion(object):
    def __init__(self, data, protect, max_protect):
        self.data = array.array('B', data)
        self.protect = protect
        self.max_protect = max_protect

class VirtualMemory(object):
    def __init__(self):
        self.vm_size = 2**32
        self.page_size = 4096
        self.num_pages = self.vm_size // self.page_size
        self.page_map = [None]*self.num_pages

    def map(self, addr, size, region):
        assert addr % self.page_size == 0
        assert size % self.page_size == 0
        for p in xrange(addr // self.page_size, (addr + size) // self.page_size):
            assert self.page_map[p] is None
        for i in xrange(size // self.page_size):
            p = addr // self.page_size + i
            self.page_map[p] = (region, i * self.page_size)

    def lookup(self, addr):
        return self.page_map[addr // self.page_size]

class ARMv7VirtualMMU(object):
    def __init__(self, vm):
        self.vm = vm
        self.check_unaligned = False

    def trans_to_phyaddr(self, addr, is_write=False):
        r = self.vm.lookup(addr)
        if r is None:
            raise Exception("Translation fault %x" % addr)
        return addr