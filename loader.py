# loader.py
#
# Copyright 2014, espes
#
# Licensed under GPL Version 2 or later
#

import sys
import inspect

from macholib import MachO
from macholib.mach_o import *

import arm
from dyld_info import DyldInfo

def align(p, a):
    a -= 1
    return (p + a) & ~a;


def load_macho(filename):
    file_data = open(filename).read()

    macho = MachO.MachO(filename)
    header = macho.headers[0]
    cputype = CPU_TYPE_NAMES[header.header.cputype]

    assert cputype == "ARM"
    assert header.header.filetype == MH_EXECUTE

    regions = []

    text_base = None
    entry_point = None

    segments = [cmd for _, cmd, _ in header.commands if type(cmd) == segment_command]
    for cmd in segments:
        name = cmd.segname.replace("\x00", "")
        if name == SEG_PAGEZERO: continue
        
        if name == SEG_TEXT:
            assert cmd.fileoff == 0
            text_base = cmd.vmaddr

        filesize = align(cmd.filesize, 4096)
        vmsize = align(cmd.vmsize, 4096)

        regions.append( ( cmd.vmaddr, filesize,
            file_data[cmd.fileoff:cmd.fileoff+filesize] ) )

        if vmsize != filesize:
            regions.append( ( cmd.vmaddr + filesize,
                              vmsize - filesize,
                              None ) )

    assert text_base is not None


    dyld_info = None
    symbols = {}

    for lc, cmd, data in header.commands:
        if type(cmd) == entry_point_command:
            # the entry point is given as a file offset.
            # assume it's in the text segment...
            entry_point = cmd.entryoff + text_base
        elif type(cmd) == dyld_info_command:
            dyld_info = DyldInfo(filename, cmd, segments)
        elif type(cmd) == symtab_command:
            #TODO: populate symbols
            pass

    #assert entry_point is not None


    stack_bottom = 0x70000000 # ?
    stack_size = 0x20000 # 128k ?
    regions.append((stack_bottom-stack_size, stack_size, None))

    # print [(hex(a), hex(b), c[:16] if c else c) for a, b, c in regions]

    return (regions, entry_point, stack_bottom,
                symbols, dyld_info)

class IOSProcess(object):
    def __init__(self, filename):
        self.filename = filename

        self.hle = {
            '_printf': self.hle_printf,
            '_memcpy': self.hle_memcpy,
            '_memset': self.hle_memset,
            '_malloc': self.hle_malloc,
            '_arc4random': self.hle_arc4random,
            '___umodsi3': self.hle_umodsi3,
            '___modsi3': self.hle_modsi3,
            '___udivsi3': self.hle_udivsi3,
        }

        self.breakpoint_instruction = 0xFEDEFFE7
        self.running = False



        (regions, self.entry_point, self.stack_bottom,
            self.symbols, dyld_info) = load_macho(filename)

        # setup scratch space for putting down hooks for linking
        scratch_addr = 0x80000000
        scratch_size = 0x20000 # 128k
        regions.append((scratch_addr, scratch_size, None))

        # tmp hack of a heap
        heap_addr = 0x40000000
        heap_size = 0x200000 # 2MB
        regions.append((heap_addr, heap_size, None))
        self.heap_base = heap_addr

        # setup memory
        self.mem = arm.memory.VirtualMemory()
        for addr, size, data in regions:
            if not data: data = "\x00"*size
            region = arm.memory.VMRegion(data, None, None)
            self.mem.map(addr, size, region)
        
        self.memctlr = arm.memory.VirtualMemoryController(self.mem)

        # 'link' to breakpoints for hle
        self.hle_breakpoints = {}
        if dyld_info:
            #print "binds", dyld_info.binds
            #print "lazys", dyld_info.lazy_binds
            for i, (name, vmaddr, libord) in enumerate(dyld_info.binds+dyld_info.lazy_binds):
                saddr = scratch_addr + i * 4
                if name == "___stack_chk_guard":
                    self.memctlr.st_word(saddr, 0)
                else:
                    self.memctlr.st_word(saddr, self.breakpoint_instruction)
                    self.hle_breakpoints[saddr] = name
                self.memctlr.st_word(vmaddr, saddr)


        self.options = arm.options.Options()
        mmu = arm.memory.ARMv7VirtualMMU(self.mem)
        self.cpu = arm.cpu.ARMv7CPU(self.options, self.memctlr, mmu)

    def log(self, on=True):
        self.options.enable_tracer = on
        self.options.enable_logger = on


    def copyin(self, addr, data):
        for i, c in enumerate(data):
            self.cpu.st_byte(addr+i, ord(c))

    def copyout(self, addr, length):
        r = ""
        for i in xrange(length):
            r += chr(self.cpu.ld_byte(addr+i))
        return r

    def malloc(self, size):
        r = self.heap_base
        self.heap_base += size
        return r

    def make_hle(f):
        nargs = len(inspect.getargspec(f).args)-1
        def f2(self, cpu):
            args = cpu.regs[:min(4, nargs)]
            for i in xrange(nargs-4):
                args.append(cpu.ld_word(cpu.regs[13]+i*4))
            r = f(self, *args)
            if r is None:
                cpu.regs[0] = 0
            else:
                cpu.regs[0] = arm.bitops.uint32(r)
            cpu.regs[15] = cpu.regs[14] # ret
        return f2

    hle_malloc = make_hle(malloc)

    def hle_printf(self, cpu):
        #print "printf!"
        #cpu.dump()
        # complete hack...
        format = cpu.ld_string(cpu.regs[0])
        num_params = format.count("%")
        if num_params > 3:
            # have to do stack shit.,,
            raise NotImplementedError
        else:
            f = format % tuple(cpu.regs[1:num_params+1])
            sys.stdout.write(f)

        cpu.regs[0] = len(f)

        cpu.regs[15] = cpu.regs[14] # ret

    @make_hle
    def hle_memcpy(self, dst, src, size):
        for i in xrange(size):
            self.cpu.st_byte(dst+i, self.cpu.ld_byte(src+i))

    @make_hle
    def hle_memset(self, dst, c, length):
        for i in xrange(length):
            self.cpu.st_byte(dst+i, c)

    @make_hle
    def hle_arc4random(self):
        return 4

    @make_hle
    def hle_umodsi3(self, a, b):
        if b == 0:
            return a
        return a % b

    @make_hle
    def hle_modsi3(self, a, b):
        a = arm.bitops.sint32(a)
        b = arm.bitops.sint32(b)
        return a - (a // b) * b

    @make_hle
    def hle_udivsi3(self, a, b):
        return a // b

    def exec_(self, arg=[], env=[]):
        #todo: setup the stack...

        # note usually the entry point is only ever reached via dyld...
        # we try to do dyld's job first and jump straight into it

        # magic value for catching when we return...
        exit_addr = 0xF4F4F4F4

        self.cpu.regs[0] = 0
        self.cpu.regs[1] = 0
        self.cpu.regs[2] = 0
        self.cpu.regs[3] = 0
        self.cpu.regs[13] = self.stack_bottom
        self.cpu.regs[14] = exit_addr
        self.cpu.regs[15] = self.entry_point
        self.cpu.cpsr.m = 0b10000 # user mode

        self.run(exit_addr)

        print "we're done!", self.cpu.regs[0]

    def call(self, func, args):
        if func in self.symbols:
            addr = self.symbols[func]
        else:
            addr = int(func)

        assert addr & 1 == 0

        # magic value for catching when we return...
        exit_addr = 0xF4F4F4F4

        sp = self.stack_bottom
 
        # extra arguments on the stack
        for i, v in enumerate(args[4:][::-1]):
            sp -= 4
            self.cpu.st_word(sp, v)
 
        self.cpu.regs[0] = args[0] if len(args) > 0 else 0
        self.cpu.regs[1] = args[1] if len(args) > 1 else 0
        self.cpu.regs[2] = args[2] if len(args) > 2 else 0
        self.cpu.regs[3] = args[3] if len(args) > 3 else 0
        self.cpu.regs[13] = sp
        self.cpu.regs[14] = exit_addr
        self.cpu.regs[15] = addr
        self.cpu.cpsr.m = 0b10000 # user mode

        print self.cpu.regs
        self.run(exit_addr)

        print "we're done!", self.cpu.regs[0]
        return self.cpu.regs[0]

    def run(self, exit_addr=None):
        self.running = True
        cnt = 0
        import time
        tt = time.time()
        while self.running:
            cnt += 1
            if cnt % 100000 == 0: print cnt, cnt/(time.time()-tt)

            self.cpu.branch_to = None
            pc = self.cpu.regs[15]

            if pc == exit_addr:
                break

            inst = self.cpu.fetch_instruction(pc)

            if inst == self.breakpoint_instruction:
                if pc in self.hle_breakpoints:
                    name = self.hle_breakpoints[pc]
                    if name in self.hle:
                        self.hle[name](self.cpu)
                        continue
                    else:
                        raise Exception("no hle for %s!" % name)

            # print hex(inst)
            if self.cpu.is_valid(inst):
                inst_name = self.cpu.decode(inst, pc);
                if self.cpu.cond(inst):
                    self.cpu.exec_(inst_name, inst, pc)
                else:
                    pass
                    # print hex(inst), inst_name
            else:
                raise Exception("invalid ... 0x%08x", inst)
            if self.cpu.branch_to is not None:
                if self.cpu.branch_to & 1:
                    raise Exception("branch to thumb mode...")
                self.cpu.regs[15] = self.cpu.branch_to
                self.cpu.print_pc(self.cpu.regs[15], pc);
                # print "branch", hex(self.cpu.branch_to)
            else:
                self.cpu.regs[15] = pc + 4

            # print
            # print map(hex, self.cpu.regs)
            # raw_input()     
        print "did %d instructions" % cnt   



if __name__ == "__main__":
    from sys import argv
    p = IOSProcess(argv[1])
    p.exec_()
