# Python ARMv7 Emulator
#
# Adapted from Javascript ARMv7 Emulator
#
# Copyright 2012, Ryota Ozaki
# Copyright 2014, espes
#
# Licensed under GPL Version 2 or later
#

import bitops
import display
import logger, tracer
from utils import *


class PSR(object):
    def __init__(self):
        self.n = 0
        self.z = 0
        self.c = 0
        self.v = 0
        self.q = 0
        self.e = 0
        self.a = 0
        self.i = 0
        self.f = 0
        self.t = 0
        self.m = 0

class ARMv7CPU(object):
    def __init__(self, options, memctlr, mmu, symbols=None):
        self.options = options
        self.memctlr = memctlr
        self.mmu = mmu
        self.mmu.cpu = self

        self.symbols = symbols or {}

        self.USR_MODE = 0x10
        self.FIQ_MODE = 0x11
        self.IRQ_MODE = 0x12
        self.SVC_MODE = 0x13
        self.MON_MODE = 0x16
        self.ABT_MODE = 0x17
        self.UND_MODE = 0x1b
        self.SYS_MODE = 0x1f

        self.mode2string = {}
        self.mode2string[self.USR_MODE] = "USR"
        self.mode2string[self.FIQ_MODE] = "FIQ"
        self.mode2string[self.IRQ_MODE] = "IRQ"
        self.mode2string[self.SVC_MODE] = "SVC"
        self.mode2string[self.MON_MODE] = "MON"
        self.mode2string[self.ABT_MODE] = "ABT"
        self.mode2string[self.UND_MODE] = "UND"
        self.mode2string[self.SYS_MODE] = "SYS"

        self.is_good_mode = {}
        self.is_good_mode[self.USR_MODE] = True
        self.is_good_mode[self.FIQ_MODE] = True
        self.is_good_mode[self.IRQ_MODE] = True
        self.is_good_mode[self.SVC_MODE] = True
        self.is_good_mode[self.ABT_MODE] = True
        self.is_good_mode[self.UND_MODE] = True
        self.is_good_mode[self.SYS_MODE] = True

        self.regs = [0]*16
        # 
        # regs[10]: SL:
        # regs[11]: FP:
        # regs[12]: IP: A general register
        # regs[13]: SP: Stack pointer
        # regs[14]: LR: Link register
        # regs[15]: PC: Program counter
        # 

        self.regs_usr = [0]*16
        self.regs_svc = {}
        self.regs_svc[13] = 0
        self.regs_svc[14] = 0
        self.regs_mon = {}
        self.regs_mon[13] = 0
        self.regs_mon[14] = 0
        self.regs_abt = {}
        self.regs_abt[13] = 0
        self.regs_abt[14] = 0
        self.regs_und = {}
        self.regs_und[13] = 0
        self.regs_und[14] = 0
        self.regs_irq = {}
        self.regs_irq[13] = 0
        self.regs_irq[14] = 0
        self.regs_fiq = {}
        self.regs_fiq[8] = 0
        self.regs_fiq[9] = 0
        self.regs_fiq[10] = 0
        self.regs_fiq[11] = 0
        self.regs_fiq[12] = 0
        self.regs_fiq[13] = 0
        self.regs_fiq[14] = 0

        # CPSR: Current program status register
        # 
        # bit[31]: N: Negative condition code flag (APSR)
        # bit[30]: Z: Zero condition code flag (APSR)
        # bit[29]: C: Carry condition code flag (APSR)
        # bit[28]: V: Overflow condition code flag (APSR)
        # bit[27]: Q: Cumulative saturation flag (APSR)
        # bits[26:25]: IT: If-Then execution state bits
        # bit[24]: J: Jazelle bit
        # bits[23:20]: Reserved
        # bits[19:16]: Greater than or Equal flags (APSR)
        # bit[9]: E: Endianness execution state bit
        # bit[8]: A: Asynchronous abort disable bit
        # bit[7]: I: Interrupt disable bit
        # bit[6]: F: Fast interrupt disable bit
        # bit[5]: T: Thumb execution state bit
        # bits[4:0]: M: Mode field
        # 
        self.cpsr = PSR()

        # SPSR: banked Saved Program Status Register
        self.spsr_svc = PSR()
        self.spsr_mon = PSR()
        self.spsr_abt = PSR()
        self.spsr_und = PSR()
        self.spsr_irq = PSR()
        self.spsr_fiq = PSR()

        self.coprocs = [None]*16
        #self.coprocs[15] = ARMv7_CP15(options, self)
        self.mmu.cp15 = self.coprocs[15]

        self.shift_t = 0
        self.shift_n = 0
        self.carry_out = 0
        self.overflow = 0

        self.SRType_LSL = 0
        self.SRType_LSR = 1
        self.SRType_ASR = 2
        self.SRType_RRX = 3
        self.SRType_ROR = 4

        self.no_cond_insts = {}
        self.no_cond_insts["cps"] = True
        self.no_cond_insts["clrex"] = True
        self.no_cond_insts["dsb"] = True
        self.no_cond_insts["dmb"] = True
        self.no_cond_insts["isb"] = True

        self.allow_unaligned = {}
        self.allow_unaligned["ldrh"] = True
        self.allow_unaligned["ldrht"] = True
        self.allow_unaligned["ldrsh_imm"] = True
        self.allow_unaligned["ldrsh_reg"] = True
        self.allow_unaligned["ldrsht"] = True
        self.allow_unaligned["strh_imm"] = True
        self.allow_unaligned["strh_reg"] = True
        self.allow_unaligned["strht"] = True
        self.allow_unaligned["tbh"] = True
        self.allow_unaligned["ldr_imm"] = True
        self.allow_unaligned["ldr_reg"] = True
        self.allow_unaligned["ldr_lit"] = True
        self.allow_unaligned["ldrt"] = True
        self.allow_unaligned["str_imm"] = True
        self.allow_unaligned["str_reg"] = True
        self.allow_unaligned["strt"] = True

        self.branch_to = None
        self.is_halted = False
        self.current = ""
    

    def save(self):
        params = {}
        params['regs'] = self.regs
        params['regs_usr'] = self.regs_usr
        params['regs_svc'] = self.regs_svc
        params['regs_mon'] = self.regs_mon
        params['regs_abt'] = self.regs_abt
        params['regs_und'] = self.regs_und
        params['regs_irq'] = self.regs_irq
        params['regs_fiq'] = self.regs_fiq
        params['spsr_svc'] = self.spsr_svc
        params['spsr_mon'] = self.spsr_mon
        params['spsr_abt'] = self.spsr_abt
        params['spsr_und'] = self.spsr_und
        params['spsr_irq'] = self.spsr_irq
        params['spsr_fiq'] = self.spsr_fiq
        params['cpsr'] = self.cpsr
        params['spsr'] = self.spsr
        params['is_halted'] = self.is_halted
        return params
    

    def restore(self, params):
        self.regs = params['regs']
        self.regs_usr = params['regs_usr']
        self.regs_svc = params['regs_svc']
        self.regs_mon = params['regs_mon']
        self.regs_abt = params['regs_abt']
        self.regs_und = params['regs_und']
        self.regs_irq = params['regs_irq']
        self.regs_fiq = params['regs_fiq']
        self.spsr_svc = params['spsr_svc']
        self.spsr_mon = params['spsr_mon']
        self.spsr_abt = params['spsr_abt']
        self.spsr_und = params['spsr_und']
        self.spsr_irq = params['spsr_irq']
        self.spsr_fiq = params['spsr_fiq']
        self.cpsr = params['cpsr']
        self.spsr = params['spsr']
        self.is_halted = params['is_halted']
    

    def dump(self):
        display.log("mode=" + self.mode2string[self.cpsr.m])
        display.log("halted=" + str(self.is_halted))
        self.dump_regs(None)
        self.dump_banked_regs()
        self.dump_cpsr()
        self.dump_spsr()
    

    def dump_stack(self):
        sp = self.regs[13]
        display.wipe()
        display.log("Stack values:")
        for i in xrange(0, 50):
            addr = sp + i*4
            val = self.ld_word(addr)
            display.log("\t" + toStringHex32(addr) + ":\t" + toStringHex32(val) + "(" + str(val) + ")")
        
    

    def get_pc(self):
        return self.regs[15] + 8
    

    def reg(self, i):
        if (i == 15):
            return self.get_pc()
        else:
            return self.regs[i]
    

    def dump_banked_regs(self):
        self.output_banked_regs(display)
    

    def output_banked_regs(self, target):
        indent = "                                                                      "
        msg = "USR: "
        for i in xrange(0, 7+1):
            msg += "[ " + str(i) + "]=" + toStringHex32(self.regs_usr[i]) + " "
        target.log(msg)
        msg = "     "
        for i in xrange(8, 9+1):
            msg += "[ " + str(i) + "]=" + toStringHex32(self.regs_usr[i]) + " "
        for i in xrange(10, 15+1):
            msg += "[" + str(i) + "]=" + toStringHex32(self.regs_usr[i]) + " "
        target.log(msg)
        msg = "SVC: " + indent
        for i in xrange(13, 14+1):
            msg += "[" + str(i) + "]=" + toStringHex32(self.regs_svc[i]) + " "
        target.log(msg)
        msg = "MON: " + indent
        for i in xrange(13, 14+1):
            msg += "[" + str(i) + "]=" + toStringHex32(self.regs_mon[i]) + " "
        target.log(msg)
        msg = "ABT: " + indent
        for i in xrange(13, 14+1):
            msg += "[" + str(i) + "]=" + toStringHex32(self.regs_abt[i]) + " "
        target.log(msg)
        msg = "UND: " + indent
        for i in xrange(13, 14+1):
            msg += "[" + str(i) + "]=" + toStringHex32(self.regs_und[i]) + " "
        target.log(msg)
        msg = "IRQ: " + indent
        for i in xrange(13, 14+1):
            msg += "[" + str(i) + "]=" + toStringHex32(self.regs_irq[i]) + " "
        target.log(msg)
        msg = "FIQ: "
        for i in xrange(8, 9+1):
            msg += "[ " + str(i) + "]=" + toStringHex32(self.regs_fiq[i]) + " "
        for i in xrange(10, 14+1):
            msg += "[" + str(i) + "]=" + toStringHex32(self.regs_fiq[i]) + " "
        target.log(msg)
    

    def log_cpsr(self):
        if (not self.options.enable_logger):
            return
        self.output_cpsr(logger)
    

    def dump_cpsr(self):
        self.output_cpsr(display)
    

    def dump_spsr(self):
        self.output_spsr(display)
    

    def log_apsr(self):
        if (not self.options.enable_logger):
            return
        self.output_apsr(logger)
    

    def dump_apsr(self):
        self.output_apsr(display)
    

    def output_apsr(self, target):
        msg = "APSR: "
        msg += "N[%s]" % self.cpsr.n
        msg += "Z[%s]" % self.cpsr.z
        msg += "C[%s]" % self.cpsr.c
        msg += "V[%s]" % self.cpsr.v
        msg += "Q[%s]" % self.cpsr.q
        target.log(msg)
    

    def output_psr(self, name, psr, target):
        msg = name + ": "
        msg += "N[%s]" % psr.n
        msg += "Z[%s]" % psr.z
        msg += "C[%s]" % psr.c
        msg += "V[%s]" % psr.v
        msg += "Q[%s]" % psr.q
        msg += "A[%s]" % psr.a
        msg += "I[%s]" % psr.i
        msg += "F[%s]" % psr.f
        msg += "M[%s]" % bin(psr.m)[2:]
        target.log(msg)
    

    def output_cpsr(self, target):
        self.output_psr("CPSR", self.cpsr, target)
    

    def output_spsr(self, target):
        self.output_psr("SPSR_svc", self.spsr_svc, target)
        self.output_psr("SPSR_mon", self.spsr_mon, target)
        self.output_psr("SPSR_abt", self.spsr_abt, target)
        self.output_psr("SPSR_und", self.spsr_und, target)
        self.output_psr("SPSR_irq", self.spsr_irq, target)
        self.output_psr("SPSR_fiq", self.spsr_fiq, target)
    

    def log_regs(self, oldregs):
        if (not self.options.enable_logger):
            return
        self.output_regs(logger, oldregs)
    

    def dump_regs(self, oldregs):
        self.output_regs(display, oldregs)
    

    def output_regs(self, target, oldregs):
        indent = "     "
        msg = indent
        if (oldregs == None):
            for i in xrange(0, 8):
                msg += "[ " + str(i) + "]=" + toStringHex32(self.regs[i]) + " "
            target.log(msg)
            msg = indent
            for i in xrange(8, 16):
                msg += "[" + (" " if i < 10 else "") + str(i) + "]=" + toStringHex32(self.regs[i]) + " "
            target.log(msg)
        else:
            changed = False
            for i in xrange(0, 8):
                if (self.regs[i] == oldregs[i]):
                    #     " [10]=60000093"
                    msg += "              "
                else:
                    msg += "[ " + str(i) + "]=" + toStringHex32(self.regs[i]) + " "
                    changed = True
                
            
            if (changed):
                target.log(msg)

            changed = False
            msg = indent
            for i in xrange(8, 15): # PC will change every execution, so don't show it
                if (self.regs[i] == oldregs[i]):
                    #     " [10]=60000093"
                    msg += "              "
                else:
                    msg += "[" + (" " if i < 10 else "") + str(i) + "]=" + toStringHex32(self.regs[i]) + " "
                    changed = True
                
            
            if (changed):
                target.log(msg)
        
    
    def dump_value(self, value, name):
        self.output_value(display, value, name)
    

    def log_value(self, value, name):
        if (not self.options.enable_logger):
            return

        self.output_value(logger, value, name)
    

    def output_value(self, target, value, name):
        if (name):
            target.log(name + "=" + str(value) + "\t" + toStringHex32(value) + "(" + toStringBin32(value) + ")")
        else:
            target.log("value=" + str(value) + "\t" + toStringHex32(value) + "(" + toStringBin32(value) + ")")
    

    def is_bad_mode(self, mode):
        if mode in (self.SVC_MODE,
            self.IRQ_MODE,
            self.USR_MODE,
            self.ABT_MODE,
            self.FIQ_MODE,
            self.UND_MODE,
            self.SYS_MODE): return False

        #case self.MON_MODE: # !HaveSecurityExt()
        return True

        
    

    def is_priviledged(self):
        mode = self.cpsr.m
        if (mode == self.USR_MODE):
            return False
        else:
            return True
    

    def is_user_or_system(self):
        mode = self.cpsr.m
        if (mode == self.USR_MODE or mode == self.SYS_MODE):
            return True
        else:
            return False
    

    def is_secure(self):
        return False
    

    def scr_get_aw(self):
        return 1 # the CPSR.A bit can be modified in any security state.
    

    def scr_get_fw(self):
        return 1 # the CPSR.F bit can be modified in any security state.
    

    def nsacr_get_rfr(self):
        return 0 # FIQ mode and the FIQ Banked registers are accessible in Secure and Non-secure security states.
    

    def sctlr_get_nmfi(self):
        return self.coprocs[15].sctlr_get_nmfi()
    

    def parse_psr(self, value):
        psr = PSR()
        psr.n = value >> 31
        psr.z = (value >> 30) & 1
        psr.c = (value >> 29) & 1
        psr.v = (value >> 28) & 1
        psr.q = (value >> 27) & 1
        psr.e = (value >> 9) & 1
        psr.a = (value >> 8) & 1
        psr.i = (value >> 7) & 1
        psr.f = (value >> 6) & 1
        psr.t = (value >> 5) & 1
        psr.m = value & 0x1f
        return psr
    

    def psr_to_value(self, psr):
        value = psr.m
        value += psr.t << 5
        value += psr.f << 6
        value += psr.i << 7
        value += psr.a << 8
        value += psr.e << 9
        value += psr.q << 27
        value += psr.v << 28
        value += psr.c << 29
        value += psr.z << 30
        value += psr.n << 31
        return value
    

    def clone_psr(self, src):
        dst = PSR()
        dst.n = src.n
        dst.z = src.z
        dst.c = src.c
        dst.v = src.v
        dst.q = src.q
        dst.e = src.e
        dst.a = src.a
        dst.i = src.i
        dst.f = src.f
        dst.t = src.t
        dst.m = src.m
        return dst
    

    def set_current_spsr(self, spsr):
        if self.cpsr.m == self.USR_MODE:
            raise Exception("set_current_spsr user")
        elif self.cpsr.m == self.FIQ_MODE:
            self.spsr_fiq = spsr
        elif self.cpsr.m == self.IRQ_MODE:
            self.spsr_irq = spsr
        elif self.cpsr.m == self.SVC_MODE:
            self.spsr_svc = spsr
        elif self.cpsr.m == self.MON_MODE:
            self.spsr_mon = spsr
        elif self.cpsr.m == self.ABT_MODE:
            self.spsr_abt = spsr
        elif self.cpsr.m == self.UND_MODE:
            self.spsr_und = spsr
        elif self.cpsr.m == self.SYS_MODE:
            raise Exception("set_current_spsr system user")
        else:
            raise Exception("set_current_spsr unknown")
        
    

    def get_current_spsr(self):
        if self.cpsr.m == self.USR_MODE:
            raise Exception("get_current_spsr user")
        elif self.cpsr.m == self.FIQ_MODE:
            return self.spsr_fiq
        elif self.cpsr.m == self.IRQ_MODE:
            return self.spsr_irq
        elif self.cpsr.m == self.SVC_MODE:
            return self.spsr_svc
        elif self.cpsr.m == self.MON_MODE:
            return self.spsr_mon
        elif self.cpsr.m == self.ABT_MODE:
            return self.spsr_abt
        elif self.cpsr.m == self.UND_MODE:
            return self.spsr_und
        elif self.cpsr.m == self.SYS_MODE:
            raise Exception("get_current_spsr system user")
        else:
            raise Exception("get_current_spsr unknown")
        
        return None
    

    def spsr_write_by_instr0(self, spsr, psr, bytemask):
        if (self.is_user_or_system()):
            self.abort_unpredictable("spsr_write_by_instr0")
        if (bytemask & 8):
            spsr.n = psr.n
            spsr.z = psr.z
            spsr.c = psr.c
            spsr.v = psr.v
            spsr.q = psr.q
        
        if (bytemask & 4):
            spsr.ge = psr.ge
        
        if (bytemask & 2):
            spsr.e = psr.e
            spsr.a = psr.a
        
        if (bytemask & 1):
            spsr.i = psr.i
            spsr.f = psr.f
            spsr.t = psr.t
            if (not self.is_good_mode[psr.m]):
                self.abort_unpredictable("spsr_write_by_instr0", psr.m)
            else:
                spsr.m = psr.m
        
        return spsr
    

    def spsr_write_by_instr(self, psr, bytemask):
        spsr = self.get_current_spsr()
        self.spsr_write_by_instr0(spsr, psr, bytemask)
        self.set_current_spsr(spsr) # XXX
    

    def cpsr_write_by_instr(self, psr, bytemask, affect_execstate):
        is_priviledged = self.is_priviledged()
        nmfi = self.sctlr_get_nmfi() == 1
        if (self.options.enable_logger):
            oldregs = [0]*16
            self.store_regs(oldregs)
            self.log_cpsr()
        

        if (bytemask & 8):
            self.cpsr.n = psr.n
            self.cpsr.z = psr.z
            self.cpsr.c = psr.c
            self.cpsr.v = psr.v
            self.cpsr.q = psr.q
        
        if (bytemask & 2):
            self.cpsr.e = psr.e
            if (is_priviledged and (self.is_secure() or self.scr_get_aw() == 1)):
                self.cpsr.a = psr.a
        
        if (bytemask & 1):
            if (is_priviledged):
                self.cpsr.i = psr.i
            
            if (is_priviledged and (self.is_secure() or self.scr_get_fw() == 1) and (not nmfi or psr.f == 0)):
                self.cpsr.f = psr.f
            if (affect_execstate):
                self.cpsr.t = psr.t
            if (is_priviledged):
                if (not self.is_good_mode[psr.m]):
                    self.abort_unpredictable("cpsr_write_by_instr", psr.m)
                else:
                    if (not self.is_secure() and psr.m == self.MON_MODE):
                        self.abort_unpredictable("cpsr_write_by_instr", psr.m)
                    if (not self.is_secure() and psr.m == self.FIQ_MODE and self.nsacr_get_rfr() == 1):
                        self.abort_unpredictable("cpsr_write_by_instr", psr.m)
                    if (self.cpsr.m != psr.m):
                        self.change_mode(psr.m)
                
            
        
        if (self.options.enable_logger):
            self.log_cpsr()
            self.log_regs(oldregs)
        
    

    def save_to_regs(self, mode):
        if mode == self.USR_MODE:
            self.regs_usr[13] = self.regs[13]
            self.regs_usr[14] = self.regs[14]
        elif mode == self.FIQ_MODE:
            self.regs_fiq[8] = self.regs[8]
            self.regs_fiq[9] = self.regs[9]
            self.regs_fiq[10] = self.regs[10]
            self.regs_fiq[11] = self.regs[11]
            self.regs_fiq[12] = self.regs[12]
            self.regs_fiq[13] = self.regs[13]
            self.regs_fiq[14] = self.regs[14]
        elif mode == self.IRQ_MODE:
            self.regs_irq[13] = self.regs[13]
            self.regs_irq[14] = self.regs[14]
        elif mode == self.SVC_MODE:
            self.regs_svc[13] = self.regs[13]
            self.regs_svc[14] = self.regs[14]
        elif mode == self.MON_MODE:
            self.regs_mon[13] = self.regs[13]
            self.regs_mon[14] = self.regs[14]
        elif mode == self.ABT_MODE:
            self.regs_abt[13] = self.regs[13]
            self.regs_abt[14] = self.regs[14]
        elif mode == self.UND_MODE:
            self.regs_und[13] = self.regs[13]
            self.regs_und[14] = self.regs[14]
        elif mode == self.SYS_MODE:
            raise Exception("save_to_regs system")
        else:
            raise Exception("save_to_regs unknown: " + hex(mode))
        
    

    def restore_from_regs(self, mode):
        if mode == self.USR_MODE:
            self.regs[13] = self.regs_usr[13]
            self.regs[14] = self.regs_usr[14]
        elif mode == self.FIQ_MODE:
            self.regs[8] = self.regs_fiq[8]
            self.regs[9] = self.regs_fiq[9]
            self.regs[10] = self.regs_fiq[10]
            self.regs[11] = self.regs_fiq[11]
            self.regs[12] = self.regs_fiq[12]
            self.regs[13] = self.regs_fiq[13]
            self.regs[14] = self.regs_fiq[14]
        elif mode == self.IRQ_MODE:
            self.regs[13] = self.regs_irq[13]
            self.regs[14] = self.regs_irq[14]
        elif mode == self.SVC_MODE:
            self.regs[13] = self.regs_svc[13]
            self.regs[14] = self.regs_svc[14]
        elif mode == self.MON_MODE:
            self.regs[13] = self.regs_mon[13]
            self.regs[14] = self.regs_mon[14]
        elif mode == self.ABT_MODE:
            self.regs[13] = self.regs_abt[13]
            self.regs[14] = self.regs_abt[14]
        elif mode == self.UND_MODE:
            self.regs[13] = self.regs_und[13]
            self.regs[14] = self.regs_und[14]
        elif mode == self.SYS_MODE:
            raise Exception("restore_from_regs system")
        else:
            raise Exception("restore_from_regs unknown: " + hex(mode))
        
    

    def change_mode(self, mode):
        if (not mode):
            raise Exception("Invalid mode: " + mode)
        if (self.options.enable_logger):
            logger.log("changing mode from " + self.mode2string[self.cpsr.m] + " to " + self.mode2string[mode])
        self.save_to_regs(self.cpsr.m)
        self.cpsr.m = mode
        self.restore_from_regs(self.cpsr.m)
    

    def set_apsr(self, val, set_overflow):
        self.cpsr.n = val >> 31
        self.cpsr.z = (1 if (val == 0) else 0)
        self.cpsr.c = self.carry_out
        if (set_overflow):
            self.cpsr.v = self.overflow
        if (self.options.enable_logger):
            self.log_apsr()
    

    def store_regs(self, regs):
        for i in xrange(0, 16):
            regs[i] = self.regs[i]
    


    # 
    # Coprocessors
    # 
    def coproc_accepted(self, cp):
        return cp == 15 # FIXME
    

    def coproc_get_word(self, cp, inst):
        return self.coprocs[cp].get_word(inst)
    

    def coproc_send_word(self, cp, inst, word):
        return self.coprocs[cp].send_word(inst, word)
    

    def coproc_internal_operation(self, cp, inst):
        self.log_value(cp, "cp")
        raise Exception("coproc")
        return self.coprocs[cp].internal_operation(inst)
    

    # 
    # Alignment
    # 
    def align(self, value, align):
        assert (value & 3) == 0, "align"
        return value # FIXME
    

    def unaligned_support(self):
        return True
    

    # 
    # Instruction printers
    # 
    def abort_unknown_inst(self, inst, addr):
        display.log("\nUnknown instruction: " + toStringInst(inst))
        raise Exception("UNKNOWN")
    

    def abort_simdvfp_inst(self, inst, addr):
        display.log("\nSIMD or VFP instruction: " + toStringInst(inst))
        raise Exception("SIMD or VFP")
    

    def abort_not_impl(self, name, inst, addr):
        display.log("\n--" + name + " not implemented: " + toStringInst(inst))
        raise Exception("NOT IMPLEMENTED: " + name)
    

    def abort_undefined_instruction(self, category, inst, addr):
        display.log("\nUndefined instruction in " + category + ": " + toStringInst(inst))
        raise Exception("UNDEFINED: " + category)
    

    def abort_unpredictable(self, category, value):
        display.log("\nUnpredictable in " + category + ": " + hex(value) + "(" + hex(value) + ")")
        raise Exception("UNPREDICTABLE: " + category)
    

    def abort_unpredictable_instruction(self, category, inst, addr):
        display.log("\nUnpredictable instruction in " + category + ": " + hex(inst) + "(" + bin(inst) + ")")
        raise Exception("UNPREDICTABLE: " + category)
    

    def abort_decode_error(self, inst, addr):
        display.log("\nDecode error: " + toStringInst(inst))
        raise Exception("Decode error")
    

    def print_inst(self, name, inst, addr):
        if (not self.options.enable_logger):
            return
        msg = "\n@" + toStringHex32(addr) + ": "
        if (name):
            msg += toStringInst(inst) + ": " + name
        else:
            msg += toStringInst(inst)
        
        logger.log(msg)
    

    def toRegName(self, i):
        if i == 15: return "pc"
        elif i == 14: return "lr"
        elif i == 13: return "sp"
        elif i == 12: return "ip"
        elif i == 11: return "fp"
        elif i == 10: return "sl"
        else: return "r" + str(i)
        
    

    def print_inst_unimpl(self, addr, inst, name):
        if (not self.options.enable_tracer):
            return
        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        pf = self.cond_postfix(inst)
        msg += name + pf + "\t"
        tracer.log(msg, inst)
    

    def print_inst_uxtab(self, addr, inst, name, d, n, m, rotation):
        if (not self.options.enable_tracer):
            return
        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        pf = self.cond_postfix(inst)
        msg += name + pf + "\t"
        items = []
        items.append(self.toRegName(d))
        if (n):
            items.append(self.toRegName(n))
        items.append(self.toRegName(m))
        if (rotation):
            items.append(str(rotation))

        msg += ', '.join(items)
        tracer.log(msg, inst)
    

    def print_inst_ubfx(self, addr, inst, name, d, n, msbit, lsbit):
        if (not self.options.enable_tracer):
            return
        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        pf = self.cond_postfix(inst)
        msg += name + pf + "\t"
        items = []
        items.append(self.toRegName(d))
        if (n):
            items.append(self.toRegName(n))
        items.append("#" + str(msbit))
        items.append("#" + str(lsbit))
        msg += ', '.join(items)
        tracer.log(msg, inst)
    

    def print_inst_mcrmrc(self, addr, inst, name, t, cp):
        if (not self.options.enable_tracer):
            return
        opc1 = bitops.get_bits(inst, 23, 21)
        crn = bitops.get_bits(inst, 19, 16)
        opc2 = bitops.get_bits(inst, 7, 5)
        crm = bitops.get_bits(inst, 3, 0)

        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        pf = self.cond_postfix(inst)
        msg += name + pf + "\t"
        items = []
        items.append(str(cp))
        items.append(str(opc1))
        items.append(self.toRegName(t))
        items.append("cr" + str(crn))
        items.append("cr" + str(crm))
        #if (opc2):
        items.append("{" + str(opc2) + "}")
        msg += ', '.join(items)
        tracer.log(msg, inst)
    

    def print_inst_svc(self, addr, inst, val):
        if (not self.options.enable_tracer):
            return
        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        msg += "svc\t"
        msg += "0x" + toStringHex32(val)
        tracer.log(msg, inst)
    

    def print_inst_mrs(self, addr, inst, d):
        if (not self.options.enable_tracer):
            return
        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        msg += "mrs\t"
        msg += self.toRegName(d) + ", CPSR"
        tracer.log(msg, inst)
    

    def print_inst_msr(self, addr, inst, n, imm):
        if (not self.options.enable_tracer):
            return
        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        msg += "msr\t"
        if (n):
            msg += "CPSR_c, " + self.toRegName(n)
        elif (imm):
            imm_str = "#" + str(imm)
            msg += "CPSR_c, " + imm_str
        
        tracer.log(msg, inst)
    

    def print_inst_ldstm(self, addr, inst, name, wback, t, reglist):
        if (not self.options.enable_tracer):
            return
        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        pf = self.cond_postfix(inst)
        msg += name + pf + "\t"
        items = []
        if (t != None):
            items.append(self.toRegName(t) + ("!" if wback else ""))
        _items = []
        for r in reglist:
            _items.append(self.toRegName(r))
        
        items.append("{" + ", ".join(_items) + "}")
        msg += ', '.join(items)
        tracer.log(msg, inst)
    

    def print_inst_rsr(self, addr, inst, name, s, d, n, m, stype, sn):
        if (not self.options.enable_tracer):
            return
        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        pf = self.cond_postfix(inst)
        msg += name + pf + ("s" if s == 1 else "") + "\t"
        items = []
        if (d):
            items.append(self.toRegName(d))
        if (n):
            items.append(self.toRegName(n))
        if (m):
            items.append(self.toRegName(m))
        items.append(self.shift_type_name(stype) + " " + self.toRegName(sn))
        msg += ', '.join(items)
        tracer.log(msg, inst)
    

    def print_inst_mul(self, addr, inst, name, s, dhi, dlo, n, m):
        if (not self.options.enable_tracer):
            return
        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        pf = self.cond_postfix(inst)
        msg += name + pf + ("s" if s == 1 else "") + "\t"
        items = []
        if (dlo != None):
            items.append(self.toRegName(dlo))
        if (dhi != None):
            items.append(self.toRegName(dhi))
        if (n != None):
            items.append(self.toRegName(n))
        if (m != None):
            items.append(self.toRegName(m))
        msg += ', '.join(items)
        tracer.log(msg, inst)
    
    def print_inst_reg(self, addr, inst, name, s, d, n, m, stype=None, sn=None, ldst=None, wback=None, index=False):
        if (not self.options.enable_tracer):
            return
        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        pf = self.cond_postfix(inst)
        msg += name + pf + ("s" if s == 1 else "") + "\t"
        items = []
        if (d != None):
            items.append(self.toRegName(d))
        if (ldst):
            _items = []
            if (n != None):
                _items.append(self.toRegName(n))
            if (m != None):
                _items.append(self.toRegName(m))
            if (sn):
                _items.append(self.shift_type_name(stype) + " #" + str(sn))
            items.append("[" + ", ".join(_items) + "]" + ("!" if wback else ""))
        else:
            if (n != None):
                items.append(self.toRegName(n))
            if (m != None):
                items.append(self.toRegName(m))
            if (sn):
                items.append(self.shift_type_name(stype) + " #" + str(sn))
        
        msg += ', '.join(items)
        tracer.log(msg, inst)
    

    def print_inst_imm(self, addr, inst, name, s, d, n, imm, ldst=None, wback=None, is_add=True, is_index=True):
        if (not self.options.enable_tracer):
            return
        # is_add = add == undefined ? True : add
        # is_index = index == undefined ? True : index
        imm_str = "#" + str(imm if is_add else -imm)
        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        pf = self.cond_postfix(inst)
        msg += name + pf + ("s" if s == 1 else "") + "\t"
        items = []
        if (d != None):
            items.append(self.toRegName(d))
        if (ldst):
            if (is_index):
                _items = []
                _items.append(self.toRegName(n))
                if (imm != 0):
                    _items.append(imm_str)
                items.append("[" + ", ".join(_items) + "]" + ("!" if wback else ""))
            else:
                items.append("[" + self.toRegName(n) + "]")
                items.append(imm_str)
            
        else:
            if (n != None):
                items.append(self.toRegName(n))
            items.append(imm_str)
        
        msg += ', '.join(items)
        tracer.log(msg, inst)
    

    def print_inst_branch(self, addr, inst, name, branch_to, reg=None):
        if (not self.options.enable_tracer):
            return
        msg = toStringHex32(addr) + ":\t"
        msg += toStringHex32(inst) + "\t"
        pf = self.cond_postfix(inst)
        msg += name + pf + "\t"
        if (reg):
            msg += self.toRegName(reg)
            msg += "\t " + toStringHex32(branch_to)
        else:
            if (branch_to in self.symbols):
                msg += toStringHex32(branch_to) + " <" + self.symbols[branch_to] + ">"
            else:
                msg += toStringHex32(branch_to)
        
        tracer.log(msg, inst)
    

    def sp_used(self, name, inst):
        if (not self.options.enable_logger):
            return
        logger.log("SP: " + name + ": " + toStringInst(inst))
    

    def push_used(self, name, list):
        if (not self.options.enable_logger):
            return
        logger.log("PUSH: " + name + ": " + toStringBin16(list))
    

    def pop_used(self, name, list):
        if (not self.options.enable_logger):
            return
        logger.log("POP: " + name + ": " + toStringBin16(list))
    

    def print_pc(self, newpc, oldpc):
        if (not self.options.enable_logger):
            return
        if (oldpc):
            logger.log("PC: %x from %x (%x)"%(newpc, oldpc, newpc-oldpc))
        else:
            logger.log("PC: %x" % newpc)
    

    def call_supervisor(self):
        raise Exception("SUPERVISOR")
    

    def toStringSymbol(self, addr):
        if (addr in self.symbols):
            return self.symbols[addr] + "(%x)"%addr
        else:
            return "%x"%addr
    

    # 
    # Load/Store operations
    # 
    def allow_unaligned_access(self):
        if (not self.mmu.check_unaligned):
            return True
        else:
            return False
    

    def ld_word(self, addr):
        if (addr == self.options.show_act_on_viraddr):
            display.log("@" + hex(self.regs[15]) + ": " + self.toStringSymbol(addr) + ": read")

        if (addr & 3):
            if (not self.allow_unaligned_access()):
                raise Exception("Unaligned ld_word: " + self.current + "@" + toStringHex32(addr))
            else:
                val = 0
                mmu = self.mmu
                memctlr = self.memctlr
                for i in xrange(0, 4):
                    phyaddr = mmu.trans_to_phyaddr(addr + i)
                    val = bitops.set_bits(val, 8*i+7, 8*i, memctlr.ld_byte(phyaddr))
                
                return val
            
        else:
            phyaddr = self.mmu.trans_to_phyaddr(addr)
            return self.memctlr.ld_word(phyaddr)
        
    

    def st_word(self, addr, word):
        if (addr == self.options.show_act_on_viraddr):
            display.log("@" + hex(self.regs[15]) + ": " + self.toStringSymbol(addr) + ": write " + toStringNum(word))

        if (addr & 3):
            if (not self.allow_unaligned_access()):
                raise Exception("Unaligned st_word: " + self.current + "@" + toStringHex32(addr))
            else:
                mmu = self.mmu
                memctlr = self.memctlr
                for i in xrange(0, 4):
                    phyaddr = mmu.trans_to_phyaddr(addr + i)
                    memctlr.st_byte(phyaddr, bitops.get_bits(word, 8*i+7, 8*i))
                
            
        else:
            phyaddr = self.mmu.trans_to_phyaddr(addr, True)
            self.memctlr.st_word(phyaddr, word)
        
    

    def ld_halfword(self, addr):
        if (addr & 1):
            if (not self.allow_unaligned_access()):
                raise Exception("Unaligned ld_halfword: " + self.current + "@" + toStringHex32(addr))
            else:
                val = 0
                mmu = self.mmu
                memctlr = self.memctlr
                for i in xrange(0, 2):
                    phyaddr = mmu.trans_to_phyaddr(addr + i)
                    val = bitops.set_bits(val, 8*i+7, 8*i, memctlr.ld_byte(phyaddr))
                
                return val
            
        else:
            phyaddr = self.mmu.trans_to_phyaddr(addr)
            return self.memctlr.ld_halfword(phyaddr)
        
    

    def st_halfword(self, addr, hw):
        if (addr & 1):
            if (not self.allow_unaligned_access()):
                raise Exception("Unaligned st_halfword: " + self.current + "@" + toStringHex32(addr))
            else:
                mmu = self.mmu
                memctlr = self.memctlr
                for i in xrange(0, 2):
                    phyaddr = mmu.trans_to_phyaddr(addr + i)
                    memctlr.st_byte(phyaddr, bitops.get_bits(hw, 8*i+7, 8*i))
                
            
        else:
            phyaddr = self.mmu.trans_to_phyaddr(addr, True)
            self.memctlr.st_halfword(phyaddr, hw)
        
    

    def ld_byte(self, addr):
        phyaddr = self.mmu.trans_to_phyaddr(addr)
        return self.memctlr.ld_byte(phyaddr)
    

    def st_byte(self, addr, b):
        phyaddr = self.mmu.trans_to_phyaddr(addr, True)
        self.memctlr.st_byte(phyaddr, b)
    
    def ld_string(self, addr):
        r = ""
        while True:
            c = self.ld_byte(addr)
            if c == 0:
                break
            r += chr(c)
            addr += 1
        return r

    def fetch_instruction(self, addr):
        phyaddr = self.mmu.trans_to_phyaddr(addr)
        return self.memctlr.ld_word_fast(phyaddr)
    

    # 
    # Shift Operations
    # 
    def shift_type_name(self, type):
        if type == self.SRType_LSL: return "lsl"
        elif type == self.SRType_LSR: return "lsr"
        elif type == self.SRType_ASR: return "asr"
        elif type == self.SRType_RRX: return "rrx"
        elif type == self.SRType_ROR: return "ror"
        else: return "unknown"
        
    

    def shift(self, value, type, amount, carry_in):
        return self.shift_c(value, type, amount, carry_in)
    

    def decode_imm_shift(self, type, imm5):
        # 
        # 0: LSL
        # 1: LSR
        # 2: ASR
        # 3: RRX or ROR (ARM encoding)
        # 3: RRX (In this emulator)
        # 4: ROR (In this emulator)
        # 
        if type == 0:
            self.shift_t = type
            self.shift_n = imm5
        elif type == 1 or type == 2:
            self.shift_t = type
            if (imm5 == 0):
                self.shift_n = 32
            else:
                self.shift_n = imm5
        elif type == 3:
            if (imm5 == 0):
                self.shift_t = type
                self.shift_n = 1
            else:
                self.shift_t = self.SRType_ROR
                self.shift_n = imm5
            
        else:
            raise Exception("decode_imm_shift")
        
    

    def shift_c(self, value, type, amount, carry_in):
        if (amount == 0):
            self.carry_out = carry_in
            return value
        else:
            # FIXME
            if type == 0: # LSL
                #assert(amount > 0, "lsl: amount > 0")
                val64 = value << amount
                self.carry_out = (val64 >> 32) & 1
                return val64 & 0xffffffff
                #val64 = Number64(0, value)
                #extended = val64.lsl(amount)
                #self.carry_out = extended.high & 1
                #return extended.low
            elif type == 1: # LSR
                #assert(amount > 0, "lsr: amount > 0")
                self.carry_out = 0 if (amount == 32) else ((value >> (amount - 1)) & 1)
                result = bitops.lsr(value, amount)
                #assert(result >= 0, "lsr: result = " + str(result))
                return result
            elif type == 2: # ASR
                #assert(amount > 0, "asr: amount > 0")
                self.carry_out = 0 if (amount == 32) else ((value >> (amount - 1)) & 1)
                result = bitops.asr(value, amount)
                return result
            elif type == 3: # RRX
                self.carry_out = value & 1
                result = bitops.set_bit(value >> 1, 31, carry_in)
                #assert(result >= 0, "rrx")
                return result
            elif type == 4: # ROR
                return self.ror_c(value, amount, True)
            else:
                raise Exception("shift_c")
                return 0
            
        
    

    def ror_c(self, value, amount, write):
        #assert(amount != 0)
        result = bitops.ror(value, amount)
        #assert(result >= 0, "ror")
        if (write):
            self.carry_out = result >> 31
        return result
    

    def ror(self, val, rotation):
        if (rotation == 0):
            return val
        return self.ror_c(val, rotation, False)
    

    def is_zero_bit(self, val):
        if (val == 0):
            return 1
        else:
            return 0
    

    def expand_imm_c(self, imm12, carry_in):
        unrotated_value = imm12 & 0xff
        amount = 2*(imm12 >> 8)
        if (not amount):
            self.carry_out = carry_in
            return unrotated_value
        
        return self.ror_c(unrotated_value, amount, True)
    

    def expand_imm(self, imm12):
        return self.expand_imm_c(imm12, self.cpsr.c)
    

    def add_with_carry(self, x, y, carry_in):
        unsigned_sum = x + y + carry_in
        signed_sum = bitops.sint32(x) + bitops.sint32(y) + carry_in
        #result = bitops.get_bits64(unsigned_sum, 31, 0)
        result = unsigned_sum & 0xffffffff
        #if (result < 0):
        #    result += 0x100000000
        self.carry_out = (0 if (result == unsigned_sum) else 1)
        self.overflow = 0 if (bitops.sint32(result) == signed_sum) else 1
        return result
    

    def decode_reg_shift(self, type):
        self.shift_t = type
        return type
    

    def cond_postfix(self, inst):
        cond = bitops.get_bits(inst, 31, 28)
        if cond == 0: return "eq"
        elif cond == 1: return "ne"
        elif cond == 2: return "cs"
        elif cond == 3: return "cc"
        elif cond == 4: return "mi"
        elif cond == 8: return "hi"
        elif cond == 9: return "ls"
        elif cond == 0xa: return "ge"
        elif cond == 0xb: return "lt"
        elif cond == 0xc: return "gt"
        elif cond == 0xd: return "le"
        else:
            return ""
        
    

    def is_valid(self, inst):
        return (inst != 0xe1a00000 and inst != 0) # NOP or NULL?
    

    def cond(self, inst):
        cond = inst >> 28
        ret = False
        if (cond >> 1) == 0:
            ret = self.cpsr.z == 1 # EQ or NE
        elif (cond >> 1) == 1:
            ret = self.cpsr.c == 1 # CS or CC
        elif (cond >> 1) == 2:
            ret = self.cpsr.n == 1 # MI or PL
        elif (cond >> 1) == 3:
            ret = self.cpsr.v == 1 # VS or VC
        elif (cond >> 1) == 4:
            ret = self.cpsr.c == 1 and self.cpsr.z == 0 # HI or LS
        elif (cond >> 1) == 5:
            ret = self.cpsr.n == self.cpsr.v # GE or LT
        elif (cond >> 1) == 6:
            ret = self.cpsr.n == self.cpsr.v and self.cpsr.z == 0 # GT or LE
        elif (cond >> 1) == 7:
            ret = True # AL
        
        if ((cond & 1) and cond != 0xf):
            ret = not ret
        return ret
    

    # 
    #
    # Instruction Execution
    #
    # 

    # 
    # Immediate
    # 
    def adc_imm(self, inst, addr):
        self.print_inst("ADC (immediate)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm(imm12)
        ret = self.add_with_carry(self.reg(n), imm32, self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, True)
        
        self.print_inst_imm(addr, inst, "adc", s, d, n, imm32)
    

    def add_imm(self, inst, addr):
        self.print_inst("ADD (immediate)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm(imm12)
        ret = self.add_with_carry(self.reg(n), imm32, 0)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, True)
        
        self.print_inst_imm(addr, inst, "add", s, d, n, imm32)
    

    def adr_a1(self, inst, addr):
        self.print_inst("ADR A1", inst, addr)
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm(imm12)
        ret = (self.align(self.get_pc(), 4) + imm32) & 0xffffffff
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
        
        self.print_inst_imm(addr, inst, "adr", None, d, None, imm32)
    

    def adr_a2(self, inst, addr):
        self.print_inst("ADR A2", inst, addr)
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm(imm12)
        ret = (self.align(self.get_pc(), 4) - imm32) & 0xffffffff
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
        
        self.print_inst_imm(addr, inst, "adr", None, d, None, imm32)
    

    def and_imm(self, inst, addr):
        self.print_inst("AND (immediate)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm_c(imm12, self.cpsr.c)

        valn = self.reg(n)
        ret = bitops.and_(valn, imm32)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_imm(addr, inst, "and", s, d, n, imm32)
    

    def asr_imm(self, inst, addr):
        self.print_inst("ASR (immediate)", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        m = inst & 0xf
        self.decode_imm_shift(2, imm5)
        ret = self.shift_c(self.reg(m), self.SRType_ASR, self.shift_n, self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_imm(addr, inst, "asr", s, d, m, imm5)
    

    def bic_imm(self, inst, addr):
        self.print_inst("BIC (immediate)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff

        valn = self.reg(n)
        imm32 = self.expand_imm_c(imm12, self.cpsr.c)
        ret = bitops.and_(valn, bitops.not_(imm32))
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_imm(addr, inst, "bic", s, d, n, bitops.sint32(imm32))
    

    def b(self, inst, addr):
        self.print_inst("B", inst, addr)
        imm24 = inst & 0x00ffffff
        #imm32 = SignExtend(imm24:'00', 32)
        #imm32 = bitops.sign_extend(imm24 << 2, 26, 32)
        imm26 = imm24 << 2
        imm32 = imm26
        if (imm26 & 0x02000000):
            imm32 = imm26 | 0xfc000000
        self.branch_to = self.get_pc() + imm32
        if (self.branch_to >= 0x100000000):
            self.branch_to -= 0x100000000
        self.print_inst_branch(addr, inst, "b", self.branch_to)
    

    def bl_imm(self, inst, addr):
        self.print_inst("BL, BLX (immediate)", inst, addr)
        #imm24 = bitops.get_bits(inst, 23, 0)
        #imm32 = bitops.sign_extend(imm24 << 2, 26, 32)
        imm24 = inst & 0x00ffffff
        imm26 = imm24 << 2
        imm32 = imm26
        if (imm26 & 0x02000000):
            imm32 = imm26 | 0xfc000000
        self.regs[14] = (self.get_pc() - 4) & 0xffffffff
        # BranchWritePC(Align(PC,4) + imm32)
        self.branch_to = self.align(bitops.lsl((self.get_pc()) >> 2, 2), 4) + imm32
        if (self.branch_to >= 0x100000000):
            self.branch_to -= 0x100000000
        self.print_inst_branch(addr, inst, "bl", self.branch_to)
    

    def cmn_imm(self, inst, addr):
        self.print_inst("CMN (immediate)", inst, addr)
        n = (inst >> 16) & 0xf
        imm12 = inst & 0xfff

        valn = self.reg(n)
        imm32 = self.expand_imm(imm12)
        ret = self.add_with_carry(valn, imm32, 0)
        self.set_apsr(ret, True)
        self.print_inst_imm(addr, inst, "cmn", None, None, n, imm32)
    

    def cmp_imm(self, inst, addr):
        self.print_inst("CMP (immediate)", inst, addr)
        n = (inst >>  16) & 0xf
        imm12 = inst & 0xfff
        valn = self.reg(n)
        imm32 = self.expand_imm(imm12)
        ret = self.add_with_carry(valn, bitops.not_(imm32), 1)
        self.set_apsr(ret, True)
        self.print_inst_imm(addr, inst, "cmp", None, None, n, imm32)
    

    def eor_imm(self, inst, addr):
        self.print_inst("EOR (immediate)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm_c(imm12, self.cpsr.c)

        valn = self.reg(n)
        ret = bitops.xor(valn, imm32)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_imm(addr, inst, "eor", s, d, n, imm32)
    

    def ldr_imm(self, inst, addr):
        self.print_inst("LDR (immediate)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm12 = (inst & 0xfff)

        if (n == 13 and p == 0 and u == 1 and w == 0 and imm12 == 4):
            # POP A2
            if (t == 15):
                self.branch_to = self.ld_word(self.regs[13])
            else:
                self.regs[t] = self.ld_word(self.regs[13])
            self.regs[13] = (self.regs[13] + 4) & 0xffffffff
            self.print_inst_unimpl(addr, inst, "pop")
            return
        
        imm32 = imm12
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn= self.reg(n)
        offset_addr = (valn + (imm32 if is_add else -imm32)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        data = self.ld_word(address)
        if (is_wback):
            self.regs[n] = offset_addr
        if (t == 15):
            self.branch_to = data
        else:
            self.regs[t] = data
        self.print_inst_imm(addr, inst, "ldr", None, t, n, imm32, True, is_wback, is_add, is_index)
    

    def ldrb_imm(self, inst, addr):
        self.print_inst("LDRB (immediate)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm32 = inst & 0xfff
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn= self.reg(n)
        offset_addr = (valn + (imm32 if is_add else -imm32)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        data = self.ld_byte(address)
        self.regs[t] = data
        if (is_wback):
            self.regs[n] = offset_addr
        self.print_inst_imm(addr, inst, "ldrb", None, t, n, imm32, True, is_wback, is_add, is_index)
    

    def ldrd_imm(self, inst, addr):
        self.print_inst("LDRD (immediate)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm4h = (inst >> 8) & 0xf
        imm4l = inst & 0xf
        t2 = t + 1
        imm32 = (imm4h << 4) + imm4l
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn= self.reg(n)
        offset_addr = (valn + (imm32 if is_add else -imm32)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        self.regs[t] = self.ld_word(address)
        self.regs[t2] = self.ld_word(address+4)
        if (is_wback):
            self.regs[n] = offset_addr
        self.print_inst_imm(addr, inst, "ldrd", None, t, n, imm32, True, is_wback, is_add, is_index)
    

    def ldrsh_imm(self, inst, addr):
        self.print_inst("LDRSH (immediate)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm4h = (inst >> 8) & 0xf
        imm4l = inst & 0xf
        imm32 = (imm4h << 4) + imm4l
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn= self.reg(n)
        offset_addr = (valn + (imm32 if is_add else -imm32)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        data = self.ld_halfword(address)
        if (is_wback):
            self.regs[n] = offset_addr
        self.regs[t] = bitops.sign_extend(data, 16, 32)
        self.print_inst_imm(addr, inst, "ldrsh", None, t, n, imm32, True, is_wback, is_add, is_index)
    

    def ldrsh_reg(self, inst, addr):
        self.print_inst("LDRSH (register)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        m = inst & 0xf
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn= self.reg(n)
        offset = self.shift(self.reg(m), self.SRType_LSL, 0, self.cpsr.c)
        offset_addr = (valn + (offset if is_add else -offset)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        data = self.ld_halfword(address)
        if (is_wback):
            self.regs[n] = offset_addr
        self.regs[t] = bitops.sign_extend(data, 16, 32)
        self.print_inst_reg(addr, inst, "ldrsh", None, t, n, m, self.SRType_LSL, 0)
    

    def lsl_imm(self, inst, addr):
        self.print_inst("LSL (immediate)", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        m = inst & 0xf

        valm = self.reg(m)
        self.decode_imm_shift(0, imm5)
        ret = self.shift_c(valm, self.SRType_LSL, self.shift_n, self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_imm(addr, inst, "lsl", s, d, m, imm5)
    

    def lsr_imm(self, inst, addr):
        self.print_inst("LSR (immediate)", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        m = inst & 0xf

        valm = self.reg(m)
        self.decode_imm_shift(1, imm5)
        ret = self.shift_c(valm, self.SRType_LSR, self.shift_n, self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_imm(addr, inst, "lsr", s, d, m, imm5)
    

    def mov_imm_a1(self, inst, addr):
        self.print_inst("MOV (immediate)", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm_c(imm12, self.cpsr.c)

        ret = imm32
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_imm(addr, inst, "mov", s, d, None, imm32)
    

    def mov_imm_a2(self, inst, addr):
        self.print_inst("MOV (immediate) A2", inst, addr)
        imm4 = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = (imm4 << 12) + imm12

        ret = imm32
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
        
        self.print_inst_imm(addr, inst, "movw", False, d, None, imm32)
    

    def movt(self, inst, addr):
        self.print_inst("MOVT", inst, addr)
        imm4 = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm16 = (imm4 << 12) + imm12

        self.regs[d] = bitops.set_bits(self.reg(d), 16, 31, imm16)
        #self.print_inst_imm(addr, inst, "movw", False, d, None, imm32)
    

    def msr_imm_sys(self, inst, addr):
        self.print_inst("MSR (immediate) (system level)", inst, addr)
        r = inst & (1 << 22)
        mask = (inst >> 16) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm(imm12)

        if (r):
            # SPSRWriteByInstr(R[n], mask)
            self.spsr_write_by_instr(self.parse_psr(imm32), mask)
        else:
            # CPSRWriteByInstr(R[n], mask, False)
            self.cpsr_write_by_instr(self.parse_psr(imm32), mask, False)
        
        self.print_inst_msr(addr, inst, None, imm32)
    

    def mvn_imm(self, inst, addr):
        self.print_inst("MVN (immediate)", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm_c(imm12, self.cpsr.c)

        ret = bitops.not_(imm32)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_imm(addr, inst, "mvn", s, d, None, imm32)
    

    def orr_imm(self, inst, addr):
        self.print_inst("ORR (immediate)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff

        valn = self.reg(n)
        imm32 = self.expand_imm_c(imm12, self.cpsr.c)
        ret = bitops.or_(valn, imm32)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_imm(addr, inst, "orr", s, d, n, imm32)
    

    def hint_preload_data(self, address):
        # FIXME
        self.log_value(address, "preload address")
    

    def pld_imm(self, inst, addr):
        self.print_inst("PLD (immediate, literal)", inst, addr)
        u = (inst >> 23) & 1
        n = (inst >> 16) & 0xf
        imm12 = inst & 0xfff

        valn = self.reg(n)
        imm32 = imm12
        is_add = u == 1
        base = self.align(self.get_pc(), 4) if (n == 15) else valn
        address = (base + (imm32 if is_add else -imm32)) & 0xffffffff
        self.hint_preload_data(address)
        self.print_inst_imm(addr, inst, "pld", None, None, n, imm32, True, None, is_add, True)
    

    def rsb_imm(self, inst, addr):
        self.print_inst("RSB (immediate)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm(imm12)
        valn = self.reg(n)
        ret = self.add_with_carry(bitops.not_(valn), imm32, 1)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, True)
        
        self.print_inst_imm(addr, inst, "rsb", s, d, n, imm32)
    

    def rsc_imm(self, inst, addr):
        self.print_inst("RSC (immediate)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm(imm12)

        valn = self.reg(n)
        ret = self.add_with_carry(bitops.not_(valn), imm32, self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, True)
        
        self.print_inst_imm(addr, inst, "rsc", s, d, n, imm32)
    

    def ror_imm(self, inst, addr):
        self.print_inst("ROR (immediate)", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        m = inst & 0xf

        valm = self.reg(m)
        self.decode_imm_shift(3, imm5)
        ret = self.shift_c(valm, self.SRType_ROR, self.shift_n, self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_imm(addr, inst, "ror", s, d, m, imm5)
    

    def rrx(self, inst, addr):
        self.print_inst("RRX", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 12) & 0xf
        m = inst & 0xf

        valm = self.reg(m)
        ret = self.shift_c(valm, self.SRType_RRX, 1, self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        #self.print_inst_imm(addr, inst, "rrx", s, d, m, None)
        self.print_inst_unimpl(addr, inst, "rrx")
    

    def sbc_imm(self, inst, addr):
        self.print_inst("SBC (immediate)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm(imm12)

        valn = self.reg(n)
        ret = self.add_with_carry(valn, bitops.not_(imm32), self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, True)
        
        self.print_inst_imm(addr, inst, "sbc", s, d, n, imm32)
    

    def str_imm(self, inst, addr):
        self.print_inst("STR (immediate)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        if (n == 13 and p == 1 and u == 0 and w == 1 and imm12 == 4):
            # PUSH A2
            sp = self.reg(13)
            address = (sp - 4) & 0xffffffff
            self.st_word(address, self.reg(t))
            self.regs[13] = address
            return
        
        imm32 = imm12
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1
        valn= self.reg(n)
        offset_addr = (valn + (imm32 if is_add else -imm32)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        valt = self.reg(t)
        self.st_word(address, valt)
        if (is_wback):
            self.regs[n] = offset_addr
        self.print_inst_imm(addr, inst, "str", None, t, n, imm32, True, is_wback, is_add, is_index)
    

    def strb_imm(self, inst, addr):
        self.print_inst("STRB (immediate)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm32 = inst & 0xfff
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn= self.reg(n)
        offset_addr = (valn + (imm32 if is_add else -imm32)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        self.st_byte(address, self.reg(t) & 0xff)
        if (is_wback):
            self.regs[n] = offset_addr
        self.print_inst_imm(addr, inst, "strb", None, t, n, imm32, True, is_wback, is_add, is_index)
    

    def sub_imm(self, inst, addr):
        self.print_inst("SUB (immediate)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm12 = inst & 0xfff
        imm32 = self.expand_imm(imm12)

        ret = self.add_with_carry(self.reg(n), bitops.not_(imm32), 1)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, True)
        
        self.print_inst_imm(addr, inst, "sub", s, d, n, imm32)
    

    def teq_imm(self, inst, addr):
        self.print_inst("TEQ (immediate)", inst, addr)
        n = (inst >> 16) & 0xf
        imm12 = inst & 0xfff

        valn = self.reg(n)
        imm32 = self.expand_imm_c(imm12, self.cpsr.c)
        ret = bitops.xor(valn, imm32)
        self.set_apsr(ret, False)
        self.print_inst_imm(addr, inst, "teq", None, None, n, imm32)
    

    def tst_imm(self, inst, addr):
        self.print_inst("TST (immediate)", inst, addr)
        n = (inst >> 16) & 0xf
        imm12 = inst & 0xfff

        valn = self.reg(n)
        imm32 = self.expand_imm_c(imm12, self.cpsr.c)
        ret = bitops.and_(valn, imm32)
        self.set_apsr(ret, False)
        self.print_inst_imm(addr, inst, "tst", None, None, n, imm32)
    

    # 
    # Literal
    # 
    def ldr_lit(self, inst, addr):
        self.print_inst("LDR (literal)", inst, addr)
        u = inst & (1 << 23)
        t = (inst >> 12) & 0xf
        imm32 = inst & 0xfff

        base = self.align(self.get_pc(), 4)
        address = (base + (imm32 if u else -imm32)) & 0xffffffff
        data = self.ld_word(address)
        if (t == 15):
            self.branch_to = data
        else:
            self.regs[t] = data
        self.print_inst_imm(addr, inst, "ldr", None, t, 15, imm32, True, None, u, True)
    

    # 
    # Register
    # 
    def adc_reg(self, inst, addr):
        self.print_inst("ADC (register)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valn = self.reg(n)
        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = self.add_with_carry(valn, shifted, self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, True)
        
        self.print_inst_reg(addr, inst, "adc", s, d, n, m, self.shift_t, self.shift_n)
    

    def add_reg(self, inst, addr):
        self.print_inst("ADD (register)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valn = self.reg(n)
        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = self.add_with_carry(valn, shifted, 0)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, True)
        
        self.print_inst_reg(addr, inst, "add", s, d, n, m, self.shift_t, self.shift_n)
    

    def and_reg(self, inst, addr):
        self.print_inst("AND (register)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valn = self.reg(n)
        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift_c(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = bitops.and_(valn, shifted)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_reg(addr, inst, "and", s, d, n, m, self.shift_t, self.shift_n)
    

    def asr_reg(self, inst, addr):
        self.print_inst("ASR (register)", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 12) & 0xf
        m = (inst >> 8) & 0xf
        n = inst & 0xf

        shift_n = bitops.get_bits(self.reg(m), 7, 0)
        ret = self.shift_c(self.reg(n), self.SRType_ASR, shift_n, self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_reg(addr, inst, "asr", s, d, n, m)
    

    def bic_reg(self, inst, addr):
        self.print_inst("BIC (register)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valn = self.reg(n)
        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift_c(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = bitops.and_(valn, bitops.not_(shifted))
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_reg(addr, inst, "bic", s, d, n, m, self.shift_t, self.shift_n)
    

    def bfc(self, inst, addr):
        self.print_inst("BFC", inst, addr)
        msbit = (inst >> 16) & 0x1f
        d = (inst >> 12) & 0xf
        lsbit = (inst >> 7) & 0x1f

        if (msbit >= lsbit):
            self.regs[d] = bitops.clear_bits(self.regs[d], msbit, lsbit)
        else:
            self.abort_unpredictable("BFC", inst, addr)
        self.print_inst_ubfx(addr, inst, "bfc", d, None, msbit, lsbit)
    

    def bfi(self, inst, addr):
        self.print_inst("BFI", inst, addr)
        msbit = (inst >> 16) & 0x1f
        d = (inst >> 12) & 0xf
        lsbit = (inst >> 7) & 0x1f
        n = inst & 0xf

        if (msbit >= lsbit):
            self.regs[d] = bitops.set_bits(self.regs[d], msbit, lsbit, bitops.get_bits(self.reg(n), msbit-lsbit, 0))
        else:
            self.abort_unpredictable("BFI", inst, addr)
        self.print_inst_ubfx(addr, inst, "bfi", d, n, msbit, lsbit)
    

    def blx_reg(self, inst, addr):
        self.print_inst("BLX (register)", inst, addr)
        m = inst & 0xf

        next_instr_addr = (self.get_pc() - 4) & 0xffffffff
        self.regs[14] = next_instr_addr
        self.branch_to = self.reg(m)
        #self.print_inst_reg(addr, inst, "blx", None, None, None, m)
        self.print_inst_branch(addr, inst, "blx", self.branch_to, m)
    

    def bx(self, inst, addr):
        self.print_inst("BX", inst, addr)
        m = inst & 0xf

        self.branch_to = self.reg(m)
        self.print_inst_branch(addr, inst, "bx", self.branch_to, m)
    

    def cdp_a1(self, inst, addr):
        self.print_inst("CDP, CDP2 A1?", inst, addr)
        t = (inst >> 12) & 0xf
        cp = (inst >> 8) & 0xf

        if ((cp >> 1) == 5):
            self.abort_simdvfp_inst(inst, addr)
        
        if (not self.coproc_accepted(cp)):
            raise Exception("GenerateCoprocessorException(): " + cp)
        else:
            self.coproc_internal_operation(cp, inst)
        
        #self.print_inst_mcrmrc(inst, "cdp", t, cp)
        self.print_inst_unimpl(addr, inst, "cdp")
    

    def clz(self, inst, addr):
        self.print_inst("CLZ", inst, addr)
        d = (inst >> 12) & 0xf
        m = inst & 0xf

        self.regs[d] = bitops.count_leading_zero_bits(self.reg(m))
        self.print_inst_reg(addr, inst, "clz", None, d, None, m)
    

    def cmn_reg(self, inst, addr):
        self.print_inst("CMN (register)", inst, addr)
        n = (inst >> 16) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valn = self.reg(n)
        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = self.add_with_carry(valn, shifted, 0)
        self.set_apsr(ret, True)
        self.print_inst_reg(addr, inst, "cmn", None, None, n, m, self.shift_t, self.shift_n)
    

    def cmp_reg(self, inst, addr):
        self.print_inst("CMP (register)", inst, addr)
        n = (inst >> 16) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valn = self.reg(n)
        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = self.add_with_carry(valn, bitops.not_(shifted), 1)
        self.set_apsr(ret, True)
        self.print_inst_reg(addr, inst, "cmp", None, None, n, m, self.shift_t, self.shift_n)
    

    def eor_reg(self, inst, addr):
        self.print_inst("EOR (register)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valn = self.reg(n)
        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift_c(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = bitops.xor(valn, shifted)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_reg(addr, inst, "eor", s, d, n, m, self.shift_t, self.shift_n)
    

    def ldr_reg(self, inst, addr):
        self.print_inst("LDR (register)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn = self.reg(n)
        self.decode_imm_shift(type, imm5)
        offset = self.shift(self.reg(m), self.shift_t, self.shift_n, self.cpsr.c)
        offset_addr = (valn + (offset if is_add else -offset)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        address = bitops.get_bits64(address, 31, 0) # XXX
        data = self.ld_word(address)
        if (is_wback):
            self.regs[n] = offset_addr
        if (t == 15):
            self.branch_to = data
        else:
            self.regs[t] = data
        self.print_inst_reg(addr, inst, "ldr", None, t, n, m, self.shift_t, self.shift_n, True, is_wback)
    

    def ldrb_reg(self, inst, addr):
        self.print_inst("LDRB (register)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        self.decode_imm_shift(type, imm5)
        valn = self.reg(n)
        offset = self.shift(self.reg(m), self.shift_t, self.shift_n, self.cpsr.c)
        offset_addr = (valn + (offset if is_add else -offset)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        data = self.ld_byte(address)
        self.regs[t] = data
        if (is_wback):
            self.regs[n] = offset_addr
        self.print_inst_reg(addr, inst, "ldrb", None, t, n, m, self.shift_t, self.shift_n, True, is_wback, is_index)
    

    def ldrd_reg(self, inst, addr):
        self.print_inst("LDRD (register)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        m = inst & 0xf
        t2 = t + 1
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn = self.reg(n)
        valm = self.reg(m)
        offset_addr = (valn + (valm if is_add else -valm)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        self.regs[t] = self.ld_word(address)
        self.regs[t2] = self.ld_word(address + 4)
        if (is_wback):
            self.regs[n] = offset_addr
        self.print_inst_reg(addr, inst, "ldrd", None, t, n, m, None, None, True, is_wback, is_index)
    

    def ldrex(self, inst, addr):
        self.print_inst("LDREX", inst, addr)
        n = bitops.get_bits(inst, 19, 16)
        t = bitops.get_bits(inst, 15, 12)

        imm32 = 0
        address = (self.reg(n) + imm32) & 0xffffffff
        # SetExclusiveMonitors(address,4)
        # R[t] = MemA[address,4]
        self.regs[t] = self.ld_word(address)
        self.print_inst_reg(addr, inst, "ldrex", None, t, n, None, None, None, True, False)
    

    def ldrexd(self, inst, addr):
        self.print_inst("LDREXD", inst, addr)
        n = bitops.get_bits(inst, 19, 16)
        t = bitops.get_bits(inst, 15, 12)
        t2 = t + 1

        address = self.reg(n)
        # SetExclusiveMonitors(address,8)
        # value = MemA[address,8]
        # R[t] = value<31:0>
        # R[t2] = value<63:31>
        self.regs[t] = self.ld_word(address)
        self.regs[t2] = self.ld_word((address + 4) & 0xffffffff)
        self.print_inst_reg(addr, inst, "ldrexd", None, t, n, None, None, None, True, False)
    

    def ldrt_a1(self, inst, addr):
        self.print_inst("LDRT A1", inst, addr)
        u = (inst >> 23) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm32 = inst & 0xfff
        is_add = u == 1

        valn = self.reg(n)
        offset = imm32
        offset_addr = (valn + (offset if is_add else -offset)) & 0xffffffff
        address = valn
        address = bitops.get_bits64(address, 31, 0) # XXX
        data = self.ld_word(address)
        if (t == 15):
            self.branch_to = data
        else:
            self.regs[t] = data
        #self.print_inst_reg(addr, inst, "ldrt", None, t, n, m, self.shift_t, self.shift_n, True, is_wback)
    

    def lsl_reg(self, inst, addr):
        self.print_inst("LSL (register)", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 12) & 0xf
        m = (inst >> 8) & 0xf
        n = inst & 0xf

        shift_n = bitops.get_bits(self.reg(m), 7, 0)
        ret = self.shift_c(self.reg(n), self.SRType_LSL, shift_n, self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_reg(addr, inst, "lsl", s, d, n, m)
    

    def lsr_reg(self, inst, addr):
        self.print_inst("LSR (register)", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 12) & 0xf
        m = (inst >> 8) & 0xf
        n = inst & 0xf

        shift_n = bitops.get_bits(self.reg(m), 7, 0)
        ret = self.shift_c(self.reg(n), self.SRType_LSR, shift_n, self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_reg(addr, inst, "lsr", s, d, n, m)
    

    def mcr_a1(self, inst, addr):
        self.print_inst("MCR, MCR2 A1", inst, addr)
        t = (inst >> 12) & 0xf
        cp = (inst >> 8) & 0xf

        if ((cp >> 1) == 5):
            self.abort_simdvfp_inst(inst, addr)
        
        if (not self.coproc_accepted(cp)):
            raise Exception("GenerateCoprocessorException()")
        else:
            self.coproc_send_word(cp, inst, self.regs[t])
        
        self.print_inst_mcrmrc(addr, inst, "mcr", t, cp)
    

    def mla(self, inst, addr):
        self.print_inst("MLA", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 16) & 0xf
        a = (inst >> 12) & 0xf
        m = (inst >> 8) & 0xf
        n = inst & 0xf

        ope1 = self.reg(n)
        ope2 = self.reg(m)
        addend = self.reg(a)

        #n64_ope1 = Number64(0, ope1)
        #n64_ope2 = Number64(0, ope2)
        #n64_addend = Number64(0, addend)
        #n64 = n64_ope1.mul(n64_ope2)
        #ret = n64.add(n64_addend)
        #self.regs[d] = ret.low
        
        ret = (ope1 * ope2 + addend) & 0xffffffff
        self.regs[d] = ret

        if (s):
            self.cpsr.n = (ret >> 31) & 1
            self.cpsr.z = (1 if (ret == 0) else 0)
            self.log_apsr()
        
        self.print_inst_reg(addr, inst, "mla", s, d, n, m) # FIXME
    


    def mls(self, inst, addr):
        self.print_inst("MLS", inst, addr)
        d = (inst >> 16) & 0xf
        a = (inst >> 12) & 0xf
        m = (inst >> 8) & 0xf
        n = inst & 0xf

        ope1 = self.reg(n)
        ope2 = self.reg(m)
        addend = self.reg(a)
        n64_ope1 = Number64(0, ope1)
        n64_ope2 = Number64(0, ope2)
        n64_addend = Number64(0, addend)
        n64 = n64_ope1.mul(n64_ope2)
        ret = n64_addend.sub(n64)
        self.regs[d] = ret.low
        self.print_inst_mul(addr, inst, "mls", None, n, d, m, a)
    

    def subs_pc_lr_a2(self, inst, addr):
        opcode = (inst >> 21) & 0xf
        n = (inst >> 16) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        self.decode_imm_shift(type, imm5)
        operand2 = self.shift(self.reg(m), self.shift_t, self.shift_n, self.cpsr.c)
        if opcode == 0:
            ret = bitops.and_(self.reg(n), operand2)
        elif opcode == 1:
            ret = bitops.xor(self.reg(n), operand2)
        elif opcode == 2:
            ret = self.add_with_carry(self.reg(n), bitops.not_(operand2), 1)
        elif opcode == 3:
            ret = self.add_with_carry(bitops.not_(self.reg(n)), operand2, 1)
        elif opcode == 4:
            ret = self.add_with_carry(self.reg(n), operand2, 0)
        elif opcode == 5:
            ret = self.add_with_carry(self.reg(n), operand2, self.cpsr.c)
        elif opcode == 6:
            ret = self.add_with_carry(self.reg(n), bitops.not_(operand2), self.cpsr.c)
        elif opcode == 7:
            ret = self.add_with_carry(bitops.not_(self.reg(n)), operand2, self.cpsr.c)
        elif opcode == 0xc:
            ret = bitops.or_(self.reg(n), operand2)
        elif opcode == 0xd:
            ret = operand2
        elif opcode == 0xe:
            ret = bitops.and_(self.reg(n), bitops.not_(operand2))
        elif opcode == 0xf:
            ret = bitops.not_(operand2)
        else:
            raise Exception("subs_pc_lr_a2: unknown opcode")
        
        self.cpsr_write_by_instr(self.get_current_spsr(), 15, True)
        self.branch_to = ret
        self.print_inst_unimpl(addr, inst, "subs")
    

    def mov_reg(self, inst, addr):
        s = inst & 0x00100000
        d = (inst >> 12) & 0xf
        m = inst & 0xf
        if (d == 15 and s):
            self.print_inst("SUBS PC LR A2", inst, addr)
            self.subs_pc_lr_a2(inst, addr)
            return
        

        ret = self.reg(m)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.cpsr.n = ret >> 31
                self.cpsr.z = (1 if (ret == 0) else 0)
                # FIXME: APSR.C = carry
                # I guess carry == 0
                #self.cpsr.c(bitops.get_bit(value, 29))
                #self.abort_not_impl("MOV (register) flag", inst, addr)
                self.log_apsr()
            
        
        self.print_inst_reg(addr, inst, "mov", s, d, None, m)
    

    def mrc_a1(self, inst, addr):
        t = (inst >> 12) & 0xf
        cp = (inst >> 8) & 0xf
        if ((cp >> 1) == 5):
            self.abort_simdvfp_inst(inst, addr)
        
        if (not self.coproc_accepted(cp)):
            raise Exception("GenerateCoprocessorException()")
        else:
            value = self.coproc_get_word(cp, inst)
            if (t != 15):
                self.regs[t] = value
            else:
                self.cpsr.n = (value >> 31) & 1
                self.cpsr.z = (value >> 30) & 1
                self.cpsr.c = (value >> 29) & 1
                self.cpsr.v = (value >> 28) & 1
                self.log_apsr()
            
        
        self.print_inst_mcrmrc(addr, inst, "mrc", t, cp)
    

    def mrs(self, inst, addr):
        self.print_inst("MRS", inst, addr)
        read_spsr = inst & (1 << 22)
        d = (inst >> 12) & 0xf

        if (read_spsr):
            if (self.is_user_or_system()):
                self.abort_unpredictable("MRS", inst, addr)
            else:
                self.regs[d] = self.psr_to_value(self.get_current_spsr())
        else:
            # CPSR AND '11111000 11111111 00000011 11011111'
            self.regs[d] = bitops.and_(self.psr_to_value(self.cpsr), 0xf8ff03df)
        
        self.print_inst_mrs(addr, inst, d)
    

    def msr_reg_sys(self, inst, addr):
        self.print_inst("MSR (register) (system level)", inst, addr)
        r = inst & (1 << 22)
        mask = (inst >> 16) & 0xf
        n = inst & 0xf

        if (r):
            # SPSRWriteByInstr(R[n], mask)
            self.spsr_write_by_instr(self.parse_psr(self.reg(n)), mask)
        else:
            # CPSRWriteByInstr(R[n], mask, False)
            self.cpsr_write_by_instr(self.parse_psr(self.reg(n)), mask, False)
        
        self.print_inst_msr(addr, inst, n)
    

    def mul(self, inst, addr):
        self.print_inst("MUL", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 16) & 0xf
        m = (inst >> 8) & 0xf
        n = inst & 0xf

        ope1 = self.reg(n)
        ope2 = self.reg(m)

        #n64_ope1 = Number64(0, ope1)
        #n64_ope2 = Number64(0, ope2)
        #ret = n64_ope1.mul(n64_ope2)
        
        ret = (ope1 * ope2) & 0xffffffff
        self.regs[d] = ret
        if (s):
            #self.cpsr.n = bitops.get_bit(ret.low, 31)
            self.cpsr.n = ret >> 31
            self.cpsr.z = (1 if (ret == 0) else 0)
            self.log_apsr()
        
        self.print_inst_reg(addr, inst, "mul", s, d, n, m) # FIXME
    

    def mvn_reg(self, inst, addr):
        self.print_inst("MVN (register)", inst, addr)
        s = inst & 0x00100000
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift_c(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = bitops.not_(shifted)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_reg(addr, inst, "mvn", s, d, None, m, self.shift_t, self.shift_n)
    

    def orr_reg(self, inst, addr):
        self.print_inst("ORR (register)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valn = self.reg(n)
        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift_c(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = bitops.or_(valn, shifted)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, False)
        
        self.print_inst_reg(addr, inst, "orr", s, d, n, m, self.shift_t, self.shift_n)
    

    def rev(self, inst, addr):
        self.print_inst("REV", inst, addr)
        d = bitops.get_bits(inst, 15, 12)
        m = bitops.get_bits(inst, 3, 0)

        valm = self.reg(m)
        ret = 0
        ret = bitops.set_bits(ret, 31, 24, bitops.get_bits(valm, 7, 0))
        ret = bitops.set_bits(ret, 23, 16, bitops.get_bits(valm, 15, 8))
        ret = bitops.set_bits(ret, 15, 8, bitops.get_bits(valm, 23, 16))
        ret = bitops.set_bits(ret, 7, 0, bitops.get_bits(valm, 31, 24))
        self.regs[d] = ret
        self.print_inst_reg(addr, inst, "rev", None, d, None, m)
    

    def rev16(self, inst, addr):
        self.print_inst("REV16", inst, addr)
        d = bitops.get_bits(inst, 15, 12)
        m = bitops.get_bits(inst, 3, 0)

        valm = self.reg(m)
        ret = 0
        ret = bitops.set_bits(ret, 31, 24, bitops.get_bits(valm, 23, 16))
        ret = bitops.set_bits(ret, 23, 16, bitops.get_bits(valm, 31, 24))
        ret = bitops.set_bits(ret, 15, 8, bitops.get_bits(valm, 7, 0))
        ret = bitops.set_bits(ret, 7, 0, bitops.get_bits(valm, 15, 8))
        self.regs[d] = ret
        self.print_inst_reg(addr, inst, "rev16", None, d, None, m)
    

    def rsb_reg(self, inst, addr):
        self.print_inst("RSB (register)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valn = self.reg(n)
        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = self.add_with_carry(bitops.not_(valn), shifted, 1)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, True)
        
        self.print_inst_reg(addr, inst, "rsb", s, d, n, m, self.shift_t, self.shift_n)
    

    def sbc_reg(self, inst, addr):
        self.print_inst("SBC (register)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valn = self.reg(n)
        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = self.add_with_carry(valn, bitops.not_(shifted), self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, True)
        
        self.print_inst_reg(addr, inst, "sbc", s, d, n, m, self.shift_t, self.shift_n)
    

    def sbfx(self, inst, addr):
        self.print_inst("SBFX", inst, addr)
        widthminus1 = (inst >> 16) & 0x1f
        d = (inst >> 12) & 0xf
        lsbit = (inst >> 7) & 0x1f
        n = inst & 0xf

        msbit = lsbit + widthminus1
        if (msbit <= 31):
            self.regs[d] = bitops.sign_extend(bitops.get_bits(self.reg(n), msbit, lsbit), msbit-lsbit+1, 32)
        else:
            self.abort_unpredictable("SBFX", inst, addr)
        self.print_inst_ubfx(addr, inst, "sbfx", d, n, lsbit, widthminus1 + 1)
    

    def smlal(self, inst, addr):
        self.print_inst("SMLAL", inst, addr)
        s = inst & 0x00100000
        dhi = (inst >> 16) & 0xf
        dlo = (inst >> 12) & 0xf
        m = (inst >> 8) & 0xf
        n = inst & 0xf

        n64_n = Number64(0, self.reg(n))
        n64_m = Number64(0, self.reg(m))
        n64 = Number64(self.reg(dhi), self.reg(dlo))
        ret = n64_n.mul(n64_m).add(n64)
        self.regs[dhi] = ret.high
        self.regs[dlo] = ret.low
        if (s):
            self.cpsr.n = bitops.get_bit(ret.high, 31)
            self.cpsr.z = 1 if ret.is_zero() else 0
            self.log_apsr()
        
        self.print_inst_mul(addr, inst, "smlal", s, dhi, dlo, n, m)
    

    def smull(self, inst, addr):
        self.print_inst("SMULL", inst, addr)
        s = inst & 0x00100000
        dhi = (inst >> 16) & 0xf
        dlo = (inst >> 12) & 0xf
        m = (inst >> 8) & 0xf
        n = inst & 0xf

        #n64_n = Number64(0, self.reg(n))
        #n64_m = Number64(0, self.reg(m))
        #ret = n64_n.mul(n64_m)
        #self.regs[dhi] = ret.high
        #self.regs[dlo] = ret.low
        
        ret = bitops.sint32(self.reg(n)) * bitops.sint32(self.reg(m))
        ret = ret % 2**64
        self.regs[dhi] = ret >> 32
        self.regs[dlo] = ret & 0xffffffff

        if (s):
            #self.cpsr.n = bitops.get_bit(ret.high, 31)
            #self.cpsr.z = 1 if ret.is_zero() else 0
            self.cpsr.n = ret >> 63
            self.cpsr.z = 1 if ret == 0 else 0
            self.log_apsr()
        
        self.print_inst_mul(addr, inst, "smull", s, dhi, dlo, n, m)
    

    def swp(self, inst, addr):
        self.print_inst("SWP(B?)", inst, addr)
        B  = (inst >> 22) & 0x1   
        Rn = (inst >> 16) & 0xF
        Rd = (inst >> 12) & 0xF
        Rm = inst & 0xF
    		
        valn = self.reg(Rn)
        valm = self.reg(Rm)
    		
        address = valn
    		
        if(B):
            data = self.ld_byte(address)
            self.st_byte(address, bitops.get_bits(valm, 7, 0))
            self.regs[Rd] = data
        else:
            data = self.ld_word(address)
            self.st_word(address, valm)
            self.regs[Rd] = data
        
        self.print_inst_reg(addr, inst, "swp"+("B" if B else ""), None, Rn, Rd, Rm, None, None, False, False) 	
    

    def strex(self, inst, addr):
        self.print_inst("STREX", inst, addr)
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        t = inst & 0xf
        imm32 = 0

        address = (self.reg(n) + imm32) & 0xffffffff
        # ExclusiveMonitorsPass(address,4)
        self.st_word(address, self.reg(t))
        self.regs[d] = 0
        # FIXME
        self.print_inst_reg(addr, inst, "strex", None, t, n, d, None, None, True, False)
    

    def strexd(self, inst, addr):
        self.print_inst("STREXD", inst, addr)
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        t = inst & 0xf
        t2 = t + 1

        address = self.reg(n)
        # ExclusiveMonitorsPass(address,8)
        self.st_word(address, self.reg(t))
        self.st_word((address + 4) & 0xffffffff, self.reg(t2))
        self.regs[d] = 0
        # FIXME
        self.print_inst_reg(addr, inst, "strexd", None, t, n, d, None, None, True, False)
    

    def sub_reg(self, inst, addr):
        self.print_inst("SUB (register)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valn = self.reg(n)
        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = self.add_with_carry(valn, bitops.not_(shifted), 1)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (s):
                self.set_apsr(ret, True)
        
        self.print_inst_reg(addr, inst, "sub", s, d, n, m, self.shift_t, self.shift_n)
    

    def sxtb(self, inst, addr):
        self.print_inst("SXTB", inst, addr)
        d = (inst >> 12) & 0xf
        m = inst & 0xf
        rotation = ((inst >> 10) & 3) << 3

        rotated = self.ror(self.reg(m), rotation)
        self.regs[d] = bitops.sign_extend(bitops.get_bits64(rotated, 7, 0), 8, 32)
        self.print_inst_reg(addr, inst, "sxtb", None, d, None, m)
    

    def sxth(self, inst, addr):
        self.print_inst("SXTH", inst, addr)
        d = (inst >> 12) & 0xf
        m = inst & 0xf
        rotation = ((inst >> 10) & 3) << 3

        rotated = self.ror(self.reg(m), rotation)
        self.regs[d] = bitops.sign_extend(bitops.get_bits64(rotated, 15, 0), 16, 32)
        self.print_inst_reg(addr, inst, "sxth", None, d, None, m)
    

    def sxtah(self, inst, addr):
        self.print_inst("SXTAH", inst, addr)
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        m = inst & 0xf
        rotation = ((inst >> 10) & 3) << 3

        rotated = self.ror(self.reg(m), rotation)
        n64 = Number64(0, self.reg(n))
        self.regs[d] = n64.add(bitops.sign_extend(bitops.get_bits64(rotated, 15, 0), 16, 32)).low
        self.print_inst_reg(addr, inst, "sxtah", None, d, None, m)
    

    def teq_reg(self, inst, addr):
        self.print_inst("TEQ (register)", inst, addr)
        n = (inst >> 16) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        valn = self.reg(n)
        valm = self.reg(m)
        self.decode_imm_shift(type, imm5)
        shifted = self.shift(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = bitops.xor(valn, shifted)
        self.set_apsr(ret, False)
        self.print_inst_reg(addr, inst, "teq", None, None, n, m, self.shift_t, self.shift_n)
    

    def tst_reg(self, inst, addr):
        self.print_inst("TST (register)", inst, addr)
        n = (inst >> 16) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf

        self.decode_imm_shift(type, imm5)
        valn = self.reg(n)
        valm = self.reg(m)
        shifted = self.shift_c(valm, self.shift_t, self.shift_n, self.cpsr.c)
        ret = bitops.and_(valn, shifted)
        self.set_apsr(ret, False)
        self.print_inst_reg(addr, inst, "tst", None, None, n, m, self.shift_t, self.shift_n)
    

    def ubfx(self, inst, addr):
        self.print_inst("UBFX", inst, addr)
        widthminus1 = bitops.get_bits(inst, 20, 16)
        d = bitops.get_bits(inst, 15, 12)
        lsbit = bitops.get_bits(inst, 11, 7)
        n = bitops.get_bits(inst, 3, 0)

        msbit = lsbit + widthminus1
        if (msbit <= 31):
            self.regs[d] = bitops.get_bits(self.reg(n), msbit, lsbit)
        else:
            self.abort_unpredictable("UBFX", inst, addr)
        self.print_inst_ubfx(addr, inst, "ubfx", d, n, lsbit, widthminus1 + 1)
    

    def umlal(self, inst, addr):
        self.print_inst("UMLAL", inst, addr)
        s = inst & 0x00100000
        dhi = bitops.get_bits(inst, 19, 16)
        dlo = bitops.get_bits(inst, 15, 12)
        m = bitops.get_bits(inst, 11, 8)
        n = bitops.get_bits(inst, 3, 0)
        
        n64_n = Number64(0, self.reg(n))
        n64_m = Number64(0, self.reg(m))
        n64_d = Number64(self.reg(dhi), self.reg(dlo))
        ret = n64_n.mul(n64_m).add(n64_d)
        self.regs[dhi] = ret.high
        self.regs[dlo] = ret.low
        if (s):
            self.cpsr.n = bitops.get_bit(ret.high, 31)
            self.cpsr.z = 1 if ret.is_zero() else 0
            self.log_apsr()
        
        self.print_inst_mul(addr, inst, "umlal", s, dhi, dlo, n, m)
    

    def umull(self, inst, addr):
        self.print_inst("UMULL", inst, addr)
        s = inst & 0x00100000
        dhi = bitops.get_bits(inst, 19, 16)
        dlo = bitops.get_bits(inst, 15, 12)
        m = bitops.get_bits(inst, 11, 8)
        n = bitops.get_bits(inst, 3, 0)

        #n64_n = Number64(0, self.reg(n))
        #n64_m = Number64(0, self.reg(m))
        #ret = n64_n.mul(n64_m)
        #self.regs[dhi] = ret.high
        #self.regs[dlo] = ret.low
        
        ret = self.reg(n) * self.reg(m)
        self.regs[dhi] = ret >> 32
        self.regs[dlo] = ret & 0xffffffff
        
        if (s):
            #self.cpsr.n = bitops.get_bit(ret.high, 31)
            #self.cpsr.z = 1 if ret.is_zero() else 0
            self.cpsr.n = ret >> 63
            self.cpsr.n = 1 if ret == 0 else 0
            self.log_apsr()
        
        self.print_inst_mul(addr, inst, "umull", s, dhi, dlo, n, m)
    

    def unsigned_satq(self, i, n):
        if (i > ((2 ** n) - 1)):
            ret = (2 ** n) - 1
            self.saturated = True
        elif (i < 0):
            ret = 0
            self.saturated = True
        else:
            ret = i
            self.saturated = False
        
        return bitops.get_bits64(ret, 31, 0)
    

    def usat(self, inst, addr):
        self.print_inst("USAT", inst, addr)
        saturate_to = bitops.get_bits(inst, 20, 16)
        d = bitops.get_bits(inst, 15, 12)
        imm5 = bitops.get_bits(inst, 11, 7)
        sh = bitops.get_bit(inst, 6)
        n = bitops.get_bits(inst, 3, 0)
        self.decode_imm_shift(sh << 1, imm5)

        operand = self.shift(self.reg(n), self.shift_t, self.shift_n, self.cpsr.c)
        ret = self.unsigned_satq(self.sint32(operand), saturate_to)
        self.regs[n] = ret
        if (self.saturated):
            self.cpsr.q = 1
        self.print_inst_unimpl(addr, inst, "usat")
    

    def uxtab(self, inst, addr):
        self.print_inst("UXTAB", inst, addr)
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        rotation = ((inst >> 10) & 3) << 3
        m = inst & 0xf

        rotated = self.ror(self.reg(m), rotation)
        self.regs[d] = (self.reg(n) + bitops.get_bits64(rotated, 7, 0)) & 0xffffffff
        self.print_inst_uxtab(addr, inst, "uxtab", d, n, m, rotation)
    

    def uxtah(self, inst, addr):
        self.print_inst("UXTAH", inst, addr)
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        m = inst & 0xf
        rotation = ((inst >> 10) & 3) << 3

        rotated = self.ror(self.reg(m), rotation)
        self.regs[d] = (self.reg(n) + bitops.get_bits64(rotated, 15, 0)) & 0xffffffff
        self.print_inst_uxtab(addr, inst, "uxtah", d, None, m, rotation)
    

    def uxtb(self, inst, addr):
        self.print_inst("UXTB", inst, addr)
        d = (inst >> 12) & 0xf
        m = inst & 0xf
        rotation = ((inst >> 10) & 3) << 3

        rotated = self.ror(self.reg(m), rotation)
        self.regs[d] = bitops.get_bits64(rotated, 7, 0)
        self.print_inst_uxtab(addr, inst, "uxtb", d, None, m, rotation)
    

    def uxth(self, inst, addr):
        self.print_inst("UXTH", inst, addr)
        d = (inst >> 12) & 0xf
        m = inst & 0xf
        rotation = ((inst >> 10) & 3) << 3

        rotated = self.ror(self.reg(m), rotation)
        self.regs[d] = bitops.get_bits64(rotated, 15, 0)
        self.print_inst_uxtab(addr, inst, "uxth", d, None, m, rotation)
    

    # 
    # Register-shifted Register
    # 
    def add_rsr(self, inst, addr):
        self.print_inst("ADD (register-shifted register)", inst, addr)
        sf = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        s = (inst >> 8) & 0xf
        type = (inst >> 5) & 3
        m = inst & 0xf

        shift_t = self.decode_reg_shift(type)
        shift_n = bitops.get_bits(self.reg(s), 7, 0)
        shifted = self.shift(self.reg(m), shift_t, shift_n, self.cpsr.c)
        ret = self.add_with_carry(self.reg(n), shifted, 0)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (sf):
                self.set_apsr(ret, True)
        
        self.print_inst_rsr(addr, inst, "add", sf, d, n, m, shift_t, s)
    

    def and_rsr(self, inst, addr):
        self.print_inst("AND (register-shifted register)", inst, addr)
        sf = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        s = (inst >> 8) & 0xf
        type = (inst >> 5) & 3
        m = inst & 0xf

        shift_t = self.decode_reg_shift(type)
        shift_n = bitops.get_bits(self.reg(s), 7, 0)
        shifted = self.shift_c(self.reg(m), shift_t, shift_n, self.cpsr.c)
        ret = bitops.and_(self.reg(n), shifted)
        self.regs[d] = ret
        if (sf):
            self.set_apsr(ret, False)
        self.print_inst_rsr(addr, inst, "and", sf, d, n, m, shift_t, s)
    

    def bic_rsr(self, inst, addr):
        self.print_inst("BIC (register-shifted register)", inst, addr)
        sf = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        s = (inst >> 8) & 0xf
        type = (inst >> 5) & 3
        m = inst & 0xf

        shift_t = self.decode_reg_shift(type)
        shift_n = bitops.get_bits(self.reg(s), 7, 0)
        shifted = self.shift_c(self.reg(m), shift_t, shift_n, self.cpsr.c)
        ret = bitops.and_(self.reg(n), bitops.not_(shifted))
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (sf):
                self.set_apsr(ret, False)
        
        self.print_inst_rsr(addr, inst, "bic", sf, d, n, m, shift_t, s)
    

    def cmp_rsr(self, inst, addr):
        self.print_inst("CMP (register-shifted register)", inst, addr)
        n = (inst >> 16) & 0xf
        s = (inst >> 8) & 0xf
        type = (inst >> 5) & 3
        m = inst & 0xf

        shift_t = self.decode_reg_shift(type)
        shift_n = bitops.get_bits(self.reg(s), 7, 0)
        shifted = self.shift(self.reg(m), shift_t, shift_n, self.cpsr.c)
        ret = self.add_with_carry(self.reg(n), bitops.not_(shifted), 1)
        self.set_apsr(ret, True)
        self.print_inst_rsr(addr, inst, "cmp", None, None, n, m, shift_t, s)
    

    def eor_rsr(self, inst, addr):
        self.print_inst("EOR (register-shifted register)", inst, addr)
        sf = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        s = (inst >> 8) & 0xf
        type = (inst >> 5) & 3
        m = inst & 0xf

        shift_t = self.decode_reg_shift(type)
        shift_n = bitops.get_bits(self.reg(s), 7, 0)
        shifted = self.shift_c(self.reg(m), shift_t, shift_n, self.cpsr.c)
        ret = bitops.xor(self.reg(n), shifted)
        self.regs[d] = ret
        if (sf):
            self.set_apsr(ret, False)
        self.print_inst_rsr(addr, inst, "eor", sf, d, n, m, shift_t, s)
    

    def mvn_rsr(self, inst, addr):
        self.print_inst("MVN (register-shifted register)", inst, addr)
        sf = inst & 0x00100000
        d = (inst >> 12) & 0xf
        s = (inst >> 8) & 0xf
        type = (inst >> 5) & 3
        m = inst & 0xf

        shift_t = self.decode_reg_shift(type)
        shift_n = bitops.get_bits(self.reg(s), 7, 0)
        shifted = self.shift_c(self.reg(m), shift_t, shift_n, self.cpsr.c)
        ret = bitops.not_(shifted)
        self.regs[d] = ret
        if (sf):
            self.set_apsr(ret, False)
        self.print_inst_rsr(addr, inst, "mvn", sf, d, None, m, shift_t, s)
    

    def orr_rsr(self, inst, addr):
        self.print_inst("ORR (register-shifted register)", inst, addr)
        sf = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        s = (inst >> 8) & 0xf
        type = (inst >> 5) & 3
        m = inst & 0xf

        shift_t = self.decode_reg_shift(type)
        shift_n = bitops.get_bits(self.reg(s), 7, 0)
        shifted = self.shift_c(self.reg(m), shift_t, shift_n, self.cpsr.c)
        ret = bitops.or_(self.reg(n), shifted)
        self.regs[d] = ret
        if (sf):
            self.set_apsr(ret, False)
        self.print_inst_rsr(addr, inst, "orr", sf, d, n, m, shift_t, s)
    

    def rsb_rsr(self, inst, addr):
        self.print_inst("RSB (register-shifted register)", inst, addr)
        sf = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        s = (inst >> 8) & 0xf
        type = (inst >> 5) & 3
        m = inst & 0xf

        shift_t = self.decode_reg_shift(type)
        shift_n = bitops.get_bits(self.reg(s), 7, 0)
        shifted = self.shift(self.reg(m), shift_t, shift_n, self.cpsr.c)
        ret = self.add_with_carry(bitops.not_(self.reg(n)), shifted, 1)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (sf):
                self.set_apsr(ret, True)
        
        self.print_inst_rsr(addr, inst, "rsb", sf, d, n, m, shift_t, s)
    

    def sbc_rsr(self, inst, addr):
        self.print_inst("SBC (register-shifted register)", inst, addr)
        sf = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        s = (inst >> 8) & 0xf
        type = (inst >> 5) & 3
        m = inst & 0xf

        shift_t = self.decode_reg_shift(type)
        shift_n = bitops.get_bits(self.reg(s), 7, 0)
        shifted = self.shift(self.reg(m), shift_t, shift_n, self.cpsr.c)
        ret = self.add_with_carry(self.reg(n), bitops.not_(shifted), self.cpsr.c)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (sf):
                self.set_apsr(ret, True)
        
        self.print_inst_rsr(addr, inst, "sbc", sf, d, n, m, shift_t, s)
    

    def sub_rsr(self, inst, addr):
        self.print_inst("SUB (register-shifted register)", inst, addr)
        sf = inst & 0x00100000
        n = (inst >> 16) & 0xf
        d = (inst >> 12) & 0xf
        s = (inst >> 8) & 0xf
        type = (inst >> 5) & 3
        m = inst & 0xf

        shift_t = self.decode_reg_shift(type)
        shift_n = bitops.get_bits(self.reg(s), 7, 0)
        shifted = self.shift(self.reg(m), shift_t, shift_n, self.cpsr.c)
        ret = self.add_with_carry(self.reg(n), bitops.not_(shifted), 1)
        if (d == 15):
            self.branch_to = ret
        else:
            self.regs[d] = ret
            if (sf):
                self.set_apsr(ret, True)
        
        self.print_inst_rsr(addr, inst, "sub", sf, d, n, m, shift_t, s)
    

    def tst_rsr(self, inst, addr):
        self.print_inst("TST (register-shifted register)", inst, addr)
        s = inst & 0x00100000
        n = (inst >> 16) & 0xf
        type = (inst >> 5) & 3
        m = inst & 0xf

        shift_t = self.decode_reg_shift(type)
        shift_n = bitops.get_bits(self.reg(s), 7, 0)
        shifted = self.shift_c(self.reg(m), shift_t, shift_n, self.cpsr.c)
        ret = bitops.and_(self.reg(n), shifted)
        self.set_apsr(ret, False)
        self.print_inst_rsr(addr, inst, "tst", None, None, n, m, shift_t, s)
    

    # 
    # Load Store
    # 
    def ldrh_imm(self, inst, addr):
        self.print_inst("LDRH (immediate)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm4h = (inst >> 8) & 0xf
        imm4l = inst & 0xf
        imm32 = (imm4h << 4) + imm4l
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn = self.reg(n)
        offset_addr = (valn + (imm32 if is_add else -imm32)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        # data = MemU[address,2]
        data = self.ld_halfword(address)
        if (is_wback):
            self.regs[n] = offset_addr
        self.regs[t] = data
        self.log_regs(None)
        self.print_inst_imm(addr, inst, "ldrh", None, t, n, imm32, True, is_wback, is_add)
    

    def ldrh_reg(self, inst, addr):
        self.print_inst("LDRH (register)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        m = inst & 0xf
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn = self.reg(n)
        offset = self.shift(self.reg(m), self.SRType_LSL, 0, self.cpsr.c)
        offset_addr = (valn + (offset if is_add else -offset)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        # data = MemU[address,2]
        data = self.ld_halfword(address)
        if (is_wback):
            self.regs[n] = offset_addr
        self.regs[t] = data
        self.print_inst_reg(addr, inst, "ldrh", None, t, n, m, self.SRType_LSL, 0, True, is_wback, is_add)
    

    def ldrsb_imm(self, inst, addr):
        self.print_inst("LDRSB (immediate)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm4h = (inst >> 8) & 0xf
        imm4l = inst & 0xf
        imm32 = (imm4h << 4) + imm4l
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn = self.reg(n)
        offset_addr = (valn + (imm32 if is_add else -imm32)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        self.regs[t] = bitops.sign_extend(self.ld_byte(address), 8, 32)
        if (is_wback):
            self.regs[n] = offset_addr
        #self.print_inst_reg(addr, inst, "ldrsb", None, t, n, m, None, None, True, is_wback, is_add)
        self.print_inst_unimpl(addr, inst, "ldrsb")
    

    def ldrsb_reg(self, inst, addr):
        self.print_inst("LDRSB (register)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        m = inst & 0xf
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        offset = self.shift(self.reg(m), self.SRType_LSL, 0, self.cpsr.c)
        valn = self.reg(n)
        offset_addr = (valn + (offset if is_add else -offset)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        self.regs[t] = bitops.sign_extend(self.ld_byte(address), 8, 32)
        if (is_wback):
            self.regs[n] = offset_addr
        #self.print_inst_reg(addr, inst, "ldrsb", None, t, n, m, None, None, True, is_wback, is_add)
        self.print_inst_unimpl(addr, inst, "ldrsb")
    

    def str_reg(self, inst, addr):
        self.print_inst("STR (register)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        self.decode_imm_shift(type, imm5)
        valn = self.reg(n)
        offset = self.shift(self.reg(m), self.shift_t, self.shift_n, self.cpsr.c)
        offset_addr = (valn + (offset if is_add else -offset)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        address = bitops.get_bits64(address, 31, 0) # XXX
        data = self.reg(t)
        self.st_word(address, data)
        if (is_wback):
            self.regs[n] = offset_addr
        self.print_inst_reg(addr, inst, "str", None, t, n, m, self.shift_t, self.shift_n, True, is_wback)
    

    def strbt_a1(self, inst, addr):
        self.print_inst("STRBT A1", inst, addr)
        u = inst & (1 << 23)
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm32 = inst & 0xfff
        is_add = u == 1

        valn = self.reg(n)
        offset = imm32
        offset_addr = (valn + (offset if is_add else -offset)) & 0xffffffff
        self.st_byte(valn, bitops.get_bits(self.reg(t), 7, 0))
        self.regs[n] = offset_addr
        self.print_inst_reg(addr, inst, "strbt", None, t, n, m, self.shift_t, self.shift_n, True, True)
    

    def strbt_a2(self, inst, addr):
        self.print_inst("STRBT A2", inst, addr)
        u = (inst >> 23) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf
        is_add = u == 1
        self.decode_imm_shift(type, imm5)

        valn = self.reg(n)
        offset = self.shift(self.reg(m), self.shift_t, self.shift_n, self.cpsr.c)
        offset_addr = (valn + (offset if is_add else -offset)) & 0xffffffff
        self.st_byte(valn, bitops.get_bits(self.reg(t), 7, 0))
        self.regs[n] = offset_addr
        self.print_inst_reg(addr, inst, "strbt", None, t, n, m, self.shift_t, self.shift_n, True, True)
    

    def strb_reg(self, inst, addr):
        self.print_inst("STRB (register)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm5 = (inst >> 7) & 0x1f
        type = (inst >> 5) & 3
        m = inst & 0xf
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        self.decode_imm_shift(type, imm5)
        valn = self.reg(n)
        offset = self.shift(self.reg(m), self.shift_t, self.shift_n, self.cpsr.c)
        offset_addr = (valn + (offset if is_add else -offset)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        self.st_byte(address, bitops.get_bits(self.reg(t), 7, 0))
        if (is_wback):
            self.regs[n] = offset_addr
        self.print_inst_reg(addr, inst, "strb", None, t, n, m, self.shift_t, self.shift_n, True, is_wback)
    

    def strd_reg(self, inst, addr):
        self.print_inst("STRD (register)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        m = inst & 0xf
        t2 = t + 1
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn = self.reg(n)
        valm = self.reg(m)
        offset_addr = (valn + (valm if is_add else -valm)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        self.st_word(address, self.reg(t))
        self.st_word((address + 4) & 0xffffffff, self.reg(t2))
        if (is_wback):
            self.regs[n] = offset_addr
        self.print_inst_reg(addr, inst, "strd", None, t, n, m, None, None, True, is_wback, is_index)
    

    def strd_imm(self, inst, addr):
        self.print_inst("STRD (immediate)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm4h = (inst >> 8) & 0xf
        imm4l = inst & 0xf
        t2 = t + 1
        imm32 = (imm4h << 4) + imm4l
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn = self.reg(n)
        offset_addr = (valn + (imm32 if is_add else -imm32)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        self.st_word(address, self.reg(t))
        self.st_word((address + 4) & 0xffffffff, self.reg(t2))
        if (is_wback):
            self.regs[n] = offset_addr
        self.print_inst_imm(addr, inst, "strd", None, t, n, imm32, True, is_wback, is_add)
    

    def strh_imm(self, inst, addr):
        self.print_inst("STRH (immediate)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        imm4h = (inst >> 8) & 0xf
        imm4l = inst & 0xf
        imm32 = (imm4h << 4) + imm4l
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn = self.reg(n)
        offset_addr = (valn + (imm32 if is_add else -imm32)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        self.st_halfword(address, bitops.get_bits(self.reg(t), 15, 0))
        if (is_wback):
            self.regs[n] = offset_addr
        self.print_inst_imm(addr, inst, "strh", None, t, n, imm32, True, is_wback, is_add)
    

    def strh_reg(self, inst, addr):
        self.print_inst("STRH (register)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        t = (inst >> 12) & 0xf
        m = inst & 0xf
        is_index = p == 1
        is_add = u == 1
        is_wback = p == 0 or w == 1

        valn = self.reg(n)
        offset = self.shift(self.reg(m), self.SRType_LSL, 0, self.cpsr.c)
        offset_addr = (valn + (offset if is_add else -offset)) & 0xffffffff
        address = (offset_addr if is_index else valn)
        self.st_halfword(address, bitops.get_bits(self.reg(t), 15, 0))
        if (is_wback):
            self.regs[n] = offset_addr
        self.print_inst_reg(addr, inst, "strh", None, t, n, m, self.SRType_LSL, 0, True, is_wback, is_add)
    

    def ldm(self, inst, addr):
        self.print_inst("LDM / LDMIA / LDMFD", inst, addr)
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        register_list = inst & 0xffff
        n_registers = bitops.bit_count(register_list, 16)
        is_pop = False
        if (w and n == 13 and n_registers >= 2):
            is_pop = True
        
        is_wback = w == 1

        valn = self.reg(n)
        address = valn
        reglist = []
        for i in xrange(0, 15):
            if ((register_list >> i) & 1):
                reglist.append(i)
                self.regs[i] = self.ld_word(address)
                address += 4
            
        
        #if ((register_list >> 15) & 1):
        if (register_list & 0x8000):
            reglist.append(15)
            self.branch_to = self.ld_word(address)
        
        if (is_wback):
            self.regs[n] = (self.reg(n) + 4 * n_registers) & 0xffffffff
        self.log_regs(None)
        if (is_pop):
            self.print_inst_ldstm(addr, inst, "pop", is_wback, None, reglist)
        else:
            self.print_inst_ldstm(addr, inst, "ldm", is_wback, n, reglist)
    

    def ldm_er(self, inst, addr):
        self.print_inst("LDM (exception return)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        register_list = inst & 0x7fff
        n_registers = bitops.bit_count(register_list, 15)
        is_wback = w == 1
        is_increment = u == 1
        is_wordhigher = p == u

        valn = self.reg(n)
        if (self.is_user_or_system()):
            self.abort_unpredictable("LDM (exception return)", inst, addr)
        length = 4*n_registers + 4
        address = (valn + (0 if is_increment else -length)) & 0xffffffff
        if (is_wordhigher):
            address += 4
        reglist = []
        for i in xrange(0, 15):
            if ((register_list >> i) & 1):
                reglist.append(i)
                self.regs[i] = self.ld_word(address)
                address += 4
            
        
        new_pc = self.ld_word(address)

        if (is_wback):
            self.regs[n] = (valn + (length if is_increment else -length)) & 0xffffffff
        self.log_regs(None)
        self.cpsr_write_by_instr(self.get_current_spsr(), 15, True)
        self.branch_to = new_pc
        #self.print_inst_ldstm(addr, inst, "ldm", is_wback, n, reglist)
        self.print_inst_unimpl(addr, inst, "ldm")
    

    def ldm_ur(self, inst, addr):
        self.print_inst("LDM (user registers)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        n = (inst >> 16) & 0xf
        register_list = inst & 0x7fff
        n_registers = bitops.bit_count(register_list, 15)
        is_increment = u == 1
        is_wordhigher = p == u

        valn = self.reg(n)
        if (self.is_user_or_system()):
            self.abort_unpredictable("LDM (user registers)", inst, addr)
        length = 4*n_registers
        address = (valn + (0 if is_increment else -length)) & 0xffffffff
        if (is_wordhigher):
            address += 4
        reglist = []
        self.log_regs(None)
        for i in xrange(0, 15):
            if ((register_list >> i) & 1):
                reglist.append(i)
                # FIXME
                self.regs_usr[i] = self.ld_word(address)
                if (self.cpsr.m == self.FIQ_MODE):
                    if (not (i >= 8 and i <= 14)):
                        self.regs[i] = self.regs_usr[i]
                else:
                    if (not (i >= 13 and i <= 14)):
                        self.regs[i] = self.regs_usr[i]
                
                address += 4
            
        
        logger.log(str(reglist))
        self.print_inst_unimpl(addr, inst, "ldm")
    

    def ldmda(self, inst, addr):
        self.print_inst("LDMDA / LDMFA", inst, addr)
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        register_list = inst & 0xffff
        n_registers = bitops.bit_count(register_list, 16)

        address = (self.reg(n) - 4 * n_registers + 4) & 0xffffffff
        reglist = []
        for i in xrange(0, 15):
            if ((register_list >> i) & 1):
                reglist.append(i)
                self.regs[i] = self.ld_word(address)
                address += 4
            
        
        if (register_list & 0x8000):
            reglist.append(15)
            self.branch_to = self.ld_word(address)
        
        if (w):
            self.regs[n] = (self.reg(n) - 4 * n_registers) & 0xffffffff
        self.log_regs(None)
        self.print_inst_ldstm(addr, inst, "ldmda", w, n, reglist)
    

    def ldmdb(self, inst, addr):
        self.print_inst("LDMDB / LDMEA", inst, addr)
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        register_list = inst & 0xffff
        n_registers = bitops.bit_count(register_list, 16)

        address = (self.reg(n) - 4 * n_registers) & 0xffffffff
        reglist = []
        for i in xrange(0, 15):
            if ((register_list >> i) & 1):
                reglist.append(i)
                self.regs[i] = self.ld_word(address)
                address += 4
            
        
        if (register_list & 0x8000):
            reglist.append(15)
            self.branch_to = self.ld_word(address)
        
        if (w):
            self.regs[n] = (self.reg(n) - 4 * n_registers) & 0xffffffff
        self.log_regs(None)
        self.print_inst_ldstm(addr, inst, "ldmdb", w, n, reglist)
    

    def ldmib(self, inst, addr):
        self.print_inst("LDMIB / LDMED", inst, addr)
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        register_list = inst & 0xffff
        n_registers = bitops.bit_count(register_list, 16)

        address = (self.reg(n) + 4) & 0xffffffff
        reglist = []
        for i in xrange(0, 15):
            if ((register_list >> i) & 1):
                reglist.append(i)
                self.regs[i] = self.ld_word(address)
                address += 4
            
        
        if (register_list & 0x8000):
            reglist.append(15)
            self.branch_to = self.ld_word(address)
        
        if (w):
            self.regs[n] = (self.reg(n) + 4 * n_registers) & 0xffffffff
        self.log_regs(None)
        self.print_inst_ldstm(addr, inst, "ldmib", w, n, reglist)
    

    def stm(self, inst, addr):
        self.print_inst("STM / STMIA / STMEA", inst, addr)
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        register_list = inst & 0xffff
        n_registers = bitops.bit_count(register_list, 16)

        self.log_regs(None)
        address = self.reg(n)
        reglist = []
        for i in xrange(0, 15):
            if ((register_list >> i) & 1):
                reglist.append(i)
                self.st_word(address, self.regs[i])
                address += 4
            
        
        if (register_list & 0x8000):
            reglist.append(15)
            self.st_word(address, self.get_pc())
        
        if (w):
            self.regs[n] = (self.reg(n) + 4 * n_registers) & 0xffffffff
        self.print_inst_ldstm(addr, inst, "stm", w, n, reglist)
    

    def stmdb(self, inst, addr):
        self.print_inst("STMDB / STMFD", inst, addr)
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        register_list = inst & 0xffff
        n_registers = bitops.bit_count(register_list, 16)
        is_push = False
        valn = self.reg(n)
        if (w and n == 13 and n_registers >= 2):
            is_push = True
        

        self.log_regs(None)
        address = (valn - 4 * n_registers) & 0xffffffff
        reglist = []
        for i in xrange(0, 15):
            if ((register_list >> i) & 1):
                reglist.append(i)
                self.st_word(address, self.regs[i])
                address += 4
            
        
        if (register_list & 0x8000):
            reglist.append(15)
            self.st_word(address, self.get_pc())
        
        if (w or is_push):
            self.regs[n] = (self.reg(n) - 4 * n_registers) & 0xffffffff
        if (is_push):
            self.print_inst_ldstm(addr, inst, "push", w, None, reglist)
        else:
            self.print_inst_ldstm(addr, inst, "stmdb", w, n, reglist)
    

    def stmib(self, inst, addr):
        self.print_inst("STMIB / STMFA", inst, addr)
        w = (inst >> 21) & 1
        n = (inst >> 16) & 0xf
        register_list = inst & 0xffff
        n_registers = bitops.bit_count(register_list, 16)
        valn = self.reg(n)
        self.log_regs(None)
        address = (valn + 4) & 0xffffffff
        reglist = []
        for i in xrange(0, 15):
            if ((register_list >> i) & 1):
                reglist.append(i)
                self.st_word(address, self.regs[i])
                address += 4
            
        
        if (register_list & 0x8000):
            reglist.append(15)
            self.st_word(address, self.get_pc())
        
        if (w):
            self.regs[n] = (self.reg(n) + 4 * n_registers) & 0xffffffff
        self.print_inst_ldstm(addr, inst, "stmib", w, n, reglist)
    

    def stm_ur(self, inst, addr):
        self.print_inst("STM (user registers)", inst, addr)
        p = (inst >> 24) & 1
        u = (inst >> 23) & 1
        n = (inst >> 16) & 0xf
        register_list = inst & 0xffff
        n_registers = bitops.bit_count(register_list, 16)
        is_increment = u == 1
        is_wordhigher = p == u
        if (n == 15 or n_registers < 1):
            self.abort_unpredictable("STM (user registers)", inst, addr)
        if (self.is_user_or_system()):
            self.abort_unpredictable("STM (user registers)")

        length = 4*n_registers
        self.log_regs(None)
        address = (self.reg(n) + (0 if is_increment else -length)) & 0xffffffff
        if (is_wordhigher):
            address += 4
        reglist = []
        for i in xrange(0, 15):
            if ((register_list >> i) & 1):
                reglist.append(i)
                # XXX
                if (self.cpsr.m == self.FIQ_MODE):
                    if (i >= 8 and i <= 14):
                        self.st_word(address, self.regs_usr[i])
                    else:
                        self.st_word(address, self.regs[i])
                else:
                    if (i >= 13 and i <= 14):
                        self.st_word(address, self.regs_usr[i])
                    else:
                        self.st_word(address, self.regs[i])
                
                address += 4
            
        
        if (register_list & 0x8000):
            reglist.append(15)
            #self.st_word(address, self.regs_usr[15] + 8)
            self.st_word(address, self.get_pc())
        
        self.print_inst_ldstm(addr, inst, "stm_usr", None, n, reglist) # FIXME
    

    def cps(self, inst, addr):
        self.print_inst("CPS", inst, addr)
        imod = (inst >> 18) & 3
        m = inst & (1 << 17)
        a = inst & (1 << 8)
        i = inst & (1 << 7)
        f = inst & (1 << 6)
        mode = inst & 0xf
        enable = imod == 2
        disable = imod == 3

        if (self.is_priviledged()):
            new_cpsr = self.clone_psr(self.cpsr)
            if (enable):
                if (a): new_cpsr.a = 0
                if (i): new_cpsr.i = 0
                if (f): new_cpsr.f = 0
            
            if (disable):
                if (a): new_cpsr.a = 1
                if (i): new_cpsr.i = 1
                if (f): new_cpsr.f = 1
            
            if (m):
                new_cpsr.m = mode
            self.cpsr_write_by_instr(new_cpsr, 15, True)
        
        self.print_inst_unimpl(addr, inst, "cps")
    

    def svc(self, inst, addr):
        self.print_inst("SVC (previously SWI)", inst, addr)
        imm32 = inst & 0x00ffffff
        self.print_inst_svc(inst, imm32)
        self.call_supervisor()
    

    def clrex(self, inst, addr):
        self.print_inst("CLREX", inst, addr)
        # Clear Exclusive clears the local record of the executing processor that an address has had a request for an exclusive access.
        # FIXME: Need to do nothing?
        self.print_inst_unimpl(addr, inst, "clrex")
    

    def dsb(self, inst, addr):
        self.print_inst("DSB", inst, addr)
        #option = bitops.get_bits(inst, 3, 0)
        # Data Synchronization Barrier
        # FIXME: Need to do nothing?
        self.print_inst_unimpl(addr, inst, "dsb")
    

    def dmb(self, inst, addr):
        self.print_inst("DMB", inst, addr)
        #option = bitops.get_bits(inst, 3, 0)
        # Data Memory Barrier
        # FIXME: Need to do nothing?
        self.print_inst_unimpl(addr, inst, "dmb")
    

    def isb(self, inst, addr):
        self.print_inst("ISB", inst, addr)
        #option = bitops.get_bits(inst, 3, 0)
        # Instruction Synchronization Barrier
        # FIXME: Need to do nothing?
        self.print_inst_unimpl(addr, inst, "isb")
    

    def wfi(self, inst, addr):
        self.print_inst("WFI", inst, addr)
        self.is_halted = True
        self.cpsr.i = 0
        self.print_inst_unimpl(addr, inst, "wfi")
    

    def vmrs(self, inst_name, inst, addr):
        self.print_inst("VMRS", inst, addr)
        # XXX: VFP support v0.3: no double precision support                                   
        self.regs[6] = 1<<20
        self.print_inst_unimpl(addr, inst, "vmrs")
    

    def nop(self, inst_name, inst, addr):
        self.print_inst("NOP", inst, addr)
        self.print_inst_unimpl(addr, inst, "nop")
    

    def exec_(self, inst_name, inst, addr):
        self.current = inst_name
        return getattr(self, inst_name)(inst, addr)
    

    # 
    #
    # Decoder
    #
    # 
    def decode_uncond(self, inst, addr):
        # Unconditional instructions
        op = 0
        op1 = 0
        op2 = 0
        tmp = 0

        op1 = (inst >> 20) & 0xff
        if ((op1 >> 7) == 0):
            # [31:27]=11110
            # Miscellaneous instructions, memory hints, and Advanced SIMD instructions
            op1 = (inst >> 20) & 0x7f
            op = (inst >> 16) & 1
            op2 = (inst >> 4) & 0xf

            tmp = (op1 >> 5) & 3
            if tmp == 0:
                if (op1 == 0x10 and (op2 & 2) == 0):
                    if (op):
                        # SETEND
                        self.abort_not_impl("SETEND", inst, addr)
                    else:
                        # CPS
                        return "cps"
                    
                else:
                    self.abort_unknown_inst(inst, addr)
            elif tmp == 1:
                # Advanced SIMD data-processing instructions
                self.abort_simdvfp_inst(inst, addr)
            elif tmp == 2:
                if ((op1 & 1) == 0):
                    # Advanced SIMD element or structure load/store instructions
                    self.abort_simdvfp_inst(inst, addr)
                
                if (op1 >> 1 & 3) == 2:
                    if (op1 & 0x10):
                        # PLD (immediate, literal)
                        return "pld_imm"
                    else:
                        # PLI (immediate, literal)
                        self.abort_not_impl("PLI (immediate, literal)", inst, addr)
                elif (op1 >> 1 & 3) == 3:
                    if ((op1 & 0x18) == 0x10):
                        if op2 == 1:
                            # CLREX
                            return "clrex"
                            # Clear Exclusive clears the local record of the executing processor that an address has had a request for an exclusive access.
                            # FIXME: Need to do nothing?
                        elif op2 == 4:
                            # DSB
                            return "dsb"
                            #option = bitops.get_bits(inst, 3, 0)
                            # Data Synchronization Barrier
                            # FIXME: Need to do nothing?
                        elif op2 == 5:
                            # DMB
                            return "dmb"
                            #option = bitops.get_bits(inst, 3, 0)
                            # Data Memory Barrier
                            # FIXME: Need to do nothing?
                        elif op2 == 6:
                            # ISB
                            return "isb"
                            #option = bitops.get_bits(inst, 3, 0)
                            # Instruction Synchronization Barrier
                            # FIXME: Need to do nothing?
                        else:
                            # UNPREDICTABLE
                            self.abort_unpredictable_instruction("Miscellaneous instructions, memory hints, and Advanced SIMD instructions", inst, addr)
                        
                    else:
                        # UNPREDICTABLE
                        self.abort_unpredictable_instruction("Miscellaneous instructions, memory hints, and Advanced SIMD instructions", inst, addr)
                else:
                    self.abort_unknown_inst(inst, addr)
                
            elif tmp == 3:
                if ((op2 & 1) == 0):
                    if (op1 & 7) == 5:
                        if (op1 & 0x10):
                            # PLD (register)
                            self.abort_not_impl("PLD (register)", inst, addr)
                        else:
                            # PLI (register)
                            self.abort_not_impl("PLI (register)", inst, addr)
                        
                    elif (op1 & 7) == 7:
                        # UNPREDICTABLE
                        self.abort_unpredictable_instruction("Miscellaneous instructions, memory hints, and Advanced SIMD instructions", inst, addr)
                    else:
                        self.abort_unknown_inst(inst, addr)
                    
                
            else:
                self.abort_decode_error(inst, addr)
            
        else:
            if op1 == 0xc4:
                # MCRR, MCRR2
                self.abort_not_impl("MCRR, MCRR2", inst, addr)
            elif op1 == 0xc5:
                # MRRC, MRRC2
                self.abort_not_impl("MRRC, MRRC2", inst, addr)
            else:
                tmp = (op1 >> 5) & 7
                if tmp == 4:
                    if (op1 & 4):
                        if (not (op1 & 1)):
                            # SRS
                            self.abort_not_impl("SRS", inst, addr)
                        else:
                            self.abort_unknown_inst(inst, addr)
                    else:
                        if (op1 & 1):
                            # RFE
                            self.abort_not_impl("RFE", inst, addr)
                        else:
                            self.abort_unknown_inst(inst, addr)
                elif tmp == 5:
                    # BL, BLX (immediate)
                    self.abort_not_impl("BL, BLX (immediate)", inst, addr)
                elif tmp == 6:
                    if (op1 & 1):
                        # LDC, LDC2 (immediate) & LDC, LDC2 (literal)
                        raise Exception("UND")
                    else:
                        # STC, STC2
                        raise Exception("UND")
                    
                elif tmp == 7:
                    if (not (op1 & 1<<4)):
                        if (op & 1):
                            if (op1 & 1):
                                # MRC, MRC2
                                # TODO
                                self.abort_not_impl("MRC, MRC2", inst, addr)
                            else:
                                # MCR, MCR2
                                # TODO
                                self.abort_not_impl("MCR, MCR2", inst, addr)
                            
                        else:
                            # CDP, CDP2
                            raise Exception("UND")
                        
                    else:
                        self.abort_unknown_inst(inst, addr)
                else:
                    self.abort_unknown_inst(inst, addr)
                    
            
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def decode_sync_prim(self, inst, addr):
        # Synchronization primitives
        # [27:24]=0001 [7:4]=1001
        op = (inst >> 20) & 0xf

        if ((op & 8) == 0):
            if ((op & 3) == 0):
                # SWP, SWPB
                return "swp"
            else:
                self.abort_unknown_inst(inst, addr)
            
        else:
            if (op & 7) == 0:
                # STREX
                return "strex"
            elif (op & 7) == 1:
                # LDREX
                return "ldrex"
            elif (op & 7) == 2:
                # STREXD
                return "strexd"
            elif (op & 7) == 3:
                # LDREXD
                return "ldrexd"
            elif (op & 7) == 4:
                # STREXB
                self.abort_not_impl("STREXB", inst, addr)
            elif (op & 7) == 5:
                # LDREXB
                self.abort_not_impl("LDREXB", inst, addr)
            elif (op & 7) == 6:
                # STREXH
                self.abort_not_impl("STREXH", inst, addr)
            elif (op & 7) == 7:
                # LDREXH
                self.abort_not_impl("LDREXH", inst, addr)
            
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def decode_dataproc_imm(self, inst, addr):
        # [27:25]=001
        # Data-processing (immediate)
        op = (inst >> 20) & 0x1f
        if (op >> 1) == 0:
            # AND (immediate)
            return "and_imm"
        elif (op >> 1) == 1:
            # EOR (immediate)
            return "eor_imm"
        elif (op >> 1) == 2:
            rn = (inst >> 16) & 0xf
            if (rn == 0xf):
                # [24:21]=0010
                # ADR A2
                return "adr_a2"
            else:
                # SUB (immediate)
                return "sub_imm"
            
        elif (op >> 1) == 3:
            # RSB (immediate)
            return "rsb_imm"
        elif (op >> 1) == 4:
            rn = (inst >> 16) & 0xf
            if (rn == 0xf):
                # [24:21]=0100
                # ADR A1
                return "adr_a1"
            else:
                # ADD (immediate)
                return "add_imm"
            
        elif (op >> 1) == 5:
            # ADC (immediate)
            return "adc_imm"
        elif (op >> 1) == 6:
            # SBC (immediate)
            return "sbc_imm"
        elif (op >> 1) == 7:
            # RSC (immediate)
            return "rsc_imm"
        elif (op >> 1) == 8:
            if ((op & 1) == 0):
                self.abort_unknown_inst(inst, addr)
            
            # TST (immediate)
            return "tst_imm"
        elif (op >> 1) == 9:
            if ((op & 1) == 0):
                self.abort_unknown_inst(inst, addr)
            
            # TEQ (immediate)
            return "teq_imm"
        elif (op >> 1) == 0xa:
            if ((op & 1) == 0):
                self.abort_unknown_inst(inst, addr)
            
            # CMP (immediate)
            return "cmp_imm"
        elif (op >> 1) == 0xb:
            if ((op & 1) == 0):
                self.abort_unknown_inst(inst, addr)
            
            # CMN (immediate)
            return "cmn_imm"
        elif (op >> 1) == 0xc:
            # ORR (immediate)
            return "orr_imm"
        elif (op >> 1) == 0xd:
            # MOV (immediate) A1
            return "mov_imm_a1"
        elif (op >> 1) == 0xe:
            # BIC (immediate)
            return "bic_imm"
        elif (op >> 1) == 0xf:
            # MVN (immediate)
            return "mvn_imm"
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def decode_msr_imm_and_hints(self, inst, addr):
        # [27:23]=00110 [21:20]=10
        # MSR (immediate), and hints
        op = inst & (1 << 22)
        op1 = (inst >> 16) & 0xf
        op2 = inst & 0xff
        if (op):
            # MSR (immediate) (system level)
            return "msr_imm_sys"
        else:
            if ((op1 & 2)):
                # MSR (immediate) (system level)
                return "msr_imm_sys"
            else:
                if ((op1 & 1)):
                    # MSR (immediate) (system level)
                    return "msr_imm_sys"
                else:
                    if (op1 & 8):
                        # MSR (immediate) (application level)
                        self.abort_not_impl("MSR (immediate) (application level)", inst, addr)
                    else:
                        if (op1 & 4):
                            # MSR (immediate) (application level)
                            self.abort_not_impl("MSR (immediate) (application level)", inst, addr)
                        else:
                            if ((op2 & 0xf0) == 0xf0):
                                # DBG
                                self.abort_not_impl("DBG", inst, addr)
                            else:
                                if op2 == 0:
                                    # NOP
                                    return "nop"
                                elif op2 == 1:
                                    # YIELD
                                    self.abort_not_impl("YIELD", inst, addr)
                                elif op2 == 2:
                                    # WFE
                                    self.abort_not_impl("WFE", inst, addr)
                                elif op2 == 3:
                                    # WFI
                                    return "wfi"
                                elif op2 == 4:
                                    # SEV
                                    self.abort_not_impl("SEV", inst, addr)
                                else:
                                    self.abort_unknown_inst(inst, addr)
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def decode_half_mul(self, inst, addr):
        raise Exception("decode_half_mul")
    

    def decode_misc(self, inst, addr):
        # [27:23]=00010 [20]=0 [7]=0
        # Miscellaneous instructions
        op = (inst >> 21) & 0x3
        op1 = (inst >> 16) & 0xf
        op2 = (inst >> 4) & 0x7
        if op2 == 0:
            if (op & 1):
                if (not ((op & 2) == 2) and (op1 & 3) == 0):
                    # MSR (register) (application level)
                    self.abort_not_impl("MSR (register) (application level)", inst, addr)
                else:
                    # MSR (register) (system level)
                    return "msr_reg_sys"
                
            else:
                # MRS
                return "mrs"
            
        elif op2 == 1:
            if op == 1:
                # BX
                return "bx"
            elif op == 3:
                # CLZ
                return "clz"
            else:
                self.abort_unknown_inst(inst, addr)
            
        elif op2 == 2:
            if (op != 1):
                self.abort_unknown_inst(inst, addr)
            
            # BXJ
            self.abort_not_impl("BXJ", inst, addr)
        elif op2 == 3:
            if (op != 1):
                self.abort_unknown_inst(inst, addr)
            
            # BLX (register)
            return "blx_reg"
        elif op2 == 5:
            # Saturating addition and subtraction
            self.abort_not_impl("Saturating addition and subtraction", inst, addr)
        elif op2 == 7:
            if op == 1:
                # BKPT
                self.abort_not_impl("BKPT", inst, addr)
            elif op == 3:
                # SMC (previously SMI)
                self.abort_not_impl("SMC (previously SMI)", inst, addr)
            else:
                self.abort_unknown_inst(inst, addr)
            
        else:
            self.abort_unknown_inst(inst, addr)
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def decode_dataproc_reg(self, inst, addr):
        # [27:25]=000 [4]=0
        # Data-processing (register)
        op1 = (inst >> 20) & 0x1f
        op2 = (inst >> 7) & 0x1f
        op3 = (inst >> 5) & 0x3
        # op1 != 0b10xx0
        if (op1 >> 1) == 0:
            # AND (register)
            return "and_reg"
        elif (op1 >> 1) == 1:
            # EOR (register)
            return "eor_reg"
        elif (op1 >> 1) == 2:
            # SUB (register)
            return "sub_reg"
        elif (op1 >> 1) == 3:
            # RSB (register)
            return "rsb_reg"
        elif (op1 >> 1) == 4:
            # ADD (register)
            return "add_reg"
        elif (op1 >> 1) == 5:
            # ADC (register)
            return "adc_reg"
        elif (op1 >> 1) == 6:
            # SBC (register)
            return "sbc_reg"
        elif (op1 >> 1) == 7:
            # RSC (register)
            self.abort_not_impl("RSC (register)", inst, addr)
        elif (op1 >> 1) == 8:
            if ((op1 & 1) == 0):
                self.abort_unknown_inst(inst, addr)
            
            # TST (register)
            return "tst_reg"
        elif (op1 >> 1) == 9:
            if ((op1 & 1) == 0):
                self.abort_unknown_inst(inst, addr)
            
            # TEQ (register)
            return "teq_reg"
        elif (op1 >> 1) == 0xa:
            if ((op1 & 1) == 0):
                self.abort_unknown_inst(inst, addr)
            
            # CMP (register)
            return "cmp_reg"
        elif (op1 >> 1) == 0xb:
            if ((op1 & 1) == 0):
                self.abort_unknown_inst(inst, addr)
            
            # CMN (register)
            return "cmn_reg"
        elif (op1 >> 1) == 0xc:
            # ORR (register)
            return "orr_reg"
        elif (op1 >> 1) == 0xd:
            if op3 == 0:
                if (op2 == 0):
                    # MOV (register)
                    return "mov_reg"
                else:
                    # LSL (immediate)
                    return "lsl_imm"
                
            elif op3 == 1:
                # LSR (immediate)
                return "lsr_imm"
            elif op3 == 2:
                # ASR (immediate)
                return "asr_imm"
            elif op3 == 3:
                if (op2 == 0):
                    # RRX
                    return "rrx"
                else:
                    # ROR (immediate)
                    return "ror_imm"
            
        elif (op1 >> 1) == 0xe:
            # BIC (register)
            return "bic_reg"
        elif (op1 >> 1) == 0xf:
            # MVN (register)
            return "mvn_reg"
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def decode_dataproc_rsr(self, inst, addr):
        # [27:25]=000 [7]=0 [4]=1
        # Data-processing (register-shifted register)
        op1 = (inst >> 20) & 0x1f
        op2 = (inst >> 5) & 0x3
        # op1 != 0b10xx0
        if (op1 >> 1) == 0:
            # AND (register-shifted register)
            return "and_rsr"
        elif (op1 >> 1) == 1:
            # EOR (register-shifted register)
            return "eor_rsr"
        elif (op1 >> 1) == 2:
            # SUB (register-shifted register)
            return "sub_rsr"
        elif (op1 >> 1) == 3:
            # RSB (register-shifted register)
            return "rsb_rsr"
        elif (op1 >> 1) == 4:
            # ADD (register-shifted register)
            return "add_rsr"
        elif (op1 >> 1) == 5:
            # ADC (register-shifted register)
            self.abort_not_impl("ADC (register-shifted register)", inst, addr)
        elif (op1 >> 1) == 6:
            # SBC (register-shifted register)
            return "sbc_rsr"
        elif (op1 >> 1) == 7:
            # RSC (register-shifted register)
            self.abort_not_impl("RSC (register-shifted register)", inst, addr)
        elif (op1 >> 1) == 8:
            if ((op1 & 1) == 0):
                self.abort_unknown_inst(inst, addr)
            
            # TST (register-shifted register)
            return "tst_rsr"
        elif (op1 >> 1) == 9:
            if ((op1 & 1) == 0):
                self.abort_unknown_inst(inst, addr)
            
            # TEQ (register-shifted register)
            self.abort_not_impl("TEQ (register-shifted register)", inst, addr)
        elif (op1 >> 1) == 0xa:
            if ((op1 & 1) == 0):
                self.abort_unknown_inst(inst, addr)
            
            # CMP (register-shifted register)
            return "cmp_rsr"
        elif (op1 >> 1) == 0xb:
            if ((op1 & 1) == 0):
                self.abort_unknown_inst(inst, addr)
            
            # CMN (register-shifted register)
            self.abort_not_impl("CMN (register-shifted register)", inst, addr)
        elif (op1 >> 1) == 0xc:
            # ORR (register-shifted register)
            return "orr_rsr"
        elif (op1 >> 1) == 0xd:
            if op2 == 0:
                # LSL (register)
                return "lsl_reg"
            elif op2 == 1:
                # LSR (register)
                return "lsr_reg"
            elif op2 == 2:
                # ASR (register)
                return "asr_reg"
            elif op2 == 3:
                # ROR (register)
                self.abort_not_impl("ROR (register)", inst, addr)
            
        elif (op1 >> 1) == 0xe:
            # BIC (register-shifted register)
            return "bic_rsr"
        elif (op1 >> 1) == 0xf:
            # MVN (register-shifted register)
            return "mvn_rsr"
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def decode_extra_ldst_unpriv1(self, inst, addr):
        # [27:24]=0000 [21]=1 [7]=1 [4]=1
        # [7:4]=1011
        # Extra load/store instructions (unprivileged) #1
        op = bitops.get_bit(inst, 20)
        #op2=01
        #if ((op2 & 3) == 0):
        #    self.abort_unknown_inst(inst, addr)
        #}
        if (op):
            # LDRHT
            self.abort_not_impl("LDRHT", inst, addr)
        else:
            # STRHT
            self.abort_not_impl("STRHT", inst, addr)
        
    

    def decode_extra_ldst_unpriv2(self, inst, addr):
        # [27:24]=0000 [21]=1 [7]=1 [4]=1
        # [7:4]=11x1
        # Extra load/store instructions (unprivileged) #2
        # op2=1x
        op2 = bitops.get_bits(inst, 6, 5)
        #if ((op2 & 3) == 0):
        #    self.abort_unknown_inst(inst, addr)
        #}
        if (op):
            if op2 == 2:
                # LDRSBT
                self.abort_not_impl("LDRSBT", inst, addr)
            elif op2 == 3:
                # LDRSHT
                self.abort_not_impl("LDRSHT", inst, addr)
            else:
                self.abort_unknown_inst(inst, addr)
            
        else:
            rt = bitops.get_bits(inst, 15, 12)
            if (rt & 1):
                # UNDEFINED
                self.abort_undefined_instruction("Extra load/store instructions (unprivileged) #2", inst, addr)
            else:
                # UNPREDICTABLE
                self.abort_unpredictable_instruction("Extra load/store instructions (unprivileged) #2", inst, addr)
            
        
    

    def decode_extra_ldst1(self, inst, addr):
        # [27:25]=000 [7]=1 [4]=1
        # [7:4]=1011
        # Extra load/store instructions #1
        op1 = (inst >> 20) & 0x1f
        #op2 = bitops.get_bits(inst, 6, 5)
        #op2=01
        if (op1 & 1):
            if (op1 & 4):
                rn = (inst >> 16) & 0xf
                if (rn == 0xf):
                    # LDRH (literal)
                    self.abort_not_impl("LDRH (literal)", inst, addr)
                else:
                    # LDRH (immediate)
                    return "ldrh_imm"
                
            else:
                # LDRH (register)
                return "ldrh_reg"
            
        else:
            if (op1 & 4):
                # STRH (immediate)
                return "strh_imm"
            else:
                # STRH (register)
                return "strh_reg"
            
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def decode_extra_ldst2(self, inst, addr):
        # [27:25]=000 [7]=1 [4]=1
        # [7:4]=11x1
        # Extra load/store instructions #2
        op1 = (inst >> 20) & 0x1f
        op2 = (inst >> 5) & 0x3
        #op2=1x
        rn = (inst >> 16) & 0xf
        if (op2 & 1):
            if (op1 & 1):
                if (op1 & 4):
                    if (rn == 0xf):
                        # LDRSH (literal)
                        self.abort_not_impl("LDRSH (literal)", inst, addr)
                    else:
                        # LDRSH (immediate)
                        return "ldrsh_imm"
                    
                else:
                    # LDRSH (register)
                    return "ldrsh_reg"
                
            else:
                if (op1 & 4):
                    # STRD (immediate)
                    return "strd_imm"
                else:
                    # STRD (register)
                    return "strd_reg"
                
            
        else:
            if (op1 & 1):
                if (op1 & 4):
                    if (rn == 0xf):
                        # LDRSB (literal)
                        self.abort_not_impl("LDRSB (literal)", inst, addr)
                    else:
                        # LDRSB (immediate)
                        return "ldrsb_imm"
                    
                else:
                    # LDRSB (register)
                    return "ldrsb_reg"
                
            else:
                if (op1 & 4):
                    if (rn == 0xf):
                        # LDRD (literal)
                        self.abort_not_impl("LDRD (literal)", inst, addr)
                    else:
                        # LDRD (immediate)
                        return "ldrd_imm"
                    
                else:
                    # LDRD (register)
                    return "ldrd_reg"
                
            
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def decode_multi(self, inst, addr):
        # [27:24]=0000 [7:4]=1001
        # Multiply and multiply-accumulate

        op = (inst >> 20) & 0xf
        if (op >> 1) == 0:
            # MUL
            return "mul"
        elif (op >> 1) == 1:
            # MLA
            return "mla"
        elif (op >> 1) == 2:
            if (op & 1):
                # UNDEFINED
                self.abort_undefined_instruction("Multiply and multiply-accumulate", inst, addr)
            else:
                # UMAAL
                self.abort_not_impl("UMAAL", inst, addr)
            
        elif (op >> 1) == 3:
            if (op & 1):
                # UNDEFINED
                self.abort_undefined_instruction("Multiply and multiply-accumulate", inst, addr)
            else:
                # MLS
                return "mls"
            
        elif (op >> 1) == 4:
            # UMULL
            return "umull"
        elif (op >> 1) == 5:
            # UMLAL
            return "umlal"
        elif (op >> 1) == 6:
            # SMULL
            return "smull"
        elif (op >> 1) == 7:
            # SMLAL
            return "smlal"
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def decode_datamisc(self, inst, addr):
        # Data-processing and miscellaneous instructions
        op = (inst >> 25) & 1
        op1 = (inst >> 20) & 0x1f
        op2 = (inst >> 4) & 0xf
        rn = None

        if (op):
            #if ((op1 >> 3) == 2 and (op1 & 3) == 2): # 10x10
            if (op1 == 0x12 or op1 == 0x16): # 10x10
                return self.decode_msr_imm_and_hints(inst, addr)
            else:
                if op1 == 0x10:
                    # MOV (immediate) A2?
                    return "mov_imm_a2"
                elif op1 == 0x14:
                    # MOVT
                    return "movt"
                else:
                    if ((op1 >> 3) == 2 and (op1 & 1) == 0):
                        self.abort_unknown_inst(inst, addr)
                        return None
                    else: #if (not (op1 >> 3 == 2 and (op1 & 1) == 0)):
                        # [27:25]=001
                        # Data-processing (immediate)
                        return self.decode_dataproc_imm(inst, addr)
                
            
        else:
            if (op2 & 1):
                if (op2 >> 3):
                    if ((op2 & 4) == 4):
                        if ((op1 >> 4) == 0 and (op1 & 2) == 2): # 0xx1x
                            # Extra load/store instructions (unprivileged) #2
                            return self.decode_extra_ldst_unpriv2(inst, addr)
                        else:
                            # Extra load/store instructions #2
                            return self.decode_extra_ldst2(inst, addr)
                        
                    else:
                        if (op2 & 2):
                            if ((op1 >> 4) == 0 and (op1 & 2) == 2): # 0xx1x
                                # Extra load/store instructions (unprivileged) #1
                                return self.decode_extra_ldst_unpriv1(inst, addr)
                            else:
                                # Extra load/store instructions #1
                                return self.decode_extra_ldst1(inst, addr)
                            
                        else:
                            if (op1 >> 4):
                                # Synchronization primitives
                                return self.decode_sync_prim(inst, addr)
                            else:
                                # Multiply and multiply-accumulate
                                return self.decode_multi(inst, addr)
                            
                        
                    
                else:
                    if ((op1 >> 3) == 2 and (op1 & 1) == 0): # 10xx0
                        # Miscellaneous instructions
                        return self.decode_misc(inst, addr)
                    else:
                        # Data-processing (register-shifted register)
                        return self.decode_dataproc_rsr(inst, addr)
                    
                
            else:
                if ((op1 >> 3) == 2 and (op1 & 1) == 0): # 10xx0
                    if (op2 >> 3):
                        # Halfword multiply and multiply-accumulate
                        self.abort_not_impl("Halfword multiply and multiply-accumulate", inst, addr)
                    else:
                        # Miscellaneous instructions
                        return self.decode_misc(inst, addr)
                    
                else:
                    # Data-processing (register)
                    return self.decode_dataproc_reg(inst, addr)
                
            
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def decode_media(self, inst, addr):
        # [27:25]=011 [4]=1
        # Media instructions
        op1 = (inst >> 20) & 0x1f
        op2 = (inst >> 5) & 0x7
        tmp = op1 >> 3
        rn = None
        a = None
        if tmp == 0:
            if (op1 & 4):
                # [27:22]=011001 [4]=1
                # Parallel addition and subtraction, unsigned
                op1 = bitops.get_bits(inst, 21, 20)
                op2 = bitops.get_bits(inst, 7, 5)
                if op1 == 1:
                    if op2 == 0:
                        # UADD16
                        self.abort_not_impl("UADD16", inst, addr)
                    elif op2 == 1:
                        # UASX
                        self.abort_not_impl("UASX", inst, addr)
                    elif op2 == 2:
                        # USAX
                        self.abort_not_impl("USAX", inst, addr)
                    elif op2 == 3:
                        # USUB16
                        self.abort_not_impl("USUB16", inst, addr)
                    elif op2 == 4:
                        # UADD8
                        self.abort_not_impl("UADD8", inst, addr)
                    elif op2 == 7:
                        # USUB8
                        self.abort_not_impl("USUB8", inst, addr)
                    else:
                        self.abort_unknown_inst(inst, addr)
                    
                elif op1 == 2:
                    if op2 == 0:
                        # UQADD16
                        self.abort_not_impl("UQADD16", inst, addr)
                    elif op2 == 1:
                        # UQASX
                        self.abort_not_impl("UQASX", inst, addr)
                    elif op2 == 2:
                        # UQSAX
                        self.abort_not_impl("UQSAX", inst, addr)
                    elif op2 == 3:
                        # UQSUB16
                        self.abort_not_impl("UQSUB16", inst, addr)
                    elif op2 == 4:
                        # UQADD8
                        self.abort_not_impl("UQADD8", inst, addr)
                    elif op2 == 7:
                        # UQSUB8
                        self.abort_not_impl("UQSUB8", inst, addr)
                    else:
                        self.abort_unknown_inst(inst, addr)
                    
                elif op1 == 3:
                    if op2 == 0:
                        # UHADD16
                        self.abort_not_impl("UHADD16", inst, addr)
                    elif op2 == 1:
                        # UHASX
                        self.abort_not_impl("UHASX", inst, addr)
                    elif op2 == 2:
                        # UHSAX
                        self.abort_not_impl("UHSAX", inst, addr)
                    elif op2 == 3:
                        # UHSUB16
                        self.abort_not_impl("UHSUB16", inst, addr)
                    elif op2 == 4:
                        # UHADD8
                        self.abort_not_impl("UHADD8", inst, addr)
                    elif op2 == 7:
                        # UHSUB8
                        self.abort_not_impl("UHSUB8", inst, addr)
                    else:
                        self.abort_unknown_inst(inst, addr)
                    
                else:
                    self.abort_unknown_inst(inst, addr)
                
            else:
                # [27:22]=011000 [4]=1
                # Parallel addition and subtraction, signed
                op1 = bitops.get_bits(inst, 21, 20)
                op2 = bitops.get_bits(inst, 7, 5)
                if op1 == 1:
                    if op2 == 0:
                        # SADD16
                        self.abort_not_impl("SADD16", inst, addr)
                    elif op2 == 1:
                        # SASX
                        self.abort_not_impl("SASX", inst, addr)
                    elif op2 == 2:
                        # SSAX
                        self.abort_not_impl("SSAX", inst, addr)
                    elif op2 == 3:
                        # SSUB16
                        self.abort_not_impl("SSUB16", inst, addr)
                    elif op2 == 4:
                        # SADD8
                        self.abort_not_impl("SADD8", inst, addr)
                    elif op2 == 7:
                        # SSUB8
                        self.abort_not_impl("SSUB8", inst, addr)
                    else:
                        self.abort_unknown_inst(inst, addr)
                    
                elif op1 == 2:
                    if op2 == 0:
                        # QADD16
                        self.abort_not_impl("QADD16", inst, addr)
                    elif op2 == 1:
                        # QASX
                        self.abort_not_impl("QASX", inst, addr)
                    elif op2 == 2:
                        # QSAX
                        self.abort_not_impl("QSAX", inst, addr)
                    elif op2 == 3:
                        # QSUB16
                        self.abort_not_impl("QSUB16", inst, addr)
                    elif op2 == 4:
                        # QADD8
                        self.abort_not_impl("QADD8", inst, addr)
                    elif op2 == 7:
                        # QSUB8
                        self.abort_not_impl("QSUB8", inst, addr)
                    else:
                        self.abort_unknown_inst(inst, addr)
                    
                elif op1 == 3:
                    if op2 == 0:
                        # SHADD16
                        self.abort_not_impl("SHADD16", inst, addr)
                    elif op2 == 1:
                        # SHASX
                        self.abort_not_impl("SHASX", inst, addr)
                    elif op2 == 2:
                        # SHSAX
                        self.abort_not_impl("SHSAX", inst, addr)
                    elif op2 == 3:
                        # SHSUB16
                        self.abort_not_impl("SHSUB16", inst, addr)
                    elif op2 == 4:
                        # SHADD8
                        self.abort_not_impl("SHADD8", inst, addr)
                    elif op2 == 7:
                        # SHSUB8
                        self.abort_not_impl("SHSUB8", inst, addr)
                    else:
                        self.abort_unknown_inst(inst, addr)
                    
                else:
                    self.abort_unknown_inst(inst, addr)
                
            
        elif tmp == 1:
            # [27:23]=01101 [4]=1
            # Packing, unpacking, saturation, and reversal
            op1 = (inst >> 20) & 0x7
            op2 = (inst >> 5) & 0x7
            tmp = op1 >> 1
            if tmp == 0:
                if (op1):
                    self.abort_unknown_inst(inst, addr)
                
                if (op2 & 1):
                    if (op2 >> 1) == 1:
                        a = bitops.get_bits(inst, 19, 16)
                        if (a == 0xf):
                            # SXTB16
                            self.abort_not_impl("SXTB16", inst, addr)
                        else:
                            # SXTAB16
                            self.abort_not_impl("SXTAB16", inst, addr)
                        
                    elif (op2 >> 1) == 2:
                        # SEL
                        self.abort_not_impl("SEL", inst, addr)
                    else:
                        self.abort_unknown_inst(inst, addr)
                    
                else:
                    raise Exception("PKH")
                
            elif tmp == 1:
                if (op2 & 1):
                    if op1 == 2:
                        if op2 == 1:
                            # SSAT16
                            self.abort_not_impl("SSAT16", inst, addr)
                        elif op2 == 3:
                            a = bitops.get_bits(inst, 19, 16)
                            if (a == 0xf):
                                # SXTB
                                return "sxtb"
                            else:
                                # SXTAB
                                self.abort_not_impl("SXTAB", inst, addr)
                            
                        else:
                            self.abort_unknown_inst(inst, addr)
                        
                    elif op1 == 3:
                        if op2 == 1:
                            # REV
                            return "rev"
                        elif op2 == 3:
                            a = (inst >> 16) & 0xf
                            if (a == 0xf):
                                    # SXTH
                                    return "sxth"
                            else:
                                    # SXTAH
                                    return "sxtah"
                            
                        elif op2 == 5:
                            # REV16
                            return "rev16"
                        else:
                            self.abort_unknown_inst(inst, addr)
                        
                    else:
                        self.abort_unknown_inst(inst, addr)
                    
                else:
                    # SSAT
                    self.abort_not_impl("SSAT", inst, addr)
                
            elif tmp == 2:
                if (op2 != 3):
                    self.abort_unknown_inst(inst, addr)
                
                a = bitops.get_bits(inst, 19, 16)
                if (a == 0xf):
                        # UXTB16
                        self.abort_not_impl("UXTB16", inst, addr)
                else:
                        # UXTAB16
                        self.abort_not_impl("UXTAB16", inst, addr)
                
            elif tmp == 3:
                if (op2 & 1):
                    if op1 == 6:
                        if op2 == 1:
                            # USAT16
                            self.abort_not_impl("USAT16", inst, addr)
                        elif op2 == 3:
                            a = (inst >> 16) & 0xf
                            if (a == 0xf):
                                    # UXTB
                                    return "uxtb"
                            else:
                                    # UXTAB
                                    return "uxtab"
                            
                        else:
                            self.abort_unknown_inst(inst, addr)
                        
                    elif op1 == 7:
                        if op2 == 1:
                            # RBIT
                            self.abort_not_impl("RBIT", inst, addr)
                        elif op2 == 3:
                            a = (inst >> 16) & 0xf
                            if (a == 0xf):
                                    # UXTH
                                    return "uxth"
                            else:
                                    # UXTAH
                                    return "uxtah"
                            
                        elif op2 == 5:
                            # REVSH
                            self.abort_not_impl("REVSH", inst, addr)
                        else:
                            self.abort_unknown_inst(inst, addr)
                        
                    else:
                        self.abort_unknown_inst(inst, addr)
                    
                else:
                    # USAT
                    return "usat"
                
            
        elif tmp == 2:
            # [27:23]=01110 [4]=1
            # Signed multiplies
            op1 = (inst >> 20) & 0x7
            op2 = (inst >> 5) & 0x7
            a = (inst >> 12) & 0xf
            if op1 == 0:
                if (op2 >> 1) == 0:
                    if (a == 0xf):
                        # SMUAD
                        self.abort_not_impl("SMUAD", inst, addr)
                    else:
                        # SMLAD
                        self.abort_not_impl("SMLAD", inst, addr)
                    
                elif (op2 >> 1) == 1:
                    if (a == 0xf):
                        # SMUSD
                        self.abort_not_impl("SMUSD", inst, addr)
                    else:
                        # SMLSD
                        self.abort_not_impl("SMLSD", inst, addr)
                    
                else:
                    self.abort_unknown_inst(inst, addr)
                
            elif op1 == 4:
                if (op2 >> 1) == 0:
                    # SMLALD
                    self.abort_not_impl("SMLALD", inst, addr)
                elif (op2 >> 1) == 1:
                    # SMLSLD
                    self.abort_not_impl("SMLSLD", inst, addr)
                else:
                    self.abort_unknown_inst(inst, addr)
                
            elif op1 == 5:
                if (op2 >> 1) == 0:
                    if (a == 0xf):
                        # SMMUL
                        self.abort_not_impl("SMMUL", inst, addr)
                    else:
                        # SMMLA
                        self.abort_not_impl("SMMLA", inst, addr)
                    
                elif (op2 >> 1) == 3:
                    # SMMLS
                    self.abort_not_impl("SMMLS", inst, addr)
                else:
                    self.abort_unknown_inst(inst, addr)
                
            else:
                self.abort_unknown_inst(inst, addr)
            
        elif tmp == 3:
            if (op1 == 0x1f and op2 == 7):
                # UNDEFINED
                self.abort_undefined_instruction("Signed multiplies", inst, addr)
            
            if (op1 >> 1 & 3) == 0:
                if ((op1 & 1) == 0 and op2 == 0):
                    rd = bitops.get_bits(inst, 15, 12)
                    if (rd == 0xf):
                        # USAD8
                        self.abort_not_impl("USAD8", inst, addr)
                    else:
                        # USADA8
                        self.abort_not_impl("USADA8", inst, addr)
                    
                else:
                    self.abort_unknown_inst(inst, addr)
            elif (op1 >> 1 & 3) == 1:
                if ((op2 & 3) == 2):
                    # SBFX
                    return "sbfx"
                
                self.abort_unknown_inst(inst, addr)
            elif (op1 >> 1 & 3) == 2:
                if ((op2 & 3) == 0):
                    rn = inst & 0xf
                    if (rn == 0xf):
                        # BFC
                        return "bfc"
                    else:
                        # BFI
                        return "bfi"
                    
                else:
                    self.abort_unknown_inst(inst, addr)
            elif (op1 >> 1 & 3) == 3:
                if ((op2 & 3) == 2):
                    # UBFX
                    return "ubfx"
                
                self.abort_unknown_inst(inst, addr)
            
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def decode(self, inst, addr):
        # 
        #  bits[31:28]: cond
        #  bits[27:25]: op1
        #  bit[4]: op
        # 
        cond = inst >> 28
        op = (inst >> 4) & 1
        op1 = (inst >> 25) & 7
        op2 = None
        tmp = None
        rn = None
        coproc = None

        self.shift_t = 0
        self.shift_n = 0
        self.carry_out = 0
        self.overflow = 0

        if (inst == 0xeef06a10):
            return "vmrs"

        if (cond == 0xf):
            # Unconditional instructions
            return self.decode_uncond(inst, addr)
        else: # cond != 0xf
            if (op1 >> 1) == 0:
                # Data-processing and miscellaneous instructions
                return self.decode_datamisc(inst, addr)
            elif (op1 >> 1) == 1:
                if (op1 & 1):
                    if (op):
                        # [27:25]=011 [4]=1
                        # Media instructions
                        return self.decode_media(inst, addr)
                    else:
                        # [27:25]=011 [4]=0
                        # Load/store word and unsigned byte #2
                        op1 = (inst >> 20) & 0x1f
                        # A=1 B=0
                        if (op1 & 1):
                            if (op1 & 4): # xx1x1
                                if (op1 == 7 or op1 == 15): # 0x111
                                    # LDRBT
                                    self.abort_not_impl("LDRBT", inst, addr)
                                else:
                                    # LDRB (register)
                                    return "ldrb_reg"
                                
                            else: # xx0x1
                                if (op1 == 3 or op1 == 11): # 0x011
                                    # LDRT
                                    self.abort_not_impl("LDRT A2", inst, addr)
                                else:
                                    # LDR (register)
                                    return "ldr_reg"
                                
                            
                        else:
                            if (op1 & 4): # xx1x0
                                if (op1 == 6 or op1 == 14): # 0x110
                                    # STRBT A2
                                    return "strbt_a2"
                                else:
                                    # STRB (register)
                                    return "strb_reg"
                                
                            else: # xx0x0
                                if (op1 == 2 or op1 == 10): # 0x010
                                    # STRT
                                    self.abort_not_impl("STRT", inst, addr)
                                else:
                                    # STR (register)
                                    return "str_reg"
                                
                            
                        
                    
                else:
                    # [27:25]=010 [4]=x
                    # Load/store word and unsigned byte #1
                    op1 = (inst >> 20) & 0x1f
                    # A=0 B=x
                    if (op1 & 1):
                        if (op1 & 4): # xx1x1
                            if (op1 == 7 or op1 == 15): # 0x111
                                # LDRBT
                                self.abort_not_impl("LDRBT", inst, addr)
                            else:
                                rn = (inst >> 16) & 0xf
                                if (rn == 0xf):
                                    # LDRB (literal)
                                    self.abort_not_impl("LDRB (literal)", inst, addr)
                                else:
                                    # LDRB (immediate)
                                    return "ldrb_imm"
                                
                            
                            #break
                        else: # xx0x1
                            if (op1 == 3 or op1 == 0xb): # 0x011
                                # LDRT
                                return "ldrt_a1"
                            else:
                                rn = (inst >> 16) & 0xf
                                if (rn == 0xf):
                                    # LDR (literal)
                                    return "ldr_lit"
                                else:
                                    # LDR (immediate)
                                    return "ldr_imm"
                                
                            
                        
                    else:
                        if (op1 & 4): # xx1x0
                            if (op1 == 6 or op1 == 14): # 0x110
                                # STRBT A1
                                return "strbt_a1"
                            else:
                                # STRB (immediate)
                                return "strb_imm"
                            
                        else: # xx0x0
                            if (op1 == 2 or op1 == 10): # 0x010
                                # STRT
                                self.abort_not_impl("STRT", inst, addr)
                            else:
                                # STR (immediate)
                                return "str_imm"
                            
                        
                    
                
            elif (op1 >> 1) == 2:
                # [27:26]=10
                # Branch, branch with link, and block data transfer
                op = (inst >> 20) & 0x3f
                if (op & 0x20):
                    if (op & 0x10):
                        # BL, BLX (immediate)
                        return "bl_imm"
                    else:
                        # [27:24]=1010
                        # B (branch)
                        return "b"
                    
                else:
                    if (op & 4):
                        if (op & 1):
                            r = (inst >> 15) & 1
                            if (r):
                                # LDM (exception return)
                                return "ldm_er"
                            else:
                                # LDM (user registers)
                                return "ldm_ur"
                            
                        else:
                            # STM (user registers)
                            return "stm_ur"
                        
                    else:
                        if (op & 1):
                            # 0b11100
                            if (op >> 2 & 7) == 0:
                                # LDMDA / LDMFA
                                return "ldmda"
                            elif (op >> 2 & 7) == 2:
                                # LDM / LDMIA / LDMFD
                                return "ldm"
                            elif (op >> 2 & 7) == 4:
                                # LDMDB / LDMEA
                                return "ldmdb"
                            elif (op >> 2 & 7) == 6:
                                # LDMIB / LDMED
                                return "ldmib"
                            else:
                                self.abort_unknown_inst(inst, addr)
                            
                        else:
                            # 0b11100
                            if (op >> 2 & 7) == 0:
                                # STMDA / STMED
                                self.abort_not_impl("STMDA / STMED", inst, addr)
                            elif (op >> 2 & 7) == 2:
                                # STM / STMIA / STMEA
                                return "stm"
                            elif (op >> 2 & 7) == 4:
                                # STMDB / STMFD
                                return "stmdb"
                            elif (op >> 2 & 7) == 6:
                                # STMIB / STMFA
                                return "stmib"
                            else:
                                self.abort_unknown_inst(inst, addr)
                            
                        
                    
                
            elif (op1 >> 1) == 3:
                # [27:26]=11
                # System call, and coprocessor instructions
                op1 = (inst >> 20) & 0x3f
                op = (inst >> 4) & 1
                if (op1 & 0x20):
                    if (op1 & 0x10):
                        # SVC (previously SWI)
                        return "svc"
                    else:
                        coproc = (inst >> 8) & 0xf
                        if (op):
                            if ((coproc >> 1) == 5): # 0b101x
                                # Advanced SIMD, VFP
                                # 8, 16, and 32-bit transfer between ARM core and extension registers
                                self.abort_simdvfp_inst(inst, addr)
                            else:
                                if (op1 & 1):
                                    # cond != 1111
                                    # MRC, MRC2 A1
                                    return "mrc_a1"
                                else:
                                    # cond != 1111
                                    # MCR, MCR2 A1
                                    return "mcr_a1"
                                
                            
                        else:
                            if ((coproc >> 1) == 5): # 0b101x
                                # VFP data-processing instructions
                                self.abort_simdvfp_inst(inst, addr)
                            else:
                                # CDP, CDP2
                                raise Exception("UND")
                            
                        
                    
                else:
                    if ((op1 >> 3) == 0 and (op1 & 2) == 0): # 000x0x
                        if (op1 >> 1) == 0:
                            # UNDEFINED
                            self.abort_undefined_instruction("System call, and coprocessor instructions", inst, addr)
                        elif (op1 >> 1) == 2:
                            coproc = bitops.get_bits(inst, 11, 8)
                            if ((coproc >> 1) == 5): # 0b101x
                                # 64-bit transfers between ARM core and extension registers
                                self.abort_simdvfp_inst(inst, addr)
                            else:
                                if (op1 & 1):
                                    # MRRC, MRRC2
                                    self.abort_not_impl("MRRC, MRRC2", inst, addr)
                                else:
                                    # MCRR, MCRR2
                                    self.abort_not_impl("MCRR, MCRR2", inst, addr)
                                
                            
                        else:
                            self.abort_unknown_inst(inst, addr)
                        
                    else:
                        coproc = bitops.get_bits(inst, 11, 8)
                        if ((coproc >> 1) == 5): # 0b101x
                            # Advanced SIMD, VFP
                            # Extension register load/store instructions
                            self.abort_simdvfp_inst(inst, addr)
                        else:
                            if (op1 & 1):
                                rn = bitops.get_bits(inst, 19, 16)
                                if (rn == 0xf):
                                    # LDC, LDC2 (literal)
                                    raise Exception("UND")
                                else:
                                    # LDC, LDC2 (immediate)
                                    raise Exception("UND")
                                
                            else:
                                # STC, STC2
                                raise Exception("UND")
                            
                        
                    
                
            
        
        self.abort_unknown_inst(inst, addr)
        return None
    

    def interrupt(self, irq):
        logger.log("got interrupt")
        self.spsr_irq = self.clone_psr(self.cpsr)
        self.regs_irq[14] = (self.get_pc() - 4) & 0xffffffff

        self.change_mode(self.IRQ_MODE)
        self.cpsr.i = 1
        self.cpsr.a = 1

        cp15 = self.coprocs[15]
        self.regs[15] = cp15.interrupt_vector_address + 0x18
    

    def data_abort(self):
        logger.log("got data abort")
        self.spsr_abt = self.clone_psr(self.cpsr)
        self.regs_abt[14] = self.get_pc()

        self.change_mode(self.ABT_MODE)
        self.cpsr.i = 1

        cp15 = self.coprocs[15]
        self.regs[15] = cp15.interrupt_vector_address + 0x10
    

    def prefetch_abort(self):
        logger.log("got prefetch abort")
        self.spsr_abt = self.clone_psr(self.cpsr)
        self.regs_abt[14] = (self.get_pc() - 4) & 0xffffffff

        self.change_mode(self.ABT_MODE)
        self.cpsr.i = 1

        cp15 = self.coprocs[15]
        self.regs[15] = cp15.interrupt_vector_address + 0x0c
    

    def supervisor(self):
        logger.log("got svc")
        self.spsr_svc = self.clone_psr(self.cpsr)
        self.regs_svc[14] = (self.get_pc() - 4) & 0xffffffff

        self.change_mode(self.SVC_MODE)
        self.cpsr.i = 1

        cp15 = self.coprocs[15]
        self.regs[15] = cp15.interrupt_vector_address + 0x08
    

    def undefined_instruction(self):
        logger.log("undef instr")
        self.spsr_und = self.clone_psr(self.cpsr)
        self.regs_und[14] = (self.get_pc() - 4) & 0xffffffff

        self.change_mode(self.UND_MODE)
        self.cpsr.i = 1

        cp15 = self.coprocs[15]
        self.regs[15] = cp15.interrupt_vector_address + 0x04
    
