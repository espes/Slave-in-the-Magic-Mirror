# drm.py
#
# Copyright 2014, espes
#
# Licensed under GPL Version 2 or later
#

import hashlib

import loader

class FairPlaySAP(object):
    """FairPlay Secure Association Protocol"""

    def __init__(self, airtunes_filename="airtunesd"):

        with open(airtunes_filename, "rb") as f:
            hash_ = hashlib.sha1(f.read()).hexdigest()

        if hash_ == "1024dbffd30d55ecea4fabbc78ee4b3bda265874":
            # AirTunes 120.2, from AppleTV2,1 build 9A334v
            self.fp_initsap = 0x435B4
            self.fp_challenge = 0xEB00C
            self.fp_decryptkey = 0xEB964
        else:
            raise Exception("unsupported airtunesd")

        self.p = loader.IOSProcess(airtunes_filename)
        

        self.fpInfo = 0x123
        self.initSAP()

    def initSAP(self):
        pSapInfo = self.p.malloc(4)
        self.p.call(self.fp_initsap, (pSapInfo, self.fpInfo))

        self.sapInfo = self.p.cpu.ld_word(pSapInfo)

    def challenge(self, type_, data, stage):
        if stage == 0:
            assert len(data) == 16
        elif stage == 1:
            assert len(data) == 164
        else:
            assert False

        p_data = self.p.malloc(len(data))
        self.p.copyin(p_data, data)

        p_unkn = 0xabc
        
        p_out_data = self.p.malloc(4)
        p_out_length = self.p.malloc(4)

        p_inout_stage = self.p.malloc(4)
        self.p.cpu.st_word(p_inout_stage, stage)

        r = self.p.call(self.fp_challenge,
                (type_, self.fpInfo, self.sapInfo,
                 p_data, p_unkn, p_out_data, p_out_length, p_inout_stage))

        # print "args", map(hex, (type_, self.fpInfo, self.sapInfo,
        #          p_data, p_unkn, p_out_data, p_out_length, p_inout_stage))

        # print "r", hex(r)

        #assert r == 0

        out_data = self.p.cpu.ld_word(p_out_data)
        # print "out_data", hex(out_data)
        out_length = self.p.cpu.ld_word(p_out_length)
        # print "out_length", hex(out_length)
        out_stage = self.p.cpu.ld_word(p_inout_stage)
        # print "out_stage", out_stage

        if stage == 0:
            assert out_length == 0x8e
            assert out_stage == 1
        else:
            assert out_stage == 0

        return self.p.copyout(out_data, out_length)

    def decrypt_key(self, param1):
        p_param1 = self.p.malloc(len(param1))
        self.p.copyin(p_param1, param1)

        p_out_data = self.p.malloc(4)
        p_out_length = self.p.malloc(4)

        r = self.p.call(self.fp_decryptkey,
                (self.sapInfo, p_param1, len(param1),
                 p_out_data, p_out_length))

        assert r == 0

        out_data = self.p.cpu.ld_word(p_out_data)
        # print "out_data", hex(out_data)
        out_length = self.p.cpu.ld_word(p_out_length)
        # print "out_length", hex(out_length)

        assert out_length == 16

        return self.p.copyout(out_data, out_length)
