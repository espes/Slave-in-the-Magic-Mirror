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

        print "args", map(hex, (type_, self.fpInfo, self.sapInfo,
                 p_data, p_unkn, p_out_data, p_out_length, p_inout_stage))

        print "r", hex(r)

        #assert r == 0

        out_data = self.p.cpu.ld_word(p_out_data)
        print "out_data", hex(out_data)
        out_length = self.p.cpu.ld_word(p_out_length)
        print "out_length", hex(out_length)
        out_stage = self.p.cpu.ld_word(p_inout_stage)
        print "out_stage", out_stage

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
        print "out_data", hex(out_data)
        out_length = self.p.cpu.ld_word(p_out_length)
        print "out_length", hex(out_length)

        assert out_length == 16

        return self.p.copyout(out_data, out_length)

if __name__ == "__main__":

    fp = FairPlaySAP("airtunesd_44")
    
    # print
    # print "Stage 0"
    # print
    # r0 = fp.challenge(2, "46504C590301010000000004020003BB".decode("hex"), 0)
    # print r0.encode("hex")
    
    # print
    # print "Stage 1"
    # print
    # r1 = fp.challenge(2, "46504C590301030000000098018F1A9C7D0AF257B31F21F5C2D2BC814C032D457835AD0B06250574BBC7AB4A58CCA6EEAD2C911D7F3E1E7ED4C058955DFF3D5CEEF014387A985BDB34995015E3DFBDACC56047CB926E093B13E9FDB5E1EEE317C018BBC87FC5453C7671647DA686DA3D564875D03F8AEA9D60092DE06110BC7BE0C16F391C369C75344AE47F33ACFCF10E63A9B58BFCE215E96001C49E4BE967C5067F2A".decode("hex"), 1)
    # print len(r1), r1.encode("hex")

    print
    print "Stage 0"
    print
    r0 = fp.challenge(2, "46504c590201010000000004020001bb".decode("hex"), 0)
    print r0.encode("hex")
    assert r0 == "46504c59020102000000008202012157a656cf4046c01a75aad3fce23a29caf39d1a4f9b3c2db38519b0e9486e3da39f956d57db3eadc5f87c33f31ae1b5e28d23c45ac26dd15d8bdc04808440f4065657b1df9e12895c9b88a7a2b707ef2c23959012d4fcc733a0e8e3cc496e8bdebf2bfff7e9e906748dfe3ebbee8ebe798365ac0b4f9e40e034df3c7781849c".decode("hex")
    
    print
    print "Stage 1"
    print
    r1 = fp.challenge(2, "46504c590201030000000098018f1a9c0955797af1df9d2ce22b3441090b61c98e9cd5f68cda65cc855bb0079bfceee13319f21873344cd4f4844556c2b78814cf78011c90f357a7f451dad8401e26edb8342f230c02ec0afdee5dfbf01629d0d2f8d2e01d0d5576dfe63a8cae86dc34beffb0fac0b44ba99e4c34017c9a9c01892e9ba4ffa2f032bd209ecd03b64e5da571516282ddc61b8514dac267430d82ecb64439".decode("hex"), 1)
    print len(r1), r1.encode("hex")
