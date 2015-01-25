# hfs.py
#
# Adapted from iphone-dataprotection
#
# Licensed under GPL Version 3 or later
#

import os
import sys
import zlib
import struct
import hashlib
import datetime
import cStringIO

from structs import *
from btree import AttributesTree, CatalogTree, ExtentsOverflowTree


def hfs_date(t):
    return datetime.datetime(1904,1,1) + datetime.timedelta(seconds=t)

class HFSFile(object):
    def __init__(self, volume, hfsplusfork, fileID, deleted=False):
        self.volume = volume
        self.blockSize = volume.blockSize
        self.fileID = fileID
        self.totalBlocks = hfsplusfork.totalBlocks
        self.logicalSize = hfsplusfork.logicalSize
        self.extents = volume.getAllExtents(hfsplusfork, fileID)
        self.deleted = deleted

    def readAll(self, output, truncate=True):
        if truncate: truncate = (self.logicalSize % self.volume.blockSize) != 0
        for i in xrange(self.totalBlocks):
            data = self.readBlock(i)
            if truncate and i == self.totalBlocks - 1:
                data = data[:self.logicalSize % len(data)]
            output.write(data)

    def readAllBuffer(self, truncate=True):
        r = ""
        for i in xrange(self.totalBlocks):
            r += self.readBlock(i)
        if truncate:
            r = r[:self.logicalSize]
        return r

    def processBlock(self, block, lba):
        return block

    def readBlock(self, n):
        bs = self.volume.blockSize
        if n*bs > self.logicalSize:
            # return "BLOCK OUT OF BOUNDS" + "\xFF" * (bs - len("BLOCK OUT OF BOUNDS"))
            assert False, "BLOCK OUT OF BOUNDS"
        bc = 0
        for extent in self.extents:
            bc += extent.blockCount
            if n < bc:
                lba = extent.startBlock+(n-(bc-extent.blockCount))
                if not self.deleted and self.fileID != kHFSAllocationFileID and  not self.volume.isBlockInUse(lba):
                    pass#print "FAIL, block %x not marked as used" % n
                return self.processBlock(self.volume.readBlock(lba), lba)
        return ""

    def getLBAforBlock(self, n):
        bc = 0
        for extent in self.extents:
            bc += extent.blockCount
            if n < bc:
                return extent.startBlock+(n-(bc-extent.blockCount))

    def writeBlock(self, n, data):
        bs = self.volume.blockSize
        if n*bs > self.logicalSize:
            raise Exception("writeBlock, out of bounds %d" % n)
        bc = 0
        for extent in self.extents:
            bc += extent.blockCount
            if n < bc:
                lba = extent.startBlock+(n-(bc-extent.blockCount))
                self.volume.writeBlock(lba, data)
                return


class HFSCompressedResourceFork(HFSFile):
    def __init__(self, volume, hfsplusfork, fileID):
        super(HFSCompressedResourceFork,self).__init__(volume, hfsplusfork, fileID)
        block0 = self.readBlock(0)
        self.header = HFSPlusCmpfRsrcHead.parse(block0)
        #print self.header
        self.blocks = HFSPlusCmpfRsrcBlockHead.parse(block0[self.header.headerSize:])
        #print "HFSCompressedResourceFork numBlocks:", self.blocks.numBlocks
        #print self.blocks

    #HAX, readblock not implemented
    def readAllBuffer(self, output):
        buff = super(HFSCompressedResourceFork, self).readAllBuffer()
        r = ""
        base = self.header.headerSize + 4
        for b in self.blocks.HFSPlusCmpfRsrcBlock:
            x = buff[base+b.offset:base+b.offset+b.size]
            if x.startswith("\xFF"):
                output.write(x[1:])
            else:
                output.write(zlib.decompress(x))
        #return r

class HFSVolume(object):
    def __init__(self, bdev):
        self.bdev = bdev

        self.bdev.seek(0x400)
        self.header = HFSPlusVolumeHeader.parse_stream(self.bdev)
        assert self.header.signature == 0x4858 or self.header.signature == 0x482B

        self.blockSize = self.header.blockSize

        #if os.path.getsize(filename) < self.header.totalBlocks * self.blockSize:
        #    print "WARNING: HFS image appears to be truncated"

        self.allocationFile = HFSFile(self, self.header.allocationFile, kHFSAllocationFileID)
        self.allocationBitmap = self.allocationFile.readAllBuffer()
        self.extentsFile = HFSFile(self, self.header.extentsFile, kHFSExtentsFileID)
        self.extentsTree = ExtentsOverflowTree(self.extentsFile)
        self.catalogFile = HFSFile(self, self.header.catalogFile, kHFSCatalogFileID)
        self.xattrFile = HFSFile(self, self.header.attributesFile, kHFSAttributesFileID)
        self.catalogTree = CatalogTree(self.catalogFile, self)
        self.xattrTree = AttributesTree(self.xattrFile)

        self.hasJournal = self.header.attributes & (1 << kHFSVolumeJournaledBit)

        k,v = self.catalogTree.search((kHFSRootFolderID, ""))
        self.volumename = getString(v.data)

    def readBlock(self, b):
        self.bdev.seek(b * self.blockSize)
        return self.bdev.read(self.blockSize)

    def writeBlock(self, lba, data):
        raise NotImplementedError
        # return self.bdev.writeBlock(lba, data)

    def volumeID(self):
        return struct.pack(">LL", self.header.finderInfo[6], self.header.finderInfo[7])

    def isBlockInUse(self, block):
        thisByte = ord(self.allocationBitmap[block / 8])
        return (thisByte & (1 << (7 - (block % 8)))) != 0

    # def unallocatedBlocks(self):
    #     for i in xrange(self.header.totalBlocks):
    #         if not self.isBlockInUse(i):
    #             yield i, self.read(i*self.blockSize, self.blockSize)

    def getExtentsOverflowForFile(self, fileID, startBlock, forkType=kForkTypeData):
        return self.extentsTree.searchExtents(fileID, forkType, startBlock)

    def getXattr(self, fileID, name):
        return self.xattrTree.searchXattr(fileID, name)

    def getFileByPath(self, path):
        return self.catalogTree.getRecordFromPath(path)

    def getFileIDByPath(self, path):
        key, record = self.catalogTree.getRecordFromPath(path)
        if not record:
            return
        if record.recordType == kHFSPlusFolderRecord:
            return record.data.folderID
        return record.data.fileID

    def listFolderContents(self, path):
        k,v = self.catalogTree.getRecordFromPath(path)
        if not k or v.recordType != kHFSPlusFolderRecord:
            return
        for k,v in self.catalogTree.getFolderContents(v.data.folderID):
            if v.recordType == kHFSPlusFolderRecord:
                #.HFS+ Private Directory Data\r
                print v.data.folderID, getString(k).replace("\r","") + "/"
            elif v.recordType == kHFSPlusFileRecord:
                print v.data.fileID, getString(k)

    def ls(self, path):
        k,v = self.catalogTree.getRecordFromPath(path)
        return self._ls(k, v)

    def _ls(self, k, v):
        res = {}

        if not k or v.recordType != kHFSPlusFolderRecord:
            return None
        for k,v in self.catalogTree.getFolderContents(v.data.folderID):
            if v.recordType == kHFSPlusFolderRecord:
                #.HFS+ Private Directory Data\r
                res[getString(k).replace("\r","") + "/"] =  v.data
            elif v.recordType == kHFSPlusFileRecord:
                if is_hardlink(v.data):
                    #print "hardlink iNode%d" % v.data.HFSPlusBSDInfo.special.iNodeNum
                    k2,v2 = self.catalogTree.getRecordFromPath("/\x00\x00\x00\x00HFS+ Private Data/iNode%d" % v.data.HFSPlusBSDInfo.special.iNodeNum)
                    res[getString(k)] = v2.data
                else:
                    res[getString(k)] = v.data
        return res

    def listXattrs(self, path):
        k,v = self.catalogTree.getRecordFromPath(path)
        if k and v.recordType == kHFSPlusFileRecord:
            return self.xattrTree.getAllXattrs(v.data.fileID)
        elif k and v.recordType == kHFSPlusFolderThreadRecord:
            return self.xattrTree.getAllXattrs(v.data.folderID)

    def readCompressedFile(self, record, xattr, output):
        decmpfs = HFSPlusDecmpfs.parse(xattr)
        data = None
        if decmpfs.compression_type == 1:
            output.write(xattr[16:])
        elif decmpfs.compression_type == 3:
            if decmpfs.uncompressed_size == len(xattr) - 16:
                output.write(xattr[16:])
            elif xattr[16] == "\xFF":
                output.write(xattr[17:])
            else:
                output.write(zlib.decompress(xattr[16:]))
        elif decmpfs.compression_type == 4:
            f = HFSCompressedResourceFork(self, record.data.resourceFork, record.data.fileID)
            f.readAllBuffer(output)

    def readFileByRecord(self, key, record, output):
        assert record.recordType == kHFSPlusFileRecord
        xattr = self.getXattr(record.data.fileID, "com.apple.decmpfs")
        if xattr:
            self.readCompressedFile(record, xattr, output)
        else:
            f = HFSFile(self, record.data.dataFork, record.data.fileID)
            f.readAll(output)
        return True


    def _readFile(self, path, output):
        k,v = self.catalogTree.getRecordFromPath(path)
        if not v:
            print "File %s not found" % path
            return
        assert v.recordType == kHFSPlusFileRecord
        return self.readFileByRecord(k, v, output)

    def readFile(self, path, outdir="./", returnString=False):
        if returnString:
            return self.readFileToString(path)
        outputfile = os.path.join(outdir,os.path.basename(path))
        f = open(outputfile, "wb")
        res = self._readFile(path, f)
        f.close()
        if not res:
            os.unlink(outputfile)
        return res

    def readFileToString(self, path):
        sio = cStringIO.StringIO()
        self._readFile(path, sio)
        return sio.getvalue()

    def readJournal(self):
        #jb = self.read(self.header.journalInfoBlock * self.blockSize, self.blockSize)
        #jib = JournalInfoBlock.parse(jb)
        #return self.read(jib.offset,jib.size)
        return self.readFile("/.journal", returnString=True)

    def listAllFileIds(self):
        self.fileids={}
        self.catalogTree.traverseLeafNodes(callback=self.grabFileId)
        return self.fileids

    def grabFileId(self, k,v):
        if v.recordType == kHFSPlusFileRecord:
            self.fileids[v.data.fileID] = True

    def getFileRecordForFileID(self, fileID):
        k,v = self.catalogTree.searchByCNID(fileID)
        return v

    def getFullPath(self, fileID):
        k,v = self.catalogTree.search((fileID, ""))
        if not k:
            print "File ID %d not found" % fileID
            return ""
        if fileID == kHFSRootFolderID:
            return "/"
        p = getString(v.data)
        while k:
            k,v = self.catalogTree.search((v.data.parentID, ""))
            if k.parentID == kHFSRootFolderID:
                break
            p = getString(v.data) + "/" + p

        return "/" + p

    def getFileRecordForPath(self, path):
        k,v = self.catalogTree.getRecordFromPath(path)
        if not k:
            return
        return v.data

    def getAllExtents(self, hfsplusfork, fileID):
        b = 0
        extents = []
        for extent in hfsplusfork.HFSPlusExtentDescriptor:
            extents.append(extent)
            b += extent.blockCount
        while b != hfsplusfork.totalBlocks:
            k,v = self.getExtentsOverflowForFile(fileID, b)
            if not v:
                print "extents overflow missing, startblock=%d" % b
                break
            for extent in v:
                extents.append(extent)
                b += extent.blockCount
        return extents

    def dohashFiles(self, k,v):
        if v.recordType == kHFSPlusFileRecord and not is_symlink(v.data):
            filename = getString(k)
            f = HFSFile(self, v.data.dataFork, v.data.fileID)
            print filename, hashlib.sha1(f.readAllBuffer()).hexdigest()

    def hashFiles(self):
        self.catalogTree.traverseLeafNodes(callback=self.dohashFiles)

