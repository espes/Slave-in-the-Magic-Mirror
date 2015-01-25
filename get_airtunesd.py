# get_airtunesd.py
#
# Copyright 2015, espes
#
# Using information from xpwn by planetbeing
#
# Licensed under GPL Version 2 or later
#

import os
import sys
import time
import zlib
import shutil
import struct
import urllib
import zipfile
import tempfile
import plistlib

import requests
import construct
from bs4 import BeautifulSoup

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend

import hfs

class BaseFile(object):
    def __init__(self):
        self.offset = 0
    def size(self):
        raise NotImplementedError
    def seek(self, offset, whence=0):
        if whence == 0:
            self.offset = offset
        elif whence == 1:
            self.offset += offset
        elif whence == 2:
            self.offset = self.size() + offset
        else:
            assert False
        self.offset = min(self.offset, self.size())
        self.offset = max(self.offset, 0)
    def tell(self):
        return self.offset

FileVaultV2Header = construct.Struct("FileVaultV2Header",
    construct.Magic("encrcdsa"),
    construct.UBInt32("version"),
    construct.UBInt32("encIVSize"),
    construct.UBInt32("_unk1"),
    construct.UBInt32("_unk2"),
    construct.UBInt32("keyBits"),
    construct.UBInt32("_unk4"),
    construct.UBInt32("_unk5"),
    construct.Array(4, construct.UBInt32("UDIFID")),
    construct.UBInt32("blockSize"),
    construct.UBInt64("dataSize"),
    construct.UBInt64("dataOffset"),
    construct.Padding(0x260),
    construct.UBInt32("kdfAlgorithm"),
    construct.UBInt32("kdfPRNGAlgorithm"),
    construct.UBInt32("kdfIterationCount"),
    construct.UBInt32("kdfSaltLen"),
    construct.String("kdfSalt", 0x20),
    construct.UBInt32("blobEncIVSize"),
    construct.String("blobEncIV", 0x20),
    construct.UBInt32("blobEncKeyBits"),
    construct.UBInt32("blobEncAlgorithm"),
    construct.UBInt32("blobEncPadding"),
    construct.UBInt32("blobEncMode"),
    construct.UBInt32("encryptedKeyblobSize"),
    construct.String("encryptedKeyblob", 0x30))

class FileVaultFile(BaseFile):
    def __init__(self, f, key):
        BaseFile.__init__(self)

        self.f = f
        self.aes_key = key[:16]
        self.hmac_key = key[16:]

        self.header = FileVaultV2Header.parse_stream(self.f)
        assert self.header.version == 2
        assert self.header.encIVSize == 16
        assert self.header.keyBits == 128

        self.chunk_cache = {}

    def size(self):
        return self.header.dataSize

    def read_chunk(self, chunk):
        if chunk in self.chunk_cache: return self.chunk_cache[chunk]

        h = hmac.HMAC(self.hmac_key, hashes.SHA1(), backend=default_backend())
        h.update(struct.pack(">I", chunk))
        iv = h.finalize()[:16]
        # print len(iv), `iv`

        cipher = Cipher(algorithms.AES(self.aes_key),
                        modes.CBC(iv),
                        backend=default_backend())
        decryptor = cipher.decryptor()

        self.f.seek(self.header.dataOffset + chunk * self.header.blockSize)
        data = self.f.read(self.header.blockSize)
        assert len(data) == self.header.blockSize

        r = decryptor.update(data)
        self.chunk_cache[chunk] = r
        return r

    def read(self, n=1000000000):
        parts = []
        while n > 0 and self.offset < self.size():
            chunk = self.offset // self.header.blockSize
            start = self.offset % self.header.blockSize
            end = start + n
            end = min(end, self.size() - chunk * self.header.blockSize)
            end = min(end, self.header.blockSize)
            assert end >= 0

            d = self.read_chunk(chunk)[start:end]
            parts.append(d)

            self.offset += len(d)
            n -= len(d)

        return ''.join(parts)


UDIFChecksum = construct.Struct("UDIFChecksum",
    construct.UBInt32("type"),
    construct.UBInt32("size"),
    construct.Array(32, construct.UBInt32("data")))

UDIFResourceFile = construct.Struct("UDIFResourceFile",
    construct.Magic("koly"), #fUDIFSignature,
    construct.UBInt32("fUDIFVersion"),
    construct.UBInt32("fUDIFHeaderSize"),
    construct.UBInt32("fUDIFFlags"),
    
    construct.UBInt64("fUDIFRunningDataForkOffset"),
    construct.UBInt64("fUDIFDataForkOffset"),
    construct.UBInt64("fUDIFDataForkLength"),
    construct.UBInt64("fUDIFRsrcForkOffset"),
    construct.UBInt64("fUDIFRsrcForkLength"),
    
    construct.UBInt32("fUDIFSegmentNumber"),
    construct.UBInt32("fUDIFSegmentCount"),
    construct.Array(4, construct.UBInt32("fUDIFSegmentID")),
    
    construct.Rename("fUDIFDataForkChecksum", UDIFChecksum),
    
    construct.UBInt64("fUDIFXMLOffset"), # 0xd8
    construct.UBInt64("fUDIFXMLLength"),
    
    construct.Padding(0x78),
    
    construct.Rename("fUDIFMasterChecksum", UDIFChecksum),
    
    construct.UBInt32("fUDIFImageVariant"),
    construct.UBInt64("fUDIFSectorCount"),
    
    construct.UBInt32("_reserved2"),
    construct.UBInt32("_reserved3"),
    construct.UBInt32("_reserved4"),)

BLKXRun = construct.Struct("BLKXRun",
    construct.UBInt32("type"),
    construct.UBInt32("_reserved"),
    construct.UBInt64("sectorStart"),
    construct.UBInt64("sectorCount"),
    construct.UBInt64("compOffset"),
    construct.UBInt64("compLength"))

BLKXTable = construct.Struct("BLKXTable",
    construct.Magic("mish"), #fUDIFBlocksSignature
    construct.UBInt32("infoVersion"),
    construct.UBInt64("firstSectorNumber"),
    construct.UBInt64("sectorCount"),
    
    construct.UBInt64("dataStart"),
    construct.UBInt32("decompressBufferRequested"),
    construct.UBInt32("blocksDescriptor"),
    
    construct.UBInt32("_reserved1"),
    construct.UBInt32("_reserved2"),
    construct.UBInt32("_reserved3"),
    construct.UBInt32("_reserved4"),
    construct.UBInt32("_reserved5"),
    construct.UBInt32("_reserved6"),

    UDIFChecksum,

    construct.UBInt32("blocksRunCount"),
    construct.Array(lambda ctx: ctx.blocksRunCount, construct.Rename("runs", BLKXRun)),
    #construct.Terminator
    )


BLOCK_ZLIB = 0x80000005
BLOCK_RAW = 0x00000001
BLOCK_IGNORE = 0x00000002
BLOCK_COMMENT = 0x7FFFFFFE
BLOCK_TERMINATOR = 0xFFFFFFFF

SECTOR_SIZE = 512

class DMG(BaseFile):
    def __init__(self, f):
        BaseFile.__init__(self)

        self.f = f

        self.f.seek(-UDIFResourceFile.sizeof(), 2)
        udif = UDIFResourceFile.parse_stream(self.f)
        assert udif.fUDIFVersion == 4
        assert udif.fUDIFDataForkOffset == 0
        # print udif

        self.f.seek(udif.fUDIFXMLOffset)
        resource_xml_data = self.f.read(udif.fUDIFXMLLength)

        resource_xml = plistlib.readPlistFromString(resource_xml_data)

        blks = resource_xml['resource-fork']['blkx']

        hfs_blk = filter(lambda b: 'Apple_HFSX' in b['Name'], blks)[0]
        hfs_blk_table = BLKXTable.parse(hfs_blk['Data'].data)
        # print hfs_blk_table

        self.sector_count = hfs_blk_table.sectorCount
        self.data_start = hfs_blk_table.dataStart
        self.runs = hfs_blk_table.runs

        self.run_cache = {}

    def size(self):
        return self.sector_count * SECTOR_SIZE

    def read_run(self, i):
        if i in self.run_cache: return self.run_cache[i]

        run = self.runs[i]
        
        if run.type == BLOCK_RAW:
            self.f.seek(self.data_start + run.compOffset)
            r = self.f.read(run.compLength)
        elif run.type == BLOCK_ZLIB:
            self.f.seek(self.data_start + run.compOffset)
            d = self.f.read(run.compLength)
            r = zlib.decompress(d)
            assert len(r) == run.sectorCount * SECTOR_SIZE
        elif run.type == BLOCK_IGNORE:
            r = ''
        else:
            assert False

        self.run_cache[i] = r
        return r

    def read(self, n=1000000000):
        parts = []
        while n > 0 and self.offset < self.size():

            for i, r in enumerate(self.runs):
                if r.type not in (BLOCK_IGNORE, BLOCK_RAW, BLOCK_ZLIB): continue
                if (r.sectorStart * SECTOR_SIZE
                    <= self.offset < (r.sectorStart+r.sectorCount) * SECTOR_SIZE):
                    break
            else:
                assert False

            start = self.offset - r.sectorStart * SECTOR_SIZE
            end = (self.offset + n) - r.sectorStart * SECTOR_SIZE
            end = min(end, r.sectorCount * SECTOR_SIZE)

            d = self.read_run(i)[start:end].ljust(end-start, "\x00")
            parts.append(d)

            self.offset += len(d)
            n -= len(d)

        return ''.join(parts)


def download_file(url, out):
    file_name = url.split('/')[-1]
    with open(out, 'wb') as f:
        start = time.time()
        response = requests.get(url, stream=True)
        total_length = response.headers.get('content-length')

        dl = 0
        total_length = int(total_length)
        for data in response.iter_content(chunk_size=128*1024):
            dl += len(data)
            f.write(data)
            done = int(50 * dl / total_length)
            sys.stdout.write("\r[%s%s] %d kB/s" % (
                '=' * done, ' ' * (50-done),
                dl / (time.time() - start) / 1024))
            sys.stdout.flush()
    print

def main():
    print "Looking up key..."
    key_resp = requests.get('https://ipsw.me/keys/AppleTV2,1/9A334v',
            headers={'User-Agent': 'get_airtunesd.py'},
            verify=False)
    key_html = key_resp.content
    key_soup = BeautifulSoup(key_html)
    key_row = key_soup.find("td", text="RootFileSystem").parent
    key_cell = key_row.find("td", "key")
    key_text = key_cell.text
    root_key = key_text.decode("hex")
    print "Done!", key_text

    ipsw_filename = "AppleTV2,1_4.4_9A334v_Restore.ipsw"
    ipsw_url = "http://appldnld.apple.com/AppleTV/061-9621.20111012.Vgijx/AppleTV2,1_4.4_9A334v_Restore.ipsw"

    tmpdir = tempfile.mkdtemp()
    try:
        print
        print "Downloading %s..." % ipsw_filename
        ipsw_path = os.path.join(tmpdir, ipsw_filename)
        download_file(ipsw_url, ipsw_path)
        assert os.path.exists(ipsw_path)
        print "Done!", ipsw_path

        ipsw = zipfile.ZipFile(ipsw_path, 'r')
        manifest = plistlib.readPlist(ipsw.open("BuildManifest.plist"))

        root_filename = manifest["BuildIdentities"][0]["Manifest"]["OS"]["Info"]["Path"]

        print
        print "Extracting %s..." % root_filename
        ipsw.extract(root_filename, tmpdir)
        root_path = os.path.join(tmpdir, root_filename)
        print "Done!", root_path

        print
        print "Extracting airtunesd..."
        with open(root_path, "rb") as root:
            root_fv = FileVaultFile(root, root_key)
            dmg = DMG(root_fv)
            volume = hfs.HFSVolume(dmg)
            volume.readFile("/usr/libexec/airtunesd")

        assert os.path.exists("airtunesd")
        print "Done!"
    finally:
        shutil.rmtree(tmpdir)


if __name__ == "__main__":
    main()
