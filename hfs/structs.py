# structs.py
#
# Adapted from iphone-dataprotection
#
# Licensed under GPL Version 3 or later
#

from construct import *
"""
http://developer.apple.com/library/mac/#technotes/tn/tn1150.html
"""

def getString(obj):
    return obj.HFSUniStr255.unicode

S_IFLNK  = 0120000
kSymLinkFileType  = 0x736C6E6B
kSymLinkCreator   = 0x72686170
kHardLinkFileType = 0x686C6E6B
kHFSPlusCreator   = 0x6866732B

kHFSCaseFolding = 0xCF
kHFSBinaryCompare = 0xBC


def is_symlink(rec):
    return rec.FileInfo.fileCreator == kSymLinkCreator and rec.FileInfo.fileType == kSymLinkFileType

def is_hardlink(rec):
    return rec.FileInfo.fileCreator == kHFSPlusCreator and rec.FileInfo.fileType == kHardLinkFileType

kHFSRootParentID            = 1
kHFSRootFolderID            = 2
kHFSExtentsFileID           = 3
kHFSCatalogFileID           = 4
kHFSBadBlockFileID          = 5
kHFSAllocationFileID        = 6
kHFSStartupFileID           = 7
kHFSAttributesFileID        = 8
kHFSRepairCatalogFileID     = 14
kHFSBogusExtentFileID       = 15
kHFSFirstUserCatalogNodeID  = 16

kBTLeafNode       = -1
kBTIndexNode      =  0
kBTHeaderNode     =  1
kBTMapNode        =  2

kHFSPlusFolderRecord        = 0x0001
kHFSPlusFileRecord          = 0x0002
kHFSPlusFolderThreadRecord  = 0x0003
kHFSPlusFileThreadRecord    = 0x0004

kHFSPlusAttrInlineData  = 0x10
kHFSPlusAttrForkData    = 0x20
kHFSPlusAttrExtents     = 0x30

kForkTypeData = 0
kForkTypeRsrc = 0xFF

kHFSVolumeHardwareLockBit       =  7
kHFSVolumeUnmountedBit          =  8
kHFSVolumeSparedBlocksBit       =  9
kHFSVolumeNoCacheRequiredBit    = 10
kHFSBootVolumeInconsistentBit   = 11
kHFSCatalogNodeIDsReusedBit     = 12
kHFSVolumeJournaledBit          = 13
kHFSVolumeSoftwareLockBit       = 15

DECMPFS_MAGIC = 0x636d7066  #cmpf

HFSPlusExtentDescriptor = Struct("HFSPlusExtentDescriptor",
    UBInt32("startBlock"),
    UBInt32("blockCount")
)
HFSPlusExtentRecord = Array(8,HFSPlusExtentDescriptor)

HFSPlusForkData = Struct("HFSPlusForkData",
    UBInt64("logicalSize"),
    UBInt32("clumpSize"),
    UBInt32("totalBlocks"),
    Array(8, HFSPlusExtentDescriptor)
)

HFSPlusVolumeHeader= Struct("HFSPlusVolumeHeader",
    UBInt16("signature"),
    UBInt16("version"),
    UBInt32("attributes"),
    UBInt32("lastMountedVersion"),
    UBInt32("journalInfoBlock"),
    UBInt32("createDate"),
    UBInt32("modifyDate"),
    UBInt32("backupDate"),
    UBInt32("checkedDate"),
    UBInt32("fileCount"),
    UBInt32("folderCount"),
    UBInt32("blockSize"),
    UBInt32("totalBlocks"),
    UBInt32("freeBlocks"),
    UBInt32("nextAllocation"),
    UBInt32("rsrcClumpSize"),
    UBInt32("dataClumpSize"),
    UBInt32("nextCatalogID"),
    UBInt32("writeCount"),
    UBInt64("encodingsBitmap"),
    
    Array(8, UBInt32("finderInfo")),
 
    Struct("allocationFile", Embed(HFSPlusForkData)),
    Struct("extentsFile", Embed(HFSPlusForkData)),
    Struct("catalogFile", Embed(HFSPlusForkData)),
    Struct("attributesFile", Embed(HFSPlusForkData)),
    Struct("startupFile", Embed(HFSPlusForkData)),
)

BTNodeDescriptor = Struct("BTNodeDescriptor",
    UBInt32("fLink"),
    UBInt32("bLink"),
    SBInt8("kind"),
    UBInt8("height"),
    UBInt16("numRecords"),
    UBInt16("reserved")
)

BTHeaderRec = Struct("BTHeaderRec",
    UBInt16("treeDepth"),
    UBInt32("rootNode"),
    UBInt32("leafRecords"),
    UBInt32("firstLeafNode"),
    UBInt32("lastLeafNode"),
    UBInt16("nodeSize"),
    UBInt16("maxKeyLength"),
    UBInt32("totalNodes"),
    UBInt32("freeNodes"),
    UBInt16("reserved1"),
    UBInt32("clumpSize"),
    UBInt8("btreeType"),
    UBInt8("keyCompareType"),
    UBInt32("attributes"),
    Array(16, UBInt32("reserved3"))
)

HFSUniStr255 = Struct("HFSUniStr255",
    UBInt16("length"),
    String("unicode", lambda ctx: ctx["length"] * 2, encoding="utf-16-be")
)

HFSPlusAttrKey = Struct("HFSPlusAttrKey",
    UBInt16("keyLength"),
    UBInt16("pad"),
    UBInt32("fileID"),
    UBInt32("startBlock"),
    HFSUniStr255,
    #UBInt32("nodeNumber")
)

HFSPlusAttrData = Struct("HFSPlusAttrData",
    UBInt32("recordType"),
    Array(2, UBInt32("reserved")),
    UBInt32("size"),
    MetaField("data", lambda ctx: ctx["size"])
)

HFSPlusCatalogKey = Struct("HFSPlusCatalogKey",
    UBInt16("keyLength"),
    UBInt32("parentID"),
    HFSUniStr255
)

HFSPlusBSDInfo = Struct("HFSPlusBSDInfo",
    UBInt32("ownerID"),
    UBInt32("groupID"),
    UBInt8("adminFlags"),
    UBInt8("ownerFlags"),
    UBInt16("fileMode"),
    Union("special",
          UBInt32("iNodeNum"),
          UBInt32("linkCount"),
          UBInt32("rawDevice"),
          )
)

Point = Struct("Point",
    SBInt16("v"),
    SBInt16("h")
)
Rect = Struct("Rect",
    SBInt16("top"),
    SBInt16("left"),
    SBInt16("bottom"),
    SBInt16("right")
)
FileInfo = Struct("FileInfo",
    UBInt32("fileType"),
    UBInt32("fileCreator"),
    UBInt16("finderFlags"),
    Point,
    UBInt16("reservedField")
)
ExtendedFileInfo = Struct("ExtendedFileInfo",
    Array(4, SBInt16("reserved1")),
    UBInt16("extendedFinderFlags"),
    SBInt16("reserved2"),
    SBInt32("putAwayFolderID")
)

FolderInfo = Struct("FolderInfo",
    Rect,
    UBInt16("finderFlags"),
    Point,
    UBInt16("reservedField")
)

ExtendedFolderInfo = Struct("ExtendedFolderInfo", 
    Point,
    SBInt32("reserved1"),
    UBInt16("extendedFinderFlags"),
    SBInt16("reserved2"),
    SBInt32("putAwayFolderID")
)

HFSPlusCatalogFolder = Struct("HFSPlusCatalogFolder",
    UBInt16("flags"),
    UBInt32("valence"),
    UBInt32("folderID"),
    UBInt32("createDate"),
    UBInt32("contentModDate"),
    UBInt32("attributeModDate"),
    UBInt32("accessDate"),
    UBInt32("backupDate"),
    HFSPlusBSDInfo,
    FolderInfo,
    ExtendedFolderInfo,
    UBInt32("textEncoding"),
    UBInt32("reserved")
)

HFSPlusCatalogFile = Struct("HFSPlusCatalogFile",
    UBInt16("flags"),
    UBInt32("reserved1"),
    UBInt32("fileID"),
    UBInt32("createDate"),
    UBInt32("contentModDate"),
    UBInt32("attributeModDate"),
    UBInt32("accessDate"),
    UBInt32("backupDate"),
    HFSPlusBSDInfo,
    FileInfo,
    ExtendedFileInfo,
    UBInt32("textEncoding"),
    UBInt32("reserved2"),
    Struct("dataFork", Embed(HFSPlusForkData)),
    Struct("resourceFork", Embed(HFSPlusForkData))
)

HFSPlusCatalogThread = Struct("HFSPlusCatalogThread",
    SBInt16("reserved"),
    UBInt32("parentID"),
    HFSUniStr255,
)

HFSPlusCatalogData = Struct("HFSPlusCatalogData",
    UBInt16("recordType"),
    Switch("data", lambda ctx: ctx["recordType"],
    {
        kHFSPlusFolderRecord : HFSPlusCatalogFolder,
        kHFSPlusFileRecord : HFSPlusCatalogFile,
        kHFSPlusFolderThreadRecord: HFSPlusCatalogThread,
        kHFSPlusFileThreadRecord: HFSPlusCatalogThread
    },
    default=HFSPlusCatalogFolder #XXX: should not reach
    )
)

HFSPlusExtentKey = Struct("HFSPlusExtentKey",
    UBInt16("keyLength"),
    UBInt8("forkType"),
    UBInt8("pad"),
    UBInt32("fileID"),
    UBInt32("startBlock")
)

HFSPlusDecmpfs  = Struct("HFSPlusDecmpfs ",
   ULInt32("compression_magic"),
   ULInt32("compression_type"),
   ULInt64("uncompressed_size"),
)

HFSPlusCmpfRsrcHead = Struct("HFSPlusCmpfRsrcHead",
    UBInt32("headerSize"),
    UBInt32("totalSize"),
    UBInt32("dataSize"),
    UBInt32("flags")
)

HFSPlusCmpfRsrcBlock = Struct("HFSPlusCmpfRsrcBlock",
    ULInt32("offset"),
    ULInt32("size")
)

HFSPlusCmpfRsrcBlockHead = Struct("HFSPlusCmpfRsrcBlockHead",
    UBInt32("dataSize"),
    ULInt32("numBlocks"),
    Array(lambda ctx:ctx["numBlocks"], HFSPlusCmpfRsrcBlock)
)

HFSPlusCmpfEnd = Struct("HFSPlusCmpfEnd",
    Array(6, UBInt32("pad")),
    UBInt16("unk1"),
    UBInt16("unk2"),
    UBInt16("unk3"),
    UBInt32("magic"),
    UBInt32("flags"),
    UBInt64("size"),
    UBInt32("unk4")
)


"""
Journal stuff
"""
JournalInfoBlock = Struct("JournalInfoBlock",
    UBInt32("flags"),
    Array(8, UBInt32("device_signature")),
    UBInt64("offset"),
    UBInt64("size"),
    Array(32, UBInt32("reserved"))
)

journal_header = Struct("journal_header",
    ULInt32("magic"),
    ULInt32("endian"),
    ULInt64("start"),
    ULInt64("end"),
    ULInt64("size"),
    ULInt32("blhdr_size"),
    ULInt32("checksum"),
    ULInt32("jhdr_size")
)

block_info = Struct("block_info",
    ULInt64("bnum"),
    ULInt32("bsize"),
    ULInt32("next")
)

block_list_header = Struct("block_list_header",
    ULInt16("max_blocks"),
    ULInt16("num_blocks"),
    ULInt32("bytes_used"),
    SLInt32("checksum"),
    UBInt32("pad"),
    Array(lambda ctx:ctx["num_blocks"], block_info)
)
