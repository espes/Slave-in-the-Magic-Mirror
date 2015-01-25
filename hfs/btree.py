# btree.py
#
# Adapted from iphone-dataprotection
#
# Licensed under GPL Version 3 or later
#

import cStringIO
from structs import *
from fastunicode import FastUnicodeCompare

"""
Probably buggy
HAX, should work on case sensitive/insensitive volumes
"""

class BTree(object):
    def __init__(self, file, keyStruct, dataStruct):
        self.file = file
        self.keyStruct = keyStruct
        self.dataStruct = dataStruct
        block0 = self.file.readBlock(0)
        btnode = BTNodeDescriptor.parse(block0)
        assert btnode.kind == kBTHeaderNode
        self.header = BTHeaderRec.parse(block0[BTNodeDescriptor.sizeof():])
        #TODO: do more testing when nodeSize != blockSize
        self.nodeSize = self.header.nodeSize
        self.nodesInBlock = file.blockSize / self.header.nodeSize
        self.blocksForNode = self.header.nodeSize / file.blockSize
        #print file.blockSize , self.header.nodeSize
        self.lastRecordNumber = 0
        type, (hdr, maprec) = self.readBtreeNode(0)
        assert len(maprec) == self.nodeSize - 256
        if self.header.totalNodes / 8 > len(maprec):
            pass #TODO: handle map records
        self.maprec = maprec

    def isNodeInUse(self, nodeNumber):
        thisByte = ord(self.maprec[nodeNumber / 8])
        return (thisByte & (1 << (7 - (nodeNumber % 8)))) != 0
    
    def readEmptySpace(self):
        res = ""
        z = 0
        for i in xrange(self.header.totalNodes):
            if not self.isNodeInUse(i):
                z += 1
                res += self.readNode(i)
        assert z == self.header.freeNodes
        return res
    
    #convert construct structure to tuple
    def getComparableKey(self, k):
        raise Exception("implement in subclass")
    
    def compareKeys(self, k1, k2):
        k2 = self.getComparableKey(k2) 
        if k1 == k2:
            return 0
        return -1 if k1 < k2 else 1
    
    def printLeaf(self, key, data):
        print key, data

    def readNode(self, nodeNumber):
        node = ""
        for i in xrange(self.blocksForNode):
            node += self.file.readBlock(nodeNumber * self.blocksForNode + i)
        return node
    
    def readBtreeNode(self, nodeNumber):
        self.lastnodeNumber = nodeNumber
        node = self.readNode(nodeNumber)
        self.lastbtnode = btnode = BTNodeDescriptor.parse(node)

        if btnode.kind == kBTHeaderNode:
            assert btnode.numRecords == 3
            end = self.nodeSize - 8 #2*4
            offsets = Array(btnode.numRecords+1, UBInt16("off")).parse(node[end:])
            assert offsets[-4] == end
            hdr = BTHeaderRec.parse(node[BTNodeDescriptor.sizeof():])
            maprec = node[offsets[-3]:end]
            return kBTHeaderNode, [hdr, maprec]
        elif btnode.kind == kBTIndexNode:
            recs = []
            offsets = Array(btnode.numRecords, UBInt16("off")).parse(node[-2*btnode.numRecords:])
            for i in xrange(btnode.numRecords):
                off = offsets[btnode.numRecords-i-1]
                k = self.keyStruct.parse(node[off:])
                off += 2 + k.keyLength
                k.childNode = UBInt32("nodeNumber").parse(node[off:off+4])
                recs.append(k)
            return kBTIndexNode, recs
        elif btnode.kind == kBTLeafNode:
            recs = []
            offsets = Array(btnode.numRecords, UBInt16("off")).parse(node[-2*btnode.numRecords:])
            for i in xrange(btnode.numRecords):
                off = offsets[btnode.numRecords-i-1]
                k = self.keyStruct.parse(node[off:])
                off += 2 + k.keyLength
                d = self.dataStruct.parse(node[off:])
                recs.append((k,d))
            return kBTLeafNode, recs
        else:
            raise Exception("Invalid node type " + str(btnode)) 

    def search(self, searchKey, node=None):
        if node == None:
            node = self.header.rootNode
            
        type, stuff = self.readBtreeNode(node)
        if len(stuff) == 0:
            return None, None
        
        if type == kBTIndexNode: 
            for i in xrange(len(stuff)):
                if self.compareKeys(searchKey, stuff[i]) < 0:
                    if i > 0:
                        i = i - 1
                    return self.search(searchKey, stuff[i].childNode)
            return self.search(searchKey, stuff[len(stuff)-1].childNode)
        elif type == kBTLeafNode:
            self.lastRecordNumber = 0
            for k,v in stuff:
                res = self.compareKeys(searchKey, k)
                if res == 0:
                    return k, v
                if res < 0:
                    return None, None
                self.lastRecordNumber += 1
        return None, None

    def traverse(self, node=None, count=0, callback=None):
        if node == None:
            node = self.header.rootNode
   
        type, stuff = self.readBtreeNode(node)
        
        if type == kBTIndexNode: 
            for i in xrange(len(stuff)):
                count += self.traverse(stuff[i].childNode, callback=callback)
        elif type == kBTLeafNode:
            for k,v in stuff:
                if callback:
                    callback(k,v)
                else:
                    self.printLeaf(k, v)
                count += 1
        return count
    
    def traverseLeafNodes(self, callback=None):
        nodeNumber = self.header.firstLeafNode
        count = 0
        while nodeNumber != 0:
            _, stuff = self.readBtreeNode(nodeNumber)
            lastbtnode = self.lastbtnode
            count += len(stuff)
            for k,v in stuff:
                if callback:
                    callback(k,v) #XXX callback might modify self.lastbtnode
                else:
                    self.printLeaf(k, v)
            nodeNumber = lastbtnode.fLink
        return count
    
    #XXX
    def searchMultiple(self, searchKey, filterKeyFunction=lambda x:False):
        self.search(searchKey)
        nodeNumber = self.lastnodeNumber
        recordNumber = self.lastRecordNumber
        kv = []
        while nodeNumber != 0:
            _, stuff = self.readBtreeNode(nodeNumber)
            for k,v in stuff[recordNumber:]:
                if filterKeyFunction(k):
                    kv.append((k,v))
                else:
                    return kv
            nodeNumber = self.lastbtnode.fLink
            recordNumber = 0
        return kv

    def getLBAsHax(self):
        nodes = [self.lastnodeNumber]
        n = self.lastbtnode
        for i in xrange(2):
            nodes.append(self.lastbtnode.bLink)
            self.readBtreeNode(self.lastbtnode.bLink)
        self.lastbtnode = n
        for i in xrange(2):
            nodes.append(self.lastbtnode.fLink)
            self.readBtreeNode(self.lastbtnode.fLink)
        res = []
        for n in nodes:
            res.append(self.file.getLBAforBlock(n * self.blocksForNode))
        return res
        
class CatalogTree(BTree):
    def __init__(self, file, volume):
        super(CatalogTree,self).__init__(file, HFSPlusCatalogKey, HFSPlusCatalogData)
        self.volume = volume
        if self.header.keyCompareType == kHFSCaseFolding:
            print "CatalogTree: Using case insensitive compare"
            self.compareKeys = self.compareKeysCaseInSensitive
    
    def printLeaf(self, k, d):
        if d.recordType == kHFSPlusFolderRecord or d.recordType == kHFSPlusFileRecord:
            print getString(k)
   
    def getComparableKey(self, k2):
        #XXX http://dubeiko.com/development/FileSystems/HFSPLUS/tn1150.html#StringComparisonAlgorithm
        return (k2.parentID, getString(k2))
    
    def compareKeysCaseInSensitive(self, k1, k2):
        k2 = self.getComparableKey(k2)
        if k1[0] != k2[0]:
            return -1 if k1[0] < k2[0] else 1
        return FastUnicodeCompare(k1[1], k2[1])

    def searchByCNID(self, cnid):
        threadk, threadd = self.search((cnid, ""))
        return self.search((threadd.data.parentID, getString(threadd.data))) if threadd else (None, None)
    
    def getFolderContents(self, cnid):
        return self.searchMultiple((cnid, ""), lambda k:k.parentID == cnid)
    
    def getRecordFromPath(self, path):
        if not path.startswith("/"):
            return None, None
        if path == "/":
            return self.searchByCNID(kHFSRootFolderID)
        parentId=kHFSRootFolderID
        i = 1
        k, v = None, None
        for p in path.split("/")[1:]:
            if p == "":
                break
            k,v  = self.search((parentId, p))
            if (k,v) == (None, None):
                return None, None

            if v.recordType == kHFSPlusFolderRecord:
                parentId = v.data.folderID
            elif v.recordType == kHFSPlusFileRecord:
                if is_symlink(v.data):
                    sio = cStringIO.StringIO()
                    self.volume.readFileByRecord(k, v, sio)
                    linkdata = sio.getvalue()
                    print "symlink %s => %s" % (p, linkdata)
                    if not linkdata:
                        return None, None
                    t = path.split("/")
                    t[i] = linkdata
                    newpath = "/".join(t)
                    return self.getRecordFromPath(newpath)
                elif is_hardlink(v.data):
                    print "hardlink => iNode%d" % v.data.HFSPlusBSDInfo.special.iNodeNum
                    return self.getRecordFromPath("/\x00\x00\x00\x00HFS+ Private Data/iNode%d" % v.data.HFSPlusBSDInfo.special.iNodeNum)
                break
            i += 1
        return k,v
    
class ExtentsOverflowTree(BTree):
    def __init__(self, file):
        super(ExtentsOverflowTree,self).__init__(file, HFSPlusExtentKey, HFSPlusExtentRecord)
    
    def getComparableKey(self, k2):
        return (k2.fileID, k2.forkType, k2.startBlock)
    
    def searchExtents(self, fileID, forkType, startBlock):
        return self.search((fileID, forkType, startBlock))

class AttributesTree(BTree):
    def __init__(self, file):
        super(AttributesTree,self).__init__(file, HFSPlusAttrKey, HFSPlusAttrData)
    
    def printLeaf(self, k, d):
        print k.fileID, getString(k), d.data.encode("hex")
    
    def getComparableKey(self, k2):
        return (k2.fileID, getString(k2))
    
    def searchXattr(self, fileID, name):
        k,v = self.search((fileID, name))
        return v.data if v else None
    
    def getAllXattrs(self, fileID):
        res = {}
        for k,v in self.searchMultiple((fileID, ""), lambda k:k.fileID == fileID):
            res[getString(k)] = v.data
        return res
