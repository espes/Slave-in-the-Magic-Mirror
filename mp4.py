# mp4.py
#
# Copyright 2015, espes
#
# Licensed under GPL Version 2 or later
#

import struct
from construct import *

from construct_utils import *
import aac

# ISO/IEC 14496-1:2010
# Coding of audio-visual objects - Part 1: Systems

# 8.3.3
class InstanceLengthAdapter(Adapter):
    def _encode(self, obj, context):
        if obj >= 128:
            raise NotImplemented
        return [0x80, 0x80, 0x80, obj]
    def _decode(self, obj, context):
        size = 0
        for v in obj:
            size <<= 7
            size |= v & 0b1111111
        return size
InstanceLength = InstanceLengthAdapter(
    RepeatUntil(lambda obj, ctx: (obj >> 7) == 0,
        UBInt8("sizeOfInstance")))

# 7.2.6.14.3.4
def ByteArray(name):
    return Struct(name,
        InstanceLength,
        String("data", this.sizeOfInstance))

def ExpandableTag(name, tags, *subcons):
    tagcons = UBInt8("tag")
    if isinstance(tags, int):
        tagcons = Const(tagcons, tags)
    elif tags is not None:
        tagcons = OneOf(tagcons, tags)

    if subcons:
        datacons = Embed(TunnelAdapter(
            Field("data", this.sizeOfInstance),
            Struct(None, *subcons)))
    else:
        datacons = String("data", this.sizeOfInstance)

    return Struct(name,
        tagcons,
        InstanceLength,
        datacons)

# 7.2.2.2
def BaseDescriptor(name, tags, *subcons):
    return ExpandableTag(name, tags, *subcons)

# 7.2.6.3
MP4_OD_Tag = 0x11
ObjectDescrTag = 0x01
ObjectDescriptor_data = Struct(None,
    EmbeddedBitStruct(
        Bits("ObjectDescriptorID", 10),
        Flag("URL_Flag"),
        Padding(5)), # reserved
    Embed(IfThenElse(None, this.URL_Flag,
        PascalString("URLstring", UBInt8("URLlength")),
        Struct(None,
            Range(1, 255, LazyBound("esDescr", lambda: ES_Descriptor)),
            Range(0, 255, LazyBound("ociDescr", lambda: OCI_Descriptor)),
            Range(0, 255, LazyBound("ipmpDescrPtr", lambda: IPMP_DescriptorPointer)),
            Range(0, 255, LazyBound("ipmpDescr", lambda: IPMP_Descriptor))))),
    Range(0, 255, LazyBound("extDescr", lambda: ExtensionDescriptor)))

ObjectDescriptor = BaseDescriptor("OD", ObjectDescrTag,
    Embed(ObjectDescriptor_data))

# 7.2.6.4
MP4_IOD_Tag = 0x10
InitialObjectDescrTag = 0x2
InitialObjectDescriptor_data = Struct(None,
    EmbeddedBitStruct(
        Bits("ObjectDescriptorID", 10),
        Flag("URL_Flag"),
        Flag("includeInlineProfileLevelFlag"),
        Padding(4)), # reserved
    Embed(IfThenElse(None, this.URL_Flag,
        PascalString("URLstring", UBInt8("URLlength")),
        Struct(None,
            UBInt8("ODProfileLevelIndication"),
            UBInt8("sceneProfileLevelIndication"),
            UBInt8("audioProfileLevelIndication"),
            UBInt8("visualProfileLevelIndication"),
            UBInt8("graphicsProfileLevelIndication"),
            Range(0, 255, LazyBound("esDescr", lambda: ES_Descriptor)), # should be [1...255]??
            Range(0, 255, LazyBound("ociDescr", lambda: OCI_Descriptor)),
            Range(0, 255, LazyBound("ipmpDescrPtr", lambda: IPMP_DescriptorPointer)),
            Range(0, 255, LazyBound("ipmpDescr", lambda: IPMP_Descriptor)),
            Range(0, 255, LazyBound("toolListDescr", lambda: IPMP_ToolListDescriptor))))),
    Range(0, 255, LazyBound("extDescr", lambda: ExtensionDescriptor)))

InitialObjectDescriptor = BaseDescriptor("IOD", InitialObjectDescrTag,
    Embed(InitialObjectDescriptor_data))

# 7.2.6
ObjectDescriptorBase = BaseDescriptor("OD", (ObjectDescrTag, InitialObjectDescrTag),
    Embed(Switch("OD", this.tag,
        { ObjectDescrTag: ObjectDescriptor_data,
          InitialObjectDescrTag: InitialObjectDescriptor_data }, default=Bork())))

MP4_ObjectDescriptorBase = BaseDescriptor("OD", (MP4_OD_Tag, MP4_IOD_Tag),
    Embed(Switch("OD", this.tag,
        { MP4_OD_Tag: ObjectDescriptor_data,
          MP4_IOD_Tag: InitialObjectDescriptor_data }, default=Bork())))

# 7.2.6.9
ContentIdentDescrTag = 0x07
SupplContentIdentDescrTag = 0x08
IP_IdentificationDataSet = BaseDescriptor("ipIDS",
    range(ContentIdentDescrTag, SupplContentIdentDescrTag+1))

# 7.2.6.12
IPI_DescrPointerTag = 0x09
IPI_DescrPointer = BaseDescriptor("ipiPtr", IPI_DescrPointerTag,
    UBInt16("IPI_ES_Id"))

# 7.2.6.13
IPMP_DescrPtrTag = 0x0a
IPMP_DescriptorPointer = BaseDescriptor("ipmpDesrPtr", IPMP_DescrPtrTag)

# 7.2.6.14
IPMP_DescrTag = 0x0b
IPMP_Descriptor = BaseDescriptor("ipmpDescr", IPMP_DescrTag)

# 7.2.6.14.3.2
IPMP_ToolTag = 0x61
IPMP_Tool = BaseDescriptor("ipmpTool", IPMP_ToolTag)

# 7.2.6.14.3
IPMP_ToolsListDescrTag = 0x60
IPMP_ToolListDescriptor = BaseDescriptor("toolListDescr", IPMP_ToolsListDescrTag,
    Range(0, 255, IPMP_Tool))

# 7.2.6.15
QoS_DescrTag = 0x0c
QoS_Descriptor = BaseDescriptor("qosDescr", QoS_DescrTag)

# 7.2.6.16
ExtDescrTagStartRange = 0x6a
ExtDescrTagEndRange = 0xfe
ExtensionDescriptor = BaseDescriptor("extDescr",
    range(ExtDescrTagStartRange, ExtDescrTagEndRange+1))

# 7.2.6.17
RegistrationDescrTag = 0x0d
RegistrationDescriptor = BaseDescriptor("regDescr", RegistrationDescrTag)

# 7.2.6.18
OCIDescrTagStartRange = 0x40
OCIDescrTagEndRange = 0x5f
OCI_Descriptor = BaseDescriptor("ociDescr",
    range(OCIDescrTagStartRange, OCIDescrTagEndRange+1))

# 7.2.6.18.6
LanguageDescrTag = 0x43
LanguageDescriptor = BaseDescriptor("langDescr", LanguageDescrTag,
    Array(3, UBInt8("languageCode")))

# 7.2.6.20
DecSpecificInfoTag = 0x05
def DecoderSpecificInfo(objectTypeFunc=None):
    if objectTypeFunc is None:
        return BaseDescriptor("decSpecificInfo", DecSpecificInfoTag)

    return BaseDescriptor("decSpecificInfo", DecSpecificInfoTag,
        Switch("data", lambda ctx: objectTypeFunc(ctx._), {
            0x40: aac.AudioSpecificConfig_bytes,
        }, default=String("data", this.sizeOfInstance)))

# 7.2.6.20
ProfileLevelIndicationIndexDescrTag = 0x14
ProfileLevelIndicationIndexDescriptor = BaseDescriptor(
    "profileLevelIndicationIndexDescriptor", ProfileLevelIndicationIndexDescrTag,
    UBInt8("profileLevelIndicationIndex"))

# 7.2.6.6
DecoderConfigDescrTag = 0x04
DecoderConfigDescriptor = BaseDescriptor("decoderConfigDescr", DecoderConfigDescrTag,
    EmbeddedBitStruct(
        Bits("objectTypeIndication", 8),
        Bits("streamType", 6),
        Bits("upStream", 1),
        Padding(1), #reserved
        Bits("bufferSizeDB", 24)),
    UBInt32("maxBitrate"),
    UBInt32("avgBitrate"),
    Optional(DecoderSpecificInfo(this.objectTypeIndication)),
    Range(0, 255, ProfileLevelIndicationIndexDescriptor))

# 7.3.2.3
SLConfigDescrTag = 0x06
SLConfigDescriptor = BaseDescriptor("slConfigDescr", SLConfigDescrTag,
    UBInt8("predefined"),
    If(lambda ctx: ctx.predefined == 0,
        Embed(Struct(None,
            EmbeddedBitStruct(
                Flag("useAccessUnitStartFlag"),
                Flag("useAccessUnitEndFlag"),
                Flag("useRandomAccessPointFlag"),
                Flag("hasRandomAccessUnitsOnlyFlag"),
                Flag("usePaddingFlag"),
                Flag("useTimeStampsFlag"),
                Flag("useIdleFlag"),
                Flag("durationFlag"),
                Bits("timeStampResolution", 32),
                Bits("OCRResolution", 32),
                Bits("timeStampLength", 8),
                Bits("OCRLength", 8),
                Bits("AU_Length", 8),
                Bits("instantBitrateLength", 8),
                Bits("degredationPriorityLength", 4),
                Bits("AU_seqNumLength", 5),
                Bits("packetSeqNumLength", 5),
                Padding(2)), #reserved
            If(this.durationFlag,
                Embed(Struct(None,
                    UBInt32("timeScale"),
                    UBInt16("accessUnitDuration"),
                    UBInt16("compositionUnitDuration")))),
            If(lambda ctx: not ctx.useTimeStampsFlag,
                Bits("startDecodingTimeStamp", this.timeStampLength),
                Bits("startCompositionTimeStamp", this.timeStampLength))))))


# 7.2.6.5
ES_DescrTag = 0x03
ES_Descriptor = BaseDescriptor("ES", ES_DescrTag,
    UBInt16("ES_ID"),
    EmbeddedBitStruct(
        Flag("streamDependenceFlag"),
        Flag("URL_Flag"),
        Flag("OCRstreamFlag"),
        Bits("streamPriority", 5)),
    If(this.streamDependenceFlag,
        UBInt16("dependsOn_ES_ID")),
    If(this.URL_Flag,
        PascalString("URLstring", UBInt8("URLlength"))),
    If(this.OCRstreamFlag,
        UBInt16("OCR_ES_Id")),
    DecoderConfigDescriptor,
    SLConfigDescriptor,
    Optional(IPI_DescrPointer),
    Range(0, 255, IP_IdentificationDataSet),
    Range(0, 255, IPMP_DescriptorPointer),
    Range(0, 255, LanguageDescriptor),
    Optional(QoS_Descriptor),
    Optional(RegistrationDescriptor),
    Range(0, 255, ExtensionDescriptor))



# ISO/IEC 14496-12:2012
# Coding of audio-visual objects - Part 12: ISO base media file format

box_data = {}

def make_box(fourcc=None):
    typeCons = String("type", 4)
    if fourcc:
        typeCons = Const(typeCons, fourcc)

    return StructWithLength(fourcc or "box",
        UBInt32("size"),

        Anchor("_box_start"),
        typeCons,
        # If(lambda ctx: ctx.size == 1,
        #     UBInt64("largesize")),
        If(lambda ctx: ctx.type == 'uuid',
            String("usertype", 16)),
        Anchor("_header_end"),
        ParseOnly(Value("data_size",
            lambda ctx: ctx.size - 4 - (ctx._header_end - ctx._box_start))),
        Probe("box", show_stream=False, show_stack=False),
        Switch("data", this.type, box_data, default=Bork("unimplemented box")),
        OptionalGreedyRange(LazyBound("children", lambda: Box)),
        Terminator,
        inclusive=True)

Box = make_box()


def define_box(fourcc, datacons=None):
    if datacons:
        box_data[fourcc] = Rename(fourcc, datacons)
    else:
        box_data[fourcc] = Struct(fourcc)
    return make_box(fourcc)


def BaseBox(*subcons):
    return Struct(None, *subcons)

# 4.2
def FullBox(*subcons):
    return Struct(None,
        UBInt8("version"),
        UBInt24("flags"),
        *subcons)

# 4.3
FileTypeBox = define_box("ftyp",
    BaseBox(
        String("major_brand", 4),
        UBInt32("major_brand_version"),
        OptionalGreedyRange(String("compatible_brands", 4))))

# 8.1
MediaDataBox = define_box("mdat",
    OnDemand(Field("data", this.data_size)))

# 8.1.2
FreeSpaceBox = define_box("free",
    Padding(this.data_size))

# 8.2.1
MovieBox = define_box("moov")

# 8.2.2
MovieHeaderBox = define_box("mvhd",
    FullBox(
        Embed(IfThenElse(None, lambda ctx: ctx.version == 1,
           Struct(None,
               UBInt64("creation_time"),
               UBInt64("modification_time"),
               UBInt32("timescale"),
               UBInt64("duration")),
           Struct(None,
               UBInt32("creation_time"),
               UBInt32("modification_time"),
               UBInt32("timescale"),
               UBInt32("duration")))),
        UBInt32("rate"),
        UBInt16("volume"),
        Padding(2), #reserved
        Padding(8), #reserved
        Array(9, UBInt32("matrix")),
        Padding(6*4), #pre_defined
        UBInt32("next_track_id")))

# 8.3.1
TrackBox = define_box("trak")

# 8.3.2
TrackHeaderBox = define_box("tkhd",
    FullBox(
        Embed(IfThenElse(None, lambda ctx: ctx.version == 1,
           Struct(None,
               UBInt64("creation_time"),
               UBInt64("modification_time"),
               UBInt32("track_id"),
               Padding(4), #reserved
               UBInt64("duration")),
           Struct(None,
               UBInt32("creation_time"),
               UBInt32("modification_time"),
               UBInt32("track_id"),
               Padding(4), #reserved
               UBInt32("duration")))),
        Padding(8), #reserved
        UBInt16("layer"),
        UBInt16("alternate_group"),
        UBInt16("volume"),
        Padding(2), #reserved
        Array(9, UBInt32("matrix")),
        UBInt32("width"),
        UBInt32("height")))

# 8.4.1
MediaBox = define_box("mdia")

# 8.4.2
MediaHeaderBox = define_box("mdhd",
    FullBox(
        Embed(IfThenElse(None, lambda ctx: ctx.version == 1,
           Struct(None,
               UBInt64("creation_time"),
               UBInt64("modification_time"),
               UBInt32("timescale"),
               UBInt64("duration")),
           Struct(None,
               UBInt32("creation_time"),
               UBInt32("modification_time"),
               UBInt32("timescale"),
               UBInt32("duration")))),
        EmbeddedBitStruct(
            Padding(1),
            Array(3, Bits("language", 5))),
        Padding(2))) #pre_defined

# 8.4.3
HandlerBox = define_box("hdlr",
    FullBox(
        Padding(4), #pre_defined
        String("handler_type", 4),
        Padding(3*4), #reserved
        CString("name")))

# 8.4.4
MediaInformationBox = define_box("minf"),

VideoMediaHeaderBox = define_box("vmhd",
    FullBox(
        UBInt16("graphicsmode"),
        Array(3, UBInt16("opcolor"))))

# 8.4.5.3
SoundMediaHeaderBox = define_box("smhd",
    FullBox(
        UBInt16("balance"),
        Padding(2))) #reserved


# 8.5.1
SampleTableBox = define_box("stbl")

# 8.5.2
SampleDescriptionBox = define_box("stsd",
    FullBox(
        PrefixedArray(
            Rename("entry", Box), # TODO
            UBInt32("entry_count"))))

# 8.5.2.2
def SampleEntry(*subcons):
    return Struct(None,
        Padding(6), #reserved
        UBInt16("data_reference_index"),
        *subcons)

PixelAspectRatioBox = define_box("pasp",
    BaseBox(
        UBInt32("hSpacing"),
        UBInt32("vSpacing")))

CleanApertureBox = define_box("clap",
    BaseBox(
        UBInt32("cleanApertureWidthN"),
        UBInt32("cleanApertureWidthD"),
        UBInt32("cleanApertureHeightN"),
        UBInt32("cleanApertureHeightD"),
        UBInt32("horizOffN"),
        UBInt32("horizOffD"),
        UBInt32("vertOffN"),
        UBInt32("vertOffD")))

def VisualSampleEntry(*subcons):
    return SampleEntry(
        Padding(2), #pre_defined
        Padding(2), #reserved
        Padding(4*3), #pre_defined
        UBInt16("width"),
        UBInt16("height"),
        UBInt32("horizresolution"),
        UBInt32("vertresolution"),
        Padding(4), #reserved
        UBInt16("frame_count"),
        String("compressorname", 32, padchar="\x00"),
        UBInt16("depth"),
        Padding(2),  #pre_defined
        *(subcons + (
        Optional(CleanApertureBox),
        Optional(PixelAspectRatioBox)
        )))

def AudioSampleEntry(*subcons):
    return SampleEntry(
        Padding(8), #reserved
        UBInt16("channelcount"),
        UBInt16("samplesize"),
        Padding(2), #pre_defined
        Padding(2), #reserved
        UBInt32("samplerate"),
        *subcons)

# 8.6.1.2
TimeToSampleBox = define_box("stts",
    FullBox(
        PrefixedArray(
            Struct("sample_entry",
                UBInt32("sample_count"),
                UBInt32("sample_delta")),
            UBInt32("entry_count"))))

# 8.6.2
SyncSampleBox = define_box("stss",
    FullBox(
        PrefixedArray(
            UBInt32("sample_number"),
            UBInt32("entry_count"))))

# 8.6.5
EditBox = define_box("edts")

# 8.6.6 
EditListBox = define_box("elst",
    FullBox(
        UBInt32("entry_count"),
        Array(this.entry_count,
            Struct('entry',
                Embed(IfThenElse(None, lambda ctx: ctx._.version == 1,
                    Struct(None,
                        UBInt64("segment_duration"),
                        UBInt64("media_time")),
                    Struct(None,
                        UBInt32("segment_duration"),
                        UBInt32("media_time")))),
                UBInt16("media_rate_integer"),
                UBInt16("media_rate_fraction")))))

# 8.7.1
DataInformationBox = define_box("dinf")

# 8.7.2
DataEntryUrlBox = define_box("url ",
    FullBox(
        Optional(CString("location"))))
DataEntryUrnBox = define_box("urn ",
    FullBox(
        CString("name"),
        Optional(CString("location"))))
DataReferenceBox = define_box("dref",
    FullBox(
        PrefixedArray(
            Rename("data_entry", Box), #TODO
            UBInt32("entry_count"))))

# 8.7.3.2
SampleSizeBox = define_box("stsz",
    FullBox(
        UBInt32("sample_size"),
        UBInt32("sample_count"),
        If(lambda ctx: ctx.sample_size == 0,
            OnDemand(Array(this.sample_count,
                UBInt32("sample_size_list"))))))

# 8.7.4
SampleToChunkBox = define_box("stsc",
    FullBox(
        PrefixedArray(
            Struct("sample_entry",
                UBInt32("first_chunk"),
                UBInt32("samples_per_chunk"),
                UBInt32("sample_description_index")),
            UBInt32("entry_count"))))

# 8.7.5
ChunkOffsetBox = define_box("stco",
    FullBox(
        PrefixedArray(
            UBInt32("chunk_offset"),
            UBInt32("entry_count"))))

# 8.10.1
UserDataBox = define_box("udta")

# 8.11.1
MetaBox = define_box("meta",
    FullBox(
        LazyBound("theHandler", lambda: HandlerBox),
        # TODO
        OptionalGreedyRange(Rename("other_boxes", Box))))


# ISO/IEC 14496-14:2003
# Coding of audio-visual objects - Part 14: MP4 file format

# 5.1
ObjectDescriptorBox = define_box("iods",
    FullBox(MP4_ObjectDescriptorBase))

# 5.6
ESDBox = define_box("esds", FullBox(ES_Descriptor))
MP4AudioSampleEntry = define_box("mp4a",
    AudioSampleEntry(Rename("ES", ESDBox)))


# ISO/IEC 14496-15:2014
# Coding of audio-visual objects
# Part 15: Carriage of NAL unit structured video in ISO base media file format

# 5.3.3.1
AVCDecoderConfigurationRecord = Struct("avcC",
    UBInt8("configurationVersion"),
    UBInt8("AVCProfileIndication"),
    UBInt8("profile_compatibility"),
    UBInt8("AVCLevelIndication"),
    EmbeddedBitStruct(
        Padding(6), #reserved
        Bits("lengthSizeMinusOne", 2),
        Padding(3), #reserved
        Bits("numOfSequenceParameterSets", 5)),
    Array(this.numOfSequenceParameterSets,
        PascalString("sequenceParameterSetNALUnit",
            UBInt16("sequenceParameterSetLength"))),
    PrefixedArray(
        PascalString("pictureParameterSetNALUnit",
            UBInt16("pictureParameterSetLength")),
        UBInt8("numOfPictureParameterSets")),
    If(lambda ctx: ctx.AVCProfileIndication in (100, 110, 122, 144),
        Optional(Struct("ext",
            EmbeddedBitStruct(
                Padding(6), #reserved
                Bits("chroma_format", 2),
                Padding(5), #reserved
                Bits("bit_depth_luma_minus8", 3),
                Padding(5), #reserved
                Bits("bit_depth_chromw_minus8", 3)),
            PrefixedArray(
                PascalString("sequenceParameterSetExt",
                    UBInt16("sequenceParameterSetExtLength")),
                UBInt8("numOfSequenceParameterSetExt"))))))

# 5.4.2.1
AVCConfigurationBox = define_box("avcC",
    BaseBox(AVCDecoderConfigurationRecord))
MPEG4BitRateBox = define_box("btrt",
    BaseBox(
        UBInt32("bufferSizeDB"),
        UBInt32("maxBitrate"),
        UBInt32("avgBitrate")))
MPEG4ExtensionDescriptorsBox = define_box("m4ds",
    BaseBox(
        Range(0, 255, BaseDescriptor("descr", None))))
AVCSampleEntry = define_box("avc1",
    VisualSampleEntry(
        AVCConfigurationBox,
        Optional(MPEG4BitRateBox),
        Optional(MPEG4ExtensionDescriptorsBox)))


# derp
IlstBox = define_box("ilst", BaseBox(Padding(this._.data_size)))

MP4 = GreedyRange(Box)


def mux_aac_eld(channels, sample_rate, sample_size, frame_duration, frames):

    # ftyp    4.3 File Type
    # moov    8.2.1 Movie
    #     mvhd    8.2.2 Movie Header
    #     trak    8.3.1 Track
    #         tkhd    8.3.2 Track Header
    #             mdia        8.4.1 Media
    #                 mdhd    8.4.2 Media Header
    #                 hdlr    8.4.3 Handler Reference
    #                 minf    8.4.4 Media Information
    #                     smhd    8.4.5.3 Sound Media Header
    #                     dinf    8.7.1 Data Information
    #                         dref    Data Reference ...
    #                     stbl    8.5.1 Sample Table
    #                         stsd    8.5.2 Sample Description
    #                             mp4a
    #                                 esds
    #                         stts    8.6.1.2 Decoding Time to Sample
    #                         stsc    8.7.4 Sample To Chunk
    #                         stsz?   8.7.3.2 Sample Size
    #                         stco    8.7.5 Chunk Offset - Index of each chunk into the file

    assert frame_duration in (512, 480)
    
    # sample_rate in hz
    # sample_size in bits
    # frame_duration in samples
    duration = 1000 * frame_duration * len(frames) / sample_rate # in ms

    ftyp = DefaultingContainer(
        type = 'ftyp',
        data = Container(
            major_brand = 'M4A ',
            major_brand_version = 512,
            compatible_brands = ['isom', 'iso2']),
        children = [])

    mvhd = DefaultingContainer(
        type = 'mvhd',
        data = Container(
            version = 0,
            flags = 0,
            creation_time = 0,
            modification_time = 0,
            timescale = 1000,
            duration = duration,
            rate = 6, # wtf
            volume = 0x100,
            matrix = [
                0x10000, 0, 0,
                0, 0x10000, 0,
                0, 0, 0x40000000
            ],
            next_track_id = 2),
        children = [])


    audioSpecificConfig = Container(
        audioObjectType = 39, # AAC-ELD
        samplingFrequency = sample_rate,
        channelConfiguration = channels,
        extensionConfig = None,
        config = Container(
            frameLengthFlag = frame_duration == 480,
            aacSectionDataResilienceFlag = False,
            aacScalefactorDataResilienceFlag = False,
            aacSpectralDataResilienceFlag = False,
            ldSbrPresentFlag = False,
            ld = None,
            eldext = [Container(eldExtType=0)]),
        ep = Container(epConfig = 0),
        remaining = [0, 0])

    esds = DefaultingContainer(
        type = 'esds',
        data = Container(
            version = 0,
            flags = 0,
            ES = Container(
                tag = 3, # ES_DescrTag
                sizeOfInstance = 36,
                ES_ID = 1,
                streamDependenceFlag = False,
                URL_Flag = False,
                OCRstreamFlag = False,
                streamPriority = 0,
                dependsOn_ES_ID = None,
                URLstring = None,
                OCR_ES_Id = None,
                decoderConfigDescr = Container(
                    tag = 4, # DecoderConfigDescrTag
                    sizeOfInstance = 22,
                    objectTypeIndication = 0x40, # Audio ISO/IEC 14496-3
                    streamType = 5,
                    upStream = 0,
                    bufferSizeDB = 0,
                    maxBitrate = 0,
                    avgBitrate = 0,
                    decSpecificInfo = Container(
                        tag = 5, # DecSpecificInfoTag
                        sizeOfInstance = 4,
                        data = audioSpecificConfig),
                    profileLevelIndicationIndexDescriptor = []),
                slConfigDescr = Container(
                    tag = 6, # SLConfigDescrTag
                    sizeOfInstance = 1,
                    predefined = 2),
                ipiPtr = None,
                ipIDS = [],
                ipmpDesrPtr = [],
                langDescr = [],
                qosDescr = None,
                regDescr = None,
                extDescr = [])),
        children = [])
    
    mp4a = DefaultingContainer(
        type = 'mp4a',
        data = Container(
            data_reference_index = 1,
            channelcount = channels,
            samplesize = sample_size,
            samplerate = sample_rate << 16,
            ES = esds),
        children = [])

    stsd = DefaultingContainer(
        type = 'stsd',
        data = Container(
            version = 0,
            flags = 0,
            entry = [ mp4a ]),
        children = [])

    stts = DefaultingContainer(
        type = 'stts',
        data = Container(
            version = 0,
            flags = 0,
            sample_entry = [
                Container(
                    sample_count = len(frames),
                    sample_delta = frame_duration)
            ]),
        children = [])

    stsc = DefaultingContainer(
        type = 'stsc',
        data = Container(
            version = 0,
            flags = 0,
            sample_entry = [
                Container(
                    first_chunk = 1,
                    samples_per_chunk = len(frames),
                    sample_description_index = 1)
            ]),
        children = [])

    stsz = DefaultingContainer(
        type = 'stsz',
        data = Container(
            version = 0,
            flags = 0,
            sample_size = 0,
            sample_count = len(frames),
            sample_size_list = map(len, frames)),
        children = [])

    stco = DefaultingContainer(
        type = 'stco',
        data = Container(
            version = 0,
            flags = 0,
            chunk_offset = [
                0xff998877, # hax
            ]),
        children = [])

    minf = DefaultingContainer(
        type = 'minf',
        children = [
            DefaultingContainer(
                type = 'smhd',
                data = Container(
                    version = 0,
                    flags = 0,
                    balance = 0),
                children = []),

            DefaultingContainer(
                type = 'dinf',
                children = [
                    DefaultingContainer(
                        type = 'dref',
                        data = Container(
                            version = 0,
                            flags = 0,
                            data_entry = [
                                DefaultingContainer(
                                    type = 'url ',
                                    data = Container(
                                        version = 0,
                                        flags = 1,
                                        location = None),
                                    children = [])
                            ]),
                        children = [])
                ]),

            DefaultingContainer(
                type = 'stbl',
                children = [
                    stsd,
                    stts,
                    stsc,
                    stsz,
                    stco
                ])
        ])

    mdia = DefaultingContainer(
        type = 'mdia',
        children = [
            DefaultingContainer(
                type = 'mdhd',
                data = Container(
                    version = 0,
                    flags = 0,
                    creation_time = 0,
                    modification_time = 0,
                    timescale = sample_rate, # wtf
                    duration = frame_duration * len(frames),
                    language = [ 21, 14, 4 ]),
                children = []),
            DefaultingContainer(
                type = 'hdlr',
                data = Container(
                    version = 0,
                    flags = 0,
                    handler_type = 'soun',
                    name = 'SoundHandler'),
                children = []),

            minf
        ])

    trak = DefaultingContainer(
        type = 'trak',
        children = [
            DefaultingContainer(
                type = 'tkhd',
                data = Container(
                    version = 0,
                    flags = 3,
                    creation_time = 0,
                    modification_time = 0,
                    track_id = 1,
                    duration = duration,
                    layer = 0,
                    alternate_group = 1,
                    volume = 0x100,
                    matrix = [
                        0x10000, 0, 0,
                        0, 0x10000, 0,
                        0, 0, 0x40000000
                    ],
                    width = 0,
                    height = 0),
                children = []),

            mdia
        ])

    moov = DefaultingContainer(
        type = 'moov',
        children = [
            mvhd,
            trak
        ])


    header = MP4.build([ftyp, moov])
    # print header.encode("hex")
    # print len(header)

    # hax
    header = header.replace("\xFF\x99\x88\x77", struct.pack(">I", len(header)+8))

    data = ''.join(frames)
    mdat = Box.build(DefaultingContainer(
        type = 'mdat',
        data_size = len(data),
        data = data,
        children = []))

    open("/tmp/tmp.m4a", "a").write(header+mdat)

def extract_samples(file_name):
    f = open(file_name, "rb")
    r = MP4.parse_stream(f)

    def find_box(t, n=r):
        if isinstance(n, list):
            for c in n:
                v = find_box(t, c)
                if v is not None: return v
            return None

        if n.type == t: return n
        for c in n.children:
            v = find_box(t, c)
            if v is not None: return v
        return None

    # stts = find_box('stts')
    stsc = find_box('stsc')
    stco = find_box('stco')
    stsz = find_box('stsz')
    sample_sizes = stsz.data.sample_size_list.read()

    chunk_samples = []
    for c in stsc.data.sample_entry:
        while len(chunk_samples) < c.first_chunk-1:
            chunk_samples.append(chunk_samples[-1])
        chunk_samples.append(c.samples_per_chunk)
    while len(chunk_samples) < len(stco.data.chunk_offset):
        chunk_samples.append(chunk_samples[-1])

    samples = []

    j = 0
    for i, s in enumerate(chunk_samples):
        offset = stco.data.chunk_offset[i]
        for k in xrange(j, j+s):
            sample_size = sample_sizes[k]
            samples.append(d[offset:offset+sample_size])
            offset += sample_size
        j += s
    

    return samples
