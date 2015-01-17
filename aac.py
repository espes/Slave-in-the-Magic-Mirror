# aac.py
#
# Copyright 2015, espes
#
# Licensed under GPL Version 2 or later
#

from construct import *
from construct_utils import *

# ISO/IEC 14496-3:2009
# Coding of audio-visual objects - Part 3: Audio

# 4.4.1
def GASpecificConfig(channelConfiguration,
                     audioObjectType):
    return Struct("GASpecificConfig",
        Flag("frameLengthFlag"),
        Flag("dependsOnCoreCoder"),
        If(this.dependsOnCoreCoder, Bits("coreCoderDelay", 14)),
        Flag("extensionFlag"),
        If(lambda ctx: channelConfiguration(ctx) == 0, Bork("program_config_element")),
        If(lambda ctx: audioObjectType(ctx) in (6, 20), Bork("layerNr")),
        # P("K"),
        # If(this.extensionFlag, Bork("extension")),
        # If(lambda ctx: audioObjectType(ctx._) in (17, 19, 20, 23), Bork("aacStuff")),
        Flag("extensionFlag3"),
        If(this.extensionFlag3, Bork("extensionFlag3")))

# 4.6.20.3
ELDEXT_TERM = 0
ELDSpecificConfig = Struct("ELDSpecificConfig",
    Flag("frameLengthFlag"),
    Flag("aacSectionDataResilienceFlag"),
    Flag("aacScalefactorDataResilienceFlag"),
    Flag("aacSpectralDataResilienceFlag"),
    
    Flag("ldSbrPresentFlag"),
    If(this.ldSbrPresentFlag,
        Struct("ld",
            Bits("ldSbrSamplingRate", 1),
            Bits("ldSbrCrcFlag", 1),
            Bork("ld_sbr_header"))),

    RepeatUntil(lambda obj, ctx: obj.eldExtType == ELDEXT_TERM,
        Struct("eldext",
            Bits("eldExtType", 4),
            If(lambda ctx: ctx.eldExtType != ELDEXT_TERM,
                Bork("eldExt"))
            # ...
            )))

# 1.6.2.1
AudioObjectType = ExprAdapter(
    Struct("audioObjectType",
        Bits("audioObjectType", 5),
        If(lambda ctx: ctx.audioObjectType == 31,
            Bits("audioObjectTypeExt", 6))),
    decoder = lambda obj, ctx: (obj.audioObjectType if obj.audioObjectType < 31
            else 32+obj.audioObjectTypeExt),
    encoder = lambda obj, ctx: Container(
            audioObjectType = 31 if obj >= 31 else obj,
            audioObjectTypeExt=obj - 32 if obj >= 32 else None)
)

# 1.6.3.4

frequencyIndex = [
    97000,
    88200,
    64000,
    48000,
    44100,
    32000,
    24000,
    22050,
    16000,
    12000,
    11025,
    8000,
    7350
]
SamplingFrequency = ExprAdapter(
    Struct("samplingFrequency",
        Bits("samplingFrequencyIndex", 4),
        # P("sampling"),
        If(lambda ctx: ctx.samplingFrequencyIndex == 0xf,
            Bits("samplingFrequency", 24))),
    decoder = lambda obj, ctx: obj.samplingFrequency or frequencyIndex[obj.samplingFrequencyIndex],
    encoder = lambda obj, ctx: Container(
            samplingFrequencyIndex=frequencyIndex.index(obj) if obj in frequencyIndex else 0xf,
            samplingFrequency=obj)
    )
    
AudioSpecificConfig = Struct("AudioSpecificConfig",
    AudioObjectType,
    SamplingFrequency,
    Bits("channelConfiguration", 4),
    If(lambda ctx: ctx.audioObjectType in (5, 29),
        Struct("extensionConfig",
            Rename("extensionSamplingFrequency", SamplingFrequency),
            Rename("extensionAudioObjectType", AudioObjectType),
            If(lambda ctx: ctx.extensionAudioObjectType == 22,
                Bits("extensionChannelConfiguration", 4)))),

    # P("wut"),

    Switch("config", this.audioObjectType, {
        2: GASpecificConfig(this._.channelConfiguration, this._.audioObjectType), # AAC-LC
        39: ELDSpecificConfig, # AAC-ELD
        # TODO
    }, default=Bork("unimplemented audioObjectType")),

    If(lambda ctx: ctx.audioObjectType in (17, 19, 20, 21, 22, 23, 24, 25, 26, 27, 39),
        Struct("ep",
            Bits("epConfig", 2),
            If(lambda ctx: ctx.epConfig in (2, 3), Bork("epConfig")))),
    # TODO
    )

AudioSpecificConfig_bytes = BitStruct("AudioSpecificConfig",
    Embed(AudioSpecificConfig),
    ByteAlign())


# 1.7.3 

# This stuff is too messed up for construct. Really should be done manually...

StreamMuxConfig = Struct("cfg",
    Bit("audioMuxVersion"),
    If(this.audioMuxVersion,
        Flag("audioMuxVersionA")),
    If(this.audioMuxVersionA, Bork("audioMuxVersionA")),

    If(this.audioMuxVersion, Bork("taraBufferFullnexx")),
    Flag("allStreamsSameTimeFraming"),
    Bits("numSubFrames", 6),
    Bits("numProgram", 4),

    If(lambda ctx: ctx.numProgram > 0, Bork("numProgram")),
    Bits("numLayer", 3),
    If(lambda ctx: ctx.numLayer > 0, Bork("numLayer")),
    Struct("layer",
        # useSameConfig
        # if not useSameConfig
        If(lambda ctx: ctx._.audioMuxVersion == 0,
            AudioSpecificConfig),

        Bits("frameLengthType", 3),
        Embed(IfThenElse(None,
            lambda ctx: ctx.frameLengthType == 0,
            Struct(None,
                Bits("latmBufferFullness", 8),
                # TODO: coreFrameOffset is object type stuff
                ),
            Bork("frameLengthType")
            ))
        ),

    Flag("otherDataPresent"),
    If(this.otherDataPresent, Bork("otherData")),
    Flag("crcCheckPresent"),
    If(this.crcCheckPresent, Bork("crcCheck")),

    # Probe("SM", show_stream=False, show_stack=False)
    )

AudioMuxElement_1 = BitStruct("AudioMuxElement",
    Flag("useSameStreamMux"),
    If(lambda ctx: not ctx.useSameStreamMux,
        StreamMuxConfig),

    # If(lambda ctx: ctx.cfg.numSubFrames != 0, Bork("numSubFrames")),

    # PayloadLengthInfo
    # If(lambda ctx: not ctx.cfg.allStreamsSameTimeFraming, Bork()),
    # If(lambda ctx: ctx.cfg.layer.frameLengthType != 0, Bork()),
    ExprAdapter(
        RepeatUntil(lambda obj, ctx: obj != 255,
            Bits("MuxSlotLengthBytes", 8)),
        decoder = lambda obj, ctx: sum(obj),
        encoder = lambda obj, ctx: [255] * (obj // 255) + [obj % 255]),
    # PayloadMux
    Array(this.MuxSlotLengthBytes, Bits('payload', 8)),

    ByteAlign()
    )

# 1.7.2

AudioSyncStream = StructWithLengthAdapter("AudioSyncStream",
    StructLengthAdapter(
        EmbeddedBitStruct(
            Const(Bits("syncword", 11), 0x2b7),
            Bits("audioMuxLengthBytes", 13)),
        decoder = lambda obj, ctx: obj.audioMuxLengthBytes,
        encoder = lambda length, obj, ctx: container_add(obj, audioMuxLengthBytes=length)
    ),
    Embed(AudioMuxElement_1),
    Terminator
    )


def latm_mux(cfg, frames):
    first_mux = DefaultingContainer(
        useSameStreamMux = False,
        cfg = cfg,
        MuxSlotLengthBytes = len(frames[0]),
        payload = map(ord, frames[0]))

    r = [AudioSyncStream.build(first_mux)]

    for f in frames[1:]:
        mux = DefaultingContainer(
            useSameStreamMux = True,
            MuxSlotLengthBytes = len(f),
            payload = map(ord, f))
        r.append(AudioSyncStream.build(mux))

    return r

def latm_mux_aac_lc(channels, sample_rate, frame_duration, frames):
    assert frame_duration in (1024, 960)
    assert len(frames) >= 1

    cfg = Container(
        audioMuxVersion = 0,
        audioMuxVersionA = None,
        allStreamsSameTimeFraming = True,
        numSubFrames = 0,
        numProgram = 0,
        numLayer = 0,
        layer = Container(
            AudioSpecificConfig = Container(
                audioObjectType = 2, # AAC-LC
                samplingFrequency = sample_rate,
                channelConfiguration = channels,
                extensionConfig = None,
                config = Container(
                    frameLengthFlag = frame_duration == 960,
                    dependsOnCoreCoder = False,
                    coreCoderDelay = None,
                    extensionFlag = True,
                    extensionFlag3 = False),
                ep = Container(epConfig = 0)),
            frameLengthType = 0,
            latmBufferFullness = 0xff), #??
        otherDataPresent = False,
        crcCheckPresent = False)
    
    return latm_mux(cfg, frames)
    

def latm_mux_aac_eld(channels, sample_rate, frame_duration, frames):
    assert frame_duration in (512, 480)
    assert len(frames) >= 1

    cfg = Container(
        audioMuxVersion = 0,
        audioMuxVersionA = None,
        allStreamsSameTimeFraming = True,
        numSubFrames = 0,
        numProgram = 0,
        numLayer = 0,
        layer = Container(
            AudioSpecificConfig = Container(
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
                ep = Container(epConfig = 0)),
            frameLengthType = 0,
            latmBufferFullness = 0xff), #??
        otherDataPresent = False,
        crcCheckPresent = False)
    
    return latm_mux(cfg, frames)

