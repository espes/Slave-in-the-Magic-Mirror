# mpegts.py
#
# Copyright 2015, espes
#
# Parts adapted from rtmp-livestreaming
# Copyright 2014, Michael Liao
#
# Licensed under GPL Version 3 or later
#

from construct import *
from collections import defaultdict

from construct_utils import *

crc32_tab = [
        0x00000000, 0x04c11db7, 0x09823b6e, 0x0d4326d9,
        0x130476dc, 0x17c56b6b, 0x1a864db2, 0x1e475005,
        0x2608edb8, 0x22c9f00f, 0x2f8ad6d6, 0x2b4bcb61,
        0x350c9b64, 0x31cd86d3, 0x3c8ea00a, 0x384fbdbd,
        0x4c11db70, 0x48d0c6c7, 0x4593e01e, 0x4152fda9,
        0x5f15adac, 0x5bd4b01b, 0x569796c2, 0x52568b75,
        0x6a1936c8, 0x6ed82b7f, 0x639b0da6, 0x675a1011,
        0x791d4014, 0x7ddc5da3, 0x709f7b7a, 0x745e66cd,
        0x9823b6e0, 0x9ce2ab57, 0x91a18d8e, 0x95609039,
        0x8b27c03c, 0x8fe6dd8b, 0x82a5fb52, 0x8664e6e5,
        0xbe2b5b58, 0xbaea46ef, 0xb7a96036, 0xb3687d81,
        0xad2f2d84, 0xa9ee3033, 0xa4ad16ea, 0xa06c0b5d,
        0xd4326d90, 0xd0f37027, 0xddb056fe, 0xd9714b49,
        0xc7361b4c, 0xc3f706fb, 0xceb42022, 0xca753d95,
        0xf23a8028, 0xf6fb9d9f, 0xfbb8bb46, 0xff79a6f1,
        0xe13ef6f4, 0xe5ffeb43, 0xe8bccd9a, 0xec7dd02d,
        0x34867077, 0x30476dc0, 0x3d044b19, 0x39c556ae,
        0x278206ab, 0x23431b1c, 0x2e003dc5, 0x2ac12072,
        0x128e9dcf, 0x164f8078, 0x1b0ca6a1, 0x1fcdbb16,
        0x018aeb13, 0x054bf6a4, 0x0808d07d, 0x0cc9cdca,
        0x7897ab07, 0x7c56b6b0, 0x71159069, 0x75d48dde,
        0x6b93dddb, 0x6f52c06c, 0x6211e6b5, 0x66d0fb02,
        0x5e9f46bf, 0x5a5e5b08, 0x571d7dd1, 0x53dc6066,
        0x4d9b3063, 0x495a2dd4, 0x44190b0d, 0x40d816ba,
        0xaca5c697, 0xa864db20, 0xa527fdf9, 0xa1e6e04e,
        0xbfa1b04b, 0xbb60adfc, 0xb6238b25, 0xb2e29692,
        0x8aad2b2f, 0x8e6c3698, 0x832f1041, 0x87ee0df6,
        0x99a95df3, 0x9d684044, 0x902b669d, 0x94ea7b2a,
        0xe0b41de7, 0xe4750050, 0xe9362689, 0xedf73b3e,
        0xf3b06b3b, 0xf771768c, 0xfa325055, 0xfef34de2,
        0xc6bcf05f, 0xc27dede8, 0xcf3ecb31, 0xcbffd686,
        0xd5b88683, 0xd1799b34, 0xdc3abded, 0xd8fba05a,
        0x690ce0ee, 0x6dcdfd59, 0x608edb80, 0x644fc637,
        0x7a089632, 0x7ec98b85, 0x738aad5c, 0x774bb0eb,
        0x4f040d56, 0x4bc510e1, 0x46863638, 0x42472b8f,
        0x5c007b8a, 0x58c1663d, 0x558240e4, 0x51435d53,
        0x251d3b9e, 0x21dc2629, 0x2c9f00f0, 0x285e1d47,
        0x36194d42, 0x32d850f5, 0x3f9b762c, 0x3b5a6b9b,
        0x0315d626, 0x07d4cb91, 0x0a97ed48, 0x0e56f0ff,
        0x1011a0fa, 0x14d0bd4d, 0x19939b94, 0x1d528623,
        0xf12f560e, 0xf5ee4bb9, 0xf8ad6d60, 0xfc6c70d7,
        0xe22b20d2, 0xe6ea3d65, 0xeba91bbc, 0xef68060b,
        0xd727bbb6, 0xd3e6a601, 0xdea580d8, 0xda649d6f,
        0xc423cd6a, 0xc0e2d0dd, 0xcda1f604, 0xc960ebb3,
        0xbd3e8d7e, 0xb9ff90c9, 0xb4bcb610, 0xb07daba7,
        0xae3afba2, 0xaafbe615, 0xa7b8c0cc, 0xa379dd7b,
        0x9b3660c6, 0x9ff77d71, 0x92b45ba8, 0x9675461f,
        0x8832161a, 0x8cf30bad, 0x81b02d74, 0x857130c3,
        0x5d8a9099, 0x594b8d2e, 0x5408abf7, 0x50c9b640,
        0x4e8ee645, 0x4a4ffbf2, 0x470cdd2b, 0x43cdc09c,
        0x7b827d21, 0x7f436096, 0x7200464f, 0x76c15bf8,
        0x68860bfd, 0x6c47164a, 0x61043093, 0x65c52d24,
        0x119b4be9, 0x155a565e, 0x18197087, 0x1cd86d30,
        0x029f3d35, 0x065e2082, 0x0b1d065b, 0x0fdc1bec,
        0x3793a651, 0x3352bbe6, 0x3e119d3f, 0x3ad08088,
        0x2497d08d, 0x2056cd3a, 0x2d15ebe3, 0x29d4f654,
        0xc5a92679, 0xc1683bce, 0xcc2b1d17, 0xc8ea00a0,
        0xd6ad50a5, 0xd26c4d12, 0xdf2f6bcb, 0xdbee767c,
        0xe3a1cbc1, 0xe760d676, 0xea23f0af, 0xeee2ed18,
        0xf0a5bd1d, 0xf464a0aa, 0xf9278673, 0xfde69bc4,
        0x89b8fd09, 0x8d79e0be, 0x803ac667, 0x84fbdbd0,
        0x9abc8bd5, 0x9e7d9662, 0x933eb0bb, 0x97ffad0c,
        0xafb010b1, 0xab710d06, 0xa6322bdf, 0xa2f33668,
        0xbcb4666d, 0xb8757bda, 0xb5365d03, 0xb1f740b4]

def crc32(data):
    i_crc = 0xffffffff;
    for ch in data:
        i_crc = ((i_crc << 8) & 0xffffffff) ^ crc32_tab[(i_crc >> 24) ^ ord(ch)]
    return i_crc


# ISO/IEC 13818-1:2013
# Generic coding of moving pictures and associated audio information

# 2.6
descriptor = Struct("descriptor",
    UBInt8("descriptor_tag"),
    UBInt8("descriptor_length"),
    String("data", this.descriptor_length))
    # Switch("data", this.descriptor_tag, {

    # }, default=Bork())

# 2.4.3.4
adaptation_field = Struct("adaptation_field",
    UBInt8("adaptation_field_length"),
    Anchor("_field_start"),
    If(lambda ctx: ctx.adaptation_field_length > 0,
        Embed(Struct(None,
            EmbeddedBitStruct(
                Flag("disconuity_indicator"),
                Flag("random_access_indicator"),
                Flag("elementary_stream_priority_indicator"),
                Flag("PCR_flag"),
                Flag("OPCR_flag"),
                Flag("splicing_point_flag"),
                Flag("transport_private_data_flag"),
                Flag("adaptation_field_extension_flag")),
            If(this.PCR_flag, BitStruct("PCR",
                Bits("program_clock_reference_base", 33),
                Padding(6),
                Bits("program_clock_reference_extension", 9))),
            If(this.OPCR_flag, BitStruct("OPCR",
                Bits("original_program_clock_reference_base", 33),
                Padding(6),
                Bits("original_program_clock_reference_extension", 9))),
            If(this.splicing_point_flag, UBInt8("splice_countdown")),
            # Probe(show_stack=False),
            If(this.transport_private_data_flag, Bork("transport_private_data")),
            If(this.adaptation_field_extension_flag, Bork("adaptation_field_extension")),

            Anchor("_field_end"),
            # stuffing
            Padding(lambda ctx: ctx.adaptation_field_length - (ctx._field_end - ctx._field_start),
                "\xFF", True))))
    )


# 2.4.3.2

transport_packet_length = 188
transport_packet_header = Struct("transport_packet_header",
    Magic("\x47"), #sync_byte
    EmbeddedBitStruct(
        Flag("transport_error_indicator"),
        Flag("payload_unit_start_indicator"),
        Flag("transport_priority"),
        Bits("PID", 13),
        Bits("transport_scrambling_control", 2),
        Bits("adaptation_field_control", 2),
        Bits("continuity_counter", 4)),
    
    If(lambda ctx: ctx.adaptation_field_control == 0, Bork()),

    If(lambda ctx: ctx.adaptation_field_control & 0b10,
        adaptation_field))

transport_packet = Struct("transport_packet",
    Anchor("_header_start"),
    Embed(transport_packet_header),
    Anchor("_header_end"),
    If(lambda ctx: ctx.adaptation_field_control & 0b01,
        String("data",
            lambda ctx: transport_packet_length - (ctx._header_end - ctx._header_start)))
    )


MPEG_transport_stream = GreedyRange(transport_packet)


def section(name, table_id, *subcons):
    return Struct(name,
        Padding(1), #pointer_field ........... ???
        Anchor("_crc_start"),
        Embed(StructWithLengthAdapter("section",
            StructLengthAdapter(
                EmbeddedBitStruct(
                    Const(Bits("table_id", 8), table_id),
                    Flag("section_syntax_indicator"),
                    Magic("\x00"),
                    Padding(2, "\x01"),
                    Bits("section_length", 12)),
                decoder = lambda obj, ctx: obj.section_length-4,
                encoder = lambda length, obj, ctx: container_add(obj, section_length=length+4)
            ),
            Embed(Struct(None, *subcons))
        )),
        Anchor("_crc_end"),

        Hash(UBInt32("CRC_32"),
            this._crc_start,
            lambda ctx: ctx._crc_end - ctx._crc_start,
            lambda data, ctx: crc32(data))
    )

# 2.4.4.3
# PAT
program_association_section = section("program_association_section", 0,
    EmbeddedBitStruct(
        Bits("transport_stream_id", 16),
        Padding(2, "\x01"),
        Bits("version_number", 5),
        Flag("current_next_indicator"),
        Bits("section_number", 8),
        Bits("last_section_number", 8)),

    OptionalGreedyRange(BitStruct("maps",
        Bits("program_number", 16),
        Padding(3, "\x01"),
        Bits("program_map_PID", 13))))

# 2.4.4.8
# PMT
TS_program_map_section = section("TS_program_map_section", 2,
    EmbeddedBitStruct(
        Bits("program_number", 16),
        Padding(2, "\x01"),
        Bits("version_number", 5),
        Flag("current_next_indicator"),
        Bits("section_number", 8),
        Bits("last_section_number", 8),
        Padding(3, "\x01"),
        Bits("PCR_PID", 13),
        Padding(4, "\x01"),
        Bits("program_info_length", 12)),

    String("program_info", this.program_info_length),

    OptionalGreedyRange(Struct("maps",
            EmbeddedBitStruct(
                Bits("stream_type", 8),
                Padding(3, "\x01"),
                Bits("elementary_PID", 13),
                Padding(4, "\x01"),
                Bits("ES_info_length", 12)),
            String("ES_info", this.ES_info_length))),
)



# 2.4.3.6

# Table 2-22 - Stream_id assignments

PES_STREAM_ID_PROGRAM_STREAM_MAP              = 0b10111100
PES_STREAM_ID_PRIVATE_STREAM_1                = 0b10111101
PES_STREAM_ID_PADDING_STREAM                  = 0b10111110
PES_STREAM_ID_PRIVATE_STREAM_2                = 0b10111111
PES_STREAM_ID_ECM                             = 0b11110000
PES_STREAM_ID_EMM                             = 0b11110001
PES_STREAM_ID_PROGRAM_STREAM_DIRECTORY        = 0b11111111
PES_STREAM_ID_DSMCC_STREAM                    = 0b11110010
PES_STREAM_ID_ITU_T_REC_H_222_1_TYPE_E_STREAM = 0b11111000

PES_HEADERLESS_STREAMS = (
    PES_STREAM_ID_PROGRAM_STREAM_MAP,
    PES_STREAM_ID_PRIVATE_STREAM_1,
    PES_STREAM_ID_PADDING_STREAM,
    PES_STREAM_ID_PRIVATE_STREAM_2,
    PES_STREAM_ID_ECM,
    PES_STREAM_ID_EMM,
    PES_STREAM_ID_PROGRAM_STREAM_DIRECTORY,
    PES_STREAM_ID_DSMCC_STREAM,
    PES_STREAM_ID_ITU_T_REC_H_222_1_TYPE_E_STREAM)


def Split32(name):
    return ExprAdapter(Struct(name,
        Bits("v0", 3),
        Magic("\x01"),
        Bits("v1", 15),
        Magic("\x01"),
        Bits("v2", 15),
        Magic("\x01")),
    decoder = lambda obj, ctx: (obj.v0 << 30) | (obj.v1 << 15) | obj.v2,
    encoder = lambda obj, ctx: Container(
        v0 = obj >> 30,
        v1 = (obj >> 15) & 0x7fff,
        v2 = obj & 0x7fff)
    )

# Table 2-21 - PES packet
PES_packet = Struct("PES_packet",
    Magic("\x00\x00\x01"), #packet_start_code_prefix
    UBInt8("stream_id"),
    Embed(StructWithLengthAdapter(None,
        StructLengthAdapter(
            UBInt16("PES_packet_length"),
            encoder = lambda length, obj, ctx: 0, #length if length < 65536 else 0,
            decoder = lambda obj, con: obj if obj != 0 else 1000000000),
        
        # Anchor("header_start"),
        If(lambda ctx: ctx.stream_id not in PES_HEADERLESS_STREAMS,
            Struct("header",
                EmbeddedBitStruct(
                    Magic("\x01\x00"),
                    Bits("PES_scrambling_control", 2),
                    Bits("PES_priority", 1),
                    Flag("data_alignment_indicator"),
                    Flag("copyright"),
                    Flag("original_or_copy"),
                    Bits("PTS_DTS_flags", 2),
                    Flag("ESCR_flag"),
                    Flag("ES_rate_flag"),
                    Flag("DSM_trick_mode_flag"),
                    Flag("additional_copy_info_flag"),
                    Flag("PES_CRC_flag"),
                    Flag("PES_extension_flag")),
                Embed(StructWithLength(None,
                    UBInt8("PES_header_data_length"),
                    
                    If(lambda ctx: ctx.PTS_DTS_flags == 0b10,
                        EmbeddedBitStruct(
                            Magic("\x00\x00\x01\x00"),
                            Split32("PTS"))),
                    If(lambda ctx: ctx.PTS_DTS_flags == 0b11,
                        EmbeddedBitStruct(
                            Magic("\x00\x00\x01\x01"),
                            Split32("PTS"),
                            Magic("\x00\x00\x00\x01"),
                            Split32("DTS"))),
                    If(this.ESCR_flag, Bork("ESCR")),
                    If(this.ES_rate_flag, Bork("ES_rate")),
                    If(this.DSM_trick_mode_flag, Bork("DSM_trick")),
                    If(this.additional_copy_info_flag, Bork("additional_copy_info")),
                    If(this.PES_CRC_flag, Bork("PES_CRC")),
                    If(this.PES_extension_flag, Bork("PES_extension")),
                    StringAdapter(OptionalGreedyRange(Field("stuffing", 1)))
                    ))
            )),
        # Anchor("header_end"),
        # Probe(show_stack=False),
        # IfThenElse("data", lambda ctx: ctx.PES_packet_length != 0,
        #     String("data", lambda ctx: ctx.PES_packet_length - (ctx.header_end - ctx.header_start)),
        #     StringAdapter(OptionalGreedyRange(Field("data", 1)))
        #     )
        # )
        StringAdapter(OptionalGreedyRange(Field("data", 1)))
    ))
)



class TSMuxer(object):
    def __init__(self, f, has_vid_stream, has_aud_stream):
        self.f = f
        self.has_vid_stream = has_vid_stream
        self.has_aud_stream = has_aud_stream

        assert self.has_vid_stream or self.has_aud_stream

        self.program_number = 1
        self.pmt_pid = 4096

        self.vid_es_pid = 256
        self.aud_es_pid = 267

        self.pcr_pid = self.vid_es_pid if self.has_vid_stream else self.self.aud_es_pid

        self.vid_stream_type = 0x1B # AVC video stream
        self.aud_stream_type = 0x11 # ACC audio with LATM transport

        self.pts_clock = 90000 # hz

        self.continuity_counters = defaultdict(int)

    def write_tables(self):
        pat = DefaultingContainer(
            table_id = 0,
            section_syntax_indicator = True,
            transport_stream_id = 1,
            version_number = 22,
            current_next_indicator = True,
            section_number = 0,
            last_section_number = 0,
            maps = [
                Container(
                    program_number = self.program_number,
                    program_map_PID = self.pmt_pid)
            ])
        pat_data = program_association_section.build(pat)
        # print pat_data.encode("hex")

        pat_packet = DefaultingContainer(
            transport_error_indicator = False,
            payload_unit_start_indicator = True,
            transport_priority = False,
            PID = 0,
            transport_scrambling_control = 0,
            adaptation_field_control = 1,
            continuity_counter = self.continuity_counters[0] % 16,
            adaptation_field = None
        )
        pat_packet_header = transport_packet_header.build(pat_packet)
        pat_packet_data = (pat_packet_header + pat_data).ljust(transport_packet_length, "\xFF")


        self.f.write(pat_packet_data)
        self.continuity_counters[0] += 1

        maps = []
        if self.has_vid_stream: maps.append((self.vid_stream_type, self.vid_es_pid))
        if self.has_aud_stream: maps.append((self.aud_stream_type, self.aud_es_pid))

        pmt = DefaultingContainer(
            table_id = 2,
            section_syntax_indicator = True,
            program_number = self.program_number,
            version_number = 0,
            current_next_indicator = True,
            section_number = 0,
            last_section_number = 0,
            PCR_PID = self.pcr_pid,
            program_info_length = 0,
            program_info = '',
            maps = [
                Container(
                    stream_type = t,
                    elementary_PID = pid,
                    ES_info_length = 0,
                    ES_info = '') for t, pid in maps
            ],
        )
        pmt_data = TS_program_map_section.build(pmt)

        pmt_packet = DefaultingContainer(
            transport_error_indicator = False,
            payload_unit_start_indicator = True,
            transport_priority = False,
            PID = self.pmt_pid,
            transport_scrambling_control = 0,
            adaptation_field_control = 1,
            continuity_counter = self.continuity_counters[self.pmt_pid] % 16,
            adaptation_field = None,
            # data = pmt_data.ljust(184, "\xFF")
        )
        pmt_packet_header = transport_packet_header.build(pmt_packet)
        pmt_packet_data = (pmt_packet_header + pmt_data).ljust(transport_packet_length, "\xFF")

        
        self.f.write(pmt_packet_data)
        self.continuity_counters[self.pmt_pid] += 1


    def mux_h264(self, t, data):
        pts = int(t * self.pts_clock)

        pes = DefaultingContainer(
            stream_id = 0b11100000, # video stream number 0
            header = DefaultingContainer(
                PES_scrambling_control = 0,
                PES_priority = 0,
                data_alignment_indicator = False,
                copyright = False,
                original_or_copy = False,
                PTS_DTS_flags = 2, # 3 if DTS else 2
                ESCR_flag = False,
                ES_rate_flag = False,
                DSM_trick_mode_flag = False,
                additional_copy_info_flag = False,
                PES_CRC_flag = False,
                PES_extension_flag = False,
                PTS = pts,
                # DTS = t, # wut
                stuffing = ''),
            data = data)

        pes_data = PES_packet.build(pes)

        self.write_pes_data(self.vid_es_pid, pes_data, pts)

    def mux_latm(self, t, data):
        pts = int(t * self.pts_clock)

        pes = DefaultingContainer(
            stream_id = 0b11000001, # audio stream number 1
            header = DefaultingContainer(
                PES_scrambling_control = 0,
                PES_priority = 0,
                data_alignment_indicator = True,
                copyright = False,
                original_or_copy = False,
                PTS_DTS_flags = 2, # 3 if DTS else 2
                ESCR_flag = False,
                ES_rate_flag = False,
                DSM_trick_mode_flag = False,
                additional_copy_info_flag = False,
                PES_CRC_flag = False,
                PES_extension_flag = False,
                PTS = pts,
                stuffing = ''),
            data = data)

        pes_data = PES_packet.build(pes)

        self.write_pes_data(self.aud_es_pid, pes_data, pts)

    def write_pes_data(self, pid, data, ts=None):
        pcr = ts if pid == self.pcr_pid else None
        
        first_packet = True
        while len(data):
            pcr_v = None
            if first_packet and pcr is not None:
                pcr_v = Container(program_clock_reference_base = pcr, program_clock_reference_extension = 0)

            field = None
            if pcr_v:
                field_length = 8
                field = DefaultingContainer(
                    adaptation_field_length = field_length - 1,
                    disconuity_indicator = False,
                    random_access_indicator = False,
                    elementary_stream_priority_indicator = False,
                    PCR_flag = True,
                    OPCR_flag = False,
                    splicing_point_flag = False,
                    transport_private_data_flag = False,
                    adaptation_field_extension_flag = False,
                    PCR = pcr_v)

            header_data = transport_packet_header.build(
                DefaultingContainer(
                    transport_error_indicator = False,
                    payload_unit_start_indicator = first_packet,
                    transport_priority = False,
                    PID = pid,
                    transport_scrambling_control = 0,
                    adaptation_field_control = 3 if field else 1,
                    continuity_counter = self.continuity_counters[pid] % 16,
                    adaptation_field = field
                )
            )

            data_slice = data[:transport_packet_length - len(header_data)]
            data = data[len(data_slice):]
            
            packet = header_data + data_slice
            if len(packet) < transport_packet_length:
                assert len(data) == 0
                # last packet, pad it
                # pad with an adaptation_field when the pes data length is not given...
                # (otherwise we /could/ pad just pad the data with \xFF...)
                padding_needed = transport_packet_length - len(packet)
                if field:
                    field.adaptation_field_length += padding_needed
                else:
                    assert pcr_v is None
                    if padding_needed == 1:
                        field = DefaultingContainer(adaptation_field_length = 0)
                    else:
                        field = DefaultingContainer(
                                adaptation_field_length = padding_needed-1,
                                disconuity_indicator = False,
                                random_access_indicator = False,
                                elementary_stream_priority_indicator = False,
                                PCR_flag = False,
                                OPCR_flag = False,
                                splicing_point_flag = False,
                                transport_private_data_flag = False,
                                adaptation_field_extension_flag = False,
                            )

                header_data = transport_packet_header.build(
                    DefaultingContainer(
                        transport_error_indicator = False,
                        payload_unit_start_indicator = first_packet,
                        transport_priority = False,
                        PID = pid,
                        transport_scrambling_control = 0,
                        adaptation_field_control = 3,
                        continuity_counter = self.continuity_counters[pid] % 16,
                        adaptation_field = field
                    )
                )
                packet = header_data + data_slice
                assert len(packet) == transport_packet_length

            self.f.write(packet)
            self.continuity_counters[pid] += 1
            first_packet = False




