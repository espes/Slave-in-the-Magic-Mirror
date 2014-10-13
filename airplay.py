# airplay.py
#
# Copyright 2014, espes
#
# Parts adapted from rtmp-livestreaming
# Copyright 2014, Michael Liao
#
# Licensed under GPL Version 3 or later
#

import sys
import time
import select
import socket
import struct
import threading
import SocketServer
from collections import defaultdict, namedtuple, OrderedDict
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

import biplist
import zeroconf

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import drm


class BytesIO(object):
    def __init__(self, data):
        self._data = data
        self._position = 0
        self._length = len(data)

    def read_uint8(self):
        if self._position >= self._length:
            raise IOError('EOF of BytesIO')
        n = ord(self._data[self._position])
        self._position += 1
        return n

    def read_uint16(self):
        return (self.read_uint8() << 8) + self.read_uint8()

    def read_uint24(self):
        return ((self.read_uint8() << 16)
            + (self.read_uint8() << 8)
            + self.read_uint8())

    def read_uint32(self):
        return ((self.read_uint8() << 24)
            + (self.read_uint8() << 16)
            + (self.read_uint8() << 8)
            + self.read_uint8())

    def read_uint64(self):
        return ((self.read_uint8() << 56)
            + (self.read_uint8() << 48)
            + (self.read_uint8() << 40)
            + (self.read_uint8() << 32)
            + (self.read_uint8() << 24)
            + (self.read_uint8() << 16)
            + (self.read_uint8() << 8)
            + self.read_uint8())

    def read_bytes(self, n):
        if self._position + n > self._length:
            raise IOError('Skip n bytes cause EOF.')
        start = self._position
        self._position = self._position + n
        return self._data[start:self._position]

    def available(self):
        return self._length - self._position

    def skip(self, n):
        if self._position + n > self._length:
            raise IOError('Skip n bytes cause EOF.')
        self._position = self._position + n

    def left(self):
        return self._data[self._position:]

    def __getitem__(self, key):
        return self._data[key]


class AirPlayMirroringVideoStream(object):
    # Reading:
    #   https://nto.github.io/AirPlay.html#screenmirroring-streampackets

    def __init__(self, con, fd, key, iv):
        self.con = con
        self.fd = fd

        self.cipher = Cipher(algorithms.AES(key),
                             modes.CTR(iv),
                             backend=default_backend())
        self.decryptor = self.cipher.decryptor()

        self.shutdown_request = False
        self.is_shutdown = threading.Event()

    def shutdown(self):
        self.shutdown_request = True
        self.is_shutdown.wait()

    def handle(self):

        self.of = open("/tmp/vids.h264", "wb")

        while not self.shutdown_request:
            
            header = self.fd.read(128)
            if header == "": break

            size, type_, unkn, timestamp = struct.unpack("<IHHB", header[:9])

            data = self.fd.read(size)
            
            if type_ == 0: # video data
                decrypted_data = self.decryptor.update(data)

                self._parse_NALUs(BytesIO(decrypted_data))
            elif type_ == 1: # codec data
                self._parse_config_record(BytesIO(data))

            elif type_ == 2: # heartbeat
                pass
            else:
                print "wtf", size, type_, unkn, timestamp

        self.of.close()

        self.is_shutdown.set()

    def _parse_config_record(self, s):
        """Parses H.264 AVCC extradata and writes it out as Annex B"""

        ver = s.read_uint8()
        if ver != 1:
            raise Exception('Bad config version in AVCDecoderConfigurationRecord: %d' % ver)

        avc_profile_indication = s.read_uint8()
        print 'profile:', avc_profile_indication

        profile_compatibility = s.read_uint8()
        avc_level_indication = s.read_uint8()
        length_size_minus_one = s.read_uint8() & 0x03
        print 'length_size_minus_one:', length_size_minus_one

        num_of_sps = s.read_uint8() & 0x1f
        print 'num_of_sps:', num_of_sps
        for i in range(num_of_sps):
            sps_length = s.read_uint16()
            spsNALU = s.read_bytes(sps_length)
            print 'spsNALU Length:', sps_length
            print 'spsNALU:', hex(ord(spsNALU[0]))

            self.of.write('\x00\x00\x00\x01')
            self.of.write(spsNALU)

        num_of_pps = s.read_uint8()
        print 'num_of_pps:', num_of_pps
        for i in range(num_of_pps):
            pps_length = s.read_uint16()
            ppsNALU = s.read_bytes(pps_length)
            print 'ppsNALU Length:', pps_length
            print 'ppsNALU:', hex(ord(ppsNALU[0]))
            
            self.of.write('\x00\x00\x00\x01')
            self.of.write(ppsNALU)

        self._nalu_length_size = length_size_minus_one + 1
        print 'data available shoud be 0:', s.available()

    def _parse_NALUs(self, s):
        """Parses a series of H.264 AVCC NALUs and writes them out as Annex B"""

        nalu_length_size = self._nalu_length_size

        # split each NALUs and add '00000001' for each NALUs:
        while s.available() > 0:
            # the max value of nalu_length_size is 4 (=0x03 + 1)
            length = 0
            if nalu_length_size==4:
                length = s.read_uint32()
            elif nalu_length_size==3:
                length = s.read_uint24()
            elif nalu_length_size==2:
                length = s.read_uint16()
            else:
                length = s.read_uint8()
            
            if s.available() < length:
                raise Exception('bad NALU length: %d' % length)

            self.of.write('\x00\x00\x00\x01')
            self.of.write(s.read_bytes(length))


class ThreadedHTTPServer(SocketServer.ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""


class AirPlayHTTPHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        sys.stderr.write("AirPlay: ")
        BaseHTTPRequestHandler.log_message(self, format, *args)

class AirPlayMirroringHTTPHandler(BaseHTTPRequestHandler):
    # Reading:
    #   https://nto.github.io/AirPlay.html#screenmirroring-httprequests

    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):
        sys.stderr.write("Mirroring: ")
        BaseHTTPRequestHandler.log_message(self, format, *args)

    def send_response(self, code, message=None):
        self.log_request(code)
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''
        if self.request_version != 'HTTP/0.9':
            self.wfile.write("%s %d %s\r\n" %
                             (self.protocol_version, code, message))

    def setup(self):
        self.sap = drm.FairPlaySAP(self.server.parent.airtunesd_filename)
        self.sap_stage = 0

        BaseHTTPRequestHandler.setup(self)

    def do_GET(self):
        print `self.path`
        print self.headers

        if self.path == "/stream.xml":
            response = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
 <key>height</key>
 <integer>720</integer>
 <key>overscanned</key>
 <true/>
 <key>version</key>
 <string>120.2</string>
 <key>width</key>
 <integer>1280</integer>
 </dict>
</plist>
"""

            self.send_response(200)
            self.send_header("Date", self.date_time_string())
            self.send_header("Content-Type", "text/x-apple-plist+xml")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()

            self.wfile.write(response)
        else:
            self.send_error(404)

    def do_POST(self):
        print `self.path`
        print self.headers

        if self.path == "/fp-setup":
            chal_data = self.rfile.read(int(self.headers["Content-Length"]))
            print "chal", `chal_data`

            response = self.sap.challenge(3, chal_data, self.sap_stage)
            self.sap_stage += 1
            print "resp", `response`

            self.send_response(200)
            self.send_header("Date", self.date_time_string())
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(response)))

            self.end_headers()

            self.wfile.write(response)
        
        elif self.path == "/stream":

            device_id = int(self.headers["X-Apple-Device-ID"], 16)
            con = self.server.parent.connections[device_id]

            bplist_data = self.rfile.read(int(self.headers["Content-Length"]))
            bplist = biplist.readPlistFromString(bplist_data)
            print `bplist`

            assert bplist['deviceID'] == device_id

            iv = bplist['param2']
            key = self.sap.decrypt_key(bplist['param1'])
            print "decrypted key!", `key`

            con.handle_mirroring_video_stream(self.rfile, key, iv)
            self.close_connection = 1

        else:
            self.send_error(404)


class AirTunesRTPDataHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        # print "RTP Data"

        packet, sock = self.request

        # See http://tools.ietf.org/html/rfc3550#section-5.1

        hdrpieces = struct.unpack('!BBHII', packet[:12])

        v = hdrpieces[0] >> 6
        assert v == 2
        # Padding
        p = bool(hdrpieces[0] & 32)
        # Extension header present
        x = bool(hdrpieces[0] & 16)
        # CSRC Count
        cc = bool(hdrpieces[0] & 15)
        # Marker bit
        marker = bool(hdrpieces[1] & 128)
        # Payload type
        pt = hdrpieces[1] & 127
        # Sequence number
        seq = hdrpieces[2]
        # Timestamp
        ts = hdrpieces[3]
        ssrc = hdrpieces[4]
        headerlen = 12 + cc * 4
        
        # XXX throwing away csrc info for now
        bytes = packet[headerlen:]

        if x:
            # Only one extension header
            xhdrtype, xhdrlen = struct.unpack('!HH', bytes[:4])
            xhdrdata = bytes[4:4+xhdrlen*4]
            bytes = bytes[xhdrlen*4 + 4:]
        else:
            xhdrtype, xhdrdata = None, None

        if p:
            # padding
            padlen = struct.unpack('!B', bytes[-1])[0]
            if padlen:
                bytes = bytes[:-padlen]

        decrypted_bytes = self.server.rtp.cipher.decryptor().update(bytes)
        bytes = decrypted_bytes + bytes[len(decrypted_bytes):]

        # print "-", bytes.encode("hex")

        self.server.rtp.handle_rtp_payload(ts, seq, bytes)



class AirTunesRTPControlHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        print "RTP Control", self.request

class AirTunesRTPTimingHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        print "RTP Timing", self.request

class AirTunesRTPEventHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        print "RTP Event"

class AirTunesRTP(object):
    # Reading:
    #   https://nto.github.io/AirPlay.html#audio-rtpstreams
    #   http://www.ietf.org/rfc/rfc3550.txt

    def __init__(self, con, url, sdp, key, iv):
        self.con = con

        sdp_audio = sdp.media["audio"]
        assert sdp_audio.proto == "RTP/AVP"
        assert sdp.fmtp[sdp_audio.fmt]["mode"] == "AAC-eld"
        assert sdp.rtpmap[int(sdp_audio.fmt)].encoding == "mpeg4-generic"

        self.cipher = Cipher(algorithms.AES(key),
                             modes.CBC(iv),
                             backend=default_backend())

        self.of = open("/tmp/aud1.mp4", "wb")

        self.packet_queue = OrderedDict()



    def start(self, is_udp, cport, tport):
        assert is_udp

        self.cport = cport
        self.tport = tport

        self.dserver = SocketServer.UDPServer(('', 0), AirTunesRTPDataHandler)
        self.cserver = SocketServer.UDPServer(('', 0), AirTunesRTPControlHandler)
        self.tserver = SocketServer.UDPServer(('', 0), AirTunesRTPTimingHandler)
        self.eserver = SocketServer.TCPServer(('', 0), AirTunesRTPEventHandler)

        self.dserver.rtp = self
        self.cserver.rtp = self
        self.tserver.rtp = self
        self.eserver.rtp = self

        self.dthread = threading.Thread(target=self.dserver.serve_forever)
        self.cthread = threading.Thread(target=self.cserver.serve_forever)
        self.tthread = threading.Thread(target=self.tserver.serve_forever)
        self.ethread = threading.Thread(target=self.eserver.serve_forever)

        self.dthread.start()
        self.cthread.start()
        self.tthread.start()
        self.ethread.start()

    def shutdown(self):
        self.dserver.shutdown()
        self.cserver.shutdown()
        self.tserver.shutdown()
        self.eserver.shutdown()

        self.dthread.join()
        self.cthread.join()
        self.tthread.join()
        self.ethread.join()

    def handle_rtp_payload(self, ts, seq, payload):

        if seq in self.packet_queue:
            return
        self.packet_queue[seq] = (ts, payload)

        # payload should be rfc3640 per spec, but looks like raw aac packets instead





class SDP(object):
    # Reading:
    #   http://www.ietf.org/rfc/rfc4566.txt

    Rtpmap = namedtuple('Rtpmap', 'encoding clock parameters')
    Media = namedtuple('Media', 'port proto fmt')

    def __init__(self, s):

        self.desc = {}
        self.attrs = {}

        self.media = {}
        self.rtpmap = {}
        self.fmtp = {}

        for line in s.strip().split("\r\n"):
            print `line`
            key, value = line.split("=", 1)

            if key == "a":
                ak, av = value.split(":", 1)
                # See http://tools.ietf.org/html/rfc4566#section-6
                if ak == "rtpmap":
                    payload, parameters = av.split(' ')
                    parameters = parameters.split('/')
                    self.rtpmap[int(payload)] = self.Rtpmap(
                        parameters[0], parameters[1], parameters[2:])
                elif ak == "fmtp":
                    format, parameters = av.split(' ', 1)
                    parameters_d = {}
                    for p in parameters.split('; '):
                        pk, pv = p.split("=", 1)
                        parameters_d[pk] = pv
                    self.fmtp[format] = parameters_d
                else:
                    self.attrs[ak] = av
            elif key == "m":
                # See http://tools.ietf.org/html/rfc4566#section-5.14
                media_type, port, proto, fmt = value.split(' ')
                self.media[media_type] = self.Media(port, proto, fmt)
            else:
                self.desc[key] = value

class AirTunesRTSPHandler(BaseHTTPRequestHandler):
    # Reading:
    #   https://nto.github.io/AirPlay.html#audio-rtsprequests
    #   http://www.ietf.org/rfc/rfc2326.txt

    def log_message(self, format, *args):
        sys.stderr.write("AirTunes: ")
        BaseHTTPRequestHandler.log_message(self, format, *args)

    def parse_request(self):
        self.raw_requestline = self.raw_requestline.replace("RTSP/1.0", "HTTP/1.1")

        r = BaseHTTPRequestHandler.parse_request(self)
        self.protocol_version = "RTSP/1.0"
        self.close_connection = 0
        return r

    def send_response(self, code, message=None):
        self.log_request(code)
        if message is None:
            if code in self.responses:
                message = self.responses[code][0]
            else:
                message = ''

        self.wfile.write("%s %d %s\r\n" %
                         (self.protocol_version, code, message))

    def version_string(self):
        return "AirTunes/120.2"

    def setup(self):
        self.sap = drm.FairPlaySAP(self.server.parent.airtunesd_filename)
        self.sap_stage = 0

        BaseHTTPRequestHandler.setup(self)

    def do_POST(self):

        print `self.path`
        print self.headers

        if self.path == "/fp-setup":
            chal_data = self.rfile.read(int(self.headers["Content-Length"]))

            print "chal", `chal_data`

            response = self.sap.challenge(2, chal_data, self.sap_stage)
            self.sap_stage += 1
            print "resp", `response`

            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(response)))
            self.send_header("Server", self.version_string())
            self.send_header("CSeq", self.headers["CSeq"])
            self.end_headers()

            self.wfile.write(response)

        else:
            self.send_error(404)

    def do_ANNOUNCE(self):
        print `self.path`
        print self.headers

        device_id = int(self.headers["X-Apple-Device-ID"], 16)
        con = self.server.parent.connections[device_id]

        sdp_str = self.rfile.read(int(self.headers["Content-Length"]))
        print sdp_str

        sdp = SDP(sdp_str)

        iv = sdp.attrs["aesiv"].decode("base64")
        key = self.sap.decrypt_key(sdp.attrs["fpaeskey"].decode("base64"))
        print "decrypted key!", `key`

        con.rtp = AirTunesRTP(con, self.path, sdp, key, iv)

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def parse_transport(self, s):
        r = {}
        for v in s.split(";"):
            if "=" in v:
                key, value = v.split("=", 1)
                r[key] = value
            else:
                r[v] = None
        return r

    def do_SETUP(self):
        print `self.path`
        print self.headers

        device_id = int(self.headers["X-Apple-Device-ID"], 16)
        con = self.server.parent.connections[device_id]

        transport = self.parse_transport(self.headers["Transport"])
        print transport

        is_udp = "RTP/AVP/UDP" in transport
        con.rtp.start(is_udp, int(transport["control_port"]), int(transport["timing_port"]))

        server_port = con.rtp.dserver.server_address[1]
        control_port = con.rtp.cserver.server_address[1]
        timing_port = con.rtp.tserver.server_address[1]
        event_port = con.rtp.eserver.server_address[1]

        rtransport = ";".join((
            "RTP/AVP/UDP",
            "unicast",
            "mode=record",
            "server_port=%i" % server_port,
            "control_port=%i" % control_port,
            "timing_port=%i" % timing_port,
            "event_port=%i" % event_port,
        ))

        print `rtransport`

        # why don't I get /audio and /video ???

        self.send_response(200)
        self.send_header("Transport", rtransport)
        self.send_header("Session", "1")
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_RECORD(self):
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.send_header("Audio-Latency", "0")
        self.end_headers()

    def do_GET_PARAMETER(self):
        print `self.path`
        print self.headers

        parameter = self.rfile.read(int(self.headers["Content-Length"]))

        print `parameter`

        parameter = parameter.strip()

        if parameter == "volume":
            self.send_response(200)
            self.send_header("Server", self.version_string())
            self.send_header("CSeq", self.headers["CSeq"])
            self.send_header("volume", "0.000000")
            self.end_headers()
        else:
            raise NotImplementedError


    def do_SET_PARAMETER(self):
        print `self.path`
        print self.headers

        setting = self.rfile.read(int(self.headers["Content-Length"]))
        print `setting`

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Public", ', '.join([
            "ANNOUNCE", "SETUP", "PLAY", "DESCRIBE", "REDIRECT", "RECORD", "PAUSE", "FLUSH",
            "TEARDOWN", "OPTIONS", "GET_PARAMETER", "SET_PARAMETER", "POST", "GET"
        ]))
        self.send_header("Server", self.version_string())
        self.end_headers()

    def do_FLUSH(self):
        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.end_headers()


class AirplayConnection(object):
    def __init__(self, server):
        self.server = server

        self.mirroring_stream = None
        self.mirroring_thread = None

        self.rtp = None

    def handle_mirroring_video_stream(self, fd, key, iv):
        self.mirroring_thread = threading.current_thread()
        self.mirroring_stream = AirPlayMirroringVideoStream(self, fd, key, iv)
        self.mirroring_stream.handle()

    def shutdown(self):
        if self.mirroring_stream:
            self.mirroring_stream.shutdown()
            self.mirroring_thread.join()
            self.mirroring_stream = None
            self.mirroring_thread = None

        if self.rtp:
            self.rtp.shutdown()
            self.rtp = None



class AirplayServer(object):
    def __init__(self, airtunesd_filename=None):
        self.airtunesd_filename = airtunesd_filename

        self.airtunes_port = 49152
        self.airplay_port = 7000
        self.airplay_mirroring_port = 7100

        self.zc = None
        self.airplay_server = None
        self.airplay_mirroring_server = None
        self.airtunes_server = None

        self.local_ip = self.get_local_ip()

        # usually a mac adress, but ceebs
        self.device_id = ("11", "22", "33", "44", "55", "66")
        self.service_name = "lolol"

        self.connections = defaultdict(lambda: AirplayConnection(self))

    def get_local_ip(self):
        # Really the only cross-platform way without adding a dependency
        # Use DNS so we don't look sus to outgoing firewalls.
        # Note no packets are actually sent.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 53))
        r = s.getsockname()[0]
        s.close()
        return r

    def register_airplay(self, port):
        # See https://nto.github.io/AirPlay.html#servicediscovery-airplayservice
        info = zeroconf.ServiceInfo(
            "_airplay._tcp.local.",
            self.service_name+"._airplay._tcp.local.",
            address=socket.inet_aton(self.local_ip),
            port=port,
            properties={
                'deviceid': u':'.join(self.device_id),
                'features': u'0x39f7',
                'model' : u'AppleTV2,1',
                'srcvers': u'120.2',
            }
        )
        self.zc.registerService(info)

    def register_airtunes(self, port):
        # See https://nto.github.io/AirPlay.html#servicediscovery-airtunesservice
        info = zeroconf.ServiceInfo(
            "_raop._tcp.local.",
            ''.join(self.device_id)+"@"+self.service_name+"._raop._tcp.local.",
            address=socket.inet_aton(self.local_ip),
            port=port,
            properties={
                'txtvers' : u'1',
                'ch': u'2', #audio channels: stereo
                'cn': u'0,1,2,3', #audio codecs
                'da': u'true',
                'et': u'0,3', #supported encryption types
                'md': u'0,1,2', #supported metadata types
                'pw': u'false', #password required
                'sv': u'false',
                'sr': u'44100', #audio sample rate: 44100 Hz
                'ss': u'16', #audio sample size: 16-bit
                'tp': u'UDP',
                'vn': u'65537',
                'vs': u'120.2',
                'sf': u'0x4',
            }
        )
        self.zc.registerService(info)

    def run(self):

        self.zc = zeroconf.Zeroconf()
        self.register_airtunes(self.airtunes_port)
        self.register_airplay(self.airplay_port)


        self.airplay_server = ThreadedHTTPServer(
            ('', self.airplay_port), AirPlayHTTPHandler)

        self.airplay_mirroring_server = ThreadedHTTPServer(
            ('', self.airplay_mirroring_port), AirPlayMirroringHTTPHandler)

        self.airtunes_server = ThreadedHTTPServer(
            ('', self.airtunes_port), AirTunesRTSPHandler)

        self.airplay_server.parent = self
        self.airplay_mirroring_server.parent = self
        self.airtunes_server.parent = self

        print 'Starting servers'
        self.airplay_thread = threading.Thread(
            target=self.airplay_server.serve_forever)
        self.airplay_mirroring_thread = threading.Thread(
            target=self.airplay_mirroring_server.serve_forever)

        self.airplay_thread.start()
        self.airplay_mirroring_thread.start()

        try:
            self.airtunes_server.serve_forever()
        finally:
            for con in self.connections.itervalues():
                con.shutdown()

            self.airplay_server.shutdown()
            self.airplay_mirroring_server.shutdown()

            self.airplay_thread.join()
            self.airplay_mirroring_thread.join()

            self.zc.close()

if __name__ == "__main__":
    server = AirplayServer("airtunesd_44")
    server.run()


