# airplay.py
#
# Copyright 2015, espes
#
# Parts adapted from Livestreamer
#
# Licensed under GPL Version 2 or later
#

import os
import re
import sys
import time
import socket
import struct
import threading
import subprocess
import SocketServer
from collections import defaultdict, namedtuple
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

import biplist
import zeroconf

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import drm

import aac
import mp4
import mpegts


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

        self.config_record = None

    def shutdown(self):
        self.shutdown_request = True
        self.is_shutdown.wait()

    def handle(self):

        while not self.shutdown_request:
            
            header = self.fd.read(128)
            if header == "": break

            size, type_, unkn, timestamp = struct.unpack("<IHHQ", header[:16])

            # timestamp is a 64-bit ntp timestamp
            timestamp = (timestamp >> 32) + float(timestamp & 0xffffffff) / 2**32

            data = self.fd.read(size)
            
            if type_ == 0: # video data
                decrypted_data = self.decryptor.update(data)
                
                self.con.viewer.handle_h264_nalus(timestamp,
                    list(self.parse_NALUs(decrypted_data)))

            elif type_ == 1: # config record
                self.config_record = mp4.AVCDecoderConfigurationRecord.parse(data)
                
                self.con.viewer.handle_h264_nalus(timestamp,
                    self.config_record.sequenceParameterSetNALUnit
                     + self.config_record.pictureParameterSetNALUnit)

            elif type_ == 2: # heartbeat
                pass
            else:
                print "wtf", size, type_, unkn, timestamp

        self.is_shutdown.set()

    def parse_NALUs(self, s):
        assert self.config_record is not None
        length_size = self.config_record.lengthSizeMinusOne + 1
        assert 1 <= length_size <= 4

        i = 0
        while i+length_size <= len(s):
            length, = struct.unpack(">I", s[i:i+length_size].rjust(4, "\x00"))
            i += length_size
            nal = s[i:i+length];
            i += length
            if len(nal) < length:
                raise Exception('bad NALU length: %d' % length)

            yield nal

        assert i == len(s)


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
        print "Initialising FairPlay SAP..."
        st = time.clock()
        self.sap = drm.FairPlaySAP(self.server.parent.airtunesd_filename)
        et = time.clock()
        print "Done! Took %.2f seconds." % (et-st)

        self.sap_stage = 0

        BaseHTTPRequestHandler.setup(self)

    def do_GET(self):
        # print `self.path`
        # print self.headers

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
        # print `self.path`
        # print self.headers

        if self.path == "/fp-setup":
            chal_data = self.rfile.read(int(self.headers["Content-Length"]))
            # print "chal", `chal_data`

            print "Calculating AirPlay challenge stage %d..." % self.sap_stage
            st = time.clock()
            response = self.sap.challenge(3, chal_data, self.sap_stage)
            et = time.clock()
            print "Done! Took %.2f seconds." % (et-st)
            self.sap_stage += 1
            # print "resp", `response`

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
            # print `bplist`

            assert bplist['deviceID'] == device_id

            iv = bplist['param2']

            print "Decrypting AirPlay key..."
            st = time.clock()
            key = self.sap.decrypt_key(bplist['param1'])
            et = time.clock()
            print "Done! Took %.2f seconds. AirPlay key: %s" % (et-st, key.encode("hex"))

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

        v = hdrpieces[0] >> 6 # Version
        assert v == 2
        p = bool(hdrpieces[0] & 32) # Padding
        assert not p
        x = bool(hdrpieces[0] & 16) # Extension header present
        assert not x
        cc = hdrpieces[0] & 15 # CSRC Count
        assert cc == 0
        marker = bool(hdrpieces[1] & 128) # Marker bit
        pt = hdrpieces[1] & 127 # Payload type
        seq = hdrpieces[2] # Sequence number
        ts = hdrpieces[3] # Timestamp
        ssrc = hdrpieces[4]


        bytes = packet[12:]

        decrypted_bytes = self.server.rtp.cipher.decryptor().update(bytes)
        bytes = decrypted_bytes + bytes[len(decrypted_bytes):]

        self.server.rtp.handle_rtp_payload(ts, seq, bytes)



class AirTunesRTPControlHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        # print "RTP Control", self.request

        packet, sock = self.request
        hdrpieces = struct.unpack('!BBHIQI', packet)

        v = hdrpieces[0] >> 6 # Version
        assert v == 2
        p = bool(hdrpieces[0] & 32) # Padding
        assert not p
        x = bool(hdrpieces[0] & 16) # Extension header present
        # assert not x
        cc = hdrpieces[0] & 15 # CSRC Count
        assert cc == 0
        marker = bool(hdrpieces[1] & 128) # Marker bit
        pt = hdrpieces[1] & 127 # Payload type
        seq = hdrpieces[2] # Sequence number
        ts = hdrpieces[3] # Timestamp

        # no SSRC

        ntp_ts = hdrpieces[4]
        ts_next = hdrpieces[5]

        ntp_ts = (ntp_ts >> 32) + float(ntp_ts & 0xffffffff) / 2**32

        # given as seconds since 1900, adjust it to seconds since 1970
        # maybe this'll make more sense when NTP is actualy implemented...
        ntp_ts -= 2208988800

        self.server.rtp.last_sync = (ts, ntp_ts)

        # print ts, ntp_ts, ts_next



class AirTunesRTPTimingHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        pass
        # print "RTP Timing", self.request

class AirTunesRTPEventHandler(SocketServer.StreamRequestHandler):
    def handle(self):
        pass
        # print "RTP Event"

class AirTunesRTP(object):
    # Reading:
    #   https://nto.github.io/AirPlay.html#audio-rtpstreams
    #   http://www.ietf.org/rfc/rfc3550.txt

    def __init__(self, con, url, sdp, key, iv):
        self.con = con

        sdp_audio = sdp.media["audio"]
        assert sdp_audio.proto == "RTP/AVP"
        audio_fmt = sdp.fmtp[sdp_audio.fmt]
        assert audio_fmt["mode"] == "AAC-eld"
        audio_map = sdp.rtpmap[int(sdp_audio.fmt)]
        assert audio_map.encoding == "mpeg4-generic"

        self.sample_rate = int(audio_map.clock)
        self.channels = int(audio_map.parameters[0])
        self.frame_duration = int(audio_fmt["constantDuration"])

        self.cipher = Cipher(algorithms.AES(key),
                             modes.CBC(iv),
                             backend=default_backend())

        self.next_seq = None
        self.last_sync = None


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

        if self.next_seq is not None and seq < self.next_seq:
            return

        if self.last_sync is not None:
            sync_ts, sync_ntp_ts = self.last_sync

            samples_since_sync = ts - sync_ts
            seconds_since_sync = samples_since_sync / float(self.sample_rate)

            timestamp = sync_ntp_ts + seconds_since_sync

            self.con.viewer.handle_aac_frame(timestamp, payload)

        self.next_seq = seq + 1






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
            # print `line`
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
        print "Initialising FairPlay SAP..."
        st = time.clock()
        self.sap = drm.FairPlaySAP(self.server.parent.airtunesd_filename)
        et = time.clock()
        print "Done! Took %.2f seconds." % (et-st)
        self.sap_stage = 0

        BaseHTTPRequestHandler.setup(self)

    def do_POST(self):

        # print `self.path`
        # print self.headers

        if self.path == "/fp-setup":
            chal_data = self.rfile.read(int(self.headers["Content-Length"]))
            # print "chal", `chal_data`

            print "Calculating AirTunes challenge stage %d..." % self.sap_stage
            st = time.clock()
            response = self.sap.challenge(2, chal_data, self.sap_stage)
            et = time.clock()
            print "Done! Took %.2f seconds." % (et-st)
            self.sap_stage += 1
            # print "resp", `response`

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
        # print `self.path`
        # print self.headers

        device_id = int(self.headers["X-Apple-Device-ID"], 16)
        con = self.server.parent.connections[device_id]

        sdp_str = self.rfile.read(int(self.headers["Content-Length"]))
        # print sdp_str

        sdp = SDP(sdp_str)

        iv = sdp.attrs["aesiv"].decode("base64")

        print "Decrypting AirTunes key..."
        st = time.clock()
        key = self.sap.decrypt_key(sdp.attrs["fpaeskey"].decode("base64"))
        et = time.clock()
        print "Done! Took %.2f seconds. AirTunes key: %s" % (et-st, key.encode("hex"))

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
        # print `self.path`
        # print self.headers

        device_id = int(self.headers["X-Apple-Device-ID"], 16)
        con = self.server.parent.connections[device_id]

        transport = self.parse_transport(self.headers["Transport"])
        # print transport

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

        # print `rtransport`

        # why don't I get /audio and /video ???

        self.send_response(200)
        self.send_header("Transport", rtransport)
        self.send_header("Session", "1")
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.end_headers()

    def do_RECORD(self):
        # print `self.path`
        # print self.headers

        self.send_response(200)
        self.send_header("Server", self.version_string())
        self.send_header("CSeq", self.headers["CSeq"])
        self.send_header("Audio-Latency", "0")
        self.end_headers()

    def do_GET_PARAMETER(self):
        # print `self.path`
        # print self.headers

        parameter = self.rfile.read(int(self.headers["Content-Length"]))

        # print `parameter`

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
        # print `self.path`
        # print self.headers

        setting = self.rfile.read(int(self.headers["Content-Length"]))
        # print `setting`

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




class AirplayViewer(object):
    def __init__(self, con):
        self.con = con

        self.vlc = self.find_vlc()
        assert self.vlc

        self.proc = subprocess.Popen([self.vlc, "--file-caching=3000", "-"],
            stdin=subprocess.PIPE,
            close_fds=True)

        self.muxer = mpegts.TSMuxer(self.proc.stdin, True, True)
        self.muxer.write_tables()


    def check_paths(self, exes, paths):
        for path in paths:
            for exe in exes:
                path = os.path.expanduser(os.path.join(path, exe))
                if os.path.isfile(path):
                    return path
        return None

    def find_vlc(self):
        paths = os.environ.get("PATH", "").split(":")
        if "darwin" in sys.platform:
            paths += ["/Applications/VLC.app/Contents/MacOS/"]
            paths += ["~/Applications/VLC.app/Contents/MacOS/"]
            return self.check_paths(("VLC", "vlc"), paths)
        else:
            return self.check_paths(("vlc",), paths)

    def handle_aac_frame(self, ts, frame):
        # hax
        channels = self.con.rtp.channels
        sample_rate = self.con.rtp.sample_rate
        frame_duration = self.con.rtp.frame_duration

        packets = aac.latm_mux_aac_eld(channels, sample_rate, frame_duration, [frame])

        self.muxer.mux_latm(ts, ''.join(packets))

    def handle_h264_nalus(self, ts, nalus):
        self.muxer.mux_h264(ts, ''.join('\x00\x00\x00\x01'+nalu for nalu in nalus))



class AirplayConnection(object):
    def __init__(self, server):
        self.server = server

        self.mirroring_stream = None
        self.mirroring_thread = None

        self.rtp = None
        
        self.viewer = AirplayViewer(self)

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
        self.service_name = "Slave in the Magic Mirror"

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
        self.zc.register_service(info)

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
        self.zc.register_service(info)

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

        self.airplay_thread = threading.Thread(
            target=self.airplay_server.serve_forever)
        self.airplay_mirroring_thread = threading.Thread(
            target=self.airplay_mirroring_server.serve_forever)
        # self.airtunes_thead = threading.Thread(
        #     target=self.airtunes_server.serve_forever)

        self.airplay_thread.start()
        self.airplay_mirroring_thread.start()
        # self.airtunes_thead.start()

        print 'Ready'

        try:
            self.airtunes_server.serve_forever()
        finally:
            for con in self.connections.itervalues():
                con.shutdown()

            self.airplay_server.shutdown()
            self.airplay_mirroring_server.shutdown()
            # self.airtunes_server.shutdown()

            self.airplay_thread.join()
            self.airplay_mirroring_thread.join()
            # self.airtunes_thead.join()

            self.zc.close()

if __name__ == "__main__":
    server = AirplayServer("airtunesd")
    server.run()


