# Copyright (c) 2015 Jason Ish
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""Convert packets in EVE logs to pcap.

eve2pcap will convert the packets or the payloads found in an eve log
file to a pcap file.

Note that payload conversion requires Scapy, and will not recreate the
original packets as the headers need to be built on the fly from the
available information in the eve log.

"""

from __future__ import print_function

import sys
import os
import json
import argparse
import base64
from datetime import datetime
import ctypes
import ctypes.util

PCAP_ERRBUF_SIZE = 256

DLT_EN10MB = 1
DLT_RAW = 12

DLT = {
    "DN10MB": DLT_EN10MB,
    "RAW": DLT_RAW,
}

libpcap_filename = ctypes.util.find_library("pcap")
if not libpcap_filename:
    has_libpcap = False
else:
    has_libpcap = True
    libpcap = ctypes.cdll.LoadLibrary(libpcap_filename)
    libpcap.pcap_geterr.restype = ctypes.c_char_p
    pcap_errbuf = ctypes.create_string_buffer(PCAP_ERRBUF_SIZE)
    libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library("c"))

# For now, Scapy is required for payload to packet conversion. And do
# it quietly.
try:
    orig_stderr = sys.stderr
    sys.stderr = open(os.devnull, "w")
    from scapy.all import *
    has_scapy = True
except:
    has_scapy = False
finally:
    sys.stderr = orig_stderr

class pcap_pkthdr(ctypes.Structure):
    """Internal class representing struct pcap_pkthdr. """
    _fields_ = [
        ("ts_sec", ctypes.c_ulong),
        ("ts_usec", ctypes.c_ulong),
        ("caplen", ctypes.c_uint32),
        ("pktlen", ctypes.c_uint32),
    ]

class Pcap:

    def __init__(self, pcap_t):
        self._pcap_t = pcap_t

    @classmethod
    def open_dead(cls, linktype, snaplen):
        pcap_t = libpcap.pcap_open_dead(linktype, snaplen)
        if not pcap_t:
            raise Exception(pcap_errbuf.value)
        return cls(pcap_t)

    def dump_open(self, filename):
        if filename == "-":
            return self.dump_fopen(sys.stdout.fileno())
        pcap_dumper_t = libpcap.pcap_dump_open(self._pcap_t, filename)
        if not pcap_dumper_t:
            print(pcap_errbuf.value)
            raise Exception(pcap_errbuf.value)
        return PcapDumper(pcap_dumper_t)

    def dump_fopen(self, fileno):
        """Not quite a direct wrapper around pcap_dump_fopen - instead of a
        file pointer, take a file descriptor.
        """
        fp = libc.fdopen(fileno, "w")
        pcap_dumper_t = libpcap.pcap_dump_fopen(self._pcap_t, fp)
        if not pcap_dumper_t:
            raise Exception(self.pcap_errbuf.value)
        return PcapDumper(pcap_dumper_t)

class PcapDumper:
    """ Minimal wrapper around pcap_dumper_t. """

    def __init__(self, pcap_dumper_t):
        self._pcap_dumper_t = pcap_dumper_t

    def dump(self, pkthdr, packet):
        libpcap.pcap_dump(self._pcap_dumper_t, ctypes.byref(pkthdr), packet)

    def close(self):
        libpcap.pcap_dump_close(self._pcap_dumper_t)

def parse_timestamp(timestamp):
    dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f-0600")
    return (int(dt.strftime("%s")), dt.microsecond)

def eve2pcap(event):
    if not "packet" in event:
        return None, None
    packet = base64.b64decode(event["packet"])
    hdr = pcap_pkthdr()
    hdr.ts_sec, hdr.ts_usec = parse_timestamp(
        event["timestamp"])
    hdr.pktlen = len(packet)
    hdr.caplen = len(packet)
    return (hdr, packet)

def payload2packet(event):
    if not "payload" in event:
        return None, None
    payload = base64.b64decode(event["payload"])
    packet = IP(src=event["src_ip"], dst=event["dest_ip"])
    if event["proto"] == "TCP":
        packet = packet / TCP(sport=event["src_port"], dport=event["dest_port"])
    elif event["proto"] == "UDP":
        packet = packet / UDP(sport=event["src_port"], dport=event["dest_port"])
    elif event["proto"] == "ICMP":
        packet = packet / ICMP(type=event["icmp_type"], code=event["icmp_code"])
    else:
        print("Unhandled protocol: %s" % event["proto"], file=sys.stderr)
        try:
            protonum = int(event["proto"])
            packet.proto = protonum
        except:
            pass

    packet = packet / payload
    packet = packet.build()

    hdr = pcap_pkthdr()
    hdr.ts_sec, hdr.ts_usec = parse_timestamp(
        event["timestamp"])
    hdr.pktlen = len(packet)
    hdr.caplen = len(packet)

    return (hdr, packet)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("-o", metavar="<filename>",
                        dest="output", default="-",
                        help="Output filename")
    parser.add_argument("--payload", action="store_true",
                        help="Convert payload instead of packet")
    parser.add_argument("--dlt")
    parser.add_argument("filenames", nargs="+")
    args = parser.parse_args()

    if not has_libpcap:
        print("ERROR: Failed to load libpcap.")
        return 1

    # Bail if payload is requested but we don't have Scapy.
    if args.payload and not has_scapy:
        print("ERROR: Scapy is required for payload conversion.",
              file=sys.stderr)
        return 1

    dlt = None

    if args.dlt:
        if args.dlt.upper() in DLT:
            dlt = DLT[args.dlt.upper()]
        else:
            print("ERROR: Unknown DLT type: %s" % (args.dlt), file=sys.stderr)
            return 1
    elif args.payload:
        dlt = DLT_RAW
    else:
        dlt = DLT_EN10MB

    # Bail if writing out to a tty.
    if args.output == "-" and os.isatty(sys.stdout.fileno()):
        print("Cowardly refusing to write output to terminal.", file=sys.stderr)
        return 1

    pcap = Pcap.open_dead(dlt, 65535)
    dumper = pcap.dump_open(args.output)

    for filename in args.filenames:
        with open(filename) as fileobj:
            for line in fileobj:
                event = json.loads(line)
                hdr, packet = None, None
                if args.payload:
                    hdr, packet = payload2packet(event)
                elif "packet" in event:
                    hdr, packet = eve2pcap(event)
                if hdr and packet:
                    dumper.dump(hdr, ctypes.c_char_p(packet))

    dumper.close()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
