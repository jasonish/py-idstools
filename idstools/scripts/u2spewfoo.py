# Copyright (c) 2011 Jason Ish
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
#
# An example of how to create a program much like u2spewfoo that comes
# with Snort.

"""A python reimplementation of Snort's u2spewfoo. """

from __future__ import print_function

import sys
import os
import socket
import struct
import string
import logging
import re

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    import argparse
except ImportError as err:
    from idstools.compat.argparse import argparse

from idstools import unified2

# Initialize logging.
logging.basicConfig(level=logging.INFO, format="%(message)s")
LOG = logging.getLogger()

# Create a list of characters we consider printable.
not_printable = "\t\r\n\x0b\x0c"
printable = [c for c in string.printable if c not in not_printable]

def print_char(char):
    c = chr(char)
    if c in printable:
        return c
    return "."

def printable_chars(buf):
    if buf:
        return "".join([c for c in buf if c in printable])
    return ""

def print_raw(raw):
    bytes_per_line = 16
    parts = struct.unpack("B" * len(raw), raw)
    lines = []
    for i in range(int((len(parts) / bytes_per_line)) + 1):
        prefix = "[%5d]" % (i * 16)
        as_hex = " ".join(["%02x" % p for p in parts[i*16:(i*16)+16]])
        printable = "".join([print_char(p) for p in parts[i*16:(i*16)+16]])
        lines.append("%s %-48s  %s" % (prefix, as_hex, printable))
    return "\n".join(lines)

def print_address(addr):
    if len(addr) <= 15:
        return addr
    return re.sub(":::+", "::", addr.replace("0000", ""))

def print_event(event):
    rows = (
        (("sensor id", "sensor-id", str),
         ("event id", "event-id", str),
         ("event second", "event-second", str),
         ("event microsecond", "event-microsecond", str),
         ),
        (("sig id", "signature-id", str),
         ("gen id", "generator-id", str),
         ("revision", "signature-revision", str),
         ("classification", "classification-id", str),
         ),
        (("priority", "priority", str),
         ("ip source", "source-ip", print_address),
         ("ip destination", "destination-ip", print_address),
         ),
        (("src port", "sport-itype", str),
         ("dest port", "dport-icode", str),
         ("protocol", "protocol", str),
         ("impact_flag", "impact-flag", str),
         ("blocked", "blocked", str),
         ),
        (("mpls label", "mpls-label", str),
         ("vlan id", "vlan-id", str),
         ("policy id", "pad2", str),
         ("appid", "appid", printable_chars),
         ),
        )
    print("\n(Event)")
    for row in rows:
        parts = ["%s: %s" % (col[0], col[2](event[col[1]])) for col in row]
        print("\t" + "\t".join(parts))

def print_packet(packet):
    rows = (
        (("sensor id", "sensor-id", str),
         ("event id", "event-id", str),
         ("event second", "event-second", str),
         ),
        (("packet second", "packet-second", str),
         ("packet microsecond", "packet-microsecond", str),
         ),
        (("linktype", "linktype", str),
         ("packet_length", "length", str),
         ),
        )
    print("\nPacket")
    for row in rows:
        parts = ["%s: %s" % (col[0], col[2](packet[col[1]])) for col in row]
        print("\t" + "\t".join(parts))
    print(print_raw(packet["data"]))

def print_extra(extra):
    rows = [
        [["sensor id", str(extra["sensor-id"])],
         ["event id", str(extra["event-id"])],
         ["event second", str(extra["event-second"])],
        ],
        [["type", str(extra["type"])],
         ["datatype", str(extra["data-type"])],
         ["bloblength", str(extra["data-length"])],
     ]]

    body = None

    if extra["type"] == unified2.EXTRA_DATA_TYPE["HTTP_URI"]:
        rows[1] += [["HTTP URI", str(extra["data"])]]
    elif extra["type"] == unified2.EXTRA_DATA_TYPE["HTTP_HOSTNAME"]:
        rows[1] += [["HTTP Hostname", str(extra["data"])]]
    else:
        # Don't yet know how to render this.
        body = extra["data"]

    print("\n(ExtraDataHdr)")
    print("\tevent type: %(event-type)d\tevent length: %(event-length)d" % (
            extra))

    print("\n(ExtraData)")
    for row in rows:
        parts = ["%s: %s" % (col[0], col[1]) for col in row]
        print("\t" + "\t".join(parts))
    if body:
        print(body)

def print_record(record):
    if isinstance(record, unified2.Event):
        print_event(record)
    elif isinstance(record, unified2.Packet):
        print_packet(record)
    elif isinstance(record, unified2.ExtraData):
        print_extra(record)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("filename", nargs="*")
    args = parser.parse_args()

    if not args.filename:
        parser.print_usage()
        return

    reader = unified2.FileRecordReader(*args.filename)
    for record in reader:
        print_record(record)

if __name__ == '__main__':
    sys.exit(main())
