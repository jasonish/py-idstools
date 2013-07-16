#! /usr/bin/env python
#
# An example of how to create a program much like u2spewfoo that comes
# with Snort.

from __future__ import print_function

import sys
import os
import socket
import struct
import string

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))))

from idstools import unified2

# Create a list of characters we consider printable.
not_printable = "\t\r\n\x0b\x0c"
printable = [c for c in string.printable if c not in not_printable]

def print_ip(addr):
    if len(addr) == 4:
        return socket.inet_ntoa(addr)
    else:
        parts = struct.unpack("H" * (len(addr) / 2), addr)
        return ":".join("%x" % p for p in parts)

def print_char(char):
    c = chr(char)
    if c in printable:
        return c
    return "."

def print_raw(raw):
    bytes_per_line = 16
    parts = struct.unpack("B" * len(raw), raw)
    lines = []
    for i in range((len(parts) / bytes_per_line) + 1):
        prefix = "[%5d]" % (i * 16)
        as_hex = " ".join(["%02x" % p for p in parts[i*16:(i*16)+16]])
        printable = "".join([print_char(p) for p in parts[i*16:(i*16)+16]])
        lines.append("%s %s  %s" % (prefix, as_hex, printable))
    return "\n".join(lines)

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
         ("ip source", "ip-source", print_ip),
         ("ip destination", "ip-destination", print_ip),
         ),
        (("src port", "sport-itype", str),
         ("dest port", "dport-icode", str),
         ("protocol", "protocol", str),
         ("impact_flag", "impact-flag", str),
         ("blocked", "blocked", str),
         ),
        (("mpls label", "mpls-label", str),
         ("vlan id", "vlan-id", str),
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
    rows = (
        (("sensor id", "sensor-id", str),
         ("event id", "event-id", str),
         ("event second", "event-second", str),
         ),
        (("type", "type", str),
         ("datatype", "data-type", str),
         ("bloglength", "data-length", str),
         ))

    print("\n(ExtraDataHdr)")
    print("\tevent type: %(event-type)d\tevent length: %(event-length)d" % (
            extra))

    print("\n(ExtraData)")
    for row in rows:
        parts = ["%s: %s" % (col[0], col[2](extra[col[1]])) for col in row]
        print("\t" + "\t".join(parts))
    print(extra["data"])

def print_record(record):
    if record.type in unified2.EVENT_TYPES:
        print_event(record.value)
    elif record.type == unified2.PACKET:
        print_packet(record.value)
    elif record.type == unified2.EXTRA_DATA:
        print_extra(record.value)

def main():

    files = sys.argv[1:]
    if not files:
        print("usage: %s <file>..." % (sys.argv[0]))
        return 1

    reader = unified2.FileRecordReader(sys.argv[1:])
    for record in reader:
        print_record(record)

if __name__ == '__main__':
    sys.exit(main())
