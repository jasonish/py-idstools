#! /usr/bin/env python
#
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

"""Read unified2 log files and output events as JSON

::

    usage: u2json.py [options] <filename>...

    options:
	-C <classification.config>
	-G <gen-msg.map>
	-S <sid-msg.map>

Providing classification and map files are optional and will be used
to resolve event ID's to event descriptions.
"""

from __future__ import print_function

import sys
import os
import getopt
import socket
import time
import base64
import json
import struct
import socket
from datetime import datetime
from collections import OrderedDict

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from idstools import unified2
from idstools import maps

proto_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

def get_tzoffset(sec):
    offset = datetime.fromtimestamp(sec) - datetime.utcfromtimestamp(sec)
    if offset.days == -1:
        return "-%02d%02d" % (
            (86400 - offset.seconds) / 3600, (86400 - offset.seconds) % 3600)
    else:
        return "+%02d%02d" % (
            offset.seconds / 3600, offset.seconds % 3600)

def render_timestamp(sec, usec):
    tt = time.localtime(sec)
    return "%04d-%02d-%02dT%02d:%02d:%02d.%06d%s" % (
        tt.tm_year, tt.tm_mon, tt.tm_mday, tt.tm_hour, tt.tm_min, tt.tm_sec, 
        usec, get_tzoffset(sec))

def print_event(event, msgmap, classmap):

    for packet in event["packets"]:
        packet["data"] = base64.b64encode(packet["data"])
        packet["timestamp"] = render_timestamp(
            packet["packet-second"], packet["packet-microsecond"])
        del(packet["packet-second"])
        del(packet["packet-microsecond"])
        del(packet["event-second"])
        del(packet["sensor-id"])
        del(packet["event-id"])

    for extra_data in event["extra-data"]:
        del(extra_data["event-second"])
        del(extra_data["sensor-id"])
        del(extra_data["event-id"])

    event["timestamp"] = render_timestamp(
        event["event-second"], event["event-microsecond"])
    del(event["event-second"])
    del(event["event-microsecond"])
    del(event["event-id"])

    if event["protocol"] in [socket.IPPROTO_UDP, socket.IPPROTO_TCP]:
        event["source-port"] = event["sport-itype"]
        event["destination-port"] = event["dport-icode"]
    elif event["protocol"] == socket.IPPROTO_ICMP:
        event["icmp-type"] = event["sport-itype"]
        event["icmp-code"] = event["dport-icode"]
    del(event["sport-itype"])
    del(event["dport-icode"])

    msg_entry = msgmap.get(event["generator-id"], event["signature-id"])
    if msg_entry:
        event["signature"] = msg_entry["msg"]
    else:
        event["signature"] = "Snort Event"

    class_entry = classmap.get(event["classification-id"])
    if class_entry:
        event["classtype"] = class_entry["name"]

    if event["protocol"] in proto_map:
        event["protocol"] = proto_map[event["protocol"]]

    print(json.dumps(event))

def usage(fileobj=sys.stderr):
    print("usage: %s [options] <filename>..." % sys.argv[0], file=fileobj)
    print("")
    print("options:")
    print("\t-C <classification.config>", file=fileobj)
    print("\t-G <gen-msg.map>", file=fileobj)
    print("\t-S <sid-msg.map>", file=fileobj)

def main():

    msgmap = maps.SignatureMap()
    classmap = maps.ClassificationMap()

    try:
        opts, args = getopt.getopt(sys.argv[1:], "hC:G:S:")
    except getopt.GetoptError as err:
        print("error: %s\n" % err, file=sys.stderr)
        usage()
        return 1
    for o, a in opts:
        if o == "-C":
            classmap.load_from_file(open(a))
        elif o == "-G":
            msgmap.load_generator_map(open(a))
        elif o == "-S":
            msgmap.load_signature_map(open(a))
        elif o == "-h":
            usage(sys.stdout)
            return 0

    if not args:
        usage()
        return 1

    reader = unified2.FileEventReader(*args)
    for event in reader:
        print_event(event, msgmap, classmap)

if __name__ == "__main__":
    sys.exit(main())
