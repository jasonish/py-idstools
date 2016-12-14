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

"""Read unified2 log files and output events in "fast" style. """

from __future__ import print_function

import sys
import os
import os.path

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import time
import logging

try:
    import argparse
except ImportError as err:
    from idstools.compat.argparse import argparse

from idstools import unified2
from idstools import maps

logging.basicConfig(level=logging.INFO, format="%(message)s")
LOG = logging.getLogger()

proto_map = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

def print_time(sec, usec):
    tt = time.localtime(sec)
    return "%04d/%02d/%02d-%02d:%02d:%02d.%06d" % (
        tt.tm_year, tt.tm_mon, tt.tm_mday, tt.tm_hour, tt.tm_min, tt.tm_sec,
        usec)

def print_event(event, msgmap, classmap):
    msg_entry = msgmap.get(event["generator-id"], event["signature-id"])
    if msg_entry:
        msg = msg_entry["msg"]
    else:
        msg = "Snort Event"

    class_entry = classmap.get(event["classification-id"])
    if class_entry:
        class_description = class_entry["description"]
    else:
        class_description = str(event["classification-id"])

    proto = proto_map.get(event["protocol"], str(event["protocol"]))

    print("%s [**] [%d:%d:%d] %s [**] [Classification: %s] [Priority: %d] {%s} %s:%d -> %s:%d" % (
            print_time(event["event-second"], event["event-microsecond"]),
            event["generator-id"],
            event["signature-id"],
            event["signature-revision"],
            msg,
            class_description,
            event["priority"],
            proto,
            event["source-ip"],
            event["sport-itype"],
            event["destination-ip"],
            event["dport-icode"],
            ))

def load_from_snort_conf(snort_conf, classmap, msgmap):
    snort_etc = os.path.dirname(snort_conf)

    classification_config = os.path.join(snort_etc, "classification.config")
    if os.path.exists(classification_config):
        LOG.debug("Loading %s.", classification_config)
        classmap.load_from_file(open(classification_config))

    genmsg_map = os.path.join(snort_etc, "gen-msg.map")
    if os.path.exists(genmsg_map):
        LOG.debug("Loading %s.", genmsg_map)
        msgmap.load_generator_map(open(genmsg_map))

    sidmsg_map = os.path.join(snort_etc, "sid-msg.map")
    if os.path.exists(sidmsg_map):
        LOG.debug("Loading %s.", sidmsg_map)
        msgmap.load_signature_map(open(sidmsg_map))

def main():

    msgmap = maps.SignatureMap()
    classmap = maps.ClassificationMap()

    parser = argparse.ArgumentParser(
        fromfile_prefix_chars='@')
    parser.add_argument(
        "-C", dest="classification_path", metavar="<classification.config>",
        help="path to classification config")
    parser.add_argument(
        "-S", dest="sidmsgmap_path", metavar="<msg-msg.map>",
        help="path to sid-msg.map")
    parser.add_argument(
        "-G", dest="genmsgmap_path", metavar="<gen-msg.map>",
        help="path to gen-msg.map")
    parser.add_argument(
        "--snort-conf", dest="snort_conf", metavar="<snort.conf>",
        help="attempt to load classifications and map files based on the "
        "location of the snort.conf")
    parser.add_argument(
        "--directory", metavar="<spool directory>",
        help="spool directory (eg: /var/log/snort)")
    parser.add_argument(
        "--prefix", metavar="<spool file prefix>",
        help="spool filename prefix (eg: unified2.log)")
    parser.add_argument(
        "--bookmark", action="store_true", default=False,
        help="enable bookmarking")
    parser.add_argument(
        "--follow", action="store_true", default=False,
        help="follow files/continuous mode (spool mode only)")
    parser.add_argument(
        "filenames", nargs="*")
    args = parser.parse_args()

    if args.snort_conf:
        load_from_snort_conf(args.snort_conf, classmap, msgmap)

    if args.classification_path:
        classmap.load_from_file(
            open(os.path.expanduser(args.classification_path)))
    if args.genmsgmap_path:
        msgmap.load_generator_map(open(os.path.expanduser(args.genmsgmap_path)))
    if args.sidmsgmap_path:
        msgmap.load_signature_map(open(os.path.expanduser(args.sidmsgmap_path)))

    if msgmap.size() == 0:
        LOG.warn("WARNING: No alert message map entries loaded.")
    else:
        LOG.info("Loaded %s rule message map entries.", msgmap.size())

    if classmap.size() == 0:
        LOG.warn("WARNING: No classifications loaded.")
    else:
        LOG.info("Loaded %s classifications.", classmap.size())

    if args.directory and args.prefix:
        reader = unified2.SpoolEventReader(
            directory=args.directory,
            prefix=args.prefix,
            follow=args.follow,
            bookmark=args.bookmark)

        for event in reader:
            print_event(event, msgmap, classmap)

    elif args.filenames:
        reader = unified2.FileEventReader(*args.filenames)
        for event in reader:
            print_event(event, msgmap, classmap)

    else:
        parser.print_help()
        return 1

if __name__ == "__main__":
    sys.exit(main())
