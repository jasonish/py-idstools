# Copyright (c) 2014-2015 Jason Ish
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

"""Read unified2 log files and output records as JSON."""

from __future__ import print_function

import sys
import os
import os.path
import base64

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import json
import logging

try:
    import argparse
except ImportError as err:
    from idstools.compat.argparse import argparse

from idstools import unified2
from idstools import maps

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
LOG = logging.getLogger()

class Formatter(object):

    def __init__(self, msgmap=None, classmap=None):
        self.msgmap = msgmap
        self.classmap = classmap

    def resolve_msg(self, event, default=None):
        if self.msgmap:
            signature = self.msgmap.get(
                event["generator-id"], event["signature-id"])
            if signature:
                return signature["msg"]
        return default

    def resolve_classification(self, event, default=None):
        if self.classmap:
            classinfo = self.classmap.get(event["classification-id"])
            if classinfo:
                return classinfo["description"]
        return default

    def format_event(self, record):
        event = {}

        msg = self.resolve_msg(record)
        if msg:
            event["msg"] = msg
        classification = self.resolve_classification(record)
        if classification:
            event["classification"] = classification

        for key in record:
            if key.endswith(".raw"):
                continue
            elif key in ["extra-data", "packets"]:
                continue
            elif key == "appid" and not record["appid"]:
                continue
            else:
                event[key] = record[key]
        return {"event": event}

    def format_packet(self, record):
        packet = {}
        for key in record:
            if key == "data":
                packet[key] = base64.b64encode(record[key]).decode("utf-8")
            else:
                packet[key] = record[key]
        return {"packet": packet}

    def format_extra_data(self, record):
        data = {}

        # For data types that can be printed in plain text, extract
        # the data into its own field with a descriptive name.
        if record["type"] == unified2.EXTRA_DATA_TYPE["SMTP_FILENAME"]:
            data["smtp-filename"] = record["data"]
        elif record["type"] == unified2.EXTRA_DATA_TYPE["SMTP_MAIL_FROM"]:
            data["smtp-from"] = record["data"]
        elif record["type"] == unified2.EXTRA_DATA_TYPE["SMTP_RCPT_TO"]:
            data["smtp-rcpt-to"] = record["data"]
        elif record["type"] == unified2.EXTRA_DATA_TYPE["SMTP_HEADERS"]:
            data["smtp-headers"] = record["data"]
        elif record["type"] == unified2.EXTRA_DATA_TYPE["HTTP_URI"]:
            data["http-uri"] = record["data"]
        elif record["type"] == unified2.EXTRA_DATA_TYPE["HTTP_HOSTNAME"]:
            data["http-hostname"] = record["data"]
        elif record["type"] == unified2.EXTRA_DATA_TYPE["NORMALIZED_JS"]:
            data["javascript"] = record["data"]
        else:
            LOG.warning("Unknown extra-data record type: %s" % (
                str(record["type"])))

        for key in record:
            if key == "data":
                data[key] = base64.b64encode(record[key]).decode("utf-8")
            else:
                data[key] = record[key]

        return {"extra-data": data}

    def format(self, record):
        if isinstance(record, unified2.Event):
            return self.format_event(record)
        elif isinstance(record, unified2.Packet):
            return self.format_packet(record)
        elif isinstance(record, unified2.ExtraData):
            return self.format_extra_data(record)
        else:
            LOG.warning("Unknown record type: %s: %s" % (
                str(record.__class__), str(record)))

class OutputWrapper(object):

    def __init__(self, filename, fileobj=None):
        self.filename = filename
        self.fileobj = fileobj

        if self.fileobj is None:
            self.reopen()
            self.isfile = True
        else:
            self.isfile = False

    def reopen(self):
        if self.fileobj:
            self.fileobj.close()
        self.fileobj = open(self.filename, "ab")

    def write(self, buf):
        if self.isfile:
            if not os.path.exists(self.filename):
                self.reopen()
        self.fileobj.write(buf)
        self.fileobj.write("\n")
        self.fileobj.flush()

def load_from_snort_conf(snort_conf, classmap, msgmap):
    snort_etc = os.path.dirname(os.path.expanduser(snort_conf))

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

epilog = """If --directory and --prefix are provided files will be
read from the specified 'spool' directory.  Otherwise files on the
command line will be processed.
"""

def rollover_hook(closed, opened):
    """ The rollover hook for the spool reader. Will delete the closed file. """
    LOG.debug("closed=%s; opened=%s" % (closed, opened))
    LOG.debug("Deleting %s.", closed)
    os.unlink(closed)

def main():

    msgmap = maps.SignatureMap()
    classmap = maps.ClassificationMap()

    parser = argparse.ArgumentParser(
        fromfile_prefix_chars='@', epilog=epilog)
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
        "--bookmark", metavar="<filename>", help="enable bookmarking")
    parser.add_argument(
        "--follow", action="store_true", default=False,
        help="follow files/continuous mode (spool mode only)")
    parser.add_argument(
        "--delete", action="store_true", default=False,
        help="delete spool files")
    parser.add_argument(
        "--output", metavar="<filename>",
        help="output filename (eg: /var/log/snort/alerts.json")
    parser.add_argument(
        "--stdout", action="store_true", default=False,
        help="also log to stdout if --output is a file")
    parser.add_argument(
        "--sort-keys", dest="sort_keys", action="store_true", default=False,
        help="the output of dictionaries will be sorted by key")
    parser.add_argument(
        "--verbose", action="store_true", default=False,
        help="be more verbose")
    parser.add_argument(
        "filenames", nargs="*")
    args = parser.parse_args()

    if args.verbose:
        LOG.setLevel(logging.DEBUG)

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
        LOG.warn("No alert message map entries loaded.")
    else:
        LOG.info("Loaded %s rule message map entries.", msgmap.size())

    if classmap.size() == 0:
        LOG.warn("No classifications loaded.")
    else:
        LOG.info("Loaded %s classifications.", classmap.size())

    outputs = []

    if args.output:
        outputs.append(OutputWrapper(args.output))
        if args.stdout:
            outputs.append(OutputWrapper("-", sys.stdout))
    else:
        outputs.append(OutputWrapper("-", sys.stdout))

    bookmark = None

    if args.filenames:
        if args.bookmark:
            LOG.error("Bookmarking not valid in file mode.")
            return 1
        if args.follow:
            LOG.error("Follow not valid in file mode.")
            return 1
        if args.delete:
            LOG.error("Delete not valid in file mode.")
            return 1
        reader = unified2.FileRecordReader(*args.filenames)
    elif args.directory and args.prefix:
        if args.bookmark:
            bookmark = unified2.Unified2Bookmark(filename=args.bookmark)
            init_filename, init_offset = bookmark.get()
        else:
            init_filename = None
            init_offset = None
        reader = unified2.SpoolRecordReader(
            directory=args.directory,
            prefix=args.prefix,
            follow=args.follow,
            rollover_hook=rollover_hook if args.delete else None,
            init_filename=init_filename,
            init_offset=init_offset)
    else:
        LOG.error("No spool or files provided.")
        return 1

    formatter = Formatter(msgmap=msgmap, classmap=classmap)

    count = 0

    try:
        for record in reader:
            try:
                as_json = json.dumps(formatter.format(record), sort_keys=args.sort_keys)
                for out in outputs:
                    out.write(as_json)
                count += 1
            except Exception as err:
                LOG.error("Failed to encode record as JSON: %s: %s" % (
                    str(err), str(record)))
            if bookmark:
                filename, offset = reader.tell()
                bookmark.update(filename, offset)
    except unified2.UnknownRecordType as err:
        if count == 0:
            LOG.error("%s: Is this a unified2 file?" % (err))
        else:
            LOG.error(err)

if __name__ == "__main__":
    sys.exit(main())
