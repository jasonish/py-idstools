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

"""
This program is an example of how one might "tail" a directory
containing unified2 spool files using the spool directory readers
provided by idstools.

::

    usage: u2tail.py [options] <directory> <prefix>

    options:

        --delete        delete files on close (when a new one is opened)
        --records       read records instead of events
        --bookmark      filename to store bookmark in

Example::

    ./examples/u2tail.py --delete --bookmark /var/log/snort merged.log

will read events from the unified2 log files in /var/log/snort
bookmarking its progress and deleting the files when they have been
completely processed.
"""

from __future__ import print_function

import sys
import os
import getopt
import logging
import pprint
import json

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from idstools import unified2

logging.basicConfig(level=logging.DEBUG, format="<%(msg)s>")

LOG = logging.getLogger(__name__)

def usage(fileobj=sys.stderr):
    print("usage: %s [options] <directory> <prefix>" % (
            sys.argv[0]))
    print("""
options:

    --delete        delete files on close (when a new one is opened)
    --records       read records instead of events
""")

def rollover_hook(closed_filename, opened_filename):
    LOG.info("Closed %s; opened %s" % (closed_filename, opened_filename))
    if opt_delete_on_close and closed_filename:
        os.unlink(closed_filename)
        LOG.info("Deleted %s." % (closed_filename))

def main():

    global opt_delete_on_close
    
    opt_delete_on_close = False
    opt_records = False
    opt_bookmark = None

    try:
        opts, args = getopt.getopt(
            sys.argv[1:], "h", [
                "delete",
                "records",
                "bookmark=",
                ])
    except getopt.GetoptError as err:
        print("error: %s" % err, file=sys.stderr)
        print("")
        usage()
        return 1
    if ('h', None) in opts:
        usage(sys.stdout)
        return 1
    for o, a in opts:
        if o == "--delete":
            opt_delete_on_close = True
        elif o == "--records":
            opt_records = True
        elif o == "--bookmark":
            opt_bookmark = a

    try:
        directory, prefix = args
    except:
        usage()
        return 1

    if not os.path.exists(directory):
        print("error: directory %s does not exist" % (directory), 
              file=sys.stderr)
        return 1

    bookmark_filename = bookmark_offset = None
    try:
        if opt_bookmark:
            if os.path.exists(opt_bookmark):
                bookmark_filename, bookmark_offset = json.load(open(opt_bookmark))
    except Exception as err:
        LOG.error("Error caught reading bookmark:", err)

    if bookmark_offset:
        LOG.info("Opening spool reader with file %s at offset %d." % (
            bookmark_filename, bookmark_offset))

    # Create a spool reader.  If --records was used we'll open the
    # reader that reads one record at a time.  Otherwise the more
    # useful reader will be used that aggregates records into events
    # for us.
    if opt_records:
        reader = unified2.SpoolRecordReader(
            directory, prefix, tail=True, rollover_hook=rollover_hook,
            init_filename = bookmark_filename,
            init_offset = bookmark_offset)
    else:
        reader = unified2.SpoolEventReader(
            directory, prefix, tail=True, rollover_hook=rollover_hook,
            init_filename = bookmark_filename,
            init_offset = bookmark_offset)

    # This example uses an iterator to read events which might be OK
    # if running in its own thread.  You may also want to call
    # reader.next() which will return a record (or event) if
    # available, otherwise it will return None expecting you to call
    # next again.  This is more useful if you are hooking into some
    # form of event loop.
    for record in reader:
        pprint.pprint(record)

        # Update bookmark.  We'll just dump json for now.
        if opt_bookmark:
            json.dump(reader.tell(), open(opt_bookmark, "w"))

if __name__ == "__main__":
    sys.exit(main())
