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
        --bookmark      enable spool bookmarking
        --records       read records instead of events

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

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

from idstools import spool
from idstools import unified2

logging.basicConfig(level=logging.DEBUG, format="<%(msg)s>")

LOG = logging.getLogger(__name__)

def usage(fileobj=sys.stderr):
    print("usage: %s [options] <directory> <prefix>" % (
            sys.argv[0]))
    print("""
options:

    --delete        delete files on close (when a new one is opened)
    --bookmark      enable spool bookmarking
    --records       read records instead of events
""")

def main():
    
    opt_bookmarking = False
    opt_delete_on_close = False
    opt_records = False

    try:
        opts, args = getopt.getopt(
            sys.argv[1:], "h", [
                "bookmarking",
                "delete",
                "records",
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
        if o == "--bookmarking":
            opt_bookmarking = True
        elif o == "--delete":
            opt_delete_on_close = True
        elif o == "--records":
            opt_records = True

    try:
        directory, prefix = args
    except:
        usage()
        return 1

    if not os.path.exists(directory):
        print("error: directory %s does not exist" % (directory), 
              file=sys.stderr)
        return 1

    # Create a spool reader.  If --records was used we'll open the
    # reader that reads one record at a time.  Otherwise the more
    # useful reader will be used that aggregates records into events
    # for us.
    if opt_records:
        reader = spool.Unified2RecordSpoolReader(
            directory, prefix,
            bookmarking=opt_bookmarking,
            delete_on_close=opt_delete_on_close)
    else:
        reader = spool.Unified2EventSpoolReader(
            directory, prefix,
            bookmarking=opt_bookmarking,
            delete_on_close=opt_delete_on_close)

    # This example uses an iterator to read events which might be OK
    # if running in its own thread.  You may also want to call
    # reader.next() which will return a record (or event) if
    # available, otherwise it will return None expecting you to call
    # next again.  This is more useful if you are hooking into some
    # form of event loop.
    for record in reader:
        pprint.pprint(record)

if __name__ == "__main__":
    sys.exit(main())
