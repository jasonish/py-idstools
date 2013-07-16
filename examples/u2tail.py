#! /usr/bin/env python
#
# This program is an example of how one might "tail" a directory
# containing unified2 spool files using the spool directory readers
# provided by idstools.

from __future__ import print_function

import sys
import os
import getopt
import time
import logging
import pprint

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))))

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
