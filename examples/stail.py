#! /usr/bin/env python
#
# This program implements "tail -f" like behaviour for directories
# containing line based spool files.

from __future__ import print_function

import sys
import os
import os.path
import time
import logging
import getopt

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))))

from idstools import spool

logging.basicConfig(level=logging.DEBUG, format="<%(msg)s>")

LOG = logging.getLogger(__name__)

def usage(fileobj=sys.stderr):
    print("usage: %s [options] <directory> <prefix>" % (
            sys.argv[0]))
    print("""
options:

    --delete        delete files on close (when a new one is opened)
    --bookmark      enable spool bookmarking
""")

def main():

    opt_bookmarking = False
    opt_delete_on_close = False

    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["bookmarking", "delete"])
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

    try:
        directory, prefix = args
    except:
        usage()
        return 1

    if not os.path.exists(directory):
        print("error: directory %s does not exist" % (directory), 
              file=sys.stderr)
        return 1

    reader = spool.LineSpoolReader(directory, prefix,
                                   bookmarking=opt_bookmarking,
                                   delete_on_close=True)
    for line in reader:
        print(line)

if __name__ == "__main__":
    sys.exit(main())
