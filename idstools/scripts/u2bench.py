#! /usr/bin/env python
#
# Benchmark record and event reading.

from __future__ import print_function

import sys
import os
import time
import getopt

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))))

from idstools import unified2

def usage(fileobj=sys.stderr):
    print("""
usage: %s [options] <filenames>

options:

    no options yet
""" % (sys.argv[0]))

def main():

    try:
        opts, args = getopt.getopt(
            sys.argv[1:], "h", 
            ["help"])
    except getopt.GetoptError as err:
        print("error: invalid command line: %s" % err, file=sys.stderr)
        usage()
        return 1
    for o, a in opts:
        if o in ["-h", "--help"]:
            usage(sys.stdout)
            return 0

    if not args:
        print("error: nothing to do", file=sys.stderr)
        usage()
        return 1

    record_count = 0
    start_time = time.time()

    for arg in args:
        print("Processing file %s." % arg)

        with open(arg) as fileobj:
            while 1:
                record = unified2.read_record(fileobj)
                if not record:
                    break
                record_count += 1

    elapsed_time = time.time() - start_time
    print("Records: %d; Time: %d; Records/sec: %d" % (
        record_count, elapsed_time, record_count / int(elapsed_time)))

if __name__ == "__main__":
    sys.exit(main())
