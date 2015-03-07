# Copyright (c) 2015 Jason Ish
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

from __future__ import print_function

import sys
import os
import os.path
import logging

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

try:
    import argparse
except:
    # Python 2.6.
    from idstools.compat.argparse import argparse

from idstools import snort

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger()

def find_snort():
    """ Find the path to Snort from the PATH. """
    for path in os.environ["PATH"].split(os.pathsep):
        filename = os.path.join("snort")
        if os.path.exists(filename):
            return filename
    return None

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--snort", dest="snort", help="path to snort")
    parser.add_argument(
        "--version", dest="version", help="Snort version")
    parser.add_argument(
        "--dist", dest="dist", help="operating system/distribution")
    parser.add_argument(
        "path", metavar="<path>",
        help="SO rule directory or rule tarball")
    args = parser.parse_args()

    print(args)

    if not args.snort:
        args.snort = find_snort()
        if not args.snort:
            logger.error("Failed to find Snort program on path.")
            return 1
    elif not os.path.exists(args.snort):
        logger.error("Error: %s does not exists.", args.snort)
        return 1

    snort_app = snort.SnortApp(path=args.snort)
    logger.info("Using Snort %s." % str(snort_app.version()[1]))

    stubs = snort_app.dump_dynamic_rules(args.path, verbose=True)
    #print(stubs)

if __name__ == "__main__":
    sys.exit(main())

