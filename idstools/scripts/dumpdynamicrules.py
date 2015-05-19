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

"""Dump Snort SO rule stub helper program. Can optionally repack a
Snort rule tarball with the generated stubs, in place or to a new
file.

"""

from __future__ import print_function

import sys
import os
import os.path
import logging
import subprocess
import re
import tempfile
import atexit
import shutil
import glob

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

def mktempdir(delete_on_exit=True):
    """ Create a temporary directory that is removed on exit. """
    tmpdir = tempfile.mkdtemp("idstools")
    if delete_on_exit:
        atexit.register(shutil.rmtree, tmpdir, ignore_errors=True)
    return tmpdir

def find_snort():
    """ Find the path to Snort from the PATH. """
    for path in os.environ["PATH"].split(os.pathsep):
        filename = os.path.join("snort")
        if os.path.exists(filename):
            return filename
    return None

def repack(prefix, stubs, filename):
    logger.info("Repacking to %s.", filename)
    stubdir = os.path.join(prefix, "so_rules")
    existing_stubs = glob.glob("%s/*.rules" % (stubdir))

    for stub in stubs:
        rpath = os.path.join("so_rules", stub)
        fpath = os.path.join(prefix, rpath)
        if fpath in existing_stubs:
            logger.debug("Overwriting %s.", rpath)
            existing_stubs.remove(fpath)
        else:
            print("Creating %s." % (rpath))

    # Log the orphaned stubs.
    logger.debug("Orphaned SO stubs: %s", ",".join(existing_stubs))

    logger.info("Writing %s.", filename)
    subprocess.Popen(
        "tar cf - * | gzip -c > %s" % (filename),
        shell=True, cwd=prefix).communicate()

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--snort", dest="snort", help="path to snort")
    parser.add_argument(
        "--version", dest="version", help="Snort version")
    parser.add_argument(
        "--dist", dest="dist", help="operating system/distribution")
    parser.add_argument(
        "--out", dest="out", help="path to output SO stubs to")
    parser.add_argument(
        "--repack", nargs="?", metavar="filename", const=True, default=False,
        help="repack archive with generated SO stubs")
    parser.add_argument(
        "-v", "--verbose", action="store_true", default=False,
        help="log more information")
    parser.add_argument(
        "path", metavar="<path>",
        help="SO rule directory or rule tarball")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    if not args.snort:
        args.snort = find_snort()
        if not args.snort:
            logger.error("Failed to find Snort program on path.")
            return 1
    elif not os.path.exists(args.snort):
        logger.error("Error: %s does not exists.", args.snort)
        return 1

    snort_app = snort.SnortApp(path=args.snort)
    logger.info("Using Snort %s.", snort_app.version()[1])
    if not args.version:
        args.version = snort_app.version()[0]

    if os.path.isdir(args.path):
        stubs = snort_app.dump_dynamic_rules(args.path, verbose=True)
    else:
        tempdir = mktempdir(delete_on_exit=False)
        logger.info("Expanding %s to directory %s." % (args.path, tempdir))
        subprocess.Popen(
            "gunzip -c %s | tar xf -" % (args.path),
            cwd=tempdir, shell=True).wait()

        precompiled_dir = "%s/so_rules/precompiled" % (tempdir)

        if args.dist:
            path = "%s/%s/%s/%s" % (precompiled_dir, args.dist, snort_app.arch,
                                    args.version)
            logger.info("Using %s.", path)
            stubs = snort_app.dump_dynamic_rules(path, verbose=args.verbose)

        else:
            for dist in reversed(os.listdir(precompiled_dir)):
                path = "%s/%s/%s/%s" % (precompiled_dir, dist, snort_app.arch, args.version)
                print("Trying %s." % path)
                stubs = snort_app.dump_dynamic_rules(path, args.verbose)
                if stubs:
                    break

        logger.info("Generated %d stubs.", len(stubs))

        if stubs and args.out:
            if not os.path.exists(args.out):
                logger.info("Creating directory %s.", args.out)
                os.makedirs(args.out)
            for stub in stubs:
                out_path = os.path.join(args.out, stub)
                logger.info("Writing %s.", out_path)
                with open(out_path, "w") as fileobj:
                    fileobj.write(stubs[stub])

        if args.repack:
            if not stubs:
                logger.error("Error: No stubs generated, nothing to repace.")
            repack(tempdir, stubs, args.path if args.repack == True
                   else args.repack)

if __name__ == "__main__":
    sys.exit(main())
