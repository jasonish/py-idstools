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

from __future__ import print_function

import sys
import os
import tarfile
import re
import getopt

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))))

import idstools.rule

def file_iterator(files):
    print(files)

    for filename in files:

        if os.path.isdir(filename):
            for filename, fileobj in file_iterator(
                    ["%s/%s" % (filename, f) for f in os.listdir(filename)]):
                yield filename, fileobj

        # Files that look like archives.
        elif filename.endswith(".gz") or filename.endswith(".bz2"):
            tf = tarfile.open(filename)
            for member in tf:
                fileobj = tf.extractfile(member)
                if fileobj:
                    yield member.name, fileobj

        elif filename.endswith(".rules"):
            yield filename, open(filename)

def render(rule):
    return " || ".join([str(rule.sid), rule.msg] + rule.references)

def usage(file=sys.stderr):
    print("""
usage: %s <file>...

The files passed on the command line can be a list of a filenames, a
tarball, a directory name (containing rule files) or any combination
of the above.
""" % (sys.argv[0]))

def main():

    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["help"])
    except getopt.GetoptError as err:
        print("bad command line: %s" % (err), file=sys.stderr)
        usage()
        return 1
    for o, a in opts:
        if o in ["-h", "--help"]:
            usage(sys.stdout)
            return 0

    rules = {}

    # First load all the rules, warn on duplicate or missing sids.
    for filename, fileobj in file_iterator(sys.argv[1:]):

        # For a legacy style sid-msg.map we only handle gid 1 and 3 rules.
        if re.search(".*\.rules$", filename):

            print("Processing file %s" % (filename), file=sys.stderr)

            for rule in idstools.rule.parse_fileobj(fileobj):

                # Old style sid-msg.map.
                if rule.gid not in [1, 3]:
                    continue

                if rule.sid is None:
                    print("WARNING: Rule found without sid: %s" % (rule.raw),
                          file=sys.stderr)
                elif rule.sid in rules:
                    print("WARNING: Duplicate sid %d: "
                          "rule will be ignored: %s" % (rule.sid, rule.raw),
                          file=sys.stderr)
                else:
                    rules[rule.sid] = rule

    print("Loaded %d rules." % (len(rules)), file=sys.stderr)

    for sid in sorted(rules):
        print(render(rules[sid]))

    return 0

if __name__ == "__main__":
    sys.exit(main())
