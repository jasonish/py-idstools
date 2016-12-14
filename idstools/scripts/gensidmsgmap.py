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

"""Generate sid-msg.map files (v1 and v2) from rule archives, files
and/or directories.

"""

from __future__ import print_function

import sys
import os
import tarfile
import re
import getopt

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import idstools.rule

def file_iterator(files):

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

def usage(file=sys.stderr):
    print("""
usage: %s [options] <file>...

options:

    -2, --v2      Output a new (v2) style sid-msg.map file.

The files passed on the command line can be a list of a filenames, a
tarball, a directory name (containing rule files) or any combination
of the above.
""" % (sys.argv[0]))

def main():

    opt_v2 = False

    try:
        opts, args = getopt.getopt(sys.argv[1:], "h2", ["help", "v2"])
    except getopt.GetoptError as err:
        print("bad command line: %s" % (err), file=sys.stderr)
        usage()
        return 1
    for o, a in opts:
        if o in ["-h", "--help"]:
            usage(sys.stdout)
            return 0
        elif o in ["-2", "--v2"]:
            opt_v2 = True

    if not args:
        print("error: no files specified")
        usage()
        return 1

    rules = {}

    # First load all the rules, warn on duplicate or missing sids.
    for filename, fileobj in file_iterator(args):

        # For a legacy style sid-msg.map we only handle gid 1 and 3 rules.
        if re.search(".*\.rules$", filename):

            print("Processing file %s" % (filename), file=sys.stderr)

            for rule in idstools.rule.parse_fileobj(fileobj):

                if not opt_v2 and rule.gid not in [1, 3]:
                    continue

                if rule.sid is None:
                    print("WARNING: Rule found without sid: %s" % (rule.raw),
                          file=sys.stderr)
                elif (rule.gid, rule.sid) in rules:
                    print("WARNING: Duplicate sid %d: "
                          "rule will be ignored: %s" % (rule.sid, rule.raw),
                          file=sys.stderr)
                else:
                    rules[(rule.gid, rule.sid)] = rule

    print("Loaded %d rules." % (len(rules)), file=sys.stderr)

    for rule_id in sorted(rules):
        if opt_v2:
            print(idstools.rule.format_sidmsgmap_v2(rules[rule_id]))
        else:
            print(idstools.rule.format_sidmsgmap(rules[rule_id]))

    return 0

if __name__ == "__main__":
    sys.exit(main())
