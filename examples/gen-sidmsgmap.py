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

import sys
import os
import tarfile
import re

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0]))))

import idstools.rule

def file_iterator(files):
    for filename in files:
        
        # Files that look like archives.
        if filename.endswith(".gz") or filename.endswith(".bz2"):
            tf = tarfile.open(filename)
            for member in tf:
                fileobj = tf.extractfile(member)
                if fileobj:
                    yield member.name, fileobj

def render(rule):
    return " || ".join([str(rule.sid), rule.msg] + rule.references)

def main():

    rules = {}

    # First load all the rules, warn on duplicate or missing sids.
    for filename, fileobj in file_iterator(sys.argv[1:]):

        # For a legacy style sid-msg.map we only handle gid 1 and 3 rules.
        if re.match("(so_)?rules/.*\.rules", filename):

            for rule in idstools.rule.parse_fileobj(fileobj):

                if rule.sid is None:
                    print("WARNING: Rule found without sid: %s" % (rule.raw))
                elif rule.sid in rules:
                    print("WARNING: Duplicate sid %d: "
                          "rule will be ignored: %s" % (rule.sid, rule.raw))
                else:
                    rules[rule.sid] = rule

    print("Loaded %d rules." % (len(rules)))

    for sid in sorted(rules):
        print(render(rules[sid]))

    return 0

if __name__ == "__main__":
    sys.exit(main())
