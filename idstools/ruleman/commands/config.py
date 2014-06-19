# Copyright (c) 2011-2014 Jason Ish
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
import os.path
import getopt

from idstools.ruleman.commands.common import BaseCommand

class ConfigCommand(BaseCommand):

    usage = """
usage %(progname)s config [-h]
   or %(progname)s config snort.path <path-to-snort>
   or %(progname)s config snort.os <OS-type>
   or %(progname)s config snort.dynamic-engine-lib <path-to-engine-lib>
""" % {
    "progname": os.path.basename(sys.argv[0]),
}
    
    def __init__(self, config, args):
        self.config = config
        self.args = args

    def run(self):
        try:
            opts, self.args = getopt.getopt(self.args, "-h", [])
        except getopt.GetoptError as err:
            print("error: %s" % (err), file=sys.stderr)
            print(self.usage, file=sys.stderr)
            return 1
        for o, a in opts:
            if o in ["-h"]:
                print(self.usage)
                return 0

        if not self.args:
            self.show(self.config.store)
        else:
            key = self.args[0].split(".")
            return self.set_value(key, self.args[1:])

    def show(self, root, prefix=[]):
        if type(root) == type({}):
            for key in root:
                self.show(root[key], prefix + [key])
        elif type(root) == type([]):
            for i, val in enumerate(root):
                self.show(val, prefix + [str(i)])
        else:
            print("%s=%s" % (".".join(prefix), root))

    def set_value(self, key, value):
        if key[0] == "snort":
            return self.set_snort_value(key[1:], value)

    def set_snort_value(self, key, value):
        if "snort" not in self.config:
            self.config["snort"] = {}
        if key[0] == "path":
            path = value[0]
            if not os.path.exists(path):
                print("error: %s does not exist." % (path), file=sys.stderr)
                return 1
            self.config["snort"]["path"] = path
        elif key[0] == "os":
            self.config["snort"][key[0]] = value[0]
        elif key[0] == "dynamic-engine-lib":
            self.config["snort"][key[0]] = value[0]
