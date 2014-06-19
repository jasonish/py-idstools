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
import getopt

from idstools.ruleman import matchers as rulematchers

class EnableRuleCommand(object):

    usage = """
usage: %(progname)s enable [-h]
   or: %(progname)s enable [-r] <gid:sid>
   or: %(progname)s enable [-r] re:<regex>

    -r,--remove      Removes the rule matcher from the enabled list.
""" % {"progname": sys.argv[0]}

    def __init__(self, config, args):
        self.config = config
        self.args = args
        self.opt_remove = False

    def run(self):
        try:
            opts, self.args = getopt.getopt(
                self.args, 
                "hr",
                ["help", "remove"])
        except getopt.GetoptError as err:
            print("error: %s" % (err), file=sys.stderr)
            print(self.usage)
            return 1
        for o, a in opts:
            if o == "-h":
                print(self.usage)
                return 0
            elif o in ["-r", "--remove"]:
                self.opt_remove = True

        if not self.args:
            return self.list()
        elif self.opt_remove:
            return self.remove()

        descriptor = self.args[0]
        message = " ".join(self.args[1:])

        matcher = rulematchers.parse(self.args[0])
        if not matcher:
            print("error: invalid rule matcher: %s" % (descriptor))
            return 1

        enabled_rules = self.config["enabled-rules"]

        exists = filter(lambda m: m["matcher"] == str(matcher), enabled_rules)
        if exists:
            print("error: rules matching %s are already enabled." % (
                str(matcher)))
            print(" - comment: %s" % (exists[0]["comment"]))
            return 1

        enabled_rules.append({
            "matcher": str(matcher),
            "comment": message,
        })

    def remove(self):
        """Remove the matcher for the disabled list."""
        self.config["enabled-rules"] = filter(
            lambda m: m["matcher"] != self.args[0],
            self.config["enabled-rules"])

    def list(self):
        for disabled in self.config["enabled-rules"]:
            print("%s: %s" % (disabled["matcher"], disabled["comment"]))
