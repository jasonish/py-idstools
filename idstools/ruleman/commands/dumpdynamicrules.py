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
import os.path
import getopt

import idstools.snort

from idstools.ruleman.commands.common import BaseCommand

class DumpDynamicRulesCommand(BaseCommand):

    usage = """
usage: %(progname)s dump-dynamic-rules <source-name>
""" % {"progname": os.path.basename(sys.argv[0])}

    def __init__(self, config, args):
        self.config = config
        self.args = args

    def run(self):

        if not self.args:
            print(self.usage, file=sys.stderr)
            return 1
        return self.dump_source(self.args[0])

    def dump_source(self, source_name):

        source_path = os.path.join("sources", source_name)
        if not os.path.exists(source_path):
            print("error: source %s does not exist" % (source_name),
                  file=sys.stderr)
            return 1

        if not os.path.exists(os.path.join(source_path, "so_rules")):
            print("error: source %s does not appear to have dynamic rules" % (
                source_name), file=sys.stderr)
            return 1

        if not "snort" in self.config:
            print("error: snort configuration section does not exist",
                  file=sys.stderr)
            return 1

        snortapp = idstools.snort.SnortApp(self.config.get("snort"))
        dynamic_rule_directory = snortapp.find_dynamic_detection_lib_dir(
            "sources/%s" % (source_name))
        if dynamic_rule_directory is None:
            print("error: failed to find dynamic rule directory")
            return 1

        files = snortapp.dump_dynamic_rules(dynamic_rule_directory)
        if files:
            destination_dir = os.path.join(
                "sources", source_name, "so_rules")  
            for filename in files:
                if os.path.exists(os.path.join(destination_dir, filename)):
                    print("Overwriting %s." % os.path.join(
                        destination_dir, filename))
            for filename in os.listdir(destination_dir):
                if filename.endswith(".rules") and filename not in files:
                    path = os.path.join(destination_dir, filename)
                    print("Removing %s as it was not regenerated." % (filename))
                    os.unlink(path)

