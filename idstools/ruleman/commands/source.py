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

import os.path
import sys
import getopt
import types

from idstools.ruleman.commands.common import BaseCommand
from idstools.ruleman.commands.common import CommandLineError
from idstools.ruleman.commands.common import CommandError

class SourceCommand(object):

    usage = """
usage: %(progname)s source [-h]
   or: %(progname)s source add <name> <url>
   or: %(progname)s source remove <name>
   or: %(progname)s source disable <name>
   or: %(progname)s source enable <name>
   or: %(progname)s source set <name> <parameter> <value>
   or: %(progname)s source ignore-file <source-name> <filename>
   or: %(progname)s source ignore-file --remove <source-name> <filename>
   or: %(progname)s source set-policy <source> <policy>
   or: %(progname)s source unset-policy <source>
""" % {"progname": os.path.basename(sys.argv[0])}

    def __init__(self, config, args):
        self.config = config
        self.args = args
        self.sources = config.get_sources()

        self.subcommands = {
            "add": self.add,
            "remove": self.remove,
            "enable": self.enable,
            "disable": self.disable,
            "set": self.set_parameter,

            "ignore-file": SourceSubCommandIgnoreFile,
            
            "set-policy": self.set_policy,
            "unset-policy": self.unset_policy,

            # Aliases.
            "rm": self.remove,
        }

    def run(self):
        try:
            self.opts, self.args = getopt.getopt(self.args, "h", [])
        except getopt.GetoptError as err:
            print("error: %s" % (err), file=sys.stderr)
            print(self.usage, file=sys.stderr)
            return 1
        for o, a in self.opts:
            if o == "-h":
                print(self.usage)
                return 0

        if not self.args:
            return self.list()

        command = self.args.pop(0)

        if command in self.subcommands:
            try:
                subcommand = self.subcommands[command]
                if type(subcommand) == types.TypeType and issubclass(self.subcommands[command], BaseCommand):
                    return self.subcommands[command](
                        self.config, self.args).run()
                else:
                    return self.subcommands[command]()
            except (getopt.GetoptError, CommandLineError) as err:
                print("error: %s" % (err), file=sys.stderr)
                usage = getattr(self.subcommands[command], "usage", self.usage)
                print(usage, file=sys.stderr)
                return 1
            except CommandError as err:
                print("error: %s" % (err))
                return 1
        else:
            print("error: unknown subcommand: %s" % (command), file=sys.stderr)

    def set_policy(self):
        try:
            source = self.args[0]
            policy = self.args[1]
        except:
            raise CommandLineError("missing argument(s)")
        if source not in self.sources:
            raise CommandError("source %s does not exist" % (source))
        self.sources[source]["policy"] = policy

    def unset_policy(self):
        try:
            source = self.args[0]
        except:
            raise CommandLineError("missing argument")
        if source not in self.sources:
            raise CommandError("source %s does not exist" % (source))
        if "policy" in self.sources[source]:
            del(self.sources[source]["policy"])

    def set_parameter(self):
        name = self.args.pop(0)
        key = self.args.pop(0)
        val = self.args.pop(0)

        if name not in self.sources:
            print("error: source %s does not exist." % (name), file=sys.stderr)

        self.sources[name][key] = val

    def list(self):
        for source in self.sources:
            print("%s: %s" % (source, self.sources[source]))

    def add(self):
        name = self.args.pop(0)
        url = self.args.pop(0)

        if name in self.sources:
            print("error: source %s already exists" % (name), file=sys.stderr)
            return 1

        self.sources[name] = {
            "name": name,
            "url": url,
        }

    add.usage = "usage: add <name> <url>"

    def remove(self):
        name = self.args.pop(0)
        if name not in self.sources:
            print("error: source %s does not exist" % (name), file=sys.stderr)
            return 1
        del(self.sources[name])
    
    remove.usage = "usage: remove <name>"

    def enable(self):
        name = self.args.pop(0)
        if name not in self.sources:
            print("error: source %s does not exist" % (name), file=sys.stderr)
        self.sources[name]["enabled"] = True

    enable.usage = "usage: enable <name>"

    def disable(self):
        name = self.args.pop(0)
        if name == "*":
            for source in self.sources.values():
                source["enabled"] = False
        else:
            if name not in self.sources:
                print("error: source %s does not exist" % (name),
                      file=sys.stderr)
                self.sources[name]["enabled"] = False
            else:
                self.sources[name]["enabled"] = False

    disable.usage = "usage: disable <name>"

class SourceSubCommandIgnoreFile(BaseCommand):

    usage = """
usage: ignore-file <source-name> <filename>
   or: ignore-file --remove <source-name> <filename>
"""

    def __init__(self, config, args):
        self.config = config
        self.args = args
        self.sources = config.get_sources()

        self.opt_remove = False

    def run(self):
        opts, self.args = getopt.getopt(self.args, "", ["remove"])
        for o, a in opts:
            if o in ["--remove"]:
                self.opt_remove = True

        try:
            name = self.args.pop(0)
            filename = self.args.pop(0)
        except:
            raise CommandLineError("not enough arguments")

        if name not in self.sources:
            print("error: source %s does not exist" % (name), file=sys.stderr)
            return 1
        source = self.sources[name]
        if "ignore-files" not in source:
            source["ignore-files"] = []
        if self.opt_remove:
            if filename in source["ignore-files"]:
                source["ignore-files"].remove(filename)
        else:
            source["ignore-files"].append(filename)
            source["ignore-files"] = list(set(source["ignore-files"]))
