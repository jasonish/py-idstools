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
import tempfile
import subprocess
import os.path
import shutil

import idstools.net
import idstools.rule

from idstools.ruleman import util
from idstools.ruleman import matchers as rulematchers
from idstools.ruleman import core

from idstools.ruleman.commands.common import BaseCommand
from idstools.ruleman.commands.common import CommandLineError
from idstools.ruleman.commands.source import SourceCommand
from idstools.ruleman.commands.fetch import FetchCommand
from idstools.ruleman.commands.dumpdynamicrules import DumpDynamicRulesCommand
from idstools.ruleman.commands.config import ConfigCommand
from idstools.ruleman.commands.disable import DisableRuleCommand
from idstools.ruleman.commands.enable import EnableRuleCommand
from idstools.ruleman.commands.apply import ApplyCommand

class DisableRuleCommand(object):

    usage = """
usage: %(progname)s disable [-h]
   or: %(progname)s disable [-r] <gid:sid>
   or: %(progname)s disable [-r] re:<regex>

    -r,--remove      Removes the rule matcher from the disabled list.
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
            print(usage)
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

        disabled_rules = self.config["disabled-rules"]

        exists = filter(lambda m: m["matcher"] == str(matcher), disabled_rules)
        if exists:
            print("error: rules matching %s are already disabled." % (
                str(matcher)))
            print(" - comment: %s" % (exists[0]["comment"]))
            return 1

        disabled_rules.append({
            "matcher": str(matcher),
            "comment": message,
        })

    def remove(self):
        """Remove the matcher for the disabled list."""
        self.config["disabled-rules"] = filter(
            lambda m: m["matcher"] != self.args[0],
            self.config["disabled-rules"])

    def list(self):
        for disabled in self.config["disabled-rules"]:
            print("%s: %s" % (disabled["matcher"], disabled["comment"]))

class SearchCommand(object):

    def __init__(self, config, args):
        self.config = config
        self.args = args

    def run(self):
        if not self.args:
            print("error: nothing to search for.")
            return 1

        matcher = rulematchers.ReRuleMatcher.parse("re:" + self.args[0])

        for filename in self.iter_source_rule_files():
            rules = idstools.rule.parse_fileobj(open(filename))
            for rule in rules:
                if matcher.match(rule):
                    ruleset, group = self.parse_filename(filename)
                    print("%s:%s: %s" % (
                        ruleset, group, self.render_brief(rule)))

    def parse_filename(self, filename):
        parts = filename.split("/")
        return parts[1], "/".join(parts[2:])

    def iter_source_rule_files(self):
        for source in self.config.get_sources():
            for dirpath, dirs, files in os.walk("sources/%s" % (source)):
                for filename in files:
                    if filename.endswith(".rules"):
                        yield os.path.join(dirpath, filename)

    def render_brief(self, rule):
        return "%s[%d:%d:%d] %s" % (
            "" if rule.enabled else "# ",
            rule.gid, rule.sid, rule.rev,
            rule.msg)

commands = {
    "fetch": FetchCommand,
    "source": SourceCommand,
    "disable": DisableRuleCommand,
    "enable": EnableRuleCommand,
    "search": SearchCommand,
    "apply": ApplyCommand,
    "config": ConfigCommand,
    "dump-dynamic-rules": DumpDynamicRulesCommand,
}

command_help = """
  fetch                Fetch rule sources
  source               Manage rule sources
  disable              Disable rules
  search               Search rules
  apply                Apply ruleset modifications and write
  config               Configuration commands
  dump-dynamic-rules   Dump dynamic rules
"""
