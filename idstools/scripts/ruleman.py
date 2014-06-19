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
import os.path
import getopt
import json
import collections
import logging

import yaml

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import idstools.ruleman.commands as commands

logging.basicConfig(format="%(message)s", level=logging.INFO)

class Config(collections.MutableMapping):

    config_template = {
        "sources": {},
        "disabled-rules": [],
        "enabled-rules": [],
    }
    
    source_template = {
        "name": "",
        "url": "",
        "enabled": True,
        "ignore-files": [],
    }

    def __init__(self):
        self.store = dict()
        self.update(dict(self.config_template))

    def __getitem__(self, key):
        return self.store[key]

    def __setitem__(self, key, value):
        self.store[key] = value

    def __delitem__(self, key):
        del self.store[key]

    def __iter__(self):
        return iter(self.store)

    def __len__(self):
        return len(self.store)

    def get_sources(self):
        sources = self.store["sources"]
        for source in sources.values():
            for key, default in self.source_template.items():
                if key not in source:
                    source[key] = default
        return sources

    def save(self):
        yaml.safe_dump(
            self.store, 
            open(".ruleman.yaml", "w"), 
            default_flow_style=False)
        os.rename(".ruleman.yaml", "ruleman.yaml")

def load_config():
    config = Config()
    if os.path.exists("ruleman.yaml"):
        yaml_config = yaml.load(open("ruleman.yaml"))
        if yaml_config:
            config.update(yaml_config)
    return config

def usage():
    print("""usage: %s <command> [args...]

Commands:
%s""" % (
    os.path.basename(sys.argv[0]),
    commands.command_help))

def main():

    try:
        opts, args = getopt.getopt(sys.argv[1:], "", [])
    except getopt.GetoptError as err:
        print("error: %s" % (err), file=sys.stderr)
        return 1

    if not args:
        usage()
        return 0

    command, args = args[0], args[1:]
    config = load_config()

    if command in commands.commands:
        commands.commands[command](config, args).run()
    else:
        print("error: unknown command: %s" % (command), file=sys.stderr)
        usage()
        return 1

    # Dump a YAML config as well.
    config.save()

if __name__ == "__main__":
    sys.exit(main())
