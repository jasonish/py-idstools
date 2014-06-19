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

import os
import os.path
import io

import idstools.rule

class Ruleset(object):

    def __init__(self, config):
        self.config = config
        self.directory = os.path.abspath(
            os.path.join("sources", self.config["name"]))

        # Rules keyed by (gid, sid).  Loaded by load_rules.
        self.rules = {}

        # Cache for the filenames.
        self._filenames = None

    def get_filenames(self):

        if self._filenames is not None:
            return self._filenames

        self._filenames = []

        for dirpath, dirnames, filenames in os.walk(self.directory):
            for filename in filenames:
                path = os.path.join(dirpath[len(self.directory) + 1:], filename)
                if not path in self.config["ignore-files"]:
                    self._filenames.append(path)

        return self._filenames

    def total_count(self):
        return len(self.rules)

    def enabled_count(self):
        return len([rule for rule in self.rules.values() if rule.enabled])

    def get_fileobj(self, filename):
        return open(os.path.join(self.directory, filename), "rb")

    def load_rules(self):
        for filename in self.get_filenames():
            if not filename.endswith(".rules"):
                continue
            for rule in idstools.rule.parse_fileobj(
                    self.get_fileobj(filename), filename):
                if rule.id in self.rules:
                    print("warning: duplicate rule id found")
                else:
                    self.rules[rule.id] = rule

    def set_policy(self, policy):
        for rule in self.rules.values():
            if policy in self.get_policies(rule):
                rule.enabled = True
            else:
                rule.enabled = False

    def get_policies(self, rule):
        policies = []
        for item in rule.metadata:
            if item.startswith("policy"):
                parts = item.split()
                policies.append(parts[1])
        return policies