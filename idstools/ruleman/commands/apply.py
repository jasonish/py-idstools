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

import idstools.rule
from idstools.ruleman import core
from idstools.ruleman import matchers as rulematchers

class ApplyCommand(object):

    def __init__(self, config, args):
        self.config = config
        self.args = args

    def run(self):

        rulesets = []

        sources = self.config.get_sources()
        for source in sources.values():
            if source["enabled"]:
                print("Loading rules from %s" % (source["name"]))
                ruleset = core.Ruleset(source)
                ruleset.load_rules()
                print("- Loaded %d rules (%d enabled)." % (
                    ruleset.total_count(),
                    ruleset.enabled_count()))

                if "policy" in source:
                    policy = source["policy"]
                    print("- Applying policy %s." % (policy))
                    ruleset.set_policy(source["policy"])
                    print("- Now %d rules enabled." % (
                        ruleset.enabled_count()))

                rulesets.append(ruleset)

        rules = {}

        for ruleset in rulesets:
            for rule_id, rule in ruleset.rules.items():
                if rule.id in rules:
                    print("Duplicate rule found:", rule.id)
                else:
                    rules[rule.id] = rule

        disabled = self.disable_rules(rules)
        print("- %s rules disabled." % (len(disabled)))

        enabled = self.enable_rules(rules)
        print("- %s rules enabled." % (len(enabled)))

        flowbit_resolver = idstools.rule.FlowbitResolver()
        enabled = flowbit_resolver.resolve(rules)
        print("- Enabled %d rules for flowbit dependencies." % (len(enabled)))

        count = 0
        with open("snort.rules", "wb") as fileobj:
            for rule in rules.values():
                if rule.enabled:
                    fileobj.write((str(rule) + "\n").encode())
                    count += 1
        print("Wrote %d rules to %s." % (count, "snort.rules"))

    def disable_rules(self, rules):
        matchers = []
        for entry in self.config["disabled-rules"]:
            matchers.append(rulematchers.parse(entry["matcher"]))

        disabled = []
        for rule in rules.values():
            for matcher in matchers:
                if matcher.match(rule) and rule.enabled:
                    rule.enabled = False
                    disabled.append(rule)

        return disabled

    def enable_rules(self, rules):
        matchers = []
        for entry in self.config["enabled-rules"]:
            matchers.append(rulematchers.parse(entry["matcher"]))

        enabled = []
        for rule in rules.values():
            for matcher in matchers:
                if matcher.match(rule) and not rule.enabled:
                    rule.enabled = True
                    enabled.append(rule)

        return enabled

