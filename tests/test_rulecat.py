# Copyright (c) 2015 Jason Ish
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

import unittest
import shlex
import re

import idstools.rule
from idstools.scripts import rulecat

class ThresholdProcessorTestCase(unittest.TestCase):

    processor = rulecat.ThresholdProcessor()

    def test_extract_regex(self):
        processor = rulecat.ThresholdProcessor()

        line = "suppress re:java"
        self.assertEquals("java", processor.extract_regex(line))
        
        line = 'suppress re:"vulnerable java version"'
        self.assertEquals(
            "vulnerable java version", processor.extract_regex(line))

        line = "suppress re:java, track <by_src|by_dst>, ip <ip|subnet>"
        self.assertEquals("java", processor.extract_regex(line))
    
        line = 'suppress re:"vulnerable java version", track <by_src|by_dst>, ip <ip|subnet>'
        self.assertEquals(
            "vulnerable java version", processor.extract_regex(line))

        line = 'threshold re:"vulnerable java version", type threshold, track by_dst, count 1, seconds 10'
        self.assertEquals(
            "vulnerable java version", processor.extract_regex(line))

    def test_replace(self):
        rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""
        rule = idstools.rule.parse(rule_string)

        line = "suppress re:windows"
        self.assertEquals(
            "suppress gen_id 1, sig_id 2020757",
            self.processor.replace(line, rule))

        line = 'threshold re:"ET MALWARE Windows", type threshold, ' \
               'track by_dst, count 1, seconds 10'
        self.assertEquals("threshold gen_id 1, sig_id 2020757, type threshold, track by_dst, count 1, seconds 10", self.processor.replace(line, rule))

        line = 'threshold re:malware, type threshold, track by_dst, count 1, ' \
               'seconds 10'
        self.assertEquals(
            "threshold gen_id 1, sig_id 2020757, type threshold, "
            "track by_dst, count 1, seconds 10",
            self.processor.replace(line, rule))

class ModifyRuleFilterTestCase(unittest.TestCase):

    rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""

    def test_id_match(self):
        rule0 = idstools.rule.parse(self.rule_string)
        line = '2020757 "\|0d 0a\|" "|ff ff|"'
        rule_filter = rulecat.ModifyRuleFilter.parse(line)
        self.assertTrue(rule_filter != None)
        self.assertTrue(rule_filter.match(rule0))
        rule1 = rule_filter.filter(rule0)
        self.assertEqual(
            str(rule1),
            """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|ff ff|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)""")

    def test_re_match(self):
        rule0 = idstools.rule.parse(self.rule_string)
        line = 're:classtype:trojan-activity "\|0d 0a\|" "|ff ff|"'
        rule_filter = rulecat.ModifyRuleFilter.parse(line)
        self.assertTrue(rule_filter != None)
        self.assertTrue(rule_filter.match(rule0))
        rule1 = rule_filter.filter(rule0)
        self.assertEqual(
            str(rule1),
            """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|ff ff|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)""")

class GroupMatcherTestCase(unittest.TestCase):

    rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""

    def test_match(self):
        rule = idstools.rule.parse(self.rule_string, "rules/malware.rules")
        matcher = rulecat.GroupMatcher.parse("group: */malware.rules")
        self.assertTrue(matcher.match(rule))

class DropRuleFilterTestCase(unittest.TestCase):

    rule_string = """alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"ET MALWARE Windows executable sent when remote host claims to send an image 2"; flow: established,from_server; content:"|0d 0a|Content-Type|3a| image/jpeg|0d 0a 0d 0a|MZ"; fast_pattern:12,20; classtype:trojan-activity; sid:2020757; rev:2;)"""

    def test_enabled_rule(self):
        rule0 = idstools.rule.parse(self.rule_string, "rules/malware.rules")
        id_matcher = rulecat.IdRuleMatcher.parse("2020757")
        self.assertTrue(id_matcher.match(rule0))

        drop_filter = rulecat.DropRuleFilter(id_matcher)
        rule1 = drop_filter.filter(rule0)
        self.assertEquals("drop", rule1.action)
        self.assertTrue(rule1.enabled)
        self.assertTrue(str(rule1).startswith("drop"))

    def test_disabled_rule(self):
        rule0 = idstools.rule.parse(
            "# " + self.rule_string, "rules/malware.rules")
        id_matcher = rulecat.IdRuleMatcher.parse("2020757")
        self.assertTrue(id_matcher.match(rule0))

        drop_filter = rulecat.DropRuleFilter(id_matcher)
        rule1 = drop_filter.filter(rule0)
        self.assertEquals("drop", rule1.action)
        self.assertFalse(rule1.enabled)
        self.assertTrue(str(rule1).startswith("# drop"))
        
    def test_drop_noalert(self):
        """ Test the rules with "noalert" are not marked as drop. """

        rule_without_noalert = """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN [CrowdStrike] ANCHOR PANDA Torn RAT Beacon Message Header Local"; flow:established, to_server; dsize:16; content:"|00 00 00 11 c8 00 00 00 00 00 00 00 00 00 00 00|"; depth:16; flowbits:set,ET.Torn.toread_header; reference:url,blog.crowdstrike.com/whois-anchor-panda/index.html; classtype:trojan-activity; sid:2016659; rev:2; metadata:created_at 2013_03_22, updated_at 2013_03_22;)"""

        rule_with_noalert = """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN [CrowdStrike] ANCHOR PANDA Torn RAT Beacon Message Header Local"; flow:established, to_server; dsize:16; content:"|00 00 00 11 c8 00 00 00 00 00 00 00 00 00 00 00|"; depth:16; flowbits:set,ET.Torn.toread_header; flowbits: noalert; reference:url,blog.crowdstrike.com/whois-anchor-panda/index.html; classtype:trojan-activity; sid:2016659; rev:2; metadata:created_at 2013_03_22, updated_at 2013_03_22;)"""

        rule = idstools.rule.parse(rule_without_noalert)
        matcher = rulecat.IdRuleMatcher.parse("2016659")
        filter = rulecat.DropRuleFilter(matcher)
        self.assertTrue(filter.match(rule))

        rule = idstools.rule.parse(rule_with_noalert)
        matcher = rulecat.IdRuleMatcher.parse("2016659")
        filter = rulecat.DropRuleFilter(matcher)
        self.assertFalse(filter.match(rule))
