# Copyright (c) 2011-2013 Jason Ish
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

import idstools.rule
from idstools.ruleman import util
from idstools.ruleman.matchers import GroupMatcher

class RulemanUtilTestCase(unittest.TestCase):

    def test_get_filename_from_url(self):

        url = "http://localhost/ruleset.tar.gz"
        filename = "ruleset.tar.gz"
        self.assertEqual(util.get_filename_from_url(url), filename)

        url = "http://localhost/ruleset.tar.gz/some-oink-code"
        filename = "ruleset.tar.gz"
        self.assertEqual(util.get_filename_from_url(url), filename)

class GroupMatcherTestCase(unittest.TestCase):

    def test_parse(self):

        self.assertTrue(GroupMatcher.parse("re:something") == None)
        self.assertTrue(GroupMatcher.parse("classtype:something") == None)
        self.assertTrue(GroupMatcher.parse("groups:asdf") == None)

        self.assertTrue(
            GroupMatcher.parse("group:rules/stream-event.rules") != None)

    def test_match(self):
        matcher = GroupMatcher.parse("group:rules/stream-events.rules")
        
        rule = idstools.rule.Rule()
        self.assertFalse(matcher.match(rule))

        rule.group = "rules/stream-events.rules"
        self.assertTrue(matcher.match(rule))

        matcher = GroupMatcher.parse("group:*/stream-events.rules")
        self.assertTrue(matcher.match(rule))

        matcher = GroupMatcher.parse("group:*stream-events.rules")
        self.assertTrue(matcher.match(rule))

        matcher = GroupMatcher.parse("group:rules/stream-events*")
        self.assertTrue(matcher.match(rule))
