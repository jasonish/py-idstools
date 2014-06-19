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

import re
import fnmatch

class ReRuleMatcher(object):

    def __init__(self, pattern):
        self.pattern = pattern

    def match(self, rule):
        if self.pattern.search(rule.raw):
            return True
        else:
            return False

    def __repr__(self):
        return "re:%s" % (self.pattern.pattern)

    @classmethod
    def parse(cls, buf):
        if buf.startswith("re:"):
            try:
                pattern = re.compile(buf.split(":", 1)[1], re.I)
                return cls(pattern)
            except:
                pass
        return None

class SidRuleMatcher(object):

    def __init__(self, gid, sid):
        self.gid = gid
        self.sid = sid

    def match(self, rule):
        return self.gid == rule.gid and self.sid == rule.sid

    def __repr__(self):
        return "%d:%d" % (self.gid, self.sid)

    @classmethod
    def parse(cls, buf):
        try:
            parts = buf.split(":")
            if len(parts) == 1:
                return cls(1, int(parts[0]))
            elif len(parts) > 1:
                return cls(int(parts[0]), int(parts[1]))
        except:
            pass

class ClasstypeMatcher(object):

    def __init__(self, classtype):
        self.classtype = classtype

    def match(self, rule):
        return rule.classtype == self.classtype

    def __repr__(self):
        return "classtype:%s" % (self.classtype)

    @classmethod
    def parse(cls, buf):
        if buf.startswith("classtype:"):
            try:
                classtype = buf.split(":", 1)[1]
                return cls(classtype)
            except:
                pass
        return None

class GroupMatcher(object):

    def __init__(self, group):
        self.group = group

    def match(self, rule):
        if hasattr(rule, "group") and rule.group is not None:
            return fnmatch.fnmatch(rule.group, self.group)
        return False

    def __repr__(self):
        return "group:%s" % (self.group)

    @classmethod
    def parse(cls, buf):
        if buf.startswith("group:"):
            try:
                group = buf.split(":", 1)[1]
                return cls(group)
            except:
                pass
        return None

matchers = [
    SidRuleMatcher,
    ReRuleMatcher,
    ClasstypeMatcher,
    GroupMatcher,
]

def parse(buf):
    for cls in matchers:
        matcher = cls.parse(buf)
        if matcher:
            return matcher
