# Copyright (c) 2017 Jason Ish
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
import tempfile

try:
    import unittest2 as unittest
except:
    import unittest

from idstools import suricata

class Suricata(unittest.TestCase):
    """ Tests for idstools/suricata.py."""

    @unittest.skipIf(
        suricata.get_path() is None,
        "suricata application not found on path")
    def test_get_version(self):
        version = suricata.get_version()

    def test_parse_version_string(self):
        """Test parsing the version from a string buffer, as returned from
        subprocess.check_output in Python 2.7.
        """
        buf = "This is Suricata version 3.1.3 RELEASE"
        version = suricata.parse_version(buf)
        self.assertIsNotNone(version)
        self.assertEqual(version.major, 3)
        self.assertEqual(version.minor, 1)
        self.assertEqual(version.patch, 3)
        self.assertEqual(version.full, "3.1.3")
        self.assertEqual(version.raw, buf)

    def test_parse_version_bytes(self):
        """Test parsing the version from a string buffer, as returned from
        subprocess.check_output in Python 3.
        """
        buf = b"This is Suricata version 3.1.3 RELEASE"
        version = suricata.parse_version(buf)
        self.assertIsNotNone(version)
        self.assertEqual(version.major, 3)
        self.assertEqual(version.minor, 1)
        self.assertEqual(version.patch, 3)
        self.assertEqual(version.full, "3.1.3")
        self.assertEqual(version.raw, buf)

    def test_parse_version_3_part(self):
        """Test parsing of a short version like "3.2.1" as may be provided by
        the user on the command line. """
        buf = "3.2.1"
        version = suricata.parse_version(buf)
        self.assertIsNotNone(version)
        self.assertEqual(version.major, 3)
        self.assertEqual(version.minor, 2)
        self.assertEqual(version.patch, 1)
        self.assertEqual(version.full, "3.2.1")
        self.assertEqual(version.raw, "3.2.1")

    def test_parse_version_2_part(self):
        """Test parsing of a short version like "3.2" as may be provided by
        the user on the command line. """
        buf = "3.2"
        version = suricata.parse_version(buf)
        self.assertIsNotNone(version)
        self.assertEqual(version.major, 3)
        self.assertEqual(version.minor, 2)
        self.assertEqual(version.patch, 0)
        self.assertEqual(version.full, "3.2")
        self.assertEqual(version.raw, "3.2")
        
    def test_parse_version_dev(self):
        buf = "This is Suricata version 4.0dev (rev 0fc9003)"
        version = suricata.parse_version(buf)
        self.assertIsNotNone(version)
        self.assertEqual(version.major, 4)
        self.assertEqual(version.minor, 0)
        self.assertEqual(version.patch, 0)
        self.assertEqual(version.full, "4.0dev")
        self.assertEqual(version.raw, buf)
