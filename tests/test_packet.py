# Copyright (c) 2014 Jason Ish
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

try:
    import unittest2 as unittest
except:
    import unittest

from idstools import packet

class TestIPv6WithExtensionHeader(unittest.TestCase):

    def setUp(self):
        with open("tests/NPD_2_1_2_1_Type_0.pcap", "rb") as file:
            self.packet = file.read()[40:]

    def test_decode(self):
        decoded = packet.decode_ethernet(self.packet)
        self.assertEqual("3000:0000:0000:0000:0000:0000:0000:0001",
                         decoded["ip6_source"])
        self.assertEqual("3001:0000:0000:0000:0000:0000:0000:0001",
                         decoded["ip6_destination"])
        self.assertEqual(128, decoded["icmp_type"])
        self.assertEqual(0, decoded["icmp_code"])
        self.assertEqual(0x1fba, decoded["icmp_chksum"])
