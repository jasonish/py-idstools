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

import sys
import unittest
import io
import tempfile

import idstools.rule

class RuleTestCase(unittest.TestCase):

    def test_parse1(self):
        # Some mods have been made to this rule (flowbits) for the
        # purpose of testing.
        rule = idstools.rule.parse("""alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET CURRENT_EVENTS Request to .in FakeAV Campaign June 19 2012 exe or zip"; flow:established,to_server; content:"setup."; fast_pattern:only; http_uri; content:".in|0d 0a|"; flowbits:isset,somebit; flowbits:unset,otherbit; http_header; pcre:"/\/[a-f0-9]{16}\/([a-z0-9]{1,3}\/)?setup\.(exe|zip)$/U"; pcre:"/^Host\x3a\s.+\.in\r?$/Hmi"; metadata:stage,hostile_download; reference:url,isc.sans.edu/diary/+Vulnerabilityqueerprocessbrittleness/13501; classtype:trojan-activity; sid:2014929; rev:1;)""")
        self.assertEqual(rule.enabled, True)
        self.assertEqual(rule.action, "alert")
        self.assertEquals(rule.proto, "tcp")
        self.assertEquals(rule.source_addr, "$HOME_NET")
        self.assertEquals(rule.source_port, "any")
        self.assertEqual(rule.direction, "->")
        self.assertEquals(rule.dest_addr, "$EXTERNAL_NET")
        self.assertEquals(rule.dest_port, "$HTTP_PORTS")
        self.assertEqual(rule.sid, 2014929)
        self.assertEqual(rule.rev, 1)
        self.assertEqual(rule.msg, "ET CURRENT_EVENTS Request to .in FakeAV Campaign June 19 2012 exe or zip")
        self.assertEqual(len(rule.metadata), 2)
        self.assertEqual(rule.metadata[0], "stage")
        self.assertEqual(rule.metadata[1], "hostile_download")
        self.assertEqual(len(rule.flowbits), 2)
        self.assertEquals(rule.flowbits[0], "isset,somebit")
        self.assertEquals(rule.flowbits[1], "unset,otherbit")
        self.assertEqual(len(rule.xbits), 0)
        self.assertEqual(len(rule.flowints), 0)
        self.assertEquals(rule.classtype, "trojan-activity")

    def test_disable_rule(self):
        rule_buf = """# alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)"""
        rule = idstools.rule.parse(rule_buf)
        self.assertFalse(rule.enabled)
        self.assertEquals(rule.raw, """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)""")
        self.assertEquals(str(rule), rule_buf)

    def test_parse_rule_double_commented(self):
        rule_buf = """## alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)"""
        rule = idstools.rule.parse(rule_buf)
        self.assertFalse(rule.enabled)
        self.assertEquals(rule.raw, """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)""")

    def test_parse_rule_comments_and_spaces(self):
        rule_buf = """## #alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)"""
        rule = idstools.rule.parse(rule_buf)
        self.assertFalse(rule.enabled)
        self.assertEquals(rule.raw, """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)""")

    def test_toggle_rule(self):
        rule_buf = """# alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)"""
        rule = idstools.rule.parse(rule_buf)
        self.assertFalse(rule.enabled)
        rule.enabled = True
        self.assertEquals(str(rule), """alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"some message";)""")

    def test_parse_fileobj(self):
        rule_buf = ("""# alert tcp $HOME_NET any -> $EXTERNAL_NET any """
                    """(msg:"some message";)""")
        fileobj = io.StringIO()
        for i in range(2):
            fileobj.write(u"%s\n" % rule_buf)
        fileobj.seek(0)
        rules = idstools.rule.parse_fileobj(fileobj)
        self.assertEquals(2, len(rules))

    def test_parse_file(self):
        rule_buf = ("""# alert tcp $HOME_NET any -> $EXTERNAL_NET any """
                    """(msg:"some message";)""")
        tmp = tempfile.NamedTemporaryFile()
        for i in range(2):
            tmp.write(("%s\n" % rule_buf).encode())
        tmp.flush()
        rules = idstools.rule.parse_file(tmp.name)
        self.assertEquals(2, len(rules))

    def test_parse_file_with_unicode(self):
        rules = idstools.rule.parse_file("./tests/rule-with-unicode.rules")

    def test_parse_decoder_rule(self):
        rule_string = """alert ( msg:"DECODE_NOT_IPV4_DGRAM"; sid:1; gid:116; rev:1; metadata:rule-type decode; classtype:protocol-command-decode;)"""
        rule = idstools.rule.parse(rule_string)
        self.assertEquals(rule["direction"], None)

    def test_multiline_rule(self):
        rule_string = u"""
alert dnp3 any any -> any any (msg:"SURICATA DNP3 Request flood detected"; \
      app-layer-event:dnp3.flooded; sid:2200104; rev:1;)
"""
        rules = idstools.rule.parse_fileobj(io.StringIO(rule_string))
        self.assertEquals(len(rules), 1)

    def test_parse_nomsg(self):
        rule_string = u"""alert ip any any -> any any (content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000000; rev:1;)"""
        rule = idstools.rule.parse(rule_string)
        self.assertEquals("", rule["msg"])

    def test_add_option(self):
        rule_string = u"""alert ip any any -> any any (content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000000; rev:1;)"""
        rule = idstools.rule.parse(rule_string, "local.rules")
        rule = idstools.rule.add_option(
            rule, "msg", "\"This is a test description.\"", 0)
        self.assertEquals("This is a test description.", rule["msg"])
        self.assertEquals("local.rules", rule["group"])

    def test_remove_option(self):
        rule_string = u"""alert ip any any -> any any (msg:"TEST MESSAGE"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:10000000; rev:1;)"""
        rule = idstools.rule.parse(rule_string, "local.rules")

        rule = idstools.rule.remove_option(rule, "msg")
        self.assertEquals("", rule["msg"])

        rule = idstools.rule.remove_option(rule, "classtype")
        self.assertEquals(None, rule["classtype"])

    def test_remove_tag_option(self):
        rule_string = u"""alert ip any any -> any any (msg:"TEST RULE"; content:"uid=0|28|root|29|"; tag:session,5,packets; classtype:bad-unknown; sid:10000000; rev:1;)"""
        rule = idstools.rule.parse(rule_string)
        self.assertIsNotNone(rule)
        print(rule["options"])

    def test_scratch(self):
        rule_string = """alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET CURRENT_EVENTS Request to .in FakeAV Campaign June 19 2012 exe or zip"; flow:established,to_server; content:"setup."; fast_pattern:only; http_uri; content:".in|0d 0a|"; flowbits:isset,somebit; flowbits:unset,otherbit; http_header; pcre:"/\/[a-f0-9]{16}\/([a-z0-9]{1,3}\/)?setup\.(exe|zip)$/U"; pcre:"/^Host\x3a\s.+\.in\r?$/Hmi"; metadata:stage,hostile_download; reference:url,isc.sans.edu/diary/+Vulnerabilityqueerprocessbrittleness/13501; classtype:trojan-activity; sid:2014929; rev:1;)"""
        rule = idstools.rule.parse(rule_string)
        self.assertEquals(rule_string, str(rule))

        options = []
        for option in rule["options"]:
            if option["value"] is None:
                options.append(option["name"])
            else:
                options.append("%s:%s" % (option["name"], option["value"]))

        reassembled = "%s (%s)" % (rule["header"], rule.rebuild_options())

        print("")
        print("%s" % rule_string)
        print("%s" % reassembled)

        self.assertEquals(rule_string, reassembled)

    def test_parse_message_with_semicolon(self):
        rule_string = u"""alert ip any any -> any any (msg:"TEST RULE\; and some"; content:"uid=0|28|root|29|"; tag:session,5,packets; classtype:bad-unknown; sid:10000000; rev:1;)"""
        rule = idstools.rule.parse(rule_string)
        self.assertIsNotNone(rule)
        self.assertEquals(rule.msg, "TEST RULE\; and some")

        # Look for the expected content.
        found=False
        for o in rule.options:
            if o["name"] == "content" and o["value"] == '"uid=0|28|root|29|"':
                found=True
                break
        self.assertTrue(found)

    def test_parse_message_with_colon(self):
        rule_string = u"""alert tcp 93.174.88.0/21 any -> $HOME_NET any (msg:"SN: Inbound TCP traffic from suspect network (AS29073 - NL)"; flags:S; reference:url,https://suspect-networks.io/networks/cidr/13/; threshold: type limit, track by_dst, seconds 30, count 1; classtype:misc-attack; sid:71918985; rev:1;)"""
        rule = idstools.rule.parse(rule_string)
        self.assertIsNotNone(rule)
        self.assertEquals(
            rule.msg,
            "SN: Inbound TCP traffic from suspect network (AS29073 - NL)")

    def test_parse_multiple_metadata(self):
        # metadata: former_category TROJAN;
        # metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Onion_Domain, tag Ransomware, signature_severity Major, created_at 2017_08_08, malware_family Crypton, malware_family Nemesis, performance_impact Low, updated_at 2017_08_08;
        rule_string = u"""alert udp $HOME_NET any -> any 53 (msg:"ET TROJAN CryptON/Nemesis/X3M Ransomware Onion Domain"; content:"|01 00 00 01 00 00 00 00 00 00|"; depth:10; offset:2; content:"|10|yvvu3fqglfceuzfu"; fast_pattern; distance:0; nocase; metadata: former_category TROJAN; reference:url,blog.emsisoft.com/2017/05/01/remove-cry128-ransomware-with-emsisofts-free-decrypter/; reference:url,www.cyber.nj.gov/threat-profiles/ransomware-variants/crypt-on; classtype:trojan-activity; sid:2024525; rev:2; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, deployment Perimeter, tag Ransomware_Onion_Domain, tag Ransomware, signature_severity Major, created_at 2017_08_08, malware_family Crypton, malware_family Nemesis, performance_impact Low, updated_at 2017_08_08;)"""
        rule = idstools.rule.parse(rule_string)
        self.assertIsNotNone(rule)
        self.assertTrue("former_category TROJAN" in rule.metadata)
        self.assertTrue("updated_at 2017_08_08" in rule.metadata)

    def test_metadata_missing_semicolon(self):
        rule_buf = u""" alert icmp any any -> $HOME_NET any (msg:"ICMP test detected"; gid:0; sid:10000001; rev:1; classtype: icmp-event; metadata:policy balanced-ips drop, policy connectivity-ips drop, policy security-ips drop)"""
        self.assertRaises(Exception, idstools.rule.parse, rule_buf)

    def test_parse(self):
        rs = u"""alert any [1.1.1.1, !2.2.2.2] any -> any [1,2,3] (msg:"TEST"; sid:1; rev:1;)"""
        rule = idstools.rule.parse(rs)
        self.assertIsNotNone(rule)

    def test_parse_flowint_rule(self):
        rs = u"""alert tcp any any -> any any (msg:"Counting Usernames"; content:"jonkman"; flowint: usernamecount, +, 1; noalert;)"""
        rule = idstools.rule.parse(rs)
        self.assertEqual(len(rule.flowints), 1)
        self.assertEqual(rule.flowints[0], "usernamecount, +, 1")

        rs = """alert tcp any any -> any any (msg:"More than Five Usernames!"; content:"jonkman"; flowint: usernamecount, +, 1; flowint:usernamecount, >, 5;)"""
        rule = idstools.rule.parse(rs)
        self.assertEqual(len(rule.flowints), 2)
        self.assertEqual(rule.flowints[0], "usernamecount, +, 1")
        self.assertEqual(rule.flowints[1], "usernamecount, >, 5")

        rs = """alert tcp any any -> any any (msg:"Setting a flowint counter"; content:"GET"; flowint:myvar, notset; flowint:maxvar,notset; flowint:myvar,=,1; flowint: maxvar,=,6;)"""
        rule = idstools.rule.parse(rs)
        self.assertEqual(len(rule.flowints), 4)
        self.assertEqual(rule.flowints[0], "myvar, notset")
        self.assertEqual(rule.flowints[1], "maxvar,notset")
        self.assertEqual(rule.flowints[2], "myvar,=,1")
        self.assertEqual(rule.flowints[3], "maxvar,=,6")

    def test_parse_xbits_rule(self):
        rs = u"""drop ssh any any -> $MYSERVER 22 (msg:"DROP libssh incoming"; flow:to_server,established; ssh.softwareversion:"libssh"; xbits:set, badssh, track ip_src, expire 3600; sid:4000000005;)"""
        rule = idstools.rule.parse(rs)
        self.assertEqual(len(rule.xbits), 1)
        self.assertEqual(rule.xbits[0], "set, badssh, track ip_src, expire 3600")

        rs = """drop ssh any any -> $MYSERVER 22 (msg:"DROP BLACKLISTED"; xbits:isset, badssh, track ip_src; sid:4000000006;)"""
        rule = idstools.rule.parse(rs)
        self.assertEqual(len(rule.xbits), 1)
        self.assertEqual(rule.xbits[0], "isset, badssh, track ip_src")
