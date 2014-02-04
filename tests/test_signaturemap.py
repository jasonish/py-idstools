import unittest

from idstools import maps

class SignatureMapTestCase(unittest.TestCase):

    def test_load_generator_map(self):

        sigmap = maps.SignatureMap()
        sigmap.load_generator_map(open("tests/gen-msg.map"))

        sig = sigmap.get(1, 1)
        self.assertTrue(sig is not None)
        self.assertEquals(1, sig["gid"])
        self.assertEquals(1, sig["sid"])
        self.assertEquals("snort general alert", sig["msg"])

        sig = sigmap.get(139, 1)
        self.assertTrue(sig is not None)
        self.assertEquals(139, sig["gid"])
        self.assertEquals(1, sig["sid"])
        self.assertEquals(
            "sensitive_data: sensitive data global threshold exceeded",
            sig["msg"])

    def test_load_signature_map(self):

        sigmap = maps.SignatureMap()
        sigmap.load_signature_map(open("tests/sid-msg.map"))

        # Get a basic signature.
        sig = sigmap.get(1, 2000356)
        self.assertTrue(sig is not None)
        self.assertEquals(1, sig["gid"])
        self.assertEquals(2000356, sig["sid"])
        self.assertEquals("ET POLICY IRC connection", sig["msg"])
        self.assertEquals(len(sig["ref"]), 1)
        self.assertEquals("url,doc.emergingthreats.net/2000356", sig["ref"][0])

        # Try again but with a gid of 3.
        self.assertEquals(sig, sigmap.get(3, 2000356))

        # This signature has multiple refs.
        sig = sigmap.get(1, 2000373)
        print(sig)
        self.assertEquals(3, len(sig["ref"]))

    def test_load_signature_v2_map(self):

        sigmap = maps.SignatureMap()
        sigmap.load_signature_map(open("tests/sid-msg-v2.map"))

        sig = sigmap.get(1, 2495)
        self.assertEquals(1, sig["gid"])
        self.assertEquals(2495, sig["sid"])
        self.assertEquals("misc-attack", sig["classification"])
        self.assertEquals(0, sig["priority"])
        self.assertEquals(
            "GPL NETBIOS SMB DCEPRC ORPCThis request flood attempt",
            sig["msg"])
        self.assertEquals(4, len(sig["ref"]))