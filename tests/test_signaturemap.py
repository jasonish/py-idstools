import unittest

from idstools import maps

class SignatureMapTestCase(unittest.TestCase):

    def test_load_generator_map(self):

        sigmap = maps.SignatureMap()
        with open("tests/gen-msg.map") as infile:
            sigmap.load_generator_map(infile)

        sig = sigmap.get(1, 1)
        self.assertTrue(sig is not None)
        self.assertEqual(1, sig["gid"])
        self.assertEqual(1, sig["sid"])
        self.assertEqual("snort general alert", sig["msg"])

        sig = sigmap.get(139, 1)
        self.assertTrue(sig is not None)
        self.assertEqual(139, sig["gid"])
        self.assertEqual(1, sig["sid"])
        self.assertEqual(
            "sensitive_data: sensitive data global threshold exceeded",
            sig["msg"])

    def test_load_signature_map(self):

        sigmap = maps.SignatureMap()
        with open("tests/sid-msg.map") as infile:
            sigmap.load_signature_map(infile)

        # Get a basic signature.
        sig = sigmap.get(1, 2000356)
        self.assertTrue(sig is not None)
        self.assertEqual(1, sig["gid"])
        self.assertEqual(2000356, sig["sid"])
        self.assertEqual("ET POLICY IRC connection", sig["msg"])
        self.assertEqual(len(sig["ref"]), 1)
        self.assertEqual("url,doc.emergingthreats.net/2000356", sig["ref"][0])

        # Try again but with a gid of 3.
        self.assertEqual(sig, sigmap.get(3, 2000356))

        # This signature has multiple refs.
        sig = sigmap.get(1, 2000373)
        self.assertEqual(3, len(sig["ref"]))

        sig = sigmap.get(1, 71918985)
        self.assertEqual(
            "SN: Inbound TCP traffic from suspect network (AS29073 - NL)",
            sig["msg"])

    def test_load_signature_v2_map(self):

        sigmap = maps.SignatureMap()
        with open("tests/sid-msg-v2.map") as infile:
            sigmap.load_signature_map(infile)

        sig = sigmap.get(1, 2495)
        self.assertEqual(1, sig["gid"])
        self.assertEqual(2495, sig["sid"])
        self.assertEqual("misc-attack", sig["classification"])
        self.assertEqual(0, sig["priority"])
        self.assertEqual(
            "GPL NETBIOS SMB DCEPRC ORPCThis request flood attempt",
            sig["msg"])
        self.assertEqual(4, len(sig["ref"]))
