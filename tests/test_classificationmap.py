import unittest

from idstools.maps import ClassificationMap

class ClassificationMapTestCase(unittest.TestCase):

    test_filename = "tests/classification.config"

    def test_load_from_file(self):
        with open(self.test_filename) as test_file:
            m = ClassificationMap(test_file)

        # Classifications are indexed at 1.
        self.assertEqual(None, m.get(0))

        c = m.get(1)
        self.assertEqual("not-suspicious", c["name"])
        self.assertEqual("Not Suspicious Traffic", c["description"])
        self.assertEqual(3, c["priority"])

        c = m.get(34)
        self.assertEqual("default-login-attempt", c["name"])
        self.assertEqual("Attempt to Login By a Default Username and Password",
                          c["description"])
        self.assertEqual(2, c["priority"])

        c = m.get_by_name("unknown")
        self.assertTrue(c is not None)
        self.assertEqual("unknown", c["name"])
        self.assertEqual("Unknown Traffic", c["description"])
        self.assertEqual(3, c["priority"])
