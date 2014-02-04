import unittest

from idstools.maps import ClassificationMap

class ClassificationMapTestCase(unittest.TestCase):

    test_filename = "tests/classification.config"

    def test_load_from_file(self):
        m = ClassificationMap(open(self.test_filename))
        
        # Classifications are indexed at 1.
        self.assertEquals(None, m.get(0))
        
        c = m.get(1)
        self.assertEquals("not-suspicious", c["name"])
        self.assertEquals("Not Suspicious Traffic", c["description"])
        self.assertEquals(3, c["priority"])

        c = m.get(34)
        self.assertEquals("default-login-attempt", c["name"])
        self.assertEquals("Attempt to Login By a Default Username and Password",
                          c["description"])
        self.assertEquals(2, c["priority"])

        c = m.get_by_name("unknown")
        self.assertTrue(c is not None)
        self.assertEquals("unknown", c["name"])
        self.assertEquals("Unknown Traffic", c["description"])
        self.assertEquals(3, c["priority"])
