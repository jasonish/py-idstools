# Copyright (c) 2013 Jason Ish
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
import sys
import shutil
import tempfile
import time
import logging
import os

from idstools import spool

logging.basicConfig(level=logging.DEBUG)

LOG = logging.getLogger(__name__)

class SpoolTestCase(unittest.TestCase):

    def open(self, filename, mode=None):
        return open("%s/%s" % (self.tmpdir, filename), mode)

class TestSpoolDirectoryReader(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="idstools-test.")
        self.prefix = "idstools-test"

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_open_next(self):
        reader = spool.BaseSpoolDirectoryReader(self.tmpdir, self.prefix)
        self.assertEqual(None, reader.fileobj)
        reader.open_next()
        self.assertEqual(None, reader.fileobj)

        open("%s/%s.0" % (self.tmpdir, self.prefix), "w").close()
        reader.open_next()
        self.assertNotEqual(None, reader.fileobj)
        self.assertEqual(reader.fileobj.name, "%s/%s.0" % (
                self.tmpdir, self.prefix))

        # Attempting to open the next file should do nothing, as there
        # is no new file top open.
        reader.open_next()
        self.assertNotEqual(None, reader.fileobj)
        self.assertEqual(reader.fileobj.name, "%s/%s.0" % (
                self.tmpdir, self.prefix))

        time.sleep(1)

        # Add another file, open_next should open it.
        open("%s/%s.1" % (self.tmpdir, self.prefix), "w").close()
        reader.open_next()
        self.assertEqual(reader.fileobj.name, "%s/%s.1" % (
                self.tmpdir, self.prefix))

    def test_getfiles(self):
        reader = spool.BaseSpoolDirectoryReader(self.tmpdir, self.prefix)
        files = reader.get_files()
        self.assertEqual(files, [])
        open("%s/%s.1" % (self.tmpdir, self.prefix), "w").close()
        files = reader.get_files()
        self.assertEqual(files, ["idstools-test.1"])
        
        # Sleep for one second, as the default mtime sorted only has
        # one second resolution.
        time.sleep(1)

        # Add another file, verify that mtime sort order works.
        open("%s/%s.0" % (self.tmpdir, self.prefix), "w").close()
        files = reader.get_files()
        self.assertEqual(files, ["idstools-test.1", "idstools-test.0"])
        
        # Add a file that should not get returned.
        open("%s/blah.1" % (self.tmpdir), "w").close()
        self.assertFalse("blah.1" in reader.get_files())

class TestLineSpoolReader(SpoolTestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="idstools-test.")
        self.prefix = "line.log"

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_open_at_bookmark(self):
        open("%s/%s.1" % (self.tmpdir, self.prefix), "w").write(
            "line1\nline2\nline3\n")
        reader = spool.LineSpoolReader(self.tmpdir, self.prefix,
                                       bookmarking=True)
        self.assertNotEqual(None, reader.next())
        self.assertNotEqual(None, reader.next())

        # For line reading, the offset is the actual offset in the
        # file.
        offset = reader.fileobj.tell()

        # Open a new reader and check the current offset.
        reader.close()
        reader = spool.LineSpoolReader(self.tmpdir, self.prefix,
                                       bookmarking=True)
        self.assertEqual(offset, reader.fileobj.tell())
        
        # Should be able to read one record, and then get None.
        self.assertNotEqual(None, reader.next())
        self.assertEqual(None, reader.next())

    def test_delete_on_close(self):
        reader = spool.LineSpoolReader(self.tmpdir, self.prefix,
                                       delete_on_close=True)
        self.open("%s.1" % (self.prefix), "w").write("line1\n")
        self.assertTrue(os.path.exists("%s/%s.1" % (self.tmpdir, self.prefix)))
        self.assertEqual(reader.next(), "line1")
        time.sleep(1)
        self.open("%s.2" % (self.prefix), "w").write("line2\n")
        self.assertEqual(reader.next(), "line2")
        self.assertFalse(os.path.exists("%s/%s.1" % (self.tmpdir, self.prefix)))

    def test_hooks(self):

        hook_count = {
            "open": 0,
            "close": 0,
            }

        def open_hook(reader, filename):
            hook_count["open"] += 1

        def close_hook(reader, filename):
            hook_count["close"] += 1

        reader = spool.LineSpoolReader(self.tmpdir, self.prefix,
                                       open_hook=open_hook,
                                       close_hook=close_hook)
        self.open("%s.1" % (self.prefix), "w").write("line1\n")
        self.assertNotEqual(None, reader.next())
        self.assertEqual(hook_count["open"], 1)
        time.sleep(1)
        self.open("%s.2" % (self.prefix), "w").write("line2\n")
        self.assertNotEqual(None, reader.next())
        self.assertEqual(hook_count["close"], 1)
        self.assertEqual(hook_count["open"], 2)

class TestUnified2RecordSpoolReader(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="idstools-test.")
        self.prefix = "unified2.log"

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_open_at_bookmark(self):
        shutil.copy("tests/merged.log", "%s/%s.1" % (self.tmpdir, self.prefix))
        reader = spool.Unified2RecordSpoolReader(self.tmpdir, self.prefix,
                                                 bookmarking=True)
        self.assertNotEqual(None, reader.next())
        offset = reader.fileobj.tell()
        self.assertTrue(offset > 0)
        reader.close()

        reader = spool.Unified2RecordSpoolReader(self.tmpdir, self.prefix,
                                                 bookmarking=True)
        self.assertEqual(offset, reader.fileobj.tell())

class TestUnified2EventSpoolReader(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="idstools-test.")
        self.prefix = "unified2.log"

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def test_open_at_bookmark(self):
        shutil.copy("tests/merged.log", "%s/%s.1" % (self.tmpdir, self.prefix))
        reader = spool.Unified2EventSpoolReader(self.tmpdir, self.prefix,
                                                 bookmarking=True)
        self.assertNotEqual(None, reader.next())
        offset = reader.fileobj.tell()
        self.assertTrue(offset > 0)
        reader.close()

        reader = spool.Unified2EventSpoolReader(self.tmpdir, self.prefix,
                                                 bookmarking=True)
        self.assertEqual(offset, reader.fileobj.tell())
