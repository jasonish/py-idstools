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

""" Module for spool directory reading. """

import os
import fnmatch
import logging
import time

from idstools import unified2

LOG = logging.getLogger(__name__)

class SpoolDirectoryReaderIterator(object):
    """ An iterator that can be used for the spool directory readers.

    It basically just implements an infinite loop with a timeout, much
    like a user of a reader might.
    """

    def __init__(self, reader):
        self.reader = reader

    def next(self):
        while 1:
            record = self.reader.next()
            if record:
                return record
            else:
                time.sleep(0.1)

class BaseSpoolDirectoryReader(object):
    """ A base class for classes implementing spool readers.
    """

    def __init__(self, directory, prefix, open_mode="r", **kwargs):
        """
        :param directory: Spool directory to read from.
        :param prefix: Prefix of filenames to read
        :param delete_on_close: Delete file after processing and a new one 
          has been opened. Default: False
        :param bookmarking: Enable bookmarking. Default: True
        :param open_hook: Optional function to be called after a file is opened.
        :param close_hook: Optional function to be called after a file
          is closed.  This function will be called before the file is
          deleted allowing the close hook to make a copy of the file
          for archiving.
        """

        self.directory = directory
        self.prefix = prefix
        self.open_mode = open_mode

        # Delete on close.  While I think this should be default, it
        # may be unexpected.
        self.delete_on_close = kwargs.get("delete_on_close", False)

        # By default bookmarking is enabled, but it can be disabled.
        self.bookmarking = kwargs.get("bookmarking", True)

        # File opening and closing hooks.  The caller can implementing
        # something like an archive command on closing by set a close
        # hook.
        self.open_hook = kwargs.get("open_hook", None)
        self.close_hook = kwargs.get("close_hook", None)

        self.filter = "%s*" % (self.prefix)

        self.fileobj = None

        # The name of the bookmark file.
        self.bookmark_filename = "%s/_%s.bookmark" % (
            self.directory, self.prefix)

        # If we are bookmarking and have a bookmark file, attempt to
        # open at bookmark.
        if self.bookmarking:
            self.open_at_bookmark()

    def open_at_bookmark(self):
        filename, offset = self.get_bookmark()
        if filename:
            if self.exists(filename):
                self.open_file(filename)
                self.set_to_offset(offset)
                LOG.debug("Open bookmarked file %s at offset %d" % (
                        filename, offset))
            else:
                LOG.warn("Bookmarked file %s does not exist" % (filename))

    def set_bookmark(self, offset):
        """ Set the bookmark at the provided offset. If bookmarking is
        not enabled this method does nothing."""
        if self.bookmarking:
            open(self.bookmark_filename, "w").write("%s,%d" % (
                    os.path.basename(self.fileobj.name), offset))

    def get_bookmark(self):
        """ Return the current bookmark filename and offset. If there
        is no bookmark, or bookmarking is disabled then None, None
        will be returned. """
        if self.bookmarking and os.path.exists(self.bookmark_filename):
            buf = open(self.bookmark_filename).read()
            filename, record = buf.split(",")
            return filename, int(record)
        else:
            return None, None

    def default_sort_key(self, filename):
        """ This function is for use a key to sorted, to return the
        files in mtime order. """
        return os.stat("%s/%s" % (self.directory, filename)).st_mtime

    def get_files(self):
        """ Return the files in self.directory that have the prefix self.prefix.

        Files will be sorted.
        """
        files = fnmatch.filter(os.listdir(self.directory), self.filter)
        return sorted(files, key=self.default_sort_key)

    def get_next_files(self):
        """ Return the files in the spool directory that are 'after'
        the current file. """

        files = self.get_files()
        
        if self.fileobj:
            filename = os.path.basename(self.fileobj.name)
            if filename in files:
                files = files[files.index(filename) + 1:]
        
        return files

    def open_file(self, filename):
        """ Open the provided filename as set it as our active fileobj.

        If a path is provided, it will be stripped and replaced with
        the spool directory. """
        filename = os.path.basename(filename)
        self.fileobj = open(
            "%s/%s" % (self.directory, filename), self.open_mode)
        LOG.debug("Opened file %s" % filename)
        if self.open_hook:
            self.open_hook(self, filename)

    def close_file(self):
        """ Closing the currently open file, calling the close hook if
        set. """
        if self.fileobj:
            filename = os.path.basename(self.fileobj.name)
            self.fileobj.close()
            LOG.debug("Closed file %s" % (filename))
            if self.close_hook:
                self.close_hook(self, filename)
            if self.delete_on_close:
                os.unlink(os.path.join(self.directory, filename))
                LOG.debug("Deleted file %s" % (filename))

    def open_next(self):
        """ Open the next file in the spool if it exists. """
        files = self.get_next_files()
        if files:
            self.close_file()
            self.open_file(files[0])
            return True

    def close(self):
        """ Close the reader. This just closes the currently open file
        descriptor silently with no close hook. Intended to be used
        when a caller is done with a spool reader. """
        if self.fileobj:
            self.fileobj.close()

    def exists(self, filename):
        return os.path.exists(
            os.path.join(self.directory, os.path.basename(filename)))

    def __iter__(self):
        """ Provides an iterator for those that wish use a reader as
        an iterable. """
        return SpoolDirectoryReaderIterator(self)

    def next(self):
        raise NotImplementedError()

    def set_to_offset(self, offset):
        raise NotImplementedError()

class LineSpoolReader(BaseSpoolDirectoryReader):
    """ A spool reader for directories containing line based
    files. """

    def __init__(self, directory, prefix, strip_newline=True, **kwargs):
        """ In addition to the parameters provided by
        :py:class:`.BaseSpoolDirectoryReader`, the
        `LineSpoolReader` also accepts the following
        parameters.

        :param strip_newline: Strip the trailing new line characters
          from the line returned. Default: True.
        """
        super(LineSpoolReader, self).__init__(directory, prefix, **kwargs)
        self.strip_newline = strip_newline

    def set_to_offset(self, offset):
        self.fileobj.seek(offset)

    def next(self):
        if not self.fileobj and not self.open_next():
            return None

        while 1:
            offset = self.fileobj.tell()
            record = self.fileobj.readline()
            if record:
                # If there is no \n in the record, only return it if
                # there are newer spool files.  Otherwise, seek back
                # and return None.
                if "\n" not in record and not self.get_next_files():
                    self.fileobj.seek(offset)
                    return None

                self.set_bookmark(self.fileobj.tell())

                if self.strip_newline:
                    return record.strip("\r\n")
                else:
                    return record

            elif not self.open_next():
                return None

class Unified2RecordSpoolReader(BaseSpoolDirectoryReader):
    """ A record based spool reader for directories of unified2 spool
    files. """

    def __init__(self, directory, prefix, **kwargs):
        """ See :py:class:`.BaseSpoolDirectoryReader`. """
        super(Unified2RecordSpoolReader, self).__init__(
            directory, prefix, open_mode="rb", **kwargs)

    def set_to_offset(self, offset):
        self.fileobj.seek(offset)

    def next(self):
        if not self.fileobj and not self.open_next():
            return

        record = None
        try:
            record = unified2.read_record(self.fileobj)
            if record:
                self.set_bookmark(self.fileobj.tell())
        except unified2.ShortReadError:
            # We can ignore this, read_record would have reset the
            # pointer already.
            pass
        return record

class Unified2EventSpoolReader(BaseSpoolDirectoryReader):
    """ An event based reader for directories containing unified2
    spool files.
    """

    def __init__(self, directory, prefix, timeout=1, **kwargs):
        """ In addition to the parameters provided by
        :py:class:`.BaseSpoolDirectoryReader`, the
        `Unified2EventSpoolReader` also accepts the following
        parameters.

        :param timeout: Timeout in seconds before the records in the
          aggregator will be flushed as an event.
        """
        super(Unified2EventSpoolReader, self).__init__(
            directory, prefix, open_mode="rb", **kwargs)
        self.aggregator = unified2.EventAggregator()
        self.timeout = timeout
        self.last_record_read_ts = None

    def set_to_offset(self, offset):
        self.fileobj.seek(offset)

    def next(self):
        if not self.fileobj and not self.open_next():
            return None
        
        short_read_count = 0

        while 1:
            try:
                record = unified2.read_record(self.fileobj)
            except unified2.ShortReadError as err:
                if short_read_count:
                    return None
                short_read_count += 1
                continue

            if not record and not self.open_next():

                # We didn't read a record, and there was no file to
                # open next.  If the last record was read is older
                # than the timeout, attempt to flush the aggregator
                # for an event.
                if self.last_record_read_ts is not None and \
                        time.time() - self.last_record_read_ts > 1:
                    event = self.aggregator.flush()
                    if event:
                        self.set_bookmark(self.fileobj.tell())
                        return event
                return None

            elif record:

                # If we have a record, update the last_record_read_ts.
                self.last_record_read_ts = time.time()

                event = self.aggregator.add(record)
                if event:
                    self.set_bookmark(self.fileobj.tell())
                    return event
