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

"""Unified2 record and event reading.

Unified2 is a file format used by the Snort and Suricata IDS engines
for logging events.

For more information on the unified2 file format see:

    http://manual.snort.org/node44.html

::

    usage: from idstools import unified2

"""

from __future__ import print_function

import sys
import os
import os.path
import struct
import collections
import logging
import fnmatch
import time
import socket

LOG = logging.getLogger(__name__)

# Record header length.
HDR_LEN = 8

# Length of an appid name.
APPID_NAME_LEN = 16

# Record types.
PACKET          = 2
EVENT           = 7
EVENT_IP6       = 72
EVENT_V2        = 104
EVENT_IP6_V2    = 105
EXTRA_DATA      = 110
EVENT_APPID     = 111
EVENT_APPID_IP6 = 112
APPSTAT         = 113

RECORD_TYPES = [
    PACKET,
    EVENT,
    EVENT_IP6,
    EVENT_V2,
    EVENT_IP6_V2,
    EXTRA_DATA,
    EVENT_APPID,
    EVENT_APPID_IP6,
    APPSTAT,
]

EXTRA_DATA_TYPE = {
    "ORIG_CLIENT_IP4": 1,
    "ORIG_CLIENT_IP6": 2,
    "UNUSED0": 3,
    "GZIP_DATA": 4,
    "SMTP_FILENAME": 5,
    "SMTP_MAIL_FROM": 6,
    "SMTP_RCPT_TO": 7,
    "SMTP_HEADERS": 8,
    "HTTP_URI": 9,
    "HTTP_HOSTNAME": 10,
    "IP6_SRC_ADDR": 11,
    "IP6_DST_ADDR": 12,
    "NORMALIZED_JS": 13,
}

class UnknownRecordType(Exception):

    def __init__(self, record_type):
        super(UnknownRecordType, self).__init__(
            "Unknown record type: %d" % (record_type))

class Field(object):
    """ A class to represent a field in a unified2 record. Used for
    building the decoders. """

    def __init__(self, name, length, fmt=None):
        self.name = name
        self.length = length
        self._fmt = fmt

    @property
    def fmt(self):
        """Builds a format string for struct.unpack."""
        if self._fmt:
            return self._fmt
        elif self.length == 4:
            return "L"
        elif self.length == 2:
            return "H"
        elif self.length == 1:
            return "B"
        else:
            return None

# Fields in a PACKET record.
PACKET_FIELDS = (
    Field("sensor-id", 4),
    Field("event-id", 4),
    Field("event-second", 4),
    Field("packet-second", 4),
    Field("packet-microsecond", 4),
    Field("linktype", 4),
    Field("length", 4),
    Field("data", None),
)

# Fields in a EVENT record.
EVENT_FIELDS = (
    Field("sensor-id", 4),
    Field("event-id", 4),
    Field("event-second", 4),
    Field("event-microsecond", 4),
    Field("signature-id", 4),
    Field("generator-id", 4),
    Field("signature-revision", 4),
    Field("classification-id", 4),
    Field("priority", 4),
    Field("source-ip.raw", 4, "4s"),
    Field("destination-ip.raw", 4, "4s"),
    Field("sport-itype", 2),
    Field("dport-icode", 2),
    Field("protocol", 1),
    Field("impact-flag", 1),
    Field("impact", 1),
    Field("blocked", 1),
)

# Fields for an IPv6 event.
EVENT_IP6_FIELDS = (
    Field("sensor-id", 4),
    Field("event-id", 4),
    Field("event-second", 4),
    Field("event-microsecond", 4),
    Field("signature-id", 4),
    Field("generator-id", 4),
    Field("signature-revision", 4),
    Field("classification-id", 4),
    Field("priority", 4),
    Field("source-ip.raw", 16, "16s"),
    Field("destination-ip.raw", 16, "16s"),
    Field("sport-itype", 2),
    Field("dport-icode", 2),
    Field("protocol", 1),
    Field("impact-flag", 1),
    Field("impact", 1),
    Field("blocked", 1),
)

# Fields in a v2 event.
EVENT_V2_FIELDS = EVENT_FIELDS + (
    Field("mpls-label", 4),
    Field("vlan-id", 2),
    Field("pad2", 2),
)

EVENT_APPID_FIELDS = EVENT_V2_FIELDS

# Fields for an IPv6 v2 event.
EVENT_IP6_V2_FIELDS = EVENT_IP6_FIELDS + (
    Field("mpls-label", 4),
    Field("vlan-id", 2),
    Field("pad2", 2),
)

EVENT_APPID_IP6_FIELDS = EVENT_IP6_FIELDS

# Fields in a UNIFIED_EXTRA_DATA record.
EXTRA_DATA_FIELDS = (
    Field("event-type", 4),
    Field("event-length", 4),
    Field("sensor-id", 4),
    Field("event-id", 4),
    Field("event-second", 4),
    Field("type", 4),
    Field("data-type", 4),
    Field("data-length", 4),
    Field("data", None),
)

class Event(dict):
    """Event represents a unified2 event record with a dict-like
    interface.

    Fields:

    * sensor-id
    * event-id
    * event-second
    * event-microsecond
    * signature-id
    * generator-id
    * signature-revision
    * classification-id
    * priority
    * source-ip
    * destination-ip
    * sport-itype
    * dport-icode
    * protocol
    * impact-flag
    * impact
    * blocked
    * mpls-label
    * vlan-id

    Methods that return events rather than single records will also
    populate the fields *packets* and *extra-data*.  These fields are
    lists of the :class:`.Packet` and :class:`.ExtraData` records
    associated with the event.

    """

    def __init__(self, event):

        # Create fields to hold extra data and packets associated with
        # this event.
        self["packets"] = []
        self["extra-data"] = []

        # Only v2 events have MPLS and VLAN ids.
        self["mpls-label"] = None
        self["vlan-id"] = None

        # Only v3/appid events have an appid.
        self["appid"] = None

        self.update(event)

class Packet(dict):
    """Packet represents a unified2 packet record with a dict-like interface.

    Fields:

    * sensor-id
    * event-id
    * event-second
    * packet-second
    * packet-microsecond
    * linktype
    * length
    * data

    """

    def __init__(self, *fields, **kwargs):
        for field, value in zip(PACKET_FIELDS, fields):
            self[field.name] = value
        self.update(kwargs)

class ExtraData(dict):
    """ExtraData represents a unified2 extra-data record with a dict
    like interface.

    Fields:

    * event-type
    * event-length
    * sensor-id
    * event-id
    * event-second
    * type
    * data-type
    * data-length
    * data

    """

    def __init__(self, *fields, **kwargs):
        for field, value in zip(EXTRA_DATA_FIELDS, fields):
            self[field.name] = value
        self.update(kwargs)

class Unknown(object):
    """Class to represent an unknown record type.

    In the unlikely case that a record is of an unknown type, an
    instance of `Unknown` will be used to hold the record type and
    buffer.

    """

    def __init__(self, record_type, buf):
        """
        :param type: The record type.
        :param buf: The record buffer.
        """
        self.record_type = record_type
        self.buf = buf

class AbstractDecoder(object):
    """ Base class for decoders. """

    def __init__(self, fields):
        self.fields = fields

        # Calculate the length of the fixed portion of the record.
        self.fixed_len = sum(
            [field.length for field in self.fields if field.length is not None])

        # Build the format string.
        self.format = ">" + "".join(
            [field.fmt for field in self.fields if field.fmt])

class EventDecoder(AbstractDecoder):
    """ Decoder for event type records. """

    def decode(self, buf):
        """Decodes a buffer into an :class:`.Event` object."""
        values = struct.unpack(self.format, buf[0:self.fixed_len])
        keys = [field.name for field in self.fields]
        event = dict(zip(keys, values))
        event["source-ip"] = self.decode_ip(event["source-ip.raw"])
        event["destination-ip"] = self.decode_ip(event["destination-ip.raw"])

        # Check for remaining data, the appid.
        remainder = buf[self.fixed_len:]
        if remainder:
            event["appid"] = str(remainder).split("\x00")[0]

        return Event(event)

    def decode_ip(self, addr):
        if len(addr) == 4:
            return socket.inet_ntoa(addr)
        else:
            parts = struct.unpack(">" + "H" * int((len(addr) / 2)), addr)
            return ":".join("%04x" % p for p in parts)

class PacketDecoder(AbstractDecoder):
    """ Decoder for packet type records. """

    def decode(self, buf):
        """Decodes a buffer into a :class:`.Packet` object."""
        parts = struct.unpack(self.format, buf[0:self.fixed_len])
        return Packet(*parts, data=buf[self.fixed_len:])

class ExtraDataDecoder(AbstractDecoder):
    """ Decoder for extra data type records. """

    def decode(self, buf):
        """Decodes a buffer into an :class:`.ExtraData` object."""
        parts = struct.unpack(self.format, buf[0:self.fixed_len])
        return ExtraData(*parts, data=buf[self.fixed_len:])

# Map of decoders keyed by record type.
DECODERS = {
    EVENT:           EventDecoder(EVENT_FIELDS),
    EVENT_IP6:       EventDecoder(EVENT_IP6_FIELDS),
    EVENT_V2:        EventDecoder(EVENT_V2_FIELDS),
    EVENT_IP6_V2:    EventDecoder(EVENT_IP6_V2_FIELDS),
    EVENT_APPID:     EventDecoder(EVENT_APPID_FIELDS),
    EVENT_APPID_IP6: EventDecoder(EVENT_APPID_IP6_FIELDS),
    PACKET:          PacketDecoder(PACKET_FIELDS),
    EXTRA_DATA:      ExtraDataDecoder(EXTRA_DATA_FIELDS),
}

class Aggregator(object):
    """A class implementing something like the aggregator pattern to
    aggregate records until an event can be built.

    """

    def __init__(self):
        self.queue = collections.deque()

    def add(self, record):
        """ Add a new record to aggregator.

        :param record: The decoded unified2 record to add.

        :return: If adding a new record allows an event to be
          completed, an :py:class:`.Event` will be returned.
        """

        event = None

        if isinstance(record, Event):
            if self.queue:
                event = self.flush()
            self.queue.append(record)
        elif self.queue:
            if record["event-id"] == self.queue[-1]["event-id"]:
                self.queue.append(record)
            else:
                LOG.warn("Record not associated with current event, discarding.")
        else:
            LOG.warn("Discarding non-event type while not in event context.")
        return event

    def flush(self):
        """Flush the queue.  This converts the records in the queue
        into an Event.

        If using the Aggregator directly, you'll want to call flush
        after adding all your records to get the final event.

        :returns: An :class:`.Event` or None if there are no records.
        """

        if not self.queue:
            return None

        event = self.queue.popleft()
        assert(isinstance(event, Event))
        while self.queue:
            record = self.queue.popleft()
            assert(not isinstance(record, Event))
            if isinstance(record, Packet):
                event["packets"].append(record)
            elif isinstance(record, ExtraData):
                event["extra-data"].append(record)
        return event

class Unified2Bookmark(object):
    """Class to represent a "bookmark" for unified2 spool
    directories.

    """

    def __init__(self, directory=None, prefix=None, filename=None):
        self.directory = directory
        self.prefix = prefix

        if filename:
            self.filename = filename
        else:
            self.filename = os.path.join(
                os.path.abspath(self.directory), "_%s.bookmark" % (prefix))

        self.fileobj = open(self.filename, "ab")

    def get(self):
        """Get the current bookmark.

        Returns a tuple of filename and offset.

        """
        if os.path.exists(self.filename):
            buf = open(self.filename, "rb").read()
            if buf:
                filename, offset = buf.decode().split("\0")
                return filename, int(offset)
        return None, None

    def update(self, filename, offset):
        """Update the bookmark with the given filename and offset."""
        if filename is None or offset is None:
            return
        self.fileobj.truncate(0)
        self.fileobj.seek(0, 0)
        self.fileobj.write(("%s\x00%d" % (
            os.path.basename(filename), offset)).encode())
        self.fileobj.flush()

def decode_record(record_type, buf):
    """Decodes a raw record into an object representing the record.

    :param record_type: The type of record.
    :param buf: Buffer containing the raw record.

    :returns: The decoded record as a :class:`.Event`,
      :class:`.Packet`, :class:`.ExtraData` or :class:`.Unknown` if the
      record is of an unknown type.
    """
    if record_type in DECODERS:
        return DECODERS[record_type].decode(buf)
    else:
        return Unknown(record_type, buf)

def read_record(fileobj):
    """Reads a unified2 record from the provided file object.

    :param fileobj: The file like object to read from.  Currently this
      object needs to support read, seek and tell.

    :returns: If a complete record is read a :py:class:`.Record` will
      be returned, otherwise None will be returned.

    If some data is read, but not enough for a whole record, the
    location of the file object will be reset and a
    :exc:`.EOFError` exception will be raised.

    """

    offset = fileobj.tell()

    # Not sure why this is needed, but without doing this, read on OS X
    # won't read the new data in a file in the case where the file
    # being read is growing.
    fileobj.seek(offset)

    try:
        buf = fileobj.read(HDR_LEN)
        if not buf:
            # EOF.
            return None
        elif len(buf) < HDR_LEN:
            raise EOFError()
        rtype, rlen = struct.unpack(">LL", buf)
        if rtype not in RECORD_TYPES:
            raise UnknownRecordType(rtype)
        buf = fileobj.read(rlen)
        if len(buf) < rlen:
            raise EOFError()
        try:
            return decode_record(rtype, buf)
        except Exception as err:
            LOG.error("Failed to decode record of type %d (len=%d): %s" % (
                rtype, rlen, err))
            raise err
    except EOFError as err:
        fileobj.seek(offset)
        raise err

class RecordReader(object):
    """RecordReader reads and decodes unified2 records from a
    file-like object.

    :param fileobj: The file-like object to read from.

    Example::

        fileobj = open("/var/log/snort/merged.log.1382627987", "rb")
        reader = RecordReader(fileobj):
        for record in reader:
            print(record)

    """

    def __init__(self, fileobj):
        self.fileobj = fileobj

    def next(self):
        """Return the next record or None if EOF.

        Records returned will be one of the types :class:`.Event`,
        :class:`.Packet`, :class:`.ExtraData` or :class:`.Unknown` if
        the record is of an unknown type.
        """
        return read_record(self.fileobj)

    def tell(self):
        """Get the current offset in the underlying file object."""
        return self.fileobj.tell()

    def __iter__(self):
        return iter(self.next, None)

class FileRecordReader(object):
    """FileRecordReader reads and decodes unified2 records from one or
    more files supplied by filename.

    :param files...: One or more filenames to read records from.

    Example::

        reader = unified2.RecordReader("unified2.log.1382627941",
                                       "unified2.log.1382627966)
        for record in reader:
            print(record)

    """

    def __init__(self, *files):
        self.files = list(files)
        self.fileobj = open(self.files.pop(0), "rb")
        self.reader = RecordReader(self.fileobj)

    def next(self):
        """Return the next record or None if EOF.

        Records returned will be one of the types :class:`.Event`,
        :class:`.Packet`, :class:`.ExtraData` or :class:`.Unknown` if the
        record is of an unknown type.
        """
        while 1:
            record = self.reader.next()
            if record:
                return record
            if not self.files:
                return
            self.fileobj.close()
            self.fileobj = open(self.files.pop(0), "rb")
            self.reader = RecordReader(self.fileobj)

    def tell(self):
        """ Returns the current filename and offset. """
        return self.fileobj.name, self.fileobj.tell()

    def __iter__(self):
        return iter(self.next, None)

class FileEventReader(object):
    """FileEventReader reads records from one or more filenames and
    aggregates them into events.

    :param files...: One or more files to read events from.

    Example::

        reader = unified2.FileEventReader("unified2.log.1382627941",
                                          "unified2.log.1382627966)
        for event in reader:
            print(event)

    """

    def __init__(self, *files):
        self.reader = FileRecordReader(*files)
        self.aggregator = Aggregator()

    def next(self):
        """Return the next :class:`.Event` or None if EOF."""
        while 1:
            record = self.reader.next()
            if not record:
                return self.aggregator.flush()
            else:
                event = self.aggregator.add(record)
                if event:
                    return event

    def __iter__(self):
        return iter(self.next, None)

class SpoolRecordReader(object):
    """SpoolRecordReader reads and decodes records from a unified2
    spool directory.

    Required parameters:

    :param directory: Path to unified2 spool directory.
    :param prefix: Filename prefix for unified2 log files.

    Optional parameters:

    :param init_filename: Filename open on initialization.
    :param init_offset: Offset to seek to on initialization.

    :param follow: Set to true if reading should wait for the next
      record to become available.

    :param rollover_hook: Function to call on rollover of log file,
      the first parameter being the filename being closed, the second
      being the filename being opened.

    Example with following and rollover deletion::

        def rollover_hook(closed, opened):
            os.unlink(closed)

        reader = unified2.SpoolRecordReader("/var/log/snort",
            "unified2.log", rollover_hook = rollover_hook,
            follow = True)
        for record in reader:
            print(record)

    """

    def __init__(self, directory, prefix, init_filename=None, init_offset=None,
                 follow=False, rollover_hook=None):
        self.directory = directory
        self.prefix = prefix
        self.follow = follow
        self.rollover_hook = rollover_hook
        self.fileobj = None
        self.reader = None
        self.fnfilter = "%s*" % (self.prefix)

        if init_filename:
            if os.path.exists("%s/%s" % (
                    self.directory, os.path.basename(init_filename))):
                self.open_file(init_filename)
                self.fileobj.seek(init_offset)
                self.reader = RecordReader(self.fileobj)

    def get_filenames(self):
        """Return the filenames (sorted) from the spool directory."""
        return sorted(fnmatch.filter(os.listdir(self.directory), self.fnfilter))

    def open_file(self, filename):
        if self.fileobj:
            closed_filename = self.fileobj.name
            self.fileobj.close()
            LOG.debug("Closed %s.", closed_filename)
        else:
            closed_filename = None
        self.fileobj = open("%s/%s" % (
            self.directory, os.path.basename(filename)), "rb")
        LOG.debug("Opened %s.", self.fileobj.name)
        self.reader = RecordReader(self.fileobj)
        if self.rollover_hook and closed_filename:
            self.rollover_hook(closed_filename, self.fileobj.name)

    def open_next(self):
        """Open the next available file.  If a new file is opened its
        filename will be returned, otherwise None will be returned.
        """
        filenames = self.get_filenames()

        # If there are no files, just return.
        if not filenames:
            return

        # If we do not have a current fileobj, open the first file.
        if not self.fileobj:
            self.open_file(filenames[0])
            return os.path.basename(self.fileobj.name)

        if os.path.basename(self.fileobj.name) not in filenames:
            # The current file doesn't exist anymore, move on.
            self.open_file(filenames[0])
            return os.path.basename(self.fileobj.name)
        else:
            current_idx = filenames.index(os.path.basename(self.fileobj.name))
            if current_idx + 1 < len(filenames):
                self.fileobj.close()
                self.open_file(filenames[current_idx + 1])
                return os.path.basename(self.fileobj.name)

    def tell(self):
        """Return a tuple containing the filename and offset of the
        file currently being processed.
        """
        if self.fileobj:
            return (self.fileobj.name, self.fileobj.tell())
        return None, None

    def _next(self):
        """Return the next decoded unified2 record from the spool
        directory.
        """

        # If we don't have a current file, try to open one.  Failing
        # that just return.
        if self.fileobj == None:
            if not self.open_next():
                return

        # Now try to get a record.  If we can't see if there is a new
        # file and try again.
        try:
            record = self.reader.next()
        except EOFError:
            return
        if record:
            return record
        else:
            while True:
                if self.open_next():
                    try:
                        record = self.reader.next()
                    except EOFError:
                        return
                    if record:
                        return record
                else:
                    return None

    def next(self):
        """Return the next record or None if EOF.

        If in follow mode and EOF, this method will sleep and
        and try again.

        :returns: A record of type :class:`.Event`, :class:`.Packet`,
          :class:`.ExtraData` or :class:`.Unknown` if the record is of
          an unknown type.

        """
        while True:
            record = self._next()
            if record:
                return record
            if not self.follow:
                return
            else:
                # Sleep for a moment and try again.
                time.sleep(0.01)

    def __iter__(self):
        return iter(self.next, None)

class SpoolEventReader(object):
    """SpoolEventReader reads records from a unified2 spool directory
    and aggregates them into events.

    Required parameters:

    :param directory: Path to unified2 spool directory.
    :param prefix: Filename prefix for unified2 log files.

    Optional parameters:

    :param follow: Set to true to follow the log files.  Reading will
      wait until an event is available before returning.
    :param delete: If True, unified2 files will be deleted when
      reading has moved onto the next one.
    :param bookmark: If True, the reader will remember its location and
      start reading from the bookmarked location on initialization.

    Example::

        reader = unified2.SpoolEventReader("/var/log/snort", "unified2.log")
        for event in reader:
            print(event)

    """

    def __init__(self, directory, prefix, follow=False, delete=False,
                 bookmark=False):

        self.follow = follow
        self.delete = delete

        self.aggregator = Aggregator()

        self.delete_on_next = []

        if bookmark:
            self.bookmark = Unified2Bookmark(directory, prefix)
            init_filename, init_offset = self.bookmark.get()
        else:
            self.bookmark = None
            init_filename, init_offset = None, None

        # Create a SpoolRecordReader.  We purposely don't pass the
        # follow parameter through as we want to handle that here so
        # we can flush the aggregator after a timeout.
        self.reader = SpoolRecordReader(
            directory, prefix, init_filename=init_filename,
            init_offset=init_offset, rollover_hook=self.rollover_hook)

    def rollover_hook(self, closed, opened):
        if closed:
            LOG.info("Closed file %s, opened file %s", closed, opened)
        else:
            LOG.info("Opened file %s", opened)
        if closed and self.delete:
            self.delete_on_next.append(closed)

    def next(self):
        """Return the next :class:`.Event`.

        If in follow mode and EOF is head, this method will sleep and
        and try again.

        """
        while True:

            # Get the underlying readers location before we read, as
            # its the read of the next event that is going to trigger
            # an event to be assembled.
            mark = self.reader.tell()

            record = self.reader.next()
            if record:
                event = self.aggregator.add(record)
                if event:
                    #return event
                    break
            else:
                event = self.aggregator.flush()
                if event or not self.follow:
                    break

                # Sleep for a moment and try again.
                time.sleep(0.1)

        while self.delete_on_next:
            filename = self.delete_on_next.pop()
            LOG.info("Deleting file %s.", filename)
            os.unlink(filename)

        if self.bookmark and mark[0] is not None:
            self.bookmark.update(mark[0], mark[1])

        return event

    def tell(self):
        """ See :func:`.SpoolRecordReader.tell`. """
        return self.reader.tell()

    def __iter__(self):
        return iter(self.next, None)
