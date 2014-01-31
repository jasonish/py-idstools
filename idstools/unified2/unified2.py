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

import struct
import collections
import logging
import types

LOG = logging.getLogger(__name__)

# Record header length.
HDR_LEN = 8

# Record types.
PACKET       = 2
EVENT        = 7
EVENT_IP6    = 72
EVENT_V2     = 104
EVENT_IP6_V2 = 105
EXTRA_DATA   = 110

# Types of records that represent an event (and the start of an event
# in a stream of records).
EVENT_TYPES = [EVENT, EVENT_IP6, EVENT_V2, EVENT_IP6_V2]

class Field(object):
    """ A class to represent a field in a unified2 record. Used for
    building the decoders. """

    def __init__(self, name, len, fmt=None):
        self.name = name
        self.len = len
        self._fmt = fmt

    @property
    def fmt(self):
        if self._fmt:
            return self._fmt
        elif self.len == 4:
            return "L"
        elif self.len == 2:
            return "H"
        elif self.len == 1:
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
    Field("ip-source", 4, "4s"),
    Field("ip-destination", 4, "4s"),
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
    Field("ip-source", 4, "16s"),
    Field("ip-destination", 4, "16s"),
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
    Field("_pad2", 2),
)

# Fields for an IPv6 v2 event.
EVENT_IP6_V2_FIELDS = EVENT_IP6_FIELDS + (
    Field("mpls-label", 4),
    Field("vlan-id", 2),
    Field("_pad2", 2),
)

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

class ShortReadError(Exception):
    """ Exception raised when there is not enough data to read a
    complete unified2 record. """
    pass

class Event(dict):
    """ Class representing a unified2 event. """

    def __init__(self, fields):

        # Create fields to hold extra data and packets associated with
        # this event.
        self["extra-data"] = []
        self["packets"] = []

        # Only v2 events have MPLS and VLAN ids.
        self["mpls-label"] = None
        self["vlan-id"] = None

        for field, value in fields:
            self[field.name] = value

class Packet(dict):
    """ Class to represent a PACKET with a dict-like interface. """

    def __init__(self, *fields, **kwargs):
        for field, value in zip(PACKET_FIELDS, fields):
            self[field.name] = value
        self.update(kwargs)

class ExtraData(dict):
    """ Class to represent EXTRA_DATA with a dict-like interface. """

    def __init__(self, *fields, **kwargs):
        for field, value in zip(EXTRA_DATA_FIELDS, fields):
            self[field.name] = value
        self.update(kwargs)

class AbstractDecoder(object):

    def __init__(self, fields):
        self.fields = fields
        
        # Calculate the length of the fixed portion of the record.
        self.fixed_len = sum(
            [field.len for field in self.fields if field.len is not None])

        # Build the format string.
        self.format = ">" + "".join(
            [field.fmt for field in self.fields if field.fmt])

class EventDecoder(AbstractDecoder):

    def decode(self, buf):
        parts = struct.unpack(self.format, buf)
        return Event(zip(self.fields, parts))

class PacketDecoder(AbstractDecoder):
    """ A decoder for records of type PACKET. """

    def decode(self, buf):
        parts = struct.unpack(self.format, buf[0:self.fixed_len])
        return Packet(*parts, data=buf[self.fixed_len:])

class ExtraDataDecoder(AbstractDecoder):
    """ A decoder for records of type EXTRA_DATA. """

    def decode(self, buf):
        parts = struct.unpack(self.format, buf[0:self.fixed_len])
        return ExtraData(*parts, data=buf[self.fixed_len:])

# Map of decoders keyed by record type. 
decoders = {
    EVENT:        EventDecoder(EVENT_FIELDS),
    EVENT_IP6:    EventDecoder(EVENT_IP6_FIELDS),
    EVENT_V2:     EventDecoder(EVENT_V2_FIELDS),
    EVENT_IP6_V2: EventDecoder(EVENT_IP6_V2_FIELDS),
    PACKET:       PacketDecoder(PACKET_FIELDS),
    EXTRA_DATA:   ExtraDataDecoder(EXTRA_DATA_FIELDS),
}

class Record(object):
    """ Class representing a unified2 record.

    :param type: Record type.
    :param value: Object (decoded) representation of the record.

    This class is just a container for the above parameters.  They are
    intended to be accessed as object fields.
    """
    
    def __init__(self, type, value):
        self.type = type
        self.value = value

class EventAggregator(object):
    """ A class implementing something like the aggregator pattern to
    aggregate records until an event can be built.
    """

    def __init__(self):
        self.queue = collections.deque()

    def add(self, record):
        """ Add a new record to aggregator.

        :param record: The :py:class:`.Record` to add.

        :return: If adding a new record allows an event to be
          completed, an :py:class:`.Event` will be returned.

        If adding the new record allows an event to be completed, the
        completed event will be returned. """
        event = None
        if record.type in EVENT_TYPES:
            if self.queue:
                event = self.flush()
            self.queue.append(record)
        elif self.queue:
            self.queue.append(record)
        else:
            LOG.warn("Discarding non-event type while not in event context.")
        return event

    def flush(self):
        """ Flush the queue.  This converts the records in the queue
        into an Event. 

        If using the EventAggregator directly, you'll want to call
        flush after adding all your records to get the final
        event. """

        if not self.queue:
            return None

        rec = self.queue.popleft()
        assert(rec.type in EVENT_TYPES)
        event = rec.value
        while self.queue:
            rec = self.queue.popleft()
            assert(rec.type not in EVENT_TYPES)
            if rec.type == PACKET:
                event["packets"].append(rec.value)
            elif rec.type == EXTRA_DATA:
                event["extra-data"].append(rec.value)
        return event

class FileRecordReader(object):
    """ A class to read records from one or more unified2 log files.

    :param files: A variable number of arguments, specifying the
      unified2 files to read.
    """

    def __init__(self, *files):
        self.files = list(files)
        self.fileobj = open(self.files.pop(0), "rb")
        
    def next(self):
        while 1:
            record = read_record(self.fileobj)
            if record:
                return record
            if not self.files:
                return
            self.fileobj = open(self.files.pop(0), "rb")

    def __iter__(self):
        return iter(self.next, None)

class FileEventReader(object):
    """ A class to read events from one or more unified2 log files.

    :param files: A variable number of arguments, specifying the
      unified2 files to read.
    """

    def __init__(self, *files):
        """ Create a new FileEventReader.  Events will be read from
        the specified file, or list of files. """
        self.files = list(files)
        self.aggregator = EventAggregator()
        self.fileobj = open(self.files.pop(0), "rb")

    def next(self):
        """ Get the next event. None will be returned when there are
        no more events to be read. """
        while 1:
            record = self._next_record()
            if not record:
                return self.aggregator.flush()
            else:
                event = self.aggregator.add(record)
                if event:
                    return event

    def _next_record(self):
        while 1:
            record = read_record(self.fileobj)
            if not record:
                if not self.files:
                    return
                else:
                    self.fileobj = open(self.files.pop(0), "rb")
            else:
                return record

    def __iter__(self):
        """ Allow iteration over the FileEventReader. """
        return iter(self.next, None)

def read_record(fileobj):
    """ Read a unified2 record from the provided file object.

    :param fileobj: The file like object to read from.  Currently this
      object needs to support read, seek and tell.

    :returns: If a complete record is read a :py:class:`.Record` will
      be returned, otherwise None will be returned.

    If some data is read, but not enough for a whole record, the
    location of the file object will be reset and a
    :py:exc:`.ShortReadError` exception will be raised.

    """

    offset = fileobj.tell()
    try:
        buf = fileobj.read(HDR_LEN)
        if not buf:
            # EOF.
            return None
        elif len(buf) < HDR_LEN:
            raise ShortReadError()
        record_type, record_len = struct.unpack(">LL", buf)
        data = fileobj.read(record_len)
        if len(data) < record_len:
            raise ShortReadError()
        return Record(record_type, decoders[record_type].decode(data))
    except ShortReadError:
        fileobj.seek(offset)
        raise
