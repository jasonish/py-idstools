Unified2 File Reading
=====================

idstools provides unified2 readers for reading individual records as
well as aggregating records into events.

.. contents:: Contents
   :depth: 2
   :local:

Reader Objects
--------------

Unified2 file reading and decoding is done with a reader objects.
Different reader objects exist for where you are reading from and
whether you want to read individual records, or have records
aggregated into events.

RecordReader
^^^^^^^^^^^^

.. autoclass:: idstools.unified2.RecordReader
   :noindex:
   :members:

FileRecordReader
^^^^^^^^^^^^^^^^

.. autoclass:: idstools.unified2.FileRecordReader
   :noindex:
   :members:

FileEventReader
^^^^^^^^^^^^^^^

.. autoclass:: idstools.unified2.FileEventReader
   :noindex:
   :members:

SpoolRecordReader
^^^^^^^^^^^^^^^^^

.. autoclass:: idstools.unified2.SpoolRecordReader
   :noindex:

   .. automethod:: idstools.unified2.SpoolRecordReader.next
      :noindex:

   .. automethod:: idstools.unified2.SpoolRecordReader.tell
      :noindex:

SpoolEventReader
^^^^^^^^^^^^^^^^

.. autoclass:: idstools.unified2.SpoolEventReader
   :noindex:
   :members:

Record Types
------------

A Unified2 log file is composed records of different types.  A IDS
event is composed of multiple records, generally a single
:class:`.Event` record followed by one or more :class:`.Packet`
records and sometimes one or more :class:`.ExtraData` records.

Record readers like :class:`.SpoolRecordReader` return individual
records while event readers like :class:`.SpoolEventReader` return
:class:`.Event` records with the associated :class:`.Packet` and
:class:`.ExtraData` records as part of the event.

For most purposes the following record types look and feel like a
Python dict.

Event
^^^^^

.. autoclass:: idstools.unified2.Event
   :noindex:

Packet
^^^^^^

.. autoclass:: idstools.unified2.Packet
   :noindex:


ExtraData
^^^^^^^^^

.. autoclass:: idstools.unified2.ExtraData
   :noindex:
