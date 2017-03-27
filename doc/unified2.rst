Unified2 File Reading
=====================

idstools provides unified2 readers for reading unified2 records.

.. contents:: Contents
   :depth: 2
   :local:

Reader Objects
--------------

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

SpoolRecordReader
^^^^^^^^^^^^^^^^^

.. autoclass:: idstools.unified2.SpoolRecordReader
   :noindex:

   .. automethod:: idstools.unified2.SpoolRecordReader.next
      :noindex:

   .. automethod:: idstools.unified2.SpoolRecordReader.tell
      :noindex:

Record Types
------------

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
