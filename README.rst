py-idstools |Build Status|
==========================

py-idstools is a collection of Python libraries for working with IDS
systems (typically Snort and Suricata).

Features
--------

- Snort/Suricata unified2 log file reading.
- Continuous unified2 directory spool reading with bookmarking (a'la
  Barnyard2).
- Parser and mapping for classification.config.
- Parser and mapping for gen-msg.map and sid-msg.map.
- Useful utility programs.

Programs
--------

- u2json - Convert unified2 files or spool directories to JSON.
- gensidmsgmap - Easily create a sid-msg.map file from rule files,
  directories or a rule tarball.

Requirements
------------

- Python 2.6 or 2.7; Python 3.3 works but is not as well tested.
- Currently only tested on Linux.

Examples
--------

Reading a Unified2 Spool Directory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code snippet will "tail" a unified log directory
aggregating records into events::

    from idstools import unified2

    reader = unified2.SpoolEventReader("/var/log/snort",
        "unified2.log", tail=True)
    for event in reader:
        print(event)

Documentation
-------------

Further documentation is located at http://idstools.readthedocs.org.

.. |Build Status| image:: https://travis-ci.org/jasonish/py-idstools.png?branch=master
   :target: https://travis-ci.org/jasonish/py-idstools

Changelog
---------

0.4.0
~~~~~

- New tool, u2json to convert unified2 files to JSON.

0.3.1
~~~~~

- Support the new appid unified2 event types introduced in Snort
  2.9.7.0.alpha.
