py-idstools |Build Status|
==========================

py-idstools is a collection of Python libraries for working with IDS
systems (typically Snort and Suricata).

Features
--------

- Snort/Suricata unified2 log file reading.
- Continuous unified2 directory spool reading with bookmarking.
- Parser and mapping for classification.config.
- Parser and mapping for gen-msg.map and sid-msg.map.
- Useful utility programs.

Programs
--------

- rulecat - Basic Suricata rule management tool.
- eve2pcap - Convert packets and payloads in eve logs to pcap.
- u2json - Convert unified2 files or spool directories to JSON.
- gensidmsgmap - Easily create a sid-msg.map file from rule files,
  directories or a rule tarball.
- dumpdynamicrules - Helper for dumping Snort SO dynamic rule stubs.
- u2eve - Convert unified2 files to EVE compatible JSON.

Requirements
------------

- Python 2.7 or newer.
- Currently only tested on Linux.

Installation
------------

Latest Release (Recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

pip install idstools

Latest from Git
~~~~~~~~~~~~~~~

pip install https://github.com/jasonish/py-idstools/archive/master.zip

Manually
~~~~~~~~

The tools do not require installation to be used, from a .tar.gz or
.zip archive the tools can be run directly from the bin directory. Or
to install:

    python setup.py install

Examples
--------

Reading a Unified2 Spool Directory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code snippet will "tail" a unified log directory
aggregating records into events::

    from idstools import unified2

    reader = unified2.SpoolEventReader("/var/log/snort",
        "unified2.log", follow=True)
    for event in reader:
        print(event)

Documentation
-------------

Further documentation is located at http://idstools.readthedocs.org.

.. |Build Status| image:: https://travis-ci.org/jasonish/py-idstools.png?branch=master
   :target: https://travis-ci.org/jasonish/py-idstools

Changelog
---------

0.5.5
~~~~~

- unified2: fix reading of ipv6 events
- idstools-u2json: option to sort the keys
- u2spewfoo: IPv6 printing fixes
- idstools-rulecat: use ET "enhanced" rules by default
- idstools-rulecat: suricata inspired colour logging
- idstools-rulecat: handle URLs ending with query parameters

0.5.4
~~~~~

- idstools: handle rules with no msg in rule parser
- idstools-rulecat: support a drop.conf for setting rules to drop
- idstools-eve2pcap: allow link type to be set on command line
- unified2: handle large appid buffer in newer versions of Snort.

0.5.3
~~~~~

- idstools-rulecat: better documentation
- idstools-rulecat: use ET Pro https URL

0.5.2
~~~~~

- idstools-u2json: fix --delete
- idstools-u2json: add --verbose flag for debug logging
- idstools-rulecat: allow multiple urls

0.5.1
~~~~~

- New tool: eve2pcap. Converts packets and payloads found in Suricata
  EVE logs to pcap files.
- Rule parser: handle multi-line rules.

0.5.0
~~~~~

- New tool: idstools-dumpdynamicrules. A wrapper around Snort to dump
  dynamic rule stubs and optionally repack the tarball with the new
  stubs.
- New tool: idstools-u2eve. Basically a copy of the current u2json,
  but will aim to keep a compatible eve output style.  idstools-u2json
  will probably become more of a basic example program.
- A basic packet decoding module.
- New tool: rulecat. A basic Suricata rule management tool.

0.4.4
~~~~~

- Fix reading of growing file on OS X.
- Fix error in parsing decoder rules introduced in 0.4.3.

0.4.3
~~~~~

- Make the rule direction an accessible field of the rule object.

0.4.2
~~~~~

- Fix issue loading signature map files (GitHub issue #2).

0.4.1
~~~~~

- Fix IPv6 address unpacking.
- In u2json, if the protocol number can't be converted to a string,
  encode the number as a string for a consistent JSON data type.

0.4.0
~~~~~

- New tool, u2json to convert unified2 files to JSON.

0.3.1
~~~~~

- Support the new appid unified2 event types introduced in Snort
  2.9.7.0.alpha.
