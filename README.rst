py-idstools |build-status| |docs|
=================================

py-idstools is a collection of Python libraries for working with IDS
systems (typically Snort and Suricata).

Features
--------

- Snort/Suricata unified2 log file reading.
- Continuous unified2 directory spool reading with bookmarking.
- Snort/Suricata rule parser.
- Parser and mapping for classification.config.
- Parser and mapping for gen-msg.map and sid-msg.map.
- Useful utility programs.

Programs
--------

- rulecat - Basic Suricata rule management tool suitable as a
  replacement for for Oinkmaster and Pulled Pork.
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

The idstools programs do not have to be installed to be used, they can
be executable directly from the archive directory::

  ./bin/idstools-rulecat

Or to install manually::

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

Changelog
---------

0.5.6
~~~~~
- idstools-rulecat: fix issue parsing Suricata version on Python 3
- idstools-rulecat: don't convert rules with noalert to drop
- idstools-rulecat: allow suricata version to be set on the command
  line (https://github.com/jasonish/py-idstools/issues/38)
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.5.5...0.5.6>`_

0.5.5
~~~~~
- unified2: fix reading of ipv6 events
- idstools-u2json: option to sort the keys
- u2spewfoo: IPv6 printing fixes
- idstools-rulecat: use ET "enhanced" rules by default
- idstools-rulecat: suricata inspired colour logging
- idstools-rulecat: handle URLs ending with query parameters
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.5.4...0.5.5>`_

0.5.4
~~~~~

- idstools: handle rules with no msg in rule parser
- idstools-rulecat: support a drop.conf for setting rules to drop
- idstools-eve2pcap: allow link type to be set on command line
- unified2: handle large appid buffer in newer versions of Snort.
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.5.3...0.5.4>`_

0.5.3
~~~~~
- idstools-rulecat: better documentation
- idstools-rulecat: use ET Pro https URL
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.5.2...0.5.3>`_

0.5.2
~~~~~
- idstools-u2json: fix --delete
- idstools-u2json: add --verbose flag for debug logging
- idstools-rulecat: allow multiple urls
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.5.1...0.5.2>`_

0.5.1
~~~~~
- New tool: eve2pcap. Converts packets and payloads found in Suricata
  EVE logs to pcap files.
- Rule parser: handle multi-line rules.
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.5.0...0.5.1>`_

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
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.4.4...0.5.0>`_

0.4.4
~~~~~
- Fix reading of growing file on OS X.
- Fix error in parsing decoder rules introduced in 0.4.3.
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.4.3...0.4.4>`_

0.4.3
~~~~~
- Make the rule direction an accessible field of the rule object.
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.4.2...0.4.3>`_

0.4.2
~~~~~
- Fix issue loading signature map files (GitHub issue #2).
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.4.1...0.4.2>`_

0.4.1
~~~~~
- Fix IPv6 address unpacking.
- In u2json, if the protocol number can't be converted to a string,
  encode the number as a string for a consistent JSON data type.
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.4.0...0.4.1>`_

0.4.0
~~~~~
- New tool, u2json to convert unified2 files to JSON.
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.3.1...0.4.0>`_

0.3.1
~~~~~
- Support the new appid unified2 event types introduced in Snort
  2.9.7.0.alpha.
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.3.0...0.3.1>`_

.. |build-status| image:: https://travis-ci.org/jasonish/py-idstools.png?branch=master
   :target: https://travis-ci.org/jasonish/py-idstools

.. |docs| image:: https://readthedocs.org/projects/idstools/badge/?version=latest
   :alt: Documentation Status
   :scale: 100%
   :target: https://idstools.readthedocs.io/en/latest/?badge=latest
