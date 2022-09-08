py-idstools |build-status| |docs|
=================================

py-idstools is a collection of Python libraries for working with IDS
systems (typically Snort and Suricata).

Note for `rulecat` Users
------------------------
Rulecat development has stalled. Future rule management work is now done in
Suricata-Update which is bundled with Suricata. Please consider switching to
Suricata-Update.

Included Programs
-----------------
- rulecat - Basic Suricata rule management tool suitable as a
  replacement for for Oinkmaster and Pulled Pork.
- eve2pcap - Convert packets and payloads in eve logs to pcap.
- u2json - Convert unified2 files or spool directories to JSON.
- gensidmsgmap - Easily create a sid-msg.map file from rule files,
  directories or a rule tarball.
- dumpdynamicrules - Helper for dumping Snort SO dynamic rule stubs.
- u2eve - Convert unified2 files to EVE compatible JSON.

Library Features
----------------

- Snort/Suricata unified2 log file parsing.
- Continuous unified2 directory spool reading with bookmarking.
- Snort/Suricata rule parser.
- Parser and lookup maps for classification.config.
- Parser and lookup maps for gen-msg.map and sid-msg.map.

Requirements
------------

- Python 2.7 or newer.
- Currently only tested on Linux.

Installation
------------

Latest Release (Recommended)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    pip install idstools

or on Fedora and CentOS (with EPEL):

    yum install python-idstools


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
returning each record as a dict-like object::

  from idstools import unified2

  reader = unified2.SpoolRecordReader("/var/log/snort",
      "unified2.log", follow=True)
  for record in reader:
      if isinstance(record, unified2.Event):
          print("Event:")
      elif isinstance(record, unified2.Packet):
          print("Packet:")
      elif isinstance(record, unified2.ExtraData):
          print("Extra-Data:")
      print(record)

See the `idstools unified2
<http://idstools.readthedocs.io/en/latest/unified2.html>`_
documentation for more information on read and parsing unified2 files.

Parse Suricata/Snort Rules
~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code snippet will parse all the rules in a rule file::

  from idstools import rule

  for rule in rule.parse_file(sys.argv[1]):
      print("[%d:%d:%d] %s" % (
          rule.gid, rule.sid, rule.rev, rule.msg))

In addition to parsing `files
<http://idstools.readthedocs.io/en/latest/apidoc/idstools.rule.html#idstools.rule.parse_file>`_,
`file objects
<http://idstools.readthedocs.io/en/latest/apidoc/idstools.rule.html#idstools.rule.parse_fileobj>`_
and `strings
<http://idstools.readthedocs.io/en/latest/apidoc/idstools.rule.html#idstools.rule.parse>`_
containing individual rules can be parsed.

Update Suricata Rules
~~~~~~~~~~~~~~~~~~~~~

The following command will update your Suricata rules with the latest
Emerging Threats Open ruleset for the version of Snort you have
installed::

  idstools-rulecat -o /etc/suricata/rules

See the `idstools-rulecat documentation
<http://idstools.readthedocs.io/en/latest/tools/rulecat.html>`_ for
more examples and options.

Documentation
-------------

Further documentation is located at http://idstools.readthedocs.org.

Changelog
---------

0.6.4 - 2020-08-02
~~~~~~~~~~~~~~~~~~
- eve2pcap: fix displaying of errors from libpcap
- eve2pcap: python3 fixes
- eve2pcap: print number of packets converted on exit
- rules: fix parsing of rules where the address or port list has a space
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.6.3...0.6.4>`_

0.6.3 - 2017-11-20
~~~~~~~~~~~~~~~~~~
- eve2pcap: fix segfault when calling libpcap functions.
- rulecat: for Emerging Threat rule URLs, use the Suricata version as found
- rulecat: default to Suricata 4.0 if it can't be found.
- rule parser: fix case where rule option does not end in ; and is
  last option (https://github.com/jasonish/py-idstools/issues/58)
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.6.2...0.6.3>`_

0.6.2 - 2017-08-09
~~~~~~~~~~~~~~~~~~
- rulecat: ignore *deleted.rules by default. Provide --no-ignore
  option to disable default ignores without having to add a new
  ignore.
- rulecat: suppress progress bar if quiet
- rulecat: fix output filenaming for downloads that are a single rule
  file
- rulecat: more python3/unicode fixes
- rule parser: if metadata is specified more than once, append to the
  existing metadata list instead of replacing it
  (https://github.com/jasonish/py-idstools/issues/57)
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.6.1...0.6.2>`_

0.6.1 - 2017-05-25
~~~~~~~~~~~~~~~~~~
- idstools-rulecat: handle zip archive files
- rules: handle msg with escaped semicolons
- rulecat: don't generate report summary if its not going to be logged
  anyways (https://github.com/jasonish/py-idstools/issues/49)
- rulecat: Python 3 fixes
- rules: speed up parsing
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.6.0...0.6.1>`_

0.6.0 - 2017-03-29
~~~~~~~~~~~~~~~~~~
- idstools-u2eve - output packet records
- idstools-rulecat: allow --local to be specified multiple times
- idstools-rulecat: --ignore option to ignore filenames
- More python 3 fixups.
- unified2 - deprecate event readers, use record readers instead
  (https://github.com/jasonish/py-idstools/issues/14)
- u2json: --packet-hex and --printable to print raw buffers as printable
  chars and hex in addition to base64.
- u2eve: --packet-printable to include a "packet_printable" field
- u2eve: include Snort extra-data with printable data.
- `Commit log <https://github.com/jasonish/py-idstools/compare/0.5.6...0.6.0>`_

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
