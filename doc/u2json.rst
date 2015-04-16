u2json
======

Convert unified2 records to a JSON representation.

Usage
-----

.. automodule:: idstools.scripts.u2json


Example 1 - View unified2 File as JSON
--------------------------------------

::

   idstools-u2json /var/log/snort/unified2.log.1397575268

To resolve alert descriptions and classifications::

   idstools-u2json --snort-conf /etc/snort/etc/snort.conf \
       /var/log/snort/unified2.log.1397575268

The above assumes that sid-msg.map, gen-msg.map and
classification.config live alongside the specified snort.conf.  If
they do not, the options to specify each individually may be used::

  idstools-u2json -C /etc/snort/etc/classification.config \
      -S /etc/snort/etc/sid-msg.map \
      -G /etc/snort/etc/gen-msg.map \
      /var/log/snort/unified2.log.1397575268

Example 2 - Continuous Conversion to JSON
-----------------------------------------

::

   idstools-u2json --snort.conf /etc/snort/etc/snort.conf \
       --directory /var/log/snort \
       --prefix unified2.log \
       --follow \
       --bookmark \
       --delete \
       --output /var/log/snort/alerts.json \

The above command will operate like barnyard, reading all unified2.log
files in /var/log/snort, waiting for new unified2 records when the end
of the last file is reached.

Additionally the last read location will be bookmarked to avoid
reading events multiple times, the unified2.log files will be deleted
once converted to JSON, and JSON events will be written to
/var/log/snort/alerts.json.

Configuration File
------------------

A configuration file is simply a file containing the command line
arguments, one per line with an '=' separating the name from the
argument.  For example, to save the arguments used in example 2
above::

   --snort.conf=/etc/snort/etc/snort.conf
   --directory=/var/log/snort
   --prefix=unified2.log
   --follow
   --bookmark
   --delete
   --output=/var/log/snort/alerts.json

Then call idstools-u2json like::

  idstools-u2json @/path/to/config-file

Addtional arguments can also be provided like::

  idstools-u2json @/path/to/config-file --stdout
