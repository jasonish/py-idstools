u2eve - Unified2 to Suricata eve events
=======================================

.. automodule:: idstools.scripts.u2eve

Usage
-----

.. program-output:: ../bin/idstools-u2eve --help

Example - View a unified2 file as eve
-------------------------------------

::

   idstools-u2eve -C path/to/classification.config \
     -S /path/to/sid-msg.map \
     -G /path/to/gen-msg.map merged.log.1431384519

Example - Continuous conversion to eve
--------------------------------------

::

   idstools-u2eve --snort-conf /etc/snort/etc/snort.conf \
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

   --snort-conf=/etc/snort/etc/snort.conf
   --directory=/var/log/snort
   --prefix=unified2.log
   --follow
   --bookmark
   --delete
   --output=/var/log/snort/alerts.json

Then call idstools-u2eve like::

  idstools-u2eve @/path/to/config-file

Addtional arguments can also be provided like::

  idstools-u2eve @/path/to/config-file --stdout

Source
------

`idstools/scripts/u2eve.py <../_modules/idstools/scripts/u2eve.html>`_
