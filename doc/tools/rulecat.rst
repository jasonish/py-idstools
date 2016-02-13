rulecat
=======

.. automodule:: idstools.scripts.rulecat

Synopsis
--------

``idstools-rulecat`` [OPTIONS]

Description
-----------

``idstools-ruleset`` aims to be a simple to use rule download and
management tool for Suricata. It can also be used for Snort when no SO
rule stub generation is required.

Options
-------

.. option:: -h, --help

   Show help.

.. option:: -v, --verbose

   Be more verbose.

.. option:: -t <directory>, --temp-dir=<directory>

   Temporary working directory (default:
   /var/tmp/idstools-rulecat). This is where downloaded files will be
   stored.

.. option:: --suricata=<path>

   The path to the Suricata program used to determine which version of
   the ET pro rules to download if not explicitly set in a --url.

.. option:: --force

   Force remote rule files to be downloaded if they otherwise wouldn't
   be due to just recently downloaded, or the remote checksum matching
   the cached copy.

.. option:: -o

   The directory where rule individual rules files will be written
   to. One of ``-o`` or ``--merged`` is required.

.. option:: --yaml-fragment=<filename.yaml>

   Output a fragment of YAML containing the *rule-files* section will
   all downloaded rule files listed for inclusion in your
   *suricata.yaml*.

.. option:: --merged=<filename>

   Write a single file containing all rules. This can be used in
   addition to ``-o`` or instead of ``-o``.

.. option:: --url=<url>

   A URL to download rules from. This option can be used multiple
   times.

.. option:: --etopen

   Download the ET open ruleset. This is the default if ``--url`` or
   ``--etpro`` are not provided.

   If one of ``etpro`` or ``--url`` is also specified, this option
   will at the ET open URL to the list of remote ruleset to be
   downloaded.

.. option:: --etpro=<code>

   Download the ET pro ruleset using the provided code.

.. option:: --sid-msg-map=<filename>

   Output a v1 style sid-msg.map file.

.. option:: --sid-msg-map-2=<filename>

   Output a v2 style sid-msg.map file.

.. option:: -q, --quiet

   Run quietly. Only warning and error message will be displayed.

.. option:: --dump-sample-configs

   Output sample configuration files for the ``--disable``,
   ``--enable``, ``--modify`` and ``--threshold-in`` commands.

.. option:: --disable=<disable.conf>

   Specify the configuration file for disabling rules.

.. option:: --enable=<enable.conf>

   Specify the configuration file for enabling rules.

.. option:: --modify=<modify.conf>

   Specify the configuration file for rule modifications.

.. option:: --threshold-in=<threshold.conf.in>

   Specify the threshold.conf input template.

.. option:: --threshold-out=<threshold.conf>

   Specify the name of the processed threshold.conf to output.

.. option:: --post-hook=<command>

   A command to run after the rules have been updated; will not run if
   not change to the output files was made.  For example::

     --post-hook=sudo kill -USR2 $(cat /var/run/suricata.pid)

   will tell Suricata to reload its rules.

Examples
--------

Download ET open rules for the version of Suricata found on the path,
saving the rules in /etc/suricata/rules::

    idstools-rulecat -o /etc/suricata/rules

Download ET pro rules for the version of Suricata found on the path,
saving the rules in /etc/suricata/rules::

    idstools-rulecat --etpro XXXXXXXXXXXXXXXX -o /etc/suricata/rules

Download ET open rules plus an additional rule files and save the
rules in /etc/suricata/rules::

    idstools-rulecat --etopen \
        --url https://sslbl.abuse.ch/blacklist/sslblacklist.rules \
	-o /etc/suricata/rules

Configuration File
------------------

Command line arguments can be put in a file, one per line and used as
a configuration file.  By default, idstools-rulecat will look for a
file in the current directory named rulecat.conf.

Example configuration file::

    --suricata=/usr/sbin/suricata
    --merged=rules/merged.rules
    --disable=disable.conf
    --enable=enable.conf
    --modify=modify.conf
    --post-hook=sudo kill -USR2 $(cat /var/run/suricata.pid)
    --etpro=XXXXXXXXXXXXXXXX
    --url=https://sslbl.abuse.ch/blacklist/sslblacklist.rules

If *rulecat.conf* is in the current directory it will be used just by
calling ``idstools-rulecat`` with no arguments. Otherwise you can
point *idstools-rulecat* at a configuration with the command
``idstools-rulecat @/path/to/rulecat.conf``.

Source
------

`idstools/scripts/rulecat.py <../_modules/idstools/scripts/rulecat.html>`_
