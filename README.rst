idstools.py
===========

idstools.py is a collection of Python libraries for working with IDS
systems (typically Snort and Suricata).

Features
--------

- Snort/Suricata unified2 log file reading.
- Continuous unified2 directory spool reading with bookmarking (a'la
  Barnyard2).
- Parser and mapping for classification.config.
- Parser and mapping for gen-msg.map and sid-msg.map.

Requirements
------------

- Python 2.6 or 2.7; Python 3.3 works but not as well tested.
- Currently only tested on Linux.

Example Programs
----------------

Example programs are found in the examples/ directory and demonstrate
basic usage of the idstools libraries.

u2spewfoo.py
^^^^^^^^^^^^

u2spewfoo.py is a Python program similar to u2spewfoo provided by
Snort. It reads and prints records from one or more unified2 log
files.

usage: python ./examples/u2spewfoo.py <file1> [file2 ...]

u2fast.py
^^^^^^^^^

u2fast.py reads unified2 log files and prints out events in the "fast"
format.

usage: python ./examples/u2fast.py \
       	      -C /path/to/classification.config \
	      -S /path/to/sid-msg.map \
	      -G /path/to/gen-msg.map

stail.py
^^^^^^^^

While not really IDS related, stail.py shows an example of how one
might do a "tail -f" on a spool directory of line oriented text files.

usage: ./examples/stail.py [options] <directory> <prefix>

options:

    --delete        delete files on close (when a new one is opened)
    --bookmark      enable spool bookmarking

The delete option will delete a file when it has been completely read
and there is a new spool file to open.

Bookmarking will remember the last location read so subsequent
invocations will start where the last instance of stail.py finished.

Bookmarking and delete on close give you basic barnyard2 like
behaviour where files are removed when they have been processed, and
the current processing location is remembered.

u2tail.py
^^^^^^^^^

A "tail -f" like program for reading unified2 spool directories as
created by Snort and Suricata.

usage: ./examples/u2tail.py [options] <directory> <prefix>

options:

    --delete        delete files on close (when a new one is opened)
    --bookmark      enable spool bookmarking
    --records       read records instead of events

Reading records in events will read individual unified2 records and
print them one at a time.  The default behaviour is to aggregate
records into complete events.

The delete and bookmark options are the same as they are for stail.py.
