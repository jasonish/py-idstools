Example Programs
================

.. contents::

u2spewfoo.py
------------

`u2spewfoo.py` is a reimplementation of u2spewfoo included with the
SNORT(R) distribution.

::

   usage: ./examples/u2spewfoo.py <file>...

gen-sidmsgmap.py
----------------

Generate a sid-msg.map style file from the rule files provided on the
command line.

::

    usage: ./examples/gen-sidmsgmap.py [options] <file>...

    options:

        -2, --v2      Output a new (v2) style sid-msg.map file.

    The files passed on the command line can be a list of a filenames, a
    tarball, a directory name (containing rule files) or any combination
    of the above.

The files support by gen-sidmsgmap.py are:
   * Individual rule files
   * Directories (containing rule files)
   * Tarballs (containing rule files such as VRT rule tarballs)

u2fast.py
---------

Reads unified log files and output them in "fast" style.

::

    usage: ./examples/u2fast.py [options] <filename>...

    options:
        -C <classification.config>
        -G <gen-msg.map>
        -S <sid-msg.map>

Classification, gen-msg.map and sid-msg.map files can be provided
resolve event description and classification names.

u2tail.py
---------

`Tail` a directory of unified2 files similar to how a unified2 spooler
might do.

::

    usage: ./examples/u2tail.py [options] <directory> <prefix>

    options:

        --delete        delete files on close (when a new one is opened)
        --bookmark      enable spool bookmarking
        --records       read records instead of events

Example::

    ./examples/u2tail.py --delete --bookmark /var/log/snort merged.log

will read events from the unified2 log files in /var/log/snort
bookmarking its progress and deleting the files when they have been
completely processed.

