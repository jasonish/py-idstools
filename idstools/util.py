# Copyright (c) 2013 Jason Ish
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

""" Module for utility functions that don't really fit anywhere else. """

import hashlib
import socket
import struct
import tempfile
import atexit
import shutil
import subprocess
import os
import fnmatch

def md5_hexdigest(filename):
    """ Compute the MD5 checksum for the contents of the provided filename.

    :param filename: Filename to computer MD5 checksum of.

    :returns: A string representing the hex value of the computed MD5.
    """
    return hashlib.md5(open(filename).read().encode()).hexdigest()

def decode_inet_addr(addr):
    if len(addr) == 4:
        return socket.inet_ntoa(addr)
    else:
        parts = struct.unpack(">" + "H" * int(len(addr) / 2), addr)
        return ":".join("%04x" % p for p in parts)

def mktempdir(delete_on_exit=True):
    """ Create a temporary directory that is removed on exit. """
    tmpdir = tempfile.mkdtemp("idstools")
    if delete_on_exit:
        atexit.register(shutil.rmtree, tmpdir, ignore_errors=True)
    return tmpdir

def archive_to_dict(filename, include="*"):
    """Convert an archive file (eg: .tar.gz) to a dict of filenames and
    their content.

    Useful for working with rules."""

    files = {}
    if filename.endswith(".tar.gz"):
        # This is faster than using the Python libs.
        tempdir = mktempdir(delete_on_exit=True)
        subprocess.Popen(
            "gunzip -c %s | tar xf -" % (filename),
            cwd=tempdir, shell=True).wait()
        for dirpath, dirnames, filenames in os.walk(tempdir):
            for filename in filenames:
                path = os.path.join(dirpath, filename)
                if include and not fnmatch.fnmatch(path, include):
                    continue
                content = open(path, "rb").read()
                files[path[len(tempdir) + 1:]] = content
    return files
