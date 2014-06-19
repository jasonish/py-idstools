#! /usr/bin/env python
#
# Copyright (c) 2011 Jason Ish
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

from __future__ import print_function

import tarfile
import hashlib
import tempfile
import shutil
import atexit

def get_filename_from_url(url):
    """Given a URL, attempt to derive the filename.

    This is required as Snort VRT URLs append the oinkcode to the end
    of the URL.

    """

    # Step backwards through the URL components looking for what might
    # be a filename.
    parts = url.split("/")
    for part in reversed(parts):
        if part.find(".") > -1:
            return part

    # Not found.
    return None

def md5_file(fileobj):
    return hashlib.md5(fileobj.read()).hexdigest()

def md5_filename(filename):
    return md5_file(open(filename, "rb"))

def extract_archive(filename, destination):
    """Extract an archive file (.tar.gz) to destination."""
    archive = tarfile.open(filename)
    archive.extractall(destination)

def mktempdir(delete_on_exit=True):
    """Create a temporary directory and optionally have it removed on
    exit.

    """
    tmpdir = tempfile.mkdtemp("idstools-rulemman-tmp")
    if delete_on_exit:
        atexit.register(shutil.rmtree, tmpdir, ignore_errors=True)
    return tmpdir
