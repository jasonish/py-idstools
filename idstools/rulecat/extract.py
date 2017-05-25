# Copyright (c) 2017 Jason Ish
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
from zipfile import ZipFile

def extract_tar(filename):
    files = {}

    tf = tarfile.open(filename, mode="r:*")

    try:
        while True:
            member = tf.next()
            if member is None:
                break
            if not member.isfile():
                continue
            fileobj = tf.extractfile(member)
            if fileobj:
                files[member.name] = fileobj.read()
    finally:
        tf.close()

    return files

def extract_zip(filename):
    files = {}

    with ZipFile(filename) as reader:
        for name in reader.namelist():
            if name.endswith("/"):
                continue
            files[name] = reader.read(name)
    
    return files

def try_extract(filename):
    try:
        return extract_tar(filename)
    except:
        pass

    try:
        return extract_zip(filename)
    except:
        pass
    
    return None
