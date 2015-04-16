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

""" Module for network related operations. """

try:
    # Python 3.3...
    from urllib.request import urlopen
    from urllib.error import HTTPError
except ImportError:
    # Python 2.6, 2.7.
    from urllib2 import urlopen
    from urllib2 import HTTPError

# Number of bytes to read at a time in a GET request.
GET_BLOCK_SIZE = 8192

def get(url, fileobj, progress_hook=None):
    """ Perform a GET request against a URL writing the contents into
    the provideded file like object.

    :param url: The URL to fetch
    :param fileobj: The fileobj to write the content to
    :param progress_hook: The function to call with progress updates

    :returns: Returns a tuple containing the number of bytes read and
      the result of the info() function from urllib2.urlopen().

    :raises: Exceptions from urllib2.urlopen() and writing to the
      provided fileobj may occur.
    """

    remote = urlopen(url)
    info = remote.info()
    try:
        content_length = int(info["content-length"])
    except:
        content_length = 0
    bytes_read = 0
    while True:
        buf = remote.read(GET_BLOCK_SIZE)
        if not buf:
            # EOF
            break
        bytes_read += len(buf)
        fileobj.write(buf)
        if progress_hook:
            progress_hook(content_length, bytes_read)
    remote.close()
    fileobj.flush()
    return bytes_read, info

if __name__ == "__main__":

    import sys

    try:
        get(sys.argv[1], sys.stdout)
    except Exception as err:
        print("ERROR: %s" % (err))
