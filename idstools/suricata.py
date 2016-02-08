# Copyright (c) 2015 Jason Ish
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

import os
import os.path
import subprocess
import re
import logging
from collections import namedtuple

logger = logging.getLogger()

SuricataVersion = namedtuple(
    "SuricataVersion", ["major", "minor", "patch", "full", "short", "raw"])

def get_path(program="suricata"):
    """Find Suricata in the shell path."""
    for path in os.environ["PATH"].split(os.pathsep):
        suricata_path = os.path.join(path, program)
        logger.debug("Testing path: %s" % (path))
        if os.path.exists(suricata_path):
            logger.debug("Found %s." % (path))
            return suricata_path

def get_version(path=None):
    """Get a SuricataVersion named tuple describing the version.

    If no path argument is found, the envionment PATH will be
    searched.
    """
    if not path:
        path = get_path("suricata")
    if not path:
        return None
    output = subprocess.check_output([path, "-V"])
    if output:
        m = re.search("version ((\d+)\.(\d+)\.?(\d+|\w+)?)", output.strip())
        if m:
            full = m.group(1)
            major = m.group(2)
            minor = m.group(3)
            patch = m.group(4)
            short = "%s.%s" % (major, minor)
            return SuricataVersion(
                major=major, minor=minor, patch=patch, short=short, full=full,
                raw=output)
    return SuricataVersion(
        major=None, minor=None, patch=None, full=None, short=None,
        raw=output)
