# Copyright (c) 2016 Jason Ish
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

import logging
import time

class SuriColourLogHandler(logging.StreamHandler):
    """An alternative stream log handler that logs with Suricata inspired
    log colours."""

    GREEN = "\x1b[32m"
    BLUE = "\x1b[34m"
    REDB = "\x1b[1;31m"
    YELLOW = "\x1b[33m"
    RED = "\x1b[31m"
    YELLOWB = "\x1b[1;33m"
    ORANGE = "\x1b[38;5;208m"
    RESET = "\x1b[0m"

    def formatTime(self, record):
        lt = time.localtime(record.created)
        t = time.strftime("%Y-%m-%d %H:%M:%S", lt)
        return "%s,%03d" % (t, record.msecs)

    def emit(self, record):

        if record.levelname == "ERROR":
            level_prefix = self.REDB
            message_prefix = self.REDB
        else:
            level_prefix = self.YELLOW
            message_prefix = ""

        self.stream.write("%s%s%s - <%s%s%s> -- %s%s%s\n" % (
            self.GREEN,
            self.formatTime(record),
            self.RESET,
            level_prefix,
            record.levelname,
            self.RESET,
            message_prefix,
            record.getMessage(),
            self.RESET))
