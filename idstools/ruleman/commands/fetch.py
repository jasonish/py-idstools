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

import sys
import os
import os.path
import tempfile
import shutil
import logging
import io

import idstools.net
import idstools.snort

from idstools.ruleman import util

from idstools.ruleman.commands.dumpdynamicrules import DumpDynamicRulesCommand

LOG = logging.getLogger()

class FetchCommand(object):

    def __init__(self, config, args):
        self.config = config
        self.args = args

        self.sources = self.config.get_sources()

    def run(self):

        fetched = []

        for source in self.sources.values():
            if self.args and source["name"] not in self.args:
                continue
            if not source["enabled"]:
                continue
            if self.check_checksum(source):
                LOG.info("Source checksum has not changed, not fetching")
            else:
                fileobj = self.fetch(source)
                if fileobj:
                    fetched.append({"source": source, "fileobj": fileobj})

        print("Fetched:", [item["source"]["name"] for item in fetched])

        for entry in fetched:
            source = entry["source"]
            print("Extracting %s." % source["name"])
            dest = "sources/%s" % source["name"]
            if os.path.exists(dest):
                shutil.rmtree(dest)
            os.makedirs(dest)
            util.extract_archive(entry["fileobj"].name, dest)
            open("%s/checksum" % (dest), "w").write(
                util.md5_filename(entry["fileobj"].name))

            self.dump_dynamic_rules(source["name"])

    def has_dynamic_rules(self, source):
        if os.path.exists("sources/%s/so_rules" % (source)):
            return True
        else:
            return False

    def dump_dynamic_rules(self, source):
        if not self.has_dynamic_rules(source):
            LOG.debug("Source %s does not appear to have dynamic rules",
                      source)
            return

        if "snort" not in self.config:
            LOG.warn("Not generating dynamic rule stubs, snort not configured")
            return

        DumpDynamicRulesCommand(self.config, [source]).run()

    def check_checksum(self, source):
        """ Check the current checksum against the source checksum.

        Return True if they match, otherwise return False.
        """
        current_checksum = self.current_checksum(source)
        if current_checksum:
            source_checksum = self.fetch_checksum(source)
            if source_checksum and source_checksum == current_checksum:
                return True
        return False

    def fetch(self, source):

        print("Fetching %s : %s" % (
            source["name"], util.get_filename_from_url(source["url"])))
        fileobj = tempfile.NamedTemporaryFile(
            suffix=util.get_filename_from_url(source["url"]), mode="wb")
        try:
            length, info = idstools.net.get(
                source["url"], fileobj, self.progress_hook)
            # A print to print a new line.
            print("")
            return fileobj
        except idstools.net.HTTPError as err:
            # HTTP errors.
            print(" error: %s %s" % (err.code, err.msg))
            body = err.read().strip()
            for line in body.split("\n"):
                print("  | %s" % (line))
        except Exception as err:
            print(" error: %s" % (err))

    def current_checksum(self, source):
        checksum_filename = "sources/%s/checksum" % (source["name"])
        if os.path.exists(checksum_filename):
            return open(checksum_filename, "rb").read()
        else:
            LOG.debug("No checksum file exists for ruleset %s", source["name"])

    def fetch_checksum(self, source):
        checksum_url = self.get_checksum_url(source)
        buf = io.BytesIO()
        try:
            length, info = idstools.net.get(checksum_url, buf)
            return buf.getvalue().strip()
        except idstools.net.HTTPError as err:
            LOG.warn("Error fetching checksum url %s: %s %s" % (
                checksum_url, err.code, err.msg))
            return None

    def get_checksum_url(self, source):
        filename = util.get_filename_from_url(source["url"])
        checksum_filename = "%s.md5" % (filename)
        checksum_url = source["url"].replace(filename, checksum_filename)
        return checksum_url

    def progress_hook(self, content_length, bytes_read):
        percent = int((bytes_read / float(content_length)) * 100)
        buf = " %3d%% - %-30s" % (
            percent, "%d/%d" % (bytes_read, content_length))
        sys.stdout.write(buf)
        sys.stdout.flush()
        sys.stdout.write("\b" * 38)
