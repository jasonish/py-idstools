# Copyright (c) 2011-2014 Jason Ish
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
import subprocess
import re
import logging

import idstools.util

LOG = logging.getLogger()

class SnortApp(object):
    """ Snort represents the Snort application.

    :param config: A dictionary configuration object.  The dictionary can
      contain the same fields as the following parameters.  Parameters take
      precedence over the config dictionary.

    :param path: The path to the Snort binary.
    """

    def __init__(self, config=None, path=None, os=None, dynamic_engine_lib=None):
        self.path = path if path else (config.get("path") if config else None)
        self.os = os if os else (config.get("os") if config else None)
        self.dynamic_engine_lib = self.set_dynamic_engine_lib(
            dynamic_engine_lib, config)
        self.arch = self.get_arch()

    def version(self):
        stdout, stderr = subprocess.Popen(
            [self.path, "-V"], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE).communicate()
        m = re.search("(Version (\d+\.\d+\.\d+\.\d+).*)$", stderr, re.M)
        return m.group(2).strip(), m.group(1).strip(), stderr

    def set_dynamic_engine_lib(self, dynamic_engine_lib, config):
        if dynamic_engine_lib:
            return dynamic_engine_lib
        elif config and "dynamic-engine-lib" in config:
            return config.get("dynamic-engine-lib")
        else:
            directory, basename = os.path.split(self.path)
            prefix = os.path.split(directory)[0]

            dynamic_engine_filename = "libsf_engine.so"

            search_paths = (
                os.path.join(
                    prefix,
                    "lib64",
                    "snort_dynamicengine",
                    dynamic_engine_filename),
                os.path.join(
                    prefix,
                    "lib",
                    "snort_dynamicengine",
                    dynamic_engine_filename),
            )

            for path in search_paths:
                if os.path.exists(path):
                    return path

            return None

    def exists(self):
        if self.path and os.path.exists(self.path):
            return True
        return False

    def get_arch(self):
        arch = os.uname()[4]
        if arch == "x86_64":
            return "x86-64"
        elif re.match(r"i\d86", arch):
            return "i386"
        else:
            return None

    def find_dynamic_detection_lib_dir(self, prefix):
        """Find the dynamic SO rule directory in prefix based on what
        we know about Snort.
        """
        assert self.os is not None
        path = os.path.join(
            prefix, "so_rules", "precompiled", self.os, self.get_arch())
        if os.path.exists(path):
            return os.path.join(path, os.listdir(path)[0])
        else:
            return None

    def dump_dynamic_rules(self, dynamic_detection_lib_dir, verbose=False):

        if not self.exists():
            LOG.warn("Snort application not set or does not exist")
            return

        destination = idstools.util.mktempdir()
        args = [self.path,
                "--dynamic-detection-lib-dir=%s" % (dynamic_detection_lib_dir),
                "--dynamic-engine-lib=%s" % (self.dynamic_engine_lib),
                "--dump-dynamic-rules=%s" % (destination)]
        stdout = sys.stdout if verbose else subprocess.PIPE
        stderr = sys.stderr if verbose else subprocess.PIPE
        process = subprocess.Popen(args, stdout=stdout, stderr=stderr)
        rc = process.wait()
        if rc == 0:
            files = {}
            for filename in os.listdir(destination):
                files[filename] = open(
                    os.path.join(destination, filename)).read()
            return files
        else:
            if not verbose:
                LOG.error("Failed to build dynamic rule stubs: %s" % (
                    process.communicate()[1]))
            else:
                # Error already printed to stderr.
                LOG.error("Failed to build dynamic rule stubs.")
            return None
