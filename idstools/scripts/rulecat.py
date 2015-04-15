#! /usr/bin/env python
#
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

import sys
import re
import os.path
import logging
import argparse
import shlex
import time
import hashlib
import fnmatch

try:
    from io import StringIO
except:
    from StringIO import StringIO

try:
    import progressbar
except:
    progressbar = None

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import idstools.rule
import idstools.suricata
import idstools.net
import idstools.util

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger()

ET_OPEN_URL = "https://rules.emergingthreats.net/open/suricata%(version)s/emerging.rules.tar.gz"

DEFAULT_RULES_DIRECTORY = "/etc/suricata/rules"

DISABLE_CONF = "/etc/suricata/disable.conf"
ENABLE_CONF  = "/etc/suricata/enable.conf"
MODIFY_CONF  = "/etc/suricata/modify.conf"

class IdRuleMatcher(object):
    """Matcher object to match an idstools rule object by its signature
    ID."""

    def __init__(self, generatorId, signatureId):
        self.generatorId = generatorId
        self.signatureId = signatureId

    def match(self, rule):
        return self.generatorId == rule.gid and self.signatureId == rule.sid

    @classmethod
    def parse(cls, match):
        try:
            signatureId = int(match)
            return cls(1, signatureId)
        except:
            pass
        try:
            generatorString, signatureString = match.split(":")
            generatorId = int(generatorString)
            signatureId = int(signatureString)
            return cls(generatorId, signatureId)
        except:
            pass
        return None

class GroupMatcher(object):
    """Matcher object to match an idstools rule object by its group (ie:
    filename)."""

    def __init__(self, pattern):
        self.pattern = pattern

    def match(self, rule):
        if hasattr(rule, "group") and rule.group is not None:
            return fnmatch.fnmatch(rule.group, self.pattern)
        return False

    @classmethod
    def parse(cls, match):
        if match.startswith("group:"):
            try:
                group = match.split(":", 1)[1]
                return cls(group.strip())
            except:
                pass
        return None

class ReRuleMatcher(object):
    """Matcher object to match an idstools rule object by regular
    expression."""

    def __init__(self, pattern):
        self.pattern = pattern

    def match(self, rule):
        if self.pattern.search(rule.raw):
            return True
        return False

    @classmethod
    def parse(cls, buf):
        if buf.startswith("re:"):
            try:
                patternstr = buf.split(":", 1)[1].strip()
                logger.debug(
                    "Compiling regular expression match: %s" % (patternstr))
                pattern = re.compile(patternstr, re.I)
                return cls(pattern)
            except:
                pass
        return None

class ModifyRuleFilter(object):
    """Filter to modify an idstools rule object.

    Important note: This filter does not modify the rule inplace, but
    instead returns a new rule object with the modification.
    """

    def __init__(self, matcher, pattern, repl):
        self.matcher = matcher
        self.pattern = pattern
        self.repl = repl

    def match(self, rule):
        return self.matcher.match(rule)

    def filter(self, rule):
        return idstools.rule.parse(
            self.pattern.sub(self.repl, str(rule)), rule.group)

    @classmethod
    def parse(cls, buf):
        tokens = shlex.split(buf)
        if len(tokens) != 3:
            raise Exception("Bad number of arguments.")
        matcher = parse_rule_match(tokens[0])
        if not matcher:
            raise Exception("Bad match string: %s" % (tokens[0]))
        pattern = re.compile(tokens[1])
        return cls(matcher, pattern, tokens[2])

class Fetch(object):

    def __init__(self, args):
        self.args = args

    def get_rule_url(self):
        suricata_version = idstools.suricata.get_version(self.args.suricata)
        if not suricata_version or not suricata_version.short:
            return ET_OPEN_URL % {"version": ""}
        else:
            return ET_OPEN_URL % {"version": "-" + suricata_version.short}

    def check_checksum(self, tmp_filename, url):
        try:
            checksum_url = url + ".md5"
            local_checksum = hashlib.md5(open(tmp_filename).read()).hexdigest()
            remote_checksum_buf = StringIO.StringIO()
            logger.info("Fetching %s." % (checksum_url))
            remote_checksum = idstools.net.get(
                checksum_url, remote_checksum_buf)
            logger.debug("Local checksum=|%s|; remote checksum=|%s|" % (
                local_checksum.strip(), remote_checksum_buf.getvalue().strip()))
            if local_checksum.strip() == remote_checksum_buf.getvalue().strip():
                os.utime(tmp_filename, None)
                return True
        except Exception as err:
            logger.error("Failed to check remote checksum: %s" % err)
        return False

    def progress_hook(self, content_length, bytes_read):
        percent = int((bytes_read / float(content_length)) * 100)
        buf = " %3d%% - %-30s" % (
            percent, "%d/%d" % (bytes_read, content_length))
        sys.stdout.write(buf)
        sys.stdout.flush()
        sys.stdout.write("\b" * 38)
        if bytes_read and bytes_read >= content_length:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def run(self):
        url = self.get_rule_url()
        tmp_filename = os.path.join(self.args.temp, os.path.basename(url))
        if not self.args.force and os.path.exists(tmp_filename):
            if time.time() - os.stat(tmp_filename).st_mtime < (60 * 15):
                logger.info(
                    "Last download less than 15 minutes ago. Not fetching.")
                return self.files_as_dict()
            if self.check_checksum(tmp_filename, url):
                logger.info("Remote checksum has not changed. Not fetching.")
                return self.files_as_dict()
        if not os.path.exists(self.args.temp):
            os.makedirs(self.args.temp)
        logger.info("Fetching %s." % (url))
        idstools.net.get(
            url, open(tmp_filename, "wb"), progress_hook=self.progress_hook)
        logger.info("Done.")
        return self.files_as_dict()

    def basename(self):
        return os.path.basename(self.get_rule_url())

    def files_as_dict(self):
        files = idstools.util.archive_to_dict(
            os.path.join(self.args.temp, self.basename()))

        # Erase path information.
        for key in files.keys():
            files[os.path.basename(key)] = files.pop(key)

        return files

def parse_rule_match(match):
    matcher = IdRuleMatcher.parse(match)
    if matcher:
        return matcher
    matcher = ReRuleMatcher.parse(match)
    if matcher:
        return matcher
    matcher = GroupMatcher.parse(match)
    if matcher:
        return matcher
    return None

def load_matchers(filename):

    matchers = []

    with open(filename) as fileobj:
        for line in fileobj:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            matcher = parse_rule_match(line)
            if not matcher:
                logger.warn("Failed to parse: \"%s\"" % (line))
            else:
                matchers.append(matcher)

    return matchers

def load_local_files(local, files):
    """Load local files into the files dict."""
    if os.path.isdir(local):
        for dirpath, dirnames, filenames in os.walk(local):
            for filename in filenames:
                if filename.endswith(".rules"):
                    path = os.path.join(local, filename)
                    if filename in files:
                        logger.warn(
                            "Local file %s overrides existing file of "
                            "same name." % (path))
                    files[filename] = open(path).read()
    else:
        filename = os.path.basename(local)
        if filename in files:
            logger.warn(
                "Local file %s overrides existing file of same name." % (
                    local))
        files[filename] = open(local).read()

def write_to_directory(directory, files, rulemap):
    logger.info("Writing rule files to %s." % (directory))
    for filename in sorted(files):
        outpath = os.path.join(
            directory, os.path.basename(filename))
        logger.debug("Writing %s." % outpath)
        if not filename.endswith(".rules"):
            open(outpath, "wb").write(files[filename])
        else:
            content = []
            for line in StringIO.StringIO(files[filename]):
                rule = idstools.rule.parse(line)
                if not rule:
                    content.append(line.strip())
                else:
                    content.append(str(rulemap[rule.id]))
            open(outpath, "wb").write("\n".join(content))

def write_merged(filename, rulemap):
    logger.info("Writing merged rules file: %s." % (filename))
    with open(filename, "w") as fileobj:
        for rule in rulemap:
            print(str(rulemap[rule]), file=fileobj)

def write_yaml_fragment(filename, files):
    logger.info(
        "Writing YAML configuration fragment: %s" % (filename))
    with open(filename, "w") as fileobj:
        print("%YAML 1.1", file=fileobj)
        print("---", file=fileobj)
        print("rule-files:", file=fileobj)
        for fn in sorted(files):
            if fn.endswith(".rules"):
                print("  - %s" % os.path.basename(fn), file=fileobj)

def main():

    if os.path.exists("rulecat.conf"):
        logger.info("Loading rulecat.conf")
        sys.argv.insert(1, "@rulecat.conf")

    suricata_path = idstools.suricata.get_path()

    parser = argparse.ArgumentParser(fromfile_prefix_chars="@")
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help="Be more verbose")
    parser.add_argument("-t", "--temp", default="/var/tmp/idstools-rulecat",
                        metavar="<directory>",
                        help="Temporary work directory")
    parser.add_argument("--suricata", default=suricata_path,
                        metavar="<path>",
                        help="Path to Suricata program (default: %s)" %
                        suricata_path)
    parser.add_argument("-f", "--force", action="store_true", default=False,
                        help="Force operations that might otherwise be skipped")
    parser.add_argument("--rules-dir", metavar="<directory>",
                        help="Output rules directory.")
    parser.add_argument("--merged", default=None, metavar="<filename>",
                        help="Output merged rules file.")
    parser.add_argument("--yaml-fragment", metavar="<filename>",
                        help="Output YAML fragment for rule inclusion.")
    parser.add_argument("--local", metavar="<filename>",
                        help="Local rule files or directories.")
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    logger.debug(args)

    disable_matchers = []
    enable_matchers = []

    if os.path.exists(DISABLE_CONF):
        disable_matchers += load_matchers(DISABLE_CONF)
    if os.path.exists(ENABLE_CONF):
        enable_matchers += load_matchers(ENABLE_CONF)

    files = Fetch(args).run()

    if args.local:
        load_local_files(args.local, files)

    rules = []
    for filename in files:
        logger.debug("Parsing %s." % (filename))
        rules += idstools.rule.parse_fileobj(
            StringIO.StringIO(files[filename]), filename)

    rulemap = {}
    for rule in rules:
        if rule.id not in rulemap:
            rulemap[rule.id] = rule
        else:
            logger.warning("Found duplicate rule id: %s" % (rule.brief()))
    logger.info("Loaded %d rules." % (len(rules)))

    disable_count = 0
    enable_count = 0
    for key, rule in rulemap.items():

        for matcher in disable_matchers:
            if rule.enabled and matcher.match(rule):
                logger.debug("Disabling: %s" % (rule.brief()))
                rule.enabled = False
                disable_count += 1

        for matcher in enable_matchers:
            if not rule.enabled and matcher.match(rule):
                logger.debug("Enabling: %s" % (rule.brief()))
                rule.enabled = True
                enable_count += 1

    logger.info("Disabled %d rules." % (disable_count))
    logger.info("Enabled %d rules." % (enable_count))

    # Fixup flowbits.
    flowbits = idstools.rule.enable_flowbit_dependencies(rulemap)
    logger.info("Enabled %d rules for flowbit dependencies." % (len(flowbits)))

    if args.rules_dir:
        write_to_directory(args.rules_dir, files, rulemap)

    if args.merged:
        write_merged(args.merged, rulemap)

    if args.yaml_fragment:
        write_yaml_fragment(args.yaml_fragment, files)

    logger.info("Done.")

    return 0

if __name__ == "__main__":
    sys.exit(main())
