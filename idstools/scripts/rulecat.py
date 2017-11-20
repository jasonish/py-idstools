# Copyright (c) 2015-2017 Jason Ish
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
import subprocess
import types
import shutil
import glob
import io

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import idstools.rule
import idstools.suricata
import idstools.net
from idstools.rulecat import configs
from idstools.rulecat.loghandler import SuriColourLogHandler
from idstools.rulecat import extract

# Initialize logging, use colour if on a tty.
if len(logging.root.handlers) == 0 and os.isatty(sys.stderr.fileno()):
    logger = logging.getLogger()
    logger.setLevel(level=logging.INFO)
    logger.addHandler(SuriColourLogHandler())
else:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - <%(levelname)s> - %(message)s")
    logger = logging.getLogger()

# If Suricata is not found, default to this version.
DEFAULT_SURICATA_VERSION = "4.0"

# Template URL for Emerging Threats Pro rules.
ET_PRO_URL = ("https://rules.emergingthreatspro.com/"
              "%(code)s/"
              "suricata%(version)s/"
              "etpro.rules.tar.gz")

# Template URL for Emerging Threats Open rules.
ET_OPEN_URL = ("https://rules.emergingthreats.net/open/"
               "suricata%(version)s/"
               "emerging.rules.tar.gz")

class AllRuleMatcher(object):
    """Matcher object to match all rules. """

    def match(self, rule):
        return True

    @classmethod
    def parse(cls, buf):
        if buf.strip() == "*":
            return cls()
        return None

class IdRuleMatcher(object):
    """Matcher object to match an idstools rule object by its signature
    ID."""

    def __init__(self, generatorId, signatureId):
        self.generatorId = generatorId
        self.signatureId = signatureId

    def match(self, rule):
        return self.generatorId == rule.gid and self.signatureId == rule.sid

    @classmethod
    def parse(cls, buf):
        logger.debug("Parsing ID matcher: %s" % (buf))
        try:
            signatureId = int(buf)
            return cls(1, signatureId)
        except:
            pass
        try:
            generatorString, signatureString = buf.split(":")
            generatorId = int(generatorString)
            signatureId = int(signatureString)
            return cls(generatorId, signatureId)
        except:
            pass
        return None

class FilenameMatcher(object):
    """Matcher object to match a rule by its filename. This is similar to
    a group but has no specifier prefix.
    """

    def __init__(self, filename):
        self.filename = filename

    def match(self, rule):
        if hasattr(rule, "group") and \
           os.path.basename(rule.group) == self.filename:
            return True
        return False

    @classmethod
    def parse(cls, buf):
        if buf.strip().endswith(".rules"):
            return cls(buf.strip())
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
    def parse(cls, buf):
        if buf.startswith("group:"):
            try:
                logger.debug("Parsing group matcher: %s" % (buf))
                group = buf.split(":", 1)[1]
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
                logger.debug("Parsing regex matcher: %s" % (buf))
                patternstr = buf.split(":", 1)[1].strip()
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
        modified_rule = self.pattern.sub(self.repl, rule.format())
        parsed = idstools.rule.parse(modified_rule, rule.group)
        if parsed is None:
            logger.error("Modification of rule %s results in invalid rule: %s",
                         rule.idstr, modified_rule)
            return rule
        return parsed

    @classmethod
    def parse(cls, buf):
        tokens = shlex.split(buf)
        if len(tokens) == 3:
            matchstring, a, b = tokens
        elif len(tokens) > 3 and tokens[0] == "modifysid":
            matchstring, a, b = tokens[1], tokens[2], tokens[4]
        else:
            raise Exception("Bad number of arguments.")
        matcher = parse_rule_match(matchstring)
        if not matcher:
            raise Exception("Bad match string: %s" % (tokens[0]))
        pattern = re.compile(a)

        # Convert Oinkmaster backticks to Python.
        b = re.sub("\$\{(\d+)\}", "\\\\\\1", b)

        return cls(matcher, pattern, b)

class DropRuleFilter(object):
    """ Filter to modify an idstools rule object to a drop rule. """

    def __init__(self, matcher):
        self.matcher = matcher

    def is_noalert(self, rule):
        for option in rule.options:
            if option["name"] == "flowbits" and option["value"] == "noalert":
                return True
        return False

    def match(self, rule):
        if self.is_noalert(rule):
            return False
        return self.matcher.match(rule)

    def filter(self, rule):
        drop_rule = idstools.rule.parse(re.sub("^\w+", "drop", rule.raw))
        drop_rule.enabled = rule.enabled
        return drop_rule

class Fetch(object):

    def __init__(self, args):
        self.args = args

    def check_checksum(self, tmp_filename, url):
        try:
            checksum_url = url + ".md5"
            local_checksum = hashlib.md5(
                open(tmp_filename, "rb").read()).hexdigest().strip()
            remote_checksum_buf = io.BytesIO()
            logger.info("Checking %s." % (checksum_url))
            idstools.net.get(checksum_url, remote_checksum_buf)
            remote_checksum = remote_checksum_buf.getvalue().decode().strip()
            logger.debug("Local checksum=|%s|; remote checksum=|%s|" % (
                local_checksum, remote_checksum))
            if local_checksum == remote_checksum:
                os.utime(tmp_filename, None)
                return True
        except Exception as err:
            logger.error("Failed to check remote checksum: %s" % err)
        return False

    def progress_hook(self, content_length, bytes_read):
        if not content_length or content_length == 0:
            percent = 0
        else:
            percent = int((bytes_read / float(content_length)) * 100)
        buf = " %3d%% - %-30s" % (
            percent, "%d/%d" % (bytes_read, content_length))
        sys.stdout.write(buf)
        sys.stdout.flush()
        sys.stdout.write("\b" * 38)

    def progress_hook_finish(self):
        sys.stdout.write("\n")
        sys.stdout.flush()

    def url_basename(self, url):
        """ Return the base filename of the URL. """
        filename = os.path.basename(url).split("?", 1)[0]
        return filename

    def get_tmp_filename(self, url):
        url_hash = hashlib.md5(url.encode("utf-8")).hexdigest()
        return os.path.join(
            self.args.temp_dir,
            "%s-%s" % (url_hash, self.url_basename(url)))

    def fetch(self, url):
        tmp_filename = self.get_tmp_filename(url)
        if not self.args.force and os.path.exists(tmp_filename):
            if time.time() - os.stat(tmp_filename).st_mtime < (60 * 15):
                logger.info(
                    "Last download less than 15 minutes ago. Not downloading %s.",
                    url)
                return self.extract_files(tmp_filename)
            if self.check_checksum(tmp_filename, url):
                logger.info("Remote checksum has not changed. Not fetching.")
                return self.extract_files(tmp_filename)
        if not os.path.exists(self.args.temp_dir):
            os.makedirs(self.args.temp_dir)
        logger.info("Fetching %s." % (url))
        idstools.net.get(
            url,
            open(tmp_filename, "wb"),
            progress_hook=self.progress_hook if not self.args.quiet else None)
        if not self.args.quiet:
            self.progress_hook_finish()
        logger.info("Done.")
        return self.extract_files(tmp_filename)

    def run(self):
        files = {}
        for url in self.args.url:
            files.update(self.fetch(url))
        return files

    def extract_files(self, filename):
        files = extract.try_extract(filename)
        if files:
            return files

        # The file is not an archive, treat it as an individual file.
        basename = os.path.basename(filename).split("-", 1)[1]
        files = {}
        files[basename] = open(filename, "rb").read()
        return files

def parse_rule_match(match):
    matcher = AllRuleMatcher.parse(match)
    if matcher:
        return matcher

    matcher = IdRuleMatcher.parse(match)
    if matcher:
        return matcher

    matcher = ReRuleMatcher.parse(match)
    if matcher:
        return matcher

    matcher = GroupMatcher.parse(match)
    if matcher:
        return matcher

    matcher = FilenameMatcher.parse(match)
    if matcher:
        return matcher

    return None

def load_filters(filename):

    filters = []

    with open(filename) as fileobj:
        for line in fileobj:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            filter = ModifyRuleFilter.parse(line)
            if filter:
                filters.append(filter)
            else:
                log.error("Failed to parse modify filter: %s" % (line))

    return filters

def load_drop_filters(filename):
    
    matchers = load_matchers(filename)
    filters = []

    for matcher in matchers:
        filters.append(DropRuleFilter(matcher))

    return filters

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

def load_local(local, files):
    """Load local files into the files dict."""
    if os.path.isdir(local):
        for dirpath, dirnames, filenames in os.walk(local):
            for filename in filenames:
                if filename.endswith(".rules"):
                    path = os.path.join(local, filename)
                    load_local(path, files)
    else:
        local_files = glob.glob(local)
        if len(local_files) == 0:
            local_files.append(local)
        for filename in local_files:
            logger.info("Loading local file %s" % (filename))
            basename = os.path.basename(filename)
            if basename in files:
                logger.warn(
                    "Local file %s overrides existing file of same name." % (
                        filename))
            files[basename] = open(filename, "rb").read()

def build_report(prev_rulemap, rulemap):
    """Build a report of changes between 2 rulemaps.

    Returns a dict with the following keys that each contain a list of
    rules.
    - added
    - removed
    - modified
    """
    report = {
        "added": [],
        "removed": [],
        "modified": []
    }

    for key in rulemap:
        rule = rulemap[key]
        if not rule.id in prev_rulemap:
            report["added"].append(rule)
        elif rule.format() != prev_rulemap[rule.id].format():
            report["modified"].append(rule)
    for key in prev_rulemap:
        rule = prev_rulemap[key]
        if not rule.id in rulemap:
            report["removed"].append(rule)

    return report

def write_merged(filename, rulemap):

    if not args.quiet:
        prev_rulemap = {}
        if os.path.exists(filename):
            prev_rulemap = build_rule_map(
                idstools.rule.parse_file(filename))
        report = build_report(prev_rulemap, rulemap)
        enabled = len([rule for rule in rulemap.values() if rule.enabled])
        logger.info("Writing rules to %s: total: %d; enabled: %d; "
                    "added: %d; removed %d; modified: %d" % (
                        filename,
                        len(rulemap),
                        enabled,
                        len(report["added"]),
                        len(report["removed"]),
                        len(report["modified"])))
    
    with io.open(filename, encoding="utf-8", mode="w") as fileobj:
        for rule in rulemap:
            print(rulemap[rule].format(), file=fileobj)

def write_to_directory(directory, files, rulemap):
    if not args.quiet:
        previous_rulemap = {}
        for filename in files:
            outpath = os.path.join(
                directory, os.path.basename(filename))
            if os.path.exists(outpath):
                previous_rulemap.update(build_rule_map(
                    idstools.rule.parse_file(outpath)))
        report = build_report(previous_rulemap, rulemap)
        enabled = len([rule for rule in rulemap.values() if rule.enabled])
        logger.info("Writing rule files to directory %s: total: %d; "
                    "enabled: %d; added: %d; removed %d; modified: %d" % (
                        directory,
                        len(rulemap),
                        enabled,
                        len(report["added"]),
                        len(report["removed"]),
                        len(report["modified"])))

    for filename in sorted(files):
        outpath = os.path.join(
            directory, os.path.basename(filename))
        logger.debug("Writing %s." % outpath)
        if not filename.endswith(".rules"):
            open(outpath, "wb").write(files[filename])
        else:
            content = []
            for line in io.StringIO(files[filename].decode("utf-8")):
                rule = idstools.rule.parse(line)
                if not rule:
                    content.append(line.strip())
                else:
                    content.append(rulemap[rule.id].format())
            io.open(outpath, encoding="utf-8", mode="w").write(
                u"\n".join(content))

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

def write_sid_msg_map(filename, rulemap, version=1):
    logger.info("Writing %s." % (filename))
    with io.open(filename, encoding="utf-8", mode="w") as fileobj:
        for key in rulemap:
            rule = rulemap[key]
            if version == 2:
                formatted = idstools.rule.format_sidmsgmap_v2(rule)
                if formatted:
                    print(formatted, file=fileobj)
            else:
                formatted = idstools.rule.format_sidmsgmap(rule)
                if formatted:
                    print(formatted, file=fileobj)

def build_rule_map(rules):
    """Turn a list of rules into a mapping of rules.

    In case of gid:sid conflict, the rule with the higher revision
    number will be used.
    """
    rulemap = {}

    for rule in rules:
        if rule.id not in rulemap:
            rulemap[rule.id] = rule
        else:
            if rule["rev"] > rulemap[rule.id]["rev"]:
                rulemap[rule.id] = rule

    return rulemap

def dump_sample_configs():

    for filename in configs.filenames:
        if os.path.exists(filename):
            logger.info("File already exists, not dumping %s." % (filename))
        else:
            logger.info("Creating %s." % (filename))
            shutil.copy(os.path.join(configs.directory, filename), filename)

def resolve_flowbits(rulemap, disabled_rules):
    flowbit_resolver = idstools.rule.FlowbitResolver()
    flowbit_enabled = set()
    while True:
        flowbits = flowbit_resolver.get_required_flowbits(rulemap)
        logger.debug("Found %d required flowbits.", len(flowbits))
        required_rules = flowbit_resolver.get_required_rules(rulemap, flowbits)
        logger.debug(
            "Found %d rules to enable to for flowbit requirements",
            len(required_rules))
        if not required_rules:
            logger.debug("All required rules enabled.")
            break
        for rule in required_rules:
            if not rule.enabled and rule in disabled_rules:
                logger.debug(
                    "Enabling previously disabled rule for flowbits: %s" % (
                        rule.brief()))
            rule.enabled = True
            flowbit_enabled.add(rule)
    logger.info("Enabled %d rules for flowbit dependencies." % (
        len(flowbit_enabled)))

class ThresholdProcessor:

    patterns = [
        re.compile("\s+(re:\"(.*)\")"),
        re.compile("\s+(re:(.*?)),.*"),
        re.compile("\s+(re:(.*))"),
    ]

    def extract_regex(self, buf):
        for pattern in self.patterns:
            m = pattern.search(buf)
            if m:
                return m.group(2)

    def extract_pattern(self, buf):
        regex = self.extract_regex(buf)
        if regex:
            return re.compile(regex, re.I)

    def replace(self, threshold, rule):
        for pattern in self.patterns:
            m = pattern.search(threshold)
            if m:
                return threshold.replace(
                    m.group(1), "gen_id %d, sig_id %d" % (rule.gid, rule.sid))
        return thresold

    def process(self, filein, fileout, rulemap):
        count = 0
        for line in filein:
            line = line.rstrip()
            if not line or line.startswith("#"):
                print(line, file=fileout)
                continue
            pattern = self.extract_pattern(line)
            if not pattern:
                print(line, file=fileout)
            else:
                for rule in rulemap.values():
                    if rule.enabled:
                        if pattern.search(rule.format()):
                            count += 1
                            print("# %s" % (rule.brief()), file=fileout)
                            print(self.replace(line, rule), file=fileout)
                            print("", file=fileout)
        logger.info("Generated %d thresholds to %s." % (count, fileout.name))

class FileTracker:
    """Used to check if files are modified.

    Usage: Add files with add(filename) prior to modification. Test
    with any_modified() which will return True if any of the checksums
    have been modified.

    """

    def __init__(self):
        self.hashes = {}

    def add(self, filename):
        checksum = self.md5(filename)
        logger.debug("Recording file %s with hash '%s'.", filename, checksum)
        self.hashes[filename] = checksum

    def md5(self, filename):
        if not os.path.exists(filename):
            return ""
        else:
            return hashlib.md5(open(filename, "rb").read()).hexdigest()

    def any_modified(self):
        for filename in self.hashes:
            if self.md5(filename) != self.hashes[filename]:
                return True
        return False

def resolve_etpro_url(etpro, suricata_version):
    mappings = {
        "code": etpro,
        "version": "",
    }

    mappings["version"] = "-%d.%d.%d" % (suricata_version.major,
                                      suricata_version.minor,
                                      suricata_version.patch)

    return ET_PRO_URL % mappings

def resolve_etopen_url(suricata_version):
    mappings = {
        "version": "",
    }

    mappings["version"] = "-%d.%d.%d" % (suricata_version.major,
                                         suricata_version.minor,
                                         suricata_version.patch)

    return ET_OPEN_URL % mappings

def ignore_file(ignore_files, filename):
    for pattern in ignore_files:
        if fnmatch.fnmatch(os.path.basename(filename), pattern):
            return True
    return False

def main():
    global args

    conf_filenames = [arg for arg in sys.argv if arg.startswith("@")]
    if not conf_filenames:
        if os.path.exists("./rulecat.conf"):
            logger.info("Loading ./rulecat.conf.")
            sys.argv.insert(1, "@./rulecat.conf")

    suricata_path = idstools.suricata.get_path()

    parser = argparse.ArgumentParser(fromfile_prefix_chars="@")
    parser.add_argument("-v", "--verbose", action="store_true", default=False,
                        help="Be more verbose")
    parser.add_argument("-t", "--temp-dir", default="/var/tmp/idstools-rulecat",
                        metavar="<directory>",
                        help="Temporary work directory")
    parser.add_argument("--suricata", default=suricata_path,
                        metavar="<path>",
                        help="Path to Suricata program (default: %s)" %
                        suricata_path)
    parser.add_argument("--suricata-version", metavar="<version>",
                        help="Override Suricata version")
    parser.add_argument("-f", "--force", action="store_true", default=False,
                        help="Force operations that might otherwise be skipped")
    parser.add_argument("--rules-dir", metavar="<directory>",
                        help=argparse.SUPPRESS)
    parser.add_argument("-o", "--output", metavar="<directory>",
                        dest="output", help="Output rules directory.")
    parser.add_argument("--merged", default=None, metavar="<filename>",
                        help="Output merged rules file")
    parser.add_argument("--yaml-fragment", metavar="<filename>",
                        help="Output YAML fragment for rule inclusion")
    parser.add_argument("--url", metavar="<url>", action="append",
                        default=[],
                        help="URL to use instead of auto-generating one")
    parser.add_argument("--local", metavar="<filename>", action="append",
                        default=[],
                        help="Local rule files or directories")
    parser.add_argument("--sid-msg-map", metavar="<filename>",
                        help="Generate a sid-msg.map file")
    parser.add_argument("--sid-msg-map-2", metavar="<filename>",
                        help="Generate a v2 sid-msg.map file")

    parser.add_argument("--disable", metavar="<filename>",
                        help="Filename of disable rule configuration")
    parser.add_argument("--enable", metavar="<filename>",
                        help="Filename of enable rule configuration")
    parser.add_argument("--modify", metavar="<filename>",
                        help="Filename of rule modification configuration")
    parser.add_argument("--drop", metavar="<filename>",
                        help="Filename of drop rules configuration")

    parser.add_argument("--ignore", metavar="<filename>", action="append",
                        default=[],
                        help="Filenames to ignore (default: *deleted.rules)")
    parser.add_argument("--no-ignore", action="store_true", default=False,
                        help="Disables the ignore option.")

    parser.add_argument("--threshold-in", metavar="<filename>",
                        help="Filename of rule thresholding configuration")
    parser.add_argument("--threshold-out", metavar="<filename>",
                        help="Output of processed threshold configuration")

    parser.add_argument("--dump-sample-configs", action="store_true",
                        default=False,
                        help="Dump sample config files to current directory")
    parser.add_argument("--etpro", metavar="<etpro-code>",
                        help="Use ET-Pro rules with provided ET-Pro code")
    parser.add_argument("--etopen", action="store_true",
                        help="Use ET-Open rules (default)")
    parser.add_argument("-q", "--quiet", action="store_true", default=False,
                       help="Be quiet, warning and error messages only")
    parser.add_argument("--post-hook", metavar="<command>",
                        help="Command to run after update if modified")
    parser.add_argument("-T", "--test-command", metavar="<command>",
                        help="Command to test Suricata configuration")
    parser.add_argument("-V", "--version", action="store_true", default=False,
                        help="Display version")

    args = parser.parse_args()

    if args.version:
        print("idstools-rulecat version %s" % idstools.version)
        return 0

    if args.verbose:
        logger.setLevel(logging.DEBUG)
    if args.quiet:
        logger.setLevel(logging.WARNING)

    logger.debug("This is idstools-rulecat version %s; Python: %s" % (
        idstools.version,
        sys.version.replace("\n", "- ")))

    if args.dump_sample_configs:
        return dump_sample_configs()

    # If --no-ignore was provided, make sure args.ignore is
    # empty. Otherwise if no ignores are provided, set a sane default.
    if args.no_ignore:
        args.ignore = []
    elif len(args.ignore) == 0:
        args.ignore.append("*deleted.rules")

    suricata_version = None

    if args.suricata_version:
        suricata_version = idstools.suricata.parse_version(args.suricata_version)
        if not suricata_version:
            logger.error("Failed to parse provided Suricata version: %s" % (
                suricata_version))
            return 1
        logger.info("Forcing Suricata version to %s." % (suricata_version.full))
    elif args.suricata and os.path.exists(args.suricata):
        suricata_version = idstools.suricata.get_version(args.suricata)
        if suricata_version:
            logger.info("Found Suricata version %s at %s." % (
                str(suricata_version.full), args.suricata))
        else:
            logger.warn("Failed to get Suricata version, using %s",
                        DEFAULT_SURICATA_VERSION)
    if suricata_version is None:
        suricata_version = idstools.suricata.parse_version(
            DEFAULT_SURICATA_VERSION)

    if args.etpro:
        args.url.append(resolve_etpro_url(args.etpro, suricata_version))
    if not args.url or args.etopen:
        args.url.append(resolve_etopen_url(suricata_version))
    args.url = set(args.url)

    file_tracker = FileTracker()

    disable_matchers = []
    enable_matchers = []
    modify_filters = []
    drop_filters = []

    if args.disable and os.path.exists(args.disable):
        disable_matchers += load_matchers(args.disable)
    if args.enable and os.path.exists(args.enable):
        enable_matchers += load_matchers(args.enable)
    if args.modify and os.path.exists(args.modify):
        modify_filters += load_filters(args.modify)
    if args.drop and os.path.exists(args.drop):
        drop_filters += load_drop_filters(args.drop)

    files = Fetch(args).run()

    # Remove ignored files.
    for filename in list(files.keys()):
        if ignore_file(args.ignore, filename):
            logger.info("Ignoring file %s" % (filename))
            del(files[filename])

    for path in args.local:
        load_local(path, files)

    rules = []
    for filename in files:
        if not filename.endswith(".rules"):
            continue
        logger.debug("Parsing %s." % (filename))
        rules += idstools.rule.parse_fileobj(
            io.BytesIO(files[filename]), filename)

    rulemap = build_rule_map(rules)
    logger.info("Loaded %d rules." % (len(rules)))

    # Counts of user enabled and modified rules.
    enable_count = 0
    modify_count = 0
    drop_count = 0

    # List of rules disabled by user. Used for counting, and to log
    # rules that are re-enabled to meet flowbit requirements.
    disabled_rules = []

    for key, rule in rulemap.items():

        for matcher in disable_matchers:
            if rule.enabled and matcher.match(rule):
                logger.debug("Disabling: %s" % (rule.brief()))
                rule.enabled = False
                disabled_rules.append(rule)

        for matcher in enable_matchers:
            if not rule.enabled and matcher.match(rule):
                logger.debug("Enabling: %s" % (rule.brief()))
                rule.enabled = True
                enable_count += 1

        for filter in drop_filters:
            if filter.match(rule):
                rulemap[rule.id] = filter.filter(rule)
                drop_count += 1

    # Apply modify filters.
    for fltr in modify_filters:
        for key, rule in rulemap.items():
            if fltr.match(rule):
                new_rule = fltr.filter(rule)
                if new_rule and new_rule.format() != rule.format():
                    rulemap[rule.id] = new_rule
                    modify_count += 1

    logger.info("Disabled %d rules." % (len(disabled_rules)))
    logger.info("Enabled %d rules." % (enable_count))
    logger.info("Modified %d rules." % (modify_count))
    logger.info("Dropped %d rules." % (drop_count))

    # Fixup flowbits.
    resolve_flowbits(rulemap, disabled_rules)

    if args.output:
        if not os.path.exists(args.output):
            logger.info("Making directory %s.", args.output)
            os.makedirs(args.output)
        for filename in files:
            file_tracker.add(
                os.path.join(args.output, os.path.basename(filename)))
        write_to_directory(args.output, files, rulemap)

    if args.merged:
        file_tracker.add(args.merged)
        write_merged(args.merged, rulemap)

    if args.yaml_fragment:
        file_tracker.add(args.yaml_fragment)
        write_yaml_fragment(args.yaml_fragment, files)

    if args.sid_msg_map:
        write_sid_msg_map(args.sid_msg_map, rulemap, version=1)
    if args.sid_msg_map_2:
        write_sid_msg_map(args.sid_msg_map_2, rulemap, version=2)

    if args.threshold_in and args.threshold_out:
        file_tracker.add(args.threshold_out)
        threshold_processor = ThresholdProcessor()
        threshold_processor.process(
            open(args.threshold_in), open(args.threshold_out, "w"), rulemap)

    if not args.force and not file_tracker.any_modified():
        logger.info(
            "No changes detected, will not reload rules or run post-hooks.")
        return 0

    if args.test_command:
        logger.info("Testing Suricata configuration with: %s" % (
            args.test_command))
        rc = subprocess.Popen(args.test_command, shell=True).wait()
        if rc != 0:
            logger.error("Suricata test failed, aborting.")
            return 1

    if args.post_hook:
        logger.info("Running %s." % (args.post_hook))
        subprocess.Popen(args.post_hook, shell=True).wait()

    logger.info("Done.")

    return 0

if __name__ == "__main__":
    sys.exit(main())
