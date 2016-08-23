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

""" Module for parsing Snort-like rules.

Parsing is done using regular expressions and the job of this module
is to do its best at parsing out fields of interest from the rule
rather than perform a sanity check.

The methods that parse multiple rules for a provided input
(parse_file, parse_fileobj) return a list of rules instead of dict
keyed by ID as its not the job of this module to detect or deal with
duplicate signature IDs.
"""

from __future__ import print_function

import sys
import re
import logging

logger = logging.getLogger(__name__)

# Rule actions we expect to see.
actions = (
    "alert", "log", "pass", "activate", "dynamic", "drop", "reject", "sdrop")

# Compiled regular expression to detect a rule and break out some of
# its parts.
rule_pattern = re.compile(
    r"^(?P<enabled>#)*\s*"      # Enabled/disabled
    r"(?P<raw>"
    r"(?P<action>%s)\s*"        # Action
    r"[^\s]*\s*"                # Protocol
    r"[^\s]*\s*"                # Source address(es)
    r"[^\s]*\s*"                # Source port
    r"(?P<direction>[-><]+)\s*"	# Direction
    r"[^\s]*\s*"		        # Destination address(es)
    r"[^\s]*\s*"                # Destination port
    r"\((?P<options>.*)\)\s*" 	# Options
    r")"
    % "|".join(actions))

# Another compiled pattern to detect preprocessor rules.  We could
# construct the general rule re to pick this up, but its much faster
# this way.
decoder_rule_pattern = re.compile(
    r"^(?P<enabled>#)*\s*"	# Enabled/disabled
    r"(?P<raw>"
    r"(?P<action>%s)\s*"	# Action
    r"\((?P<options>.*)\)\s*" 	# Options
    r")"
    % "|".join(actions))

# Regular expressions to pick out options.
option_patterns = (
    re.compile("(msg)\s*:\s*\"(.*?)\";"),
    re.compile("(gid)\s*:\s*(\d+);"),
    re.compile("(sid)\s*:\s*(\d+);"),
    re.compile("(rev)\s*:\s*(\d+);"),
    re.compile("(metadata)\s*:\s*(.*?);"),
    re.compile("(flowbits)\s*:\s*(.*?);"),
    re.compile("(reference)\s*:\s*(.*?);"),
    re.compile("(classtype)\s*:\s*(.*?);"),
    re.compile("(priority)\s*:\s*(.*?);"),
)

class Rule(dict):
    """ Class representing a rule.

    The Rule class is a class that also acts like a dictionary.

    Dictionary fields:

    - **group**: The group the rule belongs to, typically the filename.

    - **enabled**: True if rule is enabled (uncommented), False is
        disabled (commented)

    - **action**: The action of the rule (alert, pass, etc) as a
        string

    - **direction**: The direction string of the rule.

    - **gid**: The gid of the rule as an integer

    - **sid**: The sid of the rule as an integer

    - **rev**: The revision of the rule as an integer

    - **msg**: The rule message as a string

    - **flowbits**: List of flowbit options in the rule

    - **metadata**: Metadata values as a list

    - **references**: References as a list

    - **classtype**: The classification type

    - **priority**: The rule priority, 0 if not provided

    - **raw**: The raw rule as read from the file or buffer

    :param enabled: Optional parameter to set the enabled state of the rule
    :param action: Optional parameter to set the action of the rule
    """

    def __init__(self, enabled=None, action=None, group=None):
        dict.__init__(self)
        self["enabled"] = enabled
        self["action"] = action
        self["direction"] = None
        self["group"] = group
        self["gid"] = 1
        self["sid"] = None
        self["rev"] = None
        self["msg"] = None
        self["flowbits"] = []
        self["metadata"] = []
        self["references"] = []
        self["classtype"] = None
        self["priority"] = 0
        self["raw"] = None

    def __getattr__(self, name):
        return self[name]

    @property
    def id(self):
        """ The ID of the rule.

        :returns: A tuple (gid, sid) representing the ID of the rule
        :rtype: A tuple of 2 ints
        """
        return (int(self.gid), int(self.sid))

    @property
    def idstr(self):
        return "[%s:%s]" % (str(self.gid), str(self.sid))

    def brief(self):
        """ A brief description of the rule.

        :returns: A brief description of the rule
        :rtype: string
        """
        return "%s[%d:%d] %s" % (
            "" if self.enabled else "# ", self.gid, self.sid, self.msg)

    def __hash__(self):
        return self["raw"].__hash__()

    def __str__(self):
        """ The string representation of the rule.

        If the rule is disabled it will be returned as commented out.
        """
        return "%s%s" % ("" if self.enabled else "# ", self.raw)

def parse(buf, group=None):
    """ Parse a single rule for a string buffer.

    :param buf: A string buffer containing a single Snort-like rule

    :returns: An instance of of :py:class:`.Rule` representing the parsed rule
    """
    m = rule_pattern.match(buf) or decoder_rule_pattern.match(buf)
    if not m:
        return

    rule = Rule(enabled=True if m.group("enabled") is None else False,
                action=m.group("action"),
                group=group)

    rule["direction"] = m.groupdict().get("direction", None)

    options = m.group("options")
    for p in option_patterns:
        for opt, val in p.findall(options):
            if opt in ["gid", "sid", "rev"]:
                rule[opt] = int(val)
            elif opt == "metadata":
                rule[opt] = [v.strip() for v in val.split(",")]
            elif opt == "flowbits":
                rule.flowbits.append(val)
            elif opt == "reference":
                rule.references.append(val)
            else:
                rule[opt] = val

    if rule["msg"] is None:
        logger.warn("Rule has no \"msg\": %s" % (buf.strip()))
        rule["msg"] = ""

    rule["raw"] = m.group("raw").strip()

    return rule

def parse_fileobj(fileobj, group=None):
    """ Parse multiple rules from a file like object.

    Note: At this time rules must exist on one line.

    :param fileobj: A file like object to parse rules from.

    :returns: A list of :py:class:`.Rule` instances, one for each rule parsed
    """
    rules = []
    buf = ""
    for line in fileobj:
        try:
            if type(line) == type(b""):
                line = line.decode()
        except:
            pass
        if line.rstrip().endswith("\\"):
            buf = "%s%s " % (buf, line.rstrip()[0:-1])
            continue
        try:
            rule = parse(buf + line, group)
            if rule:
                rules.append(rule)
        except:
            logger.error("failed to parse rule: %s" % (buf))
            raise
        buf = ""
    return rules

def parse_file(filename, group=None):
    """ Parse multiple rules from the provided filename.

    :param filename: Name of file to parse rules from

    :returns: A list of :py:class:`.Rule` instances, one for each rule parsed
    """
    with open(filename) as fileobj:
        return parse_fileobj(fileobj, group)

class FlowbitResolver(object):

    setters = ["set", "setx", "unset", "toggle"]
    getters = ["isset", "isnotset"]

    def __init__(self):
        self.enabled = []

    def resolve(self, rules):
        required = self.get_required_flowbits(rules)
        enabled = self.set_required_flowbits(rules, required)
        if enabled:
            self.enabled += enabled
            return self.resolve(rules)
        return self.enabled

    def set_required_flowbits(self, rules, required):
        enabled = []
        for rule in [rule for rule in rules.values() if not rule.enabled]:
            for option, value in map(self.parse_flowbit, rule.flowbits):
                if option in self.setters and value in required:
                    rule.enabled = True
                    enabled.append(rule)
        return enabled

    def get_required_rules(self, rulemap, flowbits, include_enabled=False):
        """Returns a list of rules that need to be enabled in order to satisfy
        the list of required flowbits.

        """
        required = []

        for rule in [rule for rule in rulemap.values()]:
            for option, value in map(self.parse_flowbit, rule.flowbits):
                if option in self.setters and value in flowbits:
                    if rule.enabled and not include_enabled:
                        continue
                    required.append(rule)

        return required

    def get_required_flowbits(self, rules):
        required_flowbits = set()
        for rule in [rule for rule in rules.values() if rule.enabled]:
            for option, value in map(self.parse_flowbit, rule.flowbits):
                if option in self.getters:
                    required_flowbits.add(value)
        return required_flowbits

    def parse_flowbit(self, flowbit):
        tokens = flowbit.split(",", 1)
        if len(tokens) == 1:
            return tokens[0], None
        elif len(tokens) == 2:
            return tokens[0], tokens[1]
        else:
            raise Exception("Flowbit parse error on %s" % (flowbit))

def enable_flowbit_dependencies(rulemap):
    """Helper function to resolve flowbits, wrapping the FlowbitResolver
    class. """
    resolver = FlowbitResolver()
    return resolver.resolve(rulemap)

def format_sidmsgmap(rule):
    """ Format a rule as a sid-msg.map entry. """
    try:
        return " || ".join([str(rule.sid), rule.msg] + rule.references)
    except:
        logger.error("Failed to format rule as sid-msg.map: %s" % (str(rule)))
        return None

def format_sidmsgmap_v2(rule):
    """ Format a rule as a v2 sid-msg.map entry.

    eg:
    gid || sid || rev || classification || priority || msg || ref0 || refN
    """
    try:
        return " || ".join([
            str(rule.gid), str(rule.sid), str(rule.rev),
            "NOCLASS" if rule.classtype is None else rule.classtype,
            str(rule.priority), rule.msg] + rule.references)
    except:
        logger.error("Failed to format rule as sid-msg-v2.map: %s" % (
            str(rule)))
        return None
