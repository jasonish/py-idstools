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

from __future__ import print_function

import sys
import os.path
import argparse
import string
import re
import logging

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..", "..")))

import idstools.rule
import idstools.scripts.rulecat

logging.basicConfig(
    level=logging.getLevelName(os.environ.get("RULECAT_LOG_LEVEL", "INFO")),
    format="%(levelname)s: %(message)s")
logger = logging.getLogger()

def match_all(matchers, rule):
    for matcher in matchers:
        if not matcher.match(rule):
            return False
    return True

def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--inplace", action="store_true", default=False,
        help="Modify files in place")
    parser.add_argument(
        "--print", action="store_true", default=False,
        help="Print modified rules to stdout")

    parser.add_argument("--re", help="Regex of rules to match.")

    parser.add_argument(
        "--remove-option", action="append", default=[],
        help="Name of option to remove from matching rules")

    parser.add_argument(
        "--add-option", action="append", default=[],
        help="Add option to matching rules")

    parser.add_argument("files", nargs="+")

    args = parser.parse_args()

    matchers = []

    if args.re:
        matcher = idstools.scripts.rulecat.ReRuleMatcher(
            re.compile(args.re, re.I))
        matchers.append(matcher)

    if not matchers:
        logger.error("no matchers specified")
        return 1

    for filename in args.files:
        
        content = []

        with open(filename) as fileobj:
            for line in fileobj:
                rule = idstools.rule.parse(line, filename)
                if not rule:
                    content.append(line)
                    continue

                if not match_all(matchers, rule):
                    continue

                for option in args.remove_option:
                    rule = idstools.rule.remove_option(rule, option)

                for option in args.add_option:
                    try:
                        name, val = option.split(":", 1)
                    except:
                        name = option
                        val = None
                    rule = idstools.rule.add_option(rule, name, val)

                content.append(str(rule) + "\n")

                if args.print:
                    print("%s" % (str(rule)))

        if args.inplace:
            open(filename, "wb").write("".join(content))

    return 0

if __name__ == "__main__":
    sys.exit(main())
