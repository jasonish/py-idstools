#! /usr/bin/env python
#
# Rule File Parsing Example

import sys

from idstools import rule

# For each rule in a rule file, print:
#     [GENERATOR_ID:SIGNATURE_ID:REVISION] RULE_MSG
for rule in rule.parse_file(sys.argv[1]):
    print("[%d:%d:%d] %s" % (
        rule.gid, rule.sid, rule.rev, rule.msg))
    
