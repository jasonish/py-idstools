from __future__ import print_function

import sys
import os
import time
import io

if sys.argv[0] == __file__:
    sys.path.insert(
        0, os.path.abspath(os.path.join(__file__, "..", "..")))

from idstools.rulecat import extract
from idstools import rule

def main():

    start = time.time()
    files = extract.extract_tar(
        os.path.join(os.path.dirname(__file__), "emerging.rules.tar.gz"))
    end = time.time()
    print("Extraction time: %.06f" % (end - start))

    start = time.time()
    rules = []
    for filename in files:
        if filename.endswith(".rules"):
            rules += rule.parse_fileobj(io.BytesIO(files[filename]))
    end = time.time()
    print("Parsed %d rules: time: %.06f" % (len(rules), end - start))

if __name__ == "__main__":
    sys.exit(main())
    
