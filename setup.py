import os
import os.path
import shutil

from setuptools import setup

import idstools

if not os.path.exists("build/_bin"):
    os.makedirs("build/_bin")
scripts = [
    "gensidmsgmap",
    "u2fast",
    "u2json",
]
for script in scripts:
    shutil.copy(
        "bin/%s" % (script),
        "build/_bin/idstools-%s" % (script))

setup(
    name="idstools",
    version=idstools.version,
    description="IDS Utility Library",
    author="Jason Ish",
    author_email="ish@unx.ca",
    packages=[
        "idstools",
        "idstools.scripts"
    ],
    url="https://github.com/jasonish/py-idstools",
    license="BSD",
    classifiers=[
        'License :: OSI Approved :: BSD License',
    ],
    scripts = ["build/_bin/idstools-%s" % script for script in scripts],
)
