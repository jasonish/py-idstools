import os.path
import shutil

from setuptools import setup

import idstools

scripts = [
    "gensidmsgmap",
    "u2fast",
    "u2json",
]
for script in scripts:
    src = os.path.join("bin", script)
    if os.path.exists(src):
        dst = os.path.join("bin", "idstools-%s" % (script))
        shutil.copy(src, dst)

setup(
    name="idstools",
    version=idstools.version,
    description="IDS Utility Library",
    author="Jason Ish",
    author_email="ish@unx.ca",
    packages=[
        "idstools",
        "idstools.scripts",
        "idstools.compat",
        "idstools.compat.argparse",
    ],
    url="https://github.com/jasonish/py-idstools",
    license="BSD",
    classifiers=[
        'License :: OSI Approved :: BSD License',
    ],
    scripts = ["bin/idstools-%s" % script for script in scripts],
)
