from setuptools import setup

import idstools

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
        "idstools.ruleman",
        "idstools.ruleman.commands",
    ],
    url="https://github.com/jasonish/py-idstools",
    license="BSD",
    classifiers=[
        'License :: OSI Approved :: BSD License',
    ],
    scripts = [
        "bin/idstools-gensidmsgmap",
        "bin/idstools-u2fast",
        "bin/idstools-u2json",
        "bin/idstools-ruleman",
    ],
)
