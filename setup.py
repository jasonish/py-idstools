try:
    from setuptools import setup
except:
    print("Error importing setuptools, will use distutils.")
    print("- Script entry points will not be installed.")
    from distutils import setup

import idstools

setup(name="idstools",
      version=idstools.version,
      description="IDS Utility Library",
      author="Jason Ish",
      author_email="ish@unx.ca",
      packages=["idstools", "idstools.scripts"],
      url="https://github.com/jasonish/idstools.py",
      classifiers=[
        'License :: OSI Approved :: BSD License',
        ],
      entry_points = {
          'console_scripts': [
              'idstools-gensidmsgmap = idstools.scripts.gensidmsgmap:main',
              'idstools-u2fast = idstools.scripts.u2fast:main',
          ]
      },
      )
