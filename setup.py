try:
    from setuptools import setup
except:
    print("Error importing setuptools, will use distutils.")
    print("- Script entry points will not be installed.")
    from distutils import setup

setup(name="idstools",
      version="0.1.1",
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
          ]
      },
      )
