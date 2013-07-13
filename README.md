# idstools.py

idstools.py is a collection of Python libraries for working with IDS
systems (typically Snort and Suricata).

## Example Programs

Example programs are found in the examples/ directory and demonstrate
basic usage of the idstools libraries.

### u2spewfoo.py

u2spewfoo.py is a Python program similar to u2spewfoo provided by
Snort. It reads and prints records from one or more unified2 log
files.

usage: python ./examples/u2spewfoo.py <file1> [file2 ...]

### u2fast.py

u2fast.py reads unified2 log files and prints out events in the "fast"
format.

usage: python ./examples/u2fast.py \
       	      -C /path/to/classification.config \
	      -S /path/to/sid-msg.map \
	      -G /path/to/gen-msg.map
