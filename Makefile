# No default for now.
all:

clean:
	find . -name \*.pyc -print0 | xargs -0 rm -f
	find . -name \*~ -print0 | xargs -0 rm -f

# setup.py artifacts..
	rm -rf build dist MANIFEST
