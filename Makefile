# No default for now.
all:

lint:
	pylint idstools

test:
	@nosetests

clean:
	find . -name \*.pyc -print0 | xargs -0 rm -f
	find . -name \*~ -print0 | xargs -0 rm -f
	find . -name __pycache__ -type d -print0 | xargs -0 rm -rf

# setup.py artifacts..
	rm -rf build dist MANIFEST

	cd doc && $(MAKE) clean
