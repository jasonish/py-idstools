.PHONY: doc

# No default for now.
all: build

build:
	python setup.py build

install:
	python setup.py install

lint:
	pylint idstools

tox:
	@if ! which tox 2>&1 > /dev/null; then \
		echo "error: tox required to run tests"; \
		exit 1; \
	fi

test: tox
	@tox

clean:
	find . -name \*.pyc -print0 | xargs -0 rm -f
	find . -name \*~ -print0 | xargs -0 rm -f
	find . -name __pycache__ -type d -print0 | xargs -0 rm -rf
	rm -rf idstools.egg*
	rm -rf build dist MANIFEST
	cd doc && $(MAKE) clean

doc:
	cd doc && $(MAKE) clean html

sdist:
	python setup.py sdist

sdist-upload:
	python setup.py sdist upload
