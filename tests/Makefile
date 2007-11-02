AUTOM4TE = autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest

PACKAGE_NAME      = ldr-utils
PACKAGE_TARNAME   = $(PACKAGE_NAME)
PACKAGE_VERSION   = $(shell ../local-version.sh)
PACKAGE_STRING    = $(PACKAGE_NAME) $(PACKAGE_VERSION)
PACKAGE_BUGREPORT = toolchain-devel@blackfin.uclinux.org

export abs_builddir = $(shell echo $$PWD)
export abs_top_builddir = $(abs_builddir)/..
export abs_srcdir = $(abs_builddir)
export abs_top_srcdir = $(abs_top_builddir)

CFLAGS ?= -g -O2
CFLAGS += -Wall
CPPFLAGS += -I$(abs_top_srcdir)

all: check

atlocal: Makefile atlocal.in
	cp atlocal.in atlocal

atconfig: Makefile
	rm -f atconfig.tmp
	set -e ; \
	for v in abs_builddir abs_top_builddir abs_srcdir abs_top_srcdir ; do \
		val=`eval echo \\$$$${v}` ; \
		echo "$$v=$$val" >> atconfig.tmp ; \
	done
	cmp -s atconfig atconfig.tmp || mv atconfig.tmp atconfig
	rm -f atconfig.tmp

package.m4: Makefile package.m4.in
	sed \
		-e 's:@PACKAGE_NAME@:$(PACKAGE_NAME):g' \
		-e 's:@PACKAGE_TARNAME@:$(PACKAGE_TARNAME):g' \
		-e 's:@PACKAGE_VERSION@:$(PACKAGE_VERSION):g' \
		-e 's:@PACKAGE_STRING@:$(PACKAGE_STRING):g' \
		-e 's:@PACKAGE_BUGREPORT@:$(PACKAGE_BUGREPORT):g' \
		package.m4.in > package.m4

TEST_PROGS = fake-loadee
fake-loadee: LDLIBS += -lutil

testsuite: atconfig atlocal package.m4 $(wildcard *.at */*.at)
	$(AUTOTEST) -o $@.tmp $@.at
	mv $@.tmp $@

check test: testsuite $(TEST_PROGS)
	./testsuite

install:

clean:
	rm -rf testsuite.dir testsuite.log $(TEST_PROGS)

distclean: clean
	rm -rf package.m4 testsuite testsuite.m4

.PHONY: all check clean distclean install test
