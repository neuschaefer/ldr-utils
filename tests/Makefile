AUTOM4TE = autom4te
AUTOTEST = $(AUTOM4TE) --language=autotest

PACKAGE_NAME      = ldr-utils
PACKAGE_TARNAME   = $(PACKAGE_NAME)
PACKAGE_VERSION   = svn $(shell svn info .. | sed -n '/^Last Changed Rev/s|^.*: ||p')
PACKAGE_STRING    = $(PACKAGE_NAME) $(PACKAGE_VERSION)
PACKAGE_BUGREPORT = toolchain-devel@blackfin.uclinux.org

export builddir = $(shell echo $$PWD)
export top_builddir = $(builddir)/..
export srcdir = $(builddir)
export top_srcdir = $(top_builddir)

all: check

package.m4: Makefile
	( \
	echo 'm4_define([AT_PACKAGE_NAME],      [$(PACKAGE_NAME)])'; \
	echo 'm4_define([AT_PACKAGE_TARNAME],   [$(PACKAGE_TARNAME)])'; \
	echo 'm4_define([AT_PACKAGE_VERSION],   [$(PACKAGE_VERSION)])'; \
	echo 'm4_define([AT_PACKAGE_STRING],    [$(PACKAGE_STRING)])'; \
	echo 'm4_define([AT_PACKAGE_BUGREPORT], [$(PACKAGE_BUGREPORT)])'; \
	) > package.m4

testsuite: package.m4 $(wildcard *.at */*.at)
	$(AUTOTEST) -o $@.tmp $@.at
	mv $@.tmp $@

check test: testsuite
	./testsuite

install:

clean:
	rm -rf testsuite.dir testsuite.log

distclean: clean
	rm -rf package.m4 testsuite testsuite.m4

.PHONY: all check clean distclean install test
