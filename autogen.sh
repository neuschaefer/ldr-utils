#!/bin/bash

set -e -x

# force consistent sorting in generated files
# so we dont get pointless changes across builds
export LC_ALL=C

make distclean

# prep files for autotoolization
svn log > ChangeLog
topfiles=$(echo *.c *.h)
sed -i "/^ldr_SOURCES/s:=.*:= ${topfiles}:" Makefile.am
ver=$(./local-version.sh)
sed -i "/^AC_INIT/s:\([^,]*,\)[^,]*:\1 ${ver}:" configure.ac
testatfiles=$(cd tests; echo *.at)
testfiles=$(cd tests; echo *.c *.in elfs/* ldrs/*)
sed -i \
	-e "/^EXTRA_DIST/s:=.*:= ${testfiles} \$(AT_FILES) \$(TESTSUITE):" \
	-e "/^AT_FILES/s:=.*:= ${testatfiles}:" \
	tests/Makefile.am

autoreconf -f -i

# stupid automake bug
svn revert INSTALL || :

# test building
if [ -d build ] ; then
	chmod -R 777 build
	rm -rf build
fi
mkdir build
cd build
../configure
make
make check
make dist
make distcheck