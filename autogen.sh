#!/bin/bash

set -e -x

# force consistent sorting in generated files
# so we dont get pointless changes across builds
export LC_ALL=C

make distclean

# prep files for autotoolization
svn log > ChangeLog
topfiles=$(echo *.c *.h)
sed -i "/^ldr_SOURCES/s:=.*:= ${topfiles} \$(RC_SOURCES):" Makefile.am
ver=$(./local-version.sh)
sed -i "/^AC_INIT/s:\([^,]*,\)[^,]*:\1 ${ver}:" configure.ac
testatfiles=$(cd tests; echo *.at)
testfiles=$(cd tests; echo *.c *.in elfs/* ldrs/*)
sed -i \
	-e "/^EXTRA_DIST/s:=.*:= ${testfiles} \$(AT_FILES) \$(TESTSUITE):" \
	-e "/^AT_FILES/s:=.*:= ${testatfiles}:" \
	tests/Makefile.am

rm -f gnulib/lib/* gnulib/m4/*
PATH=/usr/local/src/gnu/gnulib:${PATH}
gnulib-tool --source-base=gnulib/lib --m4-base=gnulib/m4 --import printf-posix || :

autoreconf -f -i

# stupid automake bug
svn revert INSTALL || :

# update copyrights automatically
for f in $(grep -lI 'Copyright.*Analog Devices Inc.' `svn ls`) ; do
	year=$(svn info $f | awk '$0 ~ /^Last Changed Date:/ {print $4}' | cut -d- -f1)
	sed -i \
		-e "s:\(Copyright\) [-0-9]* \(Analog Devices Inc.\):\1 2006-${year} \2:" \
		${f}
done

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
