AC_INIT(ldr-utils, svn-1873, [vapier@blackfin.uclinux.org])
AM_INIT_AUTOMAKE([1.10 dist-bzip2 no-dist-gzip])
AC_CONFIG_HEADER(config.h)

AC_PROG_CC
AM_MISSING_PROG([AUTOM4TE], [autom4te])

AC_C_BIGENDIAN

AC_CHECK_HEADERS_ONCE([ \
assert.h \
ctype.h \
endian.h \
errno.h \
fcntl.h \
getopt.h \
libgen.h \
pthread.h \
signal.h \
stdbool.h \
stdint.h \
stdio.h \
string.h \
strings.h \
termios.h \
time.h \
unistd.h \
sys/endian.h \
sys/mman.h \
sys/stat.h \
sys/types.h \
sys/wait.h \
])

dnl
dnl for non-ELF systems, steal elf.h from local uClibc
dnl
AC_CHECK_HEADER([elf.h], , [
	if test -f "$ac_top_srcdir/../uClibc/include/elf.h" ; then
		dnl the DECLS stuff does not matter as all of our code is C
		sed \
			-e "/features.h/d" \
			-e "/__BEGIN_DECLS/d" \
			-e "/__END_DECLS/d" \
			"$ac_top_srcdir/../uClibc/include/elf.h" > "$ac_top_builddir/elf.h"
	else
		AC_MSG_ERROR([unable to locate a usable elf.h])
	fi
])

AC_CONFIG_TESTDIR([tests])

AC_OUTPUT([
Makefile
tests/atlocal
tests/Makefile
tests/package.m4
])
