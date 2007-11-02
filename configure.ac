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
pty.h \
signal.h \
stdbool.h \
stdint.h \
stdio.h \
string.h \
strings.h \
termios.h \
time.h \
unistd.h \
util.h \
sys/endian.h \
sys/mman.h \
sys/stat.h \
sys/types.h \
sys/wait.h \
])

AC_CHECK_LIB([util], [openpty], [PTY_LIB="-lutil"], [PTY_LIB=""])
AC_SUBST([PTY_LIB])

dnl
dnl for non-ELF systems, steal elf.h from local uClibc
dnl
AC_CHECK_HEADER([elf.h], [
	AC_DEFINE([HAVE_ELF_H], [1], [Define to 1 if you have a <elf.h> header file.])
],[
	if test -f "$srcdir/../uClibc/include/elf.h" ; then
		dnl the DECLS stuff does not matter as all of our code is C
		sed \
			-e "/features.h/d" \
			-e "/__BEGIN_DECLS/d" \
			-e "/__END_DECLS/d" \
			"$srcdir/../uClibc/include/elf.h" > elf.h
	else
		AC_MSG_ERROR([unable to locate a usable elf.h])
	fi
	AC_DEFINE([HAVE_LOCAL_ELF_H], [1], [Define to 1 if you have a local "elf.h" header file.])
])

AC_CONFIG_TESTDIR([tests])

if test "$GCC" = yes; then
	CFLAGS="$CFLAGS -Wall"
fi
#if test "$USER" = vapier; then
#	CFLAGS="$CFLAGS -Werror"
#fi

AC_OUTPUT([
Makefile
tests/atlocal
tests/Makefile
tests/package.m4
])
