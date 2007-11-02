AC_INIT(ldr-utils, svn-1866, [vapier@blackfin.uclinux.org])
AM_INIT_AUTOMAKE([1.10 dist-bzip2 no-dist-gzip])
AC_CONFIG_HEADER(config.h)

AC_PROG_CC
AM_MISSING_PROG([AUTOM4TE], [autom4te])

AC_CHECK_HEADERS([ \
assert.h \
ctype.h \
elf.h \
endian.h \
errno.h \
fcntl.h \
features.h \
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

AC_CONFIG_TESTDIR

AC_OUTPUT([
Makefile
tests/atlocal
tests/Makefile
tests/package.m4
])
