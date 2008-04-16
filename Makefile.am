SUBDIRS = tests

EXTRA_DIST = HACKING

AM_CPPFLAGS = -DLOCALSTATEDIR=\"$(localstatedir)\"

bin_PROGRAMS = ldr
ldr_SOURCES = helpers.c ldr.c ldr_elf.c lfd.c lfd_bf527.c lfd_bf533.c lfd_bf537.c lfd_bf548.c lfd_bf561.c blackfin_defines.h dxe_jump.h dxes.h headers.h helpers.h ldr.h ldr_elf.h lfd.h
ldr_LDADD = $(LIB_PTHREAD)
