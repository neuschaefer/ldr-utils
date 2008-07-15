SUBDIRS = gnulib/lib tests

EXTRA_DIST = HACKING

ACLOCAL_AMFLAGS = -I gnulib/m4
AM_CPPFLAGS = -DLOCALSTATEDIR=\"$(localstatedir)\"

bin_PROGRAMS = ldr
if USE_RC_SOURCES
RC_SOURCES = icon.rc
else
RC_SOURCES =
endif
ldr_SOURCES = helpers.c ldr.c ldr_elf.c lfd.c lfd_bf527.c lfd_bf533.c lfd_bf537.c lfd_bf548.c lfd_bf561.c termios-mingw.c blackfin_defines.h dxe_jump.h dxes.h headers.h helpers.h ldr.h ldr_elf.h lfd.h link-warning.h $(RC_SOURCES)
ldr_LDADD = $(LIB_PTHREAD)

.rc.o:
	$(WINDRES) -I $(srcdir) $< -o $@
%.o : %.rc
	$(WINDRES) -I $(srcdir) $< -o $@
