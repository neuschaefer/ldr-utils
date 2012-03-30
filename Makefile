#
# Makefile for ldr-utils
#
# Licensed under the GPL-2, see the file COPYING in this dir
#

cc-option = $(shell $(CC) $(CFLAGS) $(1) -S -o /dev/null -xc /dev/null \
              > /dev/null 2>&1 && echo "$(1)" || echo "$(2)")

WFLAGS   := $(call cc-option,-Wall,) $(call cc-option,-Wextra,)
CFLAGS   ?= -g -O0
CFLAGS   += $(WFLAGS)
CPPFLAGS += -D_GNU_SOURCE
LDFLAGS  += $(CFLAGS) -rdynamic
LDLIBS   += -lpthread

PKG_CONFIG ?= pkg-config
CPPFLAGS   += $(shell $(PKG_CONFIG) --cflags libusb-1.0)
LDFLAGS    += $(shell $(PKG_CONFIG) --libs libusb-1.0)

DESTDIR :=
PREFIX  := /usr
BINDIR  := $(PREFIX)/bin

ifneq ($(wildcard ../uClibc/include/elf.h),)
CPPFLAGS += -I.
$(shell ln -sf ../uClibc/include/elf.h)
endif

all: ldr

ldr: ldr.o helpers.o ldr_elf.o \
	$(patsubst %.c,%.o,$(wildcard lfd*.c))

.depend: $(wildcard *.c *.h)
	-$(CC) $(CPPFLAGS) -MM *.c > .depend

INSTALL := install -g 0 -o 0
install:
	$(INSTALL) -m 755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 ldr $(DESTDIR)$(BINDIR)

check test: ldr
	$(MAKE) -C tests $@

clean:
	rm -f *.o *.gdb *.elf ldr elf.h
	$(MAKE) -C tests $@

distclean: clean
	$(MAKE) -C tests $@

-include .depend

.PHONY: all autotools check clean distclean install test
