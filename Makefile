#
# Makefile for ldr-utils
#
# Licensed under the GPL-2, see the file COPYING in this dir
#

cc-option = $(shell $(CC) $(CFLAGS) $(1) -S -o /dev/null -xc /dev/null \
              > /dev/null 2>&1 && echo "$(1)" || echo "$(2)")

WFLAGS  := $(call cc-option,-Wall,) $(call cc-option,-Wextra,)
CFLAGS  ?= -g -O0
CFLAGS  += $(WFLAGS)
LDFLAGS += $(CFLAGS)

DESTDIR :=
PREFIX  := /usr
BINDIR  := $(PREFIX)/bin

all: ldr

ldr: ldrviewer.o ldr.o helpers.o ldr_elf.o

.depend: $(wildcard *.c *.h)
	$(CC) $(CPPFLAGS) -MM *.c > .depend

INSTALL := install -g 0 -o 0
install:
	$(INSTALL) -m 755 -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 ldr $(DESTDIR)$(BINDIR)

clean:
	rm -f *.o *.gdb *.elf ldr

-include .depend

.PHONY: all clean install
