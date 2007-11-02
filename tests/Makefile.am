EXTRA_DIST = fake-loadee.c atlocal.in Makefile.in package.m4.in elfs/bad.elf elfs/bss.elf elfs/POST.dxe elfs/section.elf ldrs/bf548.ldr ldrs/spi.ldr ldrs/uart.ldr $(AT_FILES) $(TESTSUITE)
AT_FILES = create.at dump.at load.at local.at show.at testsuite.at usage.at
TESTSUITE = $(srcdir)/testsuite

noinst_PROGRAMS = fake-loadee
fake_loadee_LDADD = -lutil

check-local: atlocal fake-loadee $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' $(TESTSUITEFLAGS)

installcheck-local: atlocal fake-loadee $(TESTSUITE)
	$(SHELL) '$(TESTSUITE)' AUTOTEST_PATH='$(bindir)' $(TESTSUITEFLAGS)

clean-local:
	test ! -f '$(TESTSUITE)' || \
		$(SHELL) '$(TESTSUITE)' --clean

AUTOTEST = $(AUTOM4TE) --language=autotest
$(TESTSUITE): $(AT_FILES)
	$(AUTOTEST) -I '$(srcdir)' -o $@.tmp $@.at
	mv $@.tmp $@
