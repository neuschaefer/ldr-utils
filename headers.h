/*
 * File: helpers.h
 *
 * Copyright 2006-2007 Analog Devices Inc.
 * Licensed under the GPL-2, see the file COPYING in this dir
 *
 * Description:
 * I'm too lazy to update headers in multiple files ...
 * just move all that crap here ;)
 */

#ifndef __HEADERS_H__
#define __HEADERS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>
#include <termios.h>
#include <sys/stat.h>
#include <libgen.h>
#include <elf.h>
#include <sys/mman.h>
#include <sys/wait.h>

#if defined(__linux__)
# include <endian.h>
#elif defined(__FreeBSD__)
# include <sys/endian.h>
#endif

#ifndef BYTE_ORDER
# error unable to detect endian
#endif
#if BYTE_ORDER != BIG_ENDIAN && BYTE_ORDER != LITTLE_ENDIAN
# error unknown endian
#endif

#if !defined(bswap_16)
# if defined(bswap16)
#  define bswap_16 bswap16
#  define bswap_32 bswap32
# else
#  define bswap_16(x) \
			((((x) & 0xff00) >> 8) | \
			 (((x) & 0x00ff) << 8))
#  define bswap_32(x) \
			((((x) & 0xff000000) >> 24) | \
			 (((x) & 0x00ff0000) >>  8) | \
			 (((x) & 0x0000ff00) <<  8) | \
			 (((x) & 0x000000ff) << 24))
# endif
#endif

#if BYTE_ORDER == BIG_ENDIAN
# define ldr_make_little_endian_16(x) (x) = bswap_16(x)
# define ldr_make_little_endian_32(x) (x) = bswap_32(x)
#elif BYTE_ORDER == LITTLE_ENDIAN
# define ldr_make_little_endian_16(x)
# define ldr_make_little_endian_32(x)
#endif

#ifndef ELF_DATA
# if BYTE_ORDER == BIG_ENDIAN
#  define ELF_DATA ELFDATA2MSB
# elif BYTE_ORDER == LITTLE_ENDIAN
#  define ELF_DATA ELFDATA2LSB
# endif
#endif

#endif
