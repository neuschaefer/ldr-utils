/*
 * File: helpers.h
 *
 * Copyright 2006-2007 Analog Devices Inc.
 * Licensed under the GPL-2, see the file COPYING in this dir
 *
 * Description:
 * some common utility functions
 */

#ifndef __HELPERS_H__
#define __HELPERS_H__

#include "headers.h"

#ifndef VERSION
# define VERSION "cvs"
#endif

extern int force, verbose, quiet;

extern const char *argv0;

#define warn(fmt, args...) \
	fprintf(stderr, "%s: " fmt "\n", argv0 , ## args) 
#define warnf(fmt, args...) warn("%s(): " fmt, __FUNCTION__ , ## args)
#define warnp(fmt, args...) warn(fmt ": %s" , ## args , strerror(errno))
#define _err(wfunc, fmt, args...) \
	do { \
		wfunc(fmt, ## args); \
		exit(EXIT_FAILURE); \
	} while (0)
#define err(fmt, args...) _err(warn, fmt, ## args)
#define errf(fmt, args...) _err(warnf, fmt, ## args)
#define errp(fmt, args...) _err(warnp, fmt , ## args)


void *xmalloc(size_t);
void *xrealloc(void *, size_t);
char *xstrdup(const char *);
int parse_bool(const char *);
ssize_t read_retry(int, void *, size_t);

size_t tty_get_baud(const int);
int tty_init(const int, const size_t);
int tty_lock(const char *);
int tty_unlock(const char *);

#endif
