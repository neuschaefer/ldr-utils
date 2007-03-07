/*
 * File: helpers.c
 *
 * Copyright 2006-2007 Analog Devices Inc.
 * Licensed under the GPL-2, see the file COPYING in this dir
 *
 * Description:
 * some common utility functions
 */

#include "headers.h"
#include "helpers.h"

void *xmalloc(size_t size)
{
	void *ret = malloc(size);
	if (ret == NULL)
		errp("malloc(%zi) returned NULL!", size);
	return ret;
}

void *xrealloc(void *ptr, size_t size)
{
	void *ret = realloc(ptr, size);
	if (ret == NULL)
		errp("realloc(%p, %zi) returned NULL!", ptr, size);
	return ret;
}

char *xstrdup(const char *s)
{
	char *ret = strdup(s);
	if (ret == NULL)
		errp("strdup(%p) returned NULL!", s);
	return ret;
}

int parse_bool(const char *boo)
{
	if (strcmp(boo, "1") == 0 || strcasecmp(boo, "yes") == 0 ||	
	    strcasecmp(boo, "y") == 0 || strcasecmp(boo, "true") == 0)
		return 1;
	if (strcmp(boo, "0") == 0 || strcasecmp(boo, "no") == 0 ||
	    strcasecmp(boo, "n") == 0 || strcasecmp(boo, "false") == 0)
		return 0;
	err("Invalid boolean: '%s'", boo);
}

ssize_t read_retry(int fd, void *buf, size_t count)
{
	ssize_t ret = 0, temp_ret;
	while (count > 0) {
		temp_ret = read(fd, buf, count);
		if (temp_ret > 0) {
			ret += temp_ret;
			buf += temp_ret;
			count -= temp_ret;
		} else if (temp_ret == 0) {
			break;
		} else {
			if (errno == EINTR)
				continue;
			ret = -1;
			break;
		}
	}
	return ret;
}

/*
 * tty_speed_to_baud()
 * Annoying function for translating the termios baud representation
 * into the actual decimal value.
 */
static inline size_t tty_speed_to_baud(const speed_t speed)
{
	struct {
		speed_t s;
		size_t b;
	} speeds[] = {
		{B0, 0}, {B50, 50}, {B75, 75}, {B110, 110}, {B134, 134}, {B150, 150},
		{B200, 200}, {B300, 300}, {B600, 600}, {B1200, 1200}, {B1800, 1800},
		{B2400, 2400}, {B4800, 4800}, {B9600, 9600}, {B19200, 19200},
		{B38400, 38400}, {B57600, 57600}, {B115200, 115200}, {B230400, 230400}
	};
	size_t i;

	for (i = 0; i < sizeof(speeds)/sizeof(*speeds); ++i)
		if (speeds[i].s == speed)
			return speeds[i].b;

	return 0;
}

/*
 * tty_get_baud()
 * Helper function to return the baud rate the specified fd is running at.
 */
size_t tty_get_baud(const int fd)
{
	struct termios term;
	tcgetattr(fd, &term);
	return tty_speed_to_baud(cfgetispeed(&term));
}

/*
 * tty_init()
 * Make sure the tty we're going to be working with is properly setup.
 *  - make sure we are not running in ICANON mode
 *  - set speed to 115200 so transfers go fast
 */
#define DEFAULT_SPEED B115200 /*B57600*/
int tty_init(const int fd)
{
	struct termios term;
	if (verbose)
		printf("[getattr] ");
	if (tcgetattr(fd, &term))
		return 1;
	term.c_iflag &= ~(BRKINT | ICRNL);
	term.c_iflag |= (IGNBRK | IXOFF);
	term.c_oflag &= ~(OPOST | ONLCR);
	term.c_lflag &= ~(ISIG | ICANON | ECHO | IEXTEN);
	if (verbose)
		printf("[setattr] ");
	if (tcsetattr(fd, TCSANOW, &term))
		return 1;
	if (verbose)
		printf("[speed] ");
	if (cfgetispeed(&term) != DEFAULT_SPEED || cfgetospeed(&term) != DEFAULT_SPEED) {
		/* TODO: add a runtime switch for users to control this */
		if (cfsetispeed(&term, DEFAULT_SPEED) || cfsetospeed(&term, DEFAULT_SPEED))
			return 1;
		if (tcsetattr(fd, TCSANOW, &term))
			return 1;
	}
	return 0;
}

/*
 * _tty_get_lock_name()
 * Transform the specified tty path to its lock name.
 * Note: not reentrant by any means.
 */
static const char *_tty_get_lock_name(const char *tty)
{
	const char *base_tty;
	static char lockfile[1024];
	base_tty = strrchr(tty, '/');
	if (base_tty == NULL)
		base_tty = tty;
	else
		++base_tty;
	snprintf(lockfile, sizeof(lockfile), "/var/lock/LCK..%s", base_tty);
	return lockfile;
}

/*
 * tty_lock()
 * Try to lock the specified tty.
 */
int tty_lock(const char *tty)
{
	int fd, mask, ret = -1;
	FILE *fp;
	const char *lockfile = _tty_get_lock_name(tty);

	/* first see if it's stale */
	fp = fopen(lockfile, "r");
	if (fp != NULL) {
		unsigned long pid;
		if (fscanf(fp, "%lu", &pid) == 1) {
			if (kill(pid, 0) == -1 && errno == ESRCH) {
				if (!quiet)
					printf("Removing stale lock '%s'\n", lockfile);
				unlink(lockfile);
			} else if (verbose)
				printf("TTY '%s' is locked by pid '%lu'\n", tty, pid);
		}
		fclose(fp);
	}

	/* now create a new lock and write our pid into it */
	mask = umask(022);
	fd = open(lockfile, O_WRONLY | O_CREAT | O_EXCL, 0666);
	umask(mask);
	if (fd != -1) {
		fp = fdopen(fd, "w");
		if (fp != NULL) {
			fprintf(fp, "%lu\n", (unsigned long)getpid());
			fclose(fp);
			ret = 0;
		}
		close(fd);
	}
	return ret;
}

/*
 * tty_unlock()
 * Unlock the specified tty.
 * TODO: maybe make sure this lock belongs to us ?
 */
int tty_unlock(const char *tty)
{
	const char *lockfile = _tty_get_lock_name(tty);
	return unlink(lockfile);
}
