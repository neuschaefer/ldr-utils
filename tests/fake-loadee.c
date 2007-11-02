/*
 * create a fake tty for `ldr` to load into and
 * read this data back out to make sure the ldr
 * loaded and the data sent are the same.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pty.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

pid_t child;
int status = -1;

void child_exited(int sig)
{
	/* see if the child bombed */
	waitpid(child, &status, 0);
	status = WEXITSTATUS(status);
	if (status) {
		fprintf(stderr, "ERROR: child exited with %i\n", status);
		_exit(status);
	}
}

int main(int argc, char *argv[])
{
	int master, slave;
	char *buf;
	int ret, i;
	FILE *fp;

	/* the fake tty to load into */
	ret = openpty(&master, &slave, NULL, NULL, NULL);
	assert(ret == 0);

	/* output file representing the data loaded into the tty */
	fp = fopen("load.ldr", "w+");
	assert(fp != NULL);

	/* recreate args to run `ldr` */
	for (i = 1; i < argc; ++i)
		argv[i-1] = argv[i];
	argv[argc-1] = malloc(10);
	sprintf(argv[argc-1], "#%i", slave);

	/* spawn the ldr prog and catch it exiting */
	signal(SIGCHLD, child_exited);

	child = vfork();
	if (!child) {
		int ret = execvp(argv[0], argv);
		fprintf(stderr, "ERROR: failed to execv(\"%s\"): %s\n", argv[0], strerror(errno));
		_exit(ret);
	}

	/* wait for the autobaud char */
	buf = malloc(4);
	ret = read(master, buf, 1);
	if (ret <= 0)
		return 1;
	if (buf[0] != '@')
		return 2;

	/* send autobaud reply */
	buf[0] = 0xBF;
	buf[1] = 0x00;
	buf[2] = 0x00;
	buf[3] = 0x00;
	ret = write(master, buf, 4);

	/* dont block */
	ret = fcntl(master, F_GETFL);
	fcntl(master, F_SETFL, ret | O_NONBLOCK);

	/* read the LDR in random chunks */
	i = 0x8000;
	buf = realloc(buf, i);
	while (1) {
		ret = read(master, buf, i);
		if (ret == -1 && errno == EAGAIN) {
			if (status)
				continue;
			ret = 0;
			break;
		} else if (ret < 0)
			break;
		else if (!ret)
			break;
		fwrite(buf, 1, ret, fp);
	}
	fclose(fp);

	return ret;
}
