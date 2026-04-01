#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>

#include "pipebuf_ioctl.h"

#define DEV "/dev/pipebuf0"

static void test_basic_rw(void)
{
	int fd_w, fd_r;
	char buf[256];
	ssize_t n;

	printf("=== Test 1: basic write/read ===\n");

	fd_w = open(DEV, O_WRONLY);
	if (fd_w < 0) { perror("open writer"); return; }

	fd_r = open(DEV, O_RDONLY);
	if (fd_r < 0) { perror("open reader"); close(fd_w); return; }

	write(fd_w, "hello pipebuf", 13);
	n = read(fd_r, buf, sizeof(buf));
	if (n > 0) {
		buf[n] = 0;
		printf("  Read: '%s' (%zd bytes)  [OK]\n", buf, n);
	} else {
		printf("  Read returned %zd  [FAIL]\n", n);
	}

	close(fd_w);
	close(fd_r);
}

static void test_blocking_read(void)
{
	int fd_w, fd_r;
	char buf[256];
	ssize_t n;
	pid_t pid;

	printf("\n=== Test 2: blocking read (reader waits for writer) ===\n");

	fd_w = open(DEV, O_WRONLY);
	if (fd_w < 0) { perror("open writer"); return; }

	pid = fork();
	if (pid == 0) {
		fd_r = open(DEV, O_RDONLY);
		if (fd_r < 0) { perror("child open reader"); close(fd_w); _exit(1); }
		printf("  Child: blocking on read...\n");
		n = read(fd_r, buf, sizeof(buf));
		if (n > 0) {
			buf[n] = 0;
			printf("  Child: read '%s' (%zd bytes)  [OK]\n", buf, n);
		}
		close(fd_r);
		close(fd_w);
		_exit(0);
	}

	sleep(1);
	printf("  Parent: writing after 1s delay...\n");
	write(fd_w, "delayed!", 8);
	close(fd_w);
	wait(NULL);
}

static void test_eof_no_writers(void)
{
	int fd_w, fd_r;
	char buf[256];
	ssize_t n;

	printf("\n=== Test 3: EOF when no writers ===\n");

	fd_w = open(DEV, O_WRONLY);
	if (fd_w < 0) { perror("open writer"); return; }

	fd_r = open(DEV, O_RDONLY);
	if (fd_r < 0) { perror("open reader"); close(fd_w); return; }

	close(fd_w);
	n = read(fd_r, buf, sizeof(buf));
	printf("  read returned %zd (expected 0 = EOF)  [%s]\n",
	       n, n == 0 ? "OK" : "FAIL");

	close(fd_r);
}

static void test_single_reader(void)
{
	int fd_w, fd_r, fd_r2;

	printf("\n=== Test 4: only one reader allowed ===\n");

	fd_w = open(DEV, O_WRONLY);
	if (fd_w < 0) { perror("open writer"); return; }

	fd_r = open(DEV, O_RDONLY);
	if (fd_r < 0) { perror("open first reader"); close(fd_w); return; }

	fd_r2 = open(DEV, O_RDONLY);
	if (fd_r2 < 0)
		printf("  Second reader rejected: %s  [OK]\n", strerror(errno));
	else {
		printf("  Second reader was allowed  [FAIL]\n");
		close(fd_r2);
	}

	close(fd_r);
	close(fd_w);
}

static void test_blocking_write(void)
{
	int fd_w, fd_r;
	char *big;
	ssize_t n;
	pid_t pid;
	unsigned long bufsize = 0;

	printf("\n=== Test 5: blocking write (buffer full) ===\n");

	fd_w = open(DEV, O_WRONLY);
	if (fd_w < 0) { perror("open writer"); return; }

	if (ioctl(fd_w, PIPEBUF_IOC_GET_BUFSIZE, &bufsize) == 0)
		printf("  Buffer size: %lu\n", bufsize);
	else
		bufsize = 4096;

	fd_r = open(DEV, O_RDONLY);
	if (fd_r < 0) { perror("open reader"); close(fd_w); return; }

	big = malloc(bufsize + 1024);
	if (!big) { perror("malloc"); close(fd_r); close(fd_w); return; }
	memset(big, 'X', bufsize + 1024);

	pid = fork();
	if (pid == 0) {
		close(fd_r);
		printf("  Child: writing %lu bytes (more than buffer)...\n",
		       bufsize + 1024);
		n = write(fd_w, big, bufsize + 1024);
		printf("  Child: first write returned %zd\n", n);
		n = write(fd_w, big, 1024);
		printf("  Child: second write returned %zd (may have blocked)\n", n);
		close(fd_w);
		free(big);
		_exit(0);
	}

	close(fd_w);
	sleep(2);
	printf("  Parent: draining buffer...\n");
	char drain[4096];
	while (read(fd_r, drain, sizeof(drain)) > 0)
		;

	close(fd_r);
	free(big);
	wait(NULL);
}

static void test_ioctl_bufsize(void)
{
	int fd_w;
	unsigned long size;

	printf("\n=== Test 6: ioctl get/set bufsize ===\n");

	fd_w = open(DEV, O_WRONLY);
	if (fd_w < 0) { perror("open"); return; }

	if (ioctl(fd_w, PIPEBUF_IOC_GET_BUFSIZE, &size) == 0)
		printf("  Current bufsize: %lu\n", size);

	size = 8192;
	if (ioctl(fd_w, PIPEBUF_IOC_SET_BUFSIZE, &size) == 0) {
		ioctl(fd_w, PIPEBUF_IOC_GET_BUFSIZE, &size);
		printf("  After set 8192: bufsize=%lu  [OK]\n", size);
	} else {
		printf("  Set bufsize failed: %s\n", strerror(errno));
	}

	size = 4096;
	ioctl(fd_w, PIPEBUF_IOC_SET_BUFSIZE, &size);

	close(fd_w);
}

int main(void)
{
	test_basic_rw();
	test_blocking_read();
	test_eof_no_writers();
	test_single_reader();
	test_blocking_write();
	test_ioctl_bufsize();
	return 0;
}
