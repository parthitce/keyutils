/* Key watching facility.
 *
 * Copyright (C) 2019 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <poll.h>
#include <getopt.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include "keyutils.h"
#include <limits.h>
#include "keyctl.h"
#include "watch_queue.h"

#define BUF_SIZE 4

static int consumer_stop;
static pid_t pid_con = -1, pid_cmd = -1;
static key_serial_t session;
static int watch_fd;
static int debug;

static inline bool after_eq(unsigned int a, unsigned int b)
{
        return (signed int)(a - b) >= 0;
}

static void consumer_term(int sig)
{
	consumer_stop = 1;
}

static void saw_key_change(FILE *log, struct watch_notification *n)
{
	struct key_notification *k = (struct key_notification *)n;
	unsigned int len = (n->info & WATCH_INFO_LENGTH) >> WATCH_INFO_LENGTH__SHIFT;

	if (len != sizeof(struct key_notification) / WATCH_LENGTH_GRANULARITY)
		return;

	switch (n->subtype) {
	case NOTIFY_KEY_INSTANTIATED:
		fprintf(log, "%u inst\n", k->key_id);
		break;
	case NOTIFY_KEY_UPDATED:
		fprintf(log, "%u upd\n", k->key_id);
		break;
	case NOTIFY_KEY_LINKED:
		fprintf(log, "%u link %u\n", k->key_id, k->aux);
		break;
	case NOTIFY_KEY_UNLINKED:
		fprintf(log, "%u unlk %u\n", k->key_id, k->aux);
		break;
	case NOTIFY_KEY_CLEARED:
		fprintf(log, "%u clr\n", k->key_id);
		break;
	case NOTIFY_KEY_REVOKED:
		fprintf(log, "%u rev\n", k->key_id);
		break;
	case NOTIFY_KEY_INVALIDATED:
		fprintf(log, "%u inv\n", k->key_id);
		break;
	case NOTIFY_KEY_SETATTR:
		fprintf(log, "%u attr\n", k->key_id);
		break;
	}
}

/*
 * Handle removal notification.
 */
static void saw_removal_notification(FILE *gc, struct watch_notification *n)
{
	key_serial_t key = 0;
	unsigned int wp, l;

	l = (n->info & WATCH_INFO_LENGTH) >> WATCH_INFO_LENGTH__SHIFT;
	l <<= WATCH_LENGTH_GRANULARITY;
	wp = (n->info & WATCH_INFO_ID) >> WATCH_INFO_ID__SHIFT;

	if (l >= sizeof(struct watch_notification_removal)) {
		struct watch_notification_removal *r = (void *)n;
		key = r->id;
	}

	fprintf(gc, "%u gc\n", key);
	if (wp == 1)
		exit(0);
}

/*
 * Consume and display events.
 */
static __attribute__((noreturn))
int consumer(FILE *log, FILE *gc, int fd, struct watch_queue_buffer *buf)
{
	struct watch_notification *n;
	struct pollfd p[1];
	unsigned int head, tail, mask = buf->meta.mask;

	setlinebuf(log);
	setlinebuf(gc);
	signal(SIGTERM, consumer_term);

	do {
		if (!consumer_stop) {
			p[0].fd = fd;
			p[0].events = POLLIN | POLLERR;
			p[0].revents = 0;

			if (poll(p, 1, -1) == -1) {
				if (errno == EINTR)
					continue;
				error("poll");
			}
		}

		while (head = __atomic_load_n(&buf->meta.head, __ATOMIC_ACQUIRE),
		       tail = buf->meta.tail,
		       tail != head
		       ) {
			n = &buf->slots[tail & mask];
			if (debug)
				fprintf(stderr,
					"NOTIFY[%08x-%08x] ty=%06x:%02x i=%08x\n",
					head, tail, n->type, n->subtype, n->info);

			if ((n->info & WATCH_INFO_LENGTH) == 0) {
				fprintf(stderr, "Zero-length watch record\n");
				exit(4);
			}

			switch (n->type) {
			case WATCH_TYPE_META:
				switch (n->subtype) {
				case WATCH_META_REMOVAL_NOTIFICATION:
					saw_removal_notification(gc, n);
					break;
				}
				break;
			case WATCH_TYPE_KEY_NOTIFY:
				saw_key_change(log, n);
				break;
			}

			tail += (n->info & WATCH_INFO_LENGTH) >> WATCH_INFO_LENGTH__SHIFT;
			__atomic_store_n(&buf->meta.tail, tail, __ATOMIC_RELEASE);
		}
	} while (!consumer_stop);

	fprintf(log, "Monitoring terminated\n");
	if (gc != log)
		fprintf(gc, "Monitoring terminated\n");
	exit(0);
}

static struct watch_notification_filter filter = {
	.nr_filters	= 1,
	.__reserved	= 0,
	.filters = {
		[0]	= {
			.type			= WATCH_TYPE_KEY_NOTIFY,
			.subtype_filter[0]	= UINT_MAX,
		},
	},
};

/*
 * Open the watch device and allocate a buffer.
 */
static int open_watch(struct watch_queue_buffer **_buf)
{
	struct watch_queue_buffer *buf;
	size_t page_size;
	int fd;

	fd = open("/dev/watch_queue", O_RDWR);
	if (fd == -1)
		error("/dev/watch_queue");

	if (ioctl(fd, IOC_WATCH_QUEUE_SET_SIZE, BUF_SIZE) == -1)
		error("/dev/watch_queue(size)");

	if (ioctl(fd, IOC_WATCH_QUEUE_SET_FILTER, &filter) == -1)
		error("/dev/watch_queue(filter)");

	page_size = sysconf(_SC_PAGESIZE);
	buf = mmap(NULL, BUF_SIZE * page_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED, fd, 0);
	if (buf == MAP_FAILED)
		error("mmap");

	*_buf = buf;
	return fd;
}

/*
 * Watch a key or keyring for changes.
 */
void act_keyctl_watch(int argc, char *argv[])
{
	struct watch_queue_buffer *buf;
	key_serial_t key;
	int wfd;

	if (argc != 2)
		format();

	key = get_key_id(argv[1]);
	wfd = open_watch(&buf);

	if (keyctl_watch_key(key, wfd, 0x01) == -1)
		error("keyctl_watch_key");

	consumer(stdout, stdout, wfd, buf);
}

/*
 * Add a watch on a key to the monitor created by watch_session.
 */
void act_keyctl_watch_add(int argc, char *argv[])
{
	key_serial_t key;
	int fd;

	if (argc != 3)
		format();

	fd = atoi(argv[1]);
	key = get_key_id(argv[2]);

	if (keyctl_watch_key(key, fd, 0x02) == -1)
		error("keyctl_watch_key");
	exit(0);
}

/*
 * Remove a watch on a key from the monitor created by watch_session.
 */
void act_keyctl_watch_rm(int argc, char *argv[])
{
	key_serial_t key;
	int fd;

	if (argc != 3)
		format();

	fd = atoi(argv[1]);
	key = get_key_id(argv[2]);

	if (keyctl_watch_key(key, fd, -1) == -1)
		error("keyctl_watch_key");
	exit(0);
}

static void exit_cleanup(void)
{
	pid_t me = getpid();
	int w;

	if (me != pid_cmd && me != pid_con) {
		keyctl_watch_key(session, watch_fd, -1);
		if (pid_cmd != -1) {
			kill(pid_cmd, SIGTERM);
			waitpid(pid_cmd, &w, 0);
		}
		if (pid_con != -1) {
			kill(pid_con, SIGTERM);
			waitpid(pid_con, &w, 0);
		}
	}
}

static void run_command(int argc, char *argv[], int wfd)
{
	char buf[16];

	pid_cmd = fork();
	if (pid_cmd == -1)
		error("fork");
	if (pid_cmd != 0)
		return;

	pid_cmd = -1;
	pid_con = -1;

	sprintf(buf, "%u", wfd);
	setenv("KEYCTL_WATCH_FD", buf, true);

	/* run the standard shell if no arguments */
	if (argc == 0) {
		const char *q = getenv("SHELL");
		if (!q)
			q = "/bin/sh";
		execl(q, q, NULL);
		error(q);
	}

	/* run the command specified */
	execvp(argv[0], argv);
	error(argv[0]);
}

/*
 * Open a logfiles.
 */
static FILE *open_logfile(const char *logfile)
{
	unsigned int flags;
	FILE *log;
	int lfd;

	log = fopen(logfile, "a");
	if (!log)
		error(logfile);

	lfd = fileno(log);
	flags = fcntl(lfd, F_GETFD);
	if (flags == -1)
		error("F_GETFD");
	if (fcntl(lfd, F_SETFD, flags | FD_CLOEXEC) == -1)
		error("F_SETFD");

	return log;
}

/*
 * Set up a new session keyring with a monitor that is exposed on an explicit
 * file descriptor in the program that it starts.
 */
void act_keyctl_watch_session(int argc, char *argv[])
{
	struct watch_queue_buffer *buf;
	const char *session_name = NULL;
	const char *logfile, *gcfile, *target_fd;
	unsigned int flags;
	pid_t pid;
	FILE *log, *gc;
	int wfd, tfd, opt, w, e = 0, e2 = 0;

	while (opt = getopt(argc, argv, "+dn:"),
	       opt != -1) {
		switch (opt) {
		case 'd':
			debug = 1;
			break;
		case 'n':
			session_name = optarg;
			break;
		default:
			fprintf(stderr, "Unknown option\n");
			exit(2);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc < 4)
		format();

	logfile = argv[0];
	gcfile = argv[1];
	target_fd = argv[2];
	tfd = atoi(target_fd);
	if (tfd < 3 || tfd > 9) {
		fprintf(stderr, "The target fd must be between 3 and 9\n");
		exit(2);
	}

	wfd = open_watch(&buf);
	if (wfd != tfd) {
		if (dup2(wfd, tfd) == -1)
			error("dup2");
		close(wfd);
		wfd = tfd;
	}
	watch_fd = wfd;

	atexit(exit_cleanup);

	/* We want the fd to be inherited across a fork. */
	flags = fcntl(wfd, F_GETFD);
	if (flags == -1)
		error("F_GETFD");
	if (fcntl(wfd, F_SETFD, flags & ~FD_CLOEXEC) == -1)
		error("F_SETFD");

	log = open_logfile(logfile);
	gc = open_logfile(gcfile);

	pid_con = fork();
	if (pid_con == -1)
		error("fork");
	if (pid_con == 0) {
		pid_cmd = -1;
		pid_con = -1;
		consumer(log, gc, wfd, buf);
	}

	/* Create a new session keyring and watch it. */
	session = keyctl_join_session_keyring(session_name);
	if (session == -1)
		error("keyctl_join_session_keyring");

	if (keyctl_watch_key(session, wfd, 0x01) == -1)
		error("keyctl_watch_key/session");

	fprintf(stderr, "Joined session keyring: %d\n", session);

	/* Start the command and then wait for it to finish and the
	 * notification consumer to clean up.
	 */
	run_command(argc - 3, argv + 3, wfd);
	close(wfd);
	wfd = -1;

	while (pid = wait(&w),
	       pid != -1) {
		if (pid == pid_cmd) {
			if (pid_con != -1)
				kill(pid_con, SIGTERM);
			if (WIFEXITED(w)) {
				e2 = WEXITSTATUS(w);
				pid_cmd = -1;
			} else if (WIFSIGNALED(w)) {
				e2 = WTERMSIG(w) + 128;
				pid_cmd = -1;
			} else if (WIFSTOPPED(w)) {
				raise(WSTOPSIG(w));
			}
		} else if (pid == pid_con) {
			if (pid_cmd != -1)
				kill(pid_cmd, SIGTERM);
			if (WIFEXITED(w)) {
				e = WEXITSTATUS(w);
				pid_con = -1;
			} else if (WIFSIGNALED(w)) {
				e = WTERMSIG(w) + 128;
				pid_con = -1;
			}
		}
	}

	if (e == 0)
		e = e2;
	exit(e);
}

/*
 * Wait for monitoring to synchronise.
 */
void act_keyctl_watch_sync(int argc, char *argv[])
{
	struct watch_queue_buffer *buf;
	//unsigned int head, tail;
	size_t page_size;
	int wfd;

	if (argc != 2)
		format();

	wfd = atoi(argv[1]);

	/* We only need to see the first page. */
	page_size = sysconf(_SC_PAGESIZE);
	buf = mmap(NULL, 1 * page_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED, wfd, 0);
	if (buf == MAP_FAILED)
		error("mmap");

#if 0
	head = __atomic_load_n(&buf->meta.head, __ATOMIC_RELAXED);

	while (tail = __atomic_load_n(&buf->meta.tail, __ATOMIC_RELAXED),
	       !after_eq(tail, head)
	       )
		usleep(10000);
#endif
	exit(0);
}
