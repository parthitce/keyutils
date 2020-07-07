/* keyctl program definitions
 *
 * Copyright (C) 2019 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

struct command {
	void (*action)(int argc, char *argv[]) __attribute__((noreturn));
	const char	*name;
	const char	*format;
};

#define nr __attribute__((noreturn))

/*
 * keyctl.c
 */
extern nr void do_command(int, char **, const struct command *, const char *);
extern nr void error(const char *);

/*
 * keyctl_testing.c
 */
extern nr void act_keyctl_test(int, char *[]);
