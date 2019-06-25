/*
 * Copyright (c) 2019 Alexander Bluhm <bluhm@genua.de>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void __dead
usage(void)
{
	fprintf(stderr, "usage: udpperf local|remote send|recv\n");
	exit(2);
}

enum direction {
    DIR_NONE,
    DIR_SEND,
    DIR_RECV,
} dir;

enum mode {
    MOD_NONE,
    MOD_LOCAL,
    MOD_REMOTE,
} mod;

int
main(int argc, char *argv[])
{
	int ch;

	while ((ch = getopt(argc, argv, "")) != -1) {
		switch (ch) {
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2)
		errx(1, "no mode and direction");

	if (strcmp(argv[1], "local") == 0)
		mod = MOD_LOCAL;
	else if (strcmp(argv[1], "remote") == 0)
		mod = MOD_REMOTE;
	else
		errx(1, "unknown mode: %s", argv[1]);

	if (strcmp(argv[2], "send") == 0)
		dir = DIR_SEND;
	else if (strcmp(argv[2], "recv") == 0)
		dir = DIR_RECV;
	else
		errx(1, "unknown direction: %s", argv[2]);

	return 0;
}
