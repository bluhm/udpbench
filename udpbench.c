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

#include <sys/time.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

sig_atomic_t alarm_signaled;

int address_family;
int udp_socket = -1;
size_t udp_length;
char *udp_payload;

void udp_connect(const char *, const char *);
void udp_send(void);
void alarm_handler(int);

static void __dead
usage(void)
{
	fprintf(stderr, "usage: udpperf [-l length] local|remote send|recv\n"
	    "    -l length      set length of udp payload\n"
	    );
	exit(2);
}

int plen;

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
	struct sigaction act;
	const char *errstr;
	int ch;

	while ((ch = getopt(argc, argv, "l:")) != -1) {
		switch (ch) {
		case 'l':
			udp_length = strtonum(optarg, 1, IP_MAXPACKET, &errstr);
			if (errstr != NULL)
				errx(1, "payload length is %s: %s", errstr,
				    optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2)
		errx(1, "no mode and direction");

	if (strcmp(argv[0], "local") == 0)
		mod = MOD_LOCAL;
	else if (strcmp(argv[0], "remote") == 0)
		mod = MOD_REMOTE;
	else
		errx(1, "unknown mode: %s", argv[1]);

	if (strcmp(argv[1], "send") == 0)
		dir = DIR_SEND;
	else if (strcmp(argv[1], "recv") == 0)
		dir = DIR_RECV;
	else
		errx(1, "unknown direction: %s", argv[2]);

	memset(&act, 0, sizeof(act));
	act.sa_handler = alarm_handler;
	act.sa_flags = SA_RESETHAND;
	if (sigaction(SIGALRM, &act, NULL) == -1)
		err(1, "sigaction");

	if (dir == DIR_SEND) {
		udp_payload = malloc(udp_length);
		if (udp_payload == NULL)
			err(1, "malloc udp payload");
		arc4random_buf(udp_payload, udp_length);
		udp_connect("127.0.0.1", "12345");
		alarm(1);
		udp_send();
	}

	return 0;
}

void
alarm_handler(int sig)
{
	alarm_signaled = 1;
}

void
udp_connect(const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	int error;
	int save_errno;
	const char *cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 17;
	error = getaddrinfo(host, port, &hints, &res0);
	if (error)
		errx(1, "getaddrinfo: %s", gai_strerror(error));
	udp_socket = -1;
	for (res = res0; res; res = res->ai_next) {
		udp_socket = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (udp_socket == -1) {
			cause = "socket";
			continue;
		}

		if (connect(udp_socket, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "connect";
			save_errno = errno;
			close(udp_socket);
			errno = save_errno;
			udp_socket = -1;
			continue;
		}

		break;  /* okay we got one */
	}
	if (udp_socket == -1)
		err(1, "%s", cause);
	address_family = res->ai_family;
	freeaddrinfo(res0);
}

void
udp_send(void)
{
	struct timeval begin, end, duration;
	unsigned long count;
	size_t length;
	double bits;

	if (gettimeofday(&begin, NULL) == -1)
		err(1, "gettimeofday begin");

	count = 0;
	while (!alarm_signaled) {
		if (send(udp_socket, udp_payload, udp_length, 0) == -1)
			err(1, "send");
		count++;
	}

	if (gettimeofday(&end, NULL) == -1)
		err(1, "gettimeofday end");

	switch(address_family) {
	case AF_INET:
		length = sizeof(struct ip) + sizeof(struct udphdr) +
		    udp_length;
		break;
	case AF_INET6:
		length = sizeof(struct ip6_hdr) + sizeof(struct udphdr) +
		    udp_length;
		break;
	default:
		errx(1, "address family %d", address_family);
	}
	timersub(&end, &begin, &duration);
	bits = (double)count * length;
	bits /= (double)duration.tv_sec + duration.tv_usec / 1000000.;
	printf("send: count %lu, length %zu, duration %lld.%06ld, bit/s %g\n",
	    count, length, duration.tv_sec, duration.tv_usec, bits);
}
