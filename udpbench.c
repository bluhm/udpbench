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
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

sig_atomic_t alarm_signaled;

int address_family;
int udp_socket = -1;

void udp_buffersize(int);
void udp_bind(const char *, const char *);
void udp_connect(const char *, const char *);
void udp_send(const char *, size_t);
void udp_receive(char *, size_t);
void alarm_handler(int);

static void __dead
usage(void)
{
	fprintf(stderr, "usage: udpperf [-b bufsize] [-l length] [-p port] "
	    "[-t timeout] "
	    "local|remote send|recv [hostname]\n"
	    "    -b bufsize     set size of send or receive buffer\n"
	    "    -l length      set length of udp payload\n"
	    "    -p port        udp port for bind or connect, default 12345\n"
	    "    -t timeout     send duration or receive timeout, default 1\n"
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
	char *udp_payload;
	size_t udp_length = 0;
	int ch, buffer_size = 0, timeout = 1;
	const char *host = NULL, *port = "12345";

	while ((ch = getopt(argc, argv, "b:l:p:t:")) != -1) {
		switch (ch) {
		case 'b':
			buffer_size = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "buffer size is %s: %s", errstr,
				    optarg);
			break;
		case 'l':
			udp_length = strtonum(optarg, 0, IP_MAXPACKET, &errstr);
			if (errstr != NULL)
				errx(1, "payload length is %s: %s", errstr,
				    optarg);
			break;
		case 'p':
			port = optarg;
			break;
		case 't':
			timeout = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "timeout is %s: %s", errstr,
				    optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 3)
		usage();
	if (argc < 2)
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

	if (dir == DIR_SEND && argc < 3)
		errx(1, "no hostname");
	if (argc >= 3)
		host = argv[2];

	memset(&act, 0, sizeof(act));
	act.sa_handler = alarm_handler;
	act.sa_flags = SA_RESETHAND;
	if (sigaction(SIGALRM, &act, NULL) == -1)
		err(1, "sigaction");

	udp_payload = malloc(udp_length);
	if (udp_payload == NULL)
		err(1, "malloc udp payload");
	if (dir == DIR_SEND) {
		arc4random_buf(udp_payload, udp_length);
		udp_connect(host, port);
		udp_buffersize(buffer_size);
		if (timeout > 0)
			alarm(timeout);
		udp_send(udp_payload, udp_length);
	} else {
		udp_bind(host, port);
		udp_buffersize(buffer_size);
		if (timeout > 0)
			alarm(timeout);
		udp_receive(udp_payload, udp_length);
	}

	return 0;
}

void
alarm_handler(int sig)
{
	alarm_signaled = 1;
}

void
udp_bind(const char *host, const char *port)
{
	struct addrinfo hints, *res, *res0;
	int error;
	int save_errno;
	const char *cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = 17;
	hints.ai_flags = AI_PASSIVE;
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

		if (bind(udp_socket, res->ai_addr, res->ai_addrlen) == -1) {
			cause = "bind";
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
udp_buffersize(int size)
{
	socklen_t len;
	int name;

	/* use default */
	if (size == 0)
		return;

	name = (dir == DIR_SEND) ? SO_SNDBUF : SO_RCVBUF;
	len = sizeof(size);
	if (setsockopt(udp_socket, SOL_SOCKET, name, &size, len) == -1)
		err(1, "setsockopt buffer size %d", size);

}

void
udp_send(const char *payload, size_t udplen)
{
	struct timeval begin, end, duration;
	unsigned long count;
	size_t length;
	double bits;

	if (gettimeofday(&begin, NULL) == -1)
		err(1, "gettimeofday begin");

	count = 0;
	while (!alarm_signaled) {
		if (send(udp_socket, payload, udplen, 0) == -1)
			err(1, "send");
		count++;
	}

	if (gettimeofday(&end, NULL) == -1)
		err(1, "gettimeofday end");

	length = (address_family == AF_INET) ?
	    sizeof(struct ip) : sizeof(struct ip6_hdr);
	length += sizeof(struct udphdr) + udplen;
	timersub(&end, &begin, &duration);
	bits = (double)count * length;
	bits /= (double)duration.tv_sec + duration.tv_usec / 1000000.;
	printf("send: count %lu, length %zu, duration %lld.%06ld, bit/s %g\n",
	    count, length, duration.tv_sec, duration.tv_usec, bits);
}

void
udp_receive(char *payload, size_t udplen)
{
	struct timeval begin, idle, end, duration, timeo;
	unsigned long count, syscall, bored;
	size_t length;
	socklen_t len;
	double bits;

	/* wait for the first packet to start timing */
	if (recv(udp_socket, payload, udplen, 0) == -1)
		err(1, "recv 1");

	if (gettimeofday(&begin, NULL) == -1)
		err(1, "gettimeofday begin");
	timerclear(&idle);

	timeo.tv_sec = 0;
	timeo.tv_usec = 100000;
	len = sizeof(timeo);
	if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, &timeo, len) == -1)
		err(1, "setsockopt recv timeout");

	count = 1;
	syscall = 1;
	bored = 0;
	while (!alarm_signaled) {
		syscall++;
		if (recv(udp_socket, payload, udplen, 0) == -1) {
			if (errno == EWOULDBLOCK) {
				bored++;
				if (bored == 1) {
					if (gettimeofday(&idle, NULL) == -1)
						err(1, "gettimeofday idle");
					/* packet was seen before timeout */
					timersub(&idle, &timeo, &idle);
				}
				continue;
			}
			if (errno == EINTR)
				break;
			err(1, "recv");
		}
		bored = 0;
		count++;
	}

	if (gettimeofday(&end, NULL) == -1)
		err(1, "gettimeofday end");

	length = (address_family == AF_INET) ?
	    sizeof(struct ip) : sizeof(struct ip6_hdr);
	length += sizeof(struct udphdr) + udplen;
	if (timerisset(&idle)) {
		timersub(&idle, &begin, &duration);
		timersub(&end, &idle, &idle);
	} else {
		timersub(&end, &begin, &duration);
	}
	bits = (double)count * length;
	bits /= (double)duration.tv_sec + duration.tv_usec / 1000000.;
	printf("recv: count %lu, length %zu, duration %lld.%06ld, bit/s %g\n",
	    count, length, duration.tv_sec, duration.tv_usec, bits);
	if (idle.tv_sec < 1)
		errx(1, "not enough idle time: %lld.%06ld",
		    idle.tv_sec, idle.tv_usec);
}
