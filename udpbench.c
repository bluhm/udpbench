/*
 * Copyright (c) 2019-2022 Alexander Bluhm <bluhm@genua.de>
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
#include <sys/wait.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/udp.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

sig_atomic_t alarm_signaled;

int udp_family;
int udp_socket = -1;
FILE *ssh_stream;
pid_t ssh_pid;

void alarm_handler(int);
void udp_bind(const char *, const char *);
void udp_connect(const char *, const char *);
void udp_getsockname(char **, char **);
void udp_setbuffersize(int, int);
void udp_send(const char *, size_t, unsigned long);
void udp_receive(char *, size_t);
void udp_close(void);
void ssh_bind(const char *, const char *, const char *, const char *,
    int, size_t , int);
void ssh_connect(const char *, const char *, const char *, const char *,
    int, size_t , int);
void ssh_pipe(char **);
void ssh_getpeername(char **, char **);
void ssh_wait(void);

static void
usage(void)
{
	fprintf(stderr, "usage: udpbench [-b bufsize] [-d delaypacket] "
	    "[-l length] [-p port] [-R remoteprog] [-r remotessh] "
	    "[-t timeout] send|recv [hostname]\n"
	    "    -b bufsize     set size of send or receive buffer\n"
	    "    -d delaypacket delay sending to packets per second rate\n"
	    "    -l length      set length of udp payload\n"
	    "    -p port        udp port, default 12345, random 0\n"
	    "    -R remoteprog  path of udpbench tool on remote side\n"
	    "    -r remotessh   ssh host to start udpbench on remote side\n"
	    "    -t timeout     send duration or receive timeout, default 1\n"
	    "    send|recv      send or receive mode for local side\n"
	    "    hostname       address of receiving side\n"
	    );
	exit(2);
}

int
main(int argc, char *argv[])
{
	struct sigaction act;
	const char *errstr;
	char *udppayload;
	size_t udplength = 0;
	int ch, buffersize = 0, timeout = 1, sendmode;
	unsigned long delaypacket = 0;
	const char *progname = argv[0];
	char *hostname = NULL, *service = "12345", *remotessh = NULL;
	char *localaddr, *localport;

#ifdef __OpenBSD__
	if (pledge("stdio dns inet proc exec", NULL) == -1)
		err(1, "pledge");
#endif
	if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
		err(1, "setvbuf");

	while ((ch = getopt(argc, argv, "b:d:l:p:R:r:t:")) != -1) {
		switch (ch) {
		case 'b':
			buffersize = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "buffer size is %s: %s",
				    errstr, optarg);
			break;
		case 'd':
			delaypacket = strtonum(optarg, 0, LONG_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "delay packets per second is %s: %s",
				    errstr, optarg);
			break;
		case 'l':
			udplength = strtonum(optarg, 0, IP_MAXPACKET, &errstr);
			if (errstr != NULL)
				errx(1, "payload length is %s: %s",
				    errstr, optarg);
			break;
		case 'p':
			service = optarg;
			break;
		case 'R':
			progname = optarg;
			break;
		case 'r':
			remotessh = optarg;
			break;
		case 't':
			timeout = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "timeout is %s: %s",
				    errstr, optarg);
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc > 2)
		usage();
	if (argc < 1)
		errx(1, "send or recv required");
	if (strcmp(argv[0], "send") == 0) {
		sendmode = 1;
		setprogname("udpbench send");
	} else if (strcmp(argv[0], "recv") == 0) {
		sendmode = 0;
		setprogname("udpbench recv");
	} else
		errx(1, "bad send or recv: %s", argv[0]);

	if (sendmode && argc < 2)
		errx(1, "hostname required for send");
	if (argc >= 2)
		hostname = argv[1];
#ifdef __OpenBSD__
	if (remotessh == NULL) {
		if (pledge("stdio dns inet", NULL) == -1)
			err(1, "pledge");
	}
#endif

	memset(&act, 0, sizeof(act));
	act.sa_handler = alarm_handler;
	act.sa_flags = SA_RESETHAND;
	if (sigaction(SIGALRM, &act, NULL) == -1)
		err(1, "sigaction");

	udppayload = malloc(udplength + 1);
	if (udppayload == NULL)
		err(1, "malloc udp payload");
	if (sendmode) {
		arc4random_buf(udppayload, udplength);
		if (remotessh != NULL) {
			ssh_bind(remotessh, progname, hostname, service,
			    buffersize, udplength, timeout);
#ifdef __OpenBSD__
			if (pledge("stdio dns inet", NULL) == -1)
				err(1, "pledge");
#endif
			ssh_getpeername(&hostname, &service);
		}
		udp_connect(hostname, service);
		udp_getsockname(NULL, NULL);
		udp_setbuffersize(SO_SNDBUF, buffersize);
		if (timeout > 0)
			alarm(timeout);
		udp_send(udppayload, udplength, delaypacket);
		if (remotessh != NULL) {
			free(hostname);
			free(service);
		}
	} else {
		udp_bind(hostname, service);
		udp_getsockname(&localaddr, &localport);
		udp_setbuffersize(SO_RCVBUF, buffersize);
		if (remotessh != NULL) {
			ssh_connect(remotessh, progname, localaddr, localport,
			buffersize, udplength, timeout);
#ifdef __OpenBSD__
			if (pledge("stdio dns inet", NULL) == -1)
				err(1, "pledge");
#endif
			ssh_getpeername(NULL, NULL);
		}
		if (timeout > 0)
			alarm(timeout + 2);
		udp_receive(udppayload, udplength);
		free(localaddr);
		free(localport);
	}
	if (remotessh != NULL)
		ssh_wait();
	udp_close();
	free(udppayload);

	return 0;
}

void
alarm_handler(int sig)
{
	alarm_signaled = 1;
}

void
udp_bind(const char *host, const char *service)
{
	struct addrinfo hints, *res, *res0;
	int error;
	int save_errno;
	const char *cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(host, service, &hints, &res0);
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
	udp_family = res->ai_family;
	freeaddrinfo(res0);
}

void
udp_connect(const char *host, const char *service)
{
	struct addrinfo hints, *res, *res0;
	int error;
	int save_errno;
	const char *cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo(host, service, &hints, &res0);
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
	udp_family = res->ai_family;
	freeaddrinfo(res0);
}

void
udp_getsockname(char **addr, char **port)
{
	struct sockaddr_storage ss;
	struct sockaddr *sa = (struct sockaddr *)&ss;
	char host[NI_MAXHOST], serv[NI_MAXSERV];
	socklen_t len;
	int error;

	len = sizeof(ss);
	if (getsockname(udp_socket, sa, &len) == -1)
		err(1, "getsockname");

	error = getnameinfo(sa, len, host, sizeof(host), serv, sizeof(serv),
	    NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM);
	if (error)
		errx(1, "getnameinfo: %s", gai_strerror(error));
	if (addr != NULL) {
		*addr = strdup(host);
		if (*addr == NULL)
			err(1, "strdup addr");
	}
	if (port != NULL) {
		*port = strdup(serv);
		if (*port == NULL)
			err(1, "strdup port");
	}

	printf("sockname: %s %s\n", host, serv);
}

void
udp_setbuffersize(int name, int size)
{
	socklen_t len;

	/* use default */
	if (size == 0)
		return;

	len = sizeof(size);
	if (setsockopt(udp_socket, SOL_SOCKET, name, &size, len) == -1)
		err(1, "setsockopt buffer size %d", size);

}

void
udp_send(const char *payload, size_t udplen, unsigned long delaypacket)
{
	struct timeval begin, end, duration;
	struct timespec wait;
	unsigned long syscall, packet;
	size_t length;
	double bits, expectduration, waittime;

	if (gettimeofday(&begin, NULL) == -1)
		err(1, "gettimeofday begin");
	timerclear(&end);

	syscall = 0;
	packet = 0;
	while (!alarm_signaled) {
		syscall++;
		if (send(udp_socket, payload, udplen, 0) == -1) {
			if (errno == ENOBUFS)
				continue;
			err(1, "send");
		}
		packet++;
		if (delaypacket) {
			if (!timerisset(&end)) {
				if (gettimeofday(&end, NULL) == -1)
					err(1, "gettimeofday delay");
			}
			timersub(&end, &begin, &duration);
			if (!timerisset(&duration))
				duration.tv_usec = 1;
			expectduration = (double)packet / (double)delaypacket;
			waittime = expectduration - (double)duration.tv_sec -
			    (double)duration.tv_usec / 1000000.;
			wait.tv_sec = waittime;
			wait.tv_nsec = (waittime - (double)wait.tv_sec) *
			    1000000000.;
			if (wait.tv_sec > 0 || wait.tv_nsec > 0) {
				nanosleep(&wait, NULL);
				if (gettimeofday(&end, NULL) == -1)
					err(1, "gettimeofday delay");
			}
		}
	}

	if (gettimeofday(&end, NULL) == -1)
		err(1, "gettimeofday end");

	length = (udp_family == AF_INET) ?
	    sizeof(struct ip) : sizeof(struct ip6_hdr);
	length += sizeof(struct udphdr) + udplen;
	timersub(&end, &begin, &duration);
	bits = (double)packet * length * 8;
	bits /= (double)duration.tv_sec + (double)duration.tv_usec / 1000000.;
	printf("send: syscall %lu, packet %lu, length %zu, "
	    "duration %lld.%06ld, bit/s %g\n", syscall, packet, length,
	    (long long)duration.tv_sec, duration.tv_usec, bits);
}

void
udp_receive(char *payload, size_t udplen)
{
	struct timeval begin, idle, end, duration, timeo;
	unsigned long syscall, packet, bored;
	size_t length;
	ssize_t rcvlen;
	socklen_t len;
	double bits;

	/* wait for the first packet to start timing */
	rcvlen = recv(udp_socket, payload, udplen + 1, 0);
	if (rcvlen == -1)
		err(1, "recv 1");

	if (gettimeofday(&begin, NULL) == -1)
		err(1, "gettimeofday begin");
	timerclear(&idle);

	timeo.tv_sec = 0;
	timeo.tv_usec = 100000;
	len = sizeof(timeo);
	if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, &timeo, len) == -1)
		err(1, "setsockopt recv timeout");

	syscall = 1;
	packet = 1;
	bored = 0;
	while (!alarm_signaled) {
		syscall++;
		if (recv(udp_socket, payload, udplen + 1, 0) == -1) {
			if (errno == EWOULDBLOCK) {
				bored++;
				if (bored == 1) {
					if (gettimeofday(&idle, NULL) == -1)
						err(1, "gettimeofday idle");
					/* packet was seen before timeout */
					timersub(&idle, &timeo, &idle);
				}
				if (bored * timeo.tv_usec > 1000000) {
					/* more than a second idle time */
					break;
				}
				continue;
			}
			if (errno == EINTR)
				continue;
			err(1, "recv");
		}
		bored = 0;
		packet++;
	}

	if (gettimeofday(&end, NULL) == -1)
		err(1, "gettimeofday end");

	length = (udp_family == AF_INET) ?
	    sizeof(struct ip) : sizeof(struct ip6_hdr);
	length += sizeof(struct udphdr) + rcvlen;
	if (timerisset(&idle)) {
		timersub(&idle, &begin, &duration);
		timersub(&end, &idle, &idle);
	} else {
		timersub(&end, &begin, &duration);
	}
	bits = (double)packet * length * 8;
	bits /= (double)duration.tv_sec + (double)duration.tv_usec / 1000000.;
	printf("recv: syscall %lu, packet %lu, length %zu, "
	    "duration %lld.%06ld, bit/s %g\n", syscall, packet, length,
	    (long long)duration.tv_sec, duration.tv_usec, bits);
	if (idle.tv_sec < 1)
		errx(1, "not enough idle time: %lld.%06ld",
		    (long long)idle.tv_sec, idle.tv_usec);
}

void
udp_close(void)
{
	if (close(udp_socket) == -1)
		err(1, "close");
}

void
ssh_bind(const char *remotessh, const char *progname,
    const char *hostname, const char *service,
    int buffersize, size_t udplength, int timeout)
{
	char *argv[15];
	int i = 0;

	argv[i++] = "ssh";
	argv[i++] = "-nT";
	argv[i++] = (char *)remotessh;
	argv[i++] = (char *)progname;
	argv[i++] = "-b";
	if (asprintf(&argv[i++], "%d", buffersize) == -1)
		err(1, "asprintf buffer size");
	argv[i++] = "-l";
	if (asprintf(&argv[i++], "%zu", udplength) == -1)
		err(1, "asprintf udp length");
	argv[i++] = "-p";
	argv[i++] = (char *)service;
	argv[i++] = "-t";
	if (asprintf(&argv[i++], "%d", timeout + 2) == -1)
		err(1, "asprintf timeout");
	argv[i++] = "recv";
	argv[i++] = (char *)hostname;
	argv[i++] = NULL;

	assert(i == sizeof(argv) / sizeof(argv[0]));

	ssh_pipe(argv);

	free(argv[5]);
	free(argv[7]);
	free(argv[11]);
}

void
ssh_connect(const char *remotessh, const char *progname,
    const char *hostname, const char *service,
    int buffersize, size_t udplength, int timeout)
{
	char *argv[15];
	int i = 0;

	argv[i++] = "ssh";
	argv[i++] = "-nT";
	argv[i++] = (char *)remotessh;
	argv[i++] = (char *)progname;
	argv[i++] = "-b";
	if (asprintf(&argv[i++], "%d", buffersize) == -1)
		err(1, "asprintf buffer size");
	argv[i++] = "-l";
	if (asprintf(&argv[i++], "%zu", udplength) == -1)
		err(1, "asprintf udp length");
	argv[i++] = "-p";
	argv[i++] = (char *)service;
	argv[i++] = "-t";
	if (asprintf(&argv[i++], "%d", timeout) == -1)
		err(1, "asprintf timeout");
	argv[i++] = "send";
	argv[i++] = (char *)hostname;
	argv[i++] = NULL;

	assert(i == sizeof(argv) / sizeof(argv[0]));

	ssh_pipe(argv);

	free(argv[5]);
	free(argv[7]);
	free(argv[11]);
}

void
ssh_pipe(char *argv[])
{
	int fp[2];

	if (pipe(fp) == -1)
		err(1, "pipe");
	ssh_pid = fork();
	if (ssh_pid == -1)
		err(1, "fork");
	if (ssh_pid == 0) {
		if (close(fp[0]) == -1)
			err(255, "ssh close read pipe");
		if (dup2(fp[1], 1) == -1)
			err(255, "dup2 pipe");
		if (close(fp[1]) == -1)
			err(255, "ssh close write pipe");
		execvp("ssh", argv);
		err(255, "ssh exec");
	}
	if (close(fp[1]) == -1)
		err(1, "close write pipe");

	ssh_stream = fdopen(fp[0], "r");
	if (ssh_stream == NULL)
		err(1, "fdopen");
}

void
ssh_getpeername(char **addr, char **port)
{
	char *line, *str, **wp, *words[4];
	size_t n;
	ssize_t len;

	line = NULL;
	n = 0;
	len = getline(&line, &n, ssh_stream);
	if (len < 0) {
		if (ferror(ssh_stream))
			err(1, "getline sockname");
		else
			errx(1, "getline sockname empty");
	}
	if (len > 0 && line[len-1] == '\n')
		line[len-1] = '\0';

	str = line;
	for (wp = &words[0]; wp < &words[4]; wp++)
		*wp = strsep(&str, " ");
	if (words[0] == NULL || strcmp("sockname:", words[0]) != 0)
		errx(1, "ssh no sockname: %s", line);
	if (words[1] == NULL)
		errx(1, "ssh no addr");
	if (addr != NULL) {
		*addr = strdup(words[1]);
		if (*addr == NULL)
			err(1, "strdup addr");
	}
	if (words[2] == NULL)
		errx(1, "ssh no port");
	if (port != NULL) {
		*port = strdup(words[2]);
		if (*port == NULL)
			err(1, "strdup port");
	}
	if (words[3] != NULL)
		errx(1, "ssh bad sockname: %s", words[3]);

	printf("peername: %s %s\n", words[1], words[2]);
	free(line);
}

void
ssh_wait(void)
{
	char *line;
	size_t n;
	ssize_t len;
	int status;

	line = NULL;
	n = 0;
	len = getline(&line, &n, ssh_stream);
	if (len < 0) {
		if (ferror(ssh_stream))
			err(1, "getline status");
		else
			errx(1, "getline status empty");
	}
	if (len > 0 && line[len-1] == '\n')
		line[len-1] = '\0';
	printf("%s\n", line);
	free(line);

	if (waitpid(ssh_pid, &status, 0) == -1)
		err(1, "waitpid");
	if (status != 0)
		errx(1, "ssh failed: %d", status);
}
