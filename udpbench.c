/*
 * Copyright (c) 2019-2022 Alexander Bluhm <bluhm@genua.de>
 * Copyright (c) 2022 Moritz Buhl <mbuhl@genua.de>
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

const char *progname, *hostname, *service = "12345", *remotessh;
int divert, hopbyhop;
long long bitrate;
int buffersize, mmsglen, repeat;
int timeout = 1;
const int timeout_idle = 1;
size_t udplength;
long packetrate;

void	udp_connect_send(void);
void	udp_bind_receive(void);
void	udp_socket_fork(int *,
	    int(*)(int, struct sockaddr *, socklen_t *),
	    int(*)(int, const struct sockaddr *, socklen_t));
void	alarm_handler(int);
int	udp_bind(int *, const char *, const char *);
int	udp_connect(int *, const char *, const char *);
void	udp_getsockname(int, char *, char *);
void	udp_setbuffersize(int, int, int);
void	udp_setrouteralert(int);
void	udp_send(int, int, unsigned long);
void	udp_receive(int, int);

struct mmsghdr	*mmsg_alloc(int, size_t, int);
void		 mmsg_free(struct mmsghdr *);

void print_status(const char *, unsigned long, unsigned long, unsigned long,
    int, const struct timeval *, const struct timeval *);
unsigned long udp2iplength(unsigned long, int, unsigned long *);
unsigned long udp2etherlength(unsigned long , int, int);

pid_t	ssh_bind(FILE **, const char *, const char *);
pid_t	ssh_connect(FILE **, const char *, const char *);
pid_t	ssh_pipe(FILE **, char **);
void	ssh_getpeername(FILE *, char *, char *);
void	ssh_wait(pid_t, FILE *);

static void
usage(void)
{
	fprintf(stderr, "usage: udpbench [-DH] [-B bitrate] [-b bufsize] "
	    "[-l length] [-m mmsglen] [-N repeat] [-P packetrate] [-p port] "
	    "[-R remoteprog] [-r remotessh] [-t timeout] send|recv [hostname]\n"
	    "    -B bitrate     bits per seconds send rate\n"
	    "    -b bufsize     set size of send or receive buffer\n"
	    "    -D             use pf divert packet for receive\n"
	    "    -H             send hop-by-hop router alert option\n"
	    "    -l length      set length of udp payload\n"
	    "    -m mmsglen     number of mmsghdr for sendmmsg or recvmmsg\n"
	    "    -N repeat      run parallel process with incremented address\n"
	    "    -P packetrate  packets per second send rate\n"
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
	int ch, sendmode;

	progname = argv[0];

	if (setvbuf(stdout, NULL, _IOLBF, 0) != 0)
		err(1, "setvbuf");

	while ((ch = getopt(argc, argv, "B:b:DHl:m:N:P:p:R:r:t:")) != -1) {
		switch (ch) {
		case 'B':
			bitrate = strtonum(optarg, 0, LLONG_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "bits per second rate is %s: %s",
				    errstr, optarg);
			break;
		case 'b':
			buffersize = strtonum(optarg, 0, INT_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "buffer size is %s: %s",
				    errstr, optarg);
			break;
		case 'D':
			divert = 1;
			break;
		case 'H':
			hopbyhop = 1;
			break;
		case 'l':
			udplength = strtonum(optarg, 0, IP_MAXPACKET, &errstr);
			if (errstr != NULL)
				errx(1, "payload length is %s: %s",
				    errstr, optarg);
			break;
		case 'm':
			mmsglen = strtonum(optarg, 0, 1024, &errstr);
			if (errstr != NULL)
				errx(1, "msghdr size is %s: %s",
				    errstr, optarg);
			break;
		case 'N':
			repeat = strtonum(optarg, 0, 1000, &errstr);
			if (errstr != NULL)
				errx(1, "repeat number is %s: %s",
				    errstr, optarg);
			break;
		case 'P':
			packetrate = strtonum(optarg, 0, LONG_MAX, &errstr);
			if (errstr != NULL)
				errx(1, "packets per second rate is %s: %s",
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

	if (bitrate && packetrate)
		errx(1, "either bitrate or packetrate may be given");
	if (!sendmode && remotessh == NULL && (bitrate || packetrate))
		errx(1, "bitrate or packetrate only allowed for send");
	if (sendmode && remotessh == NULL && divert)
		errx(1, "divert only allowed for receive");
	if (!sendmode && remotessh == NULL && hopbyhop)
		errx(1, "hopbyhop only allowed for send");

#ifdef __OpenBSD__
	if (sendmode && hopbyhop) {
		;
	} else if (remotessh != NULL) {
		if (pledge("stdio dns inet proc exec", NULL) == -1)
			err(1, "pledge");
	} else if (repeat) {
		if (pledge("stdio dns inet proc", NULL) == -1)
			err(1, "pledge");
	} else {
		if (pledge("stdio dns inet", NULL) == -1)
			err(1, "pledge");
	}
#endif

	memset(&act, 0, sizeof(act));
	act.sa_handler = alarm_handler;
	act.sa_flags = SA_RESETHAND;
	if (sigaction(SIGALRM, &act, NULL) == -1)
		err(1, "sigaction");

	if (sendmode)
		udp_connect_send();
	else
		udp_bind_receive();

	return 0;
}

void
udp_connect_send(void)
{
	const char *remotehost, *remoteserv;
	char remoteaddr[NI_MAXHOST], remoteport[NI_MAXSERV];
	char localaddr[NI_MAXHOST], localport[NI_MAXSERV];
	long sendrate;
	int udp_socket, udp_family = AF_UNSPEC;
	FILE *ssh_stream;
	pid_t ssh_pid;

	remotehost = hostname;
	remoteserv = service;
	if (remotessh != NULL) {
		ssh_pid = ssh_bind(&ssh_stream, remotehost, remoteserv);
#ifdef __OpenBSD__
		if (hopbyhop) {
			;
		} else if (repeat) {
			if (pledge("stdio dns inet proc", NULL) == -1)
				err(1, "pledge");
		} else {
			if (pledge("stdio dns inet", NULL) == -1)
				err(1, "pledge");
		}
#endif
		ssh_getpeername(ssh_stream, remoteaddr, remoteport);
		if (!divert) {
			remotehost = remoteaddr;
			remoteserv = remoteport;
		}
	}
	udp_socket = udp_connect(&udp_family, remotehost, remoteserv);
	udp_getsockname(udp_socket, localaddr, localport);
	if (repeat > 0) {
		udp_socket_fork(&udp_socket, getpeername, connect);
		if (udp_socket == -1) {
			if (remotessh != NULL)
				ssh_wait(ssh_pid, ssh_stream);
			return;
		}
	}
	if (buffersize)
		udp_setbuffersize(udp_socket, SO_SNDBUF, buffersize);
	if (hopbyhop) {
		if (udp_family != AF_INET6)
			errx(1, "hopbyhop only allowed with IPv6");
		udp_setrouteralert(udp_socket);
#ifdef __OpenBSD__
		if (pledge("stdio dns inet", NULL) == -1)
			err(1, "pledge");
#endif
	}
	if (bitrate) {
		unsigned long etherlen;

		etherlen = udp2etherlength(udplength, udp_family, 0);
		sendrate = bitrate / 8 / etherlen;
		if (sendrate == 0)
			errx(1, "bitrate %llu too small for ether %lu",
			    bitrate, etherlen);
	} else
		sendrate = packetrate;
	if (timeout > 0)
		alarm(timeout);
	udp_send(udp_socket, udp_family, sendrate);
	if (close(udp_socket) == -1)
		err(1, "close");
	if (repeat == 0 && remotessh != NULL)
		ssh_wait(ssh_pid, ssh_stream);
}

void
udp_bind_receive(void)
{
	const char *localhost, *localserv;
	char localaddr[NI_MAXHOST], localport[NI_MAXSERV];
	char remoteaddr[NI_MAXHOST], remoteport[NI_MAXSERV];
	int udp_socket, udp_family = AF_UNSPEC;
	FILE *ssh_stream;
	pid_t ssh_pid;

	localhost = hostname;
	localserv = service;
	udp_socket = udp_bind(&udp_family, localhost, localserv);
	udp_getsockname(udp_socket, localaddr, localport);
	if (!divert) {
		localhost = localaddr;
		localserv = localport;
	}
	if (repeat > 0) {
		udp_socket_fork(&udp_socket, getsockname, bind);
	}
	if ((repeat == 0 || udp_socket == -1) && remotessh != NULL) {
		ssh_pid = ssh_connect(&ssh_stream, localhost, localserv);
#ifdef __OpenBSD__
		if (repeat) {
			if (pledge("stdio dns inet proc", NULL) == -1)
				err(1, "pledge");
		} else {
			if (pledge("stdio dns inet", NULL) == -1)
				err(1, "pledge");
		}
#endif
		ssh_getpeername(ssh_stream, remoteaddr, remoteport);
	}
	if (repeat > 0) {
		if (udp_socket == -1) {
			if (remotessh != NULL)
				ssh_wait(ssh_pid, ssh_stream);
			return;
		}
	}
	if (buffersize)
		udp_setbuffersize(udp_socket, SO_RCVBUF, buffersize);
	if (timeout > 0)
		alarm(timeout + 4);
	udp_receive(udp_socket, udp_family);
	if (close(udp_socket) == -1)
		err(1, "close");
	if (repeat == 0 && remotessh != NULL)
		ssh_wait(ssh_pid, ssh_stream);
}

void
udp_socket_fork(int *sock,
    int(*getname)(int, struct sockaddr *, socklen_t *),
    int(*setname)(int, const struct sockaddr *, socklen_t))
{
	struct sockaddr_storage ss;
	socklen_t sslen;
	int n;

	sslen = sizeof(ss);
	if (getname(*sock, (struct sockaddr *)&ss, &sslen) == -1)
		err(1, "getname");

	for (n = repeat; n > 0; n--) {
		switch (fork()) {
		case -1:
			err(1, "fork");
		default: {
			/* parent */
			char localaddr[NI_MAXHOST], localport[NI_MAXSERV];

			if (close(*sock) == -1)
				err(1, "close %d", n);
			*sock = -1;

			if (n == 1) {
				for (n = repeat;  n > 0; n--) {
					int status;

					if (wait(&status) == -1)
						err(1, "wait");
					if (status != 0)
						errx(1, "status: %d", status);
				}
				return;
			}

			switch (ss.ss_family) {
				struct sockaddr_in *sin;
				struct sockaddr_in6 *sin6;

			case AF_INET:
				sin = (struct sockaddr_in *)&ss;
				((uint8_t *)&sin->sin_addr.s_addr)[3]++;
				break;
			case AF_INET6:
				sin6 = (struct sockaddr_in6 *)&ss;
				((uint8_t *)&sin6->sin6_addr.s6_addr)[15]++;
				break;
			}
			*sock = socket(ss.ss_family, SOCK_DGRAM, IPPROTO_UDP);
			if (*sock == -1)
				err(1, "socket %d", n);
			if (setname(*sock, (struct sockaddr *)&ss, sslen) == -1)
				err(1, "setname %d", n);
			udp_getsockname(*sock, localaddr, localport);
		}
		case 0:
			/* child */
#ifdef __OpenBSD__
			if (pledge("stdio dns inet", NULL) == -1)
				err(1, "pledge");
#endif
			n = 0;
			break;
		}
	}
}

void
alarm_handler(int sig)
{
	alarm_signaled = 1;
}

int
udp_bind(int *udp_family, const char *host, const char *serv)
{
	struct addrinfo hints, *res, *res0;
	int error, udp_socket;
	int save_errno;
	const char *cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = *udp_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_PASSIVE;
	error = getaddrinfo(host, serv, &hints, &res0);
	if (error)
		errx(1, "getaddrinfo: %s", gai_strerror(error));
	udp_socket = -1;
	for (res = res0; res; res = res->ai_next) {
		if (divert) {
			/* pf divert packet uses raw socket */
			res->ai_socktype = SOCK_RAW;
#ifdef IPPROTO_DIVERT
			res->ai_protocol = IPPROTO_DIVERT;
#else
			errx(1, "IPPROTO_DIVERT not defined");
#endif
		}
		udp_socket = socket(res->ai_family, res->ai_socktype,
		    res->ai_protocol);
		if (udp_socket == -1) {
			cause = "socket";
			continue;
		}

		if (divert) {
			/* divert packet socket is bound to port only */
			if (res->ai_family == AF_INET) {
				struct sockaddr_in *sin;

				sin = (struct sockaddr_in *)res->ai_addr;
				memset(&sin->sin_addr, 0,
				    sizeof(struct in_addr));
				if (sin->sin_port == 0)
					errx(1, "divert needs bind port");
			}
			if (res->ai_family == AF_INET) {
				struct sockaddr_in6 *sin6;

				sin6 = (struct sockaddr_in6 *)res->ai_addr;
				memset(&sin6->sin6_addr, 0,
				    sizeof(struct in6_addr));
				if (sin6->sin6_port == 0)
					errx(1, "divert needs bind port");
			}
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
	*udp_family = res->ai_family;
	freeaddrinfo(res0);
	return udp_socket;
}

int
udp_connect(int *udp_family, const char *host, const char *serv)
{
	struct addrinfo hints, *res, *res0;
	int error, udp_socket;
	int save_errno;
	const char *cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = *udp_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo(host, serv, &hints, &res0);
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
	*udp_family = res->ai_family;
	freeaddrinfo(res0);
	return udp_socket;
}

void
udp_getsockname(int udp_socket, char *addr, char *port)
{
	struct sockaddr_storage ss;
	socklen_t sslen;
	int error;

	sslen = sizeof(ss);
	if (getsockname(udp_socket, (struct sockaddr *)&ss, &sslen) == -1)
		err(1, "getsockname");

	error = getnameinfo((struct sockaddr *)&ss, sslen, addr, NI_MAXHOST,
	    port, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV | NI_DGRAM);
	if (error)
		errx(1, "getnameinfo: %s", gai_strerror(error));

	printf("sockname: %s %s\n", addr, port);
}

void
udp_setbuffersize(int udp_socket, int name, int size)
{
	socklen_t len;

	len = sizeof(size);
	if (setsockopt(udp_socket, SOL_SOCKET, name, &size, len) == -1)
		err(1, "setsockopt buffer size %d", size);

}

void
udp_setrouteralert(int udp_socket)
{
	struct {
		struct ip6_hbh		hbh;
		struct ip6_opt_router	ra;
		u_char			pad[2];
	} opts;
	socklen_t len;

	opts.hbh.ip6h_nxt = IPPROTO_UDP;
	opts.hbh.ip6h_len = (sizeof(opts) - 1) / 8;
	opts.ra.ip6or_type = IP6OPT_ROUTER_ALERT;
	opts.ra.ip6or_len = sizeof(opts.ra) - 2;
	*(uint16_t *)opts.ra.ip6or_value = IP6_ALERT_AN;
	opts.pad[0] = IP6OPT_PAD1;
	opts.pad[1] = IP6OPT_PAD1;
	len = sizeof(opts);
	if (setsockopt(udp_socket, IPPROTO_IPV6, IPV6_HOPOPTS, &opts, len)
	    == -1)
		err(1, "setsockopt router alert");
}

struct mmsghdr *
mmsg_alloc(int packets, size_t paylen, int fill)
{
	struct mmsghdr *mmsg, *mhdr;
	struct iovec *iov;
	char *payload;

	if ((mmsg = calloc(packets, sizeof(struct mmsghdr))) == NULL)
		err(1, "calloc mmsghdr");

	if ((iov = calloc(packets, sizeof(struct iovec))) == NULL)
		err(1, "calloc iovec");

	if ((payload = calloc(packets, paylen)) == NULL)
		err(1, "calloc payload");
	if (fill)
		arc4random_buf(payload, packets * paylen);

	mhdr = mmsg;
	while (packets > 0) {
		mhdr->msg_hdr.msg_iov = iov;
		mhdr->msg_hdr.msg_iovlen = 1;
		iov->iov_base = payload;
		iov->iov_len = paylen;

		mhdr++;
		iov++;
		payload += paylen;
		packets--;
	}

	return mmsg;
}

void
mmsg_free(struct mmsghdr *mmsg)
{
	free(mmsg->msg_hdr.msg_iov->iov_base);
	free(mmsg->msg_hdr.msg_iov);
	free(mmsg);
}

void
udp_send(int udp_socket, int udp_family, unsigned long sendrate)
{
	struct timeval begin, end, duration;
	struct timespec wait;
	unsigned long syscall, packet;
	struct mmsghdr *mmsg;
	char *payload;
	size_t udplen;
	ssize_t sndlen;
	int pkts;

	udplen = udplength;
	if (mmsglen) {
		mmsg = mmsg_alloc(mmsglen, udplen, 1);
	} else {
		pkts = 1;
		if ((payload = malloc(udplen)) == NULL)
			err(1, "malloc payload");
		arc4random_buf(payload, udplen);
	}

	if (gettimeofday(&begin, NULL) == -1)
		err(1, "gettimeofday begin");
	timerclear(&end);

	syscall = 0;
	packet = 0;
	sndlen = 0;
	while (!alarm_signaled) {
		syscall++;
		if (mmsglen)
			pkts = sendmmsg(udp_socket, mmsg, mmsglen, 0);
		else
			sndlen = send(udp_socket, payload, udplen, 0);
		if (pkts == -1 || sndlen == -1) {
			if (errno == ENOBUFS || errno == EINTR)
				continue;
			err(1, "send");
		}
		packet += pkts;
		if (sendrate) {
			double expectduration, waittime;

			if (!timerisset(&end)) {
				if (gettimeofday(&end, NULL) == -1)
					err(1, "gettimeofday delay");
			}
			timersub(&end, &begin, &duration);
			if (!timerisset(&duration))
				duration.tv_usec = 1;
			expectduration = (double)packet / (double)sendrate;
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
	print_status("send", syscall, packet, udplen, udp_family, &begin, &end);
	if (mmsglen)
		mmsg_free(mmsg);
	else
		free(payload);
}

void
udp_receive(int udp_socket, int udp_family)
{
	struct timeval begin, idle, end, timeo;
	unsigned long syscall, packet;
	unsigned long headerlen, paylen;
	struct mmsghdr *mmsg;
	char *payload;
	size_t udplen;
	ssize_t rcvlen;
	socklen_t len;
	int pkts;

	udplen = udplength;
	if (divert) {
		headerlen = sizeof(struct udphdr);
		if (udp_family == AF_INET)
			headerlen += sizeof(struct ip);
		if (udp_family == AF_INET6)
			headerlen += sizeof(struct ip6_hdr);
		udplen += headerlen;
	}
	if (mmsglen)
		mmsg = mmsg_alloc(mmsglen, udplen + 1, 0);
	else
		pkts = 1;
	if ((payload = malloc(udplen + 1)) == NULL)
		err(1, "malloc payload");

	/* wait for the first packet to start timing */
	rcvlen = recv(udp_socket, payload, udplen + 1, 0);
	if (rcvlen == -1)
		err(1, "recv 1");
	paylen = rcvlen;
	if (paylen < udplen)
		warnx("receive packet truncated %zd", rcvlen);
	if (paylen > udplen)
		warnx("receive packet oversized %zd", rcvlen);
	if (divert) {
		if (paylen < headerlen)
			errx(1, "receive length %zd too short for header",
			    rcvlen);
		paylen -= headerlen;
	}

	if (gettimeofday(&begin, NULL) == -1)
		err(1, "gettimeofday begin");
	timerclear(&idle);

	timeo.tv_sec = timeout_idle;
	timeo.tv_usec = 0;
	len = sizeof(timeo);
	if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, &timeo, len) == -1)
		err(1, "setsockopt recv timeout");

	syscall = 1;
	packet = 1;
	while (!alarm_signaled) {
		syscall++;
		if (mmsglen)
			pkts = recvmmsg(udp_socket, mmsg, mmsglen, 0, NULL);
		else
			rcvlen = recv(udp_socket, payload, udplen + 1, 0);
		if (pkts == -1 || rcvlen == -1) {
			if (errno == EWOULDBLOCK) {
				if (gettimeofday(&idle, NULL) == -1)
					err(1, "gettimeofday idle");
				/* packet was seen before timeout */
				timersub(&idle, &timeo, &idle);
				break;
			}
			if (errno == EINTR)
				continue;
			err(1, "recv");
		}
		packet += pkts;
	}

	if (gettimeofday(&end, NULL) == -1)
		err(1, "gettimeofday end");
	if (timerisset(&idle)) {
		struct timeval tmp;

		tmp = end;
		/* last packet was seen at idle time */
		end = idle;
		/* new idle is duration without packets */
		timersub(&tmp, &idle, &idle);
	}
	print_status("recv", syscall, packet, paylen, udp_family, &begin, &end);
	if (idle.tv_sec < 1)
		errx(1, "not enough idle time: %lld.%06ld",
		    (long long)idle.tv_sec, idle.tv_usec);
	if (mmsglen)
		mmsg_free(mmsg);
	free(payload);
}

void
print_status(const char *action, unsigned long syscall, unsigned long packet,
    unsigned long paylen, int af, const struct timeval *begin,
    const struct timeval *end)
{
	struct timeval duration;
	unsigned long frame, iplen, etherlen;
	double bits;

	iplen = udp2iplength(paylen, af, &frame);
	etherlen = udp2etherlength(paylen, af, 0);
	bits = (double)packet * etherlen * 8;
	timersub(end, begin, &duration);
	bits /= (double)duration.tv_sec + (double)duration.tv_usec / 1000000;
	printf("%s: syscalls %lu, packets %lu, frame %lu, payload %lu, "
	    "ip %lu, ether %lu, begin %lld.%06ld, end %lld.%06ld, "
	    "duration %lld.%06ld, bit/s %g\n",
	    action, syscall, packet, frame, paylen, iplen, etherlen,
	    (long long)begin->tv_sec, begin->tv_usec,
	    (long long)end->tv_sec, end->tv_usec,
	    (long long)duration.tv_sec, duration.tv_usec, bits);
}

unsigned long
udp2iplength(unsigned long payload, int af, unsigned long *packets)
{
	unsigned long iplength;

	/* IPv4 header */
	if (af == AF_INET)
		iplength = 20;
	/* IPv6 header */
	if (af == AF_INET6)
		iplength = 40;
	/* UDP header, payload */
	iplength += 8 + payload;

	/* maximum ethernet payload */
	if (iplength > 1500) {
		if (af == AF_INET) {
			/* length without IPv4 header, align to fragment */
			*packets = (iplength - 20) / ((1500 - 20) & ~7);
			/* final fragment */
			iplength = (iplength - 20) % ((1500 - 20) & ~7);
			if (iplength == 0) {
				/* full sized fragments */
				iplength = *packets * (((1500 - 20) & ~7) + 20);
			} else {
				/* final fragment header, full fragments */
				iplength += 20 +
				    (*packets * (((1500 - 20) & ~7) + 20));
				++*packets;
			}
		}
		if (af == AF_INET6) {
			/* length without IPv6, fragement header, alignment */
			*packets = (iplength - 40) / ((1500 - 40 - 8) & ~7);
			/* final fragment */
			iplength = (iplength - 40) % ((1500 - 40 - 8) & ~7);
			if (iplength == 0) {
				/* full sized fragments */
				iplength = *packets * (1500 & ~7);
			} else {
				/* final fragment header, full fragments */
				iplength += 40 + 8 + (*packets * (1500 & ~7));
				++*packets;
			}
		}
	} else
		*packets = 1;

	return iplength;
}

unsigned long
udp2etherlength(unsigned long payload, int af, int vlan)
{
	unsigned long packetlength, fragmentlength;
	unsigned long framelength, frames, padding;

	packetlength = udp2iplength(payload, af, &frames);

	/* https://en.wikipedia.org/wiki/Ethernet_frame */

	/* destination MAC, source MAC, EtherType */
	framelength = 6 + 6 + 2;
	/* TPID, VLAN */
	if (vlan)
		framelength += 4;
	/* frame check sequence */
	framelength += 4;

	/* minimum frame transmission */
	if (af == AF_INET)
		fragmentlength = ((1500 - 20) & ~7) + 20;
	if (af == AF_INET6)
		fragmentlength = 1500 & ~7;  /* 40 + 8 divisible by 8 */
	if (framelength + packetlength < 64) {
		padding = 64 - framelength - packetlength;
	} else if (packetlength > 1500 &&
	    framelength + (packetlength % fragmentlength) < 64) {
		padding = 64 - framelength - (packetlength % fragmentlength);
	} else {
		padding = 0;
	}

	/* preamble, start frame delimiter */
	framelength += 7 + 1;
	/* interpacket gap */
	framelength += 12;

	framelength *= frames;
	/* ip headers, fragment overhead, udp header, payload, ether padding */
	framelength += packetlength + padding;

	return framelength;
}

pid_t
ssh_bind(FILE **ssh_stream, const char *host, const char *serv)
{
	char *argv[20];
	size_t i = 0;
	pid_t ssh_pid;

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
	argv[i++] = "-m";
	if (asprintf(&argv[i++], "%d", mmsglen) == -1)
		err(1, "asprintf mmsg length");
	argv[i++] = "-N";
	if (asprintf(&argv[i++], "%d", repeat) == -1)
		err(1, "asprintf repeat");
	argv[i++] = "-p";
	argv[i++] = (char *)serv;
	argv[i++] = "-t";
	if (asprintf(&argv[i++], "%d", timeout) == -1)
		err(1, "asprintf timeout");
	if (divert)
		argv[i++] = "-D";
	argv[i++] = "recv";
	argv[i++] = (char *)host;
	argv[i++] = NULL;

	assert(i <= sizeof(argv) / sizeof(argv[0]));

	ssh_pid = ssh_pipe(ssh_stream, argv);

	free(argv[5]);
	free(argv[7]);
	free(argv[9]);
	free(argv[11]);
	free(argv[15]);
	return ssh_pid;
}

pid_t
ssh_connect(FILE **ssh_stream, const char *host, const char *serv)
{
	char *argv[24];
	size_t i = 0;
	pid_t ssh_pid;

	argv[i++] = "ssh";
	argv[i++] = "-nT";
	argv[i++] = (char *)remotessh;
	argv[i++] = (char *)progname;
	argv[i++] = "-B";
	if (asprintf(&argv[i++], "%lld", bitrate) == -1)
		err(1, "asprintf bit rate");
	argv[i++] = "-b";
	if (asprintf(&argv[i++], "%d", buffersize) == -1)
		err(1, "asprintf buffer size");
	argv[i++] = "-l";
	if (asprintf(&argv[i++], "%zu", udplength) == -1)
		err(1, "asprintf udp length");
	argv[i++] = "-m";
	if (asprintf(&argv[i++], "%d", mmsglen) == -1)
		err(1, "asprintf mmsg length");
	argv[i++] = "-N";
	if (asprintf(&argv[i++], "%d", repeat) == -1)
		err(1, "asprintf repeat");
	argv[i++] = "-P";
	if (asprintf(&argv[i++], "%ld", packetrate) == -1)
		err(1, "asprintf packet rate");
	argv[i++] = "-p";
	argv[i++] = (char *)serv;
	argv[i++] = "-t";
	if (asprintf(&argv[i++], "%d", timeout) == -1)
		err(1, "asprintf timeout");
	if (hopbyhop)
		argv[i++] = "-H";
	argv[i++] = "send";
	argv[i++] = (char *)host;
	argv[i++] = NULL;

	assert(i <= sizeof(argv) / sizeof(argv[0]));

	ssh_pid = ssh_pipe(ssh_stream, argv);

	free(argv[5]);
	free(argv[7]);
	free(argv[9]);
	free(argv[11]);
	free(argv[13]);
	free(argv[15]);
	free(argv[19]);
	return ssh_pid;
}

pid_t
ssh_pipe(FILE **ssh_stream, char *argv[])
{
	int fp[2];
	pid_t ssh_pid;

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

	if ((*ssh_stream = fdopen(fp[0], "r")) == NULL)
		err(1, "fdopen");
	return ssh_pid;
}

void
ssh_getpeername(FILE *ssh_stream, char *addr, char *port)
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
	strlcpy(addr, words[1], NI_MAXHOST);
	if (words[2] == NULL)
		errx(1, "ssh no port");
	strlcpy(port, words[2], NI_MAXSERV);
	if (words[3] != NULL)
		errx(1, "ssh bad sockname: %s", words[3]);

	printf("peername: %s %s\n", addr, port);
	free(line);
}

void
ssh_wait(pid_t ssh_pid, FILE *ssh_stream)
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
	if (fclose(ssh_stream) == EOF)
		err(1, "fclose");

	if (waitpid(ssh_pid, &status, 0) == -1)
		err(1, "waitpid");
	if (status != 0)
		errx(1, "ssh failed: %d", status);
}
