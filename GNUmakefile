CFLAGS=		-D_DEFAULT_SOURCE -D_GNU_SOURCE \
		-DLIBBSD_OVERLAY -isystem /usr/include/bsd \
		-isystem /usr/local/include/bsd \
		-Wall
LDFLAGS=	-lbsd
BINDIR?=        /usr/local/bin
MANDIR?=        /usr/local/man/man

all:	udpbench

clean:
	rm -f udpbench udpbench.o

install:
	install -c -m 555 -s udpbench ${DESTDIR}${BINDIR}
	install -c -m 444 udpbench.1 ${DESTDIR}${MANDIR}1
