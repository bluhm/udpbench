CFLAGS=		-D_DEFAULT_SOURCE -D_GNU_SOURCE \
		-DLIBBSD_OVERLAY -isystem /usr/include/bsd \
		-isystem /usr/local/include/bsd \
		-Wall
LDFLAGS=	-lbsd
BINDIR?=        /usr/local/bin

all:	udpbench

clean:
	rm -f udpbench udpbench.o

install:
	install -s udpbench ${DESTDIR}${BINDIR}
