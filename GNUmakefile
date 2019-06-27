CFLAGS=		-D_DEFAULT_SOURCE -D_GNU_SOURCE \
		-DLIBBSD_OVERLAY -isystem /usr/local/include/bsd \
		-Wall
LDFLAGS=	-lbsd

all:	udpbench

clean:
	rm -f udpbench udpbench.o

install:
	install -s udpbench /usr/local/bin/
