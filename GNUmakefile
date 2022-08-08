CFLAGS=		-D_DEFAULT_SOURCE -D_GNU_SOURCE \
		-DLIBBSD_OVERLAY -isystem /usr/include/bsd \
		-isystem /usr/local/include/bsd \
		-Wall
LDFLAGS=	-lbsd
BINDIR?=        /usr/local/bin
MANDIR?=        /usr/local/man/man

.PHONY: all clean install
all:	udpbench

udpbench: udpbench.c
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

clean:
	rm -f udpbench udpbench.o out

install:
	install -c -m 555 -s udpbench -D -t ${DESTDIR}${BINDIR}
	install -c -m 444 udpbench.1 -D -t ${DESTDIR}${MANDIR}1

.PHONY: test test-localhost test-localhost6
test: test-localhost test-localhost6

test-localhost:
	@echo -e '\n==== $@ ===='
	./udpbench -p 0 -t3 recv 127.0.0.1 >out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -p $$port -t1 send 127.0.0.1 || exit 1; \
	    wait $$!
	grep '^recv:' out

test-localhost6:
	@echo -e '\n==== $@ ===='
	./udpbench -p 0 -t3 recv ::1 >out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -p $$port -t1 send ::1 || exit 1; \
	    wait $$!
	grep '^recv:' out
