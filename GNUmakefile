CFLAGS+=	-D_DEFAULT_SOURCE -D_GNU_SOURCE -Wall \
		$(shell pkgconf --cflags libbsd-overlay)
LDFLAGS+=	$(shell pkgconf --libs libbsd-overlay)
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

# use any multicast capable interface; as -L1 is set, test runs on loopback
INTERFACE =	$(shell ip route get ff04::123 | \
    sed 's/^.* dev \([a-z][a-z0-9]*\) .*$$/\1/')

TEST =
TEST += localhost
test-localhost:
	@echo -e '\n==== $@ ===='
	./udpbench -p0 -t3 recv 127.0.0.1 >out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -p$$port -t1 send 127.0.0.1 || exit 1; \
	    wait $$!
	grep -q 'recv: syscalls ' out

TEST += localhost6
test-localhost6:
	@echo -e '\n==== $@ ===='
	./udpbench -p0 -t3 recv ::1 >out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -p$$port -t1 send ::1 || exit 1; \
	    wait $$!
	grep -q 'recv: syscalls ' out

TEST += mmsg
test-mmsg:
	@echo -e '\n==== $@ ===='
	./udpbench -m1024 -p0 -t3 recv 127.0.0.1 >out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -m1024 -p$$port -t1 send 127.0.0.1 || exit 1; \
	    wait $$!
	grep -q 'recv: syscalls ' out

TEST += repeat
test-repeat:
	@echo -e '\n==== $@ ===='
	./udpbench -N1 -p0 -t3 recv 127.0.0.1 >out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -N1 -p$$port -t1 send 127.0.0.1 || exit 1; \
	    wait $$!
	grep -q 'recv: syscalls ' out

TEST += mcast
test-mcast:
	@echo -e '\n==== $@ ===='
	./udpbench -I127.0.0.1 -p0 -t3 recv 224.0.0.123 | tee out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -I127.0.0.1 -L1 -T0 -p$$port -t1 \
	    send 224.0.0.123 || exit 1; \
	    wait $$!
	grep -q 'sockname: 224.0.0.123 ' out
	grep -q 'recv: syscalls ' out

# XXX Linux fails to send on loopback, use any ethernet
TEST += mcast6
test-mcast6:
	@echo -e '\n==== $@ ===='
	./udpbench -I$(INTERFACE) -p0 -t3 recv ff04::123 | tee out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -I$(INTERFACE) -L1 -T0 -p$$port -t1 \
	    send ff04::123 || exit 1; \
	    wait $$!
	grep -q 'sockname: ff04::123 ' out
	grep -q 'recv: syscalls ' out

TEST += mcast-repeat
test-mcast-repeat:
	@echo -e '\n==== $@ ===='
	./udpbench -N2 -I127.0.0.1 -p0 -t3 recv 224.0.0.123 | tee out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out | sort -u`; \
	    ./udpbench -N2 -I127.0.0.1 -L1 -T0 -p$$port -t1 \
	    send 224.0.0.123 || exit 1; \
	    wait $$!
	grep -q 'sockname: 224.0.0.123 ' out
	grep -q 'sockname: 224.0.0.124 ' out
	grep -q 'recv: syscalls ' out

# XXX Linux fails to send on loopback, use any ethernet
TEST += mcast6-repeat
test-mcast6-repeat:
	@echo -e '\n==== $@ ===='
	./udpbench -N2 -I$(INTERFACE) -p0 -t3 recv ff04::123 | tee out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out | sort -u`; \
	    ./udpbench -N2 -I$(INTERFACE) -L1 -T0 -p$$port -t1 \
	    send ff04::123 || exit 1; \
	    wait $$!
	grep -q 'sockname: ff04::123 ' out
	grep -q 'sockname: ff04::124 ' out
	grep -q 'recv: syscalls ' out

TEST += write
test-write:
	@echo -e '\n==== $@ ===='
	./udpbench -p0 -t3 recv 127.0.0.1 >out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -p$$port -t1 -w send 127.0.0.1 || exit 1; \
	    wait $$!
	grep -q 'recv: syscalls ' out

TEST += gro
test-gro:
	@echo -e '\n==== $@ ===='
	./udpbench -p0 -l1470 -G -m1 -t3 recv 127.0.0.1 >out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -p$$port -t1 -l1470 -G -m1 send 127.0.0.1 || exit 1; \
	    wait $$!

.PHONY: test $(patsubst %,test-%,$(TEST))
test: $(patsubst %,test-%,$(TEST))
