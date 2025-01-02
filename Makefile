PROG=		udpbench
WARNINGS=	yes
BINDIR?=	/usr/local/bin
MANDIR?=        /usr/local/man/man

VERSION=	1.12
CLEANFILES=	udpbench-${VERSION}.tar.gz*

.PHONY: dist udpbench-${VERSION}.tar.gz
dist: udpbench-${VERSION}.tar.gz
	gpg --armor --detach-sign udpbench-${VERSION}.tar.gz
	@echo ${.OBJDIR}/udpbench-${VERSION}.tar.gz

udpbench-${VERSION}.tar.gz:
	rm -rf udpbench-${VERSION}
	mkdir udpbench-${VERSION}
.for f in README LICENSE Changes Makefile GNUmakefile udpbench.c udpbench.1
	cp ${.CURDIR}/$f udpbench-${VERSION}/
.endfor
	tar -czvf $@ udpbench-${VERSION}
	rm -rf udpbench-${VERSION}

CLEANFILES+=	out

TEST =
TEST += localhost
test-localhost:
	@echo '\n==== $@ ===='
	./udpbench -p0 -t3 recv 127.0.0.1 | tee out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -p$$port -t1 send 127.0.0.1 || exit 1; \
	    wait $$!
	grep '^recv:' out

TEST += localhost6
test-localhost6:
	@echo '\n==== $@ ===='
	./udpbench -p0 -t3 recv ::1 | tee out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -p$$port -t1 send ::1 || exit 1; \
	    wait $$!
	grep '^recv:' out

TEST += mmsg
test-mmsg:
	@echo '\n==== $@ ===='
	./udpbench -m1024 -p0 -t3 recv 127.0.0.1 | tee out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -m1024 -p$$port -t1 send 127.0.0.1 || exit 1; \
	    wait $$!
	grep '^recv:' out

TEST += repeat
test-repeat:
	@echo '\n==== $@ ===='
	./udpbench -N1 -p0 -t3 recv 127.0.0.1 | tee out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -N1 -p$$port -t1 send 127.0.0.1 || exit 1; \
	    wait $$!
	grep '^recv:' out

TEST += mcast
test-mcast:
	@echo '\n==== $@ ===='
	./udpbench -I127.0.0.1 -p0 -t3 recv 224.0.0.123 | tee out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -I127.0.0.1 -L1 -T0 -p$$port -t1 \
	    send 224.0.0.123 || exit 1; \
	    wait $$!
	grep -q 'sockname: 224.0.0.123 ' out

TEST += mcast6
test-mcast6:
	@echo '\n==== $@ ===='
	./udpbench -Ilo0 -p0 -t3 recv ff04::123 | tee out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -Ilo0 -L1 -T0 -p$$port -t1 \
	    send ff04::123 || exit 1; \
	    wait $$!
	grep -q 'sockname: ff04::123 ' out

TEST += mcast-repeat
test-mcast-repeat:
	@echo '\n==== $@ ===='
	./udpbench -N2 -I127.0.0.1 -p0 -t3 recv 224.0.0.123 | tee out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out | sort -u`; \
	    ./udpbench -N2 -I127.0.0.1 -L1 -T0 -p$$port -t1 \
	    send 224.0.0.123 || exit 1; \
	    wait $$!
	grep -q 'sockname: 224.0.0.123 ' out
	grep -q 'sockname: 224.0.0.124 ' out

TEST += mcast6-repeat
test-mcast6-repeat:
	@echo '\n==== $@ ===='
	./udpbench -N2 -Ilo0 -p0 -t3 recv ff04::123 | tee out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out | sort -u`; \
	    ./udpbench -N2 -Ilo0 -L1 -T0 -p$$port -t1 \
	    send ff04::123 || exit 1; \
	    wait $$!
	grep -q 'sockname: ff04::123 ' out
	grep -q 'sockname: ff04::124 ' out

.PHONY: test ${TEST:S/^/test-/}
test: ${TEST:S/^/test-/}

.include <bsd.prog.mk>
