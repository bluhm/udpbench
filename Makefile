PROG=		udpbench
WARNINGS=	yes
BINDIR?=	/usr/local/bin
MANDIR?=        /usr/local/man/man

VERSION=	1.07
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

.PHONY: test test-localhost test-localhost6 test-repeat
test: test-localhost test-localhost6 test-repeat

test-localhost:
	@echo '\n==== $@ ===='
	./udpbench -p0 -t3 recv 127.0.0.1 >out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -p $$port -t1 send 127.0.0.1 || exit 1; \
	    wait $$!
	grep '^recv:' out

test-localhost6:
	@echo '\n==== $@ ===='
	./udpbench -p0 -t3 recv ::1 >out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -p $$port -t1 send ::1 || exit 1; \
	    wait $$!
	grep '^recv:' out

test-repeat:
	@echo '\n==== $@ ===='
	./udpbench -N1 -p0 -t3 recv 127.0.0.1 >out & \
	    sleep 1; \
	    port=`awk '/^sockname:/{print $$3}' out`; \
	    ./udpbench -N1 -p $$port -t1 send 127.0.0.1 || exit 1; \
	    wait $$!
	grep '^recv:' out

.include <bsd.prog.mk>
