PROG=		udpbench
NOMAN=		yes
WARNINGS=	yes
BINDIR?=	/usr/local/bin

VERSION=	1.00
CLEANFILES=	udpbench-${VERSION}.tar.gz

.PHONY: dist udpbench-${VERSION}.tar.gz
dist: udpbench-${VERSION}.tar.gz

udpbench-${VERSION}.tar.gz:
	rm -rf udpbench-${VERSION}
	mkdir udpbench-${VERSION}
.for f in README LICENSE Changes Makefile GNUmakefile udpbench.c
	cp ${.CURDIR}/$f udpbench-${VERSION}/
.endfor
	tar -czvf $@ udpbench-${VERSION}
	rm -rf udpbench-${VERSION}

.include <bsd.prog.mk>
