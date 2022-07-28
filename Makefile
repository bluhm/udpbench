PROG=		udpbench
NOMAN=		yes
WARNINGS=	yes
PREFIX?=	/usr/local
BINDIR?=	${PREFIX}/bin

VERSION=	1.0

.PHONY: tgz udpbench-${VERSION}.tar.gz
tgz: udpbench-${VERSION}.tar.gz

udpbench-${VERSION}.tar.gz:
	tar -C ${.CURDIR} -czvf $@ \
	    README LICENSE Changes Makefile GNUmakefile udpbench.c

.include <bsd.prog.mk>
