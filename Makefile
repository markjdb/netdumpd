# $FreeBSD$

PROG=	netdumpd
SRCS=	netdumpd.c	\
	cap_handler.c	\
	cap_herald.c
MAN=	netdumpd.8
BINDIR=	/usr/sbin

LDADD+=	-lcasper -lcap_dns -lnv -lutil

# Only for external build.
CFLAGS+= -I${.CURDIR}/. -O0

WARNS?=	6

# rc.d script.
FILES=	netdumpd
FILESMODE= 0555

.include <bsd.prog.mk>
