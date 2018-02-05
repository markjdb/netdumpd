# $FreeBSD$

PROG=	netdumpd
SRCS=	netdumpd.c	\
	cap_handler.c	\
	cap_herald.c
MAN=	netdumpd.8
BINDIR=	/usr/sbin

LDADD+=	-lcasper -lcap_dns -lnv -lutil

CFLAGS+= -DWITH_CASPER -I${.CURDIR}

WARNS?=	6

# rc.d script.
SUBDIR+=	etc/rc.d

.include <bsd.prog.mk>
