PROG=	netdumpd
SRCS=	netdumpd.c	\
	cap_dns.c	\
	cap_handler.c	\
	cap_herald.c
MAN=	netdumpd.8
BINDIR=	/usr/sbin

LDADD+=	-lcasper -lnv -lutil

CFLAGS+= -DWITH_CASPER

WARNS?=	6

# rc.d script.
SUBDIR+=	etc/rc.d

.include <bsd.prog.mk>
