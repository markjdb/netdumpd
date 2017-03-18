# $FreeBSD$

PROG=	netdumpd
MAN=	netdumpd.8
BINDIR=	/usr/sbin

FILES=	netdumpd
FILESDIR= /etc/rc.d
FILESMODE= 0555

#LIBADD= util
LDADD+=	-lutil

# Only for external build.
CFLAGS+= -I.

.include <bsd.prog.mk>
