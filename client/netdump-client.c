/*-
 * Copyright (c) 2017 Dell EMC
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/netdump/netdump.h>

#include <err.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void
usage(void)
{

	fprintf(stderr, "usage: %s [-c <addr>] [-p <path>] <file>\n",
	    getprogname());
	exit(1);
}

static void
sendndmsg(int sd, const struct sockaddr_in *sin,
    const struct netdump_msg_hdr *ndmsg)
{
	ssize_t len;

	len = sizeof(*ndmsg) + ntohl(ndmsg->mh_len);
	if (sendto(sd, ndmsg, len, 0, (const struct sockaddr *)sin,
	    sizeof(*sin)) != len)
		err(1, "sendto");
}

static void
waitack(int sd, uint32_t seqno)
{
	struct netdump_ack ack;
	uint32_t got;

	if (recv(sd, &ack, sizeof(ack), 0) != sizeof(ack))
		err(1, "recv");
	got = ntohl(ack.na_seqno);
	if (got != seqno)
		warnx("unexpected seqno %u, wanted %u", got, seqno);
}

int
main(int argc, char **argv)
{
	char buf[BUFSIZ];
	struct addrinfo hints, *res;
	struct msghdr msg;
	struct netdump_ack ack;
	struct netdump_msg_hdr ndmsg, *ndmsgp;
	struct sockaddr_in sin;
	struct stat sb;
	char *addr, *path;
	ssize_t off, r;
	size_t pathsz;
	uint32_t seqno;
	int ch, error, fd, sd;

	addr = path = NULL;
	while ((ch = getopt(argc, argv, "c:p:")) != -1) {
		switch (ch) {
		case 'c':
			addr = strdup(optarg);
			break;
		case 'p':
			path = strdup(optarg);
			break;
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;
	if (argc != 1)
		usage();

	if (addr == NULL)
		addr = strdup("127.0.0.1");
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(addr, NULL, &hints, &res);
	if (error != 0)
		errx(1, "%s", gai_strerror(error));
	if (res == NULL || res->ai_addr->sa_family != AF_INET)
		errx(1, "failed to look up '%s'", addr);

	fd = open(argv[0], O_RDONLY);
	if (fd < 0)
		err(1, "opening %s", argv[0]);
	if (fstat(fd, &sb) != 0)
		err(1, "failed to stat %s", argv[0]);
	if (!S_ISREG(sb.st_mode))
		errx(1, "input file must be a regular file");

	sd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sd < 0)
		err(1, "socket");

	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(NETDUMP_ACKPORT);
	sin.sin_addr.s_addr = INADDR_ANY;
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) != 0)
		err(1, "bind");

	sin.sin_port = htons(NETDUMP_PORT);
	sin.sin_addr.s_addr =
	    ((struct sockaddr_in *)(void *)res->ai_addr)->sin_addr.s_addr;
	if (sin.sin_addr.s_addr == INADDR_NONE)
		errx(1, "invalid address '%s'", addr);

	pathsz = (path != NULL ? strlen(path) + 1 : 0);
	ndmsgp = malloc(sizeof(*ndmsgp) + pathsz);
	if (ndmsgp == NULL)
		err(1, "malloc");
	memset(ndmsgp, 0, sizeof(*ndmsgp));
	ndmsgp->mh_type = htonl(NETDUMP_HERALD);
	ndmsgp->mh_len = htonl((uint32_t)pathsz);
	if (path != NULL)
		strcpy((char *)(ndmsgp + 1), path);
	sendndmsg(sd, &sin, ndmsgp);

	/*
	 * The server uses the first ACK to tell us which port it'll use for the
	 * duration of the transfer. We thus need to use recvmsg(2) to grab the
	 * srcaddr of the first ACK.
	 */
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = &sin;
	msg.msg_namelen = sizeof(sin);
	msg.msg_iov = malloc(sizeof(*msg.msg_iov));
	msg.msg_iov[0].iov_base = &ack;
	msg.msg_iov[0].iov_len = sizeof(ack);
	msg.msg_iovlen = 1;
	if (recvmsg(sd, &msg, 0) != sizeof(ack))
		err(1, "recvmsg");
	seqno = ack.na_seqno;

	/* Now we can transfer the file. */
	ndmsgp = (struct netdump_msg_hdr *)buf;
	for (off = r = 0; (r = read(fd, buf + sizeof(*ndmsgp),
	    sizeof(buf) - sizeof(*ndmsgp))) > 0; off += r) {
		ndmsgp->mh_type = htonl(NETDUMP_VMCORE);
		ndmsgp->mh_seqno = htonl(++seqno);
		ndmsgp->mh_offset = htobe64(off);
		ndmsgp->mh_len = htonl((uint32_t)r);
		sendndmsg(sd, &sin, ndmsgp);
		waitack(sd, seqno);
	}

	/* All done. */
	memset(&ndmsg, 0, sizeof(ndmsg));
	ndmsg.mh_type = htonl(NETDUMP_FINISHED);
	sendndmsg(sd, &sin, &ndmsg);
	waitack(sd, 0);

	(void)close(fd);
	(void)close(sd);
	free(addr);
	free(path);
	free(msg.msg_iov);

	return (0);
}
