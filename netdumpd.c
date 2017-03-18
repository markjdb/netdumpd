/*-
 * Copyright (c) 2005-2011 Sandvine Incorporated. All rights reserved.
 * Copyright (c) 2016-2017 Dell EMC
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/kerneldump.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>

#include "netinet/netdump/netdump.h" /* XXX */

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libutil.h>

#define	MAX_DUMPS	256	/* Maximum saved dumps per remote host. */
#define	CLIENT_TIMEOUT	600	/* Netdump timeout period, in seconds. */
#define	CLIENT_TPASS	10	/* Scan for timed-out clients every 10s. */

#define	LOGERR(m, ...)							\
	(*g_phook)(LOG_ERR | LOG_DAEMON, (m), ## __VA_ARGS__)
#define	LOGERR_PERROR(m)						\
	(*g_phook)(LOG_ERR | LOG_DAEMON, "%s: %s\n", m, strerror(errno))
#define	LOGINFO(m, ...)							\
	(*g_phook)(LOG_INFO | LOG_DAEMON, (m), ## __VA_ARGS__)
#define	LOGWARN(m, ...)							\
	(*g_phook)(LOG_WARNING | LOG_DAEMON, (m), ## __VA_ARGS__)

#define	client_ntoa(cl)							\
	inet_ntoa((cl)->ip)
#define	client_pinfo(cl, f, ...)					\
	fprintf((cl)->infofile, (f), ## __VA_ARGS__)

struct netdump_pkt {
	struct netdump_msg_hdr hdr;
	uint8_t		data[NETDUMP_DATASIZE];
} __packed;

struct netdump_msg {
	struct msghdr	nm_msg;		/* recvmsg(2) header */

	struct sockaddr_in *nm_src;	/* src addr */
	struct sockaddr_storage nm_ss;	/* src addr storage */
	struct in_addr	*nm_dst;	/* dst IP */
	struct cmsghdr	*nm_cmsg;	/* control msg for dst IP */

	struct iovec	nm_iov;		/* packet iovec */
	struct netdump_pkt nm_pkt;	/* packet contents */
};

#define	VMCORE_BUFSZ	(128 * 1024)

struct netdump_client {
	char		infofilename[MAXPATHLEN];
	char		corefilename[MAXPATHLEN];
	char		hostname[NI_MAXHOST];
	time_t		last_msg;
	LIST_ENTRY(netdump_client) iter;
	struct in_addr	ip;
	FILE		*infofile;
	int		corefd;
	int		sock;
	bool		any_data_rcvd;
	size_t		vmcorebufoff;
	off_t		vmcoreoff;
	uint8_t		vmcorebuf[VMCORE_BUFSZ];
};

/* Clients list. */
static LIST_HEAD(, netdump_client) g_clients = LIST_HEAD_INITIALIZER(g_clients);

/* Program arguments handlers. */
static char g_dumpdir[MAXPATHLEN];
static char *g_handler_script;
static char *g_handler_pre_script;
static struct in_addr g_bindip;

/* Miscellaneous handlers. */
static struct pidfh *g_pfh;
static time_t g_now;
static time_t g_last_timeout_check;
static int g_kq;
static int g_sock = -1;
static bool g_debug = false;

/* Daemon print functions hook. */
static void (*g_phook)(int, const char *, ...);

static struct netdump_client *alloc_client(struct sockaddr_in *sin,
		    struct in_addr *dip);
static int	eventloop(void);
static void	exec_handler(struct netdump_client *client, const char *reason);
static void	free_client(struct netdump_client *client);
static void	handle_finish(struct netdump_client *client,
		    struct netdump_msg *msg);
static void	handle_herald(struct netdump_client *client,
		    struct netdump_msg *msg);
static void	handle_kdh(struct netdump_client *client,
		    struct netdump_msg *msg);
static bool	handle_packet(struct netdump_client *client,
		    const char *fromstr, struct netdump_msg *msg);
static void	handle_timeout(struct netdump_client *client);
static void	handle_vmcore(struct netdump_client *client,
		    struct netdump_msg *msg);
static int	init_recvmsg(struct netdump_msg *msg);
static void	fini_recvmsg(struct netdump_msg *msg);
static void	phook_printf(int priority, const char *message, ...)
		    __printflike(2, 3);
static ssize_t	receive_message(int isock, char *fromstr, size_t fromstrlen,
		    struct netdump_msg *msg);
static void	send_ack(struct netdump_client *client,
		    struct netdump_msg *msg);
static void	timeout_clients(void);
static void	usage(const char *cmd);

static void
usage(const char *cmd)
{

	warnx(
    "usage: %s [-D] [-a bind_addr] [-d dumpdir] [-i script] [-b script]",
	    cmd);
}

static void
phook_printf(int priority, const char *message, ...)
{
	va_list ap;

	va_start(ap, message);
	if ((priority & LOG_INFO) != 0) {
		vprintf(message, ap);
	} else
		vfprintf(stderr, message, ap);
	va_end(ap);
}

static struct netdump_client *
alloc_client(struct sockaddr_in *sin, struct in_addr *dip)
{
	struct kevent event;
	struct sockaddr_in saddr;
	struct netdump_client *client;
	struct in_addr *sip;
	char *firstdot;
	int i, ecode, fd, bufsz;

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		LOGERR_PERROR("calloc()");
		goto error_out;
	}
	sip = &sin->sin_addr;
	bcopy(sip, &client->ip, sizeof(*sip));
	client->corefd = -1;
	client->sock = -1;
	client->last_msg = g_now;

	ecode = getnameinfo((struct sockaddr *)sin, sin->sin_len,
	    client->hostname, sizeof(client->hostname), NULL, 0, NI_NAMEREQD);
	if (ecode != 0) {
		/* Can't resolve, try with a numeric IP. */
		ecode = getnameinfo((struct sockaddr *)sin, sin->sin_len,
		    client->hostname, sizeof(client->hostname), NULL, 0, 0);
		if (ecode != 0) {
			LOGERR("getnameinfo(): %s\n", gai_strerror(ecode));
			goto error_out;
		}
	} else {
		/* Strip off the domain name */
		firstdot = strchr(client->hostname, '.');
		if (firstdot)
			*firstdot = '\0';
	}

	client->sock = socket(PF_INET,
	    SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, IPPROTO_UDP);
	if (client->sock == -1) {
		LOGERR_PERROR("socket()");
		goto error_out;
	}
	bzero(&saddr, sizeof(saddr));
	saddr.sin_len = sizeof(saddr);
	saddr.sin_family = AF_INET;
	saddr.sin_addr.s_addr = dip->s_addr;
	saddr.sin_port = htons(0);
	if (bind(client->sock, (struct sockaddr *)&saddr, sizeof(saddr))) {
		LOGERR_PERROR("bind()");
		goto error_out;
	}
	saddr.sin_addr.s_addr = sip->s_addr;
	saddr.sin_port = htons(NETDUMP_ACKPORT);
	if (connect(client->sock, (struct sockaddr *)&saddr, sizeof(saddr))) {
		LOGERR_PERROR("connect()");
		goto error_out;
	}

	/* It should be enough to hold approximatively twice the chunk size. */
	bufsz = 131072;
	if (setsockopt(client->sock, SOL_SOCKET, SO_RCVBUF, &bufsz,
	    sizeof(bufsz))) {
		LOGERR_PERROR("setsockopt()");
		LOGWARN(
		    "May drop packets from %s due to small receive buffer\n",
		    client->hostname);
	}

	/* Try info.host.0 through info.host.255 in sequence. */
	for (i = 0; i < MAX_DUMPS; i++) {
		snprintf(client->infofilename, sizeof(client->infofilename),
		    "%s/info.%s.%d", g_dumpdir, client->hostname, i);
		snprintf(client->corefilename, sizeof(client->corefilename),
		    "%s/vmcore.%s.%d", g_dumpdir, client->hostname, i);

		/* Try the info file first. */
		fd = open(client->infofilename, O_WRONLY | O_CREAT | O_EXCL,
		    0600);
		if (fd == -1) {
			if (errno != EEXIST)
				LOGERR("open(\"%s\"): %s\n",
				    client->infofilename, strerror(errno));
			continue;
		}
		client->infofile = fdopen(fd, "w");
		if (client->infofile == NULL) {
			LOGERR_PERROR("fdopen()");
			close(fd);
			(void)unlink(client->infofilename);
			continue;
		}

		/* Next make the core file. */
		fd = open(client->corefilename, O_RDWR | O_CREAT | O_EXCL,
		    0600);
		if (fd == -1) {
			/* Failed. Keep the numbers in sync. */
			fclose(client->infofile);
			(void)unlink(client->infofilename);
			client->infofile = NULL;
			if (errno != EEXIST)
				LOGERR("open(\"%s\"): %s\n",
				    client->corefilename, strerror(errno));
			continue;
		}
		client->corefd = fd;
		break;
	}

	if (client->infofile == NULL || client->corefd == -1) {
		LOGERR("Can't create output files for new client %s [%s]\n",
		    client->hostname, client_ntoa(client));
		goto error_out;
	}

	EV_SET(&event, client->sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(g_kq, &event, 1, NULL, 0, NULL) != 0) {
		LOGERR_PERROR("kevent(EV_ADD)");
		goto error_out;
	}

	LIST_INSERT_HEAD(&g_clients, client, iter);
	return (client);

error_out:
	if (client != NULL) {
		if (client->infofile != NULL)
			fclose(client->infofile);
		if (client->corefd != -1)
			close(client->corefd);
		if (client->sock != -1)
			(void)close(client->sock);
		free(client);
	}
	return (NULL);
}

static void
free_client(struct netdump_client *client)
{
	struct kevent event;

	EV_SET(&event, client->sock, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	if (kevent(g_kq, &event, 1, NULL, 0, NULL) != 0)
		LOGERR_PERROR("kevent(EV_DELETE)");

	/* Remove from the list.  Ignore errors from close() routines. */
	LIST_REMOVE(client, iter);
	fclose(client->infofile);
	close(client->corefd);
	close(client->sock);
	free(client);
}

static void
exec_script(struct netdump_client *client, const char *reason,
    const char *script)
{
	const char *argv[7];
	int error;
	pid_t pid;

	argv[0] = script;
	argv[1] = reason;
	argv[2] = client_ntoa(client);
	argv[3] = client->hostname;
	argv[4] = client->infofilename;
	argv[5] = client->corefilename;
	argv[6] = NULL;

	error = posix_spawn(&pid, script, NULL, NULL,
	    __DECONST(char *const *, argv), NULL);
	if (error != 0)
		LOGERR("posix_spawn(): %s", strerror(error));
}

static void
exec_handler(struct netdump_client *client, const char *reason)
{

	if (g_handler_script != NULL)
		exec_script(client, reason, g_handler_script);
}

static void
exec_pre_script(struct netdump_client *client, const char *reason)
{

	if (g_handler_pre_script != NULL)
		exec_script(client, reason, g_handler_pre_script);
}

static void
handle_timeout(struct netdump_client *client)
{

	assert(client != NULL);

	LOGINFO("Client %s timed out\n", client_ntoa(client));
	client_pinfo(client, "Dump incomplete: client timed out\n");
	exec_handler(client, "timeout");
	free_client(client);
}

static int
vmcore_flush(struct netdump_client *client)
{

	if (pwrite(client->corefd, client->vmcorebuf, client->vmcorebufoff,
	    client->vmcoreoff) != (ssize_t)client->vmcorebufoff) {
		LOGERR("pwrite (for client %s [%s]): %s\n", client->hostname,
		    client_ntoa(client), strerror(errno));
		client_pinfo(client,
		    "Dump unsuccessful: write error @ offset %08jx: %s\n",
		    (uintmax_t)client->vmcoreoff, strerror(errno));
		exec_handler(client, "error");
		free_client(client);
		return (1);
	}
	client->vmcorebufoff = 0;
	return (0);
}

static void
timeout_clients(void)
{
	struct netdump_client *client, *tmp;

	/* Only time out clients every 10 seconds. */
	if (g_now - g_last_timeout_check < CLIENT_TPASS)
		return;
	g_last_timeout_check = g_now;

	/* Traverse the list looking for stale clients. */
	LIST_FOREACH_SAFE(client, &g_clients, iter, tmp) {
		if (client->last_msg + CLIENT_TIMEOUT < g_now) {
			LOGINFO("Timingout with such values: %jd + %jd < %jd\n",
			    (intmax_t)client->last_msg,
			    (intmax_t)CLIENT_TIMEOUT, (intmax_t)g_now);
			handle_timeout(client);
		}
	}
}

static void
send_ack(struct netdump_client *client, struct netdump_msg *msg)
{
	struct netdump_ack ack;

	assert(client != NULL && msg != NULL);

	bzero(&ack, sizeof(ack));
	ack.na_seqno = htonl(msg->nm_pkt.hdr.mh_seqno);

	if (send(client->sock, &ack, sizeof(ack), 0) == -1)
		LOGERR_PERROR("send()");
	/*
	 * XXX: On EAGAIN, we should probably queue the packet
	 * to be sent when the socket is writable but
	 * that is too much effort, since it is mostly
	 * harmless to wait for the client to retransmit.
	 */
}

static void
handle_herald(struct netdump_client *client, struct netdump_msg *msg)
{

	assert(msg != NULL);

	if (client != NULL) {
		if (!client->any_data_rcvd) {
			/* Must be a retransmit of the herald packet. */
			send_ack(client, msg);
			return;
		}
		/* An old connection must have timed out. Clean it up first. */
		handle_timeout(client);
	}

	client = alloc_client(msg->nm_src, msg->nm_dst);
	if (client == NULL) {
		LOGERR("handle_herald(): new client allocation failure\n");
		return;
	}
	client_pinfo(client, "Dump from %s [%s]\n", client->hostname,
	    client_ntoa(client));
	LOGINFO("New dump from client %s [%s] (to %s)\n", client->hostname,
	    client_ntoa(client), client->corefilename);
	exec_pre_script(client, "new dump");
	send_ack(client, msg);
}

static void
handle_kdh(struct netdump_client *client, struct netdump_msg *msg)
{
	time_t t;
	uint64_t dumplen;
	struct kerneldumpheader *h;
	int parity_check;

	assert(msg != NULL);

	if (client == NULL)
		return;

	client->any_data_rcvd = true;
	h = (struct kerneldumpheader *)(void *)msg->nm_pkt.data;
	if (msg->nm_pkt.hdr.mh_len < sizeof(struct kerneldumpheader)) {
		LOGERR("Bad KDH from %s [%s]: packet too small\n",
		    client->hostname, client_ntoa(client));
		client_pinfo(client, "Bad KDH: packet too small\n");
		fflush(client->infofile);
		return;
	}
	parity_check = kerneldump_parity(h);

	/* Make sure all the strings are null-terminated. */
	h->architecture[sizeof(h->architecture) - 1] = '\0';
	h->hostname[sizeof(h->hostname) - 1] = '\0';
	h->versionstring[sizeof(h->versionstring) - 1] = '\0';
	h->panicstring[sizeof(h->panicstring) - 1] = '\0';

	client_pinfo(client, "  Architecture: %s\n", h->architecture);
	client_pinfo(client, "  Architecture version: %d\n",
	    dtoh32(h->architectureversion));
	dumplen = dtoh64(h->dumplength);
	client_pinfo(client, "  Dump length: %lldB (%lld MB)\n",
	    (long long)dumplen, (long long)(dumplen >> 20));
	client_pinfo(client, "  blocksize: %d\n", dtoh32(h->blocksize));
	t = dtoh64(h->dumptime);
	client_pinfo(client, "  Dumptime: %s", ctime(&t));
	client_pinfo(client, "  Hostname: %s\n", h->hostname);
	client_pinfo(client, "  Versionstring: %s", h->versionstring);
	client_pinfo(client, "  Panicstring: %s\n", h->panicstring);
	client_pinfo(client, "  Header parity check: %s\n",
	    parity_check ? "Fail" : "Pass");
	fflush(client->infofile);

	LOGINFO("(KDH from %s [%s])", client->hostname, client_ntoa(client));
	send_ack(client, msg);
}

static void
handle_vmcore(struct netdump_client *client, struct netdump_msg *msg)
{

	assert(msg != NULL);

	if (client == NULL)
		return;

	client->any_data_rcvd = true;
	if (msg->nm_pkt.hdr.mh_seqno % (16 * 1024 * 1024 / 1456) == 0) {
		/* Approximately every 16MB with MTU of 1500 */
		LOGINFO(".");
	}

	/*
	 * Flush the vmcore buffer if it's full, or if the received segment
	 * isn't contiguous with respect to any already-buffered data.
	 */
	if (client->vmcorebufoff + NETDUMP_DATASIZE > VMCORE_BUFSZ ||
	    (client->vmcorebufoff > 0 &&
	    client->vmcoreoff + client->vmcorebufoff !=
	    msg->nm_pkt.hdr.mh_offset))
		if (vmcore_flush(client) != 0)
			return;

	memcpy(client->vmcorebuf + client->vmcorebufoff, msg->nm_pkt.data,
	    msg->nm_pkt.hdr.mh_len);
	if (client->vmcorebufoff == 0)
		client->vmcoreoff = msg->nm_pkt.hdr.mh_offset;
	client->vmcorebufoff += msg->nm_pkt.hdr.mh_len;

	send_ack(client, msg);
}

static void
handle_finish(struct netdump_client *client, struct netdump_msg *msg)
{

	assert(msg != NULL);

	if (client == NULL)
		return;
	/* Make sure we commit any buffered vmcore data. */
	if (vmcore_flush(client) != 0)
		return;

	LOGINFO("\nCompleted dump from client %s [%s]\n", client->hostname,
	    client_ntoa(client));
	client_pinfo(client, "Dump complete\n");
	send_ack(client, msg);
	(void)fsync(client->corefd);
	exec_handler(client, "success");
	free_client(client);
}

static int
init_recvmsg(struct netdump_msg *msg)
{
	size_t cmsgsz;

	memset(&msg->nm_msg, 0, sizeof(msg->nm_msg));

	msg->nm_msg.msg_name = &msg->nm_ss;
	msg->nm_msg.msg_namelen = sizeof(msg->nm_ss);
	msg->nm_msg.msg_iov = &msg->nm_iov;
	msg->nm_msg.msg_iovlen = 1;

	msg->nm_iov.iov_base = &msg->nm_pkt;
	msg->nm_iov.iov_len = sizeof(msg->nm_pkt);

	msg->nm_src = (struct sockaddr_in *)&msg->nm_ss;

	cmsgsz = CMSG_SPACE(sizeof(struct in_addr));
	msg->nm_cmsg = calloc(1, cmsgsz);
	if (msg->nm_cmsg == NULL) {
		LOGERR("malloc");
		return (1);
	}
	msg->nm_msg.msg_control = msg->nm_cmsg;
	msg->nm_msg.msg_controllen = cmsgsz;
	return (0);
}

static void
fini_recvmsg(struct netdump_msg *msg)
{

	free(msg->nm_cmsg);
}

static ssize_t
receive_message(int isock, char *fromstr, size_t fromstrlen,
    struct netdump_msg *msg)
{
	struct sockaddr_in *from;
	ssize_t len;

	assert(fromstr != NULL && msg != NULL);

	len = recvmsg(isock, &msg->nm_msg, 0);
	if (len == -1) {

		/*
		 * As long as some callers may discard the errors printing
		 * in defined circumstances, leave them the choice and avoid
		 * any error reporting.
		 */
		return (-1);
	}

	from = (struct sockaddr_in *)msg->nm_msg.msg_name;
	snprintf(fromstr, fromstrlen, "%s:%hu", inet_ntoa(from->sin_addr),
	    ntohs(from->sin_port));
	if ((size_t)len < sizeof(struct netdump_msg_hdr)) {
		LOGERR("Ignoring runt packet from %s (got %zu)\n", fromstr,
		    (size_t)len);
		return (0);
	}

	/* Convert byte order. */
	msg->nm_pkt.hdr.mh_type = ntohl(msg->nm_pkt.hdr.mh_type);
	msg->nm_pkt.hdr.mh_seqno = ntohl(msg->nm_pkt.hdr.mh_seqno);
	msg->nm_pkt.hdr.mh_offset = be64toh(msg->nm_pkt.hdr.mh_offset);
	msg->nm_pkt.hdr.mh_len = ntohl(msg->nm_pkt.hdr.mh_len);

	if ((size_t)len <
	    sizeof(struct netdump_msg_hdr) + msg->nm_pkt.hdr.mh_len) {
		LOGERR("Packet too small from %s (got %zu, expected %zu)\n",
		    fromstr, (size_t)len,
		    sizeof(struct netdump_msg_hdr) + msg->nm_pkt.hdr.mh_len);

		return (0);
	}
	return (len);
}

static bool
handle_packet(struct netdump_client *client, const char *fromstr,
    struct netdump_msg *msg)
{
	bool finished;

	assert(fromstr != NULL && msg != NULL);

	if (client != NULL)
		client->last_msg = time(NULL);

	finished = false;
	switch (msg->nm_pkt.hdr.mh_type) {
	case NETDUMP_HERALD:
		handle_herald(client, msg);
		break;
	case NETDUMP_KDH:
		handle_kdh(client, msg);
		break;
	case NETDUMP_VMCORE:
		handle_vmcore(client, msg);
		break;
	case NETDUMP_FINISHED:
		handle_finish(client, msg);
		finished = true;
		break;
	default:
		LOGERR("Received unknown message type %d from %s\n",
		    msg->nm_pkt.hdr.mh_type, fromstr);
		break;
	}
	return (finished);
}

/* Handle a read event on the server socket. */
static int
server_event(void)
{
	char fromstr[INET_ADDRSTRLEN + 6];
	struct cmsghdr *cmh;
	struct netdump_msg msg;
	struct netdump_client *client;
	ssize_t len;
	int error;

	error = init_recvmsg(&msg);
	if (error != 0)
		return (error);
	while ((len = receive_message(g_sock, fromstr, sizeof(fromstr),
	    &msg)) > 0) {
		/*
		 * With len == 0 the packet was rejected (probably because it
		 * was too small) so just ignore this case.
		 */

		LIST_FOREACH(client, &g_clients, iter)
			if (client->ip.s_addr == msg.nm_src->sin_addr.s_addr)
				break;

		if (msg.nm_pkt.hdr.mh_type != NETDUMP_HERALD) {
			LOGERR(
			    "Received message type %d from %s on server port\n",
			    msg.nm_pkt.hdr.mh_type, fromstr);
			continue;
		}

		/*
		 * Pull out the destination address so that we know how to
		 * reply.
		 */
		cmh = CMSG_FIRSTHDR(&msg.nm_msg);
		if (cmh->cmsg_level != IPPROTO_IP ||
		    cmh->cmsg_type != IP_RECVDSTADDR) {
			LOGERR(
		    "Got unexpected control message %d in packet from %s\n",
			    cmh->cmsg_type, fromstr);
			continue;
		}
		msg.nm_dst = (struct in_addr *)(void *)CMSG_DATA(msg.nm_cmsg);

		/*
		 * The client may be non-NULL here if we're receiving a
		 * retransmit of a HERALD.
		 */
		if (handle_packet(client, fromstr, &msg))
			break;
	}
	fini_recvmsg(&msg);
	if (len < 0 && errno != EAGAIN) {
		LOGERR_PERROR("recvfrom()");
		return (1);
	}
	return (0);
}

/* Handle a read event on a client socket. */
static void
client_event(struct netdump_client *client)
{
	char fromstr[INET_ADDRSTRLEN + 6];
	struct netdump_msg msg;
	ssize_t len;
	int error;

	error = init_recvmsg(&msg);
	if (error != 0)
		return;
	while ((len = receive_message(client->sock, fromstr, sizeof(fromstr),
	    &msg)) > 0) {
		/*
		 * With len == 0 the packet was rejected (probably because it
		 * was too small) so just ignore this case.
		 */

		if (msg.nm_pkt.hdr.mh_type == NETDUMP_HERALD) {
			LOGERR("Received herald from %s on client port\n",
			    fromstr);
			continue;
		}

		if (handle_packet(client, fromstr, &msg))
			break;
	}
	fini_recvmsg(&msg);
	if (len == -1 && errno != EAGAIN) {
		LOGERR_PERROR("recvfrom()");
		handle_timeout(client);
	}
}

static int
eventloop(void)
{
	struct kevent events[8];
	struct timespec ts;
	struct netdump_client *client, *tmp;
	int ev, rc;

	/* We check for timed-out clients regularly. */
	ts.tv_sec = CLIENT_TPASS;
	ts.tv_nsec = 0;

	for (;;) {
		rc = kevent(g_kq, NULL, 0, events, nitems(events), &ts);
		if (rc < 0) {
			LOGERR_PERROR("kevent()");
			return (1);
		}

		g_now = time(NULL);
		for (ev = 0; ev < rc; ev++) {
			if (events[ev].filter == EVFILT_SIGNAL)
				/* We received SIGINT or SIGTERM. */
				goto out;

			if ((int)events[ev].ident == g_sock)
				if (server_event() != 0)
					return (1);

			/*
			 * handle_packet() and handle_timeout() may free the client,
			 * handle stale pointers.
			 */
			LIST_FOREACH_SAFE(client, &g_clients, iter, tmp) {
				if (client->sock == (int)events[ev].ident) {
					client_event(client);
					break;
				}
			}
		}

		timeout_clients();
	}
out:
	LOGINFO("Shutting down...");

	/*
	 * Clients is the head of the list, so clients != NULL iff the list
	 * is not empty. Call it a timeout so that the scripts get run.
	 */
	while (!LIST_EMPTY(&g_clients))
		handle_timeout(LIST_FIRST(&g_clients));

	return (0);
}

static char *
get_script_option(void)
{
	char *script;

	script = strdup(optarg);
	if (script == NULL) {
		err(1, "strdup()");
		return (NULL);
	}
	if (access(script, F_OK | X_OK)) {
		warn("cannot access %s", script);
		free(script);
		return (NULL);
	}
	return (script);
}

int
main(int argc, char **argv)
{
	struct stat statbuf;
	struct sockaddr_in bindaddr;
	struct sigaction sa;
	struct kevent sockev, sigev[2];
	sigset_t set;
	int ch, exit_code, one;

	g_bindip.s_addr = INADDR_ANY;

	exit_code = 0;
	while ((ch = getopt(argc, argv, "a:b:Dd:i:")) != -1) {
		switch (ch) {
		case 'a':
			if (inet_aton(optarg, &g_bindip) == 0) {
				warnx("invalid bind IP specified");
				exit_code = 1;
				goto cleanup;
			}
			warnx("listening on IP %s", optarg);
			break;
		case 'b':
			g_handler_pre_script = get_script_option();
			if (g_handler_pre_script == NULL) {
				exit_code = 1;
				goto cleanup;
			}
			break;
		case 'D':
			g_debug = true;
			break;
		case 'd':
			if (strlcpy(g_dumpdir, optarg, sizeof(g_dumpdir)) >=
			    sizeof(g_dumpdir)) {
				warnx("dumpdir '%s' is too long", optarg);
				exit_code = 1;
				goto cleanup;
			}
			break;
		case 'i':
			g_handler_script = get_script_option();
			if (g_handler_script == NULL) {
				exit_code = 1;
				goto cleanup;
			}
			break;
		default:
			usage(argv[0]);
			exit_code = 1;
			goto cleanup;
		}
	}

	g_pfh = pidfile_open(NULL, 0600, NULL);
	if (g_pfh == NULL) {
		if (errno == EEXIST)
			errx(1, "netdumpd is already running");
		else
			err(1, "pidfile_open");
	}

	if (g_bindip.s_addr == INADDR_ANY)
		warnx("default: listening on all interfaces");
	if (g_dumpdir[0] == '\0') {
		strcpy(g_dumpdir, "/var/crash");
		warnx("default: dumping to /var/crash/");
	}
	if (g_debug)
		g_phook = phook_printf;
	else
		g_phook = syslog;

	exit_code = 1;

	/* Further sanity checks on dump location. */
	if (stat(g_dumpdir, &statbuf)) {
		warnx("invalid dump location specified");
		goto cleanup;
	}
	if (!S_ISDIR(statbuf.st_mode)) {
		fprintf(stderr, "Dump location is not a directory");
		goto cleanup;
	}
	if (access(g_dumpdir, F_OK | W_OK))
		warn("warning: may be unable to write into dump location");

	if (!g_debug && daemon(0, 0) == -1) {
		warn("daemon()");
		goto cleanup;
	}
	if (pidfile_write(g_pfh) != 0) {
		warn("pidfile_write()");
		goto cleanup;
	}

	g_kq = kqueue();
	if (g_kq < 0) {
		LOGERR_PERROR("kqueue()");
		goto cleanup;
	}

	/* Set up the server socket. */
	g_sock = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (g_sock == -1) {
		LOGERR_PERROR("socket()");
		goto cleanup;
	}
	one = 1;
	if (setsockopt(g_sock, IPPROTO_IP, IP_RECVDSTADDR, &one,
	    sizeof(one)) != 0) {
		LOGERR_PERROR("setsockopt()");
		goto cleanup;
	}
	bzero(&bindaddr, sizeof(bindaddr));
	bindaddr.sin_len = sizeof(bindaddr);
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_addr.s_addr = g_bindip.s_addr;
	bindaddr.sin_port = htons(NETDUMP_PORT);
	if (bind(g_sock, (struct sockaddr *)&bindaddr, sizeof(bindaddr))) {
		LOGERR_PERROR("bind()");
		goto cleanup;
	}
	if (fcntl(g_sock, F_SETFL, O_NONBLOCK) == -1) {
		LOGERR_PERROR("fcntl()");
		goto cleanup;
	}

	EV_SET(&sockev, g_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(g_kq, &sockev, 1, NULL, 0, NULL) != 0) {
		LOGERR_PERROR("kevent(socket)");
		goto cleanup;
	}

	/* Mask all signals. */
	sigfillset(&set);
	if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) {
		LOGERR_PERROR("sigprocmask()");
		goto cleanup;
	}
	bzero(&sa, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = SA_NOCLDWAIT;
	if (sigaction(SIGCHLD, &sa, NULL)) {
		LOGERR_PERROR("sigaction(SIGCHLD)");
		goto cleanup;
	}

	/* Watch for SIGINT and SIGTERM. */
	EV_SET(&sigev[0], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&sigev[1], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	if (kevent(g_kq, sigev, nitems(sigev), NULL, 0, NULL) != 0) {
		LOGERR_PERROR("kevent(signals)");
		goto cleanup;
	}

	LOGINFO("Waiting for clients.\n");
	exit_code = eventloop();

cleanup:
	if (g_pfh != NULL)
		pidfile_remove(g_pfh);
	free(g_handler_pre_script);
	free(g_handler_script);
	if (g_sock != -1)
		close(g_sock);
	return (exit_code);
}
