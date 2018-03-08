/*-
 * Copyright (c) 2005-2011 Sandvine Incorporated. All rights reserved.
 * Copyright (c) 2016-2018 Dell EMC
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
#include <sys/capsicum.h>
#include <sys/endian.h>
#include <sys/errno.h>
#include <sys/event.h>
#include <sys/kerneldump.h>
#include <sys/nv.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/netdump/netdump.h>

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <libcasper.h>
#include <casper/cap_dns.h>

#include <libutil.h>

#include "netdumpd.h"

#define	MAX_DUMPS	1024	/* Maximum saved dumps per remote host. */
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

#define	VMCORE_BUFSZ	(128 * 1024)

struct netdump_client {
	LIST_ENTRY(netdump_client) iter;
	char		*path;
	char		infofilename[MAXPATHLEN];
	char		corefilename[MAXPATHLEN];
	char		hostname[NI_MAXHOST];
	time_t		last_msg;
	struct in_addr	ip;
	FILE		*infofile;
	int		corefd;
	int		keyfilefd;
	int		sock;
	int		index;
	bool		any_data_rcvd;
	ssize_t		vmcorebufoff;
	off_t		vmcoreoff;
	uint8_t		vmcorebuf[VMCORE_BUFSZ];
};

/* Clients list. */
static LIST_HEAD(, netdump_client) g_clients = LIST_HEAD_INITIALIZER(g_clients);

/* Capabilities. */
static cap_channel_t *g_capdns, *g_caphandler, *g_capherald;

/* Program arguments handlers. */
static char g_dumpdir[MAXPATHLEN];
static int g_dumpdir_fd = -1;
static char g_defpath[MAXPATHLEN];
static char *g_handler_script;
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

static struct netdump_client *alloc_client(int sd, struct sockaddr_in *saddr,
		    char *path);
static void	client_event(struct netdump_client *client);
static int	eventloop(void);
static void	exec_handler(struct netdump_client *client, const char *reason);
static void	free_client(struct netdump_client *client);
static void	handle_finish(struct netdump_client *client,
		    struct netdump_pkt *pkt);
static void	handle_kdh(struct netdump_client *client,
		    struct netdump_pkt *pkt);
static void	handle_timeout(struct netdump_client *client);
static void	handle_vmcore(struct netdump_client *client,
		    struct netdump_pkt *pkt);
static void	phook_printf(int priority, const char *message, ...)
		    __printflike(2, 3);
static void	send_ack(struct netdump_client *client, uint32_t seqno);
static void	server_event(void);
static void	timeout_clients(void);
static void	usage(void);

static void
usage(void)
{

	fprintf(stderr,
"usage: %s [-D] [-a <bind_addr>] [-d <dumpdir>] [-i <script>] [-P <pidfile>]\n"
"\t\t[-p <default path>]\n",
	    getprogname());
}

static void
phook_printf(int priority, const char *message, ...)
{
	va_list ap;

	va_start(ap, message);
	if ((priority & LOG_INFO) != 0)
		vprintf(message, ap);
	else
		vfprintf(stderr, message, ap);
	va_end(ap);
}

/*
 * Attempt to read the bounds file for the specified client. Return the saved
 * index if possible, else return -1.
 */
static int
read_index(struct netdump_client *client, const char *dir)
{
	char bounds[MAXPATHLEN], buf[16];
	FILE *fp;
	size_t len;
	u_long bound;
	int fd;

	len = snprintf(bounds, sizeof(bounds), "%s/bounds.%s", dir,
	    client->hostname);
	if (len >= sizeof(bounds)) {
		LOGERR("Truncated bounds file path: '%s'\n", bounds);
		return (-1);
	}
	fd = openat(g_dumpdir_fd, bounds,
	    O_RDONLY | O_CREAT | O_CLOEXEC, 0600);
	if (fd < 0) {
		LOGERR("openat(%s): %s\n", bounds, strerror(errno));
		return (-1);
	}

	fp = fdopen(fd, "r");
	if (fp == NULL) {
		LOGERR_PERROR("fdopen()");
		(void)close(fd);
		return (-1);
	}

	if (fgets(buf, sizeof(buf), fp) == NULL) {
		if (feof(fp))
			LOGINFO("Empty bounds file for client %s [%s]\n",
			    client->hostname, client_ntoa(client));
		else
			LOGERR("Failed to read bound for client %s [%s]: %s\n",
			    client->hostname, client_ntoa(client),
			    strerror(errno));
		(void)fclose(fp);
		return (-1);
	}
	(void)fclose(fp);

	errno = 0;
	bound = strtoul(buf, NULL, 10);
	if ((bound == 0 && errno == EINVAL) ||
	    (bound == ULONG_MAX && errno == ERANGE) ||
	    bound > INT_MAX) {
		LOGERR("Invalid bound for client %s [%s]: '%s'\n",
		    client->hostname, client_ntoa(client), buf);
		return (-1);
	}
	return ((int)bound);
}

static int
write_index(struct netdump_client *client)
{
	char bounds[MAXPATHLEN];
	FILE *fp;
	size_t len;
	int fd;

	len = snprintf(bounds, sizeof(bounds), "%s/bounds.%s", client->path,
	    client->hostname);
	if (len >= sizeof(bounds)) {
		LOGERR("Truncated bounds file path: '%s'\n", bounds);
		return (-1);
	}
	fd = openat(g_dumpdir_fd, bounds, O_WRONLY | O_CLOEXEC);
	if (fd < 0) {
		LOGERR("openat(%s): %s\n", bounds, strerror(errno));
		return (-1);
	}

	fp = fdopen(fd, "w");
	if (fp == NULL) {
		LOGERR_PERROR("fdopen()");
		(void)close(fd);
		return (-1);
	}

	(void)fprintf(fp, "%d\n", client->index + 1);
	(void)fclose(fp);
	return (0);
}

static int
open_info_file(struct netdump_client *client, const char *dir, int index)
{
	size_t len;
	int fd;

	len = snprintf(client->infofilename, sizeof(client->infofilename),
	    "%s/info.%s.%d", dir, client->hostname, index);
	if (len >= sizeof(client->infofilename)) {
		LOGERR("Truncated info file path: '%s'\n",
		    client->infofilename);
		return (-1);
	}

	fd = openat(g_dumpdir_fd, client->infofilename,
	    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd == -1 && errno != EEXIST)
		LOGERR("openat(\"%s\"): %s\n",
		    client->infofilename, strerror(errno));
	return (fd);
}

static int
open_client_files(struct netdump_client *client, const char *dir)
{
	size_t len;
	int error, fd, i, index;

	index = read_index(client, dir);
	if (index >= 0) {
		fd = open_info_file(client, dir, index);
		if (fd < 0) {
			LOGERR("Incorrect bounds file for client %s [%s]\n",
			    client->hostname, client_ntoa(client));
			index = -1;
		}
	}
	if (index == -1) {
		for (i = 0; i < MAX_DUMPS; i++) {
			fd = open_info_file(client, dir, i);
			if (fd >= 0)
				break;
		}
		if (i == MAX_DUMPS) {
			LOGERR("No free index for client %s [%s]\n",
			    client->hostname, client_ntoa(client));
			return (-1);
		}
		index = i;
	}
	client->index = index;

	client->infofile = fdopen(fd, "a");
	if (client->infofile == NULL) {
		LOGERR_PERROR("fdopen()");
		(void)close(fd);
		(void)unlinkat(g_dumpdir_fd, client->infofilename, 0);
		return (-1);
	}

	len = snprintf(client->corefilename, sizeof(client->corefilename),
	    "%s/vmcore.%s.%d", dir, client->hostname, i);
	if (len >= sizeof(client->corefilename)) {
		LOGERR("Truncated core file path: '%s'\n",
		    client->corefilename);
		return (-1);
	}
	fd = openat(g_dumpdir_fd, client->corefilename,
	    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd == -1) {
		error = errno;
		/* Failed. Keep the numbers in sync. */
		(void)fclose(client->infofile);
		(void)unlinkat(g_dumpdir_fd, client->infofilename, 0);
		client->infofile = NULL;
		LOGERR("openat(%s): %s\n",
		    client->corefilename, strerror(error));
		return (-1);
	}
	client->corefd = fd;
	return (0);
}

/*
 * Allocate a bookkeeping structure for a new client. The client may, in its
 * herald message, specify a path relative to the dumpdir in which to store the
 * dump.
 */
static struct netdump_client *
alloc_client(int sd, struct sockaddr_in *saddr, char *path)
{
	struct kevent event;
	struct netdump_client *client;
	char *firstdot, *origpath;
	int error, bufsz;

	client = calloc(1, sizeof(*client));
	if (client == NULL) {
		LOGERR_PERROR("calloc()");
		goto error_out;
	}

	client->corefd = client->keyfilefd = -1;
	client->index = -1;
	client->sock = sd;
	client->last_msg = g_now;
	client->ip = saddr->sin_addr;

	error = cap_getnameinfo(g_capdns, (struct sockaddr *)saddr,
	    saddr->sin_len, client->hostname, sizeof(client->hostname),
	    NULL, 0, NI_NAMEREQD);
	if (error != 0) {
		/* Can't resolve, try with a numeric IP. */
		error = cap_getnameinfo(g_capdns, (struct sockaddr *)saddr,
		    saddr->sin_len, client->hostname, sizeof(client->hostname),
		    NULL, 0, 0);
		if (error != 0) {
			LOGERR("cap_getnameinfo(): %s\n", gai_strerror(error));
			goto error_out;
		}
	} else {
		/* Strip off the domain name. */
		firstdot = strchr(client->hostname, '.');
		if (firstdot)
			*firstdot = '\0';
	}

	/* It should be enough to hold approximatively twice the chunk size. */
	bufsz = 128 * 1024;
	if (setsockopt(client->sock, SOL_SOCKET, SO_RCVBUF, &bufsz,
	    sizeof(bufsz))) {
		LOGERR_PERROR("setsockopt()");
		LOGWARN(
		    "May drop packets from %s due to small receive buffer\n",
		    client->hostname);
	}

	origpath = path;
	if (path == NULL)
		/* g_defpath defaults to "." */
		path = strdup(g_defpath);

	error = open_client_files(client, path);
	if (error != 0) {
		if (origpath != NULL) {
			LOGWARN(
"Can't create output files in path for client %s [%s], retrying with default\n",
			    client->hostname, client_ntoa(client));
			free(origpath);
			path = strdup(g_defpath);
			error = open_client_files(client, path);
		}
		if (error != 0) {
			LOGERR(
		    "Can't create output files for new client %s [%s]\n",
			    client->hostname, client_ntoa(client));
			goto error_out;
		}
	}
	client->path = path;

	EV_SET(&event, client->sock, EVFILT_READ, EV_ADD, 0, 0, client);
	if (kevent(g_kq, &event, 1, NULL, 0, NULL) != 0) {
		LOGERR_PERROR("kevent(EV_ADD)");
		goto error_out;
	}

	(void)write_index(client);

	LIST_INSERT_HEAD(&g_clients, client, iter);
	return (client);

error_out:
	free(path);
	if (client != NULL) {
		if (client->infofile != NULL)
			(void)fclose(client->infofile);
		if (client->corefd != -1)
			(void)close(client->corefd);
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
	if (client->keyfilefd != -1)
		(void)close(client->keyfilefd);
	(void)fclose(client->infofile);
	(void)close(client->corefd);
	(void)close(client->sock);
	free(client->path);
	free(client);
}

static void
exec_handler(struct netdump_client *client, const char *reason)
{
	int error;

	if (g_caphandler == NULL)
		return;
	error = netdump_cap_handler(g_caphandler, reason, client_ntoa(client),
	    client->hostname, client->infofilename, client->corefilename);
	if (error != 0)
		LOGERR("netdump_cap_handler(): %s", strerror(error));
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
	    client->vmcoreoff) != client->vmcorebufoff) {
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
		if (client->last_msg + CLIENT_TIMEOUT < g_now)
			handle_timeout(client);
	}
}

static void
send_ack(struct netdump_client *client, uint32_t seqno)
{
	struct netdump_ack ack;

	bzero(&ack, sizeof(ack));
	ack.na_seqno = htonl(seqno);

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
handle_kdh(struct netdump_client *client, struct netdump_pkt *pkt)
{
#if KERNELDUMPVERSION >= 3
	static const char *const compalgos[] = {
	    [KERNELDUMP_COMP_NONE] = "none",
	    [KERNELDUMP_COMP_GZIP] = "gzip",
#ifdef KERNELDUMP_COMP_ZSTD
	    [KERNELDUMP_COMP_ZSTD] = "zstd",
#endif
	    NULL,
	};
	static const char *const suffixes[] = {
	    [KERNELDUMP_COMP_GZIP] = ".gz",
#ifdef KERNELDUMP_COMP_ZSTD
	    [KERNELDUMP_COMP_ZSTD] = ".zst",
#endif
	};
#endif /* KERNELDUMPVERSION >= 3 */
	char newpath[MAXPATHLEN];
	struct kerneldumpheader *kdh;
	const char *compalgo;
	uint64_t dumplen;
	time_t t;
	int parity_check;

	client->any_data_rcvd = true;

	LOGINFO("(KDH from %s [%s])\n", client->hostname, client_ntoa(client));
	send_ack(client, pkt->hdr.mh_seqno);

	if (pkt->hdr.mh_len < sizeof(struct kerneldumpheader)) {
		LOGERR("Bad KDH from %s [%s]: packet too small\n",
		    client->hostname, client_ntoa(client));
		client_pinfo(client, "Bad KDH: packet too small\n");
		return;
	}

	kdh = (struct kerneldumpheader *)(void *)pkt->data;

	parity_check = kerneldump_parity(kdh);

	/* Make sure all the strings are null-terminated. */
	kdh->architecture[sizeof(kdh->architecture) - 1] = '\0';
	kdh->hostname[sizeof(kdh->hostname) - 1] = '\0';
	kdh->versionstring[sizeof(kdh->versionstring) - 1] = '\0';
	kdh->panicstring[sizeof(kdh->panicstring) - 1] = '\0';

	client_pinfo(client, "  Architecture: %s\n", kdh->architecture);
	client_pinfo(client, "  Architecture version: %d\n",
	    dtoh32(kdh->architectureversion));
	dumplen = dtoh64(kdh->dumplength);
	client_pinfo(client, "  Dump length: %lldB (%lld MB)\n",
	    (long long)dumplen, (long long)(dumplen >> 20));
	client_pinfo(client, "  Blocksize: %d\n", dtoh32(kdh->blocksize));
	t = dtoh64(kdh->dumptime);
#if KERNELDUMPVERSION >= 3
	if (kdh->compression < nitems(compalgos))
		compalgo = compalgos[kdh->compression];
	else
		compalgo = "???";
	client_pinfo(client, "  Compression: %s\n", compalgo);
#endif
	client_pinfo(client, "  Dumptime: %s", ctime(&t));
	client_pinfo(client, "  Hostname: %s\n", kdh->hostname);
	client_pinfo(client, "  Versionstring: %s", kdh->versionstring);
	client_pinfo(client, "  Panicstring: %s\n", kdh->panicstring);
	client_pinfo(client, "  Header parity check: %s\n",
	    parity_check ? "Fail" : "Pass");
	fflush(client->infofile);

#if KERNELDUMPVERSION >= 3
	/*
	 * Rename the dump file so that it has the correct suffix, and truncate
	 * it to the correct size. The kernel dump code always writes in
	 * multiples of the block size, so the resulting file size will be
	 * rounded up to the next multiple. The trailing bytes confuse
	 * decompressors, so chop them off now. This is a bit of a hack, but so
	 * it goes.
	 */
	if (kdh->compression < nitems(compalgos) &&
	    kdh->compression != KERNELDUMP_COMP_NONE) {
		(void)strlcpy(newpath, client->corefilename, sizeof(newpath));
		if (strlcat(newpath, suffixes[kdh->compression],
		    sizeof(newpath)) < sizeof(newpath)) {
			renameat(g_dumpdir_fd, client->corefilename,
			    g_dumpdir_fd, newpath);
			(void)strlcpy(client->corefilename, newpath,
			    sizeof(client->corefilename));
		} else
			LOGWARN("Couldn't append compression suffix to '%s'\n",
			    client->corefilename);

		if (vmcore_flush(client) == 0 &&
		    ftruncate(client->corefd, dumplen) != 0)
			/* Not fatal. */
			LOGERR_PERROR("ftruncate()");
	}
#endif
}

static void
handle_ekcd_key(struct netdump_client *client, struct netdump_pkt *pkt)
{
	char *data;
	size_t n;
	uint32_t bytes, offset;
	int fd;

	if (client->keyfilefd == -1) {
		char keyfile[MAXPATHLEN];
		size_t len;

		len = snprintf(keyfile, sizeof(keyfile), "%s/key.%s.%d",
		    client->path, client->hostname, client->index);
		if (len >= sizeof(keyfile)) {
			LOGERR(
			    "Truncated key file path for client %s [%s]: %s\n",
			    client->hostname, client_ntoa(client), keyfile);
			return;
		}

		fd = openat(g_dumpdir_fd, keyfile,
		    O_WRONLY | O_CREAT | O_CLOEXEC, 0400);
		if (fd < 0) {
			LOGERR_PERROR("openat()");
			return;
		}
		client->keyfilefd = fd;

		LOGINFO("(EKCD key from %s [%s])\n",
		    client->hostname, client_ntoa(client));
	} else
		fd = client->keyfilefd;

	bytes = pkt->hdr.mh_len;
	data = pkt->data;
	offset = pkt->hdr.mh_offset;
	do {
		n = pwrite(fd, data, bytes, offset);
		if (n < 0) {
			LOGERR_PERROR("write()");
			return;
		}
		bytes -= n;
		data += n;
		offset += n;
	} while (bytes > 0);

	send_ack(client, pkt->hdr.mh_seqno);
}

static void
handle_vmcore(struct netdump_client *client, struct netdump_pkt *pkt)
{

	client->any_data_rcvd = true;
	if (pkt->hdr.mh_seqno % (16 * 1024 * 1024 / 1456) == 0) {
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
	     (off_t)pkt->hdr.mh_offset))
		if (vmcore_flush(client) != 0)
			return;

	/*
	 * Buffer vmcore contents. This greatly improves throughput over
	 * simply writing each packet's contents directly.
	 */
	memcpy(client->vmcorebuf + client->vmcorebufoff, pkt->data,
	    pkt->hdr.mh_len);
	if (client->vmcorebufoff == 0)
		client->vmcoreoff = pkt->hdr.mh_offset;
	client->vmcorebufoff += pkt->hdr.mh_len;

	send_ack(client, pkt->hdr.mh_seqno);
}

static void
handle_finish(struct netdump_client *client, struct netdump_pkt *pkt)
{
	char symlinkpath[MAXPATHLEN], *symlinktarget;

	/* Make sure we commit any buffered vmcore data. */
	if (vmcore_flush(client) != 0)
		return;
	if (fsync(client->corefd) != 0)
		/* Not fatal. */
		LOGERR_PERROR("fsync()");

	/* Create symlinks to the new vmcore and info files. */
	snprintf(symlinkpath, sizeof(symlinkpath), "%s/vmcore.%s.last",
	    client->path, client->hostname);
	if (unlinkat(g_dumpdir_fd, symlinkpath, 0) != 0 && errno != ENOENT) {
		LOGERR_PERROR("unlinkat()");
		return;
	}
	symlinktarget = strdup(client->corefilename);
	if (symlinkat(basename(symlinktarget), g_dumpdir_fd,
	    symlinkpath) != 0) {
		LOGERR_PERROR("symlink()");
		free(symlinktarget);
		return;
	}
	free(symlinktarget);

	snprintf(symlinkpath, sizeof(symlinkpath), "%s/info.%s.last",
	    client->path, client->hostname);
	if (unlinkat(g_dumpdir_fd, symlinkpath, 0) != 0 && errno != ENOENT) {
		LOGERR_PERROR("unlinkat()");
		return;
	}
	symlinktarget = strdup(client->infofilename);
	if (symlinkat(basename(symlinktarget), g_dumpdir_fd,
	    symlinkpath) != 0) {
		LOGERR_PERROR("symlink()");
		free(symlinktarget);
		return;
	}
	free(symlinktarget);

	LOGINFO("Completed dump from client %s [%s]\n", client->hostname,
	    client_ntoa(client));
	client_pinfo(client, "Dump complete\n");
	send_ack(client, pkt->hdr.mh_seqno);
	exec_handler(client, "success");
	free_client(client);
}

/* Handle a read event on the server socket. */
static void
server_event(void)
{
	char *path;
	struct sockaddr_in saddr;
	struct netdump_client *client;
	uint32_t seqno;
	int error, sd;

	error = netdump_cap_herald(g_capherald, &sd, &saddr, &seqno, &path);
	if (error != 0) {
		LOGERR("netdump_cap_herald(): %s\n", strerror(error));
		return;
	}

	LIST_FOREACH(client, &g_clients, iter) {
		if (client->ip.s_addr == saddr.sin_addr.s_addr)
			break;
	}

	if (client != NULL) {
		if (!client->any_data_rcvd) {
			/* retransmit of the herald packet */
			send_ack(client, seqno);
			return;
		}
		handle_timeout(client);
	}

	/* path is always consumed or freed by alloc_client(). */
	client = alloc_client(sd, &saddr, path);
	path = NULL;
	if (client == NULL) {
		LOGERR(
		    "server_event(): new client allocation failure\n");
		return;
	}

	client_pinfo(client, "Dump from %s [%s]\n", client->hostname,
	    client_ntoa(client));
	LOGINFO("New dump from client %s [%s] (to %s)\n", client->hostname,
	    client_ntoa(client), client->corefilename);
	send_ack(client, seqno);
}

/* Handle a read event on a client socket. */
static void
client_event(struct netdump_client *client)
{
	struct netdump_pkt pkt;
	ssize_t len;

	if ((len = recv(client->sock, &pkt, sizeof(pkt), 0)) < 0) {
		if (errno != EAGAIN && errno != EINTR) {
			LOGERR_PERROR("recv()");
			handle_timeout(client);
		}
		return;
	}

	if ((size_t)len < sizeof(struct netdump_msg_hdr)) {
		LOGERR("Ignoring runt packet from %s (got %zu)\n",
		    client_ntoa(client), (size_t)len);
		return;
	}

	ndtoh(&pkt.hdr);

	if ((size_t)len - sizeof(struct netdump_msg_hdr) != pkt.hdr.mh_len) {
		LOGERR("Bad packet size from %s\n", client_ntoa(client));
		return;
	}

	client->last_msg = time(NULL);

	switch (pkt.hdr.mh_type) {
	case NETDUMP_KDH:
		handle_kdh(client, &pkt);
		break;
	case NETDUMP_EKCD_KEY:
		handle_ekcd_key(client, &pkt);
		break;
	case NETDUMP_VMCORE:
		handle_vmcore(client, &pkt);
		break;
	case NETDUMP_FINISHED:
		handle_finish(client, &pkt);
		break;
	default:
		LOGERR("Received unexpected message type %d from %s\n",
		    pkt.hdr.mh_type, client_ntoa(client));
		break;
	}
}

static int
eventloop(void)
{
	struct kevent events[8];
	struct timespec ts;
	struct netdump_client *client;
	int ev, rc;

	LOGINFO("Waiting for clients.\n");

	/* We check for timed-out clients regularly. */
	ts.tv_sec = CLIENT_TPASS;
	ts.tv_nsec = 0;

	for (;;) {
		rc = kevent(g_kq, NULL, 0, events, nitems(events), &ts);
		if (rc < 0) {
			if (errno == EINTR)
				continue;
			LOGERR_PERROR("kevent()");
			return (1);
		}

		g_now = time(NULL);
		for (ev = 0; ev < rc; ev++) {
			if (events[ev].filter == EVFILT_SIGNAL)
				/* We received SIGINT or SIGTERM. */
				goto out;

			if (events[ev].filter == EVFILT_READ) {
				if ((int)events[ev].ident == g_sock)
					server_event();
				else {
					client = events[ev].udata;
					client_event(client);
				}
				continue;
			}

			LOGERR("unexpected event %d", events[ev].filter);
			break;
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
	if (script == NULL)
		err(1, "strdup()");
	if (access(script, F_OK | X_OK)) {
		warn("cannot access %s", script);
		free(script);
		return (NULL);
	}
	return (script);
}

/*
 * Enter capability mode. This effectively sandboxes netdumpd by restricting its
 * ability to acquire new rights. In particular, capability mode enforces
 * restrictions on the dump path specified by a client: such paths are not
 * allowed to contain a '..' component or to follow a symlink containing '..'.
 *
 * Some operations that we need to perform after this point cannot be executed
 * in capability mode, so a few libcasper services are used. system.dns lets us
 * perform reverse lookups of client addresses, netdumpd.herald handles incoming
 * netdump requests and creates sockets for them, and netdumpd.handler is used
 * to execute a pre-defined script upon completion (successful or otherwise) of
 * a netdump.
 */
static int
init_cap_mode(void)
{
	cap_rights_t rights;
	cap_channel_t *capcasper;
	nvlist_t *limits;
	int error;

	error = 1;

	capcasper = cap_init();
	if (capcasper == NULL) {
		LOGERR_PERROR("cap_init()");
		return (1);
	}

	if (cap_enter() != 0) {
		LOGERR_PERROR("cap_enter()");
		goto err;
	}

	/* CAP_FCNTL is needed by fdopen(3). */
	cap_rights_init(&rights, CAP_CREATE, CAP_FCNTL, CAP_FTRUNCATE,
	    CAP_FSYNC, CAP_PWRITE, CAP_READ, CAP_RENAMEAT_SOURCE,
	    CAP_RENAMEAT_TARGET, CAP_SYMLINKAT, CAP_UNLINKAT);
	if (cap_rights_limit(g_dumpdir_fd, &rights) != 0) {
		LOGERR_PERROR("cap_rights_limit()");
		goto err;
	}
	cap_rights_init(&rights, CAP_SEND, CAP_RECV);
	if (cap_rights_limit(g_sock, &rights) != 0) {
		LOGERR_PERROR("cap_rights_limit()");
		goto err;
	}

	g_capdns = cap_service_open(capcasper, "system.dns");
	if (g_capdns == NULL) {
		LOGERR_PERROR("cap_service_open(system.dns)");
		goto err;
	}
	limits = nvlist_create(0);
	nvlist_add_string(limits, "type", "NAME");
	nvlist_add_number(limits, "family", (uint64_t)AF_INET);
	if (cap_limit_set(g_capdns, limits) != 0) {
		LOGERR_PERROR("cap_limit_set(system.dns)");
		goto err;
	}

	g_capherald = cap_service_open(capcasper, "netdumpd.herald");
	if (g_capherald == NULL) {
		LOGERR_PERROR("cap_service_open(netdumpd.herald)");
		goto err;
	}
	limits = nvlist_create(0);
	nvlist_add_descriptor(limits, "socket", g_sock);
	if (cap_limit_set(g_capherald, limits) != 0) {
		LOGERR_PERROR("cap_limit_set(netdump.herald)");
		goto err;
	}

	if (g_handler_script != NULL) {
		g_caphandler = cap_service_open(capcasper, "netdumpd.handler");
		if (g_caphandler == NULL) {
			LOGERR_PERROR("cap_service_open(netdumpd.handler)");
			goto err;
		}
		limits = nvlist_create(0);
		nvlist_add_string(limits, "dumpdir", g_dumpdir);
		nvlist_add_string(limits, "handler_script", g_handler_script);
		if (cap_limit_set(g_caphandler, limits) != 0) {
			LOGERR_PERROR("cap_limit_set(netdump.handler)");
			goto err;
		}
	}

	error = 0;

err:
	/* Other capabilities are closed by main(). */
	cap_close(capcasper);
	return (error);
}

static int
init_kqueue(void)
{
	struct kevent sockev, sigev[2];
	sigset_t set;

	g_kq = kqueue();
	if (g_kq < 0) {
		LOGERR_PERROR("kqueue()");
		return (1);
	}

	EV_SET(&sockev, g_sock, EVFILT_READ, EV_ADD, 0, 0, NULL);
	if (kevent(g_kq, &sockev, 1, NULL, 0, NULL) != 0) {
		LOGERR_PERROR("kevent(socket)");
		return (1);
	}

	/* Mask all signals. We watch for SIGINT and SIGTERM only. */
	sigfillset(&set);
	if (sigprocmask(SIG_BLOCK, &set, NULL) != 0) {
		LOGERR_PERROR("sigprocmask()");
		return (1);
	}
	EV_SET(&sigev[0], SIGINT, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	EV_SET(&sigev[1], SIGTERM, EVFILT_SIGNAL, EV_ADD, 0, 0, NULL);
	if (kevent(g_kq, sigev, nitems(sigev), NULL, 0, NULL) != 0) {
		LOGERR_PERROR("kevent(signals)");
		return (1);
	}
	return (0);
}

static int
init_server_socket(void)
{
	struct sockaddr_in bindaddr;
	int one;

	if (g_bindip.s_addr == INADDR_ANY)
		warnx("default: listening on all interfaces");
	g_sock = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, IPPROTO_UDP);
	if (g_sock == -1) {
		LOGERR_PERROR("socket()");
		return (1);
	}

	/*
	 * When a client initiates a netdump, we must ensure that we respond
	 * using the source address expected by the client. We thus configure
	 * IP_RECVDSTADDR so that we may bind+connect using the provided
	 * address. (The bind+connect is done by a libcasper service.)
	 */
	one = 1;
	if (setsockopt(g_sock, IPPROTO_IP, IP_RECVDSTADDR, &one,
	    sizeof(one)) != 0) {
		LOGERR_PERROR("setsockopt()");
		return (1);
	}
	memset(&bindaddr, 0, sizeof(bindaddr));
	bindaddr.sin_len = sizeof(bindaddr);
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_addr.s_addr = g_bindip.s_addr;
	bindaddr.sin_port = htons(NETDUMP_PORT);
	if (bind(g_sock, (struct sockaddr *)&bindaddr, sizeof(bindaddr))) {
		LOGERR_PERROR("bind()");
		return (1);
	}
	if (fcntl(g_sock, F_SETFL, O_NONBLOCK) == -1) {
		LOGERR_PERROR("fcntl()");
		return (1);
	}
	return (0);
}

int
main(int argc, char **argv)
{
	char pidfile[MAXPATHLEN];
	struct stat statbuf;
	int ch, exit_code;

	openlog("netdumpd", LOG_PID | LOG_NDELAY, LOG_DAEMON);

	g_bindip.s_addr = INADDR_ANY;

	exit_code = 1;
	pidfile[0] = '\0';
	while ((ch = getopt(argc, argv, "a:Dd:i:P:p:")) != -1) {
		switch (ch) {
		case 'a':
			if (inet_aton(optarg, &g_bindip) == 0) {
				warnx("invalid bind IP specified");
				goto cleanup;
			}
			warnx("listening on IP %s", optarg);
			break;
		case 'D':
			g_debug = true;
			break;
		case 'd':
			if (strlcpy(g_dumpdir, optarg, sizeof(g_dumpdir)) >=
			    sizeof(g_dumpdir)) {
				warnx("dumpdir '%s' is too long", optarg);
				goto cleanup;
			}
			break;
		case 'i':
			g_handler_script = get_script_option();
			if (g_handler_script == NULL)
				goto cleanup;
			break;
		case 'P':
			if (strlcpy(pidfile, optarg, sizeof(pidfile)) >=
			    sizeof(pidfile)) {
				warnx("pidfile '%s' is too long", optarg);
				goto cleanup;
			}
			break;
		case 'p':
			if (strlcpy(g_defpath, optarg, sizeof(g_defpath)) >=
			    sizeof(g_defpath)) {
				warnx("default path '%s' is too long", optarg);
				goto cleanup;
			}
			break;
		default:
			usage();
			goto cleanup;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0)
		usage();

	g_pfh = pidfile_open(pidfile[0] != '\0' ? pidfile : NULL, 0600, NULL);
	if (g_pfh == NULL) {
		if (errno == EEXIST)
			errx(1, "netdumpd is already running");
		else
			err(1, "pidfile_open");
	}

	if (g_debug)
		g_phook = phook_printf;
	else
		g_phook = syslog;

	if (g_dumpdir[0] == '\0') {
		strcpy(g_dumpdir, "/var/crash");
		warnx("default: dumping to /var/crash/");
	}
	if (g_defpath[0] == '\0')
		strcpy(g_defpath, ".");

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

	g_dumpdir_fd = open(g_dumpdir, O_DIRECTORY | O_RDONLY | O_CLOEXEC);
	if (g_dumpdir_fd < 0) {
		warn("open(%s)", g_dumpdir);
		goto cleanup;
	}

	if (!g_debug && daemon(0, 0) == -1) {
		warn("daemon()");
		goto cleanup;
	}
	if (pidfile_write(g_pfh) != 0) {
		warn("pidfile_write()");
		goto cleanup;
	}

	if (init_server_socket())
		goto cleanup;
	if (init_kqueue())
		goto cleanup;
	if (init_cap_mode())
		goto cleanup;

	exit_code = eventloop();

cleanup:
	if (g_pfh != NULL && pidfile_remove(g_pfh) != 0)
		warn("pidfile_remove");
	(void)close(g_dumpdir_fd);
	free(g_handler_script);
	if (g_sock != -1)
		close(g_sock);
	if (g_capherald != NULL)
		cap_close(g_capherald);
	if (g_capdns != NULL)
		cap_close(g_capdns);
	return (exit_code);
}
