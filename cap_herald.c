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

#include <sys/param.h>
#include <sys/dnv.h>
#include <sys/endian.h>
#include <sys/iov.h>
#include <sys/nv.h>
#include <sys/dnv.h>

#include <netinet/in.h>
#include <netinet/netdump/netdump.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <libcasper.h>
#include <libcasper_service.h>

#include "netdumpd.h"

/*
 * The herald capability allows netdumpd to process netdump herald messages.
 * Upon receipt of such a message, netdumpd needs to reply using a socket bound
 * to the destination address of the message and an ephemeral port. Such a
 * socket cannot be created in capability mode.
 *
 * The herald service reads a herald message from the pre-defined server socket.
 * If the message is valid, the service will create, bind, and connect a socket
 * with which to continue the transfer, and will the send the socket and some
 * other client parameters to netdumpd.
 */

int
netdump_cap_herald(cap_channel_t *cap, int *nsd, struct sockaddr_in *sin,
    uint32_t *seqno, char **pathp)
{
	nvlist_t *nvl;
	const struct sockaddr_in *sinp;
	size_t sz;
	int error;

	nvl = nvlist_create(0);
	nvlist_add_string(nvl, "cmd", "herald");
	nvl = cap_xfer_nvlist(cap, nvl);
	if (nvl == NULL)
		return (errno);

	error = (int)dnvlist_get_number(nvl, "error", 0);
	if (error != 0)
		goto out;

	/* Fetch output values. */
	sinp = nvlist_get_binary(nvl, "srcaddr", &sz);
	if (sz != sizeof(*sin))
		errx(1, "size mismatch for 'srcaddr': got %zu", sz);
	memcpy(sin, sinp, sizeof(*sin));
	*pathp = dnvlist_take_string(nvl, "path", NULL);
	*seqno = (uint32_t)nvlist_get_number(nvl, "seqno");
	*nsd = nvlist_take_descriptor(nvl, "socket");
out:
	nvlist_destroy(nvl);
	return (error);
}

static int
herald_command(const char *cmd, const nvlist_t *limits,
    nvlist_t *nvlin __unused, nvlist_t *nvlout)
{
	struct {
		struct netdump_msg_hdr hdr;
		char data[MAXPATHLEN];
	} ndmsg;
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_storage ss;
	struct sockaddr_in sin, *from;
	struct cmsghdr *cmh;
	struct in_addr *dip;
	size_t cmsgsz, pathsz;
	ssize_t len;
	int error, sd, nsd;

	error = 0;
	nsd = -1;

	if (strcmp(cmd, "herald") != 0)
		return (EINVAL);

	memset(&msg, 0, sizeof(msg));
	memset(&ss, 0, sizeof(ss));

	iov.iov_base = &ndmsg;
	iov.iov_len = sizeof(ndmsg);

	msg.msg_name = &ss;
	msg.msg_namelen = sizeof(ss);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	cmsgsz = CMSG_SPACE(sizeof(struct in_addr));
	msg.msg_control = calloc(1, cmsgsz);
	if (msg.msg_control == NULL) {
		error = errno;
		goto out;
	}
	msg.msg_controllen = cmsgsz;

	sd = nvlist_get_descriptor(limits, "socket");
	len = recvmsg(sd, &msg, 0);
	if (len < 0) {
		error = errno;
		goto out;
	}

	if ((size_t)len < sizeof(struct netdump_msg_hdr)) {
		error = EINVAL;
		goto out;
	}
	ndtoh(&ndmsg.hdr);
	if (ndmsg.hdr.mh_type != NETDUMP_HERALD ||
	    (size_t)len - sizeof(struct netdump_msg_hdr) != ndmsg.hdr.mh_len ||
	    ss.ss_family != AF_INET) {
		error = EINVAL;
		goto out;
	}

	cmh = CMSG_FIRSTHDR(&msg);
	if (cmh->cmsg_level != IPPROTO_IP || cmh->cmsg_type != IP_RECVDSTADDR) {
		error = EINVAL;
		goto out;
	}
	dip = (struct in_addr *)(void *)CMSG_DATA(msg.msg_control);

	nsd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    IPPROTO_UDP);
	if (nsd < 0) {
		error = errno;
		goto out;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = dip->s_addr;
	sin.sin_port = htons(0);
	if (bind(nsd, (struct sockaddr *)&sin, sin.sin_len) != 0) {
		error = errno;
		goto out;
	}

	from = (struct sockaddr_in *)msg.msg_name;
	from->sin_port = htons(NETDUMP_ACKPORT);
	if (connect(nsd, (struct sockaddr *)from, from->sin_len) != 0) {
		error = errno;
		goto out;
	}

	/* Marshall out-params. */
	nvlist_move_descriptor(nvlout, "socket", nsd);
	nvlist_add_number(nvlout, "seqno", (uint64_t)ndmsg.hdr.mh_seqno);
	pathsz = ndmsg.hdr.mh_len;
	if (pathsz > 0 && pathsz <= MIN(MAXPATHLEN, NETDUMP_DATASIZE) &&
	    ndmsg.data[pathsz - 1] == '\0')
		nvlist_add_string(nvlout, "path", ndmsg.data);
	nvlist_add_binary(nvlout, "srcaddr", from, sizeof(*from));

out:
	if (msg.msg_control != NULL)
		free(msg.msg_control);
	if (error != 0 && nsd >= 0)
		(void)close(nsd);
	return (error);
}

static int
herald_limit(const nvlist_t *oldlimits, const nvlist_t *newlimits)
{
	const char *name;
	void *cookie;
	int nvtype;
	bool hassock;

	/* Only allow limits to be set once. */
	if (oldlimits != NULL)
		return (ENOTCAPABLE);

	hassock = false;
	cookie = NULL;
	while ((name = nvlist_next(newlimits, &nvtype, &cookie)) != NULL) {
		if (nvtype == NV_TYPE_DESCRIPTOR && strcmp(name, "socket") == 0)
			hassock = true;
		else
			return (EINVAL);
	}
	if (!hassock)
		return (EINVAL);
	return (0);
}

CREATE_SERVICE("netdumpd.herald", herald_limit, herald_command, 0);
