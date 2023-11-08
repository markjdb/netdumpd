/*-
 * Copyright (c) 2023 Dell EMC
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
#include <sys/socket.h>

#include <netinet/in.h>

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "netdumpd.h"

/*
 * The herald capability allows netdumpd to process netdump herald messages.
 * Upon receipt of such a message, netdumpd needs to reply using a socket bound
 * to the destination address of the message and an ephemeral port.
 *
 * The netdump_herald reads a herald message from the pre-defined server socket.
 * If the message is valid, the service will create, bind, and connect a socket
 * with which to continue the transfer, and will the send the socket and some
 * other client parameters to netdumpd.
 */

int
netdump_herald(int g_sock, int *nsd, struct sockaddr_in *sinp,
    uint32_t *seqno, char **pathp)
{
	int error;

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

	error = 0;
	*nsd = -1;

	// zero out all the things
	memset(&msg, 0, sizeof(msg));
	memset(&ss, 0, sizeof(ss));
	memset(&ndmsg, 0, sizeof(ndmsg));

	// Set io vector to the netdump message buffer
	iov.iov_base = &ndmsg;
	iov.iov_len = sizeof(ndmsg);

	// Track the socket and message together in msg
	msg.msg_name = &ss;
	msg.msg_namelen = sizeof(ss);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	// Set the size in bytes for control messages and track size in cmsgcz
	cmsgsz = CMSG_SPACE(sizeof(struct in_addr));

	// Allocate memory for the control messages and store size
	msg.msg_control = calloc(1, cmsgsz);
	if (msg.msg_control == NULL) {
		error = errno;
		goto out;
	}
	msg.msg_controllen = cmsgsz;

	// Read message from server socket in to msg, should include path
	len = recvmsg(g_sock, &msg, 0);
	if (len < 0) {
		error = errno;
		goto out;
	}

	// Confirm we got the entire message header
	if ((size_t)len < sizeof(struct netdump_msg_hdr)) {
		error = EINVAL;
		goto out;
	}

	// Convert netdump header to standard header
	ndtoh(&ndmsg.hdr);

	// Error if message header type != HERALD
	//  or original netdump header msg length - struct's length
	//  or socket protocol != AF_INET
	if (ndmsg.hdr.mh_type != NETDUMP_HERALD ||
	    (size_t)len - sizeof(struct netdump_msg_hdr) != ndmsg.hdr.mh_len ||
	    ss.ss_family != AF_INET) {
		error = EINVAL;
		goto out;
	}

	// Read control message header
	cmh = CMSG_FIRSTHDR(&msg);
	if (cmh->cmsg_level != IPPROTO_IP || cmh->cmsg_type != IP_RECVDSTADDR) {
		error = EINVAL;
		goto out;
	}

	// This is the IP receiving the HERALD msg
	// Useful when netdump server is multi homed
	dip = (struct in_addr *)(void *)CMSG_DATA(msg.msg_control);

	// Setup new client socket
	*nsd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
	    IPPROTO_UDP);
	if (*nsd < 0) {
		error = errno;
		goto out;
	}

	// Setup sockaddr_in for new listener on server
	// Zero out socket in, copy contents from msg, set dip IP
	memset(&sin, 0, sizeof(sin));
	sin.sin_len = sizeof(sin);
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = dip->s_addr;
	sin.sin_port = htons(0);  // pick random port

	if (bind(*nsd, (struct sockaddr *)&sin, sin.sin_len) != 0) {
		error = errno;
		goto out;
	}

	// Resuse sockaddr in msg for the ACK message
	from = (struct sockaddr_in *)msg.msg_name;
	from->sin_port = htons(NETDUMP_ACKPORT);
	if (connect(*nsd, (struct sockaddr *)from, from->sin_len) != 0) {
		error = errno;
		goto out;
	}

	// Setup sockaddr to return for alloc_client later
	memset(sinp, 0, sizeof(*sinp));
	memcpy(sinp, msg.msg_name, msg.msg_namelen);

	// Get the file path from the control message
	pathsz = ndmsg.hdr.mh_len;

	*pathp = NULL;
	if (pathsz > 0 && pathsz <= MIN(MAXPATHLEN, NETDUMP_DATASIZE) &&
	    ndmsg.data[pathsz - 1] == '\0')
	    *pathp = strdup(ndmsg.data);

	*seqno = ndmsg.hdr.mh_seqno;

out:
	// ?? Is this all I need to clean up?
	if (msg.msg_control != NULL)
		free(msg.msg_control);
	if (error != 0 && *nsd >= 0)
		(void)close(*nsd);
	return (error);
}
