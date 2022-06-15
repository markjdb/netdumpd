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

#ifndef _NETDUMPD_H_
#define	_NETDUMPD_H_

#include <sys/types.h>

struct cap_channel;
struct sockaddr_in;

int	netdump_cap_handler(struct cap_channel *, const char *, const char *,
	    const char *, const char *, const char *);
int	netdump_cap_herald(struct cap_channel *, int *, struct sockaddr_in *,
	    uint32_t *, char **);

#define	NETDUMP_DATASIZE	4096
#define	NETDUMP_PORT		20023
#define	NETDUMP_ACKPORT		20024

struct netdump_msg_hdr {
#define	NETDUMP_HERALD		1
#define	NETDUMP_FINISHED	2
#define	NETDUMP_VMCORE		3
#define	NETDUMP_KDH		4
#define	NETDUMP_EKCD_KEY	5
	uint32_t	mh_type;
	uint32_t	mh_seqno;
	uint64_t	mh_offset;
	uint32_t	mh_len;
	uint32_t	mh_aux2;
} __packed;

struct netdump_ack {
	uint32_t	na_seqno;
} __packed;

struct netdump_pkt {
	struct netdump_msg_hdr hdr;
	uint8_t		data[NETDUMP_DATASIZE];
} __packed;

#define	ndtoh(hdr) do {					\
	(hdr)->mh_type = ntohl((hdr)->mh_type);		\
	(hdr)->mh_seqno = ntohl((hdr)->mh_seqno);	\
	(hdr)->mh_offset = be64toh((hdr)->mh_offset);	\
	(hdr)->mh_len = ntohl((hdr)->mh_len);		\
} while (0)

#endif /* _NETDUMPD_H_ */
