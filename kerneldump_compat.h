/*-
 * Copyright (c) 2018 Mark Johnston <markj@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
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

#ifndef _KERNELDUMP_COMPAT_H_
#define	_KERNELDUMP_COMPAT_H_

struct kerneldumpheader_v1 {
	char		magic[20];
	char		architecture[12];
	uint32_t	version;
	uint32_t	architectureversion;
	uint64_t	dumplength;
	uint64_t	dumptime;
	uint32_t	blocksize;
	char		hostname[64];
	char		versionstring[192];
	char		panicstring[192];
	uint32_t	parity;
};

struct kerneldumpheader_v2 {
	char		magic[20];
	char		architecture[12];
	uint32_t	version;
	uint32_t	architectureversion;
	uint64_t	dumplength;
	uint64_t	dumptime;
	uint32_t	dumpkeysize;
	uint32_t	blocksize;
	char		hostname[64];
	char		versionstring[192];
	char		panicstring[188];
	uint32_t	parity;
};

struct kerneldumpheader_v3 {
	char		magic[20];
	char		architecture[12];
	uint32_t	version;
	uint32_t	architectureversion;
	uint64_t	dumplength;
	uint64_t	dumpextent;
	uint64_t	dumptime;
	uint32_t	dumpkeysize;
	uint32_t	blocksize;
	uint8_t		compression;
	char		hostname[64];
	char		versionstring[192];
	char		panicstring[179];
	uint32_t	parity;
};

#endif /* _KERNELDUMP_COMPAT_H_ */
