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
#include <sys/nv.h>
#include <sys/procdesc.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "netdumpd.h"

/*
 * The handler capability lets us invoke a script upon completion (successful or
 * otherwise) of a netdump. The script is executed with cwd set to the dumpdir.
 */

int
netdump_handler(const char *script, const char *reason, const char *ip,
    const char *hostname, const char *infofile, const char *corefile)
{
	int pd;
    const char *argv[7];
    pid_t pid;

    // Starting with linux unfriendly code (pdfork)
    // ?? errno?
    if ((pid = pdfork(&pd, PD_CLOEXEC)) < 0)
        return (errno);
    if (pid == 0) {
        argv[0] = script;
        argv[1] = reason;
        argv[2] = ip;
        argv[3] = hostname;
        argv[4] = infofile;
        argv[5] = corefile;
        argv[6] = NULL;
        (void)execve(script, __DECONST(char *const *, argv), NULL);
        _exit(1);
    }

    // ?? is this correct?
    // if (pd != -1) {
    //  (void)close(pd);
    //  pd = -1;
    // }
    // return (pd);
    return pd;
}
