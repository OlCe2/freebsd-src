/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2002 Poul-Henning Kamp
 * Copyright (c) 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project by Poul-Henning Kamp
 * and NAI Labs, the Security Research Division of Network Associates, Inc.
 * under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"), as part of the
 * DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote
 *    products derived from this software without specific prior written
 *    permission.
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

#ifndef _SYS_KERNELDUMP_H
#define _SYS_KERNELDUMP_H

#ifdef __amd64__
#define OS_HIBERNATE_SUPPORT
#endif

#include <sys/param.h>
#include <sys/conf.h>

#include <machine/endian.h>

#if BYTE_ORDER == LITTLE_ENDIAN
#define	dtoh32(x)	__bswap32(x)
#define	dtoh64(x)	__bswap64(x)
#define	htod32(x)	__bswap32(x)
#define	htod64(x)	__bswap64(x)
#elif BYTE_ORDER == BIG_ENDIAN
#define	dtoh32(x)	(x)
#define	dtoh64(x)	(x)
#define	htod32(x)	(x)
#define	htod64(x)	(x)
#endif

/*
 * Don't touch the first SIZEOF_METADATA bytes on the dump device.  This is to
 * protect us from metadata and metadata from us.
 */
#define	SIZEOF_METADATA			(64 * 1024)

#define	KERNELDUMP_COMP_NONE		0
#define	KERNELDUMP_COMP_GZIP		1
#define	KERNELDUMP_COMP_ZSTD		2

#define	KERNELDUMP_ENC_NONE		0
#define	KERNELDUMP_ENC_AES_256_CBC	1
#define	KERNELDUMP_ENC_CHACHA20		2

#define	KERNELDUMP_BUFFER_SIZE		4096
#define	KERNELDUMP_IV_MAX_SIZE		32
#define	KERNELDUMP_KEY_MAX_SIZE		64
#define	KERNELDUMP_ENCKEY_MAX_SIZE	(16384 / 8)

/*
 * All uintX_t fields are in dump byte order, which is the same as
 * network byte order. Use the macros defined above to read or
 * write the fields.
 */
struct kerneldumpheader {
	char		magic[20];
#define	KERNELDUMPMAGIC		"FreeBSD Kernel Dump"
#define	TEXTDUMPMAGIC		"FreeBSD Text Dump"
#define	KERNELDUMPMAGIC_CLEARED	"Cleared Kernel Dump"
	char		architecture[12];
	uint32_t	version;
#define	KERNELDUMPVERSION		4
#define	KERNELDUMP_TEXT_VERSION		4
	uint32_t	architectureversion;
#define	KERNELDUMP_AARCH64_VERSION	1
#define	KERNELDUMP_AMD64_VERSION	2
#define	KERNELDUMP_ARM_VERSION		1
#define	KERNELDUMP_I386_VERSION		2
#define	KERNELDUMP_MIPS_VERSION		1
#define	KERNELDUMP_POWERPC_VERSION	1
#define	KERNELDUMP_RISCV_VERSION	1
#define	KERNELDUMP_SPARC64_VERSION	1
	uint64_t	dumplength;		/* excl headers */
	uint64_t	dumptime;
	uint32_t	dumpkeysize;
	uint32_t	blocksize;
	char		hostname[64];
	char		versionstring[192];
	char		panicstring[175];
	uint8_t		compression;
	uint64_t	dumpextent;
	char		unused[4];
	uint32_t	parity;
};

struct kerneldumpkey {
	uint8_t		kdk_encryption;
	uint8_t		kdk_iv[KERNELDUMP_IV_MAX_SIZE];
	uint32_t	kdk_encryptedkeysize;
	uint8_t		kdk_encryptedkey[];
} __packed;

/*
 * Parity calculation is endian insensitive.
 */
static __inline u_int32_t
kerneldump_parity(struct kerneldumpheader *kdhp)
{
	uint32_t *up, parity;
	u_int i;

	up = (uint32_t *)kdhp;
	parity = 0;
	for (i = 0; i < sizeof *kdhp; i += sizeof *up)
		parity ^= *up++;
	return (parity);
}

#ifdef _KERNEL

#include <sys/_mutex.h>

/*
 * XXX - These temporarily made public, as these are also needed by
 * 'kern_dump.c'.  All code related to dumper configuration should be moved to
 * 'kern_dump.c', which will remove the need for exposing these here.
 */
extern struct mtx dumpconf_list_lk;
extern TAILQ_HEAD(dumpconflist, dumperinfo) dumper_configs;

bool has_dumpers(void);

struct dump_pa {
	vm_paddr_t pa_start;
	vm_paddr_t pa_size;
};

struct minidumpstate {
	struct msgbuf	*msgbufp;
	struct bitset	*dump_bitset;
};

int minidumpsys(struct dumperinfo *, bool);
int dumpsys_generic(struct dumperinfo *);

void dumpsys_map_chunk(vm_paddr_t, size_t, void **);
typedef int dumpsys_callback_t(struct dump_pa *, int, void *);
int dumpsys_foreach_chunk(dumpsys_callback_t, void *);
int dumpsys_cb_dumpdata(struct dump_pa *, int, void *);
int dumpsys_buf_seek(struct dumperinfo *, size_t);
int dumpsys_buf_write(struct dumperinfo *, const char *, size_t);
int dumpsys_buf_flush(struct dumperinfo *);

void dumpsys_gen_pa_init(void);
struct dump_pa *dumpsys_gen_pa_next(struct dump_pa *);
void dumpsys_gen_wbinv_all(void);
void dumpsys_gen_unmap_chunk(vm_paddr_t, size_t, void *);
int dumpsys_gen_write_aux_headers(struct dumperinfo *);

void dumpsys_pb_init(uint64_t);
void dumpsys_pb_progress(size_t);

extern int do_minidump;

int livedump_start(int, int, uint8_t);
int livedump_start_vnode(struct vnode *, int, uint8_t);

/* Live minidump events */
typedef void (*livedump_start_fn)(void *arg, int *errorp);
typedef void (*livedump_dump_fn)(void *arg, void *virtual, off_t offset,
    size_t len, int *errorp);
typedef void (*livedump_finish_fn)(void *arg);
EVENTHANDLER_DECLARE(livedumper_start, livedump_start_fn);
EVENTHANDLER_DECLARE(livedumper_dump, livedump_dump_fn);
EVENTHANDLER_DECLARE(livedumper_finish, livedump_finish_fn);


#ifdef OS_HIBERNATE_SUPPORT
/* Hibernate support. */

/*
 * XXX
 *
 * 1. Current allocation strategy is very simple (avoid lower physical
 *    addresses) and may need to be revised to instead be based on the initial
 *    EFI map at previous boot.
 * 2. Some of these may become machine-dependent at some point.
 */

/* Sizes in bytes. */
#define HIBERNATE_CONTIG_SPARE_SIZE	(1 * 1024 * 1024)
#define HIBERNATE_SPARE_SIZE		(128 * 1024 * 1024)
#define HIBERNATE_PADDR_MIN		(2 *				\
    (HIBERNATE_CONTIG_SPARE_SIZE + HIBERNATE_SPARE_SIZE))

struct hibernate_cb;
struct hibernate_pcb;

int dumpsys_hibernate_create_hcb(uint64_t _hardware_signature,
    struct hibernate_cb **_hcb_out);
void dumpsys_hibernate_free_hcb(struct hibernate_cb *);
int dump_for_hibernate(const struct hibernate_cb *,
    const struct hibernate_pcb *);
#endif /* OS_HIBERNATE_SUPPORT */

#endif /* _KERNEL */

#endif /* _SYS_KERNELDUMP_H */
