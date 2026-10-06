/*-
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by Konstantin Belousov <kib@FreeBSD.org>, and
 * Olivier Certner <olce@FreeBSD.org> at Kumacom SARL, under sponsorship from
 * the FreeBSD Foundation.
 */

#include <sys/cdefs.h>
#include <sys/param.h>

#if defined(__amd64__)

#define __ELF_WORD_SIZE 64
#include <sys/elf_common.h>
#include <machine/elf.h>
#include <machine/hibernate.h>
#include <string.h>
#include <stdarg.h>
#include <stand.h>
#include <bootstrap.h>

#include <efi.h>
#include <efilib.h>
#include <Protocol/SimpleFileSystem.h>

#include "loader_efi.h"

#define HIBERNATE_IMAGE_OFFSET	65536ULL	/* 64 KiB = LBA 128 at 512b */
#define HIBERNATE_HDR_BUF_SIZE	(2 * 1024 * 1024)	/* 2 MiB */

#define HIBER_REFUSE_MAX_PROBES	16
#define HIBER_REFUSE_TEXT_MAX	4096
#define HIBER_TRACE_MAX		(96 * 1024)
#define HIBER_A1_BLOCK_SIZE	(16 * EFI_PAGE_SIZE)	/* fixed 64 KiB */
#define A1_BLK_CRC_MAX		65536	/* blocks per audit window (4 GiB) */

/*
 * Fixed sub-layout of the kernel-declared contiguous spare arena
 * (hc_contig_spare_start / hc_contig_spare_size).  The arena is disposable
 * handoff memory and is never a PT_LOAD destination, so loader workspaces
 * placed here cannot be clobbered by Phase A1 direct streaming or by EFI
 * allocations that alias a restore destination.  All offsets are relative
 * to hc_contig_spare_start; the arena must be >= HIBER_CSP_REQUIRED_SIZE.
 */
#define HIBER_CSP_PGTBL_START	0x02000		/* private 1:1 page tables */
#define HIBER_CSP_COPY_START	0x20000		/* deferred copy-entry list */
#define HIBER_CSP_COPY_END	0xb0000
#define HIBER_CSP_A1_CRC_START	0xb0000		/* A1 per-64KiB-block CRCs */
#define HIBER_CSP_A1_CRC_SIZE	0x40000		/* 65536 entries * 4 bytes */
#define HIBER_CSP_READBUF_START	0xf0000		/* Block I/O read buffer */
#define HIBER_CSP_READBUF_SIZE	0x10000		/* 64 KiB */
#define HIBER_CSP_REQUIRED_SIZE	0x100000	/* 1 MiB minimum arena */

/*
 * Console verbosity for hibernate resume (loader.env hibernate_loglevel).
 * Full message text is always teed into hiber_trace[] and flushed to
 * \efi\freebsd\hiber-trace.log on refuse — only the EFI FB/console is gated.
 */
enum hiber_log_level {
	HIBER_LOG_ERROR = 0,
	HIBER_LOG_WARN = 1,
	HIBER_LOG_INFO = 2,
	HIBER_LOG_DEBUG = 3,
};

static enum hiber_log_level hiber_console_level = HIBER_LOG_INFO;
static char hiber_trace[HIBER_TRACE_MAX];
static size_t hiber_trace_len;
static bool hiber_trace_truncated;
static bool hiber_log_inited;

static void
hiber_log_init(void)
{
	const char *v;
	char buf[32];
	size_t n;

	if (hiber_log_inited)
		return;
	hiber_log_inited = true;
	hiber_trace_len = 0;
	hiber_trace[0] = '\0';
	hiber_trace_truncated = false;

	v = getenv("hibernate_loglevel");
	if (v == NULL)
		v = getenv("hibernate_verbose");
	if (v == NULL)
		return;
	/* Strip optional surrounding quotes from loader.env. */
	n = strlen(v);
	if (n >= 2 && v[0] == '"' && v[n - 1] == '"') {
		n -= 2;
		if (n >= sizeof(buf))
			n = sizeof(buf) - 1;
		memcpy(buf, v + 1, n);
		buf[n] = '\0';
		v = buf;
	}
	if (strcasecmp(v, "error") == 0 || strcasecmp(v, "quiet") == 0 ||
	    strcmp(v, "0") == 0)
		hiber_console_level = HIBER_LOG_ERROR;
	else if (strcasecmp(v, "warn") == 0 || strcasecmp(v, "warning") == 0 ||
	    strcmp(v, "1") == 0)
		hiber_console_level = HIBER_LOG_WARN;
	else if (strcasecmp(v, "info") == 0 || strcmp(v, "2") == 0)
		hiber_console_level = HIBER_LOG_INFO;
	else if (strcasecmp(v, "debug") == 0 || strcasecmp(v, "verbose") == 0 ||
	    strcmp(v, "3") == 0)
		hiber_console_level = HIBER_LOG_DEBUG;
}

static void
hiber_log(enum hiber_log_level lvl, const char *fmt, ...)
{
	char line[384];
	va_list ap;
	int n;

	hiber_log_init();
	va_start(ap, fmt);
	n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof(line))
		n = (int)sizeof(line) - 1;

	if (hiber_trace_len + (size_t)n < HIBER_TRACE_MAX) {
		memcpy(hiber_trace + hiber_trace_len, line, (size_t)n);
		hiber_trace_len += (size_t)n;
		hiber_trace[hiber_trace_len] = '\0';
	} else if (!hiber_trace_truncated &&
	    hiber_trace_len + 48 < HIBER_TRACE_MAX) {
		const char *msg = "\n[hiber-trace truncated]\n";
		size_t m = strlen(msg);
		memcpy(hiber_trace + hiber_trace_len, msg, m);
		hiber_trace_len += m;
		hiber_trace[hiber_trace_len] = '\0';
		hiber_trace_truncated = true;
	}

	if (lvl <= hiber_console_level)
		printf("%s", line);
}

/*
 * Static refuse report filled as checks run, written once by
 * hibernate_refuse() (console tee + ESP overwrite). No heap.
 */
enum hiber_chk {
	HIBER_CHK_SKIP = 0,
	HIBER_CHK_PASS,
	HIBER_CHK_FAIL,
};

struct hiber_refuse_report {
	char	time[32];
	char	loader[96];
	char	boot_current[16];
	char	marker[64];
	char	probes[HIBER_REFUSE_MAX_PROBES][96];
	u_int	n_probes;
	char	image[128];
	char	elf[128];
	char	cb[192];
	char	pcb[192];
	char	mmap[160];
	char	stage[64];
	char	diag[512];
	enum hiber_chk chk_read;
	enum hiber_chk chk_elf_ident;
	enum hiber_chk chk_e_type;
	enum hiber_chk chk_e_machine;
	enum hiber_chk chk_phdr;
	enum hiber_chk chk_cb;
	enum hiber_chk chk_pcb;
	enum hiber_chk chk_staging_feas;
	enum hiber_chk chk_staging_crc;
	enum hiber_chk chk_tramp;
	enum hiber_chk chk_ebs;
	char	primary[80];
	bool	emitted;
};

static struct hiber_refuse_report hiber_refuse_rpt;
static char hiber_refuse_text[HIBER_REFUSE_TEXT_MAX];
static const char *hiber_refuse_pending;

static const char *
hiber_chk_str(enum hiber_chk c)
{
	switch (c) {
	case HIBER_CHK_PASS:
		return ("pass");
	case HIBER_CHK_FAIL:
		return ("fail");
	default:
		return ("skip");
	}
}

static void
hiber_refuse_reset(void)
{
	const char *var;
	EFI_TIME t;
	EFI_STATUS status;
	UINT16 boot_current;
	size_t sz;

	bzero(&hiber_refuse_rpt, sizeof(hiber_refuse_rpt));
	hiber_refuse_pending = NULL;
	hiber_refuse_text[0] = '\0';

	strlcpy(hiber_refuse_rpt.time, "n/a", sizeof(hiber_refuse_rpt.time));
	strlcpy(hiber_refuse_rpt.loader, "n/a", sizeof(hiber_refuse_rpt.loader));
	strlcpy(hiber_refuse_rpt.boot_current, "n/a",
	    sizeof(hiber_refuse_rpt.boot_current));
	strlcpy(hiber_refuse_rpt.marker, "hibernate_resume=absent",
	    sizeof(hiber_refuse_rpt.marker));
	strlcpy(hiber_refuse_rpt.image, "n/a", sizeof(hiber_refuse_rpt.image));
	strlcpy(hiber_refuse_rpt.elf, "n/a", sizeof(hiber_refuse_rpt.elf));
	strlcpy(hiber_refuse_rpt.cb, "n/a", sizeof(hiber_refuse_rpt.cb));
	strlcpy(hiber_refuse_rpt.pcb, "n/a", sizeof(hiber_refuse_rpt.pcb));
	strlcpy(hiber_refuse_rpt.mmap, "n/a", sizeof(hiber_refuse_rpt.mmap));
	strlcpy(hiber_refuse_rpt.stage, "n/a", sizeof(hiber_refuse_rpt.stage));
	hiber_refuse_rpt.diag[0] = '\0';

	if (bootprog_info != NULL && bootprog_info[0] != '\0')
		strlcpy(hiber_refuse_rpt.loader, bootprog_info,
		    sizeof(hiber_refuse_rpt.loader));

	if (RS != NULL) {
		status = RS->GetTime(&t, NULL);
		if (!EFI_ERROR(status)) {
			snprintf(hiber_refuse_rpt.time,
			    sizeof(hiber_refuse_rpt.time),
			    "%04u-%02u-%02uT%02u:%02u:%02u",
			    t.Year, t.Month, t.Day, t.Hour, t.Minute, t.Second);
		}
	}

	sz = sizeof(boot_current);
	if (efi_global_getenv("BootCurrent", &boot_current, &sz) == EFI_SUCCESS &&
	    sz >= sizeof(boot_current)) {
		snprintf(hiber_refuse_rpt.boot_current,
		    sizeof(hiber_refuse_rpt.boot_current), "%04x", boot_current);
	}

	var = getenv("hibernate_resume");
	if (var != NULL) {
		snprintf(hiber_refuse_rpt.marker, sizeof(hiber_refuse_rpt.marker),
		    "hibernate_resume=%s", var);
	}
}

static void
hiber_refuse_set_stage(const char *stage)
{
	if (stage == NULL)
		return;
	strlcpy(hiber_refuse_rpt.stage, stage, sizeof(hiber_refuse_rpt.stage));
}

static void
hiber_refuse_add_probe(u_int part, const char *result)
{
	if (hiber_refuse_rpt.n_probes >= HIBER_REFUSE_MAX_PROBES)
		return;
	snprintf(hiber_refuse_rpt.probes[hiber_refuse_rpt.n_probes],
	    sizeof(hiber_refuse_rpt.probes[0]),
	    "part=%u result=%s", part, result != NULL ? result : "n/a");
	hiber_refuse_rpt.n_probes++;
}

static void
hiber_refuse_format(void)
{
	struct hiber_refuse_report *r = &hiber_refuse_rpt;
	char *p = hiber_refuse_text;
	size_t rem = sizeof(hiber_refuse_text);
	int n;
	u_int i;

	n = snprintf(p, rem,
	    "hiber-refuse v1\n"
	    "time: %s\n"
	    "loader: %s\n"
	    "boot_current: %s\n"
	    "marker: %s\n"
	    "\n",
	    r->time, r->loader, r->boot_current, r->marker);
	if (n < 0)
		n = 0;
	if ((size_t)n >= rem)
		n = rem > 0 ? (int)rem - 1 : 0;
	p += n;
	rem -= n;

	if (r->n_probes == 0) {
		n = snprintf(p, rem, "probe: n/a\n");
		if (n > 0 && (size_t)n < rem) {
			p += n;
			rem -= n;
		}
	} else {
		for (i = 0; i < r->n_probes; i++) {
			n = snprintf(p, rem, "probe: %s\n", r->probes[i]);
			if (n < 0 || (size_t)n >= rem)
				break;
			p += n;
			rem -= n;
		}
	}

	n = snprintf(p, rem,
	    "image: %s\n"
	    "elf: %s\n"
	    "cb: %s\n"
	    "pcb: %s\n"
	    "mmap: %s\n"
	    "stage: %s\n"
	    "\n"
	    "checks:\n"
	    "  read image: %s\n"
	    "  elf ident: %s\n"
	    "  e_type: %s\n"
	    "  e_machine: %s\n"
	    "  phdr layout: %s\n"
	    "  CB validation: %s\n"
	    "  PCB size: %s\n"
	    "  FACS signature: skip (not implemented)\n"
	    "  staging feasibility: %s\n"
	    "  staging CRC: %s\n"
	    "  trampoline placement: %s\n"
	    "  ExitBootServices: %s\n"
	    "\n"
	    "primary: %s\n",
	    r->image, r->elf, r->cb, r->pcb, r->mmap, r->stage,
	    hiber_chk_str(r->chk_read),
	    hiber_chk_str(r->chk_elf_ident),
	    hiber_chk_str(r->chk_e_type),
	    hiber_chk_str(r->chk_e_machine),
	    hiber_chk_str(r->chk_phdr),
	    hiber_chk_str(r->chk_cb),
	    hiber_chk_str(r->chk_pcb),
	    hiber_chk_str(r->chk_staging_feas),
	    hiber_chk_str(r->chk_staging_crc),
	    hiber_chk_str(r->chk_tramp),
	    hiber_chk_str(r->chk_ebs),
	    r->primary[0] != '\0' ? r->primary : "n/a");
	if (n < 0)
		n = 0;
	if ((size_t)n >= rem)
		n = rem > 0 ? (int)rem - 1 : 0;
	p += n;
	rem -= n;

	if (r->diag[0] != '\0') {
		n = snprintf(p, rem, "diag: %s\n", r->diag);
		if (n > 0 && (size_t)n < rem) {
			p += n;
			rem -= n;
		}
	}
}

static void
hiber_esp_write_file(const CHAR16 *path, const char *text, size_t len,
    const char *tag)
{
	static EFI_GUID sfsp_guid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
	EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *fs;
	EFI_FILE_PROTOCOL *root, *file;
	EFI_STATUS status;
	UINTN wlen;

	fs = NULL;
	root = NULL;
	file = NULL;

	if (boot_img == NULL || boot_img->DeviceHandle == NULL || text == NULL ||
	    path == NULL) {
		printf("%s: ESP write failed unavailable\n", tag);
		return;
	}

	status = OpenProtocolByHandle(boot_img->DeviceHandle, &sfsp_guid,
	    (void **)&fs);
	if (EFI_ERROR(status) || fs == NULL) {
		printf("%s: ESP write failed %lu\n", tag, DECODE_ERROR(status));
		return;
	}

	status = fs->OpenVolume(fs, &root);
	if (EFI_ERROR(status) || root == NULL) {
		printf("%s: ESP write failed %lu\n", tag, DECODE_ERROR(status));
		return;
	}

	/* Overwrite: delete existing file if present, then create. */
	status = root->Open(root, &file, (CHAR16 *)(uintptr_t)path,
	    EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
	if (!EFI_ERROR(status) && file != NULL) {
		(void)file->Delete(file);
		file = NULL;
	}

	status = root->Open(root, &file, (CHAR16 *)(uintptr_t)path,
	    EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
	if (EFI_ERROR(status) || file == NULL) {
		printf("%s: ESP write failed %lu\n", tag, DECODE_ERROR(status));
		root->Close(root);
		return;
	}

	wlen = len;
	status = file->Write(file, &wlen, (void *)(uintptr_t)text);
	if (EFI_ERROR(status)) {
		printf("%s: ESP write failed %lu\n", tag, DECODE_ERROR(status));
	} else {
		(void)file->Flush(file);
	}
	file->Close(file);
	root->Close(root);
}

static void
hiber_refuse_write_esp(const char *text, size_t len)
{
	static CHAR16 refuse_path[] = L"\\efi\\freebsd\\hiber-refuse.log";

	hiber_esp_write_file(refuse_path, text, len, "hiber-refuse");
}

static void
hiber_trace_write_esp(void)
{
	static CHAR16 trace_path[] = L"\\efi\\freebsd\\hiber-trace.log";

	if (hiber_trace_len == 0)
		return;
	hiber_esp_write_file(trace_path, hiber_trace, hiber_trace_len,
	    "hiber-trace");
}

/*
 * Single refuse sink: finalize report, tee to printf, overwrite ESP log.
 * Never opens loader.env. On ESP failure print one line and continue boot.
 */
static void
hibernate_refuse(const char *primary)
{
	size_t len;

	if (hiber_refuse_rpt.emitted)
		return;

	if (primary != NULL && primary[0] != '\0')
		strlcpy(hiber_refuse_rpt.primary, primary,
		    sizeof(hiber_refuse_rpt.primary));
	if (hiber_refuse_rpt.primary[0] == '\0')
		strlcpy(hiber_refuse_rpt.primary, "no hibernate image found",
		    sizeof(hiber_refuse_rpt.primary));

	hiber_refuse_format();
	len = strlen(hiber_refuse_text);
	/* Refuse summary always hits the console (errors matter on FB). */
	printf("%s", hiber_refuse_text);
	hiber_refuse_write_esp(hiber_refuse_text, len);
	hiber_trace_write_esp();
	hiber_refuse_rpt.emitted = true;
	hiber_refuse_pending = NULL;
}

static bool
hibernate_resume_enabled(void)
{
	const char *var;

	var = getenv("hibernate_resume");
	if (var == NULL)
		return (false);
	if (strcmp(var, "YES") == 0 || strcmp(var, "\"YES\"") == 0 ||
	    strcasecmp(var, "yes") == 0 || strcasecmp(var, "\"yes\"") == 0 ||
	    strcmp(var, "1") == 0 || strcmp(var, "\"1\"") == 0)
		return (true);
	return (false);
}

enum hibernate_mem_class {
	HMC_CONVENTIONAL,
	HMC_RECLAIMABLE,
	HMC_LOADER_IN_USE,
	HMC_MUST_PRESERVE,
};

static enum hibernate_mem_class
hibernate_classify_mem_type(EFI_MEMORY_TYPE type)
{
	switch (type) {
	case EfiRuntimeServicesCode:
	case EfiRuntimeServicesData:
	case EfiReservedMemoryType:
	case EfiACPIMemoryNVS:
	case EfiACPIReclaimMemory:
	case EfiMemoryMappedIO:
	case EfiMemoryMappedIOPortSpace:
	case EfiPalCode:
	case EfiPersistentMemory:
	case EfiUnusableMemory:
		return (HMC_MUST_PRESERVE);
	case EfiLoaderCode:
	case EfiLoaderData:
		return (HMC_LOADER_IN_USE);
	case EfiBootServicesCode:
	case EfiBootServicesData:
		return (HMC_RECLAIMABLE);
	case EfiConventionalMemory:
		return (HMC_CONVENTIONAL);
	default:
		return (HMC_MUST_PRESERVE);
	}
}

static inline uint64_t
range_overlap(uint64_t a_start, uint64_t a_size, uint64_t b_start, uint64_t b_size,
    uint64_t *out_start, uint64_t *out_size)
{
	uint64_t a_end = a_start + a_size;
	uint64_t b_end = b_start + b_size;
	uint64_t o_start = (a_start > b_start) ? a_start : b_start;
	uint64_t o_end = (a_end < b_end) ? a_end : b_end;

	if (o_start < o_end) {
		if (out_start != NULL)
			*out_start = o_start;
		if (out_size != NULL)
			*out_size = o_end - o_start;
		return (o_end - o_start);
	}
	return (0);
}

static EFI_MEMORY_DESCRIPTOR *
hibernate_get_memmap(UINTN *map_sz, UINTN *map_key, UINTN *desc_sz, UINT32 *desc_ver)
{
	EFI_MEMORY_DESCRIPTOR *map;
	EFI_STATUS status;
	UINTN sz, key, dsz;
	UINT32 dver;

	sz = 0;
	map = NULL;
	key = 0;
	dsz = 0;
	dver = 0;

	for (;;) {
		status = BS->GetMemoryMap(&sz, map, &key, &dsz, &dver);
		if (!EFI_ERROR(status))
			break;
		if (status != EFI_BUFFER_TOO_SMALL) {
			hiber_log(HIBER_LOG_ERROR, "hibernate: GetMemoryMap error %lu\n",
			    DECODE_ERROR(status));
			if (map != NULL)
				free(map);
			return (NULL);
		}
		free(map);
		map = malloc(sz + (10 * dsz));
		if (map == NULL) {
			hiber_log(HIBER_LOG_ERROR, "hibernate: failed to allocate memory map buffer\n");
			return (NULL);
		}
	}

	*map_sz = sz;
	*map_key = key;
	*desc_sz = dsz;
	if (desc_ver != NULL)
		*desc_ver = dver;
	return (map);
}

struct hibernate_range {
	uint64_t start;
	uint64_t end;
};

static uint32_t hibernate_crc32_update(uint32_t, const void *, size_t);

struct a1_bad_stats {
	u_int n_bad;		/* uncapped count of mismatching 64 KiB blocks */
	u_int n_runs;		/* number of contiguous bad runs */
	uint64_t first_pa;	/* first bad block (scan order) */
	uint64_t last_pa;	/* last bad block (scan order) */
	uint64_t min_pa;	/* lowest bad block PA */
	uint64_t max_pa;	/* highest bad block PA */
	u_int n_samples;
	struct {
		uint64_t pa;
		uint32_t exp;
		uint32_t got;
	} sample[8];
};

/*
 * Cursor into the monotonically ordered direct-range stream.  Saving the
 * cursor at a window boundary lets the fixed CRC table be replayed without
 * storing one extent descriptor per block.
 */
struct a1_direct_cursor {
	u_int range;
	uint64_t pa;
};

/*
 * Audit exactly n_blk transfer extents beginning at *cursor.  The transfer
 * extent rule is identical to the streaming path, including short extents at
 * direct-range boundaries.  Return false on malformed ranges, arithmetic
 * failure, cursor exhaustion, or a table/range cardinality mismatch.
 */
static bool
a1_scan_bad_window(const struct hibernate_range *chunk_direct,
    u_int n_chunk_direct, struct a1_direct_cursor *cursor,
    const uint32_t *a1_blk_crc, u_int n_blk, struct a1_bad_stats *st)
{
	struct a1_direct_cursor cur;
	bool prev_bad;
	u_int bi;

	memset(st, 0, sizeof(*st));
	if (cursor == NULL || a1_blk_crc == NULL || n_blk == 0 ||
	    n_blk > A1_BLK_CRC_MAX)
		return (false);

	cur = *cursor;
	prev_bad = false;
	for (bi = 0; bi < n_blk; bi++) {
		uint64_t avail, blk_bytes, next_pa;
		uint32_t got_crc;

		while (cur.range < n_chunk_direct &&
		    cur.pa == chunk_direct[cur.range].end) {
			cur.range++;
			if (cur.range < n_chunk_direct)
				cur.pa = chunk_direct[cur.range].start;
		}
		if (cur.range >= n_chunk_direct ||
		    chunk_direct[cur.range].start >=
		    chunk_direct[cur.range].end ||
		    cur.pa < chunk_direct[cur.range].start ||
		    cur.pa >= chunk_direct[cur.range].end)
			return (false);

		avail = chunk_direct[cur.range].end - cur.pa;
		blk_bytes = avail > HIBER_A1_BLOCK_SIZE ?
		    HIBER_A1_BLOCK_SIZE : avail;
		if (blk_bytes == 0 || (blk_bytes % EFI_PAGE_SIZE) != 0 ||
		    cur.pa > UINT64_MAX - blk_bytes)
			return (false);
		next_pa = cur.pa + blk_bytes;
		if (next_pa > chunk_direct[cur.range].end)
			return (false);

		got_crc = hibernate_crc32_update(0xFFFFFFFF,
		    (const void *)(uintptr_t)cur.pa, (size_t)blk_bytes) ^
		    0xFFFFFFFF;
		if (got_crc != a1_blk_crc[bi]) {
			if (st->n_bad == 0) {
				st->first_pa = cur.pa;
				st->min_pa = cur.pa;
				st->max_pa = cur.pa;
			}
			st->last_pa = cur.pa;
			if (cur.pa < st->min_pa)
				st->min_pa = cur.pa;
			if (cur.pa > st->max_pa)
				st->max_pa = cur.pa;
			if (!prev_bad)
				st->n_runs++;
			if (st->n_samples < nitems(st->sample)) {
				st->sample[st->n_samples].pa = cur.pa;
				st->sample[st->n_samples].exp =
				    a1_blk_crc[bi];
				st->sample[st->n_samples].got = got_crc;
				st->n_samples++;
			}
			st->n_bad++;
			prev_bad = true;
		} else {
			prev_bad = false;
		}
		cur.pa = next_pa;
	}
	*cursor = cur;
	return (true);
}

static const EFI_MEMORY_DESCRIPTOR *
hibernate_find_memdesc(const EFI_MEMORY_DESCRIPTOR *map, u_int ndesc,
    UINTN desc_sz, uint64_t pa)
{
	u_int j;
	const EFI_MEMORY_DESCRIPTOR *md;

	if (map == NULL || ndesc == 0 || desc_sz == 0)
		return (NULL);
	for (j = 0, md = map; j < ndesc;
	    j++, md = NextMemoryDescriptor(md, desc_sz)) {
		uint64_t start = md->PhysicalStart;
		uint64_t end = start + md->NumberOfPages * EFI_PAGE_SIZE;

		if (pa >= start && pa < end)
			return (md);
	}
	return (NULL);
}

static inline void
add_avoid_range(struct hibernate_range *ranges, u_int *nranges, u_int max_ranges,
    uint64_t start, uint64_t size)
{
	if (size == 0 || *nranges >= max_ranges)
		return;
	ranges[*nranges].start = start;
	ranges[*nranges].end = start + size;
	(*nranges)++;
}

static inline bool
is_page_avoided(uint64_t pa, const struct hibernate_range *avoid, u_int navoid)
{
	for (u_int r = 0; r < navoid; r++) {
		if (pa < avoid[r].end && (pa + EFI_PAGE_SIZE) > avoid[r].start)
			return (true);
	}
	return (false);
}

/*
 * Compact IEEE 802.3 CRC32 calculation for hibernate staging integrity.
 */
static uint32_t hibernate_crc32_tab[256];
static bool hibernate_crc32_tab_inited;

static void
hibernate_crc32_init(void)
{
	uint32_t c;
	int i, j;

	for (i = 0; i < 256; i++) {
		c = (uint32_t)i;
		for (j = 0; j < 8; j++) {
			if (c & 1)
				c = 0xedb88320U ^ (c >> 1);
			else
				c >>= 1;
		}
		hibernate_crc32_tab[i] = c;
	}
	hibernate_crc32_tab_inited = true;
}

static uint32_t
hibernate_crc32_update(uint32_t crc, const void *buf, size_t len)
{
	const uint8_t *bp;
	size_t i;

	if (!hibernate_crc32_tab_inited)
		hibernate_crc32_init();
	bp = buf;
	for (i = 0; i < len; i++)
		crc = hibernate_crc32_tab[(crc ^ bp[i]) & 0xff] ^ (crc >> 8);
	return (crc);
}

struct hiber_copy_entry {
	uint64_t src_spare_pa;
	uint64_t dst_target_pa;
	uint64_t page_count;
};

struct hiber_trampoline_header {
	uint64_t magic;
	uint64_t copy_entries_pa;
	uint64_t entry_count;
	uint64_t target_rsp;
	uint64_t target_r12;
	uint64_t target_rip;
};

/*
 * Position-independent post-EBS resume stub.  L3 serializes it into the
 * protected contiguous-spare arena but does not execute it.
 */
extern const char hibernate_tramp_stub[];
extern const char hibernate_tramp_stub_end[];
#define HIBERNATE_TRAMP_STUB_SIZE \
    ((size_t)(hibernate_tramp_stub_end - hibernate_tramp_stub))

__asm__(
".text\n"
".globl hibernate_tramp_stub\n"
"hibernate_tramp_stub:\n"
"	lea -0x37(%rip), %rbx\n"
"	cli\n"
"	cld\n"
"	mov %cr0, %rax\n"
"	btrq $16, %rax\n"
"	mov %rax, %cr0\n"
"	lea 0x2000(%rbx), %rax\n"
"	mov %rax, %cr3\n"
"	lea 0x18000(%rbx), %rsp\n"
"	mov 0x08(%rbx), %rsi\n"
"	mov 0x10(%rbx), %rcx\n"
"	test %rcx, %rcx\n"
"	jz 2f\n"
"1:\n"
"	mov (%rsi), %rax\n"
"	mov 0x8(%rsi), %rdi\n"
"	mov 0x10(%rsi), %rdx\n"
"	shl $9, %rdx\n"
"	push %rsi\n"
"	push %rcx\n"
"	mov %rax, %rsi\n"
"	mov %rdx, %rcx\n"
"	rep movsq\n"
"	pop %rcx\n"
"	pop %rsi\n"
"	add $24, %rsi\n"
"	dec %rcx\n"
"	jnz 1b\n"
"2:\n"
"	mov 0x18(%rbx), %rsp\n"
"	mov 0x20(%rbx), %r12\n"
"	mov 0x28(%rbx), %rax\n"
"	jmp *%rax\n"
".globl hibernate_tramp_stub_end\n"
"hibernate_tramp_stub_end:\n"
);

static inline bool
hibernate_next_usable_spare(const struct hibernate_cb *cb, uint64_t *cursor,
    const struct hibernate_range *avoid, u_int navoid, uint64_t *out_pa)
{
	while (*cursor < cb->hc_spare_pages_nb) {
		uint64_t pa;

		pa = cb->hc_spare_pages[*cursor];
		(*cursor)++;
		if (!is_page_avoided(pa, avoid, navoid)) {
			*out_pa = pa;
			return (true);
		}
	}
	return (false);
}

static bool
hibernate_claim_next_spare(const struct hibernate_cb *cb, uint64_t *cursor,
    const struct hibernate_range *avoid, u_int navoid, uint64_t *out_pa,
    uint64_t *skipped)
{
	for (;;) {
		EFI_PHYSICAL_ADDRESS pa;

		if (!hibernate_next_usable_spare(cb, cursor, avoid, navoid,
		    out_pa))
			return (false);
		pa = *out_pa;
		if (!EFI_ERROR(BS->AllocatePages(AllocateAddress, EfiLoaderData,
		    1, &pa)))
			return (true);
		(*skipped)++;
	}
}

static bool
hibernate_append_copy_entry(struct hiber_copy_entry *entries,
    uint64_t *entry_count, uint64_t max_entries, uint64_t src_pa,
    uint64_t dst_pa)
{
	struct hiber_copy_entry *entry;

	if (*entry_count > 0) {
		entry = &entries[*entry_count - 1];
		if (entry->src_spare_pa +
		    entry->page_count * EFI_PAGE_SIZE == src_pa &&
		    entry->dst_target_pa +
		    entry->page_count * EFI_PAGE_SIZE == dst_pa) {
			entry->page_count++;
			return (true);
		}
	}
	if (*entry_count >= max_entries)
		return (false);
	entries[*entry_count].src_spare_pa = src_pa;
	entries[*entry_count].dst_target_pa = dst_pa;
	entries[*entry_count].page_count = 1;
	(*entry_count)++;
	return (true);
}

struct hibernate_restore {
	pdinfo_t *part;
	EFI_BLOCK_IO *blkio;
	uint32_t blksz;

	uint64_t loader_start;
	uint64_t loader_size;
	EFI_PHYSICAL_ADDRESS heap_base;
	UINTN heap_size;
	EFI_PHYSICAL_ADDRESS staging_base;
	UINTN staging_size;

	EFI_PHYSICAL_ADDRESS workspace;
	UINTN workspace_pages;
	const Elf_Ehdr *ehdr;
	const Elf_Phdr *ph;
	const struct hibernate_cb *cb;
	EFI_MEMORY_DESCRIPTOR *post_map;
	UINTN post_map_sz;
	UINTN post_map_key;
	UINTN post_desc_sz;
	UINT32 post_desc_ver;
	u_int post_ndesc;

	struct hibernate_range post_avoid[128];
	u_int n_post_avoid;
	bool post_contig_overlaps;
	u_int excluded_spare_cnt;
	uint64_t total_spare_bytes;
	uint64_t excluded_spare_bytes;
	uint64_t usable_spare_pages;
	uint64_t usable_spare_bytes;
	uint64_t must_stage_bytes;

	uint64_t csp_base;
	uint64_t csp_size;
	EFI_PHYSICAL_ADDRESS readbuf_paddr;
	uint32_t *a1_blk_crc;

	struct hibernate_range active_ranges[512];
	u_int n_active_ranges;
	/*
	 * Exact-address allocations backing every destination written before
	 * ExitBootServices.  Entries are coalesced and retained until EBS.
	 */
	struct hibernate_range direct_claims[512];
	u_int n_direct_claims;
	u_int direct_chunks_cnt;
	u_int deferred_chunks_cnt;
	uint64_t total_direct_bytes;
	uint64_t total_deferred_chunk_bytes;
	uint64_t total_deferred_pages;

	uint8_t *readbuf;
	struct hiber_copy_entry *entries;
	uint64_t entry_count;
	uint64_t max_entries;
	uint64_t total_staged_pages;
	uint64_t total_staged_crc;
	uint64_t claimed_spare_pages;
	uint64_t skipped_spare_claims;
	struct hiber_trampoline_header *thdr;
	u_int collisions;

	struct hibernate_range staging_reserved[1024];
	u_int n_staging_reserved;
	u_int direct_streamed_chunks;
	uint64_t total_streamed_bytes;
	UINTN ebs_map_sz;
	UINTN ebs_map_key;
	UINTN ebs_desc_sz;
	UINT32 ebs_desc_ver;
	EFI_STATUS ebs_status;
	int ebs_retry;
};

#define HIBER_DIRECT_CLAIM_CHUNK_PAGES	4096

static bool
hibernate_append_direct_claim(struct hibernate_restore *hr, uint64_t start,
    uint64_t end)
{
	struct hibernate_range *last;

	if (start >= end)
		return (false);
	if (hr->n_direct_claims > 0) {
		last = &hr->direct_claims[hr->n_direct_claims - 1];
		if (last->end == start) {
			last->end = end;
			return (true);
		}
	}
	if (hr->n_direct_claims >= nitems(hr->direct_claims))
		return (false);
	hr->direct_claims[hr->n_direct_claims].start = start;
	hr->direct_claims[hr->n_direct_claims].end = end;
	hr->n_direct_claims++;
	return (true);
}

static bool
hibernate_claim_direct_pages(struct hibernate_restore *hr, uint64_t start,
    uint64_t end)
{
	EFI_PHYSICAL_ADDRESS requested, allocated;
	EFI_STATUS status;
	UINTN pages;

	if (start >= end || (start & EFI_PAGE_MASK) != 0 ||
	    (end & EFI_PAGE_MASK) != 0)
		return (false);

	requested = start;
	allocated = requested;
	pages = EFI_SIZE_TO_PAGES(end - start);
	status = BS->AllocatePages(AllocateAddress, EfiLoaderData, pages,
	    &allocated);
	if (EFI_ERROR(status) || allocated != requested) {
		if (!EFI_ERROR(status))
			BS->FreePages(allocated, pages);
		return (false);
	}
	if (!hibernate_append_direct_claim(hr, start, end)) {
		BS->FreePages(allocated, pages);
		hiber_refuse_pending = "direct claim table overflow";
		return (false);
	}
	return (true);
}

static bool
hibernate_range_is_direct_claimed(const struct hibernate_restore *hr,
    uint64_t start, uint64_t size)
{
	uint64_t end;

	if (size == 0 || start > UINT64_MAX - size)
		return (false);
	end = start + size;
	for (u_int i = 0; i < hr->n_direct_claims; i++) {
		if (start >= hr->direct_claims[i].start &&
		    end <= hr->direct_claims[i].end)
			return (true);
	}
	return (false);
}

static void
hibernate_sort_merge_active(struct hibernate_restore *hr)
{
	u_int merged;

	for (u_int a = 0; a < hr->n_active_ranges; a++) {
		for (u_int b = a + 1; b < hr->n_active_ranges; b++) {
			if (hr->active_ranges[b].start <
			    hr->active_ranges[a].start) {
				struct hibernate_range tmp;

				tmp = hr->active_ranges[a];
				hr->active_ranges[a] = hr->active_ranges[b];
				hr->active_ranges[b] = tmp;
			}
		}
	}

	merged = 0;
	for (u_int a = 0; a < hr->n_active_ranges; a++) {
		if (merged == 0 ||
		    hr->active_ranges[a].start >
		    hr->active_ranges[merged - 1].end) {
			hr->active_ranges[merged++] = hr->active_ranges[a];
		} else if (hr->active_ranges[a].end >
		    hr->active_ranges[merged - 1].end) {
			hr->active_ranges[merged - 1].end =
			    hr->active_ranges[a].end;
		}
	}
	hr->n_active_ranges = merged;
}

static bool
hibernate_append_staging_reserved(struct hibernate_restore *hr,
    uint64_t start, uint64_t end)
{
	if (start >= end)
		return (true);
	if (hr->n_staging_reserved >= nitems(hr->staging_reserved))
		return (false);
	hr->staging_reserved[hr->n_staging_reserved].start = start;
	hr->staging_reserved[hr->n_staging_reserved].end = end;
	hr->n_staging_reserved++;
	return (true);
}

static void
hibernate_sort_merge_staging_reserved(struct hibernate_restore *hr)
{
	u_int merged;

	for (u_int a = 0; a < hr->n_staging_reserved; a++) {
		for (u_int b = a + 1; b < hr->n_staging_reserved; b++) {
			if (hr->staging_reserved[b].start <
			    hr->staging_reserved[a].start) {
				struct hibernate_range tmp;

				tmp = hr->staging_reserved[a];
				hr->staging_reserved[a] =
				    hr->staging_reserved[b];
				hr->staging_reserved[b] = tmp;
			}
		}
	}
	merged = 0;
	for (u_int i = 0; i < hr->n_staging_reserved; i++) {
		if (merged == 0 ||
		    hr->staging_reserved[i].start >
		    hr->staging_reserved[merged - 1].end) {
			hr->staging_reserved[merged++] =
			    hr->staging_reserved[i];
		} else if (hr->staging_reserved[i].end >
		    hr->staging_reserved[merged - 1].end) {
			hr->staging_reserved[merged - 1].end =
			    hr->staging_reserved[i].end;
		}
	}
	hr->n_staging_reserved = merged;
}

static bool
hibernate_prepare_staging_reserved(struct hibernate_restore *hr)
{
	uint64_t nb_pages, max_pages;

	hr->n_staging_reserved = 0;
	if (hr->cb->hc_contig_spare_size > 0 &&
	    !hibernate_append_staging_reserved(hr,
	    hr->cb->hc_contig_spare_start,
	    hr->cb->hc_contig_spare_start +
	    hr->cb->hc_contig_spare_size)) {
		hiber_refuse_pending = "staging reserved table overflow";
		return (false);
	}

	nb_pages = hr->cb->hc_spare_pages_nb;
	max_pages = hr->ph[0].p_filesz >
	    offsetof(struct hibernate_cb, hc_spare_pages) ?
	    (hr->ph[0].p_filesz -
	    offsetof(struct hibernate_cb, hc_spare_pages)) /
	    sizeof(uint64_t) : 0;
	if (nb_pages > max_pages)
		nb_pages = max_pages;

	for (uint64_t i = 0; i < nb_pages; i++) {
		uint64_t pa;

		pa = hr->cb->hc_spare_pages[i];
		if (hr->n_staging_reserved >=
		    nitems(hr->staging_reserved)) {
			hibernate_sort_merge_staging_reserved(hr);
			if (hr->n_staging_reserved >=
			    nitems(hr->staging_reserved)) {
				hiber_refuse_pending =
				    "staging reserved table overflow";
				return (false);
			}
		}
		if (!hibernate_append_staging_reserved(hr, pa,
		    pa + EFI_PAGE_SIZE)) {
			hiber_refuse_pending =
			    "staging reserved table overflow";
			return (false);
		}
	}
	hibernate_sort_merge_staging_reserved(hr);
	return (true);
}

static bool
hibernate_claim_direct_destinations(struct hibernate_restore *hr)
{
	struct hibernate_range candidates[512];
	u_int ncandidates;

	hr->n_direct_claims = 0;
	for (u_int i = 2; i < hr->ehdr->e_phnum; i++) {
		uint64_t c_start, c_end, cur;

		c_start = hr->ph[i].p_paddr;
		c_end = c_start + (hr->ph[i].p_memsz != 0 ?
		    hr->ph[i].p_memsz : hr->ph[i].p_filesz);
		cur = c_start;
		ncandidates = 0;

		while (cur < c_end) {
			uint64_t blocked_start, blocked_end;

			blocked_start = c_end;
			blocked_end = cur;
			for (u_int r = 0; r < hr->n_active_ranges; r++) {
				uint64_t start, end;

				start = hr->active_ranges[r].start;
				end = hr->active_ranges[r].end;
				if (end <= cur || start >= c_end)
					continue;
				if (start <= cur) {
					blocked_start = cur;
					if (end > blocked_end)
						blocked_end = end;
				} else if (start < blocked_start) {
					blocked_start = start;
					blocked_end = end;
				}
			}
			for (u_int r = 0; r < hr->n_staging_reserved; r++) {
				uint64_t start, end;

				start = hr->staging_reserved[r].start;
				end = hr->staging_reserved[r].end;
				if (end <= cur || start >= c_end)
					continue;
				if (start <= cur) {
					blocked_start = cur;
					if (end > blocked_end)
						blocked_end = end;
				} else if (start < blocked_start) {
					blocked_start = start;
					blocked_end = end;
				}
			}
			if (blocked_start > cur) {
				if (ncandidates >= nitems(candidates)) {
					hiber_refuse_pending =
					    "direct candidate table overflow";
					return (false);
				}
				candidates[ncandidates].start = cur;
				candidates[ncandidates].end = blocked_start;
				ncandidates++;
			}
			if (blocked_start == c_end)
				break;
			cur = blocked_end > cur ? blocked_end :
			    cur + EFI_PAGE_SIZE;
		}
		for (u_int d = 0; d < ncandidates; d++) {
			uint64_t pos;

			pos = candidates[d].start;
			while (pos < candidates[d].end) {
				uint64_t end, max_bytes;

				max_bytes = (uint64_t)
				    HIBER_DIRECT_CLAIM_CHUNK_PAGES *
				    EFI_PAGE_SIZE;
				end = candidates[d].end - pos > max_bytes ?
				    pos + max_bytes : candidates[d].end;
				if (hibernate_claim_direct_pages(hr, pos, end)) {
					pos = end;
					continue;
				}
				if (hiber_refuse_pending != NULL)
					return (false);

				for (uint64_t pa = pos; pa < end;
				    pa += EFI_PAGE_SIZE) {
					if (hibernate_claim_direct_pages(hr, pa,
					    pa + EFI_PAGE_SIZE))
						continue;
					if (hiber_refuse_pending != NULL)
						return (false);
					if (hr->n_active_ranges >=
					    nitems(hr->active_ranges)) {
						hiber_refuse_pending =
						    "active range overflow";
						return (false);
					}
					hr->active_ranges[
					    hr->n_active_ranges].start = pa;
					hr->active_ranges[
					    hr->n_active_ranges].end =
					    pa + EFI_PAGE_SIZE;
					hr->n_active_ranges++;
				}
				pos = end;
			}
		}
	}
	hibernate_sort_merge_active(hr);
	return (true);
}


static bool
hibernate_prepare_workspace(struct hibernate_restore *hr, uint8_t **bufp)
{
	uint64_t readbuf_start, readbuf_size;
	EFI_STATUS status;
	u_int ndesc2;

	hr->heap_base = 0;
	hr->staging_base = 0;
	hr->heap_size = 0;
	hr->staging_size = 0;

	readbuf_start = (bufp != NULL && *bufp != NULL) ?
	    (uint64_t)(uintptr_t)*bufp : 0;
	readbuf_size = HIBERNATE_HDR_BUF_SIZE;

	hr->loader_start = (boot_img != NULL) ?
	    (uint64_t)(uintptr_t)boot_img->ImageBase : 0;
	hr->loader_size = (boot_img != NULL) ?
	    (uint64_t)boot_img->ImageSize : 0;

	efi_heap_get_bounds(&hr->heap_base, &hr->heap_size);
	efi_staging_get_bounds(&hr->staging_base, &hr->staging_size);

	hiber_log(HIBER_LOG_INFO, "hibernate: loader allocation audit:\n");
	hiber_log(HIBER_LOG_INFO, "hibernate:   RESIDENT  binary  : 0x%016jx - 0x%016jx (%ju KiB)\n",
	    (uintmax_t)hr->loader_start, (uintmax_t)(hr->loader_start + hr->loader_size),
	    (uintmax_t)(hr->loader_size / 1024));
	hiber_log(HIBER_LOG_INFO, "hibernate:   TRANSIENT staging : 0x%016jx - 0x%016jx (%ju MiB)\n",
	    (uintmax_t)hr->staging_base, (uintmax_t)(hr->staging_base + hr->staging_size),
	    (uintmax_t)(hr->staging_size / (1024 * 1024)));
	hiber_log(HIBER_LOG_INFO, "hibernate:   TRANSIENT heap    : 0x%016jx - 0x%016jx (%ju MiB)\n",
	    (uintmax_t)hr->heap_base, (uintmax_t)(hr->heap_base + hr->heap_size),
	    (uintmax_t)(hr->heap_size / (1024 * 1024)));
	hiber_log(HIBER_LOG_INFO, "hibernate:   TRANSIENT readbuf : 0x%016jx - 0x%016jx (%ju KiB)\n",
	    (uintmax_t)readbuf_start, (uintmax_t)(readbuf_start + readbuf_size),
	    (uintmax_t)(readbuf_size / 1024));

	/*
	 * Allocate post-allocation workspace using AllocatePages so malloc()
	 * is never invoked while the loader heap is freed.
	 * Workspace holds:
	 *   [0 .. HIBERNATE_HDR_BUF_SIZE)        : Safe copy of headers (2 MiB)
	 *   [HIBERNATE_HDR_BUF_SIZE .. +128 KiB) : Post-allocation memory map (128 KiB)
	 */
	hr->workspace_pages =
	    EFI_SIZE_TO_PAGES(HIBERNATE_HDR_BUF_SIZE + 128 * 1024);
	hr->workspace = 0;

	status = BS->AllocatePages(AllocateAnyPages, EfiBootServicesData,
	    hr->workspace_pages, &hr->workspace);
	if (EFI_ERROR(status)) {
		hiber_log(HIBER_LOG_ERROR, "hibernate: failed to allocate post-allocation buffer: %lu\n",
		    DECODE_ERROR(status));
		hiber_refuse_pending = "allocation failed";
		return (false);
	}

	/*
	 * The Block I/O read buffer and the per-chunk A1 CRC table are NOT
	 * EFI-allocated. AllocateAnyPages can return pages that lie inside a
	 * PT_LOAD physical destination, and Phase A1 direct streaming then
	 * overwrites the loader's own workspace (observed as a corrupted
	 * expected-CRC table and tens of thousands of false clobber reports).
	 * Both workspaces are instead
	 * carved from the kernel-declared contiguous spare arena below, once
	 * hr->cb is available.
	 */
	if (bufp != NULL && *bufp != NULL)
		memcpy((void *)(uintptr_t)hr->workspace, *bufp, HIBERNATE_HDR_BUF_SIZE);

	hr->ehdr = (const Elf_Ehdr *)(uintptr_t)hr->workspace;
	hr->ph = (const Elf_Phdr *)((uintptr_t)hr->workspace +
	    hr->ehdr->e_phoff);
	hr->cb = (const struct hibernate_cb *)((uintptr_t)hr->workspace +
	    hr->ph[0].p_offset);

	/*
	 * Validate and adopt the fixed contiguous-spare workspace layout
	 * (HIBER_CSP_* above).  Refuse rather than fall back to an EFI
	 * allocation, which could alias a restore destination.
	 */
	hr->csp_base = hr->cb->hc_contig_spare_start;
	hr->csp_size = hr->cb->hc_contig_spare_size;
	if (hr->csp_base == 0 || hr->csp_size < HIBER_CSP_REQUIRED_SIZE ||
	    hr->csp_base + hr->csp_size < hr->csp_base) {
		hiber_log(HIBER_LOG_ERROR,
		    "hibernate: CSP_WORKSPACE_TOO_SMALL base=0x%jx size=0x%jx need=0x%x\n",
		    (uintmax_t)hr->csp_base, (uintmax_t)hr->csp_size,
		    HIBER_CSP_REQUIRED_SIZE);
		hiber_refuse_pending = "CSP_WORKSPACE_TOO_SMALL";
		return (false);
	}
	hr->readbuf_paddr = hr->csp_base + HIBER_CSP_READBUF_START;
	hr->a1_blk_crc = (uint32_t *)(uintptr_t)(hr->csp_base + HIBER_CSP_A1_CRC_START);
	hiber_log(HIBER_LOG_INFO,
	    "hibernate: CSP workspace: base=0x%016jx size=0x%jx "
	    "entries=[0x%x,0x%x) crc=[0x%x,0x%x) readbuf=[0x%x,0x%x)\n",
	    (uintmax_t)hr->csp_base, (uintmax_t)hr->csp_size,
	    HIBER_CSP_COPY_START, HIBER_CSP_COPY_END,
	    HIBER_CSP_A1_CRC_START,
	    HIBER_CSP_A1_CRC_START + HIBER_CSP_A1_CRC_SIZE,
	    HIBER_CSP_READBUF_START,
	    HIBER_CSP_READBUF_START + HIBER_CSP_READBUF_SIZE);

	/*
	 * Retain the loader's transient allocations (header pool, staging,
	 * heap) until ExitBootServices.  Returning them to the firmware pool
	 * while Boot Services remain active lets firmware reuse the released
	 * pages for storage-driver DMA/scratch, clobbering data restored into
	 * or staged from them.  Keeping them owned also keeps any overlapping
	 * image destination deferred until the post-EBS trampoline.
	 */
	hiber_log(HIBER_LOG_INFO,
	    "hibernate: retain staging [0x%016jx,0x%016jx)\n",
	    (uintmax_t)hr->staging_base, (uintmax_t)(hr->staging_base + hr->staging_size));
	hiber_log(HIBER_LOG_INFO,
	    "hibernate: retain heap [0x%016jx,0x%016jx)\n",
	    (uintmax_t)hr->heap_base, (uintmax_t)(hr->heap_base + hr->heap_size));

	/* Post-Allocation Memory Map Snapshot */
	hr->post_map = (EFI_MEMORY_DESCRIPTOR *)((uintptr_t)hr->workspace +
	    HIBERNATE_HDR_BUF_SIZE);
	hr->post_map_sz = 128 * 1024;
	hr->post_map_key = 0;
	hr->post_desc_sz = 0;
	hr->post_desc_ver = 0;

	status = BS->GetMemoryMap(&hr->post_map_sz, hr->post_map, &hr->post_map_key, &hr->post_desc_sz, &hr->post_desc_ver);
	if (EFI_ERROR(status)) {
		hiber_log(HIBER_LOG_ERROR, "hibernate: post-allocation GetMemoryMap failed: %lu\n",
		    DECODE_ERROR(status));
		hiber_refuse_pending = "allocation failed";
		return (false);
	}

	ndesc2 = (hr->post_desc_sz != 0) ? (hr->post_map_sz / hr->post_desc_sz) : 0;
	hr->post_ndesc = ndesc2;
	hiber_log(HIBER_LOG_INFO, "hibernate: post-allocation memory map: %u descriptors, key 0x%lx , descsize %lu\n",
	    ndesc2, (u_long)hr->post_map_key, (u_long)hr->post_desc_sz);

	return (true);
}

static bool
hibernate_analyze_spare_capacity(struct hibernate_restore *hr,
    uint8_t **bufp)
{
	EFI_MEMORY_DESCRIPTOR *p;
	uint64_t largest_must_stage_chunk, staging_spare_pages;
	uint64_t nb_pages, max_pages;
	bool contig_ok, staging_ok;
	const char *contig_verdict, *staging_verdict, *revised_verdict;
	u_int i, j, k, r;

	/*
	 * Corrected Conflict Recomputation (must match Phase 3 active_ranges):
	 * must-stage = PT_LOAD ∩ (MUST-PRESERVE ∪ RECLAIMABLE ∪ RESIDENT Loader ∪
	 * Low Memory < 1 MiB): Boot Services ranges are staged before
	 * ExitBootServices, so excluding them would understate the staging
	 * demand and overflow mid-stage.
	 */
	hr->must_stage_bytes = 0;
	largest_must_stage_chunk = 0;

	for (i = 2; i < hr->ehdr->e_phnum; i++) {
		uint64_t c_start = hr->ph[i].p_paddr;
		uint64_t c_size = (hr->ph[i].p_memsz != 0) ? hr->ph[i].p_memsz : hr->ph[i].p_filesz;
		uint64_t segment_must_stage = 0;

		/* Low memory < 1 MiB must always be staged */
		if (c_start < 0x100000) {
			uint64_t low_end = (c_start + c_size < 0x100000) ? (c_start + c_size) : 0x100000;
			segment_must_stage += (low_end - c_start);
		}

		if (hr->loader_size > 0) {
			segment_must_stage += range_overlap(c_start, c_size,
			    hr->loader_start, hr->loader_size, NULL, NULL);
		}

		for (j = 0, p = hr->post_map; j < hr->post_ndesc; j++, p = NextMemoryDescriptor(p, hr->post_desc_sz)) {
			enum hibernate_mem_class cl = hibernate_classify_mem_type(p->Type);
			uint64_t d_start, d_size, ov_start, ov_size;

			if (cl != HMC_MUST_PRESERVE && cl != HMC_RECLAIMABLE)
				continue;
			d_start = p->PhysicalStart;
			d_size = p->NumberOfPages * EFI_PAGE_SIZE;
			if (range_overlap(c_start, c_size, d_start, d_size,
			    &ov_start, &ov_size) == 0)
				continue;
			if (ov_start + ov_size <= 0x100000)
				continue;
			if (ov_start < 0x100000)
				segment_must_stage +=
				    ov_start + ov_size - 0x100000;
			else
				segment_must_stage += ov_size;
		}

		if (segment_must_stage > 0) {
			hr->must_stage_bytes += segment_must_stage;
			if (segment_must_stage > largest_must_stage_chunk)
				largest_must_stage_chunk = segment_must_stage;
		}
	}

	/*
	 * Re-scan spare pages against post-allocation memory map:
	 * avoid list contains strictly MUST-PRESERVE, RESIDENT Loader binary,
	 * contiguous spare, active staging buffers, and low memory below 1 MiB.
	 */
	hr->n_post_avoid = 0;

	/* 1. Low memory below 1 MiB */
	add_avoid_range(hr->post_avoid, &hr->n_post_avoid, nitems(hr->post_avoid), 0, 0x100000);

	/* 2. Resident loader binary */
	if (hr->loader_size > 0)
		add_avoid_range(hr->post_avoid, &hr->n_post_avoid, nitems(hr->post_avoid),
		    hr->loader_start, hr->loader_size);

	/* 3. Contiguous spare buffer */
	if (hr->cb->hc_contig_spare_size > 0)
		add_avoid_range(hr->post_avoid, &hr->n_post_avoid, nitems(hr->post_avoid),
		    hr->cb->hc_contig_spare_start, hr->cb->hc_contig_spare_size);

	/* 4. Active loader staging scratch buffers */
	if (hr->workspace != 0)
		add_avoid_range(hr->post_avoid, &hr->n_post_avoid, nitems(hr->post_avoid),
		    hr->workspace, hr->workspace_pages * EFI_PAGE_SIZE);

	/*
	 * hr->readbuf_paddr is a sub-range of the contiguous spare arena (already
	 * added above).  Do NOT add it separately: the arena-disjointness
	 * check below treats any non-identical overlapping entry as a
	 * conflict, which would falsely fail feasibility.
	 */

	/* 4b. Retained loader transient allocations */
	if (hr->heap_base != 0 && hr->heap_size > 0)
		add_avoid_range(hr->post_avoid, &hr->n_post_avoid, nitems(hr->post_avoid),
		    hr->heap_base, hr->heap_size);
	if (hr->staging_base != 0 && hr->staging_size > 0)
		add_avoid_range(hr->post_avoid, &hr->n_post_avoid, nitems(hr->post_avoid),
		    hr->staging_base, hr->staging_size);
	if (bufp != NULL && *bufp != NULL)
		add_avoid_range(hr->post_avoid, &hr->n_post_avoid, nitems(hr->post_avoid),
		    (uint64_t)(uintptr_t)*bufp, HIBERNATE_HDR_BUF_SIZE);


	/* 5. All HMC_MUST_PRESERVE descriptors from post-allocation memory map */
	for (j = 0, p = hr->post_map; j < hr->post_ndesc; j++, p = NextMemoryDescriptor(p, hr->post_desc_sz)) {
		enum hibernate_mem_class cl = hibernate_classify_mem_type(p->Type);
		if (cl == HMC_MUST_PRESERVE) {
			add_avoid_range(hr->post_avoid, &hr->n_post_avoid, nitems(hr->post_avoid),
			    p->PhysicalStart, p->NumberOfPages * EFI_PAGE_SIZE);
		}
	}

	hr->post_contig_overlaps = false;
	if (hr->cb->hc_contig_spare_size > 0) {
		uint64_t csp_start = hr->cb->hc_contig_spare_start;
		uint64_t csp_end = csp_start + hr->cb->hc_contig_spare_size;

		for (r = 0; r < hr->n_post_avoid; r++) {
			if (hr->post_avoid[r].start == csp_start && hr->post_avoid[r].end == csp_end)
				continue;
			if (csp_start < hr->post_avoid[r].end && csp_end > hr->post_avoid[r].start) {
				hr->post_contig_overlaps = true;
				break;
			}
		}
	}

	hr->excluded_spare_cnt = 0;
	staging_spare_pages = 0;
	if (hr->cb->hc_spare_pages_nb > 0) {
		nb_pages = hr->cb->hc_spare_pages_nb;
		max_pages = (hr->ph[0].p_filesz > offsetof(struct hibernate_cb, hc_spare_pages)) ?
		    ((hr->ph[0].p_filesz - offsetof(struct hibernate_cb, hc_spare_pages)) / sizeof(uint64_t)) : 0;
		if (nb_pages > max_pages)
			nb_pages = max_pages;
		staging_spare_pages = nb_pages;

		for (k = 0; k < nb_pages; k++) {
			if (is_page_avoided(hr->cb->hc_spare_pages[k], hr->post_avoid, hr->n_post_avoid))
				hr->excluded_spare_cnt++;
		}
	}

	hr->total_spare_bytes = staging_spare_pages * EFI_PAGE_SIZE;
	hr->excluded_spare_bytes = (uint64_t)hr->excluded_spare_cnt * EFI_PAGE_SIZE;
	hr->usable_spare_pages = (staging_spare_pages > hr->excluded_spare_cnt) ?
	    (staging_spare_pages - hr->excluded_spare_cnt) : 0;
	hr->usable_spare_bytes = hr->usable_spare_pages * EFI_PAGE_SIZE;

	hiber_log(HIBER_LOG_INFO, "hibernate: spare pages re-scan: %ju total, %u excluded (%ju KiB), %ju usable (%ju MiB)\n",
	    (uintmax_t)staging_spare_pages,
	    hr->excluded_spare_cnt,
	    (uintmax_t)(hr->excluded_spare_bytes / 1024),
	    (uintmax_t)hr->usable_spare_pages,
	    (uintmax_t)(hr->usable_spare_bytes / (1024 * 1024)));

	/* Revised Feasibility Output.
	 * Staging consumes hc_spare_pages[] only; contig spare is trampoline/PT.
	 */
	contig_ok = !hr->post_contig_overlaps;
	staging_ok = hr->usable_spare_bytes >= hr->must_stage_bytes;
	contig_verdict = contig_ok ? "FEASIBLE" : "INSUFFICIENT";
	staging_verdict = staging_ok ? "FEASIBLE" : "INSUFFICIENT";
	revised_verdict = contig_ok && staging_ok ?
	    "FEASIBLE" : "INSUFFICIENT";

	hiber_log(HIBER_LOG_INFO, "hibernate: === Revised Staging Feasibility (Post-Allocation) ===\n");
	hiber_log(HIBER_LOG_INFO, "hibernate: resident loader set: 0x%jx (%ju KiB)\n",
	    (uintmax_t)hr->loader_size, (uintmax_t)(hr->loader_size / 1024));
	hiber_log(HIBER_LOG_INFO, "hibernate: must-stage bytes   : 0x%jx (%ju KiB), largest chunk 0x%jx\n",
	    (uintmax_t)hr->must_stage_bytes, (uintmax_t)(hr->must_stage_bytes / 1024),
	    (uintmax_t)largest_must_stage_chunk);
	hiber_log(HIBER_LOG_INFO, "hibernate: contig spare disjoint : overlaps=%s loader=%ju KiB csp=%ju KiB -> %s\n",
	    hr->post_contig_overlaps ? "yes" : "no",
	    (uintmax_t)(hr->loader_size / 1024),
	    (uintmax_t)(hr->cb->hc_contig_spare_size / 1024),
	    contig_verdict);
	hiber_log(HIBER_LOG_INFO, "hibernate: staging spare pages: 0x%jx (%ju MiB usable) vs must-stage 0x%jx (%ju MiB) -> %s\n",
	    (uintmax_t)hr->usable_spare_bytes,
	    (uintmax_t)(hr->usable_spare_bytes / (1024 * 1024)),
	    (uintmax_t)hr->must_stage_bytes,
	    (uintmax_t)(hr->must_stage_bytes / (1024 * 1024)),
	    staging_verdict);
	hiber_log(HIBER_LOG_INFO, "hibernate: revised feasibility verdict -> %s\n", revised_verdict);
	snprintf(hiber_refuse_rpt.mmap, sizeof(hiber_refuse_rpt.mmap),
	    "total_spare_bytes=0x%jx excluded_bytes=0x%jx usable_bytes=0x%jx must_stage_bytes=0x%jx verdict=%s",
	    (uintmax_t)hr->total_spare_bytes,
	    (uintmax_t)hr->excluded_spare_bytes,
	    (uintmax_t)hr->usable_spare_bytes,
	    (uintmax_t)hr->must_stage_bytes,
	    revised_verdict);
	hiber_refuse_set_stage("classification");
	if (!contig_ok || !staging_ok) {
		hiber_refuse_rpt.chk_staging_feas = HIBER_CHK_FAIL;
		hiber_refuse_pending = "staging infeasible";
		return (false);
	}
	hiber_refuse_rpt.chk_staging_feas = HIBER_CHK_PASS;
	hiber_refuse_set_stage("staging");

	return (true);
}

static bool
hibernate_build_active_ranges(struct hibernate_restore *hr)
{
	EFI_MEMORY_DESCRIPTOR *p;
	u_int j;

	hr->n_active_ranges = 0;

	/*
	 * Memory below 1 MiB (0x0 .. 0x100000) must NEVER be touched pre-EBS,
	 * as UEFI Boot Services / legacy structures (IVT, BDA, EBDA) reside there,
	 * and physical address 0 is NULL in UEFI Block I/O.
	 * Mark 0 .. 0x100000 as active (deferred).
	 */
	if (hr->n_active_ranges < nitems(hr->active_ranges)) {
		hr->active_ranges[hr->n_active_ranges].start = 0;
		hr->active_ranges[hr->n_active_ranges].end = 0x100000;
		hr->n_active_ranges++;
	}

	if (hr->loader_size > 0 && hr->n_active_ranges < nitems(hr->active_ranges)) {
		hr->active_ranges[hr->n_active_ranges].start = hr->loader_start;
		hr->active_ranges[hr->n_active_ranges].end = hr->loader_start + hr->loader_size;
		hr->n_active_ranges++;
	}

	for (j = 0, p = hr->post_map; j < hr->post_ndesc;
	    j++, p = NextMemoryDescriptor(p, hr->post_desc_sz)) {
		enum hibernate_mem_class cl = hibernate_classify_mem_type(p->Type);
		if (cl == HMC_MUST_PRESERVE || cl == HMC_RECLAIMABLE || cl == HMC_LOADER_IN_USE) {
			if (cl == HMC_LOADER_IN_USE) {
				if (hr->loader_size == 0 || p->PhysicalStart < hr->loader_start ||
				    p->PhysicalStart + p->NumberOfPages * EFI_PAGE_SIZE > hr->loader_start + hr->loader_size) {
					hiber_log(HIBER_LOG_DEBUG, "hibernate: active loader allocation in map: 0x%jx - 0x%jx (%lu pages, type %u)\n",
					    (uintmax_t)p->PhysicalStart,
					    (uintmax_t)(p->PhysicalStart + p->NumberOfPages * EFI_PAGE_SIZE),
					    (u_long)p->NumberOfPages, p->Type);
				}
			}
			if (hr->n_active_ranges < nitems(hr->active_ranges)) {
				hr->active_ranges[hr->n_active_ranges].start = p->PhysicalStart;
				hr->active_ranges[hr->n_active_ranges].end = p->PhysicalStart + p->NumberOfPages * EFI_PAGE_SIZE;
				hr->n_active_ranges++;
			} else {
				hiber_log(HIBER_LOG_WARN, "hibernate: WARNING: active_ranges array full (%u entries), cannot add 0x%jx-0x%jx (type %u)\n",
				    hr->n_active_ranges, (uintmax_t)p->PhysicalStart,
				    (uintmax_t)(p->PhysicalStart + p->NumberOfPages * EFI_PAGE_SIZE), p->Type);
			}
		}
	}



	hibernate_sort_merge_active(hr);
	return (true);
}

static bool
hibernate_classify_restore_chunks(struct hibernate_restore *hr)
{
	EFI_MEMORY_DESCRIPTOR *p;
	u_int i, j, r;
	/*
	 * UEFI owns the preboot memory map: before ExitBootServices a UEFI
	 * image may use only memory it explicitly allocated (UEFI 2.x
	 * Section 7.2; AllocatePages Section 7.2.1).  A page reported as
	 * EfiConventionalMemory is free, not owned.  Claim every candidate
	 * DIRECT destination at its exact physical address and defer every
	 * page whose claim fails; the retained claim ledger is the sole
	 * authority for pre-EBS writes.
	 */

	if (!hibernate_prepare_staging_reserved(hr)) {
		hiber_refuse_rpt.chk_staging_feas = HIBER_CHK_FAIL;
		return (false);

	}
	hiber_log(HIBER_LOG_INFO,
	    "hibernate: excluded %u kernel staging workspace ranges "
	    "from direct claims\n", hr->n_staging_reserved);
	if (!hibernate_claim_direct_destinations(hr)) {
		hiber_refuse_rpt.chk_staging_feas = HIBER_CHK_FAIL;
		return (false);
	}
	hiber_log(HIBER_LOG_INFO,
	    "hibernate: retained %u direct destination claim ranges\n",
	    hr->n_direct_claims);

	hr->direct_chunks_cnt = 0;
	hr->deferred_chunks_cnt = 0;
	hr->total_direct_bytes = 0;
	hr->total_deferred_chunk_bytes = 0;
	hr->total_deferred_pages = 0;

	hiber_log(HIBER_LOG_INFO, "hibernate: === PT_LOAD Chunk Classification (Pre-EBS) ===\n");

	for (i = 2; i < hr->ehdr->e_phnum; i++) {
		uint64_t c_start = hr->ph[i].p_paddr;
		uint64_t c_size = (hr->ph[i].p_memsz != 0) ? hr->ph[i].p_memsz : hr->ph[i].p_filesz;
		uint64_t c_deferred_bytes = 0;
		uint32_t types_hit = 0;

		for (r = 0; r < hr->n_active_ranges; r++) {
			uint64_t ov_start, ov_size;
			if (range_overlap(c_start, c_size, hr->active_ranges[r].start,
			    hr->active_ranges[r].end - hr->active_ranges[r].start, &ov_start, &ov_size) > 0) {
				c_deferred_bytes += ov_size;
			}
		}

		for (j = 0, p = hr->post_map; j < hr->post_ndesc; j++, p = NextMemoryDescriptor(p, hr->post_desc_sz)) {
			if (hr->workspace != 0 && p->PhysicalStart == hr->workspace)
				continue;

			uint64_t d_start = p->PhysicalStart;
			uint64_t d_size = p->NumberOfPages * EFI_PAGE_SIZE;
			uint64_t ov_start, ov_size;

			if (range_overlap(c_start, c_size, d_start, d_size, &ov_start, &ov_size) > 0) {
				uint64_t in_loader = 0;
				if (hr->loader_size > 0)
					in_loader = range_overlap(ov_start, ov_size,
					    hr->loader_start, hr->loader_size, NULL, NULL);

				if (p->Type == EfiLoaderCode || p->Type == EfiLoaderData) {
					types_hit |= (1U << p->Type);
				} else if (in_loader > 0) {
					types_hit |= (1U << EfiLoaderCode);
					if (ov_size > in_loader && p->Type != EfiConventionalMemory)
						types_hit |= (1U << p->Type);
				} else if (p->Type != EfiConventionalMemory) {
					types_hit |= (1U << p->Type);
				}
			}
		}

		if (c_deferred_bytes == 0) {
			hr->direct_chunks_cnt++;
			hr->total_direct_bytes += c_size;
			hiber_log(HIBER_LOG_DEBUG, "hibernate:   chunk %2u: paddr 0x%016jx size 0x%08jx (%ju KiB) -> DIRECT\n",
			    i - 2, (uintmax_t)c_start, (uintmax_t)c_size, (uintmax_t)(c_size / 1024));
		} else {
			char types_buf[256];
			bool first = true;
			int t;

			hr->deferred_chunks_cnt++;
			hr->total_deferred_chunk_bytes += c_deferred_bytes;
			hr->total_deferred_pages += c_deferred_bytes / EFI_PAGE_SIZE;
			uint64_t c_direct_bytes = c_size - c_deferred_bytes;
			hr->total_direct_bytes += c_direct_bytes;

			types_buf[0] = '\0';
			if (c_start < 0x100000) {
				strlcat(types_buf, "LowMemory", sizeof(types_buf));
				first = false;
			}
			for (t = 0; t < 32; t++) {
				if ((types_hit & (1U << t)) != 0) {
					if (!first)
						strlcat(types_buf, ", ", sizeof(types_buf));
					strlcat(types_buf, efi_memory_type((EFI_MEMORY_TYPE)t),
					    sizeof(types_buf));
					first = false;
				}
			}

			if (c_direct_bytes > 0) {
				hiber_log(HIBER_LOG_DEBUG, "hibernate:   chunk %2u: paddr 0x%016jx size 0x%08jx (%ju KiB) -> DEFERRED (%ju KiB deferred, %ju KiB direct) [%s]\n",
				    i - 2, (uintmax_t)c_start, (uintmax_t)c_size, (uintmax_t)(c_size / 1024),
				    (uintmax_t)(c_deferred_bytes / 1024), (uintmax_t)(c_direct_bytes / 1024),
				    types_buf);
			} else {
				hiber_log(HIBER_LOG_DEBUG, "hibernate:   chunk %2u: paddr 0x%016jx size 0x%08jx (%ju KiB) -> DEFERRED (%ju KiB deferred) [%s]\n",
				    i - 2, (uintmax_t)c_start, (uintmax_t)c_size, (uintmax_t)(c_size / 1024),
				    (uintmax_t)(c_deferred_bytes / 1024),
				    types_buf);
			}
		}
	}

	uint64_t total_image_mem = hr->total_direct_bytes + hr->total_deferred_chunk_bytes;
	hiber_log(HIBER_LOG_INFO, "hibernate: Classification summary: %u DIRECT, %u DEFERRED (total %u chunks, %ju MiB)\n",
	    hr->direct_chunks_cnt, hr->deferred_chunks_cnt,
	    (hr->ehdr->e_phnum >= 2) ? (hr->ehdr->e_phnum - 2) : 0,
	    (uintmax_t)(total_image_mem / (1024 * 1024)));
	hiber_log(HIBER_LOG_INFO, "hibernate:   deferred data: %ju pages (%ju KiB / %ju MiB)\n",
	    (uintmax_t)hr->total_deferred_pages,
	    (uintmax_t)(hr->total_deferred_chunk_bytes / 1024),
	    (uintmax_t)(hr->total_deferred_chunk_bytes / (1024 * 1024)));

	/* Phase 3 deferred demand must fit staging spare pages. */
	if (hr->total_deferred_chunk_bytes > hr->usable_spare_bytes) {
		hiber_log(HIBER_LOG_ERROR, "hibernate: deferred %ju KiB exceeds usable spare %ju KiB -> INSUFFICIENT\n",
		    (uintmax_t)(hr->total_deferred_chunk_bytes / 1024),
		    (uintmax_t)(hr->usable_spare_bytes / 1024));
		snprintf(hiber_refuse_rpt.mmap, sizeof(hiber_refuse_rpt.mmap),
		    "total_spare_bytes=0x%jx excluded_bytes=0x%jx usable_bytes=0x%jx must_stage_bytes=0x%jx verdict=INSUFFICIENT",
		    (uintmax_t)hr->total_spare_bytes,
		    (uintmax_t)hr->excluded_spare_bytes,
		    (uintmax_t)hr->usable_spare_bytes,
		    (uintmax_t)hr->total_deferred_chunk_bytes);
		hiber_refuse_rpt.chk_staging_feas = HIBER_CHK_FAIL;
		hiber_refuse_pending = "staging infeasible";
		return (false);
	}


	return (true);
}

static bool
hibernate_prepare_restore(struct hibernate_restore *hr,
    const Elf_Ehdr *ehdr, const Elf_Phdr *ph,
    const struct hibernate_cb *cb, uint8_t **bufp)
{
	/* Save blkio interface before heap retention. */
	hr->blkio = hr->part != NULL ? hr->part->pd_blkio : NULL;
	hr->blksz = hr->blkio != NULL && hr->blkio->Media != NULL ?
	    hr->blkio->Media->BlockSize : 512;
	hr->ehdr = ehdr;
	hr->ph = ph;
	hr->cb = cb;

	if (!hibernate_prepare_workspace(hr, bufp))
		return (false);
	if (!hibernate_analyze_spare_capacity(hr, bufp))
		return (false);
	if (!hibernate_build_active_ranges(hr))
		return (false);
	return (hibernate_classify_restore_chunks(hr));
}

static bool
hibernate_stage_deferred(struct hibernate_restore *hr)
{
	struct hibernate_range chunk_deferred[512];
	EFI_STATUS status;
	uint64_t spare_cursor;
	u_int i, r;

	if (hr->blkio == NULL || hr->blkio->Media == NULL) {
		hiber_log(HIBER_LOG_INFO,
		    "hibernate: blkio unavailable for staging\n");
		hiber_refuse_rpt.chk_read = HIBER_CHK_FAIL;
		hiber_refuse_pending = "read failed";
		return (false);
	}

	hr->readbuf = (uint8_t *)(uintptr_t)hr->readbuf_paddr;
	spare_cursor = 0;
	hr->total_staged_pages = 0;
	hr->entries = (struct hiber_copy_entry *)(uintptr_t)
	    (hr->csp_base + HIBER_CSP_COPY_START);
	hr->max_entries = (HIBER_CSP_COPY_END - HIBER_CSP_COPY_START) /
	    sizeof(struct hiber_copy_entry);
	hr->entry_count = 0;
	hr->claimed_spare_pages = 0;
	hr->skipped_spare_claims = 0;

	hiber_log(HIBER_LOG_INFO,
	    "hibernate: === Streaming Staging Engine (Spare Pages) ===\n");

	for (i = 2; i < hr->ehdr->e_phnum; i++) {
		uint64_t c_start, c_size, chunk_staged_pages;
		uint32_t crc_disk, crc_mem;
		u_int n_chunk_deferred;

		c_start = hr->ph[i].p_paddr;
		c_size = hr->ph[i].p_memsz != 0 ?
		    hr->ph[i].p_memsz : hr->ph[i].p_filesz;
		n_chunk_deferred = 0;

		for (r = 0; r < hr->n_active_ranges; r++) {
			uint64_t ov_start, ov_size;

			if (range_overlap(c_start, c_size,
			    hr->active_ranges[r].start,
			    hr->active_ranges[r].end -
			    hr->active_ranges[r].start,
			    &ov_start, &ov_size) > 0) {
				if (n_chunk_deferred < nitems(chunk_deferred)) {
					chunk_deferred[n_chunk_deferred].start =
					    ov_start;
					chunk_deferred[n_chunk_deferred].end =
					    ov_start + ov_size;
					n_chunk_deferred++;
				} else {
					hiber_log(HIBER_LOG_WARN,
					    "hibernate: WARNING: chunk_deferred "
					    "array full (%u entries)\n",
					    n_chunk_deferred);
				}
			}
		}

		if (n_chunk_deferred == 0)
			continue;

		crc_disk = 0xffffffff;
		crc_mem = 0xffffffff;
		chunk_staged_pages = 0;

		for (u_int d = 0; d < n_chunk_deferred; d++) {
			uint64_t cur_page, pages_left;

			cur_page = (chunk_deferred[d].start - c_start) /
			    EFI_PAGE_SIZE;
			pages_left = (chunk_deferred[d].end -
			    chunk_deferred[d].start) / EFI_PAGE_SIZE;

			while (pages_left > 0) {
				uint64_t blk_pages, blk_bytes, disk_lba;

				blk_pages = pages_left > 16 ? 16 : pages_left;
				blk_bytes = blk_pages * EFI_PAGE_SIZE;
				disk_lba = (HIBERNATE_IMAGE_OFFSET +
				    hr->ph[i].p_offset +
				    cur_page * EFI_PAGE_SIZE) / hr->blksz;

				status = hr->blkio->ReadBlocks(hr->blkio,
				    hr->blkio->Media->MediaId, disk_lba,
				    blk_bytes, hr->readbuf);
				if (EFI_ERROR(status)) {
					hiber_log(HIBER_LOG_ERROR,
					    "hibernate: ReadBlocks error at "
					    "LBA %ju (%lu)\n",
					    (uintmax_t)disk_lba,
					    DECODE_ERROR(status));
					hiber_refuse_rpt.chk_read =
					    HIBER_CHK_FAIL;
					hiber_refuse_pending = "read failed";
					return (false);
				}

				crc_disk = hibernate_crc32_update(crc_disk,
				    hr->readbuf, blk_bytes);

				for (uint64_t p_idx = 0;
				    p_idx < blk_pages; p_idx++) {
					uint64_t spare_pa, target_pa;

					if (!hibernate_claim_next_spare(
					    hr->cb, &spare_cursor,
					    hr->post_avoid,
					    hr->n_post_avoid, &spare_pa,
					    &hr->skipped_spare_claims)) {
						hiber_log(HIBER_LOG_ERROR,
						    "hibernate: spare pages "
						    "exhausted (cursor %ju >= "
						    "%ju)\n",
						    (uintmax_t)spare_cursor,
						    (uintmax_t)
						    hr->cb->hc_spare_pages_nb);
						snprintf(hiber_refuse_rpt.mmap,
						    sizeof(hiber_refuse_rpt.mmap),
						    "total_spare_bytes=0x%jx "
						    "excluded_bytes=0x%jx "
						    "usable_bytes=0x%jx "
						    "must_stage_bytes=0x%jx "
						    "verdict=INSUFFICIENT",
						    (uintmax_t)
						    hr->total_spare_bytes,
						    (uintmax_t)
						    hr->excluded_spare_bytes,
						    (uintmax_t)
						    hr->usable_spare_bytes,
						    (uintmax_t)
						    hr->must_stage_bytes);
						hiber_refuse_rpt.
						    chk_staging_feas =
						    HIBER_CHK_FAIL;
						hiber_refuse_pending =
						    "staging infeasible";
						return (false);
					}
					hr->claimed_spare_pages++;

					target_pa = c_start +
					    (cur_page + p_idx) *
					    EFI_PAGE_SIZE;
					memcpy((void *)(uintptr_t)spare_pa,
					    hr->readbuf +
					    p_idx * EFI_PAGE_SIZE,
					    EFI_PAGE_SIZE);
					crc_mem = hibernate_crc32_update(
					    crc_mem,
					    (const void *)(uintptr_t)
					    spare_pa, EFI_PAGE_SIZE);

					if (!hibernate_append_copy_entry(
					    hr->entries, &hr->entry_count,
					    hr->max_entries, spare_pa,
					    target_pa)) {
						hiber_log(HIBER_LOG_ERROR,
						    "hibernate: copy entries "
						    "list overflow\n");
						BS->FreePages(spare_pa, 1);
						hr->claimed_spare_pages--;
						hiber_refuse_pending =
						    "COPY_LIST_CAPACITY";
						return (false);
					}
					chunk_staged_pages++;
					hr->total_staged_pages++;
				}
				pages_left -= blk_pages;
				cur_page += blk_pages;
			}
		}

		crc_disk ^= 0xffffffff;
		crc_mem ^= 0xffffffff;
		if (crc_disk != crc_mem) {
			hiber_log(HIBER_LOG_ERROR,
			    "hibernate:   chunk %2u: CRC MISMATCH "
			    "(disk 0x%08x != mem 0x%08x) [FAIL]\n",
			    i - 2, crc_disk, crc_mem);
			hiber_refuse_rpt.chk_staging_crc = HIBER_CHK_FAIL;
			hiber_refuse_pending = "staging CRC mismatch";
			return (false);
		}
		hiber_log(HIBER_LOG_INFO,
		    "hibernate:   chunk %2u: %ju pages (%ju KiB) "
		    "staged, CRC32 0x%08x [PASS]\n",
		    i - 2, (uintmax_t)chunk_staged_pages,
		    (uintmax_t)(chunk_staged_pages * 4), crc_mem);
	}

	hiber_log(HIBER_LOG_ERROR,
	    "hibernate: streaming staging complete: %ju pages (%ju KiB) "
	    "staged into spare pages (%ju usable spare pages remaining, "
	    "0 overflows)\n",
	    (uintmax_t)hr->total_staged_pages,
	    (uintmax_t)(hr->total_staged_pages * 4),
	    (uintmax_t)((hr->usable_spare_pages >
	    hr->total_staged_pages) ?
	    hr->usable_spare_pages - hr->total_staged_pages : 0));
	hiber_log(HIBER_LOG_INFO,
	    "hibernate: staging EFI claims: %ju pages, %ju skipped\n",
	    (uintmax_t)hr->claimed_spare_pages,
	    (uintmax_t)hr->skipped_spare_claims);

	hr->total_staged_crc = 0xffffffff;
	for (uint64_t e = 0; e < hr->entry_count; e++)
		hr->total_staged_crc = hibernate_crc32_update(
		    hr->total_staged_crc,
		    (const void *)(uintptr_t)
		    hr->entries[e].src_spare_pa,
		    hr->entries[e].page_count * EFI_PAGE_SIZE);
	hr->total_staged_crc ^= 0xffffffff;
	return (true);
}

static bool
hibernate_prepare_handoff(struct hibernate_restore *hr)
{
	const struct hibernate_pcb *pcb;
	uint64_t *pml4, *pdpt;
	uint64_t csp_end;
	const u_int num_gb = 8;
	u_int r;

	pcb = (const struct hibernate_pcb *)
	    ((uintptr_t)hr->workspace + hr->ph[1].p_offset);
	hr->thdr = (struct hiber_trampoline_header *)(uintptr_t)
	    hr->csp_base;

	hr->thdr->magic = 0x53345452414d5000ULL;
	hr->thdr->copy_entries_pa =
	    hr->csp_base + HIBER_CSP_COPY_START;
	hr->thdr->entry_count = hr->entry_count;
	hr->thdr->target_rsp = pcb->rsp;
	hr->thdr->target_r12 = pcb->r12;
	hr->thdr->target_rip = pcb->rip;

	memcpy((void *)(uintptr_t)(hr->csp_base + 0x30),
	    hibernate_tramp_stub, HIBERNATE_TRAMP_STUB_SIZE);

	pml4 = (uint64_t *)(uintptr_t)(hr->csp_base + 0x2000);
	pdpt = (uint64_t *)(uintptr_t)(hr->csp_base + 0x3000);
	bzero(pml4, 4096);
	bzero(pdpt, 4096);
	pml4[0] = (hr->csp_base + 0x3000) | 0x03;

	for (u_int g = 0; g < num_gb; g++) {
		uint64_t pd_pa, *pd;

		pd_pa = hr->csp_base + 0x4000 + g * 4096;
		pd = (uint64_t *)(uintptr_t)pd_pa;
		bzero(pd, 4096);
		pdpt[g] = pd_pa | 0x03;
		for (u_int j = 0; j < 512; j++) {
			uint64_t paddr;

			paddr = ((uint64_t)g << 30) |
			    ((uint64_t)j << 21);
			pd[j] = paddr | 0x83;
		}
	}
	hiber_log(HIBER_LOG_INFO,
	    "hibernate: private 1:1 identity page table built in "
	    "contiguous spare (PML4=0x%016jx, %u GiB mapped)\n",
	    (uintmax_t)(hr->csp_base + 0x2000), num_gb);

	hr->collisions = 0;
	csp_end = hr->csp_base + hr->cb->hc_contig_spare_size;
	for (uint64_t k = 0; k < hr->entry_count; k++) {
		uint64_t dst_start, dst_size;

		dst_start = hr->entries[k].dst_target_pa;
		dst_size = hr->entries[k].page_count * EFI_PAGE_SIZE;
		if (range_overlap(hr->csp_base,
		    hr->cb->hc_contig_spare_size, dst_start, dst_size,
		    NULL, NULL) > 0)
			hr->collisions++;
	}
	for (r = 0; r < hr->n_post_avoid; r++) {
		if (hr->post_avoid[r].start == hr->csp_base &&
		    hr->post_avoid[r].end == csp_end)
			continue;
		if (hr->csp_base < hr->post_avoid[r].end &&
		    csp_end > hr->post_avoid[r].start)
			hr->collisions++;
	}

	hiber_log(HIBER_LOG_INFO,
	    "hibernate: post-EBS trampoline placed at 0x%016jx "
	    "(stub: %zu bytes, copy list: %ju entries / %ju bytes)\n",
	    (uintmax_t)hr->csp_base,
	    sizeof(struct hiber_trampoline_header) +
	    HIBERNATE_TRAMP_STUB_SIZE,
	    (uintmax_t)hr->entry_count,
	    (uintmax_t)(hr->entry_count *
	    sizeof(struct hiber_copy_entry)));
	hiber_log(HIBER_LOG_INFO,
	    "hibernate:   thdr: entries_pa=0x%jx count=%ju "
	    "rsp=0x%jx r12=0x%jx rip=0x%jx\n",
	    (uintmax_t)hr->thdr->copy_entries_pa,
	    (uintmax_t)hr->thdr->entry_count,
	    (uintmax_t)hr->thdr->target_rsp,
	    (uintmax_t)hr->thdr->target_r12,
	    (uintmax_t)hr->thdr->target_rip);

	for (uint64_t k = 0; k < hr->entry_count; k++) {
		hiber_log(HIBER_LOG_DEBUG,
		    "hibernate:   entry %2ju: src 0x%016jx -> "
		    "dst 0x%016jx (%ju pages, %ju KiB)\n",
		    (uintmax_t)k,
		    (uintmax_t)hr->entries[k].src_spare_pa,
		    (uintmax_t)hr->entries[k].dst_target_pa,
		    (uintmax_t)hr->entries[k].page_count,
		    (uintmax_t)(hr->entries[k].page_count * 4));
		if ((k % 32) == 0 || k + 1 == hr->entry_count)
			hiber_log(HIBER_LOG_INFO,
			    "hibernate:   copy-list progress %ju/%ju\n",
			    (uintmax_t)(k + 1),
			    (uintmax_t)hr->entry_count);
	}

	hiber_log(HIBER_LOG_INFO,
	    "hibernate: trampoline disjointness assertion: %u "
	    "collisions (0 overlaps) [PASS]\n", hr->collisions);
	if (hr->collisions > 0) {
		hiber_log(HIBER_LOG_ERROR,
		    "hibernate: trampoline collision detected [FAIL]\n");
		hiber_refuse_rpt.chk_tramp = HIBER_CHK_FAIL;
		hiber_refuse_pending = "trampoline collision";
		return (false);
	}
	hiber_refuse_rpt.chk_tramp = HIBER_CHK_PASS;
	hiber_refuse_set_stage("A1");
	return (true);
}

static bool
hibernate_build_chunk_direct_ranges(
    const struct hibernate_restore *hr, uint64_t chunk_start,
    uint64_t chunk_size, struct hibernate_range *ranges,
    u_int max_ranges, u_int *nranges)
{
	uint64_t chunk_end;
	if (chunk_start > UINT64_MAX - chunk_size) {
		hiber_refuse_pending = "A1 direct cursor invalid";
		return (false);
	}
	chunk_end = chunk_start + chunk_size;
	*nranges = 0;

	for (u_int claim = 0; claim < hr->n_direct_claims; claim++) {
		uint64_t start, end;

		start = hr->direct_claims[claim].start;
		end = hr->direct_claims[claim].end;
		if (end <= chunk_start || start >= chunk_end)
			continue;
		if (start < chunk_start)
			start = chunk_start;
		if (end > chunk_end)
			end = chunk_end;
		if (start >= end)
			continue;
		if ((*nranges) >= max_ranges) {
			hiber_log(HIBER_LOG_ERROR,
			    "hibernate: A1 claimed-direct table overflow "
			    "(%u entries)\n", (*nranges));
			hiber_refuse_pending =
			    "A1 claimed-direct table overflow";
			return (false);
		}
		ranges[(*nranges)].start = start;
		ranges[(*nranges)].end = end;
		(*nranges)++;
	}

	/* Keep disk streaming and CRC order monotonic in physical address. */
	for (u_int a = 0; a < (*nranges); a++) {
		for (u_int b = a + 1; b < (*nranges); b++) {
			if (ranges[b].start <
			    ranges[a].start) {
				struct hibernate_range tmp;

				tmp = ranges[a];
				ranges[a] = ranges[b];
				ranges[b] = tmp;
			}
		}
	}
	return (true);
}

static bool
hibernate_stream_direct_chunk(struct hibernate_restore *hr,
    u_int ph_index, const struct hibernate_range *direct, u_int ndirect)
{
	EFI_STATUS status;
	uint64_t c_start, c_size, c_offset;

	c_start = hr->ph[ph_index].p_paddr;
	c_size = hr->ph[ph_index].p_memsz != 0 ?
	    hr->ph[ph_index].p_memsz : hr->ph[ph_index].p_filesz;
	c_offset = hr->ph[ph_index].p_offset;
	/*
	 * Stream direct ranges. Record per-64KiB content CRCs so we can
	 * audit, with a memory-only scan, whether any direct destination
	 * was clobbered after it was written. Never re-read a clobbered
	 * block for repair: that risks clobbering a different restored
	 * page and does not converge.
	 */
	uint32_t chunk_crc_stream = 0xFFFFFFFF;
	uint64_t direct_bytes = 0;
	uint64_t n_blk_total = 0;
	u_int n_window_blocks = 0;
	u_int n_windows = 0;
	struct a1_direct_cursor window_cursor = {
		.range = 0,
		.pa = direct[0].start
	};

	for (u_int dr = 0; dr < ndirect; dr++) {
		uint64_t dir_start = direct[dr].start;
		uint64_t dir_end = direct[dr].end;
		uint64_t dir_bytes, dir_pages, cur_page, pages_left;

		if (dir_start >= dir_end || dir_start < c_start ||
		    dir_end > c_start + c_size ||
		    ((dir_start | dir_end) & EFI_PAGE_MASK) != 0) {
			hiber_refuse_pending = "A1 direct cursor invalid";
			return (false);
		}
		dir_bytes = dir_end - dir_start;
		dir_pages = dir_bytes / EFI_PAGE_SIZE;
		cur_page = (dir_start - c_start) / EFI_PAGE_SIZE;
		pages_left = dir_pages;

		while (pages_left > 0) {
			uint64_t blk_pages =
			    pages_left > 16 ? 16 : pages_left;
			uint64_t blk_bytes = blk_pages * EFI_PAGE_SIZE;
			uint64_t image_off, disk_lba, dst_pa;
			void *dst_ptr;
			uint32_t blk_crc;

			if (cur_page > (UINT64_MAX - HIBERNATE_IMAGE_OFFSET -
			    c_offset) / EFI_PAGE_SIZE) {
				hiber_refuse_pending = "A1 disk offset overflow";
				return (false);
			}
			image_off = HIBERNATE_IMAGE_OFFSET + c_offset +
			    cur_page * EFI_PAGE_SIZE;
			if ((image_off % hr->blksz) != 0) {
				hiber_refuse_pending = "A1 disk alignment";
				return (false);
			}
			disk_lba = image_off / hr->blksz;
			if (dir_pages - pages_left >
			    (UINT64_MAX - dir_start) / EFI_PAGE_SIZE) {
				hiber_refuse_pending = "A1 destination overflow";
				return (false);
			}
			dst_pa = dir_start +
			    (dir_pages - pages_left) * EFI_PAGE_SIZE;
			if (dst_pa > UINT64_MAX - blk_bytes) {
				hiber_refuse_pending = "A1 destination overflow";
				return (false);
			}
			dst_ptr = (void *)(uintptr_t)dst_pa;

			if (!hibernate_range_is_direct_claimed(hr, dst_pa,
			    blk_bytes)) {
				snprintf(hiber_refuse_rpt.diag,
				    sizeof(hiber_refuse_rpt.diag),
				    "A1_UNCLAIMED_DESTINATION chunk=%u "
				    "dst_pa=0x%jx bytes=0x%jx",
				    ph_index - 2, (uintmax_t)dst_pa,
				    (uintmax_t)blk_bytes);
				hiber_log(HIBER_LOG_ERROR,
				    "hibernate: A1 destination 0x%jx+0x%jx "
				    "is not retained [FAIL]\n",
				    (uintmax_t)dst_pa,
				    (uintmax_t)blk_bytes);
				hiber_refuse_rpt.chk_staging_crc =
				    HIBER_CHK_FAIL;
				hiber_refuse_pending =
				    "A1_UNCLAIMED_DESTINATION";
				return (false);
			}

			status = hr->blkio->ReadBlocks(hr->blkio, hr->blkio->Media->MediaId,
			    disk_lba, (UINTN)blk_bytes, hr->readbuf);
			if (EFI_ERROR(status)) {
				hiber_log(HIBER_LOG_ERROR,
				    "hibernate: direct read error at LBA %ju (%lu)\n",
				    (uintmax_t)disk_lba, DECODE_ERROR(status));
				hiber_refuse_rpt.chk_read = HIBER_CHK_FAIL;
				hiber_refuse_pending = "read failed";
				return (false);
			}

			chunk_crc_stream = hibernate_crc32_update(
			    chunk_crc_stream, hr->readbuf, (size_t)blk_bytes);
			blk_crc = hibernate_crc32_update(0xFFFFFFFF,
			    hr->readbuf, (size_t)blk_bytes) ^ 0xFFFFFFFF;
			if (n_window_blocks >= A1_BLK_CRC_MAX) {
				hiber_refuse_pending = "A1 table index overflow";
				return (false);
			}
			hr->a1_blk_crc[n_window_blocks++] = blk_crc;
			n_blk_total++;
			memcpy(dst_ptr, hr->readbuf, (size_t)blk_bytes);

			if (memcmp(dst_ptr, hr->readbuf, (size_t)blk_bytes) != 0) {
				hiber_log(HIBER_LOG_ERROR,
				    "hibernate: chunk %u immediate write mismatch "
				    "at 0x%jx [FAIL]\n", ph_index - 2,
				    (uintmax_t)dst_pa);
				hiber_refuse_rpt.chk_staging_crc =
				    HIBER_CHK_FAIL;
				hiber_refuse_pending =
				    "staging CRC mismatch";
				return (false);
			}

			pages_left -= blk_pages;
			cur_page += blk_pages;

			if (n_window_blocks == A1_BLK_CRC_MAX) {
				struct a1_bad_stats bst;

				if (!a1_scan_bad_window(direct,
				    ndirect, &window_cursor,
				    hr->a1_blk_crc, n_window_blocks, &bst)) {
					hiber_refuse_pending =
					    "A1 audit cursor mismatch";
					return (false);
				}
				n_windows++;
				if (bst.n_bad != 0) {
					snprintf(hiber_refuse_rpt.diag,
					    sizeof(hiber_refuse_rpt.diag),
					    "A1_POST_READ_CLOBBER chunk=%u "
					    "window=%u n_bad=%u/%u first=0x%jx",
					    ph_index - 2, n_windows - 1, bst.n_bad,
					    n_window_blocks,
					    (uintmax_t)bst.first_pa);
					hiber_refuse_rpt.chk_staging_crc =
					    HIBER_CHK_FAIL;
					hiber_refuse_pending =
					    "direct restore clobbered";
					return (false);
				}
				n_window_blocks = 0;
			}
		}
		if (direct_bytes > UINT64_MAX - dir_bytes) {
			hiber_refuse_pending = "A1 byte count overflow";
			return (false);
		}
		direct_bytes += dir_bytes;
	}

	if (n_window_blocks != 0) {
		struct a1_bad_stats bst;

		if (!a1_scan_bad_window(direct, ndirect,
		    &window_cursor, hr->a1_blk_crc, n_window_blocks, &bst)) {
			hiber_refuse_pending = "A1 audit cursor mismatch";
			return (false);
		}
		n_windows++;
		if (bst.n_bad != 0) {
			snprintf(hiber_refuse_rpt.diag,
			    sizeof(hiber_refuse_rpt.diag),
			    "A1_POST_READ_CLOBBER chunk=%u window=%u "
			    "n_bad=%u/%u first=0x%jx",
			    ph_index - 2, n_windows - 1, bst.n_bad,
			    n_window_blocks, (uintmax_t)bst.first_pa);
			hiber_refuse_rpt.chk_staging_crc = HIBER_CHK_FAIL;
			hiber_refuse_pending = "direct restore clobbered";
			return (false);
		}
	}

	chunk_crc_stream ^= 0xFFFFFFFF;

	{
		uint32_t chunk_crc_mem = 0xFFFFFFFF;

		for (u_int dr = 0; dr < ndirect; dr++) {
			uint64_t dir_start = direct[dr].start;
			uint64_t dir_bytes =
			    direct[dr].end - dir_start;

			chunk_crc_mem = hibernate_crc32_update(
			    chunk_crc_mem,
			    (const void *)(uintptr_t)dir_start,
			    (size_t)dir_bytes);
		}
		chunk_crc_mem ^= 0xFFFFFFFF;

		if (chunk_crc_mem != chunk_crc_stream) {
			snprintf(hiber_refuse_rpt.diag,
			    sizeof(hiber_refuse_rpt.diag),
			    "CRC_MISMATCH chunk=%u stream=0x%08x "
			    "mem=0x%08x n_blk=%ju windows=%u n_direct=%u",
			    ph_index - 2, chunk_crc_stream, chunk_crc_mem,
			    (uintmax_t)n_blk_total, n_windows,
			    ndirect);
			hiber_log(HIBER_LOG_ERROR,
			    "hibernate:   chunk %2u: CRC MISMATCH "
			    "(stream 0x%08x != mem 0x%08x) [FAIL]\n",
			    ph_index - 2, chunk_crc_stream, chunk_crc_mem);
			hiber_refuse_rpt.chk_staging_crc = HIBER_CHK_FAIL;
			hiber_refuse_pending = "staging CRC mismatch";
			return (false);
		}

		hr->total_streamed_bytes += direct_bytes;
		hr->direct_streamed_chunks++;
		if (direct_bytes == c_size) {
			hiber_log(HIBER_LOG_INFO,
			    "hibernate:   chunk %2u: paddr 0x%016jx "
			    "size 0x%08jx (%ju KiB) -> DIRECT "
			    "[PASS, CRC32 0x%08x, %u window%s]\n",
			    ph_index - 2, (uintmax_t)c_start,
			    (uintmax_t)c_size,
			    (uintmax_t)(c_size / 1024), chunk_crc_mem,
			    n_windows, n_windows == 1 ? "" : "s");
		} else {
			hiber_log(HIBER_LOG_INFO,
			    "hibernate:   chunk %2u: paddr 0x%016jx "
			    "size 0x%08jx -> DEFERRED (%ju KiB direct, "
			    "CRC32 0x%08x, %u window%s) [PASS]\n",
			    ph_index - 2, (uintmax_t)c_start,
			    (uintmax_t)c_size,
			    (uintmax_t)(direct_bytes / 1024),
			    chunk_crc_mem, n_windows,
			    n_windows == 1 ? "" : "s");
		}
	}
	return (true);
}

static bool
hibernate_restore_direct(struct hibernate_restore *hr)
{
	u_int i;

	hr->total_streamed_bytes = 0;
	hr->direct_streamed_chunks = 0;
	hiber_log(HIBER_LOG_INFO, "hibernate: === Phase A1: Direct Chunk Streaming (Pre-EBS) ===\n");

	for (uint64_t e = 0; e < hr->entry_count; e++) {
		uint64_t r_start = hr->entries[e].src_spare_pa;
		uint64_t r_end = r_start + hr->entries[e].page_count * EFI_PAGE_SIZE;
		bool merged = false;

		for (u_int sr = 0; sr < hr->n_staging_reserved; sr++) {
			if (r_start == hr->staging_reserved[sr].end) {
				hr->staging_reserved[sr].end = r_end;
				merged = true;
				break;
			} else if (r_end == hr->staging_reserved[sr].start) {
				hr->staging_reserved[sr].start = r_start;
				merged = true;
				break;
			}
		}
		if (!merged) {
			if (hr->n_staging_reserved < nitems(hr->staging_reserved)) {
				hr->staging_reserved[hr->n_staging_reserved].start = r_start;
				hr->staging_reserved[hr->n_staging_reserved].end = r_end;
				hr->n_staging_reserved++;
			} else {
				hiber_log(HIBER_LOG_ERROR, "hibernate: staging_reserved table overflow\n");
				hiber_refuse_pending = "allocation failed";
				return (false);
			}
		}
	}


	/*
	 * The CRC table and read buffer retain their fixed arena layout.
	 * Validate their compile-time relationship once before streaming;
	 * table capacity limits a window, not the size of the chunk.
	 */
	if ((uint64_t)A1_BLK_CRC_MAX * sizeof(uint32_t) >
	    HIBER_CSP_A1_CRC_SIZE ||
	    HIBER_A1_BLOCK_SIZE == 0 ||
	    HIBER_A1_BLOCK_SIZE > HIBER_CSP_READBUF_SIZE ||
	    hr->blksz == 0 || (HIBER_A1_BLOCK_SIZE % hr->blksz) != 0) {
		hiber_log(HIBER_LOG_ERROR,
		    "hibernate: invalid A1 fixed workspace geometry [FAIL]\n");
		hiber_refuse_rpt.chk_staging_crc = HIBER_CHK_FAIL;
		hiber_refuse_pending = "A1 workspace geometry";
		return (false);
	}
	for (i = 2; i < hr->ehdr->e_phnum; i++) {
		uint64_t c_start, c_size;
		struct hibernate_range chunk_direct[512];
		u_int n_chunk_direct;

		c_start = hr->ph[i].p_paddr;
		c_size = hr->ph[i].p_memsz != 0 ?
		    hr->ph[i].p_memsz : hr->ph[i].p_filesz;
		if (!hibernate_build_chunk_direct_ranges(hr, c_start, c_size,
		    chunk_direct, nitems(chunk_direct), &n_chunk_direct))
			return (false);
		if (n_chunk_direct == 0)
			continue;
		if (!hibernate_stream_direct_chunk(hr, i, chunk_direct,
		    n_chunk_direct))
			return (false);
	}

	hiber_log(HIBER_LOG_INFO,
	    "hibernate: Phase A1 complete: %u chunks, %ju MiB direct streamed "
	    "[PASS]\n",
	    hr->direct_streamed_chunks,
	    (uintmax_t)(hr->total_streamed_bytes / (1024 * 1024)));

	return (true);
}

static bool
hibernate_exit_boot_services(struct hibernate_restore *hr)
{
	uint32_t check_spare_crc;

	hiber_log(HIBER_LOG_INFO,
	    "hibernate: === Phase A2: Deferred Chunk Integrity "
	    "Re-verification ===\n");
	check_spare_crc = 0xffffffff;
	for (uint64_t e = 0; e < hr->entry_count; e++) {
		check_spare_crc = hibernate_crc32_update(check_spare_crc,
		    (const void *)(uintptr_t)hr->entries[e].src_spare_pa,
		    hr->entries[e].page_count * EFI_PAGE_SIZE);
	}
	check_spare_crc ^= 0xffffffff;

	if (check_spare_crc != hr->total_staged_crc) {
		hiber_log(HIBER_LOG_ERROR,
		    "hibernate: Phase A2 CRC mismatch (staged 0x%08x != "
		    "verified 0x%08x) [FAIL]\n",
		    hr->total_staged_crc, check_spare_crc);
		hiber_refuse_rpt.chk_staging_crc = HIBER_CHK_FAIL;
		hiber_refuse_pending = "staging CRC mismatch";
		return (false);
	}
	hiber_refuse_rpt.chk_staging_crc = HIBER_CHK_PASS;
	hiber_refuse_set_stage("A3-EBS");
	hiber_log(HIBER_LOG_INFO,
	    "hibernate: Phase A2 complete: %ju deferred pages "
	    "(%ju KiB) re-verified, CRC32 0x%08x [PASS]\n",
	    (uintmax_t)hr->total_staged_pages,
	    (uintmax_t)(hr->total_staged_pages * 4), check_spare_crc);

	/*
	 * Persist the loader trace before ExitBootServices: once boot
	 * services terminate no firmware file access remains, so this is the
	 * last point at which a successful restore can be recorded on the
	 * ESP.  Best-effort and bounded; a write failure must not abort the
	 * restore.
	 */
	hiber_trace_write_esp();

	hiber_log(HIBER_LOG_INFO,
	    "hibernate: === Phase A3: ExitBootServices Transition ===\n");
	hr->ebs_map_sz = 128 * 1024;
	hr->ebs_map_key = 0;
	hr->ebs_desc_sz = 0;
	hr->ebs_desc_ver = 0;
	hr->ebs_status = EFI_SUCCESS;

	for (hr->ebs_retry = 3; hr->ebs_retry > 0; hr->ebs_retry--) {
		hr->ebs_map_sz = 128 * 1024;
		hr->ebs_status = BS->GetMemoryMap(&hr->ebs_map_sz,
		    hr->post_map, &hr->ebs_map_key, &hr->ebs_desc_sz,
		    &hr->ebs_desc_ver);
		if (EFI_ERROR(hr->ebs_status)) {
			hiber_log(HIBER_LOG_ERROR,
			    "hibernate: final GetMemoryMap failed: %lu\n",
			    DECODE_ERROR(hr->ebs_status));
			hiber_refuse_rpt.chk_ebs = HIBER_CHK_FAIL;
			hiber_refuse_pending = "ExitBootServices failed";
			return (false);
		}

		hr->ebs_status = efi_exit_boot_services(hr->ebs_map_key);
		if (!EFI_ERROR(hr->ebs_status))
			break;
	}

	if (hr->ebs_retry == 0) {
		hiber_log(HIBER_LOG_ERROR,
		    "hibernate: ExitBootServices failed after retries (%lu)\n",
		    DECODE_ERROR(hr->ebs_status));
		hiber_refuse_rpt.chk_ebs = HIBER_CHK_FAIL;
		hiber_refuse_pending = "ExitBootServices failed";
		return (false);
	}

	((void (*)(void))(uintptr_t)
	    (hr->cb->hc_contig_spare_start + 0x30))();

	for (;;)
		__asm__ __volatile__("cli; hlt");
}

static void
hibernate_release_restore(struct hibernate_restore *hr)
{
	/*
	 * Release only allocations made by this restore attempt.  The direct
	 * destination ledger records exact-address loader allocations; it never
	 * contains the kernel's contiguous-spare arena or retained loader heap.
	 */
	for (u_int i = 0; i < hr->n_direct_claims; i++) {
		BS->FreePages((EFI_PHYSICAL_ADDRESS)
		    hr->direct_claims[i].start,
		    EFI_SIZE_TO_PAGES(hr->direct_claims[i].end -
		    hr->direct_claims[i].start));
	}
	hr->n_direct_claims = 0;

	if (hr->entries != NULL) {
		for (uint64_t e = 0; e < hr->entry_count; e++)
			BS->FreePages((EFI_PHYSICAL_ADDRESS)
			    hr->entries[e].src_spare_pa,
			    hr->entries[e].page_count);
		hr->entries = NULL;
		hr->entry_count = 0;
		hr->claimed_spare_pages = 0;
	}
	if (hr->workspace != 0) {
		BS->FreePages(hr->workspace, hr->workspace_pages);
		hr->workspace = 0;
		hr->workspace_pages = 0;
	}
}

static void
hibernate_analyze_conflicts(pdinfo_t *part, const Elf_Ehdr *ehdr,
    const Elf_Phdr *ph, const struct hibernate_cb *cb, uint8_t **bufp)
{
	struct hibernate_restore hr;
	bool restored;

	bzero(&hr, sizeof(hr));
	hr.part = part;
	restored = hibernate_prepare_restore(&hr, ehdr, ph, cb, bufp);
	if (restored)
		restored = hibernate_stage_deferred(&hr);
	if (restored)
		restored = hibernate_prepare_handoff(&hr);
	if (restored)
		restored = hibernate_restore_direct(&hr);
	if (restored)
		restored = hibernate_exit_boot_services(&hr);
	hibernate_release_restore(&hr);
	if (!restored && hiber_refuse_pending != NULL)
		hibernate_refuse(hiber_refuse_pending);
}

static bool
hibernate_probe_partition(pdinfo_t *part, uint8_t **bufp)
{
	EFI_BLOCK_IO *blkio;
	EFI_STATUS status;
	Elf_Ehdr *ehdr;
	Elf_Phdr *ph;
	struct hibernate_cb *cb;
	struct hibernate_pcb *pcb;
	uint64_t blocks_needed, lba, total_mem;
	uint32_t blksz;
	u_int i, load_chunks, part_u;
	uint8_t *buf;

	if (bufp == NULL || *bufp == NULL)
		return (false);
	buf = *bufp;
	part_u = part->pd_unit;

	blkio = part->pd_blkio;
	if (blkio == NULL || blkio->Media == NULL) {
		hiber_refuse_add_probe(part_u, "skipped: read failed");
		return (false);
	}

	blksz = blkio->Media->BlockSize;
	if (blksz == 0 || (blksz & (blksz - 1)) != 0) {
		hiber_refuse_add_probe(part_u, "skipped: read failed");
		return (false);
	}

	if (HIBERNATE_IMAGE_OFFSET % blksz != 0) {
		hiber_refuse_add_probe(part_u, "skipped: read failed");
		return (false);
	}

	lba = HIBERNATE_IMAGE_OFFSET / blksz;
	if (blkio->Media->LastBlock < lba) {
		hiber_refuse_add_probe(part_u, "skipped: read failed");
		return (false);
	}

	/* Read 1 block to probe for ELF header */
	status = blkio->ReadBlocks(blkio, blkio->Media->MediaId, lba,
	    blksz, buf);
	if (status != EFI_SUCCESS) {
		hiber_refuse_add_probe(part_u, "skipped: read failed");
		return (false);
	}

	ehdr = (Elf_Ehdr *)buf;
	if (!IS_ELF(*ehdr) ||
	    ehdr->e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr->e_ident[EI_DATA] != ELFDATA2LSB ||
	    ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
	    (ehdr->e_version != 0 && ehdr->e_version != EV_CURRENT)) {
		hiber_refuse_add_probe(part_u, "skipped: bad elf ident");
		return (false);
	}
	if (ehdr->e_type != ET_FREEBSD_HIBERNATE_IMAGE) {
		hiber_refuse_add_probe(part_u, "skipped: bad e_type");
		return (false);
	}
	if (ehdr->e_machine != EM_X86_64) {
		hiber_refuse_add_probe(part_u, "skipped: bad e_machine");
		return (false);
	}
	if (ehdr->e_phentsize != sizeof(Elf_Phdr)) {
		hiber_refuse_add_probe(part_u, "skipped: bad phdr layout");
		return (false);
	}

	/* Candidate image partition found; read complete 512 KiB headers */
	hiber_refuse_add_probe(part_u, "candidate");
	hiber_refuse_set_stage("headers");
	snprintf(hiber_refuse_rpt.image, sizeof(hiber_refuse_rpt.image),
	    "part=%u lba=%ju blksz=%u bytes_read=%u status=ok",
	    part_u, (uintmax_t)lba, blksz, blksz);
	hiber_refuse_rpt.chk_read = HIBER_CHK_PASS;
	hiber_refuse_rpt.chk_elf_ident = HIBER_CHK_PASS;
	hiber_refuse_rpt.chk_e_type = HIBER_CHK_PASS;
	hiber_refuse_rpt.chk_e_machine = HIBER_CHK_PASS;
	snprintf(hiber_refuse_rpt.elf, sizeof(hiber_refuse_rpt.elf),
	    "ident=ok e_type=0x%04x e_machine=0x%04x e_phnum=%u",
	    ehdr->e_type, ehdr->e_machine, (u_int)ehdr->e_phnum);

	blocks_needed = HIBERNATE_HDR_BUF_SIZE / blksz;
	if (lba + blocks_needed - 1 > blkio->Media->LastBlock) {
		printf("Hibernate: partition %u too small for headers\n",
		    part_u);
		snprintf(hiber_refuse_rpt.image, sizeof(hiber_refuse_rpt.image),
		    "part=%u lba=%ju blksz=%u bytes_read=%u status=too-small",
		    part_u, (uintmax_t)lba, blksz, blksz);
		hiber_refuse_rpt.chk_read = HIBER_CHK_FAIL;
		hibernate_refuse("read failed");
		return (false);
	}

	status = blkio->ReadBlocks(blkio, blkio->Media->MediaId, lba,
	    HIBERNATE_HDR_BUF_SIZE, buf);
	if (status != EFI_SUCCESS) {
		printf("Hibernate: failed to read headers from partition %u (%lu)\n",
		    part_u, DECODE_ERROR(status));
		snprintf(hiber_refuse_rpt.image, sizeof(hiber_refuse_rpt.image),
		    "part=%u lba=%ju blksz=%u bytes_read=0 status=EFI error %lu",
		    part_u, (uintmax_t)lba, blksz, DECODE_ERROR(status));
		hiber_refuse_rpt.chk_read = HIBER_CHK_FAIL;
		hibernate_refuse("read failed");
		return (false);
	}
	snprintf(hiber_refuse_rpt.image, sizeof(hiber_refuse_rpt.image),
	    "part=%u lba=%ju blksz=%u bytes_read=%u status=ok",
	    part_u, (uintmax_t)lba, blksz, (u_int)HIBERNATE_HDR_BUF_SIZE);

	ehdr = (Elf_Ehdr *)buf;
	snprintf(hiber_refuse_rpt.elf, sizeof(hiber_refuse_rpt.elf),
	    "ident=ok e_type=0x%04x e_machine=0x%04x e_phnum=%u",
	    ehdr->e_type, ehdr->e_machine, (u_int)ehdr->e_phnum);

	if (ehdr->e_phnum < 2) {
		printf("Hibernate: invalid phnum %u (expected >= 2)\n",
		    (u_int)ehdr->e_phnum);
		hiber_refuse_rpt.chk_phdr = HIBER_CHK_FAIL;
		hibernate_refuse("bad phdr layout");
		return (false);
	}

	if (ehdr->e_phoff + (uint64_t)ehdr->e_phnum * sizeof(Elf_Phdr) >
	    HIBERNATE_HDR_BUF_SIZE) {
		printf("Hibernate: phdrs exceed buffer size (phoff 0x%jx, phnum %u)\n",
		    (uintmax_t)ehdr->e_phoff, (u_int)ehdr->e_phnum);
		hiber_refuse_rpt.chk_phdr = HIBER_CHK_FAIL;
		hibernate_refuse("bad phdr layout");
		return (false);
	}

	ph = (Elf_Phdr *)(buf + ehdr->e_phoff);

	/* Validate phdr[0]: PT_FREEBSD_HIBERNATE_CB */
	if (ph[0].p_type != PT_FREEBSD_HIBERNATE_CB) {
		printf("Hibernate: phdr[0] is not PT_FREEBSD_HIBERNATE_CB (type 0x%x)\n",
		    ph[0].p_type);
		hiber_refuse_rpt.chk_phdr = HIBER_CHK_FAIL;
		snprintf(hiber_refuse_rpt.cb, sizeof(hiber_refuse_rpt.cb),
		    "phdr=missing hc_version=n/a hcb_size=n/a validate=fail "
		    "hc_hardware_signature=n/a live_facs=not-checked "
		    "policy=unknown-proceed(deferred)");
		hibernate_refuse("bad phdr layout");
		return (false);
	}
	if (ph[0].p_offset + ph[0].p_filesz > HIBERNATE_HDR_BUF_SIZE) {
		printf("Hibernate: CB exceeds buffer size (offset 0x%jx, size 0x%jx)\n",
		    (uintmax_t)ph[0].p_offset, (uintmax_t)ph[0].p_filesz);
		hiber_refuse_rpt.chk_phdr = HIBER_CHK_FAIL;
		hibernate_refuse("bad phdr layout");
		return (false);
	}
	cb = (struct hibernate_cb *)(buf + ph[0].p_offset);
	snprintf(hiber_refuse_rpt.cb, sizeof(hiber_refuse_rpt.cb),
	    "phdr=found hc_version=%ju hcb_size=%ju validate=%s "
	    "hc_hardware_signature=0x%016jx live_facs=not-checked "
	    "policy=unknown-proceed(deferred)",
	    (uintmax_t)cb->hc_version, (uintmax_t)ph[0].p_filesz,
	    hcb_validate(cb, ph[0].p_filesz) ? "ok" : "fail",
	    (uintmax_t)cb->hc_hardware_signature);
	if (!hcb_validate(cb, ph[0].p_filesz)) {
		printf("Hibernate: CB validation failed (version %ju, size %ju)\n",
		    (uintmax_t)cb->hc_version, (uintmax_t)ph[0].p_filesz);
		hiber_refuse_rpt.chk_phdr = HIBER_CHK_PASS;
		hiber_refuse_rpt.chk_cb = HIBER_CHK_FAIL;
		hibernate_refuse("CB validation failed");
		return (false);
	}
	hiber_refuse_rpt.chk_phdr = HIBER_CHK_PASS;
	hiber_refuse_rpt.chk_cb = HIBER_CHK_PASS;

	/* Validate phdr[1]: PT_FREEBSD_HIBERNATE_PCB */
	if (ph[1].p_type != PT_FREEBSD_HIBERNATE_PCB) {
		printf("Hibernate: phdr[1] is not PT_FREEBSD_HIBERNATE_PCB (type 0x%x)\n",
		    ph[1].p_type);
		snprintf(hiber_refuse_rpt.pcb, sizeof(hiber_refuse_rpt.pcb),
		    "phdr=missing size=n/a/48 cr0=n/a cr3=n/a cr4=n/a "
		    "rsp=n/a rip=n/a r12=n/a");
		hiber_refuse_rpt.chk_pcb = HIBER_CHK_FAIL;
		hibernate_refuse("bad phdr layout");
		return (false);
	}
	if (ph[1].p_filesz != sizeof(struct hibernate_pcb) ||
	    ph[1].p_memsz != sizeof(struct hibernate_pcb)) {
		printf("Hibernate: PCB invalid size (filesz %ju, memsz %ju, expected %zu)\n",
		    (uintmax_t)ph[1].p_filesz, (uintmax_t)ph[1].p_memsz,
		    sizeof(struct hibernate_pcb));
		snprintf(hiber_refuse_rpt.pcb, sizeof(hiber_refuse_rpt.pcb),
		    "phdr=found size=%ju/48 cr0=n/a cr3=n/a cr4=n/a "
		    "rsp=n/a rip=n/a r12=n/a",
		    (uintmax_t)ph[1].p_filesz);
		hiber_refuse_rpt.chk_pcb = HIBER_CHK_FAIL;
		hibernate_refuse("PCB size mismatch");
		return (false);
	}
	if (ph[1].p_offset + ph[1].p_filesz > HIBERNATE_HDR_BUF_SIZE) {
		printf("Hibernate: PCB exceeds buffer size (offset 0x%jx, size 0x%jx)\n",
		    (uintmax_t)ph[1].p_offset, (uintmax_t)ph[1].p_filesz);
		hiber_refuse_rpt.chk_pcb = HIBER_CHK_FAIL;
		hibernate_refuse("PCB size mismatch");
		return (false);
	}
	pcb = (struct hibernate_pcb *)(buf + ph[1].p_offset);
	snprintf(hiber_refuse_rpt.pcb, sizeof(hiber_refuse_rpt.pcb),
	    "phdr=found size=%zu/48 cr0=0x%016jx cr3=0x%016jx cr4=0x%016jx "
	    "rsp=0x%016jx rip=0x%016jx r12=0x%016jx",
	    sizeof(struct hibernate_pcb),
	    (uintmax_t)pcb->cr0, (uintmax_t)pcb->cr3, (uintmax_t)pcb->cr4,
	    (uintmax_t)pcb->rsp, (uintmax_t)pcb->rip, (uintmax_t)pcb->r12);
	hiber_refuse_rpt.chk_pcb = HIBER_CHK_PASS;

	/* Validate phdr[2..N+1]: PT_LOAD */
	load_chunks = 0;
	total_mem = 0;
	for (i = 2; i < ehdr->e_phnum; i++) {
		if (ph[i].p_type != PT_LOAD) {
			printf("Hibernate: phdr[%u] is not PT_LOAD (type 0x%x)\n",
			    i, ph[i].p_type);
			hiber_refuse_rpt.chk_phdr = HIBER_CHK_FAIL;
			hibernate_refuse("bad phdr layout");
			return (false);
		}
		load_chunks++;
		total_mem += ph[i].p_filesz;
	}

	/* Descriptive summary to serial console */
	printf("=== Hibernate Image Probe (Read-Only Bring-Up) ===\n");
	printf("Hibernate: found image on partition %u (LBA %ju, blocksize %u)\n",
	    part_u, (uintmax_t)lba, blksz);
	printf("Hibernate ELF Header:\n");
	printf("  type: 0x%04x  machine: 0x%04x  phnum: %u  phentsize: %u\n",
	    ehdr->e_type, ehdr->e_machine, (u_int)ehdr->e_phnum,
	    (u_int)ehdr->e_phentsize);
	printf("Hibernate Control Block (CB):\n");
	printf("  version: %ju\n", (uintmax_t)cb->hc_version);
	printf("  hardware_signature: 0x%016jx\n",
	    (uintmax_t)cb->hc_hardware_signature);
	printf("  contig_spare_start: 0x%016jx  contig_spare_size: 0x%jx (%ju KiB)\n",
	    (uintmax_t)cb->hc_contig_spare_start,
	    (uintmax_t)cb->hc_contig_spare_size,
	    (uintmax_t)(cb->hc_contig_spare_size / 1024));
	printf("  spare_pages_nb: %ju (%ju KiB)\n",
	    (uintmax_t)cb->hc_spare_pages_nb,
	    (uintmax_t)(cb->hc_spare_pages_nb * 4));
	printf("Hibernate Process Control Block (PCB):\n");
	printf("  cr0: 0x%016jx  cr3: 0x%016jx  cr4: 0x%016jx\n",
	    (uintmax_t)pcb->cr0, (uintmax_t)pcb->cr3, (uintmax_t)pcb->cr4);
	printf("  rsp: 0x%016jx  rip: 0x%016jx  r12: 0x%016jx\n",
	    (uintmax_t)pcb->rsp, (uintmax_t)pcb->rip, (uintmax_t)pcb->r12);
	printf("Hibernate PT_LOAD Segments: %u chunks, total %ju bytes (%ju MiB)\n",
	    load_chunks, (uintmax_t)total_mem,
	    (uintmax_t)(total_mem / (1024 * 1024)));
	for (i = 2; i < ehdr->e_phnum; i++) {
		printf("  chunk %2u: paddr 0x%016jx size 0x%08jx (%ju KiB) offset 0x%jx\n",
		    i - 2, (uintmax_t)ph[i].p_paddr, (uintmax_t)ph[i].p_filesz,
		    (uintmax_t)(ph[i].p_filesz / 1024),
		    (uintmax_t)ph[i].p_offset);
	}
	hiber_refuse_set_stage("classification");
	hibernate_analyze_conflicts(part, ehdr, ph, cb, bufp);
	printf("=== Validation Successful: Continuing Normal Boot ===\n");
	return (true);
}

void
hibernate_probe(void)
{
	pdinfo_t *dp, *parent, *part;
	EFI_STATUS status;
	uint8_t *buf;
	bool found;

	if (!hibernate_resume_enabled())
		return;

	hiber_log_init();
	hiber_log(HIBER_LOG_INFO,
	    "hibernate: console loglevel=%u (0=error 1=warn 2=info 3=debug); "
	    "full trace -> \\efi\\freebsd\\hiber-trace.log\n",
	    (unsigned)hiber_console_level);

	hiber_refuse_reset();
	hiber_refuse_set_stage("probe");

	if (boot_img == NULL || boot_img->DeviceHandle == NULL) {
		printf("Hibernate: boot_img or DeviceHandle is NULL\n");
		hibernate_refuse("allocation failed");
		return;
	}

	dp = efiblk_get_pdinfo_by_handle(boot_img->DeviceHandle);
	if (dp == NULL) {
		printf("Hibernate: cannot find pdinfo for boot device\n");
		hibernate_refuse("allocation failed");
		return;
	}

	parent = (dp->pd_parent != NULL) ? dp->pd_parent : dp;
	buf = NULL;
	status = BS->AllocatePool(EfiBootServicesData, HIBERNATE_HDR_BUF_SIZE,
	    (void **)&buf);
	if (status != EFI_SUCCESS || buf == NULL) {
		printf("Hibernate: failed to allocate %u bytes header buffer (%lu)\n",
		    (u_int)HIBERNATE_HDR_BUF_SIZE, DECODE_ERROR(status));
		hibernate_refuse("allocation failed");
		return;
	}

	found = false;
	STAILQ_FOREACH(part, &parent->pd_part, pd_link) {
		if (hibernate_probe_partition(part, &buf)) {
			found = true;
			break;
		}
		/* Candidate abandon already called hibernate_refuse(). */
		if (hiber_refuse_rpt.emitted) {
			found = true; /* suppress no-image primary */
			break;
		}
	}

	if (!found)
		hibernate_refuse("no hibernate image found");

	if (buf != NULL)
		BS->FreePool(buf);
}

#else /* !defined(__amd64__) */

void
hibernate_probe(void)
{
}

#endif /* defined(__amd64__) */
