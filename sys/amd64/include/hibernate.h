/*
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by Konstantin Belousov <kib@FreeBSD.org>, and
 * Olivier Certner <olce@FreeBSD.org> at Kumacom SARL, under sponsorship from
 * the FreeBSD Foundation.
 */

#ifndef _MACHINE_HIBERNATE_H
#define _MACHINE_HIBERNATE_H

#include <sys/types.h>
#include <sys/_null.h>
#include <sys/_stdint.h>
#include <sys/cdefs.h>

/*
 * Content of the specific PT_FREEBSD_HIBERNATE_CB segment.
 *
 * Offset of 'hc_version' must not change.  There are no other requirements of
 * backwards compatibility nor ABI stability, but ABI changes (to 'struct
 * hibernate_cb' or also 'struct hibernate_pcb') have to be reflected through
 * 'hc_version'.
 *
 * Only the content of 'hc_hardware_signature' is actually machine-dependent,
 * and here is filled with the ACPI FACS signature (in the lower 32 bits).
 *
 * Changes here must be reflected into hcb_size() and hcb_validate() below.
 *
 * Contiguous and non-contiguous physical pages are meant to be trampoline space
 * for the loader (i.e., pages deliberately not used by the kernel, at physical
 * locations that should not overlap with the initial memory map, used to copy
 * part of the loader and provide breathing room so that it can copy all kernel
 * physical pages to their right places, overwriting pages of the initial map).
 */
struct hibernate_cb {
	uint64_t hc_version;	/* Version number. */
#define HCB_VERSION	1
	/* ACPI FACS signature in the lower 32 bits. 0 if not filled. */
	uint64_t hc_hardware_signature;
	/* Spare contiguous physical pages. */
	uint64_t hc_contig_spare_start;
	uint64_t hc_contig_spare_size;
	/* Spare non-contiguous physical pages. */
	uint64_t hc_spare_pages_nb;
	uint64_t hc_spare_pages[];
};

/*
 * Content of the specific PT_FREEBSD_HIBERNATE_PCB segment.
 *
 * Minimal state to hand control to the kernel. The layout depends on
 * HCB_VERSION.
 */
struct hibernate_pcb {
	uint64_t cr0;
	uint64_t cr3;		/* Kernel page table root. */
	uint64_t cr4;
	uint64_t rsp;		/* Stack for the entry point */
	uint64_t rip;		/* Entry point. */
	uint64_t r12;		/* Parameter for the entry point. */
};

static inline size_t __pure
hcb_size_spec(const uint64_t spare_pages_nb)
{
	return (offsetof(struct hibernate_cb, hc_spare_pages) + spare_pages_nb *
	    sizeof(*((struct hibernate_cb *)NULL)->hc_spare_pages));
}

static inline size_t __pure
hcb_size(const struct hibernate_cb *hcb)
{
	return (hcb_size_spec(hcb->hc_spare_pages_nb));
}

/*
 * Does buffer 'buf' with size 'size' contain a valid 'struct hibernate_cb'?
 */
static inline bool __pure
hcb_validate(const void *const buf, const uint64_t size)
{
	const struct hibernate_cb *const hcb = buf;

	if (size < sizeof(uint64_t) || hcb->hc_version != HCB_VERSION)
		return (false);
	if (size < offsetof(struct hibernate_cb, hc_spare_pages))
		return (false);
	return (size == hcb_size(hcb));
}


#ifdef _KERNEL

int dumpsys_hibernate_savectx(struct hibernate_pcb *hpcb) __returns_twice;

#endif


#endif /* _MACHINE_HIBERNATE_H */
