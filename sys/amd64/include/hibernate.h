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
 * Definitions for structures in the hibernate ELF image.  These definitions are
 * only valid for ELF objects of type ET_FREEBSD_HIBERNATE_IMAGE, see
 * sys/elf_common.h.  Therefore, the selected values for the symbols can be
 * freely allocated in the OS-specific ranges without a conflict with any "real"
 * ELF definitions.
 */
/* Hibernate control block. */
#define	PT_FREEBSD_HIBERNATE_CB		0x61000054
/* Hibernate minimal PCB to hand over control to the kernel. */
#define	PT_FREEBSD_HIBERNATE_PCB	0x61000055

/*
 * Descriptor for a contiguous chunk of physical memory for the loader to use.
 *
 * These pages are allocated but not used by the kernel.  They are passed to the
 * loader which can use them as it sees fit.  In particular, it will use them as
 * trampoline pages, where pages of the kernel to load will be temporarily
 * stored until they can finally be put in place (for those that collide with
 * the boot memory map).
 */
struct hibernate_chunk_desc {
	uint64_t phys_addr;
	uint64_t page_count;
};

/*
 * Content of the specific PT_FREEBSD_HIBERNATE_CB segment.
 *
 * Offset of 'hc_version' must not change.  There are no other requirements of
 * backwards compatibility nor ABI stability, but ABI changes (to 'struct
 * hibernate_cb' or also 'struct hibernate_pcb') have to be reflected through
 * 'hc_version'.
 *
 * Only the content of 'hc_hardware_signature' is really machine-dependent (in
 * addition to integer sizes), and is filled here with the ACPI FACS signature
 * (in the lower 32 bits).
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
	uint64_t version;	/* Version number. */
#define HCB_VERSION	1
	/* ACPI FACS signature in the lower 32 bits. 0 if not filled. */
	uint64_t hardware_signature;
	/* Spare chunks of memory. */
	uint64_t chunk_count;
	struct hibernate_chunk_desc chunks[];
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
hcb_size_spec(const uint64_t chunk_count)
{
	return (offsetof(struct hibernate_cb, chunks) + chunk_count *
	    sizeof(*((struct hibernate_cb *)NULL)->chunks));
}

static inline size_t __pure
hcb_size(const struct hibernate_cb *hcb)
{
	return (hcb_size_spec(hcb->chunk_count));
}

/*
 * Does buffer 'buf' with size 'size' contain a valid 'struct hibernate_cb'?
 */
static inline bool __pure
hcb_validate(const void *const buf, const uint64_t size)
{
	const struct hibernate_cb *const hcb = buf;

	if (size < sizeof(uint64_t) || hcb->version != HCB_VERSION)
		return (false);
	if (size < offsetof(struct hibernate_cb, chunks))
		return (false);
	return (size == hcb_size(hcb));
}


#ifdef _KERNEL

int dumpsys_hibernate_savectx(struct hibernate_pcb *hpcb) __returns_twice;

#endif


#endif /* _MACHINE_HIBERNATE_H */
