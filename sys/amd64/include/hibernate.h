#ifndef __AMD64_HIBERNATE_H__
#define __AMD64_HIBERNATE_H__

#include <machine/elf.h>

/*
 * Definitions for structures in the hibernate image for use by
 * hibernate image loader (HIL).  These definitions are only valid for
 * the ELF objects of type ET_FREEBSD_S4_IMAGE, see sys/elf_common.h.
 * Therefore, the selected values for the symbols can be freely
 * allocated in the OS-specific ranges without a conflict with any
 * 'real' ELF definitions.
 */

/* Pointer to the physical and virtual address of struct s4_pcb. */
#define	PT_FREEBSD_S4_PCB		0x61000054
/* Pointer to the physical and virtual address of struct trampoline_buf_desc. */
#define	PT_FREEBSD_S4_TRAMPOLINE	0x61000055

/*
 * Minimal dump of the CPU0 state enough for the HIL to transfer
 * control to the asm trampoline in kernel.  The actual kernel C state
 * is saved in the per-cpu struct pcb's.
 */
struct s4_pcb {
	uint64_t cr0;
	uint64_t cr3;			/* kernel page table root */
	uint64_t cr4;
	uint64_t rsp;			/* C stack for the entry point */
	uint64_t rip;			/* entry point */
	uint64_t gsbase;		/* KGSBASE, to have curthread right
					   away */
	uint32_t acpic_facs_hwsig;	/* hardware signature from
					   the ACPI FACS table */
	uint32_t pad0;
};

/*
 * Array of the physical addresses of pages below 4G, which are unused
 * by kernel and can be utilized by the HIL as needed.  Kernel must
 * try to select the pages unused by the BIOS boot time code.
 */
struct trampoline_cont_buf_desc {
	uint64_t num_pages;
	uint64_t phys_addr;
};

struct trampoline_buf_desc {
	uint64_t num_bufs;
	struct trampoline_cont_buf_desc bufs[];
};

#endif
