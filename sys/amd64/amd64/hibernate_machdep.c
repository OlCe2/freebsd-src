/*
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by Olivier Certner <olce@FreeBSD.org> at Kumacom
 * SARL under sponsorship from the FreeBSD Foundation.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/errno.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>
#include <vm/pmap.h>

#include <machine/cpufunc.h>
#include <machine/fpu.h>
#include <machine/hibernate.h>
#include <machine/md_var.h>
#include <machine/pcb.h>
#include <machine/pmap.h>
#include <machine/psl.h>
#include <machine/specialreg.h>

/*
 * XXX
 *
 * Code below currently requires susppcbs[] to have been allocated in advance,
 * which is currently always the case as ACPI does the allocation and hibernate
 * cannot be triggered without ACPI.
 */
extern struct susppcb **susppcbs;

/*
 * Setup transient 1:1 mapping of low 4 GiB in kernel_pmap
 * mirroring mp_machdep.c:355-399.
 */
static void
hibernate_setup_identity_map(void)
{
	static vm_page_t m_pdp, m_pd[4], m_pml4;
	static bool map_initialized = false;
	pml4_entry_t *v_pml4;
	pdp_entry_t *v_pdp;
	pd_entry_t *v_pd;
	int i, j;

	if (map_initialized)
		return;

	if (la57) {
		m_pml4 = pmap_page_alloc_below_4g(true);
		v_pml4 = (pml4_entry_t *)VM_PAGE_TO_DMAP(m_pml4);
	} else {
		v_pml4 = &kernel_pmap->pm_pmltop[0];
	}
	m_pdp = pmap_page_alloc_below_4g(true);
	v_pdp = (pdp_entry_t *)VM_PAGE_TO_DMAP(m_pdp);

	for (i = 0; i < 4; i++) {
		m_pd[i] = pmap_page_alloc_below_4g(false);
		v_pd = (pd_entry_t *)VM_PAGE_TO_DMAP(m_pd[i]);
		for (j = 0; j < NPDEPG; j++) {
			v_pd[j] = ((vm_paddr_t)i * NBPDP + ((vm_paddr_t)j << PDRSHIFT)) |
			    X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M | PG_PS;
		}
		v_pdp[i] = VM_PAGE_TO_PHYS(m_pd[i]) |
		    X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M;
	}

	if (la57) {
		kernel_pmap->pm_pmltop[0] = VM_PAGE_TO_PHYS(m_pml4) |
		    X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M;
	}
	v_pml4[0] = VM_PAGE_TO_PHYS(m_pdp) |
	    X86_PG_V | X86_PG_RW | X86_PG_A | X86_PG_M;

	if ((read_rflags() & PSL_I) != 0)
		pmap_invalidate_all(kernel_pmap);
	else
		invltlb_glob();

	map_initialized = true;
}

/*
 * Save the current context in the hibernate PCB.
 *
 * Returns twice, the second time with EJUSTRETURN (on restore).
 */
int
dumpsys_hibernate_savectx(struct hibernate_pcb *hpcb, void *stack_top,
    int (*dump_fn)(void *, void *), void *dump_arg)
{
	static void *low_page = NULL;
	struct pcb *pcb;
	uint64_t low_entry_pa, low_stack_pa;
	size_t cr3_offset;
	int error;

	/*
	 * 1. Allocate 1 contiguous physical page < 4 GiB for trampoline & stack.
	 */
	if (low_page == NULL) {
		low_page = contigmalloc(PAGE_SIZE, M_DEVBUF, M_WAITOK, 0,
		    0xfffffffful, PAGE_SIZE, 0ul);
		if (low_page == NULL)
			panic("hibernate: cannot allocate low trampoline page");
	}

	/*
	 * 2. Setup transient 1:1 mapping of low 4 GiB in kernel_pmap.
	 */
	hibernate_setup_identity_map();

	/*
	 * 3. Copy trampoline code to offset 0 and record kernel CR3.
	 */
	bcopy(hibernate_resume_tramp, low_page, hibernate_resume_tramp_size);
	cr3_offset = (uintptr_t)&hibernate_tramp_cr3 -
	    (uintptr_t)hibernate_resume_tramp;
	*(uint64_t *)((char *)low_page + cr3_offset) = kernel_pmap->pm_cr3;

	/*
	 * 4. Calculate entry and stack physical addresses.
	 */
	low_entry_pa = vtophys(low_page);
	low_stack_pa = low_entry_pa + PAGE_SIZE - 8;

	pcb = &susppcbs[0]->sp_pcb;

	/*
	 * Capture FPU state before hibernate_savectx so subsequent stack
	 * growth cannot overwrite the return-address slot savectx saved.
	 */
	fpususpend(susppcbs[0]->sp_fpususpend);

	error = hibernate_savectx(hpcb, pcb, low_entry_pa, low_stack_pa);
	if (error != 0) {
		/*
		 * Restore the BSP FPU state (and XCR0) later, in
		 * acpi_s4_resume_bsp_cpu() after initializecpu(): the CPU
		 * reset on resume leaves XCR0 at its x87-only reset value,
		 * so an early restore does not survive.
		 */
		return (EJUSTRETURN);
	}

	/*
	 * Save path: hibernate_savectx returned 0.
	 * Do not return to the caller or unwind this frame. The suspended
	 * thread's stack frame (including the return-address slot into
	 * acpi_EnterSleepState) must remain completely unperturbed.
	 * Execute the dump worker on the isolated scratch stack.
	 */
	if (stack_top != NULL && dump_fn != NULL)
		error = hibernate_call_on_stack(stack_top, dump_fn, dump_arg,
		    NULL);

	return (error);
}
