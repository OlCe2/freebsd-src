/*
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * This software was developed by Olivier Certner <olce@FreeBSD.org> at Kumacom
 * SARL under sponsorship from the FreeBSD Foundation.
 */

#include <sys/types.h>
#include <sys/proc.h>

#include <machine/hibernate.h>
#include <machine/pcb.h>


/*
 * FIXME
 *
 * The code below must be relocated below 4G (assuming the loader will map the
 * first 4G 1:1), as well as the stack.  Approach similar to ACPI wakeup?
 */

/*
 * XXX
 *
 * Code below currently requires susppcbs[] to have been allocated in advance,
 * which is currently always the case as ACPI does the allocation and hibernate
 * cannot be triggered without ACPI.
 */
extern struct susppcb **susppcbs;

/*
 * Save the current context in the hibernate PCB.
 *
 * Returns twice, the second time with EJUSTRETURN (on restore).
 */
int
dumpsys_hibernate_savectx(struct hibernate_pcb *hpcb)
{
	/*
	 * FIXME
	 *
	 * Use of 'register ... asm' is explicitly not supported to ensure
	 * passing parameters in and out to assembly code with non-standard
	 * calling conventions.
	 *
	 * The plan is to instead keep this function in C but have the part
	 * filling 'hpcb' in a separate assembly entry point, which will set RIP
	 * to some of its own block calling some resumectx() variant itself, and
	 * the CPU will come back here from the savectx() as usual (for the
	 * savectx()/resumectx() protocol).
	 */
	register struct pcb *pcb asm ("r12") = &susppcbs[0]->sp_pcb;

	if (savectx(pcb)) {
		/* Also save FPU state. */
		fpususpend(susppcbs[0]->sp_fpususpend);
		/* Fill the hibernate PCB. */
		hpcb->cr0 = pcb->pcb_cr0;
		hpcb->cr3 = pcb->pcb_cr3;
		hpcb->cr4 = pcb->pcb_cr4;
		/*
		 * Compensate for savectx() saving its %rsp value after the
		 * return address has been pushed.
		 */
		hpcb->rsp = pcb->pcb_rsp + 8;
		hpcb->rip = pcb->pcb_rip;
		hpcb->r12 = (uint64_t)pcb;

		return (0);
	}
	/*
	 * Restore all state, as the loader restores only what's in 'struct
	 * hibernate_pcb' (see above).
	 *
	 * This call must absolutely follow savectx() and works because 'pcb' is
	 * forced into %r12 and the loader restores that register.
	 */
	resumectx_return(pcb);
	fpuresume(susppcbs[0]->sp_fpususpend);

	/*
	 * FIXME
	 *
	 * Restore the rest of the machine state here!
	 */

	return (EJUSTRETURN);
}
