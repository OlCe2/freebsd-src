/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 The FreeBSD Foundation
 *
 * This software was developed by Olivier Certner <olce@FreeBSD.org> at Kumacom
 * SARL under sponsorship from the FreeBSD Foundation.
 */

#include <machine/asmacros.h>
#include <machine/specialreg.h>
#include "assym.inc"

	.text

/*
 * int hibernate_savectx(struct hibernate_pcb *hpcb, struct pcb *pcb,
 *     uint64_t low_entry, uint64_t low_stack)
 *
 * Saves CPU context using savectx(), fills the hibernate_pcb with register
 * state and low transition entry/stack pointers, and returns twice:
 *   - returns 0 on initial save (when savectx returns 1)
 *   - returns EJUSTRETURN on resume (when resumectx returns 0)
 */
ENTRY(hibernate_savectx)
	/*
	 * %rdi = struct hibernate_pcb *hpcb
	 * %rsi = struct pcb *pcb
	 * %rdx = uint64_t low_entry (physical address < 4 GiB)
	 * %rcx = uint64_t low_stack (physical address < 4 GiB)
	 */
	pushq	%rdi
	pushq	%rdx
	pushq	%rcx
	movq	%rsi, %rdi
	call	savectx
	popq	%rcx
	popq	%rdx
	popq	%rdi

	testl	%eax, %eax
	jz	.Lhibernate_resumed

	/* Save path: savectx returned 1 */
	movq	%cr0, %rax
	movq	%rax, HPCB_CR0(%rdi)
	movq	%cr3, %rax
	movq	%rax, HPCB_CR3(%rdi)
	movq	%cr4, %rax
	movq	%rax, HPCB_CR4(%rdi)

	movq	%rdx, HPCB_RIP(%rdi)
	movq	%rcx, HPCB_RSP(%rdi)
	movq	%rsi, HPCB_R12(%rdi)

	xorl	%eax, %eax		/* Return 0 to dumpsys_hibernate_savectx */
	ret

.Lhibernate_resumed:
	/* Resume path: resumectx() restored context and returned here with %eax == 0 */
	movl	$EJUSTRETURN, %eax
	ret
END(hibernate_savectx)

/*
 * Low-memory resume trampoline (< 4 GiB).
 *
 * Position-independent code copied to low page (< 4 GiB).
 * Entered from the loader under physical 1:1 identity paging.
 */
ENTRY(hibernate_resume_tramp)
	/* 1. Reload kernel page-table root (safe: low page is 1:1 mapped in kernel_pmap) */
	movq	hibernate_tramp_cr3(%rip), %rax
	movq	%rax, %cr3

	/* 2. Jump to canonical high kernel virtual address */
	movabsq	$hibernate_restore_kernel, %rax
	jmp	*%rax

	ALIGN_DATA
	.globl	hibernate_tramp_cr3
hibernate_tramp_cr3:
	.quad	0
END(hibernate_resume_tramp)

	.globl	hibernate_resume_tramp_size
hibernate_resume_tramp_size:
	.long	. - hibernate_resume_tramp

/*
 * High kernel restore entry.
 *
 * Running in canonical high virtual memory on kernel page tables.
 * %r12 holds struct pcb *.
 */
ENTRY(hibernate_restore_kernel)
	/* Reload kernel GDTR and segment registers before calling resumectx */
	leaq	PCB_GDT(%r12), %rdi
	call	lgdt

	movq	%r12, %rdi
	call	resumectx
	/* NOTREACHED - resumectx returns directly to .Lhibernate_resumed */
END(hibernate_restore_kernel)

/*
 * int hibernate_call_on_stack(void *stack_top, int (*fn)(void *, void *),
 *     void *arg1, void *arg2)
 *
 * Switches %rsp to stack_top, enforces 16-byte alignment, invokes fn(arg1, arg2),
 * and restores original %rsp.
 */
ENTRY(hibernate_call_on_stack)
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r12

	movq	%rsp, %r12		/* Preserve thread stack %rsp in %r12 */
	movq	%rdi, %rsp		/* Switch %rsp to scratch stack_top */
	andq	$~0xf, %rsp		/* Enforce 16-byte stack alignment */

	movq	%rsi, %rax		/* Save fn pointer in %rax */
	movq	%rdx, %rdi		/* arg1 -> %rdi */
	movq	%rcx, %rsi		/* arg2 -> %rsi */
	call	*%rax			/* Call worker function */

	movq	%r12, %rsp		/* Restore thread stack %rsp */
	popq	%r12
	popq	%rbp
	ret
END(hibernate_call_on_stack)

	.section .note.GNU-stack,"",%progbits
