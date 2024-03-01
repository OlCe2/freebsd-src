/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2001 Jake Burkholder <jake@FreeBSD.org>
 * All rights reserved.
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

#include <sys/cdefs.h>
#include "opt_sched.h"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/ktr.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/runq.h>
#include <sys/sched.h>
#include <sys/smp.h>
#include <sys/sysctl.h>

#include <machine/cpu.h>

/* Uncomment this to enable logging of critical_enter/exit. */
#if 0
#define	KTR_CRITICAL	KTR_SCHED
#else
#define	KTR_CRITICAL	0
#endif

#ifdef FULL_PREEMPTION
#ifndef PREEMPTION
#error "The FULL_PREEMPTION option requires the PREEMPTION option"
#endif
#endif

/*
 * kern.sched.preemption allows user space to determine if preemption support
 * is compiled in or not.  It is not currently a boot or runtime flag that
 * can be changed.
 */
#ifdef PREEMPTION
static int kern_sched_preemption = 1;
#else
static int kern_sched_preemption = 0;
#endif
SYSCTL_INT(_kern_sched, OID_AUTO, preemption, CTLFLAG_RD,
    &kern_sched_preemption, 0, "Kernel preemption enabled");

/*
 * Support for scheduler stats exported via kern.sched.stats.  All stats may
 * be reset with kern.sched.stats.reset = 1.  Stats may be defined elsewhere
 * with SCHED_STAT_DEFINE().
 */
#ifdef SCHED_STATS
SYSCTL_NODE(_kern_sched, OID_AUTO, stats, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "switch stats");

/* Switch reasons from mi_switch(9). */
DPCPU_DEFINE(long, sched_switch_stats[SWT_COUNT]);
SCHED_STAT_DEFINE_VAR(owepreempt,
    &DPCPU_NAME(sched_switch_stats[SWT_OWEPREEMPT]), "");
SCHED_STAT_DEFINE_VAR(turnstile,
    &DPCPU_NAME(sched_switch_stats[SWT_TURNSTILE]), "");
SCHED_STAT_DEFINE_VAR(sleepq,
    &DPCPU_NAME(sched_switch_stats[SWT_SLEEPQ]), "");
SCHED_STAT_DEFINE_VAR(relinquish, 
    &DPCPU_NAME(sched_switch_stats[SWT_RELINQUISH]), "");
SCHED_STAT_DEFINE_VAR(needresched,
    &DPCPU_NAME(sched_switch_stats[SWT_NEEDRESCHED]), "");
SCHED_STAT_DEFINE_VAR(idle,
    &DPCPU_NAME(sched_switch_stats[SWT_IDLE]), "");
SCHED_STAT_DEFINE_VAR(iwait,
    &DPCPU_NAME(sched_switch_stats[SWT_IWAIT]), "");
SCHED_STAT_DEFINE_VAR(suspend,
    &DPCPU_NAME(sched_switch_stats[SWT_SUSPEND]), "");
SCHED_STAT_DEFINE_VAR(remotepreempt,
    &DPCPU_NAME(sched_switch_stats[SWT_REMOTEPREEMPT]), "");
SCHED_STAT_DEFINE_VAR(remotewakeidle,
    &DPCPU_NAME(sched_switch_stats[SWT_REMOTEWAKEIDLE]), "");
SCHED_STAT_DEFINE_VAR(bind,
    &DPCPU_NAME(sched_switch_stats[SWT_BIND]), "");

static int
sysctl_stats_reset(SYSCTL_HANDLER_ARGS)
{
	struct sysctl_oid *p;
	uintptr_t counter;
        int error;
	int val;
	int i;

        val = 0;
        error = sysctl_handle_int(oidp, &val, 0, req);
        if (error != 0 || req->newptr == NULL)
                return (error);
        if (val == 0)
                return (0);
	/*
	 * Traverse the list of children of _kern_sched_stats and reset each
	 * to 0.  Skip the reset entry.
	 */
	RB_FOREACH(p, sysctl_oid_list, oidp->oid_parent) {
		if (p == oidp || p->oid_arg1 == NULL)
			continue;
		counter = (uintptr_t)p->oid_arg1;
		CPU_FOREACH(i) {
			*(long *)(dpcpu_off[i] + counter) = 0;
		}
	}
	return (0);
}

SYSCTL_PROC(_kern_sched_stats, OID_AUTO, reset,
    CTLTYPE_INT | CTLFLAG_WR | CTLFLAG_MPSAFE, NULL, 0,
    sysctl_stats_reset, "I",
    "Reset scheduler statistics");
#endif

/************************************************************************
 * Functions that manipulate runnability from a thread perspective.	*
 ************************************************************************/
/*
 * Select the thread that will be run next.
 */

static __noinline struct thread *
choosethread_panic(struct thread *td)
{

	/*
	 * If we are in panic, only allow system threads,
	 * plus the one we are running in, to be run.
	 */
retry:
	if (((td->td_proc->p_flag & P_SYSTEM) == 0 &&
	    (td->td_flags & TDF_INPANIC) == 0)) {
		/* note that it is no longer on the run queue */
		TD_SET_CAN_RUN(td);
		td = sched_choose();
		goto retry;
	}

	TD_SET_RUNNING(td);
	return (td);
}

struct thread *
choosethread(void)
{
	struct thread *td;

	td = sched_choose();

	if (KERNEL_PANICKED())
		return (choosethread_panic(td));

	TD_SET_RUNNING(td);
	return (td);
}

/*
 * Kernel thread preemption implementation.  Critical sections mark
 * regions of code in which preemptions are not allowed.
 *
 * It might seem a good idea to inline critical_enter() but, in order
 * to prevent instructions reordering by the compiler, a __compiler_membar()
 * would have to be used here (the same as sched_pin()).  The performance
 * penalty imposed by the membar could, then, produce slower code than
 * the function call itself, for most cases.
 */
void
critical_enter_KBI(void)
{
#ifdef KTR
	struct thread *td = curthread;
#endif
	critical_enter();
	CTR4(KTR_CRITICAL, "critical_enter by thread %p (%ld, %s) to %d", td,
	    (long)td->td_proc->p_pid, td->td_name, td->td_critnest);
}

void __noinline
critical_exit_preempt(void)
{
	struct thread *td;
	int flags;

	/*
	 * If td_critnest is 0, it is possible that we are going to get
	 * preempted again before reaching the code below. This happens
	 * rarely and is harmless. However, this means td_owepreempt may
	 * now be unset.
	 */
	td = curthread;
	if (td->td_critnest != 0)
		return;
	if (kdb_active)
		return;

	/*
	 * Microoptimization: we committed to switch,
	 * disable preemption in interrupt handlers
	 * while spinning for the thread lock.
	 */
	td->td_critnest = 1;
	thread_lock(td);
	td->td_critnest--;
	flags = SW_INVOL | SW_PREEMPT;
	if (TD_IS_IDLETHREAD(td))
		flags |= SWT_IDLE;
	else
		flags |= SWT_OWEPREEMPT;
	mi_switch(flags);
}

void
critical_exit_KBI(void)
{
#ifdef KTR
	struct thread *td = curthread;
#endif
	critical_exit();
	CTR4(KTR_CRITICAL, "critical_exit by thread %p (%ld, %s) to %d", td,
	    (long)td->td_proc->p_pid, td->td_name, td->td_critnest);
}

/************************************************************************
 * SYSTEM RUN QUEUE manipulations and tests				*
 ************************************************************************/
_Static_assert(RQB_BPW == (1 << RQB_L2BPW),
    "RQB_L2BPW and RQB_BPW / 'rqb_word_t' mismatch");
_Static_assert(RQ_NQS <= 256,
    "'td_rqindex' must be turned into a bigger unsigned type");
/* A macro instead of a function to get the proper calling function's name. */
#define CHECK_IDX(idx) ({						\
	__typeof(idx) _idx = (idx);					\
	KASSERT(0 <= _idx && _idx < RQ_NQS,				\
	    ("%s: %s out of range: %d", __func__, __STRING(idx), _idx)); \
})

/*
 * Initialize a run structure.
 */
void
runq_init(struct runq *rq)
{
	int i;

	bzero(rq, sizeof(*rq));
	for (i = 0; i < RQ_NQS; i++)
		TAILQ_INIT(&rq->rq_queues[i]);
}

/*
 * Set the status bit of the queue corresponding to priority level pri,
 * indicating that it is non-empty.
 */
static __inline void
runq_setbit(struct runq *rq, int idx)
{
	struct rqbits *const rqb = &rq->rq_status;
	const int word_idx = RQB_WORD(idx);
	const rqb_word_t word_bit = RQB_BIT(idx);
	rqb_word_t v;

	CHECK_IDX(idx);
	v = rqb->rqb_bits[word_idx];
	CTR4(KTR_RUNQ, "runq_setbit: idx=%d word_idx=%d bits=%#x->%#x",
	    idx, word_idx, v, v | word_bit);
	rqb->rqb_bits[word_idx] = v | word_bit;
}

/*
 * Add the thread to the queue specified by its priority, and set the
 * corresponding status bit.
 */
void
runq_add(struct runq *rq, struct thread *td, int flags)
{

	runq_add_idx(rq, td, RQ_PRI_TO_IDX(td->td_priority.level), flags);
}

void
runq_add_idx(struct runq *rq, struct thread *td, int idx, int flags)
{
	struct rqhead *rqh;

	CHECK_IDX(idx);
	/* An assert at start of section ensures that there is no wraparound. */
	td->td_rqindex = idx;
	runq_setbit(rq, idx);
	rqh = &rq->rq_queues[idx];
	CTR4(KTR_RUNQ, "runq_add_idx: td=%p pri=%d idx=%d rqh=%p",
	    td, td->td_priority.level, idx, rqh);
	if (flags & SRQ_PREEMPTED)
		TAILQ_INSERT_HEAD(rqh, td, td_runq);
	else
		TAILQ_INSERT_TAIL(rqh, td, td_runq);
}

/*
 * Clear the status bit of the queue corresponding to priority level pri,
 * indicating that it is empty.
 */
static __inline void
runq_clrbit(struct runq *rq, int idx)
{
	struct rqbits *const rqb = &rq->rq_status;
	const int word_idx = RQB_WORD(idx);
	const rqb_word_t word_bit = RQB_BIT(idx);
	rqb_word_t v;

	CHECK_IDX(idx);
	v = rqb->rqb_bits[word_idx];
	CTR4(KTR_RUNQ, "runq_clrbit: idx=%d word_idx=%d bits=%#x->%#x",
	    idx, word_idx, v, v & ~word_bit);
	rqb->rqb_bits[word_idx] = v & ~word_bit;
}

/*
 * Remove the thread from the queue specified by its priority, and clear the
 * corresponding status bit if the queue becomes empty.
 *
 * Returns whether the corresponding queue is empty after removal.
 */
bool
runq_remove(struct runq *rq, struct thread *td)
{
	struct rqhead *rqh;
	int idx;

	KASSERT(td->td_flags & TDF_INMEM, ("runq_remove: Thread swapped out"));
	idx = td->td_rqindex;
	CHECK_IDX(idx);
	rqh = &rq->rq_queues[idx];
	CTR4(KTR_RUNQ, "runq_remove: td=%p pri=%d idx=%d rqh=%p",
	    td, td->td_priority.level, idx, rqh);
	TAILQ_REMOVE(rqh, td, td_runq);
	if (TAILQ_EMPTY(rqh)) {
		runq_clrbit(rq, idx);
		CTR0(KTR_RUNQ, "runq_remove: empty");
		return (true);
	}
	return (false);
}

static inline int
runq_findq_pred_word(struct runq *const rq, const int w_idx, rqb_word_t w,
    runq_pred_t *const pred, void *const pred_data)
{
	int idx, bit_idx;

	while (w != 0) {
		bit_idx = RQB_FFS(w);
		idx = RQB_TO_IDX(w_idx, bit_idx);
		if (pred(rq, idx, pred_data))
			return (idx);
		w &= ~(1 << bit_idx);
	}

	return (-1);
}

/*
 * Find the index of the first (i.e., having lower index) non-empty queue in the
 * passed range (bounds included) that is validated by pred().  This is done by
 * scanning the status bits, a set bit indicates a non-empty queue, and calling
 * pred() with the corresponding queue index.  pred() must return whether the
 * corresponding index is accepted.  Returns the first non-empty queue index
 * validated by pred(), else -1.
 */
int
runq_findq_pred(struct runq *const rq, const int lvl_min, const int lvl_max,
    runq_pred_t *const pred, void *const pred_data)
{
	rqb_word_t const (*const rqbb)[RQB_LEN] = &rq->rq_status.rqb_bits;
	rqb_word_t w;
	int i, last, idx;

	CHECK_IDX(lvl_min);
	CHECK_IDX(lvl_max);
	MPASS(lvl_min <= lvl_max);

	i = RQB_WORD(lvl_min);
	last = RQB_WORD(lvl_max);
	/* Clear bits for runqueues below 'lvl_min'. */
	w = (*rqbb)[i] & ~(RQB_BIT(lvl_min) - 1);
	if (i == last)
		goto last_mask;
	idx = runq_findq_pred_word(rq, i, w, pred, pred_data);
	if (idx != -1)
		goto return_idx;

	for (++i; i < last; ++i) {
		w = (*rqbb)[i];
		idx = runq_findq_pred_word(rq, i, w, pred, pred_data);
		if (idx != -1)
			goto return_idx;
	}

	MPASS(i == last);
	w = (*rqbb)[i];
last_mask:
	/* Clear bits for runqueues above 'lvl_max'. */
	w &= (RQB_BIT(lvl_max) - 1) | RQB_BIT(lvl_max);
	idx = runq_findq_pred_word(rq, i, w, pred, pred_data);
	if (idx != -1)
		goto return_idx;

	return (-1);
return_idx:
	CTR3(KTR_RUNQ, "runq_findq_pred: i=%d bits=%#x idx=%d",
	    i, (*rqbb)[i], idx);
	return (idx);
}

static bool
runq_pred_first_thread(struct runq *const rq, const int idx, void *const data)
{
	struct thread **const tdp = data;
	const struct rqhead *const rqh = &rq->rq_queues[idx];
	struct thread *const td = TAILQ_FIRST(rqh);

	MPASS2(td != NULL, "no thread on non-empty queue");
	*tdp = td;
	return (true);
}

/* Make sure it has an external definition. */
struct thread *
runq_find_thread_range(struct runq *const rq, const int lvl_min,
    const int lvl_max)
{
	struct thread *td = NULL;

	(void)runq_findq_pred(rq, lvl_min, lvl_max,
	    runq_pred_first_thread, &td);
	return (td);
}

static inline struct thread *
runq_find_thread(struct runq *const rq)
{

	return (runq_find_thread_range(rq, 0, RQ_NQS));
}

/*
 * Return true if there are runnable processes of any priority on the run
 * queue, false otherwise.  Has no side effects, does not modify the run
 * queue structure.
 */
bool
runq_check(struct runq *rq)
{
	struct thread *const td = runq_find_thread(rq);

	if (td != NULL) {
		CTR2(KTR_RUNQ, "runq_check: idx=%d, td=%p", td->td_rqindex, td);
		return (true);
	}

	CTR0(KTR_RUNQ, "runq_check: empty");
	return (false);
}

/*
 * Find the highest priority process on the run queue.
 */
struct thread *
runq_choose(struct runq *rq)
{
	struct thread *td;

	td = runq_find_thread(rq);
	if (td != NULL) {
		CTR2(KTR_RUNQ, "runq_choose: idx=%d td=%p", td->td_rqindex, td);
		return (td);
	}

	CTR0(KTR_RUNQ, "runq_choose: idlethread");
	return (NULL);
}

struct runq_pred_fuzz_data {
	int fuzz;
	struct thread *td;
};

static bool
runq_pred_fuzz(struct runq *const rq, const int idx, void *const v)
{
	struct runq_pred_fuzz_data *const data = v;
	const int fuzz = data->fuzz;
	const struct rqhead *const rqh = &rq->rq_queues[idx];
	struct thread *td;

	if (fuzz > 1) {
		/*
		 * In the first couple of entries, check if
		 * there is one for our CPU as a preference.
		 */
		struct thread *td2;
		int count = fuzz;
		int cpu = PCPU_GET(cpuid);

		td2 = td = TAILQ_FIRST(rqh);

		while (count-- != 0 && td2 != NULL) {
			if (td2->td_lastcpu == cpu) {
				td = td2;
				break;
			}
			td2 = TAILQ_NEXT(td2, td_runq);
		}
	} else
		td = TAILQ_FIRST(rqh);

	MPASS2(td != NULL, "no thread on non-empty queue");
	data->td = td;
	return (true);
}

/*
 * Find the highest priority process on the run queue.
 */
struct thread *
runq_choose_fuzz(struct runq *rq, int fuzz)
{
	struct runq_pred_fuzz_data data = {
		.fuzz = fuzz,
		.td = NULL
	};
	int idx;

	idx = runq_findq_pred(rq, 0, RQ_NQS, runq_pred_fuzz, &data);
	if (idx != -1) {
		CTR2(KTR_RUNQ, "runq_choose_fuzz: idx=%d td=%p", idx, data.td);
		return (data.td);
	}

	CTR0(KTR_RUNQ, "runq_choose_fuzz: idlethread");
	return (NULL);
}
