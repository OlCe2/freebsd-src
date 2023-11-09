/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1982, 1986, 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/file.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/refcount.h>
#include <sys/racct.h>
#include <sys/resourcevar.h>
#include <sys/rtprio.h>
#include <sys/rwlock.h>
#include <sys/sched.h>
#include <sys/sx.h>
#include <sys/syscallsubr.h>
#include <sys/sysctl.h>
#include <sys/sysent.h>
#include <sys/time.h>
#include <sys/umtxvar.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>

static MALLOC_DEFINE(M_PLIMIT, "plimit", "plimit structures");
static MALLOC_DEFINE(M_UIDINFO, "uidinfo", "uidinfo structures");
#define	UIHASH(uid)	(&uihashtbl[(uid) & uihash])
static struct rwlock uihashtbl_lock;
static LIST_HEAD(uihashhead, uidinfo) *uihashtbl;
static u_long uihash;		/* size of hash table - 1 */

static void	calcru1(struct proc *p, struct rusage_ext *ruxp,
		    struct timeval *up, struct timeval *sp);
static int	donice(struct thread *td, struct proc *chgp, int n);
static struct uidinfo *uilookup(uid_t uid);
static void	ruxagg_ext_locked(struct rusage_ext *rux, struct thread *td);

/*
 * Resource controls and accounting.
 */
#ifndef _SYS_SYSPROTO_H_
struct getpriority_args {
	int	which;
	int	who;
};
#endif
int
sys_getpriority(struct thread *td, struct getpriority_args *uap)
{

	return (kern_getpriority(td, uap->which, uap->who));
}

int
kern_getpriority(struct thread *td, int which, int who)
{
	struct proc *p;
	struct pgrp *pg;
	int error, low;

	error = 0;
	low = PRIO_MAX + 1;
	switch (which) {
	case PRIO_PROCESS:
		if (who == 0)
			low = td->td_proc->p_nice;
		else {
			p = pfind(who);
			if (p == NULL)
				break;
			if (p_cansee(td, p) == 0)
				low = p->p_nice;
			PROC_UNLOCK(p);
		}
		break;

	case PRIO_PGRP:
		sx_slock(&proctree_lock);
		if (who == 0) {
			pg = td->td_proc->p_pgrp;
			PGRP_LOCK(pg);
		} else {
			pg = pgfind(who);
			if (pg == NULL) {
				sx_sunlock(&proctree_lock);
				break;
			}
		}
		sx_sunlock(&proctree_lock);
		LIST_FOREACH(p, &pg->pg_members, p_pglist) {
			PROC_LOCK(p);
			if (p->p_state == PRS_NORMAL &&
			    p_cansee(td, p) == 0) {
				if (p->p_nice < low)
					low = p->p_nice;
			}
			PROC_UNLOCK(p);
		}
		PGRP_UNLOCK(pg);
		break;

	case PRIO_USER:
		if (who == 0)
			who = td->td_ucred->cr_uid;
		sx_slock(&allproc_lock);
		FOREACH_PROC_IN_SYSTEM(p) {
			PROC_LOCK(p);
			if (p->p_state == PRS_NORMAL &&
			    p_cansee(td, p) == 0 &&
			    p->p_ucred->cr_uid == who) {
				if (p->p_nice < low)
					low = p->p_nice;
			}
			PROC_UNLOCK(p);
		}
		sx_sunlock(&allproc_lock);
		break;

	default:
		error = EINVAL;
		break;
	}
	if (low == PRIO_MAX + 1 && error == 0)
		error = ESRCH;
	td->td_retval[0] = low;
	return (error);
}

#ifndef _SYS_SYSPROTO_H_
struct setpriority_args {
	int	which;
	int	who;
	int	prio;
};
#endif
int
sys_setpriority(struct thread *td, struct setpriority_args *uap)
{

	return (kern_setpriority(td, uap->which, uap->who, uap->prio));
}

int
kern_setpriority(struct thread *td, int which, int who, int prio)
{
	struct proc *curp, *p;
	struct pgrp *pg;
	int found = 0, error = 0;

	curp = td->td_proc;
	switch (which) {
	case PRIO_PROCESS:
		if (who == 0) {
			PROC_LOCK(curp);
			error = donice(td, curp, prio);
			PROC_UNLOCK(curp);
		} else {
			p = pfind(who);
			if (p == NULL)
				break;
			error = p_cansee(td, p);
			if (error == 0)
				error = donice(td, p, prio);
			PROC_UNLOCK(p);
		}
		found++;
		break;

	case PRIO_PGRP:
		sx_slock(&proctree_lock);
		if (who == 0) {
			pg = curp->p_pgrp;
			PGRP_LOCK(pg);
		} else {
			pg = pgfind(who);
			if (pg == NULL) {
				sx_sunlock(&proctree_lock);
				break;
			}
		}
		sx_sunlock(&proctree_lock);
		LIST_FOREACH(p, &pg->pg_members, p_pglist) {
			PROC_LOCK(p);
			if (p->p_state == PRS_NORMAL &&
			    p_cansee(td, p) == 0) {
				error = donice(td, p, prio);
				found++;
			}
			PROC_UNLOCK(p);
		}
		PGRP_UNLOCK(pg);
		break;

	case PRIO_USER:
		if (who == 0)
			who = td->td_ucred->cr_uid;
		sx_slock(&allproc_lock);
		FOREACH_PROC_IN_SYSTEM(p) {
			PROC_LOCK(p);
			if (p->p_state == PRS_NORMAL &&
			    p->p_ucred->cr_uid == who &&
			    p_cansee(td, p) == 0) {
				error = donice(td, p, prio);
				found++;
			}
			PROC_UNLOCK(p);
		}
		sx_sunlock(&allproc_lock);
		break;

	default:
		error = EINVAL;
		break;
	}
	if (found == 0 && error == 0)
		error = ESRCH;
	return (error);
}

/*
 * Set "nice" for a (whole) process.
 */
static int
donice(struct thread *td, struct proc *p, int n)
{
	int error;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	if ((error = p_cansched(td, p)))
		return (error);
	if (n > PRIO_MAX)
		n = PRIO_MAX;
	if (n < PRIO_MIN)
		n = PRIO_MIN;
	if (n < p->p_nice && priv_check(td, PRIV_SCHED_SETPRIORITY) != 0)
		return (EACCES);
	sched_nice(p, n);
	return (0);
}


/*
 * Realtime Priorities
 *
 * Includes implementations of the RT priorities specification (rtprio(2) and
 * rtprio_thread(2)) and of POSIX.1b scheduling (e.g., sched_setscheduler(),
 * sched_setparam(), sched_getscheduler() and sched_getparam()).
 */

/*
 * Check that priority bounds are sane when translating from POSIX.1b priorities
 * to RT priorities and vice-versa.
 */
#define _PRI_TRANSLATION_ASSERT(macro_from_p1b, macro_to_p1b, pri, p1b_pri) \
	_Static_assert(macro_from_p1b(p1b_pri) == pri,			\
	    __STRING(macro_from_p1b) "() must map bound "		\
	    __STRING(p1b_pri) " to " __STRING(pri));			\
	_Static_assert(macro_to_p1b(pri) == p1b_pri,			\
	    __STRING(macro_to_p1b) "() must map bound "			\
	    __STRING(pri) " to " __STRING(p1b_pri));			\

_PRI_TRANSLATION_ASSERT(p1bprio_to_rtprio, rtprio_to_p1bprio,
    RTP_PRIO_MIN, P1B_RT_PRIO_MAX);
_PRI_TRANSLATION_ASSERT(p1bprio_to_rtprio, rtprio_to_p1bprio,
    RTP_PRIO_MAX, P1B_RT_PRIO_MIN);
_PRI_TRANSLATION_ASSERT(p1bprio_to_tsprio, tsprio_to_p1bprio,
    RTP_TS_PRIO_MIN, P1B_TS_PRIO_MAX);
_PRI_TRANSLATION_ASSERT(p1bprio_to_tsprio, tsprio_to_p1bprio,
    RTP_TS_PRIO_MAX, P1B_TS_PRIO_MIN);

#undef _PRI_TRANSLATION_ASSERT

/*
 * Check that the POSIX interface's priorities comply with the standard.
 */

#define CHECK_P1B_NON_NEGATIVE(pri)					\
	_Static_assert(pri >= 0, __STRING(pri) " must be non-negative")

CHECK_P1B_NON_NEGATIVE(P1B_RT_PRIO_MIN);
CHECK_P1B_NON_NEGATIVE(P1B_RT_PRIO_MAX);
CHECK_P1B_NON_NEGATIVE(P1B_TS_PRIO_MIN);
CHECK_P1B_NON_NEGATIVE(P1B_TS_PRIO_MAX);

#undef CHECK_P1B_NON_NEGATIVE

_Static_assert(P1B_RT_PRIO_MAX - P1B_RT_PRIO_MIN + 1 >= 32,
    "POSIX mandates at least 32 priorities in the realtime range");

/*
 * Priority range for the RTP_PRIO_NORMAL type.
 *
 * These macros are not "public" because they depend on some priority internals.
 * They are going to be replaced by a stable interface.
 */
#define TS_PRIO_MIN		0	/* Highest priority */
/* Lowest priority */
#define TS_PRIO_MAX		(PRI_MAX_TIMESHARE - PRI_MIN_TIMESHARE)
#define TS_PRIO_RANGE_SIZE	(TS_PRIO_MAX - TS_PRIO_MIN + 1)
/* See also rtp_is_valid() below. */
#define TS_PRIO_IS_IN_RANGE(prio) ({					\
	__typeof(prio) _pri = (prio);					\
	TS_PRIO_MIN <= _pri && _pri <= TS_PRIO_MAX;			\
})

static int unprivileged_idprio;
SYSCTL_INT(_security_bsd, OID_AUTO, unprivileged_idprio, CTLFLAG_RW,
    &unprivileged_idprio, 0,
    "Allow non-root users to set an idle priority (deprecated)");

/*
 * Check whether a 'struct rtprio' is filled correctly.
 *
 * Returns EINVAL on invalid values, ENOTSUP for values that are recognized by
 * this implementation but whose corresponding functionality is not
 * supported/implemented, or 0 if the structure is a valid specification.
 */
int
rtp_is_valid(const struct rtprio *const rtp)
{

	switch (rtp->type) {
	case RTP_PRIO_FIFO:
	case RTP_PRIO_REALTIME:
	case RTP_PRIO_IDLE:
		if (RTP_PRIO_IS_IN_RANGE(rtp->prio))
			return (0);
		break;
	case RTP_PRIO_NORMAL:
		if (TS_PRIO_IS_IN_RANGE(rtp->prio))
			return (0);
		break;
	case RTP_PRIO_ITHD:
		return (ENOTSUP);
	}

	return (EINVAL);
}

/*
 * Indicates whether the passed thread has privilege to set the priority of any
 * thread to the passed specification.  Returns 0 if it can, EPERM if it can't
 * (or the type is invalid).
 */
int
rtp_can_set_prio(struct thread *const td, const struct rtprio *const rtp)
{

	MPASS(td == curthread);

	/*
	 * Realtime priority has to be restricted for reasons which
	 * should be obvious.  However, for idleprio processes, there is
	 * a potential for system deadlock if an idleprio process gains
	 * a lock on a resource that other processes need (and the
	 * idleprio process can't run due to a CPU-bound normal
	 * process).  Fix me!  XXX
	 *
	 * This problem is not only related to idleprio process.
	 * A user level program can obtain a file lock and hold it
	 * indefinitely.  Additionally, without idleprio processes it is
	 * still conceivable that a program with low priority will never
	 * get to run.  In short, allowing this feature might make it
	 * easier to lock a resource indefinitely, but it is not the
	 * only thing that makes it possible.
	 */

	switch (rtp->type) {
	case RTP_PRIO_FIFO:
	case RTP_PRIO_REALTIME:
		if (priv_check(td, PRIV_SCHED_RTPRIO) == 0)
			return (0);
		break;

	case RTP_PRIO_IDLE:
		if (unprivileged_idprio == 1 ||
		    priv_check(td, PRIV_SCHED_IDPRIO) == 0)
			return (0);
		break;

	case RTP_PRIO_NORMAL:
		return (0);
	}

	return (EPERM);
}

/*
 * Perform all checks preliminary to setting some priority via rtprio(2) that
 * are independent of the target thread/process.
 */
int
rtp_set_check(struct thread *const td, const struct rtprio *const rtp)
{
	int error;

	if ((error = rtp_is_valid(rtp)) != 0)
		return (error);
	/*
	 * Setting rtprio requires privilege.
	 */
	return (rtp_can_set_prio(td, rtp));
}

static inline bool
has_immutable_prio(struct proc *p)
{

	return ((p->p_flag & P_KPROC) != 0);
}

/*
 * Perform all operations that don't need locks upfront, in particular basic
 * sanity checks.  All errors (EINVAL, EPERM) are final and must be reported as
 * is.
 */
static inline int
rtprio_preamble(struct thread *td, int function, struct rtprio *rtp)
{

	MPASS(td == curthread);

	switch (function) {
	case RTP_SET:
		return (rtp_set_check(td, rtp));
	case RTP_LOOKUP:
		return (0);
	}

	return (EINVAL);
}

int
kern_rtprio(struct thread *td, int function, pid_t pid, struct rtprio *rtp)
{
	struct proc *tp;
	int error;

	error = rtprio_preamble(td, function, rtp);
	if (error != 0)
		return (error);

	if (pid == 0) {
		tp = td->td_proc;
		PROC_LOCK(tp);
	} else {
		tp = pfind(pid);
		if (tp == NULL)
			return (ESRCH);
	}

	switch (function) {
	case RTP_LOOKUP:
		if ((error = p_cansee(td, tp)) != 0)
			break;
		/*
		 * Return OUR priority if no pid specified,
		 * or if one is, report the highest priority
		 * in the process.  There isn't much more you can do as
		 * there is only room to return a single priority.
		 * Note: specifying our own pid is not the same
		 * as leaving it zero.
		 */
		if (pid == 0)
			pri_to_rtp(td, rtp);
		else {
			struct thread *tdp;
			struct rtprio rtp2;

			rtp->type = RTP_PRIO_IDLE;
			rtp->prio = RTP_PRIO_MAX;
			FOREACH_THREAD_IN_PROC(tp, tdp) {
				pri_to_rtp(tdp, &rtp2);
				if (rtp2.type < rtp->type ||
				    (rtp2.type == rtp->type &&
				    rtp2.prio < rtp->prio)) {
					rtp->type = rtp2.type;
					rtp->prio = rtp2.prio;
				}
			}
		}
		break;
	case RTP_SET:
		/*
		 * If we are setting our own priority, set just our
		 * thread but if we are doing another process,
		 * do all the threads on that process. If we
		 * specify our own pid we do the latter.
		 */
		error = (pid == 0) ? rtp_set_thread(td, rtp, td) :
		    rtp_set_proc(td, rtp, tp);
		break;
	default:
		__assert_unreachable();
	}

	PROC_UNLOCK(tp);
	return (error);
}

/*
 * Set realtime priority.
 */
#ifndef _SYS_SYSPROTO_H_
struct rtprio_args {
	int		function;
	pid_t		pid;
	struct rtprio	*rtp;
};
#endif
int
sys_rtprio(struct thread *td, struct rtprio_args *uap)
{
	struct rtprio rtp;
	int error;

	if (uap->function == RTP_SET) {
		error = copyin(uap->rtp, &rtp, sizeof(struct rtprio));
		if (error != 0)
			return (error);
	}

	error = kern_rtprio(td, uap->function, uap->pid, &rtp);
	if (error != 0)
		return (error);

	if (uap->function == RTP_LOOKUP)
		error = copyout(&rtp, uap->rtp, sizeof(struct rtprio));

	return (error);
}

int
kern_rtprio_thread(struct thread *td, int function, lwpid_t lwpid,
    struct rtprio *rtp)
{
	struct proc *tp;
	struct thread *ttd;
	int error;

	error = rtprio_preamble(td, function, rtp);
	if (error != 0)
		return (error);

	if (lwpid == 0) {
		ttd = td;
		tp = td->td_proc;
		PROC_LOCK(tp);
	} else {
		ttd = tdfind(lwpid, -1);
		if (ttd == NULL)
			return (ESRCH);
		tp = ttd->td_proc;
	}

	switch (function) {
	case RTP_LOOKUP:
		if ((error = p_cansee(td, tp)) != 0)
			break;

		pri_to_rtp(ttd, rtp);
		break;
	case RTP_SET:
		error = rtp_set_thread(td, rtp, ttd);
		break;
	default:
		/* Impossible case because of rtprio_preamble() above. */
		__assert_unreachable();
	}

	PROC_UNLOCK(tp);
	return (error);
}

/*
 * Set realtime priority for LWP.
 */
#ifndef _SYS_SYSPROTO_H_
struct rtprio_thread_args {
	int		function;
	lwpid_t		lwpid;
	struct rtprio	*rtp;
};
#endif
int
sys_rtprio_thread(struct thread *td, struct rtprio_thread_args *uap)
{
	struct rtprio rtp;
	int error;

	if (uap->function == RTP_SET) {
		error = copyin(uap->rtp, &rtp, sizeof(struct rtprio));
		if (error != 0)
			return (error);
	}

	error = kern_rtprio_thread(td, uap->function, uap->lwpid, &rtp);
	if (error != 0)
		return (error);

	if (uap->function == RTP_LOOKUP)
		error = copyout(&rtp, uap->rtp, sizeof(struct rtprio));

	return (error);
}

static void
_rtp_set(const struct rtprio *rtp, struct thread *ttd)
{
	u_char newpri, oldclass, oldpri;

	KASSERT(rtp_is_valid(rtp) == 0,
	    ("%s: Called with an invalid 'struct rtprio'.", __func__));

	switch (RTP_PRIO_BASE(rtp->type)) {
	case RTP_PRIO_REALTIME:
		newpri = PRI_MIN_REALTIME + rtp->prio;
		break;
	case RTP_PRIO_NORMAL:
		newpri = PRI_MIN_TIMESHARE + rtp->prio;
		break;
	case RTP_PRIO_IDLE:
		newpri = PRI_MIN_IDLE + rtp->prio;
		break;
	default:
		/* rtp_is_valid() MUST be called prior to this function. */
		__assert_unreachable();
	}

	thread_lock(ttd);
	oldclass = ttd->td_pri_class;
	sched_class(ttd, rtp->type);	/* XXX fix */
	oldpri = ttd->td_user_pri;
	sched_user_prio(ttd, newpri);
	if (ttd->td_user_pri != oldpri && (oldclass != RTP_PRIO_NORMAL ||
	    ttd->td_pri_class != RTP_PRIO_NORMAL))
		sched_prio(ttd, ttd->td_user_pri);
	if (TD_ON_UPILOCK(ttd) && oldpri != newpri) {
		critical_enter();
		thread_unlock(ttd);
		umtx_pi_adjust(ttd, oldpri);
		critical_exit();
	} else
		thread_unlock(ttd);
}

/*
 * Set a thread's priority according to a RT Priority specification.
 *
 * Callers must ensure that 'rtp' is a valid 'struct rtprio' (via rtp_is_valid()
 * or rtp_set_check()) and, if relevant, that 'curthread' has appropriate
 * privileges to set the required priority (via rtp_can_set_prio() or
 * rtp_set_check()).
 *
 * This function checks that 'curthread' is allowed to set the priority of the
 * the target thread as per security policies.
 *
 * 'td' must be 'curthread'.  Can fail with EPERM if 'curthread' is not allowed
 * to change the priority of 'target_td' or if 'target_td' cannot have its
 * priority changed, else returns 0.
 */
int
rtp_set_thread(struct thread *td, const struct rtprio *rtp,
    struct thread *target_td)
{
	struct proc *tp = target_td->td_proc;

	MPASS(td == curthread);
	PROC_LOCK_ASSERT(tp, MA_OWNED);

	if (p_cansched(td, tp) != 0 || has_immutable_prio(tp))
		return (EPERM);

	_rtp_set(rtp, target_td);

	return (0);
}

/*
 * Set a process' threads' priority according to a RT Priority specification.
 *
 * Similar to rtp_set_thread() but operates on all threads of a process.  See
 * that function's documentation.
 *
 * 'td' must be 'curthread'.  Can fail with EPERM if 'curthread' is not allowed
 * to change the priority of 'proc' or if 'proc' cannot have its priority
 * changed, else returns 0.
 */
int
rtp_set_proc(struct thread *td, const struct rtprio *rtp, struct proc *p)
{
	struct thread *target_td;

	MPASS(td == curthread);
	PROC_LOCK_ASSERT(p, MA_OWNED);

	if (p_cansched(td, p) != 0 || has_immutable_prio(p))
		return (EPERM);

	FOREACH_THREAD_IN_PROC(p, target_td) {
		_rtp_set(rtp, target_td);
	}

	return (0);
}

void
pri_to_rtp(struct thread *td, struct rtprio *rtp)
{

	thread_lock(td);
	switch (PRI_BASE(td->td_pri_class)) {
	case PRI_REALTIME:
		rtp->prio = td->td_base_user_pri - PRI_MIN_REALTIME;
		break;
	case PRI_TIMESHARE:
		rtp->prio = td->td_base_user_pri - PRI_MIN_TIMESHARE;
		break;
	case PRI_IDLE:
		rtp->prio = td->td_base_user_pri - PRI_MIN_IDLE;
		break;
	default:
		break;
	}
	rtp->type = td->td_pri_class;
	thread_unlock(td);
}

#if defined(COMPAT_43)
#ifndef _SYS_SYSPROTO_H_
struct osetrlimit_args {
	u_int	which;
	struct	orlimit *rlp;
};
#endif
int
osetrlimit(struct thread *td, struct osetrlimit_args *uap)
{
	struct orlimit olim;
	struct rlimit lim;
	int error;

	if ((error = copyin(uap->rlp, &olim, sizeof(struct orlimit))))
		return (error);
	lim.rlim_cur = olim.rlim_cur;
	lim.rlim_max = olim.rlim_max;
	error = kern_setrlimit(td, uap->which, &lim);
	return (error);
}

#ifndef _SYS_SYSPROTO_H_
struct ogetrlimit_args {
	u_int	which;
	struct	orlimit *rlp;
};
#endif
int
ogetrlimit(struct thread *td, struct ogetrlimit_args *uap)
{
	struct orlimit olim;
	struct rlimit rl;
	int error;

	if (uap->which >= RLIM_NLIMITS)
		return (EINVAL);
	lim_rlimit(td, uap->which, &rl);

	/*
	 * XXX would be more correct to convert only RLIM_INFINITY to the
	 * old RLIM_INFINITY and fail with EOVERFLOW for other larger
	 * values.  Most 64->32 and 32->16 conversions, including not
	 * unimportant ones of uids are even more broken than what we
	 * do here (they blindly truncate).  We don't do this correctly
	 * here since we have little experience with EOVERFLOW yet.
	 * Elsewhere, getuid() can't fail...
	 */
	olim.rlim_cur = rl.rlim_cur > 0x7fffffff ? 0x7fffffff : rl.rlim_cur;
	olim.rlim_max = rl.rlim_max > 0x7fffffff ? 0x7fffffff : rl.rlim_max;
	error = copyout(&olim, uap->rlp, sizeof(olim));
	return (error);
}
#endif /* COMPAT_43 */

#ifndef _SYS_SYSPROTO_H_
struct setrlimit_args {
	u_int	which;
	struct	rlimit *rlp;
};
#endif
int
sys_setrlimit(struct thread *td, struct setrlimit_args *uap)
{
	struct rlimit alim;
	int error;

	if ((error = copyin(uap->rlp, &alim, sizeof(struct rlimit))))
		return (error);
	error = kern_setrlimit(td, uap->which, &alim);
	return (error);
}

static void
lim_cb(void *arg)
{
	struct rlimit rlim;
	struct thread *td;
	struct proc *p;

	p = arg;
	PROC_LOCK_ASSERT(p, MA_OWNED);
	/*
	 * Check if the process exceeds its cpu resource allocation.  If
	 * it reaches the max, arrange to kill the process in ast().
	 */
	if (p->p_cpulimit == RLIM_INFINITY)
		return;
	PROC_STATLOCK(p);
	FOREACH_THREAD_IN_PROC(p, td) {
		ruxagg(p, td);
	}
	PROC_STATUNLOCK(p);
	if (p->p_rux.rux_runtime > p->p_cpulimit * cpu_tickrate()) {
		lim_rlimit_proc(p, RLIMIT_CPU, &rlim);
		if (p->p_rux.rux_runtime >= rlim.rlim_max * cpu_tickrate()) {
			killproc(p, "exceeded maximum CPU limit");
		} else {
			if (p->p_cpulimit < rlim.rlim_max)
				p->p_cpulimit += 5;
			kern_psignal(p, SIGXCPU);
		}
	}
	if ((p->p_flag & P_WEXIT) == 0)
		callout_reset_sbt(&p->p_limco, SBT_1S, 0,
		    lim_cb, p, C_PREL(1));
}

int
kern_setrlimit(struct thread *td, u_int which, struct rlimit *limp)
{

	return (kern_proc_setrlimit(td, td->td_proc, which, limp));
}

int
kern_proc_setrlimit(struct thread *td, struct proc *p, u_int which,
    struct rlimit *limp)
{
	struct plimit *newlim, *oldlim, *oldlim_td;
	struct rlimit *alimp;
	struct rlimit oldssiz;
	int error;

	if (which >= RLIM_NLIMITS)
		return (EINVAL);

	/*
	 * Preserve historical bugs by treating negative limits as unsigned.
	 */
	if (limp->rlim_cur < 0)
		limp->rlim_cur = RLIM_INFINITY;
	if (limp->rlim_max < 0)
		limp->rlim_max = RLIM_INFINITY;

	oldssiz.rlim_cur = 0;
	newlim = lim_alloc();
	PROC_LOCK(p);
	oldlim = p->p_limit;
	alimp = &oldlim->pl_rlimit[which];
	if (limp->rlim_cur > alimp->rlim_max ||
	    limp->rlim_max > alimp->rlim_max)
		if ((error = priv_check(td, PRIV_PROC_SETRLIMIT))) {
			PROC_UNLOCK(p);
			lim_free(newlim);
			return (error);
		}
	if (limp->rlim_cur > limp->rlim_max)
		limp->rlim_cur = limp->rlim_max;
	lim_copy(newlim, oldlim);
	alimp = &newlim->pl_rlimit[which];

	switch (which) {
	case RLIMIT_CPU:
		if (limp->rlim_cur != RLIM_INFINITY &&
		    p->p_cpulimit == RLIM_INFINITY)
			callout_reset_sbt(&p->p_limco, SBT_1S, 0,
			    lim_cb, p, C_PREL(1));
		p->p_cpulimit = limp->rlim_cur;
		break;
	case RLIMIT_DATA:
		if (limp->rlim_cur > maxdsiz)
			limp->rlim_cur = maxdsiz;
		if (limp->rlim_max > maxdsiz)
			limp->rlim_max = maxdsiz;
		break;

	case RLIMIT_STACK:
		if (limp->rlim_cur > maxssiz)
			limp->rlim_cur = maxssiz;
		if (limp->rlim_max > maxssiz)
			limp->rlim_max = maxssiz;
		oldssiz = *alimp;
		if (p->p_sysent->sv_fixlimit != NULL)
			p->p_sysent->sv_fixlimit(&oldssiz,
			    RLIMIT_STACK);
		break;

	case RLIMIT_NOFILE:
		if (limp->rlim_cur > maxfilesperproc)
			limp->rlim_cur = maxfilesperproc;
		if (limp->rlim_max > maxfilesperproc)
			limp->rlim_max = maxfilesperproc;
		break;

	case RLIMIT_NPROC:
		if (limp->rlim_cur > maxprocperuid)
			limp->rlim_cur = maxprocperuid;
		if (limp->rlim_max > maxprocperuid)
			limp->rlim_max = maxprocperuid;
		if (limp->rlim_cur < 1)
			limp->rlim_cur = 1;
		if (limp->rlim_max < 1)
			limp->rlim_max = 1;
		break;
	}
	if (p->p_sysent->sv_fixlimit != NULL)
		p->p_sysent->sv_fixlimit(limp, which);
	*alimp = *limp;
	p->p_limit = newlim;
	PROC_UPDATE_COW(p);
	oldlim_td = NULL;
	if (td == curthread && PROC_COW_CHANGECOUNT(td, p) == 1) {
		oldlim_td = lim_cowsync();
		thread_cow_synced(td);
	}
	PROC_UNLOCK(p);
	if (oldlim_td != NULL) {
		MPASS(oldlim_td == oldlim);
		lim_freen(oldlim, 2);
	} else {
		lim_free(oldlim);
	}

	if (which == RLIMIT_STACK &&
	    /*
	     * Skip calls from exec_new_vmspace(), done when stack is
	     * not mapped yet.
	     */
	    (td != curthread || (p->p_flag & P_INEXEC) == 0)) {
		/*
		 * Stack is allocated to the max at exec time with only
		 * "rlim_cur" bytes accessible.  If stack limit is going
		 * up make more accessible, if going down make inaccessible.
		 */
		if (limp->rlim_cur != oldssiz.rlim_cur) {
			vm_offset_t addr;
			vm_size_t size;
			vm_prot_t prot;

			if (limp->rlim_cur > oldssiz.rlim_cur) {
				prot = p->p_sysent->sv_stackprot;
				size = limp->rlim_cur - oldssiz.rlim_cur;
				addr = round_page(p->p_vmspace->vm_stacktop) -
				    limp->rlim_cur;
			} else {
				prot = VM_PROT_NONE;
				size = oldssiz.rlim_cur - limp->rlim_cur;
				addr = round_page(p->p_vmspace->vm_stacktop) -
				    oldssiz.rlim_cur;
			}
			addr = trunc_page(addr);
			size = round_page(size);
			(void)vm_map_protect(&p->p_vmspace->vm_map,
			    addr, addr + size, prot, 0,
			    VM_MAP_PROTECT_SET_PROT);
		}
	}

	return (0);
}

#ifndef _SYS_SYSPROTO_H_
struct getrlimit_args {
	u_int	which;
	struct	rlimit *rlp;
};
#endif
/* ARGSUSED */
int
sys_getrlimit(struct thread *td, struct getrlimit_args *uap)
{
	struct rlimit rlim;
	int error;

	if (uap->which >= RLIM_NLIMITS)
		return (EINVAL);
	lim_rlimit(td, uap->which, &rlim);
	error = copyout(&rlim, uap->rlp, sizeof(struct rlimit));
	return (error);
}

/*
 * Transform the running time and tick information for children of proc p
 * into user and system time usage.
 */
void
calccru(struct proc *p, struct timeval *up, struct timeval *sp)
{

	PROC_LOCK_ASSERT(p, MA_OWNED);
	calcru1(p, &p->p_crux, up, sp);
}

/*
 * Transform the running time and tick information in proc p into user
 * and system time usage.  If appropriate, include the current time slice
 * on this CPU.
 */
void
calcru(struct proc *p, struct timeval *up, struct timeval *sp)
{
	struct thread *td;
	uint64_t runtime, u;

	PROC_LOCK_ASSERT(p, MA_OWNED);
	PROC_STATLOCK_ASSERT(p, MA_OWNED);
	/*
	 * If we are getting stats for the current process, then add in the
	 * stats that this thread has accumulated in its current time slice.
	 * We reset the thread and CPU state as if we had performed a context
	 * switch right here.
	 */
	td = curthread;
	if (td->td_proc == p) {
		u = cpu_ticks();
		runtime = u - PCPU_GET(switchtime);
		td->td_runtime += runtime;
		td->td_incruntime += runtime;
		PCPU_SET(switchtime, u);
	}
	/* Make sure the per-thread stats are current. */
	FOREACH_THREAD_IN_PROC(p, td) {
		if (td->td_incruntime == 0)
			continue;
		ruxagg(p, td);
	}
	calcru1(p, &p->p_rux, up, sp);
}

/* Collect resource usage for a single thread. */
void
rufetchtd(struct thread *td, struct rusage *ru)
{
	struct proc *p;
	uint64_t runtime, u;

	p = td->td_proc;
	PROC_STATLOCK_ASSERT(p, MA_OWNED);
	THREAD_LOCK_ASSERT(td, MA_OWNED);
	/*
	 * If we are getting stats for the current thread, then add in the
	 * stats that this thread has accumulated in its current time slice.
	 * We reset the thread and CPU state as if we had performed a context
	 * switch right here.
	 */
	if (td == curthread) {
		u = cpu_ticks();
		runtime = u - PCPU_GET(switchtime);
		td->td_runtime += runtime;
		td->td_incruntime += runtime;
		PCPU_SET(switchtime, u);
	}
	ruxagg_locked(p, td);
	*ru = td->td_ru;
	calcru1(p, &td->td_rux, &ru->ru_utime, &ru->ru_stime);
}

static uint64_t
mul64_by_fraction(uint64_t a, uint64_t b, uint64_t c)
{
	uint64_t acc, bh, bl;
	int i, s, sa, sb;

	/*
	 * Calculate (a * b) / c accurately enough without overflowing.  c
	 * must be nonzero, and its top bit must be 0.  a or b must be
	 * <= c, and the implementation is tuned for b <= c.
	 *
	 * The comments about times are for use in calcru1() with units of
	 * microseconds for 'a' and stathz ticks at 128 Hz for b and c.
	 *
	 * Let n be the number of top zero bits in c.  Each iteration
	 * either returns, or reduces b by right shifting it by at least n.
	 * The number of iterations is at most 1 + 64 / n, and the error is
	 * at most the number of iterations.
	 *
	 * It is very unusual to need even 2 iterations.  Previous
	 * implementations overflowed essentially by returning early in the
	 * first iteration, with n = 38 giving overflow at 105+ hours and
	 * n = 32 giving overlow at at 388+ days despite a more careful
	 * calculation.  388 days is a reasonable uptime, and the calculation
	 * needs to work for the uptime times the number of CPUs since 'a'
	 * is per-process.
	 */
	if (a >= (uint64_t)1 << 63)
		return (0);		/* Unsupported arg -- can't happen. */
	acc = 0;
	for (i = 0; i < 128; i++) {
		sa = flsll(a);
		sb = flsll(b);
		if (sa + sb <= 64)
			/* Up to 105 hours on first iteration. */
			return (acc + (a * b) / c);
		if (a >= c) {
			/*
			 * This reduction is based on a = q * c + r, with the
			 * remainder r < c.  'a' may be large to start, and
			 * moving bits from b into 'a' at the end of the loop
			 * sets the top bit of 'a', so the reduction makes
			 * significant progress.
			 */
			acc += (a / c) * b;
			a %= c;
			sa = flsll(a);
			if (sa + sb <= 64)
				/* Up to 388 days on first iteration. */
				return (acc + (a * b) / c);
		}

		/*
		 * This step writes a * b as a * ((bh << s) + bl) =
		 * a * (bh << s) + a * bl = (a << s) * bh + a * bl.  The 2
		 * additive terms are handled separately.  Splitting in
		 * this way is linear except for rounding errors.
		 *
		 * s = 64 - sa is the maximum such that a << s fits in 64
		 * bits.  Since a < c and c has at least 1 zero top bit,
		 * sa < 64 and s > 0.  Thus this step makes progress by
		 * reducing b (it increases 'a', but taking remainders on
		 * the next iteration completes the reduction).
		 *
		 * Finally, the choice for s is just what is needed to keep
		 * a * bl from overflowing, so we don't need complications
		 * like a recursive call mul64_by_fraction(a, bl, c) to
		 * handle the second additive term.
		 */
		s = 64 - sa;
		bh = b >> s;
		bl = b - (bh << s);
		acc += (a * bl) / c;
		a <<= s;
		b = bh;
	}
	return (0);		/* Algorithm failure -- can't happen. */
}

static void
calcru1(struct proc *p, struct rusage_ext *ruxp, struct timeval *up,
    struct timeval *sp)
{
	/* {user, system, interrupt, total} {ticks, usec}: */
	uint64_t ut, uu, st, su, it, tt, tu;

	ut = ruxp->rux_uticks;
	st = ruxp->rux_sticks;
	it = ruxp->rux_iticks;
	tt = ut + st + it;
	if (tt == 0) {
		/* Avoid divide by zero */
		st = 1;
		tt = 1;
	}
	tu = cputick2usec(ruxp->rux_runtime);
	if ((int64_t)tu < 0) {
		/* XXX: this should be an assert /phk */
		printf("calcru: negative runtime of %jd usec for pid %d (%s)\n",
		    (intmax_t)tu, p->p_pid, p->p_comm);
		tu = ruxp->rux_tu;
	}

	/* Subdivide tu.  Avoid overflow in the multiplications. */
	if (__predict_true(tu <= ((uint64_t)1 << 38) && tt <= (1 << 26))) {
		/* Up to 76 hours when stathz is 128. */
		uu = (tu * ut) / tt;
		su = (tu * st) / tt;
	} else {
		uu = mul64_by_fraction(tu, ut, tt);
		su = mul64_by_fraction(tu, st, tt);
	}

	if (tu >= ruxp->rux_tu) {
		/*
		 * The normal case, time increased.
		 * Enforce monotonicity of bucketed numbers.
		 */
		if (uu < ruxp->rux_uu)
			uu = ruxp->rux_uu;
		if (su < ruxp->rux_su)
			su = ruxp->rux_su;
	} else if (tu + 3 > ruxp->rux_tu || 101 * tu > 100 * ruxp->rux_tu) {
		/*
		 * When we calibrate the cputicker, it is not uncommon to
		 * see the presumably fixed frequency increase slightly over
		 * time as a result of thermal stabilization and NTP
		 * discipline (of the reference clock).  We therefore ignore
		 * a bit of backwards slop because we  expect to catch up
		 * shortly.  We use a 3 microsecond limit to catch low
		 * counts and a 1% limit for high counts.
		 */
		uu = ruxp->rux_uu;
		su = ruxp->rux_su;
		tu = ruxp->rux_tu;
	} else if (vm_guest == VM_GUEST_NO) {  /* tu < ruxp->rux_tu */
		/*
		 * What happened here was likely that a laptop, which ran at
		 * a reduced clock frequency at boot, kicked into high gear.
		 * The wisdom of spamming this message in that case is
		 * dubious, but it might also be indicative of something
		 * serious, so lets keep it and hope laptops can be made
		 * more truthful about their CPU speed via ACPI.
		 */
		printf("calcru: runtime went backwards from %ju usec "
		    "to %ju usec for pid %d (%s)\n",
		    (uintmax_t)ruxp->rux_tu, (uintmax_t)tu,
		    p->p_pid, p->p_comm);
	}

	ruxp->rux_uu = uu;
	ruxp->rux_su = su;
	ruxp->rux_tu = tu;

	up->tv_sec = uu / 1000000;
	up->tv_usec = uu % 1000000;
	sp->tv_sec = su / 1000000;
	sp->tv_usec = su % 1000000;
}

#ifndef _SYS_SYSPROTO_H_
struct getrusage_args {
	int	who;
	struct	rusage *rusage;
};
#endif
int
sys_getrusage(struct thread *td, struct getrusage_args *uap)
{
	struct rusage ru;
	int error;

	error = kern_getrusage(td, uap->who, &ru);
	if (error == 0)
		error = copyout(&ru, uap->rusage, sizeof(struct rusage));
	return (error);
}

int
kern_getrusage(struct thread *td, int who, struct rusage *rup)
{
	struct proc *p;
	int error;

	error = 0;
	p = td->td_proc;
	PROC_LOCK(p);
	switch (who) {
	case RUSAGE_SELF:
		rufetchcalc(p, rup, &rup->ru_utime,
		    &rup->ru_stime);
		break;

	case RUSAGE_CHILDREN:
		*rup = p->p_stats->p_cru;
		calccru(p, &rup->ru_utime, &rup->ru_stime);
		break;

	case RUSAGE_THREAD:
		PROC_STATLOCK(p);
		thread_lock(td);
		rufetchtd(td, rup);
		thread_unlock(td);
		PROC_STATUNLOCK(p);
		break;

	default:
		error = EINVAL;
	}
	PROC_UNLOCK(p);
	return (error);
}

void
rucollect(struct rusage *ru, struct rusage *ru2)
{
	long *ip, *ip2;
	int i;

	if (ru->ru_maxrss < ru2->ru_maxrss)
		ru->ru_maxrss = ru2->ru_maxrss;
	ip = &ru->ru_first;
	ip2 = &ru2->ru_first;
	for (i = &ru->ru_last - &ru->ru_first; i >= 0; i--)
		*ip++ += *ip2++;
}

void
ruadd(struct rusage *ru, struct rusage_ext *rux, struct rusage *ru2,
    struct rusage_ext *rux2)
{

	rux->rux_runtime += rux2->rux_runtime;
	rux->rux_uticks += rux2->rux_uticks;
	rux->rux_sticks += rux2->rux_sticks;
	rux->rux_iticks += rux2->rux_iticks;
	rux->rux_uu += rux2->rux_uu;
	rux->rux_su += rux2->rux_su;
	rux->rux_tu += rux2->rux_tu;
	rucollect(ru, ru2);
}

/*
 * Aggregate tick counts into the proc's rusage_ext.
 */
static void
ruxagg_ext_locked(struct rusage_ext *rux, struct thread *td)
{

	rux->rux_runtime += td->td_incruntime;
	rux->rux_uticks += td->td_uticks;
	rux->rux_sticks += td->td_sticks;
	rux->rux_iticks += td->td_iticks;
}

void
ruxagg_locked(struct proc *p, struct thread *td)
{
	THREAD_LOCK_ASSERT(td, MA_OWNED);
	PROC_STATLOCK_ASSERT(td->td_proc, MA_OWNED);

	ruxagg_ext_locked(&p->p_rux, td);
	ruxagg_ext_locked(&td->td_rux, td);
	td->td_incruntime = 0;
	td->td_uticks = 0;
	td->td_iticks = 0;
	td->td_sticks = 0;
}

void
ruxagg(struct proc *p, struct thread *td)
{

	thread_lock(td);
	ruxagg_locked(p, td);
	thread_unlock(td);
}

/*
 * Update the rusage_ext structure and fetch a valid aggregate rusage
 * for proc p if storage for one is supplied.
 */
void
rufetch(struct proc *p, struct rusage *ru)
{
	struct thread *td;

	PROC_STATLOCK_ASSERT(p, MA_OWNED);

	*ru = p->p_ru;
	if (p->p_numthreads > 0)  {
		FOREACH_THREAD_IN_PROC(p, td) {
			ruxagg(p, td);
			rucollect(ru, &td->td_ru);
		}
	}
}

/*
 * Atomically perform a rufetch and a calcru together.
 * Consumers, can safely assume the calcru is executed only once
 * rufetch is completed.
 */
void
rufetchcalc(struct proc *p, struct rusage *ru, struct timeval *up,
    struct timeval *sp)
{

	PROC_STATLOCK(p);
	rufetch(p, ru);
	calcru(p, up, sp);
	PROC_STATUNLOCK(p);
}

/*
 * Allocate a new resource limits structure and initialize its
 * reference count and mutex pointer.
 */
struct plimit *
lim_alloc(void)
{
	struct plimit *limp;

	limp = malloc(sizeof(struct plimit), M_PLIMIT, M_WAITOK);
	refcount_init(&limp->pl_refcnt, 1);
	return (limp);
}

struct plimit *
lim_hold(struct plimit *limp)
{

	refcount_acquire(&limp->pl_refcnt);
	return (limp);
}

struct plimit *
lim_cowsync(void)
{
	struct thread *td;
	struct proc *p;
	struct plimit *oldlimit;

	td = curthread;
	p = td->td_proc;
	PROC_LOCK_ASSERT(p, MA_OWNED);

	if (td->td_limit == p->p_limit)
		return (NULL);

	oldlimit = td->td_limit;
	td->td_limit = lim_hold(p->p_limit);

	return (oldlimit);
}

void
lim_fork(struct proc *p1, struct proc *p2)
{

	PROC_LOCK_ASSERT(p1, MA_OWNED);
	PROC_LOCK_ASSERT(p2, MA_OWNED);

	p2->p_limit = lim_hold(p1->p_limit);
	callout_init_mtx(&p2->p_limco, &p2->p_mtx, 0);
	if (p1->p_cpulimit != RLIM_INFINITY)
		callout_reset_sbt(&p2->p_limco, SBT_1S, 0,
		    lim_cb, p2, C_PREL(1));
}

void
lim_free(struct plimit *limp)
{

	if (refcount_release(&limp->pl_refcnt))
		free((void *)limp, M_PLIMIT);
}

void
lim_freen(struct plimit *limp, int n)
{

	if (refcount_releasen(&limp->pl_refcnt, n))
		free((void *)limp, M_PLIMIT);
}

void
limbatch_add(struct limbatch *lb, struct thread *td)
{
	struct plimit *limp;

	MPASS(td->td_limit != NULL);
	limp = td->td_limit;

	if (lb->limp != limp) {
		if (lb->count != 0) {
			lim_freen(lb->limp, lb->count);
			lb->count = 0;
		}
		lb->limp = limp;
	}

	lb->count++;
}

void
limbatch_final(struct limbatch *lb)
{

	MPASS(lb->count != 0);
	lim_freen(lb->limp, lb->count);
}

/*
 * Make a copy of the plimit structure.
 * We share these structures copy-on-write after fork.
 */
void
lim_copy(struct plimit *dst, struct plimit *src)
{

	KASSERT(dst->pl_refcnt <= 1, ("lim_copy to shared limit"));
	bcopy(src->pl_rlimit, dst->pl_rlimit, sizeof(src->pl_rlimit));
}

/*
 * Return the hard limit for a particular system resource.  The
 * which parameter specifies the index into the rlimit array.
 */
rlim_t
lim_max(struct thread *td, int which)
{
	struct rlimit rl;

	lim_rlimit(td, which, &rl);
	return (rl.rlim_max);
}

rlim_t
lim_max_proc(struct proc *p, int which)
{
	struct rlimit rl;

	lim_rlimit_proc(p, which, &rl);
	return (rl.rlim_max);
}

/*
 * Return the current (soft) limit for a particular system resource.
 * The which parameter which specifies the index into the rlimit array
 */
rlim_t
(lim_cur)(struct thread *td, int which)
{
	struct rlimit rl;

	lim_rlimit(td, which, &rl);
	return (rl.rlim_cur);
}

rlim_t
lim_cur_proc(struct proc *p, int which)
{
	struct rlimit rl;

	lim_rlimit_proc(p, which, &rl);
	return (rl.rlim_cur);
}

/*
 * Return a copy of the entire rlimit structure for the system limit
 * specified by 'which' in the rlimit structure pointed to by 'rlp'.
 */
void
lim_rlimit(struct thread *td, int which, struct rlimit *rlp)
{
	struct proc *p = td->td_proc;

	MPASS(td == curthread);
	KASSERT(which >= 0 && which < RLIM_NLIMITS,
	    ("request for invalid resource limit"));
	*rlp = td->td_limit->pl_rlimit[which];
	if (p->p_sysent->sv_fixlimit != NULL)
		p->p_sysent->sv_fixlimit(rlp, which);
}

void
lim_rlimit_proc(struct proc *p, int which, struct rlimit *rlp)
{

	PROC_LOCK_ASSERT(p, MA_OWNED);
	KASSERT(which >= 0 && which < RLIM_NLIMITS,
	    ("request for invalid resource limit"));
	*rlp = p->p_limit->pl_rlimit[which];
	if (p->p_sysent->sv_fixlimit != NULL)
		p->p_sysent->sv_fixlimit(rlp, which);
}

void
uihashinit(void)
{

	uihashtbl = hashinit(maxproc / 16, M_UIDINFO, &uihash);
	rw_init(&uihashtbl_lock, "uidinfo hash");
}

/*
 * Look up a uidinfo struct for the parameter uid.
 * uihashtbl_lock must be locked.
 * Increase refcount on uidinfo struct returned.
 */
static struct uidinfo *
uilookup(uid_t uid)
{
	struct uihashhead *uipp;
	struct uidinfo *uip;

	rw_assert(&uihashtbl_lock, RA_LOCKED);
	uipp = UIHASH(uid);
	LIST_FOREACH(uip, uipp, ui_hash)
		if (uip->ui_uid == uid) {
			uihold(uip);
			break;
		}

	return (uip);
}

/*
 * Find or allocate a struct uidinfo for a particular uid.
 * Returns with uidinfo struct referenced.
 * uifree() should be called on a struct uidinfo when released.
 */
struct uidinfo *
uifind(uid_t uid)
{
	struct uidinfo *new_uip, *uip;
	struct ucred *cred;

	cred = curthread->td_ucred;
	if (cred->cr_uidinfo->ui_uid == uid) {
		uip = cred->cr_uidinfo;
		uihold(uip);
		return (uip);
	} else if (cred->cr_ruidinfo->ui_uid == uid) {
		uip = cred->cr_ruidinfo;
		uihold(uip);
		return (uip);
	}

	rw_rlock(&uihashtbl_lock);
	uip = uilookup(uid);
	rw_runlock(&uihashtbl_lock);
	if (uip != NULL)
		return (uip);

	new_uip = malloc(sizeof(*new_uip), M_UIDINFO, M_WAITOK | M_ZERO);
	racct_create(&new_uip->ui_racct);
	refcount_init(&new_uip->ui_ref, 1);
	new_uip->ui_uid = uid;

	rw_wlock(&uihashtbl_lock);
	/*
	 * There's a chance someone created our uidinfo while we
	 * were in malloc and not holding the lock, so we have to
	 * make sure we don't insert a duplicate uidinfo.
	 */
	if ((uip = uilookup(uid)) == NULL) {
		LIST_INSERT_HEAD(UIHASH(uid), new_uip, ui_hash);
		rw_wunlock(&uihashtbl_lock);
		uip = new_uip;
	} else {
		rw_wunlock(&uihashtbl_lock);
		racct_destroy(&new_uip->ui_racct);
		free(new_uip, M_UIDINFO);
	}
	return (uip);
}

/*
 * Place another refcount on a uidinfo struct.
 */
void
uihold(struct uidinfo *uip)
{

	refcount_acquire(&uip->ui_ref);
}

/*-
 * Since uidinfo structs have a long lifetime, we use an
 * opportunistic refcounting scheme to avoid locking the lookup hash
 * for each release.
 *
 * If the refcount hits 0, we need to free the structure,
 * which means we need to lock the hash.
 * Optimal case:
 *   After locking the struct and lowering the refcount, if we find
 *   that we don't need to free, simply unlock and return.
 * Suboptimal case:
 *   If refcount lowering results in need to free, bump the count
 *   back up, lose the lock and acquire the locks in the proper
 *   order to try again.
 */
void
uifree(struct uidinfo *uip)
{

	if (refcount_release_if_not_last(&uip->ui_ref))
		return;

	rw_wlock(&uihashtbl_lock);
	if (refcount_release(&uip->ui_ref) == 0) {
		rw_wunlock(&uihashtbl_lock);
		return;
	}

	racct_destroy(&uip->ui_racct);
	LIST_REMOVE(uip, ui_hash);
	rw_wunlock(&uihashtbl_lock);

	if (uip->ui_sbsize != 0)
		printf("freeing uidinfo: uid = %d, sbsize = %ld\n",
		    uip->ui_uid, uip->ui_sbsize);
	if (uip->ui_proccnt != 0)
		printf("freeing uidinfo: uid = %d, proccnt = %ld\n",
		    uip->ui_uid, uip->ui_proccnt);
	if (uip->ui_vmsize != 0)
		printf("freeing uidinfo: uid = %d, swapuse = %lld\n",
		    uip->ui_uid, (unsigned long long)uip->ui_vmsize);
	free(uip, M_UIDINFO);
}

#ifdef RACCT
void
ui_racct_foreach(void (*callback)(struct racct *racct,
    void *arg2, void *arg3), void (*pre)(void), void (*post)(void),
    void *arg2, void *arg3)
{
	struct uidinfo *uip;
	struct uihashhead *uih;

	rw_rlock(&uihashtbl_lock);
	if (pre != NULL)
		(pre)();
	for (uih = &uihashtbl[uihash]; uih >= uihashtbl; uih--) {
		LIST_FOREACH(uip, uih, ui_hash) {
			(callback)(uip->ui_racct, arg2, arg3);
		}
	}
	if (post != NULL)
		(post)();
	rw_runlock(&uihashtbl_lock);
}
#endif

static inline int
chglimit(struct uidinfo *uip, long *limit, int diff, rlim_t max, const char *name)
{
	long new;

	/* Don't allow them to exceed max, but allow subtraction. */
	new = atomic_fetchadd_long(limit, (long)diff) + diff;
	if (diff > 0 && max != 0) {
		if (new < 0 || new > max) {
			atomic_subtract_long(limit, (long)diff);
			return (0);
		}
	} else if (new < 0)
		printf("negative %s for uid = %d\n", name, uip->ui_uid);
	return (1);
}

/*
 * Change the count associated with number of processes
 * a given user is using.  When 'max' is 0, don't enforce a limit
 */
int
chgproccnt(struct uidinfo *uip, int diff, rlim_t max)
{

	return (chglimit(uip, &uip->ui_proccnt, diff, max, "proccnt"));
}

/*
 * Change the total socket buffer size a user has used.
 */
int
chgsbsize(struct uidinfo *uip, u_int *hiwat, u_int to, rlim_t max)
{
	int diff, rv;

	diff = to - *hiwat;
	if (diff > 0 && max == 0) {
		rv = 0;
	} else {
		rv = chglimit(uip, &uip->ui_sbsize, diff, max, "sbsize");
		if (rv != 0)
			*hiwat = to;
	}
	return (rv);
}

/*
 * Change the count associated with number of pseudo-terminals
 * a given user is using.  When 'max' is 0, don't enforce a limit
 */
int
chgptscnt(struct uidinfo *uip, int diff, rlim_t max)
{

	return (chglimit(uip, &uip->ui_ptscnt, diff, max, "ptscnt"));
}

int
chgkqcnt(struct uidinfo *uip, int diff, rlim_t max)
{

	return (chglimit(uip, &uip->ui_kqcnt, diff, max, "kqcnt"));
}

int
chgumtxcnt(struct uidinfo *uip, int diff, rlim_t max)
{

	return (chglimit(uip, &uip->ui_umtxcnt, diff, max, "umtxcnt"));
}
