/*-
 * SPDX-License-Identifier: (BSD-4-Clause AND BSD-2-Clause)
 *
 * Copyright (c) 1994, Henrik Vestergaard Draboel
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by Henrik Vestergaard Draboel.
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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

/*-
 * Copyright (c) 2023 The FreeBSD Foundation
 *
 * This software was developed by Olivier Certner <olce.freebsd@certner.fr>
 * at Kumacom SAS under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the distribution.
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


/*
 * Realtime (and other types) priority specifications.
 *
 * To use with rtprio(2) and rtprio_thread(2).
 */

#ifndef _SYS_RTPRIO_H_
#define _SYS_RTPRIO_H_

#include <sys/_types.h>

#ifndef _LWPID_T_DECLARED
typedef	__lwpid_t	lwpid_t;
#define	_LWPID_T_DECLARED
#endif

#ifndef _PID_T_DECLARED
typedef	__pid_t		pid_t;
#define	_PID_T_DECLARED
#endif

/*
 * Priority types/classes ("Scheduling Policies" in POSIX.1b parlance; see the
 * latter in 'sys/sys/sched.h' and mapping in 'sys/kern/ksched.c').
 *
 * 0 isn't defined to help catch uninitialized fields.  Defined priority types
 * are ordered from highest to lowest priority (except that RTP_PRIO_FIFO and
 * RTP_PRIO_REALTIME are mostly equivalent, see below).  By contrast, their
 * numerical values are not since previously attributed ones are preserved for
 * ABI compatibility.
 *
 * Priority type RTP_PRIO_ITHD below is observable (RTP_LOOKUP; with appropriate
 * privileges) but not settable.
 *
 * Priority levels in RTP_PRIO_FIFO are the same as those of RTP_PRIO_REALTIME.
 * The only difference is that a RTP_PRIO_FIFO thread that is running is never
 * descheduled to run a thread with equivalent priority, whereas this happens
 * for RTP_PRIO_REALTIME threads (at quantum exhaustion).
 *
 * The priority type RTP_PRIO_FIFO is equivalent to the POSIX.1b scheduling
 * policy SCHED_FIFO, and RTP_PRIO_REALTIME to SCHED_RR, but their priority
 * levels' numerical values differ (see conversion macros below).
 *
 * Bit 3 in the priority type was previously considered as the FIFO "bit", which
 * has no meaning and effect unless used in conjunction with RTP_PRIO_REALTIME.
 * Its corresponding macro (RTP_PRIO_FIFO_BIT) was removed.  For clarity, please
 * only use the symbolic constants below and equality operators (or a straight
 * 'switch' statement).
 */

/* Kernel processes with highest priority (interrupt threads). */
#define RTP_PRIO_ITHD		1
#define RTP_PRIO_FIFO		10	/* (RTP_PRIO_REALTIME | (1 << 3)) */
#define RTP_PRIO_REALTIME	2	/* Realtime process. */
#define RTP_PRIO_NORMAL		3	/* Time sharing process. */
#define RTP_PRIO_IDLE		4	/* Idle process. */

/*
 * The obsolete function-like macros RTP_PRIO_BASE(), RTP_PRIO_IS_REALTIME() and
 * RTP_PRIO_NEED_RR() were all removed.  Just use comparisons or a switch
 * statement with the above-defined constants instead.
 */

/*
 * Priority range for the RTP_PRIO_FIFO, RTP_PRIO_REALTIME and RTP_PRIO_IDLE
 * types.
 */
#define RTP_PRIO_MIN		0	/* Highest priority */
#define RTP_PRIO_MAX		31	/* Lowest priority */
#define RTP_PRIO_RANGE_SIZE	(RTP_PRIO_MAX - RTP_PRIO_MIN + 1)
#define RTP_PRIO_IS_IN_RANGE(prio) ({					\
	__typeof(prio) _pri = (prio);					\
	RTP_PRIO_MIN <= _pri && _pri <= RTP_PRIO_MAX;			\
})


/*
 * rtprio() syscall functions
 */
#define RTP_LOOKUP		0
#define RTP_SET			1

struct rtprio {
	u_short type;		/* Scheduling type/class. */
	u_short prio;
};

/*
 * Conversions between Realtime Priorities (used for rtprio(2)), for which lower
 * numerical values mean higher priorities, and POSIX.1b priorities (used by
 * POSIX Scheduling Priorities, see 'sys/kern/ksched.c' and
 * 'lib/libthr/thread/thr_kern.c', and for userspace mutexes, see
 * 'sys/kern/kern_umtx.c'), for which lower numerical values mean lower
 * priorities.
 */

/*
 * The range [RTP_PRIO_MIN; RTP_PRIO_MAX] of POSIX Realtime Priorities (which
 * applies both for the realtime and idle classes) is mapped into [0;
 * RTP_PRIO_MAX - RTP_PRIO_MIN] but in the "opposite direction" to satisfy the
 * ordering constraint mentioned in the previous paragraph (e.g., the bounds are
 * reversed, so RTP_PRIO_MAX is mapped to 0 and RTP_PRIO_MIN to RTP_PRIO_MAX -
 * RTP_PRIO_MIN).
 */
#define P1B_RT_PRIO_MIN		0
#define P1B_RT_PRIO_MAX		(RTP_PRIO_MAX - RTP_PRIO_MIN)

#define P1B_PRIO_IS_IN_RT_RANGE(prio) ({				\
    __typeof__(prio) _pri = (prio);					\
    P1B_RT_PRIO_MIN <= _pri && _pri <= P1B_RT_PRIO_MAX;			\
})

#define rtprio_to_p1bprio(P)	(RTP_PRIO_MAX - (P) + P1B_RT_PRIO_MIN)
#define p1bprio_to_rtprio(P)	(P1B_RT_PRIO_MAX - (P) + RTP_PRIO_MIN)


#ifdef _KERNEL

/*
 * The range [0; PRI_MAX_TIMESHARE - PRI_MIN_TIMESHARE] of the timesharing class
 * is mapped into [0; PRI_MAX_TIMESHARE - PRI_MIN_TIMESHARE] for SCHED_OTHER but
 * in the "opposite direction" to satisfy the above-mentioned ordering
 * constraint (e.g., the bounds are reversed, so PRI_MAX_TIMESHARE is mapped to
 * 0 and PRI_MIN_TIMESHARE to PRI_MAX_TIMESHARE - PRI_MIN_TIMESHARE).
 */
#define RTP_TS_PRIO_MIN		0
#define RTP_TS_PRIO_MAX		(PRI_MAX_TIMESHARE - PRI_MIN_TIMESHARE)
#define P1B_TS_PRIO_MIN		0
#define P1B_TS_PRIO_MAX		(PRI_MAX_TIMESHARE - PRI_MIN_TIMESHARE)

#define P1B_PRIO_IS_IN_TS_RANGE(prio) ({				\
    __typeof__(prio) _pri = (prio);					\
    P1B_TS_PRIO_MIN <= _pri && _pri <= P1B_TS_PRIO_MAX;			\
})

#define tsprio_to_p1bprio(P)	(RTP_TS_PRIO_MAX - (P) + P1B_TS_PRIO_MIN)
#define p1bprio_to_tsprio(P)	(P1B_TS_PRIO_MAX - (P) + RTP_TS_PRIO_MIN)

int	rtp_is_valid(const struct rtprio *);
struct thread;
int	rtp_can_set_prio(struct thread *, const struct rtprio *);
int	rtp_set_check(struct thread *, const struct rtprio *);
struct sched_attr;
int	posix_sched_to_rtp(const struct sched_attr *, struct rtprio *);
int	rtp_to_posix_sched(const struct rtprio *, struct sched_attr *);
int	rtp_set_thread(struct thread *_curthread, const struct rtprio *,
	    struct thread *_target_td);
int	rtp_set_proc(struct thread *_curthread, const struct rtprio *,
	    struct proc *_target_proc);
int	rtp_get_thread(struct thread *_curthread, struct thread *_target_td,
	    struct rtprio *);
int	rtp_get_proc(struct thread *_curthread, struct proc *_target_proc,
	    struct rtprio *);

#else /* !_KERNEL */

__BEGIN_DECLS
int	rtprio(int, pid_t, struct rtprio *);
int	rtprio_thread(int, lwpid_t, struct rtprio *);
__END_DECLS

#endif /* _KERNEL */
#endif /* !_SYS_RTPRIO_H_ */
