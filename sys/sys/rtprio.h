/*-
 * SPDX-License-Identifier: BSD-4-Clause
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

#ifndef _SYS_RTPRIO_H_
#define _SYS_RTPRIO_H_

#include <sys/priority.h>

/*
 * Realtime (and other types) priority specifications.
 *
 * To use with rtprio(2) and rtprio_thread(2).
 */

/* priority types.  Start at 1 to catch uninitialized fields. */

#define RTP_PRIO_ITHD		PRI_ITHD	/* Interrupt thread. */
#define RTP_PRIO_REALTIME	PRI_REALTIME	/* real time process */
#define RTP_PRIO_NORMAL		PRI_TIMESHARE	/* time sharing process */
#define RTP_PRIO_IDLE		PRI_IDLE	/* idle process */

/* RTP_PRIO_FIFO is POSIX.1B SCHED_FIFO.
 */

#define RTP_PRIO_FIFO_BIT	PRI_FIFO_BIT
#define RTP_PRIO_FIFO		PRI_FIFO
#define RTP_PRIO_BASE(P)	PRI_BASE(P)
#define RTP_PRIO_IS_REALTIME(P) PRI_IS_REALTIME(P)
#define RTP_PRIO_NEED_RR(P)	PRI_NEED_RR(P)

/* priority range */
#define RTP_PRIO_MIN		0	/* Highest priority */
#define RTP_PRIO_MAX		31	/* Lowest priority */


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

struct thread;
int	rtp_can_set_prio(struct thread *, const struct rtprio *);
int	rtp_to_pri(struct rtprio *, struct thread *);
void	pri_to_rtp(struct thread *, struct rtprio *);

#else /* !_KERNEL */

__BEGIN_DECLS
int	rtprio(int, pid_t, struct rtprio *);
int	rtprio_thread(int, lwpid_t, struct rtprio *);
__END_DECLS

#endif /* _KERNEL */
#endif /* !_SYS_RTPRIO_H_ */
