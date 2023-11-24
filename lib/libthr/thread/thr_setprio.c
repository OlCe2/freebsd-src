/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1995 John Birrell <jb@cimlogic.com.au>.
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
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY JOHN BIRRELL AND CONTRIBUTORS ``AS IS'' AND
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

#include "namespace.h"
#include <pthread.h>
#include "un-namespace.h"

#include "thr_private.h"

__weak_reference(_pthread_setprio, pthread_setprio);

int
_pthread_setprio(pthread_t pthread, int prio)
{
	struct pthread *curthread = _get_curthread();
	struct sched_attr_v1 *attr;
	int error;

	if (pthread == curthread)
		THR_LOCK(curthread);
	/* Arg 0 is to include dead threads. */
	else if ((error = _thr_find_thread(curthread, pthread, 0)))
		return (error);

	attr = &pthread->attr.sched_attr;
	if (attr->priority == prio)
		error = 0;
	else if (attr->policy == SCHED_OTHER) {
		attr->priority = prio;
		error = 0;
	} else {
		struct sched_attr_v1 cand_attr = *attr;

		cand_attr.priority = prio;
		if (cand_attr.priority != prio) {
			/* Wraparound. */
			error = EINVAL;
			goto unlock_exit;
		}

		error = thr_sched_set(THR_SCHED_FLAGS_FROM_VERSION(1),
		    TID(pthread), &cand_attr, sizeof(cand_attr));
		if (error == 0)
			*attr = cand_attr;
		else
			error = errno;
	}

unlock_exit:
	THR_THREAD_UNLOCK(curthread, pthread);
	return (error);
}
