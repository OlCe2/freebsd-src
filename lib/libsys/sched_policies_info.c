/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 The FreeBSD Foundation
 *
 * This software was developed by Olivier Certner <olce@FreeBSD.org>
 * at Kumacom SARL under sponsorship from the FreeBSD Foundation.
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

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/sched.h>

#include <stdatomic.h>
#include <stdbool.h>


int __sys_sched_get_priority_min(int policy);
int __sys_sched_get_priority_max(int policy);

struct sched_policy_info {
	/* SCHED_NONE: Slot empty. */
	_Atomic u_int	guard;
#define SCHEDPI_GUARD_POLICY(g)		((g) & 0xFFFF)
#define SCHEDPI_GUARD_FLAG_FROM_IDX(i)	((u_int)(i) << 16)
#define SCHEDPI_GUARDF_UPDATING		SCHEDPI_GUARD_FLAG_FROM_IDX(1)
#define SCHEDPI_GUARDF_NEGATIVE		SCHEDPI_GUARD_FLAG_FROM_IDX(2)

	union {
		struct {
			uint16_t	pri_min;
			uint16_t	pri_max;
		};
		int	err;	/* If flag SCHEDPI_GUARDF_NEGATIVE is set. */
	};
};

/*
 * Reserve room for caching the boundaries of up to the first 8 used scheduling
 * policies.  8 was chosen so that it is greater than the number of scheduling
 * policies currently defined by a margin and to ensure the resulting array fits
 * in a single cache-line of 64 bytes.  As this variable is zero-filled, all
 * 'guard' fields are initialized to SCHED_NONE (with no flags), indicating free
 * slots.
 *
 * Invariants: All free slots always form a contiguous group at the end of the
 * array.  The policy in a slot's guard can only change once from SCHED_NONE to
 * some defined policy.  Once a slot has been filled (i.e., its policy is not
 * SCHED_NONE and SCHEDPI_GUARDF_UPDATING is unset), it is never changed again.
 * For each policy value, at all times the guard of at most one slot can contain
 * it.
 */
static struct sched_policy_info policies_info[8] __aligned(CACHE_LINE_SIZE);

static int
pri_int_to_uint16(int pri, uint16_t *sprip)
{
	if (pri == -1)
		return (-1);
	else {
		uint16_t spri = pri;

		/* Wraparound.  Policy is invalid. */
		if (spri != pri) {
			errno = EINVAL;
			return (-1);
		}

		*sprip = spri;
		return (0);
	}
}

/*
 * Returns 0 if slot filled, -1 if filled negatively and -2 on a race.
 *
 * On returning -1, 'errno' is also set.
 */
static int
try_fill_slot(struct sched_policy_info *slot, u_int expected_guard,
    uint16_t wanted_pol)
{
	/*
	 * Try to grab the slot.  It is very important that it
	 * is marked with the policy whose information we'll be
	 * retrieving, so that concurrent callers notice that
	 * there is now a slot for it (even if not yet filled)
	 * and can avoid wasting another slot for the same
	 * policy and info.  Weak CAS is enough since no code
	 * sets a guard to SCHED_NONE after initialization of
	 * 'policies_info'.
	 */
	if (!atomic_compare_exchange_weak_explicit(
	    &slot->guard, &expected_guard,
	    wanted_pol | SCHEDPI_GUARDF_UPDATING,
	    memory_order_acq_rel, memory_order_acquire))
		return (-2);

	/* We grabbed it, so let's try to fill it. */
	if (pri_int_to_uint16(__sys_sched_get_priority_min(wanted_pol),
	    &slot->pri_min) == -1 ||
	    pri_int_to_uint16(__sys_sched_get_priority_max(wanted_pol),
	    &slot->pri_max) == -1) {
		/* Policy must be invalid.  Remember errno. */
		slot->err = errno;
		/* Mark the slot as negatively filled. */
		atomic_store_explicit(&slot->guard,
		    wanted_pol | SCHEDPI_GUARDF_NEGATIVE, memory_order_release);
		return (-1);
	}

	/* Everything retrieved correctly! */
	atomic_store_explicit(&slot->guard, wanted_pol, memory_order_release);
	return (0);
}

/*
 * Returns 0 on success, -1 on error, -2 on cache miss.
 *
 * When returning -1, the reason is stored in errno. 'info' is filled only if
 * 0 is returned.
 *
 * Caches negative results (-1 returned).  POSIX states that the policies are
 * "symbolic constants", hence macros that applications can test with the
 * pre-processor to compile in or out each of them depending on the host's
 * support, so a well-written application normally doesn't have to test for
 * existing policies at runtime.  We expect the case of frequent runtime tests
 * to be rare.  So why implement negative entries anyway?  Simply because,
 * provided no eviction policy is put in place, such as evicting negative
 * entries with positive ones, it barely adds net complexity, since it actually
 * simplifies maintaining the invariant that any policy is never assigned more
 * than a single slot in the cache.
 */
static int
get_cached_sched_policy_info(int pol, struct sched_policy_info const** info)
{
	uint16_t s_pol = pol;

	if (s_pol != pol) {
		/* Wraparound.  Policy is invalid. */
		errno = EINVAL;
		return (-1);
	}

	for (int i = 0; i < nitems(policies_info); i++) {
		struct sched_policy_info *slot;
		u_int guard;
		uint16_t guard_pol;
loop_body:
		slot = &policies_info[i];
		guard = atomic_load_explicit(&slot->guard,
		    memory_order_acquire);
		guard_pol = SCHEDPI_GUARD_POLICY(guard);

		if (guard_pol == s_pol) {
			if (__predict_false(guard & SCHEDPI_GUARDF_UPDATING))
				/*
				 * Someone still updating it.  Spinning would be
				 * bad, since it could last for the system calls
				 * duration.  Give up and have the caller
				 * perform the call(s) itself.
				 */
				return (-2);
			if (__predict_false(guard & SCHEDPI_GUARDF_NEGATIVE)) {
				/* Return the same error as previously. */
				errno = slot->err;
				return (-1);
			}
		        /* Found and usable.  Proceed. */
		} else if (guard_pol == SCHED_NONE) {
			/* Found a free slot, implying policy was not found. */
			int ret;

			ret = try_fill_slot(slot, SCHED_NONE, s_pol);
			switch (ret) {
			case -2:
				/*
				 * Beaten by someone else, which might be trying
				 * to fill the slot with the same policy, so
				 * test it again.
				 */
				goto loop_body;
			case -1:
				/* Negative entry. 'errno' already set. */
				return (-1);
			case 0:
				/* Slot filled.  Proceed. */
				break;
			default:
			    __unreachable();
			}
		} else
			continue;

		/* Found! */
		*info = slot;
		return (0);
	}

	/* Cache full.  Give up. */
	return (-2);
}

int sched_get_priority_min(int policy)
{
	struct sched_policy_info const* slot;
	int error;

	error = get_cached_sched_policy_info(policy, &slot);
	switch (error) {
	case 0:
		return (slot->pri_min);
	case -1:
		return (-1);
	case -2:
		return (__sys_sched_get_priority_min(policy));
	}

	__unreachable();
}

int sched_get_priority_max(int policy)
{
	struct sched_policy_info const* slot;
	int error;

	error = get_cached_sched_policy_info(policy, &slot);
	switch (error) {
	case 0:
		return (slot->pri_max);
	case -1:
		return (-1);
	case -2:
		return (__sys_sched_get_priority_max(policy));
	}

	__unreachable();
}
