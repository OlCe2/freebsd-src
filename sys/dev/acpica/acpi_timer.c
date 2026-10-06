/*-
 * Copyright (c) 2000, 2001 Michael Smith
 * Copyright (c) 2000 BSDi
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
#include "opt_acpi.h"
#include <sys/param.h>
#include <sys/bus.h>
#include <sys/eventhandler.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/sysctl.h>
#include <sys/timetc.h>
#include <sys/power.h>

#include <machine/bus.h>
#include <machine/resource.h>
#include <sys/rman.h>

#include <contrib/dev/acpica/include/acpi.h>
#include <contrib/dev/acpica/include/accommon.h>

#include <dev/acpica/acpivar.h>
#include <dev/pci/pcivar.h>

/*
 * A timecounter based on the free-running ACPI timer.
 *
 * Based on the i386-only mp_clock.c by <phk@FreeBSD.ORG>.
 */

/* Hooks for the ACPI CA debugging infrastructure */
#define _COMPONENT	ACPI_TIMER
ACPI_MODULE_NAME("TIMER")

static device_t			acpi_timer_dev;
static struct resource		*acpi_timer_reg;
static bus_space_handle_t	acpi_timer_bsh;
static bus_space_tag_t		acpi_timer_bst;
static eventhandler_tag		acpi_timer_eh;

static u_int	acpi_timer_frequency = 14318182 / 4;

/* Knob to disable acpi_timer device */
bool acpi_timer_disabled = false;

static void	acpi_timer_identify(driver_t *driver, device_t parent);
static int	acpi_timer_probe(device_t dev);
static int	acpi_timer_attach(device_t dev);
static void	acpi_timer_resume_handler(struct timecounter *,
		    enum power_stype);
static void	acpi_timer_suspend_handler(struct timecounter *,
		    enum power_stype);
static u_int	acpi_timer_get_timecount(struct timecounter *tc);
static u_int	acpi_timer_get_timecount_safe(struct timecounter *tc);
static int	acpi_timer_sysctl_freq(SYSCTL_HANDLER_ARGS);

static device_method_t acpi_timer_methods[] = {
    DEVMETHOD(device_identify,	acpi_timer_identify),
    DEVMETHOD(device_probe,	acpi_timer_probe),
    DEVMETHOD(device_attach,	acpi_timer_attach),

    DEVMETHOD_END
};

static driver_t acpi_timer_driver = {
    "acpi_timer",
    acpi_timer_methods,
    0,
};

DRIVER_MODULE(acpi_timer, acpi, acpi_timer_driver, 0, 0);
MODULE_DEPEND(acpi_timer, acpi, 1, 1, 1);

static struct timecounter acpi_timer_timecounter = {
	acpi_timer_get_timecount_safe,	/* get_timecount function */
	0,				/* no poll_pps */
	0,				/* no default counter_mask */
	0,				/* no default frequency */
	"ACPI",				/* name */
	-1				/* quality (chosen later) */
};

static __inline uint32_t
acpi_timer_read(void)
{

    return (bus_space_read_4(acpi_timer_bst, acpi_timer_bsh, 0));
}

/*
 * Locate the ACPI timer using the FADT, set up and allocate the I/O resources
 * we will be using.
 */
static void
acpi_timer_identify(driver_t *driver, device_t parent)
{
    device_t dev;
    rman_res_t rlen, rstart;
    int rid, rtype;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);

    if (acpi_disabled("timer") || (acpi_quirks & ACPI_Q_TIMER) ||
	acpi_timer_dev || acpi_timer_disabled ||
	AcpiGbl_FADT.PmTimerLength == 0)
	return_VOID;

    if ((dev = BUS_ADD_CHILD(parent, 2, "acpi_timer", 0)) == NULL) {
	device_printf(parent, "could not add acpi_timer0\n");
	return_VOID;
    }
    acpi_timer_dev = dev;

    switch (AcpiGbl_FADT.XPmTimerBlock.SpaceId) {
    case ACPI_ADR_SPACE_SYSTEM_MEMORY:
	rtype = SYS_RES_MEMORY;
	break;
    case ACPI_ADR_SPACE_SYSTEM_IO:
	rtype = SYS_RES_IOPORT;
	break;
    default:
	return_VOID;
    }
    rid = 0;
    rlen = AcpiGbl_FADT.PmTimerLength;
    rstart = AcpiGbl_FADT.XPmTimerBlock.Address;
    if (bus_set_resource(dev, rtype, rid, rstart, rlen))
	device_printf(dev, "couldn't set resource (%s 0x%jx+0x%jx)\n",
	    (rtype == SYS_RES_IOPORT) ? "port" : "mem", rstart, rlen);
    return_VOID;
}

static int
acpi_timer_probe(device_t dev)
{
    int rid, rtype;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);

    if (dev != acpi_timer_dev)
	return (ENXIO);

    switch (AcpiGbl_FADT.XPmTimerBlock.SpaceId) {
    case ACPI_ADR_SPACE_SYSTEM_MEMORY:
	rtype = SYS_RES_MEMORY;
	break;
    case ACPI_ADR_SPACE_SYSTEM_IO:
	rtype = SYS_RES_IOPORT;
	break;
    default:
	return (ENXIO);
    }
    rid = 0;
    acpi_timer_reg = bus_alloc_resource_any(dev, rtype, &rid, RF_ACTIVE);
    if (acpi_timer_reg == NULL) {
	device_printf(dev, "couldn't allocate resource (%s 0x%lx)\n",
	    (rtype == SYS_RES_IOPORT) ? "port" : "mem",
	    (u_long)AcpiGbl_FADT.XPmTimerBlock.Address);
	return (ENXIO);
    }
    acpi_timer_bsh = rman_get_bushandle(acpi_timer_reg);
    acpi_timer_bst = rman_get_bustag(acpi_timer_reg);
    if (AcpiGbl_FADT.Flags & ACPI_FADT_32BIT_TIMER)
	acpi_timer_timecounter.tc_counter_mask = 0xffffffff;
    else
	acpi_timer_timecounter.tc_counter_mask = 0x00ffffff;
    acpi_timer_timecounter.tc_frequency = acpi_timer_frequency;
    acpi_timer_timecounter.tc_flags = TC_FLAGS_SUSPEND_SAFE;

    acpi_timer_timecounter.tc_name = "ACPI-fast";
    acpi_timer_timecounter.tc_get_timecount = acpi_timer_get_timecount;
    acpi_timer_timecounter.tc_quality = 900;
    tc_init(&acpi_timer_timecounter);

    device_set_descf(dev, "%d-bit timer at %u.%06uMHz",
	(AcpiGbl_FADT.Flags & ACPI_FADT_32BIT_TIMER) != 0 ? 32 : 24,
	acpi_timer_frequency / 1000000, acpi_timer_frequency % 1000000);

    /* Release the resource, we'll allocate it again during attach. */
    bus_release_resource(dev, rtype, rid, acpi_timer_reg);
    return (0);
}

static int
acpi_timer_attach(device_t dev)
{
    int rid, rtype;

    ACPI_FUNCTION_TRACE((char *)(uintptr_t)__func__);

    switch (AcpiGbl_FADT.XPmTimerBlock.SpaceId) {
    case ACPI_ADR_SPACE_SYSTEM_MEMORY:
	rtype = SYS_RES_MEMORY;
	break;
    case ACPI_ADR_SPACE_SYSTEM_IO:
	rtype = SYS_RES_IOPORT;
	break;
    default:
	return (ENXIO);
    }
    rid = 0;
    acpi_timer_reg = bus_alloc_resource_any(dev, rtype, &rid, RF_ACTIVE);
    if (acpi_timer_reg == NULL)
	return (ENXIO);
    acpi_timer_bsh = rman_get_bushandle(acpi_timer_reg);
    acpi_timer_bst = rman_get_bustag(acpi_timer_reg);

    /* Register suspend event handler. */
    if (EVENTHANDLER_REGISTER(power_suspend, acpi_timer_suspend_handler,
	&acpi_timer_timecounter, EVENTHANDLER_PRI_LAST) == NULL)
	device_printf(dev, "failed to register suspend event handler\n");

    return (0);
}

static struct timecounter *acpi_timer_saved_tc;

static void
acpi_timer_resume_handler(struct timecounter *newtc, enum power_stype stype)
{
	struct timecounter *tc;

	tc = timecounter;
	if (tc != newtc) {
		if (bootverbose && acpi_timer_dev != NULL)
			device_printf(acpi_timer_dev,
			    "restoring timecounter, %s -> %s\n",
			    tc->tc_name, newtc->tc_name);
		(void)newtc->tc_get_timecount(newtc);
		timecounter = newtc;
	}
	/*
	 * Clear saved pointer even when already restored (explicit
	 * acpi_timer_resume + power_resume EH).
	 */
	acpi_timer_saved_tc = NULL;
}

static void
acpi_timer_suspend_handler(struct timecounter *newtc, enum power_stype stype)
{
	struct timecounter *tc;

	/* Deregister existing resume event handler. */
	if (acpi_timer_eh != NULL) {
		EVENTHANDLER_DEREGISTER(power_resume, acpi_timer_eh);
		acpi_timer_eh = NULL;
	}

	if ((timecounter->tc_flags & TC_FLAGS_SUSPEND_SAFE) != 0) {
		/*
		 * Already on a suspend-safe timecounter — leave
		 * acpi_timer_saved_tc untouched so a prior switch's
		 * saved target is not lost on a redundant suspend call.
		 */
		return;
	}

	KASSERT(newtc == &acpi_timer_timecounter,
	    ("acpi_timer_suspend_handler: wrong timecounter"));

	tc = timecounter;
	if (tc != newtc) {
		if (bootverbose && acpi_timer_dev != NULL)
			device_printf(acpi_timer_dev,
			    "switching timecounter, %s -> %s\n",
			    tc->tc_name, newtc->tc_name);
		(void)acpi_timer_read();
		(void)acpi_timer_read();
		/*
		 * Preserve the first saved non-ACPI timecounter across
		 * redundant suspend calls (hibernate entry + EJUSTRETURN).
		 */
		if (acpi_timer_saved_tc == NULL)
			acpi_timer_saved_tc = tc;
		timecounter = newtc;
		acpi_timer_eh = EVENTHANDLER_REGISTER(power_resume,
		    acpi_timer_resume_handler, acpi_timer_saved_tc,
		    EVENTHANDLER_PRI_LAST);
	}
}

void
acpi_timer_suspend(void)
{
	if (acpi_timer_timecounter.tc_quality <= 0)
		return;
	acpi_timer_suspend_handler(&acpi_timer_timecounter,
	    POWER_STYPE_OS_HIBERNATE);
}

void
acpi_timer_resume(void)
{
	struct timecounter *tc;

	tc = acpi_timer_saved_tc;
	if (tc != NULL && tc != timecounter) {
		acpi_timer_saved_tc = NULL;
		acpi_timer_resume_handler(tc, POWER_STYPE_OS_HIBERNATE);
	} else {
		acpi_timer_saved_tc = NULL;
	}
	/* Drop any EH so a later power_resume cannot double-swap. */
	if (acpi_timer_eh != NULL) {
		EVENTHANDLER_DEREGISTER(power_resume, acpi_timer_eh);
		acpi_timer_eh = NULL;
	}
}

/*
 * Fetch current time value from reliable hardware.
 */
static u_int
acpi_timer_get_timecount(struct timecounter *tc)
{
    return (acpi_timer_read());
}

/*
 * Fetch current time value from hardware that may not correctly
 * latch the counter.  We need to read until we have three monotonic
 * samples and then use the middle one, otherwise we are not protected
 * against the fact that the bits can be wrong in two directions.  If
 * we only cared about monosity, two reads would be enough.
 */
static u_int
acpi_timer_get_timecount_safe(struct timecounter *tc)
{
    u_int u1, u2, u3;

    u2 = acpi_timer_read();
    u3 = acpi_timer_read();
    do {
	u1 = u2;
	u2 = u3;
	u3 = acpi_timer_read();
    } while (u1 > u2 || u2 > u3);

    return (u2);
}

/*
 * Timecounter freqency adjustment interface.
 */ 
static int
acpi_timer_sysctl_freq(SYSCTL_HANDLER_ARGS)
{
    int error;
    u_int freq;

    if (acpi_timer_timecounter.tc_frequency == 0)
	return (EOPNOTSUPP);
    freq = acpi_timer_frequency;
    error = sysctl_handle_int(oidp, &freq, 0, req);
    if (error == 0 && req->newptr != NULL) {
	acpi_timer_frequency = freq;
	acpi_timer_timecounter.tc_frequency = acpi_timer_frequency;
    }

    return (error);
}

SYSCTL_PROC(_machdep, OID_AUTO, acpi_timer_freq,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_MPSAFE, 0, 0,
    acpi_timer_sysctl_freq, "I",
    "ACPI timer frequency");
