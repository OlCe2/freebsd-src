/*-
 * Copyright (c) 2002 Marcel Moolenaar
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/cons.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/kerneldump.h>
#include <sys/malloc.h>
#include <sys/msgbuf.h>
#include <sys/proc.h>
#include <sys/smp.h>
#include <sys/watchdog.h>

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_page.h>
#include <vm/vm_pagequeue.h>
#include <vm/vm_phys.h>
#include <vm/vm_dumpset.h>
#include <vm/pmap.h>

#include <machine/_inttypes.h>
#include <machine/dump.h>
#include <machine/elf.h>
#include <machine/md_var.h>
#ifdef OS_HIBERNATE_SUPPORT
#include <machine/hibernate.h>
#endif

CTASSERT(sizeof(struct kerneldumpheader) == 512);

#define	MD_ALIGN(x)		roundup2((x), PAGE_SIZE)
#define	DEV_ALIGN(x, blocksize)	roundup2((x), (blocksize))

/* Handle buffered writes. */
static size_t fragsz;

struct dump_pa dump_map[DUMPSYS_MD_PA_NPAIRS];

bool
has_dumpers(void)
{
	bool res;

	mtx_lock(&dumpconf_list_lk);
	res = TAILQ_EMPTY(&dumper_configs);
	mtx_unlock(&dumpconf_list_lk);
	return (!res);
}

#if !defined(__powerpc__)
void
dumpsys_gen_pa_init(void)
{
	int n, idx;

	bzero(dump_map, sizeof(dump_map));
	for (n = 0; n < nitems(dump_map); n++) {
		idx = n * 2;
		if (dump_avail[idx] == 0 && dump_avail[idx + 1] == 0)
			break;
		dump_map[n].pa_start = dump_avail[idx];
		dump_map[n].pa_size = dump_avail[idx + 1] - dump_avail[idx];
	}
}
#endif

struct dump_pa *
dumpsys_gen_pa_next(struct dump_pa *mdp)
{

	if (mdp == NULL)
		return (&dump_map[0]);

	mdp++;
	if (mdp - dump_map >= nitems(dump_map) ||
	    (mdp->pa_start == 0 && mdp->pa_size == 0))
		mdp = NULL;
	return (mdp);
}

void
dumpsys_gen_wbinv_all(void)
{

}

void
dumpsys_gen_unmap_chunk(vm_paddr_t pa __unused, size_t chunk __unused,
    void *va __unused)
{

}

int
dumpsys_gen_write_aux_headers(struct dumperinfo *di)
{

	return (0);
}

int
dumpsys_buf_seek(struct dumperinfo *di, size_t sz)
{
	static uint8_t buf[DEV_BSIZE];
	size_t nbytes;
	int error;

	bzero(buf, sizeof(buf));

	while (sz > 0) {
		nbytes = MIN(sz, sizeof(buf));

		error = dump_append(di, buf, nbytes);
		if (error)
			return (error);
		sz -= nbytes;
	}

	return (0);
}

int
dumpsys_buf_write(struct dumperinfo *di, const char *ptr, size_t sz)
{
	size_t len;
	int error;

	while (sz) {
		len = di->blocksize - fragsz;
		if (len > sz)
			len = sz;
		memcpy((char *)di->blockbuf + fragsz, ptr, len);
		fragsz += len;
		ptr += len;
		sz -= len;
		if (fragsz == di->blocksize) {
			error = dump_append(di, di->blockbuf, di->blocksize);
			if (error)
				return (error);
			fragsz = 0;
		}
	}
	return (0);
}

int
dumpsys_buf_flush(struct dumperinfo *di)
{
	int error;

	if (fragsz == 0)
		return (0);

	error = dump_append(di, di->blockbuf, di->blocksize);
	fragsz = 0;
	return (error);
}

CTASSERT(PAGE_SHIFT < 20);
#define PG2MB(pgs) ((pgs + (1 << (20 - PAGE_SHIFT)) - 1) >> (20 - PAGE_SHIFT))

int
dumpsys_cb_dumpdata(struct dump_pa *mdp, int seqnr, void *arg)
{
	struct dumperinfo *di = (struct dumperinfo*)arg;
	vm_paddr_t pa;
	void *va;
	uint64_t pgs;
	size_t counter, sz, chunk;
	int c, error;
	u_int maxdumppgs;

	error = 0;	/* catch case in which chunk size is 0 */
	counter = 0;	/* Update twiddle every 16MB */
	va = NULL;
	pgs = mdp->pa_size / PAGE_SIZE;
	pa = mdp->pa_start;
	maxdumppgs = min(di->maxiosize / PAGE_SIZE, MAXDUMPPGS);
	if (maxdumppgs == 0)	/* seatbelt */
		maxdumppgs = 1;

	printf("  chunk %d: %" PRIu64 "MB (%" PRIu64 " pages)", seqnr,
	    PG2MB(pgs), pgs);

	dumpsys_wbinv_all();
	while (pgs) {
		chunk = pgs;
		if (chunk > maxdumppgs)
			chunk = maxdumppgs;
		sz = chunk << PAGE_SHIFT;
		counter += sz;
		if (counter >> 24) {
			printf(" %" PRIu64, PG2MB(pgs));
			counter &= (1 << 24) - 1;
		}

		dumpsys_map_chunk(pa, chunk, &va);
		wdog_kern_pat(WD_LASTVAL);

		error = dump_append(di, va, sz);
		dumpsys_unmap_chunk(pa, chunk, va);
		if (error)
			break;
		pgs -= chunk;
		pa += sz;

		/* Check for user abort. */
		c = cncheckc();
		if (c == 0x03)
			return (ECANCELED);
		if (c != -1)
			printf(" (CTRL-C to abort) ");
	}
	printf(" ... %s\n", (error) ? "fail" : "ok");
	return (error);
}

int
dumpsys_foreach_chunk(dumpsys_callback_t cb, void *arg)
{
	struct dump_pa *mdp;
	int error, seqnr;

	seqnr = 0;
	mdp = dumpsys_pa_next(NULL);
	while (mdp != NULL) {
		error = (*cb)(mdp, seqnr++, arg);
		if (error)
			return (-error);
		mdp = dumpsys_pa_next(mdp);
	}
	return (seqnr);
}

static uint64_t fileofs;

static int
cb_dumphdr(struct dump_pa *mdp, int seqnr, void *arg)
{
	struct dumperinfo *di = (struct dumperinfo*)arg;
	Elf_Phdr phdr;
	uint64_t size;
	int error;

	size = mdp->pa_size;
	bzero(&phdr, sizeof(phdr));
	phdr.p_type = PT_LOAD;
	phdr.p_flags = PF_R;			/* XXX */
	phdr.p_offset = fileofs;
#ifdef __powerpc__
	phdr.p_vaddr = (do_minidump? mdp->pa_start : ~0L);
	phdr.p_paddr = (do_minidump? ~0L : mdp->pa_start);
#else
	phdr.p_vaddr = mdp->pa_start;
	phdr.p_paddr = mdp->pa_start;
#endif
	phdr.p_filesz = size;
	phdr.p_memsz = size;
	phdr.p_align = PAGE_SIZE;

	error = dumpsys_buf_write(di, (char*)&phdr, sizeof(phdr));
	fileofs += phdr.p_filesz;
	return (error);
}

static int
cb_size(struct dump_pa *mdp, int seqnr, void *arg)
{
	uint64_t *sz;

	sz = (uint64_t *)arg;
	*sz += (uint64_t)mdp->pa_size;
	return (0);
}

#ifdef OS_HIBERNATE_SUPPORT

const uint64_t contig_spare_pages_nb = howmany(HIBERNATE_CONTIG_SPARE_SIZE,
    PAGE_SIZE);
const uint64_t spare_pages_nb = howmany(HIBERNATE_SPARE_SIZE, PAGE_SIZE);


int
dumpsys_hibernate_create_hcb(uint64_t hardware_signature,
    struct hibernate_cb **hcb_out)
{
	const int max_contig_tries = 2;
	const int max_spare_tries = 2;
	const int spare_pages_reclaim_slop = 3;
	/*
	 * For now, VM_ALLOC_NODUMP doesn't matter as we do only full dumps, so
	 * we need to zero the spare pages since they are going to disk.
	 *
	 * XXX - We probably need a distinct flag anyway, or better exclude
	 * allocated pages for the HCB while dumping through lookups to what we
	 * have allocated.
	 */
	const int vm_req = VM_ALLOC_NOWAIT | VM_ALLOC_ZERO | VM_ALLOC_NODUMP;
	struct hibernate_cb *hcb;
	vm_page_t p;
	int contig_tries = 0;
	int error;

	/* Allocate the control block. */
	hcb = malloc(hcb_size_spec(spare_pages_nb), M_TEMP, M_WAITOK | M_ZERO);

	hcb->hc_version = HCB_VERSION;

	/* Allocate the contiguous chunk first for better chances of success. */
	hcb->hc_contig_spare_size = contig_spare_pages_nb * PAGE_SIZE;
	for (;;) {
		p = vm_page_alloc_noobj_contig(vm_req, contig_spare_pages_nb,
		    HIBERNATE_PADDR_MIN, -1, PAGE_SIZE, 0, VM_MEMATTR_DEFAULT);
		if (p != NULL)
			break;
		if (++contig_tries >= max_contig_tries) {
			error = ENOMEM;
			goto free_hcb;
		}

		/*
		 * We try to reclaim contiguous memory once.  System is
		 * quiescent at this point, and we got rid of caches, so if
		 * allocation does not work after the reclaim, something is
		 * wrong and there's probably no point in retrying.
		 */
		error = vm_page_reclaim_contig(vm_req, contig_spare_pages_nb,
		    HIBERNATE_PADDR_MIN, -1, PAGE_SIZE, 0);
		if (error != 0)
			goto free_hcb;
	}
	hcb->hc_contig_spare_start = VM_PAGE_TO_PHYS(p);

	/* Non-contiguous pages. */
	hcb->hc_spare_pages_nb = spare_pages_nb;
	for (uint64_t i = 0; i < spare_pages_nb; ++i) {
		vm_page_t p;
		int spare_tries = 0;

		for (;;) {
			p = vm_page_alloc_noobj_contig(vm_req |
			    VM_ALLOC_COUNT(min(VM_ALLOC_COUNT_MAX,
			    spare_pages_nb - i)),
			    1, HIBERNATE_PADDR_MIN, -1, PAGE_SIZE, 0,
			    VM_MEMATTR_DEFAULT);
			if (p != NULL)
				break;
			if (++spare_tries >= max_spare_tries) {
				error = ENOMEM;
				goto free_hcb;
			}

			/* Try to reclaim pages in the wanted physical range. */
			error = vm_page_reclaim_contig(vm_req,
			    spare_pages_reclaim_slop, HIBERNATE_PADDR_MIN, -1,
			    PAGE_SIZE, 0);
				if (error != 0)
					goto free_hcb;
		}

		hcb->hc_spare_pages[i] = VM_PAGE_TO_PHYS(p);
	}

	hcb->hc_hardware_signature = hardware_signature;

	*hcb_out = hcb;
	return (0);

free_hcb:
	dumpsys_hibernate_free_hcb(hcb);
	MPASS(error != 0);
	return (error);
}

void
dumpsys_hibernate_free_hcb(struct hibernate_cb *hcb)
{
	vm_paddr_t phys;
	vm_page_t p;

	/* Dealloc contiguous pages. */
	phys = hcb->hc_contig_spare_start;
	if (phys != 0) {
		const uint64_t contig_spare_pages_nb =
		    hcb->hc_contig_spare_size / PAGE_SIZE;

		p = PHYS_TO_VM_PAGE(phys);
		/*
		 * XXX: Looks a bit too low-level and kind of a layer violation;
		 * need to evolve 'vm_page.c'.
		 */
		vm_domain_free_lock(vm_pagequeue_domain(p));
		vm_phys_free_contig(p, p->pool, contig_spare_pages_nb);
		vm_domain_free_unlock(vm_pagequeue_domain(p));
	}

	for (uint64_t i = 0; i < spare_pages_nb; ++i) {
		phys = hcb->hc_spare_pages[i];

		if (phys != 0)
			vm_page_free(PHYS_TO_VM_PAGE(phys));
	}

	free(hcb, M_TEMP);
}

static dumper_start_t dumpsys_hibernate_start;
static dumper_hdr_t dumpsys_hibernate_aux_headers;

int
dumpsys_hibernate_start(struct dumperinfo *di, struct kerneldumpheader *kdh,
    void *key, uint32_t keysize)
{
	uint64_t dumpextent, span;

	dumpextent = dtoh64(kdh->dumpextent);
	span = SIZEOF_METADATA + dumpextent;

	/*
	 * XXX - From this point on, logic is similar to that of dump_start().
	 * Difference is that we don't output the dump at the end of the
	 * partition, but at start (modulo SIZEOF_METADATA), since we don't
	 * output an additional header at the end which would indicate
	 * immediately where the dump starts.
	 */
	if (di->mediasize < span) {
		if (di->kdcomp == NULL)
			return (E2BIG);

		/*
		 * Use all space, hoping that compression will allow the dump to
		 * fit.
		 */
		dumpextent = di->mediasize - span + dumpextent;
		/*
		 * XXX - This seems unnecessary, as 'dumpextent' is used only in
		 * dump_write_headers() if there's no specific hook, and we have
		 * installed one.
		 */
		kdh->dumpextent = htod64(dumpextent);
	}

	/*
	 * Write the dump towards the start of the partition.
	 */
	di->dumpoff = di->mediaoffset + SIZEOF_METADATA;
	return (0);
}

/*
 * Dump extra (out-of-ELF) headers.
 */
int
dumpsys_hibernate_aux_headers(struct dumperinfo *di, struct kerneldumpheader *kdh)
{
	/* We have none. */
	return (0);
}

/*
 * Hibernate's additional ELF program headers.
 *
 * Two additional headers, one containing a 'struct hibernate_cb'
 * (PT_FREEBSD_HIBERNATE_CB) and another containing a 'struct hibernate_pcb'
 * (PT_FREEBSD_HIBERNATE_PCB).
 */
static const int hibernate_addphdr_nb = 2;

static inline size_t
dumpsys_hibernate_addphdr_size(const struct hibernate_cb *const hcb)
{
	return (hcb_size(hcb) + sizeof(struct hibernate_pcb));
}

static int
dumpsys_hibernate_addphdr_write_elf_headers(struct dumperinfo *di, uint64_t offset,
    const struct hibernate_cb *const hcb)
{
	Elf_Phdr phdr;
	int error;

	bzero(&phdr, sizeof(phdr));

	phdr.p_type = PT_FREEBSD_HIBERNATE_CB;
	/*
	 * Does not matter for image restoration.  May matter for external ELF
	 * analysis tools, if ever used on the dump.
	 */
	phdr.p_flags = PF_R;
	phdr.p_offset = offset;
	phdr.p_filesz = hcb_size(hcb);
	phdr.p_memsz = phdr.p_filesz;
	error = dumpsys_buf_write(di, (char*)&phdr, sizeof(phdr));
	if (error != 0)
		return (error);

	phdr.p_type = PT_FREEBSD_HIBERNATE_PCB;
	phdr.p_flags = PF_R;
	phdr.p_offset = offset + hcb_size(hcb);
	phdr.p_filesz = sizeof(struct hibernate_pcb);
	phdr.p_memsz = phdr.p_filesz;
	error = dumpsys_buf_write(di, (char*)&phdr, sizeof(phdr));
	return (error);
}

static int
dumpsys_hibernate_addphdr_write(struct dumperinfo *di,
    const struct hibernate_cb *const hcb, const struct hibernate_pcb *const hpcb)
{
	int error;

	error = dumpsys_buf_write(di, (const char *)hcb, hcb_size(hcb));
	if (error != 0)
		return (error);
	error = dumpsys_buf_write(di, (const char *)hpcb, sizeof(*hpcb));
	return (error);
}

/*
 * XXX - For now, this is mostly a copy/paste of dumpsys_generic() with
 * adaptations.  Should look into factoring out what makes sense and remove
 * specifics that do not really apply to hibernate dumps at some point.  But
 * maybe not be worth it until late, as we may want to switch to something
 * similar to a minidump.
 */
static int
dumpsys_hibernate(struct dumperinfo *di, const struct hibernate_cb *const hcb,
    const struct hibernate_pcb *const hpcb)
{
	static struct kerneldumpheader kdh;
	Elf_Ehdr ehdr;
	uint64_t dumpsize, hdrgap, hdrsiz, size_before_pages;
	int error;

	/*
	 * XXX - Temporarily hook into dump start and header callbacks, pending
	 * a better architecture.
	 */
	if (di->dumper_start != NULL || di->dumper_hdr != NULL)
		return (EOPNOTSUPP);
	di->dumper_start = dumpsys_hibernate_start;
	di->dumper_hdr = dumpsys_hibernate_aux_headers;

	bzero(&ehdr, sizeof(ehdr));
	ehdr.e_ident[EI_MAG0] = ELFMAG0;
	ehdr.e_ident[EI_MAG1] = ELFMAG1;
	ehdr.e_ident[EI_MAG2] = ELFMAG2;
	ehdr.e_ident[EI_MAG3] = ELFMAG3;
	ehdr.e_ident[EI_CLASS] = ELF_CLASS;
#if BYTE_ORDER == LITTLE_ENDIAN
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
#else
	ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
#endif
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_FREEBSD;
	ehdr.e_type = ET_FREEBSD_HIBERNATE_IMAGE;
	ehdr.e_machine = EM_VALUE;
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_flags = 0;
	ehdr.e_ehsize = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(Elf_Phdr);
	ehdr.e_shentsize = sizeof(Elf_Shdr);

	dumpsys_pa_init();

	dumpsize = 0;
	ehdr.e_phnum = dumpsys_foreach_chunk(cb_size, &dumpsize) +
	    hibernate_addphdr_nb;
	hdrsiz = ehdr.e_phoff + ehdr.e_phnum * ehdr.e_phentsize;
	size_before_pages = hdrsiz + dumpsys_hibernate_addphdr_size(hcb);
	fileofs = DEV_ALIGN(MD_ALIGN(size_before_pages), di->blocksize);
	dumpsize += fileofs;
	hdrgap = fileofs - DEV_ALIGN(size_before_pages, di->blocksize);

	/*
	 * XXX - Passed magic and version are not used, as we don't emit headers
	 * in addition to the ELF file, contrary to all other styles of dumps.
	 */
	dump_init_header(di, &kdh, KERNELDUMPMAGIC, KERNELDUMP_ARCH_VERSION,
	    dumpsize);

	/* Calls back dumpsys_hibernate_start(). */
	error = dump_start(di, &kdh);
	if (error != 0)
		goto fail;

	printf("Saving %" PRIu64 " MB (%d chunks)\n", dumpsize >> 20,
	    ehdr.e_phnum - hibernate_addphdr_nb);

	/* Dump ELF header */
	error = dumpsys_buf_write(di, (char*)&ehdr, sizeof(ehdr));
	if (error)
		goto fail;

	/* Dump hibernate specific headers. */
	error = dumpsys_hibernate_addphdr_write_elf_headers(di, hdrsiz, hcb);
	if (error != 0)
		goto fail;

	/* Dump program headers. */
	error = dumpsys_foreach_chunk(cb_dumphdr, di);
	if (error < 0)
		goto fail;

	/* Dump hibernate specific info. */
	error = dumpsys_hibernate_addphdr_write(di, hcb, hpcb);
	if (error != 0)
		goto fail;

	dumpsys_buf_flush(di);

	/*
	 * Skip to align segments containing pages to page boundaries.
	 *
	 * XXX: Does this really matter?
	 */
	error = dumpsys_buf_seek(di, (size_t)hdrgap);
	if (error)
		goto fail;

	/* Dump memory chunks. */
	error = dumpsys_foreach_chunk(dumpsys_cb_dumpdata, di);
	if (error < 0)
		goto fail;

	/* Calls back dumpsys_hibernate_aux_headers(). */
	error = dump_finish(di, &kdh);
	if (error != 0)
		goto fail;

	printf("\nHibernate image saving complete\n");
	error = 0;

finish:
	/* Remove our specific hooks. */
	di->dumper_start = NULL;
	di->dumper_hdr = NULL;
	return (error);

fail:
	if (error < 0)
		error = -error;

	if (error == ECANCELED)
		printf("\nDump aborted\n");
	else if (error == E2BIG || error == ENOSPC)
		printf("\nDump failed. Partition too small.\n");
	else
		printf("\n** DUMP FAILED (ERROR %d) **\n", error);
	goto finish;
}

/*
 * Hibernate dump.
 *
 * All other processors and the scheduler must have been stopped.
 *
 * XXX - Factor this out with existing dump functions?
 */
int
dump_for_hibernate(const struct hibernate_cb *const hcb,
    const struct hibernate_pcb *const hpcb)
{
	struct dumperinfo *di;
	int error = ENXIO;

	/*
	 * XXX - We would like that 'dumping' is not set, in case we panic while
	 * dumping here, in which case we'd want a panic dump.  But currently we
	 * can't, as the ada dump routine cannot work without it set.  Dumping
	 * needs peculiar conditions to work, and at least for the time being,
	 * we need to reproduce these here.
	 */
	++dumping;

	/* XXX - Validity of 'dumper_configs' under SCHEDULER_STOPPED(). */
	TAILQ_FOREACH(di, &dumper_configs, di_next) {
		error = dumpsys_hibernate(di, hcb, hpcb);
		switch (error) {
		case 0:
			goto finish;
		case E2BIG:
		case ENOSPC:
			continue;
		default:
			/* Other errors considered as not recoverable. */
			goto finish;
		}
	}

finish:
	--dumping;

	return (error);
}
#endif /* OS_HIBERNATE_SUPPORT */

int
dumpsys_generic(struct dumperinfo *di)
{
	static struct kerneldumpheader kdh;
	Elf_Ehdr ehdr;
	uint64_t dumpsize, hdrgap, hdrsz;
	int error;

#if MINIDUMP_PAGE_TRACKING == 1
	if (do_minidump)
		return (minidumpsys(di, false));
#endif

	bzero(&ehdr, sizeof(ehdr));
	ehdr.e_ident[EI_MAG0] = ELFMAG0;
	ehdr.e_ident[EI_MAG1] = ELFMAG1;
	ehdr.e_ident[EI_MAG2] = ELFMAG2;
	ehdr.e_ident[EI_MAG3] = ELFMAG3;
	ehdr.e_ident[EI_CLASS] = ELF_CLASS;
#if BYTE_ORDER == LITTLE_ENDIAN
	ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
#else
	ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
#endif
	ehdr.e_ident[EI_VERSION] = EV_CURRENT;
	ehdr.e_ident[EI_OSABI] = ELFOSABI_STANDALONE;	/* XXX big picture? */
	ehdr.e_type = ET_CORE;
	ehdr.e_machine = EM_VALUE;
	ehdr.e_phoff = sizeof(ehdr);
	ehdr.e_flags = 0;
	ehdr.e_ehsize = sizeof(ehdr);
	ehdr.e_phentsize = sizeof(Elf_Phdr);
	ehdr.e_shentsize = sizeof(Elf_Shdr);

	dumpsys_pa_init();

	/* Calculate dump size. */
	dumpsize = 0L;
	ehdr.e_phnum = dumpsys_foreach_chunk(cb_size, &dumpsize) +
	    DUMPSYS_NUM_AUX_HDRS;
	hdrsz = ehdr.e_phoff + ehdr.e_phnum * ehdr.e_phentsize;
	fileofs = DEV_ALIGN(MD_ALIGN(hdrsz), di->blocksize);
	dumpsize += fileofs;
	hdrgap = fileofs - DEV_ALIGN(hdrsz, di->blocksize);

	dump_init_header(di, &kdh, KERNELDUMPMAGIC, KERNELDUMP_ARCH_VERSION,
	    dumpsize);

	error = dump_start(di, &kdh);
	if (error != 0)
		goto fail;

	printf("Dumping %" PRIu64 " MB (%d chunks)\n", dumpsize >> 20,
	    ehdr.e_phnum - DUMPSYS_NUM_AUX_HDRS);

	/* Dump ELF header */
	error = dumpsys_buf_write(di, (char*)&ehdr, sizeof(ehdr));
	if (error)
		goto fail;

	/* Dump program headers */
	error = dumpsys_foreach_chunk(cb_dumphdr, di);
	if (error < 0)
		goto fail;
	error = dumpsys_write_aux_headers(di);
	if (error != 0)
		goto fail;
	dumpsys_buf_flush(di);

	/*
	 * All headers are written using blocked I/O, so we know the
	 * current offset is (still) block aligned. Skip the alignement
	 * in the file to have the segment contents aligned at page
	 * boundary.
	 */
	error = dumpsys_buf_seek(di, (size_t)hdrgap);
	if (error)
		goto fail;

	/* Dump memory chunks. */
	error = dumpsys_foreach_chunk(dumpsys_cb_dumpdata, di);
	if (error < 0)
		goto fail;

	error = dump_finish(di, &kdh);
	if (error != 0)
		goto fail;

	printf("\nDump complete\n");
	return (0);

 fail:
	if (error < 0)
		error = -error;

	if (error == ECANCELED)
		printf("\nDump aborted\n");
	else if (error == E2BIG || error == ENOSPC)
		printf("\nDump failed. Partition too small.\n");
	else
		printf("\n** DUMP FAILED (ERROR %d) **\n", error);
	return (error);
}

#if MINIDUMP_PAGE_TRACKING == 1

/* Minidump progress bar */
static struct {
	const int min_per;
	const int max_per;
	bool visited;
} progress_track[10] = {
	{  0,  10, false},
	{ 10,  20, false},
	{ 20,  30, false},
	{ 30,  40, false},
	{ 40,  50, false},
	{ 50,  60, false},
	{ 60,  70, false},
	{ 70,  80, false},
	{ 80,  90, false},
	{ 90, 100, false}
};

static uint64_t dumpsys_pb_size;
static uint64_t dumpsys_pb_remaining;
static uint64_t dumpsys_pb_check;

/* Reset the progress bar for a dump of dumpsize. */
void
dumpsys_pb_init(uint64_t dumpsize)
{
	int i;

	dumpsys_pb_size = dumpsys_pb_remaining = dumpsize;
	dumpsys_pb_check = 0;

	for (i = 0; i < nitems(progress_track); i++)
		progress_track[i].visited = false;
}

/*
 * Update the progress according to the delta bytes that were written out.
 * Check and print the progress percentage.
 */
void
dumpsys_pb_progress(size_t delta)
{
	int sofar, i;

	dumpsys_pb_remaining -= delta;
	dumpsys_pb_check += delta;

	/*
	 * To save time while dumping, only loop through progress_track
	 * occasionally.
	 */
	if ((dumpsys_pb_check >> DUMPSYS_PB_CHECK_BITS) == 0)
		return;
	else
		dumpsys_pb_check &= (1 << DUMPSYS_PB_CHECK_BITS) - 1;

	sofar = 100 - ((dumpsys_pb_remaining * 100) / dumpsys_pb_size);
	for (i = 0; i < nitems(progress_track); i++) {
		if (sofar < progress_track[i].min_per ||
		    sofar > progress_track[i].max_per)
			continue;
		if (!progress_track[i].visited) {
			progress_track[i].visited = true;
			printf("..%d%%", sofar);
		}
		break;
	}
}

int
minidumpsys(struct dumperinfo *di, bool livedump)
{
	struct minidumpstate state;
	struct msgbuf mb_copy;
	char *msg_ptr;
	int error;

	if (livedump) {
		KASSERT(!dumping, ("live dump invoked from incorrect context"));

		/*
		 * Before invoking cpu_minidumpsys() on the live system, we
		 * must snapshot some required global state: the message
		 * buffer, and the page dump bitset. They may be modified at
		 * any moment, so for the sake of the live dump it is best to
		 * have an unchanging snapshot to work with. Both are included
		 * as part of the dump and consumed by userspace tools.
		 *
		 * Other global state important to the minidump code is the
		 * dump_avail array and the kernel's page tables, but snapshots
		 * are not taken of these. For one, dump_avail[] is expected
		 * not to change after boot. Snapshotting the kernel page
		 * tables would involve an additional walk, so this is avoided
		 * too.
		 *
		 * This means live dumps are best effort, and the result may or
		 * may not be usable; there are no guarantees about the
		 * consistency of the dump's contents. Any of the following
		 * (and likely more) may affect the live dump:
		 *
		 *  - Data may be modified, freed, or remapped during the
		 *    course of the dump, such that the contents written out
		 *    are partially or entirely unrecognizable. This means
		 *    valid references may point to destroyed/mangled objects,
		 *    and vice versa.
		 *
		 *  - The dumped context of any threads that ran during the
		 *    dump process may be unreliable.
		 *
		 *  - The set of kernel page tables included in the dump likely
		 *    won't correspond exactly to the copy of the dump bitset.
		 *    This means some pages will be dumped without any way to
		 *    locate them, and some pages may not have been dumped
		 *    despite appearing as if they should.
		 */
		msg_ptr = malloc(msgbufsize, M_TEMP, M_WAITOK);
		msgbuf_duplicate(msgbufp, &mb_copy, msg_ptr);
		state.msgbufp = &mb_copy;

		state.dump_bitset = BITSET_ALLOC(vm_page_dump_pages, M_TEMP,
		    M_WAITOK);
		BIT_COPY_STORE_REL(vm_page_dump_pages, vm_page_dump,
		    state.dump_bitset);
	} else {
		KASSERT(dumping, ("minidump invoked outside of doadump()"));

		/* Use the globals. */
		state.msgbufp = msgbufp;
		state.dump_bitset = vm_page_dump;
	}

	error = cpu_minidumpsys(di, &state);
	if (livedump) {
		free(msg_ptr, M_TEMP);
		BITSET_FREE(state.dump_bitset, M_TEMP);
	}

	return (error);
}
#endif /* MINIDUMP_PAGE_TRACKING == 1 */
