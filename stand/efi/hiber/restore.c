#include "hiber.h"
#include <machine/hibernate.h>

static bool
check_elf_headers(const Elf_Ehdr *ehdr)
{
	if (!IS_ELF(*ehdr)) {
		hiber_printf("invalid file format\n");
		return (false);
	}
	if (ehdr->e_ident[EI_CLASS] != ELF_TARG_CLASS ||
	    ehdr->e_ident[EI_DATA] != ELF_TARG_DATA) {
		hiber_printf("unsupported file layout\n");
		return (false);
	}
	if (ehdr->e_ident[EI_VERSION] != EV_CURRENT ||
	    ehdr->e_version != EV_CURRENT) {
		hiber_printf("unsupported file version\n");
		return (false);
	}
	if (ehdr->e_type != ET_FREEBSD_S4_IMAGE) {
		hiber_printf("unsupported file type\n");
		return (false);
	}
	if (ehdr->e_machine != ELF_TARG_MACH) {
		hiber_printf("unsupported machine\n");
		return (false);
	}
	if (ehdr->e_phentsize != sizeof(Elf_Phdr)) {
		hiber_printf(
		    "invalid shared object: e_phentsize != sizeof(Elf_Phdr)");
		return (false);
	}
	return (true);
}


bool
hiber_check_format(void)
{
	Elf_Ehdr ehdr;
	Elf_Phdr *phdrs;
	const Elf_Phdr *ph;
	vm_paddr_t pcb_physaddr, tramp_physaddr;
	struct trampoline_buf_desc *tbd;
	uint64_t tramp_sz;
	EFI_STATUS status;
	bool res;

	res = false;
	phdrs = NULL;

	if (!hiber_read_img(0, &ehdr, sizeof(ehdr))) {
		hiber_printf("Cannot read ELF header\n");
		goto out;
	}
	if (!check_elf_headers(&ehdr))
		goto out;

	status = BS->AllocatePool(EfiBootServicesData,
	    ehdr.e_phentsize * ehdr.e_phnum, (void *)&phdrs);
	if (status != EFI_SUCCESS) {
		hiber_printf("Cannot alloc memory for phdrs\n");
		goto out;
	}
	if (!hiber_read_img(ehdr.e_phoff, phdrs, ehdr.e_phentsize *
	    ehdr.e_phnum))
		goto out;

	pcb_physaddr = 0;
	tramp_physaddr = 0;
	res = true;

	for (ph = phdrs; ph < phdrs + ehdr.e_phnum; ph++) {
		switch (ph->p_type) {
		case PT_FREEBSD_S4_PCB:
			pcb_physaddr = ph->p_paddr;
			if (ph->p_filesz != sizeof(struct s4_pcb)) {
				hiber_printf(
				    "PT_FREEBSD_S4_PCB file size %#x not %#x\n",
				    ph->p_filesz, sizeof(struct s4_pcb));
				res = false;
				break;
			}
			if (ph->p_memsz != sizeof(struct s4_pcb)) {
				hiber_printf(
				    "PT_FREEBSD_S4_PCB mem size %#x not %#x\n",
				    ph->p_memsz, sizeof(struct s4_pcb));
				res = false;
				break;
			}
			break;
		case PT_FREEBSD_S4_TRAMPOLINE:
			tramp_physaddr = ph->p_paddr;
			tbd = (void *)tramp_physaddr;
			tramp_sz = sizeof(uint64_t) +
			    sizeof(struct trampoline_cont_buf_desc) *
			    tbd->num_bufs;
			if (ph->p_filesz != tramp_sz) {
				hiber_printf("PT_FREEBSD_S4_TRAMPOLINE "
				    "file size %#x not %#x\n", ph->p_filesz,
				    sizeof(struct trampoline_buf_desc));
				res = false;
				break;
			}
			if (ph->p_memsz != tramp_sz) {
				hiber_printf("PT_FREEBSD_S4_TRAMPOLINE "
				    "file size %#x not %#x\n", ph->p_memsz,
				    sizeof(struct trampoline_buf_desc));
				res = false;
				break;
			}
			break;
		case PT_LOAD:
			if (ph->p_filesz != ph->p_memsz) {
				hiber_printf("bss segment\n");
				res = false;
			}
			break;
		default:
			break;
		}
	}
	if (pcb_physaddr == 0) {
		hiber_printf("PT_FREEBSD_S4_PCB was not found\n");
		res = false;
		goto out;
	}
	if (tramp_physaddr == 0) {
		hiber_printf("PT_FREEBSD_S4_TRAMPOLINE was not found\n");
		res = false;
		goto out;
	}

out:
	if (phdrs != NULL)
		BS->FreePool(phdrs);
	return (res);
}

static void
digest_clear_image(struct hiber_image *img)
{
	if (img->segs != NULL)
		BS->FreePool(img->segs);
	if (img->tramp_bufs != NULL)
		BS->FreePool(img->tramp_bufs);
	memset(img, 0, sizeof(*img));
}

static bool
digest_image(struct hiber_image *img)
{
	Elf_Ehdr ehdr;
	Elf_Phdr *phdrs;
	const Elf_Phdr *ph;
	const struct trampoline_buf_desc *tbd;
	const struct trampoline_cont_buf_desc *tcbd;
	struct hiber_tramp_buf *htb;
	EFI_STATUS status;
	uint64_t ii, ii1;
	u_int i;
	bool res;

	res = false;
	phdrs = NULL;
	memset(img, 0, sizeof(*img));

	if (!hiber_read_img(0, &ehdr, sizeof(ehdr))) {
		hiber_printf("Cannot read ELF header\n");
		goto out;
	}
	status = BS->AllocatePool(EfiBootServicesData,
	    ehdr.e_phentsize * ehdr.e_phnum, (void *)&phdrs);
	if (status != EFI_SUCCESS) {
		hiber_printf("Cannot alloc memory for phdrs\n");
		goto out;
	}
	if (!hiber_read_img(ehdr.e_phoff, phdrs, ehdr.e_phentsize *
	    ehdr.e_phnum))
		goto out;

	for (ph = phdrs; ph < phdrs + ehdr.e_phnum; ph++) {
		switch (ph->p_type) {
		case PT_FREEBSD_S4_PCB:
			memcpy(&img->pcb, (void *)ph->p_paddr,
			    sizeof(img->pcb));
			break;
		case PT_FREEBSD_S4_TRAMPOLINE:
			tbd = (void *)ph->p_paddr;
			img->ntramp_bufs = 0;
			for (ii = 0; ii < tbd->num_bufs; ii++) {
				tcbd = &tbd->bufs[ii];
				img->ntramp_bufs += tcbd->num_pages;
			}
			status = BS->AllocatePool(EfiBootServicesData,
			    img->ntramp_bufs * sizeof(struct hiber_tramp_buf),
			    (void *)&img->tramp_bufs);
			if (status != EFI_SUCCESS) {
				hiber_printf("Cannot alloc memory for "
				    "trampoline pages descriptions\n");
				goto out;
			}
			htb = &img->tramp_bufs[0];
			for (ii = 0; ii < tbd->num_bufs; ii++) {
				tcbd = &tbd->bufs[ii];
				for (ii1 = 0; ii1 < tcbd->num_pages; ii1++) {
					htb->buf_paddr = tcbd->phys_addr +
					    HPAGE_SIZE * ii1;
					htb->tgt_paddr = 0;
					htb++;
				}
			}
			break;
		case PT_LOAD:
			img->nsegs++;
			break;
		default:
			break;
		}
	}
	status = BS->AllocatePool(EfiBootServicesData, img->nsegs *
	    sizeof(struct hiber_image_segment), (void *)&img->segs);
	if (status != EFI_SUCCESS) {
		hiber_printf("Cannot alloc memory for image segments\n");
		goto out;
	}
	for (ph = phdrs, i = 0; ph < phdrs + ehdr.e_phnum; ph++) {
		if (ph->p_type == PT_LOAD) {
			img->segs[i].paddr = ph->p_paddr;
			img->segs[i].len = ph->p_memsz;
			img->segs[i].img_off = ph->p_offset;
			i++;
		}
	}

	res = true;
out:
	if (phdrs != NULL)
		BS->FreePool(phdrs);
	if (!res)
		digest_clear_image(img);
	return (res);
}

static void
hms_shift_right(struct hiber_mem_segment *segs, struct hiber_mem_segment *hms,
    u_int nsegs)
{
	memmove(hms + 1, hms, (nsegs - (hms - segs)) * sizeof(*hms));
}

static bool
digest_uefi_runtime(const struct hiber_image *img,
    const struct hiber_uefi_memory_map *mm, struct hiber_mem_segment **segsp,
    u_int *nsegsp)
{
	const struct hiber_image_segment *his;
	const EFI_MEMORY_DESCRIPTOR *emd;
	struct hiber_mem_segment *segs, *hms, *hmsl, *hmsr;
	uint64_t emd_start, emd_end, hms_start, hms_end;
	EFI_STATUS status;
	u_int i, j, nsegs, max_segs;
	bool res;

	res = false;
	max_segs = (img->nsegs + 1) * (mm->ndescs + 1);
	segs = NULL;

	status = BS->AllocatePool(EfiBootServicesData, max_segs *
	    sizeof(struct hiber_mem_segment), (void *)&segs);
	if (status != EFI_SUCCESS) {
		hiber_printf("Cannot alloc memory for %u memory segments\n",
		    max_segs);
		goto out;
	}
	memset(segs, 0, max_segs * sizeof(struct hiber_mem_segment));

	nsegs = img->nsegs;
	for (i = 0; i < nsegs; i++) {
		his = &img->segs[i];
		hms = &segs[i];
		hms->paddr = his->paddr;
		hms->len = his->len;
		hms->img_off = his->img_off;
		hms->img_seg = his;
	}

	for (i = 0; i < nsegs; i++) {
		if (i >= max_segs) {
			hiber_printf("XXX\n");
			goto out;
		}
		hms = &segs[i];
		for (j = 0; j < mm->ndescs; j++) {
			/* hms might be modified below. */
			hms_start = hms->paddr;
			hms_end = hms->paddr + hms->len;

			emd = &mm->descs[j];
			emd_start = emd->PhysicalStart;
			emd_end = emd_start + emd->NumberOfPages * HPAGE_SIZE;

			/* Exact fit. */
			if (emd_start == hms_start && hms_end == emd_end) {
				hms->mm_desc = emd;
				continue;
			}
			/* Do not intersect. */
			if (emd_end <= hms_start || hms_end <= emd_start)
				continue;
			/* EFI segment covers whole hiber segment.*/
			if (emd_start < hms_start && hms_end < emd_end) {
				hms->mm_desc = emd;
				continue;
			}
			/* EFI segment contains the hiber segment start. */
			if (hms_start < emd_end && emd_end < hms_end) {
				if (nsegs + 1 > max_segs) {
					hiber_printf("XXX\n");
					goto out;
				}
				hms_shift_right(segs, hms, nsegs);
				hmsl = hms;
				hms++;
				hmsl->len = emd_end - hms_start;
				hmsl->mm_desc = emd;
				hms->paddr += hmsl->len;
				hms->len -= hmsl->len;
				MPASS(hms->len != 0);
				nsegs++;
				continue;
			}
			/* EFI segment contains the hiber segment end. */
			if (hms_start < emd_start && hms_end < emd_end) {
				if (nsegs + 1 > max_segs) {
					hiber_printf("XXX\n");
					goto out;
				}
				hms_shift_right(segs, hms, nsegs);
				hmsr = hms + 1;
				hms->len -= hms_end - emd_start;
				hms->mm_desc = emd;
				hmsr->paddr = emd_start;
				hmsr->len = hms_end - emd_start;
				nsegs++;
				continue;
			}
			/* EFI segment fully contained in the hiber segment. */
			if (nsegs + 2 > max_segs) {
				hiber_printf("XXX\n");
				goto out;
			}
			hms_shift_right(segs, hms, nsegs);
			hmsl = hms;
			hms++;
			hms_shift_right(segs, hms, nsegs);
			hmsr = hms + 1;
			hmsl->len = emd_start - hms_start;
			hms->paddr += hmsl->len;
			hms->len -= hmsl->len;
			MPASS(hms->len != 0);
			hms->mm_desc = emd;
			hmsr->paddr = hms->paddr + hms->len;
			hmsr->len = hms_end - emd_end;
			nsegs += 2;
		}
	}

	for (i = 0; i < nsegs; i++) {
		hms = &segs[i];
		if (hms->mm_desc == NULL) {
			hiber_printf("Address range [%#jx, %#jx] requires "
			    "loading, but is not described in UEFI memory "
			    "map\n", hms->paddr, hms->paddr + hms->len);
			res = false;
			goto out;
		}

		/* Calculate hms->precious. */
		switch (hms->mm_desc->Type) {
		/*
		 * Already free to use.
		 * XXXKIB Unaccepted is weird, not clear what to do with it.
		 */
		case EfiConventionalMemory:
		case EfiPersistentMemory:
		case EfiUnacceptedMemoryType:
			hms->precious = false;
			break;
		/*
		 * Memory that is converted by ExitBootServices to free.
		 */
		case EfiLoaderCode:
		case EfiLoaderData:
		case EfiBootServicesCode:
		case EfiBootServicesData:
			hms->precious = true;
			break;
		/*
		 * Memory that must be kept. A conflict prevents resume.
		 */
		case EfiRuntimeServicesCode:
		case EfiRuntimeServicesData:
		case EfiACPIReclaimMemory:
		case EfiACPIMemoryNVS:
		case EfiMemoryMappedIO:
		case EfiMemoryMappedIOPortSpace:
		case EfiPalCode:
		/* Memory in which errors have been detected. */
		case EfiUnusableMemory:
			hiber_printf("Address range [%#jx, %#jx] requires "
			    "loading, but is of not reusable type %d\n",
			    hms->paddr, hms->paddr + hms->len,
			    hms->mm_desc->Type);
			res = false;
			goto out;
		default:
			hiber_printf("Address range [%#jx, %#jx] requires "
			    "loading, but has unknown type %d\n",
			    hms->paddr, hms->paddr + hms->len,
			    hms->mm_desc->Type);
			res = false;
			goto out;
		}
	}
	/* XXXKIB Merge segments? */

	res = true;
	*nsegsp = nsegs;
	*segsp = segs;
out:
	if (!res && segs != NULL)
		BS->FreePool(segs);
	return (res);
}

// bread and meat
bool
hiber_restore(void)
{
	struct hiber_image img;
	struct hiber_uefi_memory_map mm, mm1;
	struct hiber_mem_segment *segs;
	uint64_t precious_sz;
	u_int i, nsegs;
	bool res;

	res = false;
	if (!digest_image(&img))
		goto out1;
	if (!hiber_get_mem_map(&mm, false))
		goto out2;
	if (!digest_uefi_runtime(&img, &mm, &segs, &nsegs))
		goto out3;

	for (precious_sz = 0, i = 0; i < nsegs; i++) {
		if (segs[i].precious)
			precious_sz += segs[i].len;
	}
	if (precious_sz > img.ntramp_bufs * HPAGE_SIZE) {
		hiber_printf("Resume requires %lu trampoline pages, "
		    "only %lu provided by the hibernated system\n",
		    precious_sz / HPAGE_SIZE, img.ntramp_bufs);
		goto out4;
	}
	img.ntramp_copy_pages = precious_sz / HPAGE_SIZE;

	// XXX
	if (!hiber_get_mem_map(&mm1, true))
		goto out4;
	if (mm1.map_key != mm.map_key) {
		hiber_printf("key changed, aborting\n");
		hiber_clear_mem_map(&mm1);
		goto out4;
	}
	hiber_clear_mem_map(&mm1);
	// XXX distribute precious
	// XXX load non-precious
	// XXX load precious
	// XXX trampoline();
	res = true;

out4:
	if (!res)
		BS->FreePool(segs);
out3:
	if (!res)
		hiber_clear_mem_map(&mm);
out2:
	if (!res)
		digest_clear_image(&img);
out1:
	return (res);
}
