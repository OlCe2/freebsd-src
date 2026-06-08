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
	if (ehdr->e_type != ET_FREEBSD_HIBERNATE_IMAGE) {
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
	Elf_Phdr *phdrs, *ph;
	vm_paddr_t pcb_physaddr, cb_physaddr;
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
	cb_physaddr = 0;
	res = true;

	for (ph = phdrs; ph < phdrs + ehdr.e_phnum; ph++) {
		switch (ph->p_type) {
		case PT_FREEBSD_HIBERNATE_PCB:
			pcb_physaddr = ph->p_paddr;
			if (ph->p_filesz != sizeof(struct hibernate_pcb)) {
				hiber_printf(
				    "PT_FREEBSD_HIBERNATE_PCB file size "
				    "%#x not %#x\n",
				    ph->p_filesz, sizeof(struct hibernate_pcb));
				res = false;
				break;
			}
			if (ph->p_memsz != sizeof(struct hibernate_pcb)) {
				hiber_printf(
				    "PT_FREEBSD_HIBERNATE_PCB mem size "
				    "%#x not %#x\n",
				    ph->p_memsz, sizeof(struct hibernate_pcb));
				res = false;
				break;
			}
			break;
		case PT_FREEBSD_HIBERNATE_CB:
			cb_physaddr = ph->p_paddr;
			if (ph->p_filesz < hcb_size_spec(0)) {
				hiber_printf("PT_FREEBSD_HIBERNATE_CB "
				    "file size %#x too small\n", ph->p_filesz);
				res = false;
				break;
			}
			if (ph->p_memsz < hcb_size_spec(0)) {
				hiber_printf("PT_FREEBSD_HIBERNATE_CB "
				    "mem size %#x too small\n", ph->p_memsz);
				res = false;
				break;
			}
			break;
		case PT_LOAD:
			break;
		default:
			break;
		}
	}
	if (pcb_physaddr == 0) {
		hiber_printf("PT_FREEBSD_HIBERNATE_PCB was not found\n");
		res = false;
		goto out;
	}
	if (cb_physaddr == 0) {
		hiber_printf("PT_FREEBSD_HIBERNATE_CB was not found\n");
		res = false;
		goto out;
	}

out:
	if (!res) {
		if (phdrs != NULL)
			BS->FreePool(phdrs);
	}
	return (res);
}
