#ifndef __HIBER_HIBER_H__
#define	__HIBER_HIBER_H__

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>

#include <efi.h>
#include <eficonsctl.h>
#include <Protocol/SimpleFileSystem.h>
#include <Protocol/ShellParameters.h>
#include <Protocol/Shell.h>

#include <machine/hibernate.h>
#include <hparams.h>

struct hiber_image_segment {
	uint64_t paddr;
	uint64_t len;
	uint64_t img_off;
};

struct hiber_tramp_buf {
	uint64_t buf_paddr;
	uint64_t tgt_paddr;
};

struct hiber_image {
	u_int nsegs;
	struct hiber_image_segment *segs;
	struct s4_pcb pcb;
	uint64_t ntramp_bufs;
	struct hiber_tramp_buf *tramp_bufs;
	uint64_t ntramp_copy_pages;
};

struct hiber_uefi_memory_map {
	UINTN ndescs;
	EFI_MEMORY_DESCRIPTOR *descs;
	UINTN map_key;
	UINTN desc_size;
	UINT32 desc_ver;
};

struct hiber_mem_segment {
	uint64_t paddr;
	uint64_t len;
	uint64_t img_off;
	bool precious;
	const struct hiber_image_segment *img_seg;
	const EFI_MEMORY_DESCRIPTOR *mm_desc;
};

/* hiber.c */
extern EFI_HANDLE IH;
extern EFI_SYSTEM_TABLE	*ST;
extern EFI_BOOT_SERVICES *BS;
extern EFI_RUNTIME_SERVICES *RS;
extern SIMPLE_TEXT_OUTPUT_INTERFACE *conout;
extern bool boot_services_active;

/* hyber.c */
bool hiber_read_img(uint64_t offset, void *buf, unsigned sz);
bool hiber_get_mem_map(struct hiber_uefi_memory_map *mm, bool only_key);
void hiber_clear_mem_map(struct hiber_uefi_memory_map *mm);

/* hiber_printf.c */
int hiber_snprintf(CHAR16 *buf, size_t bufsize, const char *fmt, ...);
int hiber_vsnprintf(CHAR16 *buf, size_t bufsize, const char *fmt, va_list ap);
int hiber_vprintf(const char *fmt, va_list ap);
int hiber_printf(const char *fmt, ...);
void hiber_putwstr(const CHAR16 *str);
void hiber_putwchar(int c);

/* libc.c */
size_t wstrlen(const CHAR16 *str);
void *memset(void *dest, int c, size_t len);
void *memcpy(void *dst, const void *src, size_t len);
void *memmove(void *dst, const void *src, size_t len);

/* restore.c */
bool hiber_check_format(void);
bool hiber_restore(void);

#define	MPASS(a)	/* XXX */

#endif
