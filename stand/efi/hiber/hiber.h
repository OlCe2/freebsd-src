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

/* hiber.c */
extern EFI_HANDLE IH;
extern EFI_SYSTEM_TABLE	*ST;
extern EFI_BOOT_SERVICES *BS;
extern EFI_RUNTIME_SERVICES *RS;
extern SIMPLE_TEXT_OUTPUT_INTERFACE *conout;
extern bool boot_services_active;

/* hyber.c */
bool hiber_read_img(uint64_t offset, void *buf, unsigned sz);

/* hiber_printf.c */
int hiber_snprintf(CHAR16 *buf, size_t bufsize, const char *fmt, ...);
int hiber_vsnprintf(CHAR16 *buf, size_t bufsize, const char *fmt, va_list ap);
int hiber_vprintf(const char *fmt, va_list ap);
int hiber_printf(const char *fmt, ...);
void hiber_putwstr(const CHAR16 *str);
void hiber_putwchar(int c);

/* libc.c */
size_t wstrlen(const CHAR16 *str);

/* restore.c */
bool hiber_check_format(void);

#endif
