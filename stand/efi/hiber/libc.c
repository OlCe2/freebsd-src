#include "hiber.h"

size_t
strlen(const char *str)
{
	size_t res;

	for (res = 0; str[res] != '\0'; res++)
		;
	return (res);
}

size_t
wstrlen(const CHAR16 *str)
{
	size_t res;

	for (res = 0; str[res] != '\0'; res++)
		;
	return (res);
}

void *
memset(void *dst, int c, size_t len)
{
	char *x;
	size_t i;

	for (i = 0, x = dst; i < len; x++, i++)
		*x = c;
	return (dst);
}

void *
memcpy(void *dst, const void *src, size_t len)
{
	char *x;
	const char *y;
	size_t i;

	for (i = 0, x = dst, y = src; i < len; x++, y++, i++)
		*x = *y;
	return (dst);
}

void *
memmove(void *dst, const void *src, size_t len)
{
	char *x;
	const char *y;
	size_t i;

	for (i = 0, x = dst + len - 1, y = src + len - 1; i < len;
	    x--, y--, i++)
		*x = *y;
	return (dst);
}
