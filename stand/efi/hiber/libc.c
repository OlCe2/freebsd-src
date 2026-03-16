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
