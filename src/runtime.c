// bounded local runtime
#include "runtime.h"

int memcmp(const void *a, const void *b, size_t n)
{
    const uint8_t *x = (const uint8_t *)a;
    const uint8_t *y = (const uint8_t *)b;

    for (; n--; x++, y++) {
        if (*x != *y)
            return (int)*x - (int)*y;
    }
    return 0;
}

void *memcpy(void *dst, const void *src, size_t n)
{
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;

// The caller owns the overlap contract.
    for (; n--; d++, s++)
        *d = *s;
    return dst;
}

static uint8_t fold(uint8_t c)
{
    return (c >= 'A' && c <= 'Z') ? (uint8_t)(c + 0x20) : c;
}

int wide_eq_ci(const uint16_t *a, size_t alen,
                  const uint8_t *b, size_t blen)
{
    size_t n;

    if (alen != blen)
        return 0;
    for (n = 0; n < alen; n++) {
        if (fold((uint8_t)(a[n] & 0xFF)) != fold(b[n]))
            return 0;
    }
    return 1;
}

void wipe(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;

    while (n--)
        *v++ = 0;
}
