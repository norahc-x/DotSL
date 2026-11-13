// bounded local runtime: no CRT, no allocation, no globals
#ifndef RUNTIME_H
#define RUNTIME_H

#include <stddef.h>
#include <stdint.h>

int memcmp(const void *a, const void *b, size_t n);

// Regions must not overlap.
void *memcpy(void *dst, const void *src, size_t n);

// Case-insensitive exact match. A length mismatch is a mismatch.
int wide_eq_ci(const uint16_t *a, size_t alen,
                  const uint8_t *b, size_t blen);

// volatile stores; without it the compiler drops the wipe as dead code.
void wipe(void *p, size_t n);

#endif /* RUNTIME_H */
