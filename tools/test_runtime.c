/*
 * bellatrix -- unit tests for the bounded runtime primitives.
 *
 * These are the functions everything else leans on, so the edge cases are
 * the point: zero length, first/middle/last byte, and length disagreement.
 */
#include <stdio.h>
#include <string.h>

#include "runtime.h"

static int fails;

static void ok(int cond, const char *what)
{
    if (!cond) {
        printf("  FAIL  %s\n", what);
        fails++;
    } else {
        printf("  ok    %s\n", what);
    }
}

static void test_memcmp(void)
{
    const char a[] = "abcde";
    const char b[] = "abcde";
    const char c[] = "abcdf";
    const char d[] = "bbcde";
    const char e[] = "abXde";

    ok(memcmp(a, b, 5) == 0, "memcmp: identical");
    ok(memcmp(a, b, 0) == 0, "memcmp: zero length");
    ok(memcmp(a, d, 5) != 0, "memcmp: differs at first byte");
    ok(memcmp(a, e, 5) != 0, "memcmp: differs in the middle");
    ok(memcmp(a, c, 5) != 0, "memcmp: differs at last byte");
    ok(memcmp(a, c, 4) == 0, "memcmp: bound excludes the difference");
    ok(memcmp(a, c, 5) < 0, "memcmp: ordering is unsigned-lexicographic");
}

static void test_memcpy(void)
{
    unsigned char src[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    unsigned char dst[8] = { 0 };
    void *ret;

    ret = memcpy(dst, src, 8);
    ok(ret == dst, "memcpy: returns destination");
    ok(memcmp(dst, src, 8) == 0, "memcpy: copies all bytes");

    memset(dst, 0, sizeof dst);
    memcpy(dst, src, 3);
    ok(memcmp(dst, src, 3) == 0, "memcpy: partial copy writes n bytes");
    ok(dst[3] == 0, "memcpy: partial copy leaves the tail alone");
}

static void test_wide_eq_ci(void)
{
    /* "Kernel32" in UTF-16, mixed case. */
    const uint16_t w[] = { 'K','e','r','n','e','l','3','2' };
    const uint8_t  lower[]  = "kernel32";
    const uint8_t  upper[]  = "KERNEL32";
    const uint8_t  mixed[]  = "KeRnEl32";
    const uint8_t  short_[] = "kernel3";
    const uint8_t  long_[]  = "kernel323";
    const uint8_t  wrong[]  = "kernel33";

    ok(wide_eq_ci(w, 8, lower, 8) == 1, "wide_eq: exact");
    ok(wide_eq_ci(w, 8, upper, 8) == 1, "wide_eq: case folded");
    ok(wide_eq_ci(w, 8, mixed, 8) == 1, "wide_eq: mixed case");
    ok(wide_eq_ci(w, 8, short_, 7) == 0, "wide_eq: shorter name is not a match");
    ok(wide_eq_ci(w, 8, long_, 9) == 0, "wide_eq: longer name is not a match");
    ok(wide_eq_ci(w, 8, wrong, 8) == 0, "wide_eq: last byte differs");
    ok(wide_eq_ci(w, 0, lower, 0) == 1, "wide_eq: both empty");
    ok(wide_eq_ci(w, 0, lower, 8) == 0, "wide_eq: empty vs non-empty");
}

int main(void)
{
    printf("runtime primitives\n");
    test_memcmp();
    test_memcpy();
    test_wide_eq_ci();
    printf(fails ? "\n%d FAILURES\n" : "\nall pass\n", fails);
    return fails ? 1 : 0;
}