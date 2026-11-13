/*
 * bellatrix -- resolver self-test.
 *
 * Runs on the host, not in the blob. Resolves kernel32 and two of its exports
 * through the PEB walker and compares each result against the loader's own
 * answer. If either the hash parameters or the resolver drift, the two
 * disagree and the test fails.
 */
#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#include "resolve.h"

static int check(const char *what, void *got, void *want)
{
    int ok = (got == want);
    printf("  %-18s resolver=%p  loader=%p  %s\n",
           what, got, want, ok ? "OK" : "MISMATCH");
    return ok ? 0 : 1;
}

/*
 * Independent copy of the hash, written from the contract rather than from
 * resolve.c. If the two ever disagree the tests fail loudly, which is the
 * only thing that would catch a drift in either direction.
 */
static uint32_t t_hash(const char *s)
{
    uint32_t h = HASH_SEED;
    while (*s) {
        h = (h ^ (uint32_t)(uint8_t)*s++) * HASH_PRIME;
    }
    return h ^ HASH_POST;
}

/*
 * A forwarded export is one whose EAT slot points back inside the export
 * directory, at a "MODULE.FUNC" or "MODULE.#ORD" string. Walk the real
 * kernel32 table, find them, and resolve each one back through the loader's
 * own answer.
 */
static int test_forwarders(context *ctx, void *k32)
{
    const uint8_t *base = (const uint8_t *)k32;
    uint32_t lfanew = *(const uint32_t *)(base + 0x3C);
    const uint8_t *nt = base + lfanew;
    uint32_t exp_rva = *(const uint32_t *)(nt + 0x88);  /* data dir 0 */
    uint32_t exp_sz  = *(const uint32_t *)(nt + 0x8C);
    uint32_t image   = *(const uint32_t *)(nt + 0x50);  /* SizeOfImage */
    const uint8_t *exp = base + exp_rva;
    uint32_t nnames   = *(const uint32_t *)(exp + 0x18);
    uint32_t names_rv = *(const uint32_t *)(exp + 0x20);
    uint32_t ords_rv  = *(const uint32_t *)(exp + 0x24);
    uint32_t funcs_rv = *(const uint32_t *)(exp + 0x1C);
    uint32_t i, found = 0, checked = 0, bad = 0;

    (void)image;
    for (i = 0; i < nnames && checked < 40; i++) {
        uint32_t name_rv = *(const uint32_t *)(base + names_rv + i * 4);
        uint16_t ord     = *(const uint16_t *)(base + ords_rv + i * 2);
        uint32_t fn_rv   = *(const uint32_t *)(base + funcs_rv + ord * 4);
        const char *name = (const char *)(base + name_rv);
        void *got, *want;
        char label[64];
        int j;

        if (fn_rv < exp_rva || fn_rv - exp_rva >= exp_sz)
            continue;                       /* not a forwarder */

        found++;
        for (j = 0; name[j] && j < 63; j++)
            label[j] = name[j];
        label[j] = 0;

        if (export_by_hash(ctx, k32, t_hash(name), &got) == OK) {
            want = (void *)GetProcAddress((HMODULE)k32, name);
            if (got != want) {
                printf("  forwarder          %-24s MISMATCH\n", label);
                bad = 1;
            }
            checked++;
        } else if (found - checked < 6) {
            void *lw = (void *)GetProcAddress((HMODULE)k32, name);
            printf("    refused (status %u): %-28s loader=%p\n",
                   ctx->last_status, label, lw);
        }
    }

    printf("  forwarders         %u scanned, %u resolved and matched,"
           " %u refused\n", found, checked, found - checked);
    if (checked == 0) {
        printf("  forwarder          NONE EXERCISED -- test is vacuous\n");
        return 1;
    }
    return bad;
}

int main(void)
{
    context ctx;
    void *k32 = 0, *fn_load = 0, *fn_get = 0;
    void *real_k32, *real_load, *real_get;
    int bad = 0;

    /* The blob reads this from gs:0x60 in the entry stub. */
    ctx.peb = (peb *)NtCurrentTeb()->ProcessEnvironmentBlock;
    ctx.blob_base = 0;
    ctx.blob_size = 0;
    ctx.kernel32 = 0;
    ctx.user32 = 0;
    ctx.load_library_a = 0;
    ctx.get_proc_address = 0;
    ctx.last_status = 0;

    real_k32 = GetModuleHandleA("kernel32.dll");
    real_load = (void *)GetProcAddress(real_k32, "LoadLibraryA");
    real_get = (void *)GetProcAddress(real_k32, "GetProcAddress");

    if (module_by_hash(&ctx, HASH_KERNEL32, &k32) != OK) {
        printf("  kernel32           NOT FOUND (status=%u)\n", ctx.last_status);
        return 1;
    }
    bad |= check("kernel32", k32, real_k32);

    if (export_by_hash(&ctx, k32, HASH_LOADLIBRARYA, &fn_load) != OK) {
        printf("  LoadLibraryA       NOT FOUND (status=%u)\n", ctx.last_status);
        return 1;
    }
    bad |= check("LoadLibraryA", fn_load, real_load);

    if (export_by_hash(&ctx, k32, HASH_GETPROCADDRESS, &fn_get) != OK) {
        printf("  GetProcAddress     NOT FOUND (status=%u)\n", ctx.last_status);
        return 1;
    }
    bad |= check("GetProcAddress", fn_get, real_get);

    /* resolve_all must produce the same answers through the typed
     * pointers it deposits in the context. */
    if (resolve_all(&ctx) != OK) {
        printf("  resolve_all        FAILED (status=%u)\n", ctx.last_status);
        return 1;
    }
    printf("  resolve_all        kernel32=%p load=%p get=%p\n",
           ctx.kernel32, (void *)ctx.load_library_a,
           (void *)ctx.get_proc_address);
    if (ctx.kernel32 != real_k32 ||
        (void *)ctx.load_library_a != real_load ||
        (void *)ctx.get_proc_address != real_get) {
        printf("  resolve_all        MISMATCH with the loader\n");
        bad = 1;
    } else {
        printf("  resolve_all        OK -- typed pointers match\n");
    }

    bad |= test_forwarders(&ctx, real_k32);

    /* A name that must not resolve is as important as one that must. */
    if (module_by_hash(&ctx, 0xDEADBEEFu, &k32) == OK) {
        printf("  negative module    RESOLVED -- bounds or hash broken\n");
        bad = 1;
    } else {
        printf("  negative module    correctly refused\n");
    }
    if (export_by_hash(&ctx, real_k32, 0xDEADBEEFu, &fn_load) == OK) {
        printf("  negative export    RESOLVED -- hash broken\n");
        bad = 1;
    } else {
        printf("  negative export    correctly refused\n");
    }

    printf(bad ? "\nFAIL\n" : "\nall agree\n");
    return bad;
}
