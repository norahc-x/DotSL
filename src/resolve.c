// module and export resolution through the PEB loader list
#include "resolve.h"
#include "runtime.h"

// hash
// Count comes from the UNICODE_STRING length, not from a NUL.
static uint32_t hash_wide_lower(const uint16_t *s, uint32_t count)
{
    uint32_t h = HASH_SEED, n;
    for (n = 0; n < count; n++) {
        h = (h ^ (uint32_t)((s[n] & 0xFFu) | 0x20u)) * HASH_PRIME;
    }
    return h ^ HASH_POST;
}

static uint32_t hash_ascii(const uint8_t *s, uint32_t max_bytes)
{
    uint32_t h = HASH_SEED, n = 0;
    while (n < max_bytes && *s) {
        h = (h ^ (uint32_t)*s) * HASH_PRIME;
        s++;
        n++;
    }
    return h ^ HASH_POST;
}

// bounds
// True when [rva, rva+need) lies inside an image of image_size bytes.
static int rva_ok(uint32_t rva, uint32_t need, uint32_t image_size)
{
    return rva != 0 && rva <= image_size && need <= image_size - rva;
}

// The size the loader mapped; the only trustworthy bound on image reads.
static uint32_t module_mapped_size(context *ctx, const void *base)
{
    list_entry *head, *cur;
    uint32_t n = 0;

    if (!ctx || !ctx->peb || !ctx->peb->ldr)
        return 0;
    head = &ctx->peb->ldr->in_load_order;
    for (cur = head->flink; cur && cur != head && n < MAX_MODULES;
         cur = cur->flink, n++) {
        ldr_entry *e = (ldr_entry *)cur;
        if (e->dll_base == base)
            return e->size_of_image;
    }
    return 0;
}

// Export directory of a mapped image. mapped_size bounds every header read.
#define MAX_HEADERS 0x1000

static enum status image_exports(const uint8_t *base, uint32_t mapped_size,
                                    uint32_t *exp_rva,
                                    uint32_t *exp_size, uint32_t *image_size)
{
    const dos_header *dos = (const dos_header *)base;
    const nt64 *nt;
    uint32_t lfanew, hdr_limit;

    if (dos->magic[0] != 'M' || dos->magic[1] != 'Z')
        return E_BAD_IMAGE;

    hdr_limit = mapped_size ? mapped_size : MAX_HEADERS;
    lfanew = (uint32_t)dos->e_lfanew;
    if (dos->e_lfanew <= 0 || !rva_ok(lfanew, sizeof(nt64), hdr_limit))
        return E_BAD_IMAGE;

    nt = (const nt64 *)(base + lfanew);
    if (nt->signature != PE_SIGNATURE)
        return E_BAD_IMAGE;
    if (nt->machine != MACHINE_AMD64)
        return E_BAD_IMAGE;
    if (nt->optional.magic != OPT_MAGIC_PE32P)
        return E_BAD_IMAGE;
    if (nt->optional.number_of_rva <= DIR_EXPORT)
        return E_NO_EXPORT;

    *image_size = nt->optional.size_of_image;
    if (*image_size == 0)
        return E_BAD_IMAGE;
// Must not claim more than was mapped, and must contain the headers above.
    if (mapped_size && *image_size > mapped_size)
        return E_BAD_IMAGE;
    if (*image_size < lfanew + sizeof(nt64))
        return E_BAD_IMAGE;

    *exp_rva  = nt->optional.dir[DIR_EXPORT].rva;
    *exp_size = nt->optional.dir[DIR_EXPORT].size;

    if (!rva_ok(*exp_rva, sizeof(export_dir), *image_size))
        return E_BAD_IMAGE;

    return OK;
}

// module lookup
// Walk the loader list once; used by both the hash and the name lookup.
static void *find_module(context *ctx, uint32_t want_hash,
                         const uint8_t *want_name, uint32_t name_len)
{
    list_entry *head;
    list_entry *cur;
    uint32_t n = 0;

    if (!ctx || !ctx->peb || !ctx->peb->ldr)
        return 0;

    head = &ctx->peb->ldr->in_load_order;
    for (cur = head->flink; cur && cur != head && n < MAX_MODULES;
         cur = cur->flink, n++) {
        ldr_entry *e = (ldr_entry *)cur;   /* in_load_order is first */
        uint32_t chars;
        if (!e->dll_base || !e->base_name.buffer || !e->base_name.length)
            continue;
        chars = e->base_name.length / 2;
        if (want_name) {
            if (wide_eq_ci(e->base_name.buffer, chars, want_name, name_len))
                return e->dll_base;
        } else if (hash_wide_lower(e->base_name.buffer, chars) == want_hash) {
            return e->dll_base;
        }
    }
    return 0;
}

// ASCII base name as the api-set schema spells it.
static uint32_t module_name_ascii(context *ctx, const void *base,
                                  uint8_t *out, uint32_t max)
{
    list_entry *head, *cur;
    uint32_t n = 0;

    if (!ctx || !ctx->peb || !ctx->peb->ldr)
        return 0;
    head = &ctx->peb->ldr->in_load_order;
    for (cur = head->flink; cur && cur != head && n < MAX_MODULES;
         cur = cur->flink, n++) {
        ldr_entry *e = (ldr_entry *)cur;
        uint32_t chars, k;

        if (e->dll_base != base || !e->base_name.buffer || !e->base_name.length)
            continue;
        chars = e->base_name.length / 2;
        if (!chars || chars >= max)
            return 0;
        for (k = 0; k < chars; k++)
            out[k] = (uint8_t)(e->base_name.buffer[k] & 0xFF);
        return chars;
    }
    return 0;
}

// Case-insensitive prefix test; forwarder strings are free text.
static int ci_prefix(const uint8_t *s, const char *p, uint32_t n)
{
    uint32_t i;
    for (i = 0; i < n; i++) {
        uint8_t c = s[i];
        if (c >= 'A' && c <= 'Z')
            c = (uint8_t)(c - 'A' + 'a');
        if (c != (uint8_t)p[i])
            return 0;
    }
    return 1;
}

static int is_apiset_name(const uint8_t *s, uint32_t len)
{
    return (len >= 7 && ci_prefix(s, "api-ms-", 7))
        || (len >= 7 && ci_prefix(s, "ext-ms-", 7));
}


static int apiset_span(uint32_t off, uint32_t len, uint32_t size)
{
    return off <= size && len <= size - off;
}


static int apiset_span_n(uint32_t off, uint32_t count, uint32_t rec,
                         uint32_t size)
{
    if (!rec || count > size / rec)
        return 0;
    return apiset_span(off, count * rec, size);
}


static void *api_set_module(context *ctx, const uint8_t *name,
                            uint32_t name_len,
                            const uint8_t *req, uint32_t req_len)
{
    const apiset_ns *ns;
    const apiset_entry *ent;
    uintptr_t base;
    uint32_t i, j, k, qhash, pass;

    if (!ctx || !ctx->peb || !ctx->peb->api_set_map)
        return 0;

    ns = (const apiset_ns *)ctx->peb->api_set_map;
    if (ns->version != APISET_VERSION)
        return 0;
    if (!ns->size || ns->size < sizeof(apiset_ns))
        return 0;
    if (!ns->count || ns->count > MAX_APISET)
        return 0;

    base = (uintptr_t)ns;
    if (!apiset_span_n(ns->entry_offset, ns->count,
                       sizeof(apiset_entry), ns->size))
        return 0;
    ent = (const apiset_entry *)(base + ns->entry_offset);

// Hash the query as the schema does: drop the trailing version segment.
    qhash = 0;
    for (k = 0; k < name_len; k++)
        if (name[k] == '-')
            qhash = k;
    if (!qhash)
        return 0;

    for (i = 0; i < ns->count; i++) {
        const uint16_t *nm;
        const apiset_value *val;

// The name and its hashed prefix must both be inside the namespace.
        if (ent[i].hashed_length > ent[i].name_length)
            continue;
        if (!apiset_span(ent[i].name_offset, ent[i].name_length, ns->size))
            continue;
        nm = (const uint16_t *)(base + ent[i].name_offset);

        if (ent[i].hashed_length / 2 != qhash)
            continue;
        if (!wide_eq_ci(nm, qhash, name, qhash))
            continue;
        if (!ent[i].value_count)
            return 0;

        if (!apiset_span_n(ent[i].value_offset, ent[i].value_count,
                           sizeof(apiset_value), ns->size))
            return 0;
        val = (const apiset_value *)(base + ent[i].value_offset);
// Alias names the requesting module, breaking circularity.
        for (pass = 0; pass < 2; pass++) {
            for (j = 0; j < ent[i].value_count && j < MAX_MODULES; j++) {
                const uint16_t *alias;
                uint32_t alen;
                const uint16_t *host;
                uint32_t hlen;
                uint8_t hostb[64];
                void *m;

                if (!apiset_span(val[j].name_offset, val[j].name_length,
                                 ns->size))
                    continue;
                if (!apiset_span(val[j].value_offset, val[j].value_length,
                                 ns->size))
                    continue;

                alias = (const uint16_t *)(base + val[j].name_offset);
                alen = val[j].name_length / 2;

                if (pass == 0) {
                    if (!alen || alen != req_len)
                        continue;
                    if (!wide_eq_ci(alias, alen, req, req_len))
                        continue;
                } else {
                    if (alen)
                        continue;
                }

                host = (const uint16_t *)(base + val[j].value_offset);
                hlen = val[j].value_length / 2;
                if (!hlen || hlen >= sizeof hostb)
                    continue;
                for (k = 0; k < hlen; k++)
                    hostb[k] = (uint8_t)(host[k] & 0xFF);

                m = find_module(ctx, 0, hostb, hlen);
                if (m)
                    return m;
            }
        }
        return 0;
    }
    return 0;
}

enum status module_by_hash(context *ctx, uint32_t hash, void **out)
{
    void *m;
    if (!out)
        return E_BUFFER;
    m = find_module(ctx, hash, 0, 0);
    if (!m)
        return E_NO_MODULE;
    *out = m;
    return OK;
}

// export lookup
static enum status export_lookup(const uint8_t *base, uint32_t mapped_size,
                                    uint32_t want_hash, int by_ordinal,
                                    uint16_t want_ordinal,
                                    uint32_t *fn_rva, uint32_t *exp_rva,
                                    uint32_t *exp_size, uint32_t *image_size)
{
    uint32_t rva, size, isz;
    const export_dir *exp;
    uint32_t i, count;

    rva = size = 0;
    {
        enum status s = image_exports(base, mapped_size,
                                         &rva, &size, image_size);
        if (s != OK)
            return s;
    }
    exp = (const export_dir *)(base + rva);
    isz = *image_size;

    if (by_ordinal) {
// The ordinal is external; subtract the base before indexing the EAT.
        uint32_t idx;
        if (want_ordinal < exp->ordinal_base)
            return E_NO_EXPORT;
        idx = (uint32_t)want_ordinal - exp->ordinal_base;
        if (idx >= exp->number_of_functions)
            return E_NO_EXPORT;
        if (!rva_ok(exp->address_of_functions, (idx + 1) * 4, isz))
            return E_BAD_IMAGE;
        *fn_rva = ((const uint32_t *)(base + exp->address_of_functions))[idx];
    } else {
        count = exp->number_of_names;
        if (count > MAX_EXPORTS)
            count = MAX_EXPORTS;
        if (!rva_ok(exp->address_of_names, count * 4, isz) ||
            !rva_ok(exp->address_of_name_ordinals, count * 2, isz))
            return E_BAD_IMAGE;

        for (i = 0; i < count; i++) {
            uint32_t name_rva =
                ((const uint32_t *)(base + exp->address_of_names))[i];
            uint16_t ord;
            if (!rva_ok(name_rva, 1, isz))
                continue;
            if (hash_ascii(base + name_rva, isz - name_rva) != want_hash)
                continue;
            ord = ((const uint16_t *)(base + exp->address_of_name_ordinals))[i];
            if (!rva_ok(exp->address_of_functions,
                        ((uint32_t)ord + 1) * 4, isz))
                return E_BAD_IMAGE;
            *fn_rva = ((const uint32_t *)(base + exp->address_of_functions))[ord];
            break;
        }
        if (i == count)
            return E_NO_EXPORT;
    }

    if (!*fn_rva)
        return E_NO_EXPORT;

    *exp_rva  = rva;
    *exp_size = size;
    return OK;
}

// A forwarder is an RVA inside the export directory pointing at "MODULE.FUNC".
static enum status resolve_forwarder(context *ctx, const uint8_t *base,
                                        uint32_t fn_rva, uint32_t image_size,
                                        void **out, int depth,
                                        void **seen, int nseen);

static enum status resolve_export(context *ctx, const uint8_t *base,
                                     uint32_t want_hash, int by_ordinal,
                                     uint16_t want_ordinal, void **out,
                                     int depth, void **seen, int nseen)
{
    uint32_t fn_rva = 0, exp_rva = 0, exp_size = 0, image_size = 0;
    enum status s;

    if (depth > MAX_FORWARD_DEPTH)
        return E_FORWARD_DEPTH;

    s = export_lookup(base, module_mapped_size(ctx, base),
                      want_hash, by_ordinal, want_ordinal,
                      &fn_rva, &exp_rva, &exp_size, &image_size);
    if (s != OK)
        return s;

    if (fn_rva >= exp_rva && fn_rva - exp_rva < exp_size)
        return resolve_forwarder(ctx, base, fn_rva,
                                 image_size, out, depth + 1, seen, nseen);

    if (!rva_ok(fn_rva, 1, image_size))
        return E_BAD_IMAGE;

    *out = (void *)(base + fn_rva);
    return OK;
}

static enum status resolve_forwarder(context *ctx, const uint8_t *base,
                                        uint32_t fn_rva, uint32_t image_size,
                                        void **out, int depth,
                                        void **seen, int nseen)
{
    const uint8_t *s = base + fn_rva;
    uint32_t max = image_size - fn_rva;
    uint32_t n = 0, dot = 0;
    uint8_t mod[128];
    uint32_t mod_len;
    int has_ext, suffix;
    void *target;
    int i;

    if (max > 256)
        max = 256;
    while (n < max && s[n])
        n++;
    if (n == 0 || n >= max)
        return E_BAD_IMAGE;

// Split at the last '.': the function name never contains one.
    for (i = (int)n - 1; i >= 0; i--) {
        if (s[i] == '.') { dot = (uint32_t)i; break; }
    }
    if (dot == 0 || dot + 1 >= n)
        return E_BAD_IMAGE;

    mod_len = dot;
// Forwarder names omit the extension; append ".dll" unless already present.
    has_ext = 0;
    for (i = 0; i < (int)mod_len; i++)
        if (s[i] == '.') has_ext = 1;
    suffix = has_ext ? 0 : 4;

    if (mod_len + suffix >= sizeof mod)
        return E_BUFFER;
    for (i = 0; i < (int)mod_len; i++)
        mod[i] = s[i];
    if (suffix) {
        mod[mod_len + 0] = '.';
        mod[mod_len + 1] = 'd';
        mod[mod_len + 2] = 'l';
        mod[mod_len + 3] = 'l';
    }
    mod[mod_len + suffix] = 0;
    mod_len += suffix;

// api-set targets are contracts: resolve the schema before looking up.
    if (is_apiset_name(s, dot)) {
        uint8_t req[64];
        uint32_t req_len = module_name_ascii(ctx, base, req, sizeof req);
        target = api_set_module(ctx, s, dot, req, req_len);
    } else {
        target = find_module(ctx, 0, mod, mod_len);
    }
    if (!target)
        return E_NO_MODULE;

    for (i = 0; i < nseen && i < MAX_SEEN; i++) {
        if (seen[i * 2] == (void *)base &&
            seen[i * 2 + 1] == (void *)(uintptr_t)fn_rva)
            return E_FORWARD_CYCLE;
    }
    if (nseen < MAX_SEEN) {
        seen[nseen * 2] = (void *)base;
        seen[nseen * 2 + 1] = (void *)(uintptr_t)fn_rva;
        nseen++;
    }

    if (s[dot + 1] == '#') {
        uint32_t ord = 0, k = dot + 2;
        if (k >= n)
            return E_BAD_IMAGE;
        for (; k < n; k++) {
            if (s[k] < '0' || s[k] > '9')
                return E_BAD_IMAGE;
            ord = ord * 10 + (uint32_t)(s[k] - '0');
            if (ord > 0xFFFF)
                return E_BAD_IMAGE;
        }
        return resolve_export(ctx, target, 0, 1, (uint16_t)ord, out,
                              depth, seen, nseen);
    }

    return resolve_export(ctx, target,
                          hash_ascii(s + dot + 1, n - dot - 1), 0, 0,
                          out, depth, seen, nseen);
}

enum status export_by_hash(context *ctx, void *module, uint32_t hash,
                                 void **out)
{
    void *seen[MAX_SEEN * 2];
    enum status s;

    if (!ctx || !module || !out)
        return E_BUFFER;
    s = resolve_export(ctx, (const uint8_t *)module, hash, 0, 0,
                       out, 0, seen, 0);
    if (s != OK)
        ctx->last_status = (uint32_t)s;
    return s;
}

enum status export_by_ordinal(context *ctx, void *module,
                                    uint16_t ordinal, void **out)
{
    void *seen[MAX_SEEN * 2];
    enum status s;

    if (!ctx || !module || !out)
        return E_BUFFER;
    s = resolve_export(ctx, (const uint8_t *)module, 0, 1, ordinal,
                       out, 0, seen, 0);
    if (s != OK)
        ctx->last_status = (uint32_t)s;
    return s;
}

enum status resolve_all(context *ctx)
{
    void *fn;
    enum status s;

    if (!ctx)
        return E_BUFFER;

    s = module_by_hash(ctx, HASH_KERNEL32, &ctx->kernel32);
    if (s != OK)
        return s;

    s = export_by_hash(ctx, ctx->kernel32, HASH_LOADLIBRARYA, &fn);
    if (s != OK)
        return s;
    ctx->load_library_a = (fn_load_library_a)fn;

    s = export_by_hash(ctx, ctx->kernel32, HASH_GETPROCADDRESS, &fn);
    if (s != OK)
        return s;
    ctx->get_proc_address = (fn_get_proc_address)fn;

    return OK;
}
