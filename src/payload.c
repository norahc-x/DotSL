#include "implant.h"

typedef int (*fn_message_box_a)(void *hwnd, const char *text,
                                const char *caption, unsigned int type);

void payload(context *ctx)
{
    fn_message_box_a message_box_a;
    void *fn = 0;
    unsigned int name[4];
    char caption[8];
    char text[12];

    if (!ctx)
        return;
    if (resolve_all(ctx) != OK)
        return;

// "user32.dll" as immediates; a literal would land in .rdata and be dropped.
    name[0] = 0x72657375u;   /* 'u' 's' 'e' 'r' */
    name[1] = 0x642E3233u;   /* '3' '2' '.' 'd' */
    name[2] = 0x00006C6Cu;   /* 'l' 'l' 0   0   */

// Prefer the module already mapped: loading it is the fallback.
    if (module_by_hash(ctx, HASH_USER32, &ctx->user32) != OK)
        ctx->user32 = ctx->load_library_a((const char *)name);

    if (!ctx->user32)
        return;
    if (export_by_hash(ctx, ctx->user32, HASH_MESSAGEBOXA, &fn) != OK)
        return;

    message_box_a = (fn_message_box_a)fn;

// "test" / "dotlocal" as immediates; both terminated explicitly.
    caption[0] = 't'; caption[1] = 'e'; caption[2] = 's'; caption[3] = 't';
    caption[4] = 0;

    text[0] = 'd'; text[1] = 'o'; text[2] = 't'; text[3] = 'l';
    text[4] = 'o'; text[5] = 'c'; text[6] = 'a'; text[7] = 'l';
    text[8] = 0;

    message_box_a(0, text, caption, 0u);
}
