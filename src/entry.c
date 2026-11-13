// C entry: proves the ABI and the section layout.
#include "implant.h"

_Static_assert(sizeof(context) == 64,
               "context size must match CTX_BYTES in asm/entry_x64.asm");
_Static_assert(sizeof(context) % 16 == 0, "context must not break alignment");

void stage_main(context *ctx)
{
    if (!ctx || !ctx->peb)
        return;
    payload(ctx);
}
