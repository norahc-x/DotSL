// stage-1 payload contract
#ifndef IMPLANT_H
#define IMPLANT_H

#include "resolve.h"

// Runs on the caller's thread. Allocates nothing. Returns normally.
void payload(context *ctx);

#endif /* IMPLANT_H */
