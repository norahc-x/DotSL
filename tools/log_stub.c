/* log_stub: runtime contract probe for appraiser.dll's export surface.
 *
 * Stands in for the real plugin behind the .local marker and logs every
 * export call (name, four register arguments, caller return address) to
 * log.txt beside itself. Returns E_FAIL so the caller's failure handling
 * is what gets exercised.
 */
#include <windows.h>
#include <stdio.h>

static void log_call(const char *name, void *a1, void *a2, void *a3, void *a4)
{
    char line[256];
    HANDLE f;
    int n;

    n = wsprintfA(line, "%-28s rcx=%p rdx=%p r8=%p r9=%p ret=%p\r\n",
                  name, a1, a2, a3, a4, __builtin_return_address(0));
    f = CreateFileA("log.txt", FILE_APPEND_DATA, 0, NULL,
                    OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f != INVALID_HANDLE_VALUE) {
        WriteFile(f, line, n, NULL, NULL);
        CloseHandle(f);
    }
}

#define STUB(name)                                                  \
    __declspec(dllexport) long name(void *a1, void *a2,             \
                                    void *a3, void *a4)             \
    {                                                               \
        log_call(#name, a1, a2, a3, a4);                            \
        return (long)0x80004005;                                    \
    }

STUB(DoProcessRestoreApps)
STUB(DoScheduledTelemetryRun)
STUB(DoScheduledTelemetryRunTC)
STUB(GetCtacProvider)
STUB(GetProvider)
STUB(GetTargetVersionList)
STUB(ProcessRestoreApps)
STUB(RunTest)
STUB(RunXml)
STUB(Sgd)
STUB(UpdateAvStatus)
STUB(UpdateCacheCompatStatuses)
STUB(UpdateExperienceIndicators)

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        DisableThreadLibraryCalls(h);
    return TRUE;
}
