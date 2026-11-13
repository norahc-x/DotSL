#include <windows.h>
#include <stdio.h>
#include <string.h>

static void report(const char *spec, DWORD flags)
{
    HMODULE m = LoadLibraryExA(spec, NULL, flags);
    char path[MAX_PATH];

    if (!m) {
        printf("load failed (err %lu)\n", GetLastError());
        return;
    }
    GetModuleFileNameA(m, path, MAX_PATH);
    printf("%s\n", path);
}

int main(int argc, char **argv)
{
    char self[MAX_PATH];
    char sysdir[MAX_PATH];
    char full[MAX_PATH];

    GetModuleFileNameA(NULL, self, MAX_PATH);
    printf("image: %s\n", self);

    if (argc < 2) {
        fprintf(stderr, "usage: %s <name|flags|full>\n", argv[0]);
        return 2;
    }
    if (!strcmp(argv[1], "name"))
        report("ism.dll", 0);
    else if (!strcmp(argv[1], "flags"))
        report("ism.dll", LOAD_LIBRARY_SEARCH_SYSTEM32);
    else if (!strcmp(argv[1], "full") &&
             GetSystemDirectoryA(sysdir, MAX_PATH) &&
             lstrlenA(sysdir) + 12 < MAX_PATH) {
        wsprintfA(full, "%s\\ism.dll", sysdir);
        report(full, 0);
    } else {
        fprintf(stderr, "unknown mode\n");
        return 2;
    }
    return 0;
}
