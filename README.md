# DotLocal Shadow Loading

I call this implementation **DotLocal Shadow Loading**. *DotLocal* refers to
Windows' documented `.local` redirection; *Shadow Loading* describes the
package DLL loading in place of the system copy. For background on the
mechanism, search for **Windows DLL redirection (.local)** or **DotLocal**.

The current implementation runs code inside a legitimate Windows host. In the
reported test, `compattelrunner.exe` loads the package's `appraiser.dll` only
with the marker present. 

The mechanism dates from the Windows XP era and
was explored by Hexacorn in 2015 clearly explaining what it is and calling 
it 'the god of all persistence mechanisms'.
as explained by Hexacorn this implementation is a debugging feature, and more precisely defining it as a redirection mechanism designed to test COM objects.

The important thing that caught my eye while reading the blog was when it described the fact that when a file or directory called <filename.exe>.local is created, Windows will treat it as a test-in-progress signal and will attempt to load DLLs from a different directory than usual. So I decided to reuse the same concept adapted for initial access, an implementation that I couldn't find anywhere during my research.

```text
test.pdf.lnk
  └─> compattelrunner.exe -m:appraiser.dll -f:DoScheduledTelemetryRun
        └─> compattelrunner.exe.local
              └─> appraiser.dll → payload in the DLL's .text
```

## Loading

Ordinary DLL sideloading can work when Windows finds a DLL beside the
executable before the genuine copy. Here the host requests the plugin with
`LoadLibraryExW` and `LOAD_LIBRARY_SEARCH_SYSTEM32` (`0x800`), restricting the
normal search to System32. Placing `appraiser.dll` beside the host alone
does not change that request.

The reported package A/B test on build 26200 shows the difference:

| Marker | DLL selected | Package payload |
|---|---|---|
| Absent | `System32\appraiser.dll` | Not run |
| Present | Package `appraiser.dll` | Run |

Without the marker, the executable can still start: it selects the genuine
System32 DLL, leaving the package DLL unused. The replacement payload does
not run. With the marker, `.local` redirection selects the package DLL and
the payload runs. The comparison establishes which DLL is loaded, not
whether the genuine telemetry task finishes successfully.

The host has no manifest; reported manifest tests on build 26200 followed
normal resolution without `DevOverrideEnable`.

The shortcut selects the plugin and entry name from the host's allowlists
(7 DLLs, 15 entry names). The host maps `DoScheduledTelemetryRun` to
`DoScheduledTelemetryRunTC` and resolves it with `GetProcAddress`.

## Implementation

| Part | Details |
|---|---|
| Host | Copied `compattelrunner.exe`, Microsoft-signed, x64 |
| DLL | 13 exports, matching names and ordinals; no forwarders |
| Trigger | `DoScheduledTelemetryRunTC` (@3) |
| Payload | Direct call into the proxy's `.text` |
| Explicit memory and thread operations | No executable-memory allocation, RWX protection changes, or thread creation |
| Imports | `KERNEL32`, `SHELL32` |

The first export call detaches the console, opens the PDF from the package
directory, resolves the required APIs, and calls the payload once per process.
The reported runtime arguments are:

```text
DoScheduledTelemetryRunTC(rcx = 0, rdx = 0, r8 = context, r9 = 6)
```

The host treats the result as an HRESULT. When the payload returns, the
proxy returns `E_FAIL`; the reported exit code is `0x80004005`. The proxy does
not implement or forward the real telemetry function. Its other 12 exports
return the same error and are not exercised by this run.

## Build and checks

Requires MinGW-w64 GCC and binutils (`objcopy`, `objdump`, `windres`), NASM,
make, and Python 3 with `pefile`. Runtime tests use a native C compiler;
the resolver test runs on Windows.

```sh
make          # build bin/appraiser.dll and bin/payload.bin, then run checks
make test     # runtime helpers and resolver tests
```

`tools/gen_def.py` generates the exports from the reference DLL.
`REAL_APPRAISER=...` overrides the default `System32\appraiser.dll` reference.
Checks compare export names, ordinals, and version metadata, reject
forwarders, and inspect the blob's entry position, absolute image addresses,
and data sections. These checks do not establish functional compatibility.
`make test` does not run the package A/B test.

## Package

```powershell
powershell -ExecutionPolicy Bypass -File scripts\make_delivery.ps1 `
    -VhdPath C:\Users\<you>\Desktop\appraiser.vhd
```
Same as bellatrix in the collection. 

Default `File` form places the marker and DLL beside the host.
`-LocalForm Folder` selects `compattelrunner.exe.local\appraiser.dll`.
The shortcut stores the arguments shown above and the packaging drive letter
(`-DriveLetter`, default `E`); a different mount letter breaks that target path.

## Validation and limits

- **Reported tests:** package A/B, execution, arguments, and exit code apply
  to build 26200. The discovery JSON files and probe sources do not archive
  those acceptance results.
- **Intended support:** Windows 11 22000+. The reported test does not establish
  behavior on other builds. 
- **Side effects:** the genuine telemetry path writes its own state.
  The proxy does not reproduce that work.
- **Detection:** `.exe.local` is recognizable. The loading result and absence
  of certain API calls do not establish an EDR bypass.

## Background and references

The pair was selected for the host's plugin loading and role in Windows
compatibility telemetry. Its allowlist also includes `generaltel`, `invagent`,
`devinv`, `aeinv`, `aepic`, and `aemarebackup`. Each plugin needs its own exports
and version resource; this implementation targets `appraiser.dll`.

- [Microsoft: DLL redirection](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-redirection)
  — the documented mechanism.
- [Microsoft: DLL search order](https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order)
  — normal lookup and the rules that precede it.
- [Hexacorn, 2015](https://www.hexacorn.com/blog/2015/01/09/beyond-good-ol-run-key-part-23/)
  — public persistence example.
