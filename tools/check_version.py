#!/usr/bin/env python3
"""Compare the version resource of the proxy against the module it impersonates.

Detection rules that cannot see a signature key on OriginalFilename and the
fixed-version fields. If the proxy advertises anything of its own, that is the
tell; this check keeps the two in step.

    check_version.py <real.dll> <proxy.dll>
"""
import sys

import pefile


def version_strings(path):
    pe = pefile.PE(path, fast_load=True)
    pe.parse_data_directories(
        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    out = {}
    for group in getattr(pe, "FileInfo", []) or []:
        for entry in group:
            if entry.name != "StringFileInfo":
                continue
            for table in entry.StringTable:
                for key, val in table.entries.items():
                    out[key.decode("latin-1")] = val.decode("latin-1")
    if hasattr(pe, "VS_FIXEDFILEINFO") and pe.VS_FIXEDFILEINFO:
        ffi = pe.VS_FIXEDFILEINFO[0]
        out["__FileVersion"] = "%d.%d.%d.%d" % (
            ffi.FileVersionMS >> 16, ffi.FileVersionMS & 0xFFFF,
            ffi.FileVersionLS >> 16, ffi.FileVersionLS & 0xFFFF)
        out["__ProductVersion"] = "%d.%d.%d.%d" % (
            ffi.ProductVersionMS >> 16, ffi.ProductVersionMS & 0xFFFF,
            ffi.ProductVersionLS >> 16, ffi.ProductVersionLS & 0xFFFF)
        out["__FileFlags"] = "0x%x" % ffi.FileFlags
    pe.close()
    return out


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    real = version_strings(sys.argv[1])
    proxy = version_strings(sys.argv[2])

    bad = 0
    for key in sorted(real):
        want, got = real[key], proxy.get(key)
        ok = want == got
        if not ok:
            bad += 1
        print("  %-20s %s\n      real = %r\n      prox = %r"
              % (key, "OK" if ok else "MISMATCH", want, got))

    print("\n%d mismatches" % bad if bad else "\nmetadata matches")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
