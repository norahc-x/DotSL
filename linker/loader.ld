SECTIONS
{
    /* A normal x64 PE layout: .text at ImageBase + 0x1000. Leaving the
     * address unset makes the linker place it far above the image base, which
     * yields a degenerate SizeOfImage and a bogus AddressOfEntryPoint. */
    . = 0x140001000;

    .text : {
        *(.text$entry)
        *(.text)
        *(.text.*)
        *(.rdata)
        *(.rdata.*)
        *(.data)
        *(.data.*)
    }

    /DISCARD/ : {
        *(.pdata)
        *(.xdata)
        *(.edata)
        *(.idata)
        *(.CRT)
        *(.tls)
        *(.reloc)
        *(.bss)
        *(.debug*)
    }
}
