// resolution contract: no import table, every dependency resolved at runtime
#ifndef RESOLVE_H
#define RESOLVE_H

#include <stdint.h>
#include <stddef.h>

// ---------------------------------------------------------------- types
_Static_assert(sizeof(void *) == 8, "x64 only");

typedef struct _unicode_string {
    uint16_t length;      /* bytes, not chars */
    uint16_t maxlen;
    uint16_t *buffer;     /* UTF-16 */
} unicode_string;

// Minimal loader view. Offsets below are the ones the resolver walks.
typedef struct _list_entry {
    struct _list_entry *flink;
    struct _list_entry *blink;
} list_entry;

typedef struct _ldr_entry {
    list_entry in_load_order;              /* +0x00 */
    list_entry in_memory_order;            /* +0x10 */
    list_entry in_init_order;              /* +0x20 */
    void         *dll_base;                   /* +0x30 */
    void         *entry_point;                /* +0x38 */
    uint32_t      size_of_image;              /* +0x40 */
    uint32_t      pad_;                       /* +0x44 */
    unicode_string full_name;              /* +0x48 */
    unicode_string base_name;              /* +0x58 */
} ldr_entry;

typedef struct _peb_ldr {
    uint32_t     length;
    uint32_t     initialized;
    void        *ss_handle;
    list_entry in_load_order;              /* +0x10 */
} peb_ldr;

typedef struct _peb {
    uint8_t  inherited_address_space;
    uint8_t  read_image_file_exec_options;
    uint8_t  being_debugged;
    uint8_t  pad_[5];
    void    *mutant;
    void    *image_base_address;
    peb_ldr *ldr;                          /* +0x18 */
    void    *process_parameters;              /* +0x20 */
    uint8_t  pad2_[0x40];
    void    *api_set_map;                     /* +0x68 */
} peb;

_Static_assert(offsetof(peb, ldr) == 0x18, "PEB.Ldr offset");
_Static_assert(offsetof(peb, api_set_map) == 0x68, "PEB.ApiSetMap offset");
_Static_assert(offsetof(peb_ldr, in_load_order) == 0x10, "Ldr list offset");
_Static_assert(offsetof(ldr_entry, dll_base) == 0x30, "DllBase offset");
_Static_assert(offsetof(ldr_entry, base_name) == 0x58, "BaseDllName offset");
_Static_assert(sizeof(unicode_string) == 16, "UNICODE_STRING size");
_Static_assert(sizeof(list_entry) == 16, "LIST_ENTRY size");

// PE views -- only the fields the resolver consumes.
typedef struct _dos_header {
    uint8_t  magic[2];
    uint8_t  pad_[0x3A];
    int32_t  e_lfanew;                        /* +0x3C */
} dos_header;

typedef struct _export_dir {
    uint32_t characteristics;
    uint32_t timestamp;
    uint16_t major, minor;
    uint32_t name;
    uint32_t ordinal_base;
    uint32_t number_of_functions;
    uint32_t number_of_names;                 /* +0x18 */
    uint32_t address_of_functions;            /* +0x1C */
    uint32_t address_of_names;                /* +0x20 */
    uint32_t address_of_name_ordinals;        /* +0x24 */
} export_dir;

_Static_assert(offsetof(export_dir, number_of_names) == 0x18, "NumberOfNames");
_Static_assert(offsetof(export_dir, address_of_functions) == 0x1C, "EAT");
_Static_assert(offsetof(export_dir, address_of_names) == 0x20, "Name table");
_Static_assert(offsetof(export_dir, address_of_name_ordinals) == 0x24, "Ordinal table");

typedef struct _data_dir {
    uint32_t rva;
    uint32_t size;
} data_dir;

// PE32+ optional header. Only the fields the resolver consumes are named.
typedef struct _opt64 {
    uint16_t    magic;                  /* +0x00 */
    uint8_t     pad_[0x36];
    uint32_t    size_of_image;          /* +0x38 */
    uint8_t     pad2_[0x30];
    uint32_t    number_of_rva;          /* +0x6C */
    data_dir dir[16];                /* +0x70 */
} opt64;

typedef struct _nt64 {
    uint32_t signature;                 /* +0x00 "PE\0\0" */
    uint16_t machine;                   /* +0x04 */
    uint8_t  file_hdr_rest[18];         /* +0x06 */
    opt64 optional;                  /* +0x18 */
} nt64;

_Static_assert(offsetof(nt64, optional) == 0x18, "optional header offset");
_Static_assert(offsetof(opt64, size_of_image) == 0x38, "SizeOfImage offset");
_Static_assert(offsetof(opt64, number_of_rva) == 0x6C, "NumberOfRvaAndSizes");
_Static_assert(offsetof(opt64, dir) == 0x70, "data directories offset");
_Static_assert(sizeof(data_dir) == 8, "data directory entry size");

#define PE_SIGNATURE     0x00004550u   /* "PE\0\0" */
#define MACHINE_AMD64    0x8664u
#define OPT_MAGIC_PE32P  0x20Bu
#define DIR_EXPORT       0

// API Set Schema namespace v6. Offsets are relative to the namespace base.
typedef struct _apiset_ns {
    uint32_t version;          /* +0x00 must be 6 */
    uint32_t size;             /* +0x04 */
    uint32_t flags;            /* +0x08 */
    uint32_t count;            /* +0x0C */
    uint32_t entry_offset;     /* +0x10 */
    uint32_t hash_offset;      /* +0x14 */
    uint32_t hash_factor;      /* +0x18 */
} apiset_ns;

typedef struct _apiset_entry {
    uint32_t flags;            /* +0x00 */
    uint32_t name_offset;      /* +0x04 */
    uint32_t name_length;      /* +0x08 bytes */
    uint32_t hashed_length;    /* +0x0C bytes */
    uint32_t value_offset;     /* +0x10 */
    uint32_t value_count;      /* +0x14 */
} apiset_entry;

typedef struct _apiset_value {
    uint32_t flags;            /* +0x00 */
    uint32_t name_offset;      /* +0x04 */
    uint32_t name_length;      /* +0x08 */
    uint32_t value_offset;     /* +0x0C */
    uint32_t value_length;     /* +0x10 */
} apiset_value;

_Static_assert(sizeof(apiset_ns) == 0x1C, "API_SET_NAMESPACE size");
_Static_assert(sizeof(apiset_entry) == 0x18, "API_SET_NAMESPACE_ENTRY size");
_Static_assert(sizeof(apiset_value) == 0x14, "API_SET_VALUE_ENTRY size");

#define APISET_VERSION    6

// Traversal bounds. Every loop is capped by one of these.
#define MAX_MODULES      256
#define MAX_EXPORTS      8192
#define MAX_SEEN         8
// The api-set namespace is the OS's own table, not untrusted input.
#define MAX_APISET       4096

// --------------------------------------------------------------- hashes
// Multiply-XOR hash (FNV-1a shape), parameters regenerated per build.
#include "hash_params.h"   /* HASH_SEED / _PRIME / _POST and name hashes */

// ------------------------------------------------------- error handling
enum status {
    OK = 0,
    E_BAD_IMAGE,        /* e_lfanew / signature / bounds check failed */
    E_NO_MODULE,        /* module not in the loader list */
    E_NO_EXPORT,        /* name or ordinal not found */
    E_FORWARD_DEPTH,    /* forwarded export recursion limit hit */
    E_FORWARD_CYCLE,    /* forwarded export cycle detected */
    E_BUFFER,           /* caller buffer too small */
};

#define MAX_FORWARD_DEPTH 8

// ------------------------------------------------------- resolved APIs
// Declared as function pointers; filled by resolve_all().
typedef void   *(*fn_load_library_a)(const char *name);
typedef void   *(*fn_get_proc_address)(void *module, const char *name);
typedef int     (*fn_virtual_protect)(void *addr, size_t len,
                                         uint32_t new_protect,
                                         uint32_t *old_protect);

// ----------------------------------------------------------- CONTEXT
// All mutable state. Owned by the caller's stack, never a global.
typedef struct _context {
    peb *peb;                 /* captured at entry */
    const void *blob_base;       /* anchor for self-relative data */
    size_t      blob_size;

// resolver cache
    void *kernel32;
    void *user32;
    fn_load_library_a   load_library_a;
    fn_get_proc_address get_proc_address;

    uint32_t last_status;
} context;

// ---------------------------------------------------------- entry point
// One C entry, called by the asm stub with a 16-byte aligned stack.
void stage_main(context *ctx);

// ------------------------------------------------------- resolver API
// All hashes are the per-build values from hash_params.h.
enum status module_by_hash(context *ctx, uint32_t hash, void **out);
enum status export_by_hash(context *ctx, void *module, uint32_t hash,
                                 void **out);
enum status export_by_ordinal(context *ctx, void *module,
                                    uint16_t ordinal, void **out);

// Fill kernel32 and the two functions everything else is reached through.
enum status resolve_all(context *ctx);

#endif /* RESOLVE_H */
