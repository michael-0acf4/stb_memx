#ifndef MEMX_H
#define MEMX_H

#include <stddef.h>
#include <stdint.h>

#ifdef _WIN32
#include <windows.h>
#define MEMX_API __declspec(dllexport)
#else
#define MEMX_API
#endif

#ifdef __cplusplus
extern "C"
{
#endif

    typedef struct MemxProcess MemxProcess;
    typedef struct MemxScan MemxScan;

    typedef enum
    {
        MEMX_I8,
        MEMX_U8,
        MEMX_I32,
        MEMX_U32,
        MEMX_I64,
        MEMX_U64,
        MEMX_F32,
        MEMX_F64,
        MEMX_STRING
    } MemxType;

    typedef struct
    {
        void *address;
    } MemxCandidate;

    MEMX_API MemxProcess *memx_open_process(uint32_t pid);
    MEMX_API void memx_close_process(MemxProcess *p);

    MEMX_API MemxScan *memx_scan_begin(MemxProcess *p, MemxType type,
                                       const void *value, size_t value_size);
    MEMX_API void memx_scan_refine(MemxScan *scan, const void *value,
                                   size_t value_size);
    MEMX_API size_t memx_scan_count(const MemxScan *scan);
    MEMX_API size_t memx_scan_get(const MemxScan *scan, MemxCandidate *out,
                                  size_t max);
    MEMX_API void memx_scan_free(MemxScan *scan);

    MEMX_API int memx_write(MemxProcess *p, void *address, const void *value,
                            size_t size);

#ifdef __cplusplus
}
#endif

#ifdef STB_MEMX_IMPLEMENTATION

/**
 * WINDOWS IMPLEMENTATION
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct MemxProcess
{
#ifdef _WIN32
    HANDLE handle;
#endif
    uint32_t pid;
};

struct MemxScan
{
    MemxProcess *proc;
    MemxType type;
    size_t value_size;
    unsigned char *value_bytes;

    MemxCandidate *candidates;
    size_t count;
    size_t capacity;
};

MEMX_API MemxProcess *memx_open_process(uint32_t pid)
{
#ifdef _WIN32
    HANDLE h = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE |
                               PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
                           FALSE, pid);
    if (!h)
        return NULL;
    MemxProcess *p = (MemxProcess *)malloc(sizeof(MemxProcess));
    p->handle = h;
    p->pid = pid;
    return p;
#else
    (void)pid;
    return NULL;
#endif
}

MEMX_API void memx_close_process(MemxProcess *p)
{
    if (!p)
        return;
#ifdef _WIN32
    CloseHandle(p->handle);
#endif
    free(p);
}

static int isGoodRegion(MEMORY_BASIC_INFORMATION *mbi)
{
    if (mbi->State != MEM_COMMIT)
        return 0;
    if (!(mbi->Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_READONLY)))
        return 0;
    if (mbi->Protect & PAGE_GUARD)
        return 0;
    return 1;
}

static size_t type_size(MemxType t)
{
    switch (t)
    {
    case MEMX_I8:
    case MEMX_U8:
        return 1;
    case MEMX_I32:
    case MEMX_U32:
    case MEMX_F32:
        return 4;
    case MEMX_I64:
    case MEMX_U64:
    case MEMX_F64:
        return 8;
    default:
        return 1;
    }
}

static int match_value(const unsigned char *mem, const unsigned char *val,
                       size_t size)
{
    return memcmp(mem, val, size) == 0;
}

MEMX_API MemxScan *memx_scan_begin(MemxProcess *p, MemxType type,
                                   const void *value, size_t value_size)
{
#ifdef _WIN32
    if (!p || !value)
        return NULL;

    MemxScan *scan = (MemxScan *)malloc(sizeof(MemxScan));
    scan->proc = p;
    scan->type = type;
    scan->value_size = value_size;
    scan->value_bytes = (unsigned char *)malloc(value_size);
    memcpy(scan->value_bytes, value, value_size);

    scan->count = 0;
    scan->capacity = 1024;
    scan->candidates =
        (MemxCandidate *)malloc(scan->capacity * sizeof(MemxCandidate));

    SYSTEM_INFO sys;
    GetSystemInfo(&sys);

    unsigned char *addr = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (addr < (unsigned char *)sys.lpMaximumApplicationAddress)
    {
        if (VirtualQueryEx(p->handle, addr, &mbi, sizeof(mbi)) != sizeof(mbi))
            break;
        if (!isGoodRegion(&mbi))
        {
            addr += mbi.RegionSize;
            continue;
        }
        if (mbi.RegionSize < value_size)
        {
            addr += mbi.RegionSize;
            continue;
        }

        unsigned char *buffer = (unsigned char *)malloc(mbi.RegionSize);
        SIZE_T bytesRead;
        if (ReadProcessMemory(p->handle, mbi.BaseAddress, buffer, mbi.RegionSize,
                              &bytesRead))
        {
            SIZE_T step = (type == MEMX_STRING) ? 1 : type_size(type);
            for (SIZE_T i = 0; i + value_size <= bytesRead; i += step)
            {
                if (match_value(buffer + i, scan->value_bytes, value_size))
                {
                    if (scan->count >= scan->capacity)
                    {
                        scan->capacity *= 2;
                        scan->candidates = (MemxCandidate *)realloc(
                            scan->candidates, scan->capacity * sizeof(MemxCandidate));
                    }
                    scan->candidates[scan->count++].address =
                        (unsigned char *)mbi.BaseAddress + i;
                }
            }
        }
        free(buffer);
        addr += mbi.RegionSize;
    }

    return scan;
#else
    (void)p;
    (void)type;
    (void)value;
    (void)value_size;
    return NULL;
#endif
}

MEMX_API void memx_scan_refine(MemxScan *scan, const void *value,
                               size_t value_size)
{
#ifdef _WIN32
    if (!scan || !value)
        return;
    memcpy(scan->value_bytes, value, value_size);
    size_t new_count = 0;
    for (size_t i = 0; i < scan->count; i++)
    {
        unsigned char buf[64]; /* assume small size */
        if (ReadProcessMemory(scan->proc->handle, scan->candidates[i].address, buf,
                              value_size, NULL))
        {
            if (match_value(buf, scan->value_bytes, value_size))
                scan->candidates[new_count++] = scan->candidates[i];
        }
    }
    scan->count = new_count;
#else
    (void)scan;
    (void)value;
    (void)value_size;
#endif
}

MEMX_API size_t memx_scan_count(const MemxScan *scan)
{
    return scan ? scan->count : 0;
}

MEMX_API size_t memx_scan_get(const MemxScan *scan, MemxCandidate *out,
                              size_t max)
{
    if (!scan || !out)
        return 0;
    size_t n = (max < scan->count) ? max : scan->count;
    for (size_t i = 0; i < n; i++)
        out[i] = scan->candidates[i];
    return n;
}

MEMX_API void memx_scan_free(MemxScan *scan)
{
    if (!scan)
        return;
    free(scan->value_bytes);
    free(scan->candidates);
    free(scan);
}

MEMX_API int memx_write(MemxProcess *p, void *address, const void *value,
                        size_t size)
{
#ifdef _WIN32
    if (!p || !address || !value)
        return 0;
    return WriteProcessMemory(p->handle, address, value, size, NULL) != 0;
#else
    (void)p;
    (void)address;
    (void)value;
    (void)size;
    return 0;
#endif
}

#endif /* STB_MEMX_IMPLEMENTATION */

#endif /* MEMX_H */
