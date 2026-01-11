#ifndef MEMX_H
#define MEMX_H

#ifdef _WIN32
#define MEMX_API __declspec(dllexport)
#include <windows.h>
#else
#define MEMX_API
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <stddef.h>
#include <stdint.h>

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
        MEMX_BLOB
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
    char path[64];
    sprintf(path, "/proc/%u/maps", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return NULL;
    fclose(f);

    MemxProcess *p = (MemxProcess *)malloc(sizeof(MemxProcess));
    p->pid = pid;

    return p;
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

#ifdef _WIN32
static int isGoodRegionWin32(MEMORY_BASIC_INFORMATION *mbi)
{
    if (mbi->State != MEM_COMMIT)
        return 0;
    if (!(mbi->Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_READONLY)))
        return 0;
    if (mbi->Protect & PAGE_GUARD)
        return 0;

    return 1;
}
#else
static int isGoodRegionLinux(uintptr_t start, const char *line, const char *perms)
{
    if (perms[0] != 'r')
        return 0;

    // Kernel/non-canonical addr
    // limit on 64-bit systems
    if (start >= 0x7fffffffffff)
        return 0;
    if (perms[0] != 'r' || perms[3] != 'p')
        return 0;

    // System-reserved regions by name
    // line contains the path at the end
    // -> skip virtual memory tagged region [vvar], [vdso], [vsyscall]
    // https://0xax.gitbooks.io/linux-insides/content/SysCall/linux-syscall-3.html
    if (strstr(line, "[v"))
        return 0;

    // if (!strstr(line, "[stack]"))
    //    return 0;
    return 1;
}
#endif

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

static int memx_read_raw(MemxProcess *p, void *address, void *buffer, size_t size)
{
#ifdef _WIN32
    SIZE_T bytesRead;
    return ReadProcessMemory(p->handle, address, buffer, size, &bytesRead) && bytesRead == size;
#else
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = buffer;
    local[0].iov_len = size;
    remote[0].iov_base = address;
    remote[0].iov_len = size;
    return process_vm_readv(p->pid, local, 1, remote, 1, 0) == (ssize_t)size;
#endif
}

MEMX_API MemxScan *memx_scan_begin(MemxProcess *p, MemxType type,
                                   const void *value, size_t value_size)
{
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

#ifdef _WIN32
    SYSTEM_INFO sys;
    GetSystemInfo(&sys);

    unsigned char *addr = 0;
    MEMORY_BASIC_INFORMATION mbi;

    while (addr < (unsigned char *)sys.lpMaximumApplicationAddress)
    {
        if (VirtualQueryEx(p->handle, addr, &mbi, sizeof(mbi)) != sizeof(mbi))
            break;
        if (!isGoodRegionWin32(&mbi))
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
        if (memx_read_raw(p, mbi.BaseAddress, buffer, mbi.RegionSize))
        {
            size_t step = (type == MEMX_BLOB) ? 1 : type_size(type);
            for (size_t i = 0; i + value_size <= mbi.RegionSize; i += step)
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
#else
    char path[64];
    sprintf(path, "/proc/%u/maps", p->pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return scan;

    char line[512];
    while (fgets(line, sizeof(line), f))
    {
        uintptr_t start, end;
        char perms[5];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) != 3)
            continue;

        if (!isGoodRegionLinux(start, line, perms))
            continue;

        size_t region_size = end - start;
        if (region_size < value_size)
            continue;

        unsigned char *buffer = (unsigned char *)malloc(region_size);
        if (memx_read_raw(p, (void *)start, buffer, region_size))
        {
            size_t step = (type == MEMX_BLOB) ? 1 : type_size(type);
            for (size_t i = 0; i + value_size <= region_size; i += step)
            {
                if (match_value(buffer + i, scan->value_bytes, value_size))
                {
                    if (scan->count >= scan->capacity)
                    {
                        scan->capacity *= 2;
                        scan->candidates = (MemxCandidate *)realloc(
                            scan->candidates, scan->capacity * sizeof(MemxCandidate));
                    }
                    scan->candidates[scan->count++].address = (void *)(start + i);
                }
            }
        }
        free(buffer);
    }
    fclose(f);
#endif

    return scan;
}

MEMX_API void memx_scan_refine(MemxScan *scan, const void *value,
                               size_t value_size)
{
    if (!scan || !value)
        return;
    memcpy(scan->value_bytes, value, value_size);
    size_t new_count = 0;
    for (size_t i = 0; i < scan->count; i++)
    {
        unsigned char buf[1024];
        void *target_buf = (value_size <= sizeof(buf)) ? buf : malloc(value_size);

        if (memx_read_raw(scan->proc, scan->candidates[i].address, target_buf, value_size))
        {
            if (match_value((unsigned char *)target_buf, scan->value_bytes, value_size))
                scan->candidates[new_count++] = scan->candidates[i];
        }

        if (target_buf != buf)
            free(target_buf);
    }
    scan->count = new_count;
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
    if (!p || !address || !value)
        return 0;
#ifdef _WIN32
    return WriteProcessMemory(p->handle, address, value, size, NULL) != 0;
#else
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = (void *)value;
    local[0].iov_len = size;
    remote[0].iov_base = address;
    remote[0].iov_len = size;
    return process_vm_writev(p->pid, local, 1, remote, 1, 0) == (ssize_t)size;
#endif
}

#endif /* STB_MEMX_IMPLEMENTATION */

#endif /* MEMX_H */
