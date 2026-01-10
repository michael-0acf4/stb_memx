#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

typedef struct
{
  void *addr;
} Candidate;

#define MAX_CANDIDATES 1000000

int isGoodRegion(MEMORY_BASIC_INFORMATION *mbi)
{
  if (mbi->State != MEM_COMMIT)
    return 0;

  // ONLY keep readable/writable memory, including WRITECOPY
  // AND skip guard pages

  if (!(mbi->Protect & (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_READONLY)))
    return 0;
  if (mbi->Protect & PAGE_GUARD)
    return 0;

  return 1;
}

int main()
{
  printf("WARNING: Don't use this to cheat on games, only introspection");

  DWORD pid;
  printf("Enter PID of target.exe: ");
  scanf("%lu", &pid);

  HANDLE hProc =
      OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                      PROCESS_QUERY_INFORMATION,
                  FALSE, pid);

  if (!hProc)
  {
    printf("Failed to open process\n");
    return 1;
  }

  Candidate *candidates = malloc(sizeof(Candidate) * MAX_CANDIDATES);
  size_t candidateCount = 0;

  SYSTEM_INFO sys;
  GetSystemInfo(&sys);

  int target;
  printf("Initial value to scan: ");
  scanf("%d", &target);

  printf("Starting first scan...\n");

  unsigned char *addr = 0;
  MEMORY_BASIC_INFORMATION mbi;

  while (addr < (unsigned char *)sys.lpMaximumApplicationAddress)
  {
    if (VirtualQueryEx(hProc, addr, &mbi, sizeof(mbi)) != sizeof(mbi))
      break;

    if (isGoodRegion(&mbi))
    {
      // printf("Scanning region %p - %p, Protect: 0x%X\n",
      //     mbi.BaseAddress,
      //     (unsigned char*)mbi.BaseAddress + mbi.RegionSize,
      //     mbi.Protect);
      // skip tiny regions?
      if (mbi.RegionSize < sizeof(int))
      {
        addr += mbi.RegionSize;
        continue;
      }

      unsigned char *buffer = malloc(mbi.RegionSize);
      SIZE_T bytesRead;

      if (ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize,
                            &bytesRead))
      {
        // aligned int32 scan
        SIZE_T start = ((SIZE_T)mbi.BaseAddress + 3) & ~3;
        SIZE_T offset = start - (SIZE_T)mbi.BaseAddress;

        for (SIZE_T i = offset; i + sizeof(int) <= bytesRead;
             i += sizeof(int))
        {
          int val = *(int *)(buffer + i);
          if (val == target && candidateCount < MAX_CANDIDATES)
          {
            candidates[candidateCount++].addr =
                (unsigned char *)mbi.BaseAddress + i;
          }
        }
      }

      free(buffer);
    }

    addr += mbi.RegionSize;
  }

  printf("First scan: %zu candidates found\n", candidateCount);
  while (candidateCount > 1)
  {
    printf("Enter new value (or -1 to stop): ");
    scanf("%d", &target);
    if (target == -1)
      break;

    size_t new_count = 0;

    for (size_t i = 0; i < candidateCount; i++)
    {
      int val;
      if (ReadProcessMemory(hProc, candidates[i].addr, &val, sizeof(int),
                            NULL))
      {
        if (val == target)
        {
          candidates[new_count++] = candidates[i];
        }
      }
    }

    candidateCount = new_count;
    printf("Refined: %zu candidates remaining\n", candidateCount);
  }

  if (candidateCount == 1)
  {
    printf("FOUND FINAL ADDRESS: %p\n", candidates[0].addr);

    int newValue;
    printf("Enter value to write: ");
    scanf("%d", &newValue);

    if (WriteProcessMemory(hProc, candidates[0].addr, &newValue, sizeof(int),
                           NULL))
      printf("Value written successfully.\n");
    else
      printf("Failed to write value.\n");
  }
  else
  {
    printf("Stopped with %zu candidates.\n", candidateCount);
  }

  free(candidates);
  CloseHandle(hProc);
  return 0;
}
