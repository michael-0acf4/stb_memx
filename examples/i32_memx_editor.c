#define STB_MEMX_IMPLEMENTATION
#include "../stb_memx.h"

#include <stdio.h>
#include <stdint.h>

static int CALL_COUNTER = 0;

int my_eq_comparator(const unsigned char *mem,
                     const unsigned char *val,
                     size_t size,
                     MemxType type)
{
  CALL_COUNTER++;
  return -1; // -1 to fallback
}

int main(void)
{
  uint32_t pid;
  printf("WARNING: use only for introspection / learning.\n\n");

  printf("Enter PID of target process: ");
  if (scanf("%u", &pid) != 1)
  {
    printf("Invalid PID\n");
    return 1;
  }

  MemxProcess *proc = memx_open_process(pid);
  if (!proc)
  {
    printf("Failed to open process\n");
    return 1;
  }

  int32_t value;
  printf("Initial int32 value to scan: ");
  if (scanf("%d", &value) != 1)
  {
    printf("Invalid value\n");
    memx_close_process(proc);
    return 1;
  }

  printf("\nStarting first scan...\n");
  // MemxScan *scan = memx_scan_begin(proc, MEMX_I32, &value, sizeof(value), NULL);
  MemxScan *scan = memx_scan_begin(proc, MEMX_I32, &value, sizeof(value), (MemxComparator)&my_eq_comparator);
  if (!scan)
  {
    printf("Scan failed\n");
    memx_close_process(proc);
    return 1;
  }

  size_t count = memx_scan_count(scan);
  printf("First scan: %zu candidates found (comparisons %d)\n", count, CALL_COUNTER);

  while (count > 1)
  {
    printf("\nEnter new value (or -1 to stop refining): ");
    if (scanf("%d", &value) != 1)
    {
      printf("Invalid input\n");
      break;
    }

    if (value == -1)
      break;

    memx_scan_refine(scan, &value, sizeof(value));
    count = memx_scan_count(scan);
    printf("Refined: %zu candidates remaining (comparisons %d)\n", count, CALL_COUNTER);
  }

  if (count == 1)
  {
    MemxCandidate c;
    memx_scan_get(scan, &c, 1);

    printf("\nFOUND FINAL ADDRESS: %p\n", c.address);

    int32_t newValue;
    printf("Enter value to write: ");
    if (scanf("%d", &newValue) == 1)
    {
      if (memx_write(proc, c.address, &newValue, sizeof(newValue)))
        printf("Value written successfully.\n");
      else
        printf("Failed to write value.\n");
    }
  }
  else
  {
    printf("\nStopped with %zu candidates.\n", count);
  }

  memx_scan_free(scan);
  memx_close_process(proc);
  return 0;
}
