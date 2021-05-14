/*
 * Copyright (c) 2018-present StackPath, LLC
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * cpu.c -- parse cpu lists, cpu masks, and cpu information from sysfs.
 */

#define _GNU_SOURCE

#include "cpu.h"

#include <sched.h>  // for CPU_SET(), CPU_ZERO()
#include <stdio.h>  // for fclose(), feof(), fgets(), FILE, fopen()
#include <stdlib.h> // for free(), strtol()
#include <string.h> // for strcspn(), strdup(), strlen(), strsep()

#define RETURN_BAD -1
#define RETURN_GOOD 0

#define CPU_LIST_BASE 10

/*
 * The linux kernel currently supports up to 4096 cpus which will be indexed
 * from 0 to 4095. `/sys/devices/system/cpu/online` contains a cpu list of all
 * online cpus.
 *
 * Groups of 3 or more contiguous cpus will shorten the cpu list string length
 * versus the real maximum due to the efficiency of the range format. To find
 * the real maximum we need 1 out of every 3 cpus offline and no contiguous
 * groups of 3 or more cpus.
 *
 * There are 3 possible cpu lists meeting this criteria; we need to find the
 * length of the longest among them.
 *
 *   1-2,4-5,...,4090-4091,4093-4094
 *   0-1,3-4,...,4089-4090,4092-4093,4095
 *   0,2-3,5-6,...,4091-4092,4094-4095
 *
 * The following bash script produces the string length of each. The dot
 * represents a comma or a dash. The trailing dot could easily represent the
 * newline character as well, but I decided to replace it for clarity.
 *
 *   for offset in {0..2}; do
 *     for i in {0..4095}; do
 *       [[ $(((i+offset)%3)) -eq 0 ]] || echo -n "$i."
 *     done | sed 's/.$/\n/' | wc -c
 *   done
 *
 * This script produces the following output.
 *
 *   12912
 *   12914
 *   12914
 *
 * Add room for a null byte and we've got our maximum.
 */
#define MAX_ONLINE_CPU_LIST_LENGTH 12915 // 12914 + '\0'

/* ========================================================================= */
int get_online_cpu_set(cpu_set_t *cpu_set) {
  CPU_ZERO(cpu_set);

  char cpu_list[MAX_ONLINE_CPU_LIST_LENGTH];
  FILE *f = fopen("/sys/devices/system/cpu/online", "r");
  if (!f || feof(f) || !fgets(cpu_list, sizeof(cpu_list), f)) {
    fclose(f);
    return RETURN_BAD;
  }
  fclose(f);

  cpu_list[strcspn(cpu_list, "\n")] = 0;
  parse_cpu_list(cpu_list, cpu_set);

  return RETURN_GOOD;
}

/* ========================================================================= */
int get_numa_cpu_set(cpu_set_t *cpu_set, int numa_node) {
  CPU_ZERO(cpu_set);

  int status = 0;

  char cpu_list[MAX_ONLINE_CPU_LIST_LENGTH];
  char *path = NULL;

  status = asprintf(&path, "/sys/devices/system/node/node%i/cpulist",
                                                                    numa_node);
  if (status == -1) {
    return RETURN_BAD;
  }

  FILE *f = fopen(path, "r");
  if (!f || feof(f) || !fgets(cpu_list, sizeof(cpu_list), f)) {
    fclose(f);
    return RETURN_BAD;
  }
  fclose(f);

  free(path);

  cpu_list[strcspn(cpu_list, "\n")] = 0;
  parse_cpu_list(cpu_list, cpu_set);

  return RETURN_GOOD;
}

/* ========================================================================= */
static int hex2int(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

/* ========================================================================= */
int parse_cpu_list(char *cpu_list, cpu_set_t *cpu_set) {
  CPU_ZERO(cpu_set);

  /*
   * When supplied cpu list is an empty string there is nothing to parse.
   */
  if (strlen(cpu_list) == 0) {
    return RETURN_GOOD;
  }

  char *endptr;
  char *tofree, *string, *range;

  tofree = string = strdup(cpu_list);

  while ((range = strsep(&string, ",")) != NULL) {
    int first = strtol(range, &endptr, CPU_LIST_BASE);
    /*
     * When there is no endptr this is a single cpu in the cpu list, not a
     * range.
     */
    if (!*endptr) {
      CPU_SET(first, cpu_set);
      continue;
    }
    char *save = endptr;
    endptr++;
    int last = strtol(endptr, &endptr, CPU_LIST_BASE);
    /*
     * Here we check the following.
     *   1. Ensure save[0] (endptr from the strtol() operation to find first)
     *      contains our range delimiter, '-'.
     *   2. Ensure endptr (endptr from the strtol() operation to find last) is
     *      NULL.
     *   3. Ensure that last is not less than first (procfs accepts ranges
     *       where last equals first, so we will too).
     */
    if (save[0] != '-' || *endptr || last < first) {
      free(tofree);
      return RETURN_BAD;
    }

    for (int i = first; i <= last; i++) {
      CPU_SET(i, cpu_set);
    }
  }
  free(tofree);
  return RETURN_GOOD;
}

/* ========================================================================= */
int parse_cpu_mask(char *cpu_mask, cpu_set_t *cpu_set) {
  CPU_ZERO(cpu_set);

  int len = strlen(cpu_mask);
  int nybbles = 0;

  for (int i = len-1; i >= 0; --i) {
    /*
     * Accept commas for readability, but don't assume position.
     */
    if (cpu_mask[i] == ',') {
      continue;
    }

    int nybble = hex2int(cpu_mask[i]);
    if (nybble < 0) {
      return RETURN_BAD;
    }
    if (nybble & 0x01) {
      CPU_SET(0 + (nybbles * 4), cpu_set);
    }
    if (nybble & 0x02) {
      CPU_SET(1 + (nybbles * 4), cpu_set);
    }
    if (nybble & 0x04) {
      CPU_SET(2 + (nybbles * 4), cpu_set);
    }
    if (nybble & 0x08) {
      CPU_SET(3 + (nybbles * 4), cpu_set);
    }
    nybbles++;
  }
  return RETURN_GOOD;
}
