/*
 * Copyright (c) 2018-present StackPath, LLC
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 *
 * rxtx.c -- multi-stream (per-cpu, per-queue, etc.) packet captures
 */

#define _GNU_SOURCE

#include "rxtx.h"

#include "rxtx_error.h" // for RXTX_ERROR, rxtx_fill_errbuf()
#include "rxtx_ring.h" // for rxtx_ring_destroy(), rxtx_ring_init(),
                       //     rxtx_ring_mark_packets_in_buffer_as_unreliable(),
                       //     rxtx_ring_savefile_open()
#include "rxtx_stats.h" // for rxtx_stats_destroy_with_mutex(),
                        //     rxtx_stats_get_packets_received(),
                        //     rxtx_stats_get_packets_unreliable(),
                        //     rxtx_stats_increment_packets_received(),
                        //     rxtx_stats_increment_packets_unreliable(),
                        //     rxtx_stats_init_with_mutex()

#include "interface.h" // for interface_set_promisc_on()
#include "ring_set.h"  // for RING_COUNT(), RING_ISSET(), RING_SET(),
                       //     RING_SETSIZE, RING_ZERO()
#include "sig.h"       // for keep_running

#include <net/if.h>     // for if_indextoname(), if_nametoindex(), IF_NAMESIZE
#include <sys/socket.h> // for setsockopt()

#include <assert.h> // for assert()
#include <errno.h>  // for errno
#include <pcap.h>   // for PCAP_D_IN, PCAP_D_INOUT, PCAP_D_OUT
#include <stdio.h>  // for fprintf(), NULL, stderr
#include <stdlib.h> // for calloc(), free()
#include <string.h> // for memcpy(), strdup(), strerror(), strlen()
#include <unistd.h> // for getpid()

#define INCREMENT_STEP 1

#define RXTX_INACTIVE 0
#define RXTX_ACTIVATING 1
#define RXTX_ACTIVE 2

char *program_basename = NULL;

volatile sig_atomic_t rxtx_breakloop = 0;

/* ========================================================================= */
void rxtx_init(struct rxtx_desc *p, char *errbuf) {
  p->errbuf = errbuf;

  p->ifname            = NULL;
  p->rings             = NULL;
  p->savefile_template = NULL;
  p->stats             = NULL;

  p->breakloop       = 0;
  p->direction       = PCAP_D_INOUT;
  p->fanout_data_fd  = 0;
  p->fanout_group_id = getpid() & 0xffff;
  p->fanout_mode     = 0;
  p->ifindex         = 0;
  p->initialized_ring_count = 0;
  p->is_active       = RXTX_INACTIVE;
  p->packet_buffered = 0;
  p->packet_count    = 0;
  p->promiscuous     = 0;
  p->ring_count      = 0;
  p->verbose         = 0;

  RING_ZERO(&(p->ring_set));
}

/* ========================================================================= */
int rxtx_activate(struct rxtx_desc *p) {
  int i, status;

  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error activating descriptor: descriptor is"
                                                            " already active");
    return RXTX_ERROR;
  }

  p->is_active = RXTX_ACTIVATING;

  if (rxtx_breakloop_isset(p)) {
    rxtx_fill_errbuf(p->errbuf, "error activating descriptor: global breakloop"
                                                                    " is set");
    return RXTX_ERROR;
  }

  if (p->verbose) {
    char direction_str[5] = "rxtx";
    if (p->direction == PCAP_D_IN) {
      strcpy(direction_str, "rx");
    } else if (p->direction == PCAP_D_OUT) {
      strcpy(direction_str, "tx");
    }
    fprintf(stderr, "using direction '%s'\n", direction_str);
  }

  if (p->verbose) {
    fprintf(stderr, "using fanout group id '%i'\n", p->fanout_group_id);
  }

  if (!p->fanout_mode) {
    rxtx_fill_errbuf(p->errbuf, "error activating descriptor: fanout mode is"
                                                       " required, but unset");
    return RXTX_ERROR;
  }

  if (p->verbose) {
    fprintf(stderr, "using fanout mode '%i'\n", p->fanout_mode);
  }

  if (p->verbose) {
    if (!p->ifindex) {
      fprintf(stderr, "using ifindex '%u' for any interface\n", p->ifindex);
    } else {
      fprintf(stderr, "using ifindex '%u' for interface '%s'\n", p->ifindex,
                                                                    p->ifname);
    }
  }

  if (p->verbose) {
    if (p->packet_buffered) {
      fprintf(stderr, "packet buffered output requested\n");
    } else {
      fprintf(stderr, "packet buffered output unwanted\n");
    }
  }

  if (p->verbose) {
    if (!p->packet_count) {
      fprintf(stderr, "using packet count '0' (infinite)\n");
    } else {
      fprintf(stderr, "using packet count '%ju'\n", p->packet_count);
    }
  }

  if (p->verbose) {
    if (p->promiscuous) {
      fprintf(stderr, "promiscuous mode requested\n");
    } else {
      fprintf(stderr, "promiscuous mode unwanted\n");
    }
  }

  /*
   * We only have to enable promiscuity once and it will stick around for the
   * duration of the process.
   */
  if (p->promiscuous) {
    if (p->ifindex == 0) {
      if (p->verbose) {
        fprintf(stderr, "skipping promiscuous mode for ifindex '%u' (any"
                                                  " interface)\n", p->ifindex);
      }
    } else {
      status = interface_set_promisc_on(p->ifindex);
      if (status == -1) {
        rxtx_fill_errbuf(p->errbuf, "error activating descriptor: failed to"
                      " enable promiscuous mode for ifindex '%u'", p->ifindex);
        return RXTX_ERROR;
      }
    }
  }

  if (!p->ring_count) {
    rxtx_fill_errbuf(p->errbuf, "error activating descriptor: ring count of"
                                      " one or more is required, but is zero");
    return RXTX_ERROR;
  }

  if (p->verbose) {
    fprintf(stderr, "using ring count '%i'\n", p->ring_count);
  }

  if (p->verbose) {
    fprintf(stderr, "verbose output requested\n");
  }

  if (!RING_COUNT(&(p->ring_set))) {
    for_each_ring(i, p) {
      RING_SET(i, &(p->ring_set));
    }
  }

  /* TODO: Compress this into standard cpulist format. */
  if (p->verbose) {
    int count = RING_COUNT(&(p->ring_set));
    fprintf(stderr, "using ring set '");
    status = 0;
    for (i = 0; i < RING_SETSIZE; i++) {
      if (RING_ISSET(i, &(p->ring_set))) {
        fprintf(stderr, "%i", i);
        status++;
        if ((status) < count) {
          fprintf(stderr, ",");
        }
      }
    }
    fprintf(stderr, "'\n");
  }

  status = 0;
  for_each_ring(i, p) {
    if (RING_ISSET(i, &(p->ring_set))) {
      status++;
    }
  }
  if (!status) {
    rxtx_fill_errbuf(p->errbuf, "error activating descriptor: ring set"
                                       " contains only out-of-bounds members");
    return RXTX_ERROR;
  }

  p->stats = calloc(1, sizeof(*p->stats));
  if (!p->stats) {
    rxtx_fill_errbuf(p->errbuf, "error activating descriptor: %s",
                                                              strerror(errno));
    return RXTX_ERROR;
  }

  status = rxtx_stats_init_with_mutex(p->stats, p->errbuf);
  if (status == RXTX_ERROR) {
    return RXTX_ERROR;
  }

  p->rings = calloc(p->ring_count, sizeof(*p->rings));
  if (!p->rings) {
    rxtx_fill_errbuf(p->errbuf, "error activating descriptor: %s",
                                                              strerror(errno));
    return RXTX_ERROR;
  }

  /*
   * This loop creates our rings, including per-ring socket fds. We need the
   * instantiation order to follow ring index order.
   */
  for_each_ring(i, p) {
    status = rxtx_ring_init(&(p->rings[i]), p, p->errbuf);
    if (status == RXTX_ERROR) {
      return RXTX_ERROR;
    }
  }

  /*
   * Any packets which were enqueued before all socket(), bind(), and
   * setsockopt() operations were completed for our rings should be considered
   * unreliable. These packets could be from another interface (due to being
   * enqueued before bind() set the ifindex) or these packets could belong to
   * another ring (due to being enqueued before all fds are added to our fanout
   * group).
   *
   * Regardless of the reason for the packets being unreliable, we want to skip
   * them in our workers and need to record which are unreliable sooner rather
   * than later.
   */
  for_each_set_ring(i, p) {
    status = rxtx_ring_mark_packets_in_buffer_as_unreliable(&(p->rings[i]));
    if (status == RXTX_ERROR) {
      return RXTX_ERROR;
    }
  }

  /*
   * Open savefiles only for rings on which we're capturing.
   */
  for_each_set_ring(i, p) {
    if (p->savefile_template) {
      status = rxtx_ring_savefile_open(&(p->rings[i]), p->savefile_template);
      if (status == RXTX_ERROR) {
        return RXTX_ERROR;
      }
    }
  }

  p->is_active = RXTX_ACTIVE;

  return 0;
}

/* ========================================================================= */
int rxtx_close(struct rxtx_desc *p) {
  int i, status;

  p->is_active = 0;
  p->breakloop = 0;
  p->fanout_data_fd = 0;
  p->fanout_group_id = 0;
  p->ifindex = 0;
  p->initialized_ring_count = 0;

  if (p->savefile_template) {
    free(p->savefile_template);
  }
  p->savefile_template = NULL;

  if (p->ifname) {
    free(p->ifname);
  }
  p->ifname = NULL;

  if (p->stats) {
    status = rxtx_stats_destroy_with_mutex(p->stats);
    if (status == RXTX_ERROR) {
      return RXTX_ERROR;
    }

    free(p->stats);
    p->stats = NULL;
  }

  if (p->rings) {
    for_each_ring(i, p) {
      status = rxtx_ring_destroy(&(p->rings[i]));
      if (status == RXTX_ERROR) {
        return RXTX_ERROR;
      }
    }

    free(p->rings);
    p->rings = NULL;
  }

  p->errbuf = NULL;

  return 0;
}

/* ---------------------------- start of getters --------------------------- */
/* ========================================================================= */
int rxtx_breakloop_isset(struct rxtx_desc *p) {
  if (rxtx_breakloop) {
    return -1;
  }
  return p->breakloop;
}

/* ========================================================================= */
pcap_direction_t rxtx_get_direction(struct rxtx_desc *p) {
  return p->direction;
}

/* ========================================================================= */
int rxtx_get_fanout_arg(struct rxtx_desc *p) {
  assert((p->fanout_group_id >> 16) == 0);
  return p->fanout_group_id | (p->fanout_mode << 16);
}

/* ========================================================================= */
int rxtx_get_fanout_data_fd(struct rxtx_desc *p) {
  return p->fanout_data_fd;
}

/* ========================================================================= */
int rxtx_get_fanout_group_id(struct rxtx_desc *p) {
  return p->fanout_group_id;
}

/* ========================================================================= */
int rxtx_get_fanout_mode(struct rxtx_desc *p) {
  return p->fanout_mode;
}

/* ========================================================================= */
unsigned int rxtx_get_ifindex(struct rxtx_desc *p) {
  return p->ifindex;
}

/* ========================================================================= */
const char *rxtx_get_ifname(struct rxtx_desc *p) {
  return p->ifname;
}

/* ========================================================================= */
int rxtx_get_initialized_ring_count(struct rxtx_desc *p) {
  return p->initialized_ring_count;
}

/* ========================================================================= */
uintmax_t rxtx_get_packet_count(struct rxtx_desc *p) {
  return p->packet_count;
}

/* ========================================================================= */
uintmax_t rxtx_get_packets_received(struct rxtx_desc *p) {
  return rxtx_stats_get_packets_received(p->stats);
}

/* ========================================================================= */
struct rxtx_ring *rxtx_get_ring(struct rxtx_desc *p, unsigned int idx) {
  if (p->is_active != RXTX_ACTIVE) {
    rxtx_fill_errbuf(p->errbuf, "error getting ring: ring access on an"
                        " inactive or activating descriptor is not permitted");
    return NULL;
  }

  assert(p->ring_count == p->initialized_ring_count);

  if (idx >= p->ring_count) {
    rxtx_fill_errbuf(p->errbuf, "error getting ring: ring idx '%u' is"
                                                        " out-of-bounds", idx);
    return NULL;
  }

  return &(p->rings[idx]);
}

/* ========================================================================= */
int rxtx_get_ring_count(struct rxtx_desc *p) {
  return p->ring_count;
}

/* ========================================================================= */
const ring_set_t *rxtx_get_ring_set(struct rxtx_desc *p) {
  return &(p->ring_set);
}

/* ========================================================================= */
const char *rxtx_get_savefile_template(struct rxtx_desc *p) {
  return p->savefile_template;
}

/* ========================================================================= */
int rxtx_packet_buffered_isset(struct rxtx_desc *p) {
  return p->packet_buffered;
}

/* ========================================================================= */
int rxtx_packet_count_reached(struct rxtx_desc *p) {
  if (!p->packet_count) {
    return 0;
  }

  if (rxtx_stats_get_packets_received(p->stats) < p->packet_count) {
    return 0;
  }

  return 1;
}

/* ========================================================================= */
int rxtx_promiscuous_isset(struct rxtx_desc *p) {
  return p->promiscuous;
}

/* ========================================================================= */
int rxtx_verbose_isset(struct rxtx_desc *p) {
  return p->verbose;
}
/* ----------------------------- end of getters ---------------------------- */

/* ---------------------------- start of setters --------------------------- */
/* ========================================================================= */
int rxtx_increment_initialized_ring_count(struct rxtx_desc *p) {
  /* p->is_active must be RXTX_ACTIVATING */

  if (p->is_active == RXTX_INACTIVE) {
    rxtx_fill_errbuf(p->errbuf, "error incrementing initialized ring count:"
            " changing initialized ring count on an inactive descriptor is not"
                                                                 " permitted");
    return RXTX_ERROR;
  }

  if (p->is_active == RXTX_ACTIVE) {
    rxtx_fill_errbuf(p->errbuf, "error incrementing initialized ring count:"
              " changing initialized ring count on an active descriptor is not"
                                                                 " permitted");
    return RXTX_ERROR;
  }

  p->initialized_ring_count++;

  return 0;
}

/* ========================================================================= */
int rxtx_increment_packets_received(struct rxtx_desc *p) {
  int status = 0;

  if (!p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error incrementing packets received: changing"
               " packets received on an inactive descriptor is not permitted");
    return RXTX_ERROR;
  }

  status = rxtx_stats_increment_packets_received(p->stats, INCREMENT_STEP);
  if (status == RXTX_ERROR) {
    return RXTX_ERROR;
  }

  return 0;
}

/* ========================================================================= */
int rxtx_set_breakloop(struct rxtx_desc *p) {
  if (!p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting breakloop: setting breakloop on"
                                   " an inactive descriptor is not permitted");
    return RXTX_ERROR;
  }

  p->breakloop++;

  return 0;
}

/* ========================================================================= */
void rxtx_set_breakloop_global(void) {
  rxtx_breakloop = 1;
}

/* ========================================================================= */
int rxtx_set_direction(struct rxtx_desc *p, pcap_direction_t direction) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting direction: changing direction"
                                  " on an active descriptor is not permitted");
    return RXTX_ERROR;
  }

  p->direction = direction;

  return 0;
}

/* ========================================================================= */
int rxtx_set_fanout_data_fd(struct rxtx_desc *p, int fd) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting fanout data fd: changing fanout"
                          " data fd on an active descriptor is not permitted");
    return RXTX_ERROR;
  }

  p->fanout_data_fd = fd;

  return 0;
}

/* ========================================================================= */
int rxtx_set_fanout_group_id(struct rxtx_desc *p, int group_id) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting fanout group id: changing"
                  " fanout group id on an active descriptor is not permitted");
    return RXTX_ERROR;
  }

  p->fanout_group_id = group_id & 0xffff;

  return 0;
}

/* ========================================================================= */
int rxtx_set_fanout_mode(struct rxtx_desc *p, int mode) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting fanout mode: changing fanout"
                             " mode on an active descriptor is not permitted");
    return RXTX_ERROR;
  }

  p->fanout_mode = mode;

  return 0;
}

/* ========================================================================= */
int rxtx_set_ifindex(struct rxtx_desc *p, unsigned int ifindex) {
  char ifname[IF_NAMESIZE] = "";

  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting ifindex: changing ifindex on an"
                                        " active descriptor is not permitted");
    return RXTX_ERROR;
  }

  if (p->ifname) {
    free(p->ifname);
  }

  if (!ifindex) {
    p->ifindex = 0;
    p->ifname = NULL;
  } else {
    p->ifindex = ifindex;
    if_indextoname(ifindex, ifname);
    if (!strlen(ifname)) {
      rxtx_fill_errbuf(p->errbuf, "error setting ifindex '%u': %s", ifindex,
                                                              strerror(errno));
      return RXTX_ERROR;
    }

    p->ifname = strdup(ifname);
    if (!p->ifname) {
      rxtx_fill_errbuf(p->errbuf, "error setting ifindex '%u': %s", ifindex,
                                                              strerror(errno));
      return RXTX_ERROR;
    }
  }

  return 0;
}

/* ========================================================================= */
int rxtx_set_ifname(struct rxtx_desc *p, const char *ifname) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting ifname: changing ifname on an"
                                        " active descriptor is not permitted");
    return RXTX_ERROR;
  }

  if (p->ifname) {
    free(p->ifname);
  }

  if (!ifname) {
    p->ifname = NULL;
    p->ifindex = 0;
  } else {
    p->ifname = strdup(ifname);
    if (!p->ifname) {
      rxtx_fill_errbuf(p->errbuf, "error setting ifname '%s': %s", ifname,
                                                              strerror(errno));
      return RXTX_ERROR;
    }

    p->ifindex = if_nametoindex(ifname);
    if (!p->ifindex) {
      rxtx_fill_errbuf(p->errbuf, "error setting ifname '%s': %s", ifname,
                                                              strerror(errno));
      return RXTX_ERROR;
    }
  }

  return 0;
}

/* ========================================================================= */
int rxtx_set_packet_count(struct rxtx_desc *p, uintmax_t count) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting packet count: changing packet"
                            " count on an active descriptor is not permitted");
    return RXTX_ERROR;
  }

  p->packet_count = count;

  return 0;
}

/* ========================================================================= */
int rxtx_set_ring_count(struct rxtx_desc *p, unsigned int count) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting ring count: changing ring"
                            " count on an active descriptor is not permitted");
    return RXTX_ERROR;
  }

  p->ring_count = count;

  return 0;
}

/* ========================================================================= */
int rxtx_set_ring_set(struct rxtx_desc *p, const ring_set_t *set) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting ring set: changing ring set on"
                                     " an active descriptor is not permitted");
    return RXTX_ERROR;
  }

  memcpy(&(p->ring_set), set, sizeof(p->ring_set));

  return 0;
}

/* ========================================================================= */
int rxtx_set_savefile_template(struct rxtx_desc *p, const char *template) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting savefile template: changing"
                " savefile template on an active descriptor is not permitted");
    return RXTX_ERROR;
  }

  if (p->savefile_template) {
    free(p->savefile_template);
  }

  if (!template) {
    p->savefile_template = NULL;
  } else {
    p->savefile_template = strdup(template);
    if (!p->savefile_template) {
      rxtx_fill_errbuf(p->errbuf, "error setting savefile template '%s': %s",
                                                    template, strerror(errno));
      return RXTX_ERROR;
    }
  }

  return 0;
}

/* ========================================================================= */
int rxtx_set_packet_buffered(struct rxtx_desc *p) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting packet buffered: changing"
                  " packet buffered on an active descriptor is not permitted");
    return RXTX_ERROR;
  }

  p->packet_buffered = 1;

  return 0;
}

/* ========================================================================= */
int rxtx_set_promiscuous(struct rxtx_desc *p) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error setting promiscuous: changing"
                      " promiscuous on an active descriptor is not permitted");
    return RXTX_ERROR;
  }

  p->promiscuous = 1;

  return 0;
}

/* ========================================================================= */
void rxtx_set_verbose(struct rxtx_desc *p) {
  p->verbose = 1;
}

/* ========================================================================= */
int rxtx_unset_packet_buffered(struct rxtx_desc *p) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error unsetting packet buffered: changing"
                  " packet buffered on an active descriptor is not permitted");
    return RXTX_ERROR;
  }

  p->packet_buffered = 0;

  return 0;
}

/* ========================================================================= */
int rxtx_unset_promiscuous(struct rxtx_desc *p) {
  if (p->is_active) {
    rxtx_fill_errbuf(p->errbuf, "error unsetting promiscuous: changing"
                      " promiscuous on an active descriptor is not permitted");
    return RXTX_ERROR;
  }

  p->promiscuous = 0;

  return 0;
}

/* ========================================================================= */
void rxtx_unset_verbose(struct rxtx_desc *p) {
  p->verbose = 0;
}
/* ----------------------------- end of setters ---------------------------- */
