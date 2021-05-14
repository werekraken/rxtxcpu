/*
 * Copyright (c) 2019-present StackPath, LLC
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#define _GNU_SOURCE

#include "rxtx_ring.h"
#include "rxtx.h" // for rxtx_desc, rxtx_breakloop_isset(),
                  //     rxtx_get_direction(), rxtx_get_fanout_arg(),
                  //     rxtx_get_fanout_data_fd(), rxtx_get_fanout_mode(),
                  //     rxtx_get_ifindex(), rxtx_get_initialized_ring_count(),
                  //     rxtx_increment_packets_received(),
                  //     rxtx_increment_initialized_ring_count(),
                  //     rxtx_packet_buffered_isset(),
                  //     rxtx_packet_count_reached()
#include "rxtx_error.h"    // for RXTX_ERROR, rxtx_fill_errbuf(), RXTX_TIMEOUT
#include "rxtx_savefile.h" // for rxtx_savefile_close(), rxtx_savefile_dump(),
                           //     rxtx_savefile_open()
#include "rxtx_stats.h"    // for rxtx_stats_destroy(),
                           //     rxtx_stats_get_packets_unreliable(),
                           //     rxtx_stats_increment_packets_received(),
                           //     rxtx_stats_increment_packets_unreliable(),
                           //     rxtx_stats_increment_tp_packets(),
                           //     rxtx_stats_increment_tp_drops()

#include "ext.h" // for ext(), noext_copy()

#include <arpa/inet.h>       // for htons()
#include <linux/if_packet.h> // for PACKET_FANOUT, PACKET_FANOUT_DATA,
                             //     PACKET_FANOUT_EBPF, PACKET_OUTGOING,
                             //     PACKET_RX_RING, PACKET_STATISTICS,
                             //     PACKET_TX_RING, sockaddr_ll, tpacket_req,
                             //     tpacket_stats
#include <net/ethernet.h>    // for ETH_P_ALL
#include <sys/socket.h>      // for AF_PACKET, bind(), getsockopt(),
                             //     recv(), recvfrom(), setsockopt(),
                             //     SO_RCVTIMEO, SOCK_RAW, sockaddr, socket(),
                             //     socklen_t, SOL_PACKET, SOL_SOCKET
#include <sys/time.h>        // for timeval

#include <errno.h>   // for errno
#include <pcap.h>    // for bpf_u_int32, PCAP_D_IN, PCAP_D_OUT, pcap_pkthdr
#include <pthread.h> // for pthread_self()
#include <sched.h>   // for sched_getcpu()
#include <stdio.h>   // for asprintf(), fprintf(), NULL, stderr
#include <stdlib.h>  // for calloc(), exit(), free()
#include <string.h>  // for memset(), strcmp(), strdup(), strerror()
#include <time.h>    // for time()

#define INCREMENT_STEP 1

#define PACKET_BUFFER_SIZE 65535

#define packet_direction_is_rx(sll) (!packet_direction_is_tx(sll))
#define packet_direction_is_tx(sll) ((sll)->sll_pkttype == PACKET_OUTGOING)

/* ========================================================================= */
int rxtx_ring_init(struct rxtx_ring *p, struct rxtx_desc *rtd, char *errbuf) {
  int status = 0;

  p->errbuf = errbuf;
  p->rtd = rtd;

  p->stats = calloc(1, sizeof(*p->stats));
  if (!p->stats) {
    rxtx_fill_errbuf(p->errbuf, "error initializing ring: %s",
                                                              strerror(errno));
    return RXTX_ERROR;
  }
  rxtx_stats_init(p->stats, errbuf);

  p->idx = rxtx_get_initialized_ring_count(rtd);
  p->fd = -1;
  p->unreliable = 0;

  /*
   * The AF_PACKET address family gives us a packet socket at layer 2. The
   * SOCK_RAW socket type gives us packets which include the layer 2 header.
   * The htons(ETH_P_ALL) protocol gives us all packets from any protocol.
   */
  p->fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (p->fd == -1) {
    rxtx_fill_errbuf(p->errbuf, "error creating socket: %s", strerror(errno));
    return RXTX_ERROR;
  }

  /*
   * We're using the default, TPACKET_V1, presently. Updating to TPACKET_V3
   * would be cool.
   *
   * PACKET_RX_RING sets up a mmapped ring buffer for async packet reception.
   * PACKET_TX_RING sets up a mmapped ring buffer for packet transmission.
   *
   * I'm not sure if packets marked with PACKET_OUTGOING end up in the rx
   * ring buffer or the tx ring buffer. PACKET_TX_RING may only be used for
   * packets sent by this application, but it doesn't seem to cost much to
   * set it up.
   */
  struct tpacket_req req;
  memset(&req, 0, sizeof(req));

  status = setsockopt(p->fd, SOL_PACKET, PACKET_RX_RING, (void *)&req,
                                                                  sizeof(req));
  if (status == -1) {
    rxtx_fill_errbuf(p->errbuf, "error setting socket option: %s",
                                                              strerror(errno));
    return RXTX_ERROR;
  }

  status = setsockopt(p->fd, SOL_PACKET, PACKET_TX_RING, (void *)&req,
                                                                  sizeof(req));
  if (status == -1) {
    rxtx_fill_errbuf(p->errbuf, "error setting socket option: %s",
                                                              strerror(errno));
    return RXTX_ERROR;
  }

  /*
   * SO_RCVTIMEO sets a timeout for socket i/o system calls like recvfrom().
   * This gives us an easy way to keep our worker loops from getting stuck
   * waiting on a packet which may never arrive.
   */
  struct timeval receive_timeout;
  /* no need for memset(), we're initializing every member */
  receive_timeout.tv_sec = 0;
  receive_timeout.tv_usec = 10;
  status = setsockopt(p->fd, SOL_SOCKET, SO_RCVTIMEO, &receive_timeout,
                                                      sizeof(receive_timeout));
  if (status == -1) {
    rxtx_fill_errbuf(p->errbuf, "error setting socket option: %s",
                                                              strerror(errno));
    return RXTX_ERROR;
  }

  /*
   * Per packet(7), we need to set sll_family, sll_protocol, and sll_ifindex
   * in the sockaddr_ll we're passing to bind(). The values for sll_family
   * and sll_protocol are straight out of our earlier call to socket(). The
   * value for sll_ifindex is from our lookup.
   */
  struct sockaddr_ll sll;
  memset(&sll, 0, sizeof(sll));
  sll.sll_family = AF_PACKET;
  sll.sll_protocol = htons(ETH_P_ALL);
  sll.sll_ifindex = rxtx_get_ifindex(rtd);

  status = bind(p->fd, (struct sockaddr *)&sll, sizeof(sll));
  if (status == -1) {
    rxtx_fill_errbuf(p->errbuf, "error binding socket: %s", strerror(errno));
    return RXTX_ERROR;
  }

  /*
   * Add the socket to our fanout group using the set fanout mode and group id.
   */
  int fanout_arg = rxtx_get_fanout_arg(rtd);
  status = setsockopt(p->fd, SOL_PACKET, PACKET_FANOUT, &fanout_arg,
                                                           sizeof(fanout_arg));
  if (status == -1) {
    rxtx_fill_errbuf(p->errbuf, "error configuring fanout: %s",
                                                              strerror(errno));
    return RXTX_ERROR;
  }

#ifdef PACKET_FANOUT_EBPF
  if (rxtx_get_fanout_mode(rtd) == PACKET_FANOUT_EBPF) {
    int fanout_data_fd = rxtx_get_fanout_data_fd(rtd);
    status = setsockopt(p->fd, SOL_PACKET, PACKET_FANOUT_DATA, &fanout_data_fd,
                                                       sizeof(fanout_data_fd));
    if (status == -1) {
      rxtx_fill_errbuf(p->errbuf, "error configuring fanout: %s",
                                                              strerror(errno));
      return RXTX_ERROR;
    }
  }
#endif // PACKET_FANOUT_EBPF

  rxtx_increment_initialized_ring_count(rtd);

  return 0;
}

/* ========================================================================= */
int rxtx_ring_destroy(struct rxtx_ring *p) {
  p->fd = 0;

  rxtx_stats_destroy(p->stats);
  free(p->stats);
  p->stats = NULL;

  p->rtd = NULL;

  if (p->savefile) {
    int status = rxtx_savefile_close(p->savefile);
    free(p->savefile);
    if (status == RXTX_ERROR) {
      return RXTX_ERROR;
    }
  }
  p->savefile = NULL;

  p->idx = 0;
  p->errbuf = NULL;

  return 0;
}

/* ========================================================================= */
void rxtx_ring_clear_unreliable_packets_in_buffer(struct rxtx_ring *p) {
  unsigned char packet[PACKET_BUFFER_SIZE];
  int length = 0;

  while (!rxtx_breakloop_isset(p->rtd)) {

    /*
     * If we've directly processed all unreliable packets, we know all
     * unreliable packets have been cleared.
     */
    if (rxtx_stats_get_packets_unreliable(p->stats) >= p->unreliable) {
      break;
    }

    length = recv(p->fd, packet, sizeof(packet), 0);

    /*
     * If we see the ring buffer go empty, we know all unreliable packets have
     * been cleared.
     */
    if (length == -1) {
      break;
    }

    /*
     * Otherwise, this packet should be treated as unreliable.
     *
     * NOTE: We don't check return here because ring stats should never have a
     *       mutex and should therefore always return 0.
     *
     */
    rxtx_stats_increment_packets_unreliable(p->stats, INCREMENT_STEP);
  }
}

/* ========================================================================= */
int rxtx_ring_get_idx(struct rxtx_ring *p) {
  return p->idx;
}

/* ========================================================================= */
uintmax_t rxtx_ring_get_packets_received(struct rxtx_ring *p) {
  return rxtx_stats_get_packets_received(p->stats);
}

/* ========================================================================= */
void *rxtx_ring_loop(void *ring) {
  struct rxtx_ring *p = ring;

  unsigned char packet[PACKET_BUFFER_SIZE];

  struct pcap_pkthdr header;
  memset(&header, 0, sizeof(header));

  int length = 0;
  int status = 0;

  if (rxtx_verbose_isset(p->rtd)) {
    fprintf(stderr, "Worker '%lu' handling ring '%d' running on cpu '%d'.\n",
                         pthread_self(), rxtx_ring_get_idx(p), sched_getcpu());
  }

  rxtx_ring_clear_unreliable_packets_in_buffer(p);

  while (!rxtx_breakloop_isset(p->rtd)) {

    if (rxtx_packet_count_reached(p->rtd)) {
      break;
    }

    status = length = rxtx_ring_next_packet(p, &header, packet);

    if (status == RXTX_TIMEOUT) {
      continue;
    }

    if (status == RXTX_ERROR) {
      return (void *)RXTX_ERROR;
    }

    if (length == 0) {
      continue;
    }

    status = rxtx_increment_packets_received(p->rtd);
    if (status == RXTX_ERROR) {
      return (void *)RXTX_ERROR;
    }

    if (p->savefile) {
      status = rxtx_savefile_dump(p->savefile, &header, packet,
                                           rxtx_packet_buffered_isset(p->rtd));

      if (status == RXTX_ERROR) {
        return (void *)RXTX_ERROR;
      }
    }
  }

  return NULL;
}

/* ========================================================================= */
int rxtx_ring_mark_packets_in_buffer_as_unreliable(struct rxtx_ring *p) {
  int status = rxtx_ring_update_tpacket_stats(p);
  if (status == RXTX_ERROR) {
    return RXTX_ERROR;
  }

  p->unreliable = rxtx_stats_get_tp_packets(p->stats)
                    - rxtx_stats_get_tp_drops(p->stats);

  return 0;
}

/* ========================================================================= */
int rxtx_ring_next_packet(struct rxtx_ring *p, struct pcap_pkthdr *header,
                                                              u_char *packet) {
  struct sockaddr_ll sll;
  unsigned int sll_len = sizeof(sll);

  int length = 0;
  int status = 0;

  length = recvfrom(p->fd, packet, PACKET_BUFFER_SIZE, 0,
                                          (struct sockaddr *)&sll, &sll_len);

  if (length == -1) {
    return RXTX_TIMEOUT;
  }

  if (rxtx_get_direction(p->rtd) == PCAP_D_OUT &&
                                                packet_direction_is_rx(&sll)) {
    return 0;
  }

  if (rxtx_get_direction(p->rtd) == PCAP_D_IN &&
                                                packet_direction_is_tx(&sll)) {
    return 0;
  }

  status = rxtx_stats_increment_packets_received(p->stats, INCREMENT_STEP);
  if (status == RXTX_ERROR) {
    return RXTX_ERROR;
  }

  header->caplen     = (bpf_u_int32)length;
  header->len        = (bpf_u_int32)length;
  header->ts.tv_sec  = time(NULL);
  header->ts.tv_usec = 0;

  return length;
}

/* ========================================================================= */
int rxtx_ring_savefile_open(struct rxtx_ring *p, const char *template) {
  int status = 0;
  char *filename = NULL;
  char *noext = NULL;

  if (!template) {
    rxtx_fill_errbuf(p->errbuf, "error opening savefile: invalid template");
    return RXTX_ERROR;
  }

  p->savefile = calloc(1, sizeof(*p->savefile));
  if (!p->savefile) {
    rxtx_fill_errbuf(p->errbuf, "error opening savefile: %s", strerror(errno));
    return RXTX_ERROR;
  }

  if (strcmp(template, "-") == 0) {
    filename = strdup(template);
    if (!filename) {
      rxtx_fill_errbuf(p->errbuf, "error opening savefile: %s",
                                                              strerror(errno));
      return RXTX_ERROR;
    }
  } else {
    noext = noext_copy(template);
    if (!noext) {
      rxtx_fill_errbuf(p->errbuf, "error opening savefile: %s",
                                                              strerror(errno));
      return RXTX_ERROR;
    }

    status = asprintf(&filename, "%s-%d.%s", noext, p->idx, ext(template));
    if (status == -1) {
      rxtx_fill_errbuf(p->errbuf, "error opening savefile: %s",
                                                              strerror(errno));
      return RXTX_ERROR;
    }

    free(noext);
  }

  status = rxtx_savefile_open(p->savefile, filename, p->errbuf);
  free(filename);
  if (status == RXTX_ERROR) {
    return RXTX_ERROR;
  }

  return 0;
}

/* ========================================================================= */
int rxtx_ring_update_tpacket_stats(struct rxtx_ring *p) {
  int status = 0;
  struct tpacket_stats tp_stats;
  socklen_t len = sizeof(tp_stats);

  status = getsockopt(p->fd, SOL_PACKET, PACKET_STATISTICS, &tp_stats, &len);
  if (status < 0) {
    rxtx_fill_errbuf(p->errbuf, "error collecting packet statistics: %s",
                                                              strerror(errno));
    return RXTX_ERROR;
  }

  status = rxtx_stats_increment_tp_packets(p->stats, tp_stats.tp_packets);
  if (status == RXTX_ERROR) {
    return RXTX_ERROR;
  }

  return rxtx_stats_increment_tp_drops(p->stats, tp_stats.tp_drops);
}
