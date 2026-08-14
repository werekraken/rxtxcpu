/*
 * Copyright (c) 2019-present StackPath, LLC
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "rxtx_savefile.h"
#include "rxtx_error.h" // for RXTX_ERROR, rxtx_fill_errbuf()

#include <errno.h>  // for errno
#include <pcap.h>   // for DLT_EN10MB, pcap_close(), pcap_dump(),
                    //     pcap_dump_close(), pcap_dump_flush(),
                    //     pcap_dump_open(), PCAP_ERROR, pcap_geterr(),
                    //     pcap_open_dead(), pcap_pkthdr
#include <stdlib.h> // for free()
#include <string.h> // for strdup(), strerror()

#define SNAPLEN 65535

#ifdef TESTING
  #include "tests/rxtx_savefile/helper.h"
#endif

/* ========================================================================= */
int rxtx_savefile_open(struct rxtx_savefile *p, const char *filename,
                                                                char *errbuf) {
  p->errbuf = errbuf;
  p->name = strdup(filename);
  p->pd = pcap_open_dead(DLT_EN10MB, SNAPLEN);

  if (!p->name || !p->pd) {
    rxtx_fill_errbuf(p->errbuf, "error opening savefile '%s'", filename);
    return RXTX_ERROR;
  }

  p->pdd = pcap_dump_open(p->pd, p->name);

  if (!p->pdd) {
    rxtx_fill_errbuf(p->errbuf, "error opening savefile '%s': libpcap: %s",
                                                  p->name, pcap_geterr(p->pd));
    return RXTX_ERROR;
  }

  return 0;
}

/* ========================================================================= */
int rxtx_savefile_dump(struct rxtx_savefile *p, struct pcap_pkthdr *header,
                                                   u_char *packet, int flush) {
  pcap_dump((u_char *)p->pdd, header, packet);

  if (flush) {
    if (pcap_dump_flush(p->pdd) == PCAP_ERROR) {
      /*
       * pcap_dump_flush() only returns PCAP_ERROR when fflush() returns EOF;
       * errno should be set.
       */
      rxtx_fill_errbuf(p->errbuf, "error writing to savefile '%s': %s",
                                                     p->name, strerror(errno));
      return RXTX_ERROR;
    }
  }

  return 0;
}

/* ========================================================================= */
int rxtx_savefile_close(struct rxtx_savefile *p) {
  int status = 0;

  if (p->pdd) {
    /*
     * protect against silent write failures
     */
    if ((pcap_dump_flush(p->pdd)) == PCAP_ERROR) {
      /*
       * pcap_dump_flush() only returns PCAP_ERROR when fflush() returns EOF;
       * errno should be set.
       */
      rxtx_fill_errbuf(p->errbuf, "error writing to savefile '%s': %s", p->name,
                                                              strerror(errno));
      status = RXTX_ERROR;
    }

    pcap_dump_close(p->pdd);
    p->pdd = NULL;
  }

  if (p->pd) {
    pcap_close(p->pd);
    p->pd = NULL;
  }

  free(p->name);
  p->name = NULL;
  p->errbuf = NULL;

  return status;
}
