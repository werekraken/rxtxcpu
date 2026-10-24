/*
 * Copyright (c) 2019-present StackPath, LLC
 * All rights reserved.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include "rxtx_stats.h"
#include "rxtx_error.h" // for RXTX_ERROR, rxtx_fill_errbuf()

#include <errno.h>  // for errno
#include <stdlib.h> // for calloc(), free()
#include <string.h> // for strerror()

#ifdef TESTING
  #include "tests/rxtx_stats/helper.h"
#endif

/* ========================================================================= */
void rxtx_stats_init(struct rxtx_stats *p, char *errbuf) {
  p->errbuf = errbuf;
  p->packets_received = 0;
  p->packets_unreliable = 0;
  p->tp_packets = 0;
  p->tp_drops = 0;

}

/* ========================================================================= */
void rxtx_stats_destroy(struct rxtx_stats *p) {
  p->tp_drops = 0;
  p->tp_packets = 0;
  p->packets_unreliable = 0;
  p->packets_received = 0;
  p->errbuf = NULL;
}

/* ========================================================================= */
int rxtx_stats_mutex_init(struct rxtx_stats *p) {
  p->mutex = calloc(1, sizeof(*p->mutex));
  if (!p->mutex) {
    rxtx_fill_errbuf(p->errbuf, "error initializing stats mutex: %s",
                                                              strerror(errno));
    return RXTX_ERROR;
  }

  int status = pthread_mutex_init(p->mutex, NULL);
  if (status) {
    rxtx_fill_errbuf(p->errbuf, "error initializing stats mutex: %s",
                                                             strerror(status));
    return RXTX_ERROR;
  }

  return 0;
}

/* ========================================================================= */
int rxtx_stats_mutex_destroy(struct rxtx_stats *p) {
  if (p->mutex) {
    int status = pthread_mutex_destroy(p->mutex);
    if (status) {
      rxtx_fill_errbuf(p->errbuf, "error destroying stats mutex: %s",
                                                             strerror(status));
      return RXTX_ERROR;
    }

    free(p->mutex);
    p->mutex = NULL;
  }

  return 0;
}

/* ========================================================================= */
int rxtx_stats_init_with_mutex(struct rxtx_stats *p, char *errbuf) {
  rxtx_stats_init(p, errbuf);
  return rxtx_stats_mutex_init(p);
}

/* ========================================================================= */
int rxtx_stats_destroy_with_mutex(struct rxtx_stats *p) {
  int status = rxtx_stats_mutex_destroy(p);
  rxtx_stats_destroy(p);
  return status;
}

/* ========================================================================= */
uintmax_t rxtx_stats_get_packets_received(struct rxtx_stats *p) {
  return p->packets_received;
}

/* ========================================================================= */
uintmax_t rxtx_stats_get_packets_unreliable(struct rxtx_stats *p) {
  return p->packets_unreliable;
}

/* ========================================================================= */
uintmax_t rxtx_stats_get_tp_packets(struct rxtx_stats *p) {
  return p->tp_packets;
}

/* ========================================================================= */
uintmax_t rxtx_stats_get_tp_drops(struct rxtx_stats *p) {
  return p->tp_drops;
}

/* ========================================================================= */
int rxtx_stats_increment_packets_received(struct rxtx_stats *p, int step) {
  int status;

  if (p->mutex) {
    status = pthread_mutex_lock(p->mutex);
    if (status) {
      rxtx_fill_errbuf(p->errbuf, "error locking stats mutex: %s",
                                                             strerror(status));
      return RXTX_ERROR;
    }
  }

  p->packets_received += step;

  if (p->mutex) {
    status = pthread_mutex_unlock(p->mutex);
    if (status) {
      rxtx_fill_errbuf(p->errbuf, "error unlocking stats mutex: %s",
                                                             strerror(status));
      return RXTX_ERROR;
    }
  }

  return 0;
}

/* ========================================================================= */
int rxtx_stats_increment_packets_unreliable(struct rxtx_stats *p, int step) {
  int status;

  if (p->mutex) {
    status = pthread_mutex_lock(p->mutex);
    if (status) {
      rxtx_fill_errbuf(p->errbuf, "error locking stats mutex: %s",
                                                             strerror(status));
      return RXTX_ERROR;
    }
  }

  p->packets_unreliable += step;

  if (p->mutex) {
    status = pthread_mutex_unlock(p->mutex);
    if (status) {
      rxtx_fill_errbuf(p->errbuf, "error unlocking stats mutex: %s",
                                                             strerror(status));
      return RXTX_ERROR;
    }
  }

  return 0;
}

/* ========================================================================= */
int rxtx_stats_increment_tp_packets(struct rxtx_stats *p, int step) {
  int status;

  if (p->mutex) {
    status = pthread_mutex_lock(p->mutex);
    if (status) {
      rxtx_fill_errbuf(p->errbuf, "error locking stats mutex: %s",
                                                             strerror(status));
      return RXTX_ERROR;
    }
  }

  p->tp_packets += step;

  if (p->mutex) {
    status = pthread_mutex_unlock(p->mutex);
    if (status) {
      rxtx_fill_errbuf(p->errbuf, "error unlocking stats mutex: %s",
                                                             strerror(status));
      return RXTX_ERROR;
    }
  }

  return 0;
}

/* ========================================================================= */
int rxtx_stats_increment_tp_drops(struct rxtx_stats *p, int step) {
  int status;

  if (p->mutex) {
    status = pthread_mutex_lock(p->mutex);
    if (status) {
      rxtx_fill_errbuf(p->errbuf, "error locking stats mutex: %s",
                                                             strerror(status));
      return RXTX_ERROR;
    }
  }

  p->tp_drops += step;

  if (p->mutex) {
    status = pthread_mutex_unlock(p->mutex);
    if (status) {
      rxtx_fill_errbuf(p->errbuf, "error unlocking stats mutex: %s",
                                                             strerror(status));
      return RXTX_ERROR;
    }
  }

  return 0;
}
