/*
 * Copyright 2022-2023 Virtual Open Systems SAS.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef VIRTIO_RNG_DEV
#define VIRTIO_RNG_DEV

#include "virtio_loopback.h"

extern const char test_str[64];

typedef struct VirtIORNGConf {
    uint64_t max_bytes;
    uint32_t period_ms;
} VirtIORNGConf;

typedef struct VirtIORNG {
    VirtIODevice *parent_obj;

    /* Only one vq - guest puts buffer(s) on it when it needs entropy */
    VirtQueue *vq;
    VirtIORNGConf conf;

    /*
     * We purposefully don't migrate this state.  The quota will reset on the
     * destination as a result.  Rate limiting is host state, not guest state.
     */
    int64_t quota_remaining;
    bool activate_timer;

} VirtIORNG;

bool is_guest_ready(VirtIORNG *vrng);
size_t get_request_size(VirtQueue *vq, unsigned quota);
void virtio_rng_set_status(VirtIODevice *vdev, uint8_t status);
void virtio_rng_process(VirtIORNG *vrng);
void chr_read(VirtIORNG *vrng, const void *buf, size_t size);
void virtio_rng_realize(void);
void virtio_rng_init(VirtIODevice *vdev);

#endif /* VIRTIO_RNG */
