/*
 * Based on vhost-user-rng of QEMU project
 *
 * Copyright (c) 2021 Mathieu Poirier <mathieu.poirier@linaro.org>
 *
 * Copyright (c) 2022-2023 Virtual Open Systems SAS.
 *
 * Author:
 *  Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
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

#ifndef VHOST_USER_RNG
#define VHOST_USER_RNG

#include "vhost_loopback.h"
#include "virtio_rng.h"
#include "vhost_user_loopback.h"
#include "virtio_loopback.h"

typedef struct VHostUserRNG {
    VirtIODevice *parent;
    struct vhost_virtqueue *vhost_vq;
    struct vhost_dev *vhost_dev;
    VirtQueue *req_vq;
    bool connected;
} VHostUserRNG;

void vhost_user_rng_realize(void);

#endif /* VHOST_USER_RNG */
