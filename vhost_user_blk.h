/*
 * Based on vhost-user-blk.h of QEMU project
 *
 *   Copyright(C) 2017 Intel Corporation.
 *
 *   Authors:
 *    Changpeng Liu <changpeng.liu@intel.com>
 *
 *
 * Copyright (c) 2022-2023 Virtual Open Systems SAS.
 *
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

#ifndef VHOST_USER_BLK
#define VHOST_USER_BLK

#include "vhost_loopback.h"
#include "vhost_user_loopback.h"
#include "virtio_loopback.h"
#include <linux/virtio_blk.h>

#define TYPE_VHOST_USER_BLK "vhost-user-blk"

#define VHOST_USER_BLK_AUTO_NUM_QUEUES UINT16_MAX

struct VHostUserBlk {
    VirtIODevice *parent;
    struct vhost_virtqueue *vhost_vq;
    struct vhost_dev *vhost_dev;
    VirtQueue *req_vq;
    VirtQueue **virtqs;
    uint16_t num_queues;
    uint32_t queue_size;
    /* uint32_t config_wce; //We will need it for the next release */
    uint32_t config_wce;
    struct vhost_inflight *inflight;
    struct vhost_virtqueue *vhost_vqs;
    struct virtio_blk_config blkcfg;
    bool connected;
    bool started_vu;
};

void vhost_user_blk_realize(int queue_num, int queue_size);

#endif /* VHOST_USER_BLK */
