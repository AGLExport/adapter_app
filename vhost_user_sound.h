/*
 * Based on vhost-user-sound.h of QEMU project
 *
 * Copyright 2020 Red Hat, Inc.
 *
 * Copyright (c) 2023 Virtual Open Systems SAS.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.  See the COPYING file in the
 * top-level directory.
 *
 */

#ifndef VHOST_USER_SOUND
#define VHOST_USER_SOUND

#include "virtio_loopback.h"
#include "vhost_loopback.h"
#include "vhost_user_loopback.h"
#include <linux/virtio_snd.h>

typedef struct VHostUserSound {
    /*< private >*/
    VirtIODevice *parent;
    struct vhost_virtqueue *vhost_vqs;
    VirtQueue **virtqs;
    uint16_t num_queues;
    uint32_t queue_size;
    struct virtio_snd_config config;
    struct vhost_dev *vhost_dev;
    VirtQueue *ctrl_vq;
    VirtQueue *event_vq;
    VirtQueue *tx_vq;
    VirtQueue *rx_vq;
    /*< public >*/
} VHostUserSound;

void vus_device_realize(void);

#endif /* VHOST_USER_BLK */
