/*
 * Virtio CAN Device
 *
 * Based on virtio_can.h of OpenSynergy's virtio-can RFC
 * https://github.com/OpenSynergy/qemu/tree/virtio-can-spec-rfc-v3
 *
 * Copyright (C) 2021-2023 OpenSynergy GmbH
 * Copyright (c) 2023 Virtual Open Systems SAS.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#ifndef VHOST_USER_CAN
#define VHOST_USER_CAN

#include "virtio_loopback.h"
#include "vhost_loopback.h"
#include "vhost_user_loopback.h"

/* The following are defined into virtio_can.h -- Delete them in the future */
#define VIRTIO_CAN_S_CTRL_BUSOFF (1u << 0) /* Controller BusOff */
struct virtio_can_config {
    /* CAN controller status */
    __le16 status;
};

typedef struct VHostUserCan {
    VirtIODevice *parent;
    struct vhost_virtqueue *vhost_vqs;
    VirtQueue **virtqs;
    uint16_t num_queues;
    uint32_t queue_size;
    struct virtio_can_config config;
    struct vhost_dev *vhost_dev;
    VirtQueue *ctrl_vq;
    VirtQueue *tx_vq;
    VirtQueue *rx_vq;
    /* Support classic CAN */
    bool support_can_classic;
    /* Support CAN FD */
    bool support_can_fd;
} VHostUserCan;

void vhost_user_can_realize(void);

#endif /* VHOST_USER_CAN */
