/*
 * Based on vhost.h of QEMU project
 *
 * Copyright 2022 Virtual Open Systems SAS.
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

#ifndef LOOPBACK_VHOST_H
#define LOOPBACK_VHOST_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <poll.h>
#include <pthread.h>
#include "vhost_user_loopback.h"
#include "virtio_loopback.h"

#define VHOST_INVALID_FEATURE_BIT (0xff)
#define VHOST_QUEUE_NUM_CONFIG_INR 0

int vhost_dev_enable_notifiers(struct vhost_dev *hdev, VirtIODevice *vdev);
int vhost_dev_start(struct vhost_dev *hdev, VirtIODevice *vdev, bool vrings);
void vhost_virtqueue_mask(struct vhost_dev *hdev, VirtIODevice *vdev,
                          int n, bool mask);
int vhost_dev_get_config(struct vhost_dev *hdev, uint8_t *config,
                         uint32_t config_len);
int vhost_dev_set_config(struct vhost_dev *hdev, const uint8_t *data,
                         uint32_t offset, uint32_t size, uint32_t flags);
uint64_t vhost_get_features(struct vhost_dev *hdev, const int *feature_bits,
                            uint64_t features);
void vhost_ack_features(struct vhost_dev *hdev, const int *feature_bits,
                        uint64_t features);

/**
 * vhost_dev_set_config_notifier() - register VhostDevConfigOps
 * @hdev: common vhost_dev_structure
 * @ops: notifier ops
 *
 * If the device is expected to change configuration a notifier can be
 * setup to handle the case.
 */

typedef struct VhostDevConfigOps VhostDevConfigOps;

void vhost_dev_set_config_notifier(struct vhost_dev *dev,
                                   const VhostDevConfigOps *ops);
int vhost_dev_prepare_inflight(struct vhost_dev *hdev, VirtIODevice *vdev);

int vhost_dev_get_inflight(struct vhost_dev *dev, uint16_t queue_size,
                           struct vhost_inflight *inflight);

int vhost_dev_set_inflight(struct vhost_dev *dev,
                           struct vhost_inflight *inflight);

void update_mem_table(VirtIODevice *vdev);


struct vhost_inflight {
    int fd;
    void *addr;
    uint64_t size;
    uint64_t offset;
    uint16_t queue_size;
};

#endif /* LOOPBACK_VHOST_H */
