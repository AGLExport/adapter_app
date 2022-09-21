/*
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

int vhost_dev_enable_notifiers(struct vhost_dev *hdev, VirtIODevice *vdev);
int vhost_dev_start(struct vhost_dev *hdev, VirtIODevice *vdev);
void vhost_virtqueue_mask(struct vhost_dev *hdev, VirtIODevice *vdev, int n, bool mask);

#endif /* LOOPBACK_VHOST_H */
