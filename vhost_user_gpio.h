/*
 * Based on virtio-gpio.h of QEMU project
 *
 * Copyright (c) 2023 Virtual Open Systems SAS.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.  See the COPYING file in the
 * top-level directory.
 */

#ifndef VHOST_USER_GPIO
#define VHOST_USER_GPIO

#include "vhost_loopback.h"
#include "vhost_user_loopback.h"
#include "virtio_loopback.h"
#include <linux/virtio_gpio.h>
#include "queue.h"
#include <sys/mman.h>

#define TYPE_VHOST_USER_GPIO "vhost-user-gpio-device"
#define VIRTIO_GPIO_F_IRQ 0

struct VHostUserGPIO {
    VirtIODevice *parent;
    struct virtio_gpio_config config;
    struct vhost_virtqueue *vhost_vqs;
    struct vhost_dev *vhost_dev;
    VirtQueue *command_vq;
    VirtQueue *interrupt_vq;
    bool connected;
    bool started_vu;
};

void vu_gpio_device_realize();

#endif /* VHOST_USER_GPIO */
