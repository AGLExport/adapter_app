/*
 * Based on vhost-user-rng of Qemu project
 *
 * Copyright (c) 2021 Mathieu Poirier <mathieu.poirier@linaro.org>
 *
 * Copyright (c) 2022 Virtual Open Systems SAS.
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sys/param.h>

/* Project header files */
#include "vhost_loopback.h"
#include "vhost_user_rng.h"

#ifdef DEBUG
#define DBG(...) printf("vhost-user-rng: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */

static void vu_rng_start(VirtIODevice *vdev)
{
    VHostUserRNG *rng = vdev->vhrng;
    VirtioBus *k = vdev->vbus;
    int ret;
    int i;

    /* TODO: This might be deleted in future */
    if (!k->set_guest_notifiers) {
        DBG("binding does not support guest notifiers\n");
        return;
    }

    ret = vhost_dev_enable_notifiers(rng->vhost_dev, vdev);
    if (ret < 0) {
        DBG("Error enabling host notifiers: %d\n", ret);
        return;
    }

    ret = k->set_guest_notifiers(vdev, rng->vhost_dev->nvqs, true);
    if (ret < 0) {
        DBG("Error binding guest notifier: %d\n", ret);
        return;
    }

    rng->vhost_dev->acked_features = vdev->guest_features;

    ret = vhost_dev_start(rng->vhost_dev, vdev);
    if (ret < 0) {
        DBG("Error starting vhost-user-rng: %d\n", ret);
        return;
    }

    /*
     * guest_notifier_mask/pending not used yet, so just unmask
     * everything here. virtio-pci will do the right thing by
     * enabling/disabling irqfd.
     */
    for (i = 0; i < rng->vhost_dev->nvqs; i++) {
        vhost_virtqueue_mask(rng->vhost_dev, vdev, i, false);
    }

}

/* TODO: We need to implement this function in a future release */
static void vu_rng_stop(VirtIODevice *vdev)
{
    VHostUserRNG *rng = vdev->vhrng;
}


static uint64_t vu_rng_get_features(VirtIODevice *vdev,
                                    uint64_t requested_features)
{
    /* No feature bits used yet */
    return requested_features;
}

/* TODO: We need to implement this function in a future release */
static void vu_rng_guest_notifier_mask(VirtIODevice *vdev, int idx, bool mask)
{
    VHostUserRNG *rng = vdev->vhrng;

    /* vhost_virtqueue_mask(&rng->vhost_dev, vdev, idx, mask); */
}

/* TODO: We need to implement this function in a future release */
static bool vu_rng_guest_notifier_pending(VirtIODevice *vdev, int idx)
{
    VHostUserRNG *rng = vdev->vhrng;

    /* return vhost_virtqueue_pending(&rng->vhost_dev, idx); */
    return 1;
}

static void vu_rng_set_status(VirtIODevice *vdev, uint8_t status)
{
    VHostUserRNG *rng = vdev->vhrng;
    bool should_start = status & VIRTIO_CONFIG_S_DRIVER_OK;

    if (rng->vhost_dev->started == should_start) {
        DBG("rng->vhost_dev->started != should_start\n");
        return;
    }

    if (should_start) {
        vu_rng_start(vdev);
    } else {
        DBG("vu_rng_stop(vdev)\n");
        /* TODO: Add vu_rng_stop(vdev); when this function is implemented */
    }
}

static void virtio_dev_class_init (VirtIODevice *vdev) {

    vdev->vdev_class = (VirtioDeviceClass *) malloc(sizeof(VirtioDeviceClass));
    vdev->vdev_class->parent = vdev;
    vdev->vdev_class->set_status = vu_rng_set_status;
    vdev->vdev_class->get_features = vu_rng_get_features;
    vdev->vdev_class->guest_notifier_mask = vu_rng_guest_notifier_mask;
    vdev->vdev_class->guest_notifier_pending = vu_rng_guest_notifier_pending;
}


void vhost_user_rng_init(VirtIODevice *vdev) {

    VHostUserRNG *vhrng = (VHostUserRNG*) malloc (sizeof(VHostUserRNG));
    vdev->vhrng = vhrng;
    vhrng->parent = vdev;
    vhrng->req_vq = vdev->vq;
    vhrng->vhost_dev = dev;

    virtio_dev_class_init (vdev);
    virtio_mmio_bus_init(vdev->vbus);
}

static void vu_rng_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    /*
     * Not normally called; it's the daemon that handles the queue;
     * however virtio's cleanup path can call this.
     */
    DBG("vu_rng_handle_output\n");
}


void vhost_user_rng_realize(void)
{
    virtio_dev_init(global_vdev, "virtio-rng", 4, 0);

    /* This needs to be change to vhost-user-rng init */
    vhost_user_rng_init(global_vdev);

    global_vdev->vq = virtio_add_queue(global_vdev, 4, vu_rng_handle_output);

    global_vdev->host_features = 0x39000000;

    proxy = (VirtIOMMIOProxy*) malloc (sizeof(VirtIOMMIOProxy));
    *proxy = (VirtIOMMIOProxy) {
        .legacy = 1,
    };

    /* Virtqueues conf */
    dev->nvqs = 1;
    dev->vqs = (struct vhost_virtqueue*) malloc(dev->nvqs * sizeof(struct vhost_virtqueue));

    vhost_dev_init(dev);
}
