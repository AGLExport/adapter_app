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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sys/param.h>

/* Project header files */
#include "vhost_user_can.h"

#ifdef DEBUG
#define DBG(...) printf("vhost-user-can: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */

/***************************** vhost-user-can ******************************/

static const int user_feature_bits[] = {
    VIRTIO_F_VERSION_1,
    VIRTIO_RING_F_INDIRECT_DESC,
    VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_F_RING_RESET,
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VHOST_INVALID_FEATURE_BIT
};

static void vhost_user_can_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VHostUserCan *can = vdev->vhucan;

    DBG("vhost_user_can_get_config: Not yet implemented!\n");

    /*
     * TODO : Add this check depend on 'busoff' value
     * if (vcan->busoff) {
     *     config->status = cpu_to_le32(VIRTIO_CAN_S_CTRL_BUSOFF);
     * } else {
     *     config->status = cpu_to_le32(0);
     * }
     */

    memcpy(config, &can->config, sizeof(struct virtio_can_config));
}


static void vhost_user_can_start(VirtIODevice *vdev)
{
    VHostUserCan *vhucan = vdev->vhucan;
    VirtioBus *k = vdev->vbus;
    int ret;
    int i;

    DBG("vhost_user_can_start(...)\n");

    if (!k->set_guest_notifiers) {
        DBG("binding does not support guest notifiers\n");
        return;
    }

    ret = vhost_dev_enable_notifiers(vhucan->vhost_dev, vdev);
    if (ret < 0) {
        DBG("Error enabling host notifiers: %d\n", -ret);
        return;
    }

    ret = k->set_guest_notifiers(k->vdev, vhucan->vhost_dev->nvqs, true);
    if (ret < 0) {
        DBG("Error binding guest notifier: %d\n", -ret);
        goto err_host_notifiers;
    }

    vhucan->vhost_dev->acked_features = vdev->guest_features;

    ret = vhost_dev_start(vhucan->vhost_dev, vdev, true);
    if (ret < 0) {
        DBG("Error starting vhost: %d\n", -ret);
        goto err_guest_notifiers;
    }

    /*
     * guest_notifier_mask/pending not used yet, so just unmask
     * everything here.  virtio-pci will do the right thing by
     * enabling/disabling irqfd.
     */
    for (i = 0; i < vhucan->vhost_dev->nvqs; i++) {
        vhost_virtqueue_mask(vhucan->vhost_dev, vdev, i, false);
    }

    /* Wait a bit for the vrings to be set in vhost-user-device */
    sleep(1);

    return;

err_guest_notifiers:
err_host_notifiers:
    DBG("vhu_start error\n");
    return;
}

static void vhost_user_can_stop(VirtIODevice *vdev)
{
    DBG("vhost_user_can_stop: not yet implemented\n");
}

static void vhost_user_can_set_status(VirtIODevice *vdev, uint8_t status)
{
    VHostUserCan *vhucan = vdev->vhucan;
    bool should_start = virtio_device_started(vdev, status);
    DBG("vhost_user_can_set_status: %d\n", status);

    if (vhucan->vhost_dev->started == should_start) {
        DBG("can->vhost_dev->started == should_start\n");
        return;
    }

    if (should_start) {
        vhost_user_can_start(vdev);
    } else {
        vhost_user_can_stop(vdev);
    }
}

static uint64_t vhost_user_can_get_features(VirtIODevice *vdev,
                                            uint64_t features)
{
    VHostUserCan *s = vdev->vhucan;

    DBG("vhost_user_can_get_features()\n");

    return vhost_get_features(s->vhost_dev, user_feature_bits, features);
}

static void vhost_user_can_can_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    /*
     * Not normally called; it's the daemon that handles the queue;
     * however virtio's cleanup path can call this.
     */
    DBG("vhost_user_can_can_handle_output: Not yet implemented!\n");
}

/*
 * TODO: Add it later
 * static void vhost_sound_guest_notifier_mask(VirtIODevice *vdev, int idx,
 *                                             bool mask)
 */

/*
 * TODO: Add it later
 * static bool vhost_sound_guest_notifier_pending(VirtIODevice *vdev,
 *                                                int idx)
 */

static int vhost_user_can_can_config_change(struct vhost_dev *dev)
{
    VHostUserCan *vhucan = dev->vdev->vhucan;
    DBG("vhost_user_can_can_config_change: Not yet implemented!\n");

    int ret = vhost_dev_get_config(dev, (uint8_t *)&vhucan->config,
                                   sizeof(struct virtio_can_config));
    if (ret < 0) {
        DBG("vhost_user_can_sound_config_change error\n");
        return -1;
    }

    virtio_notify_config(dev->vdev);

    return 0;
}

const VhostDevConfigOps can_config_ops = {
    .vhost_dev_config_notifier = vhost_user_can_can_config_change,
};

static void vhost_user_can_init(VirtIODevice *vdev);

void vhost_user_can_realize()
{
    VirtIODevice *vdev = global_vdev;
    int ret;

    DBG("vhost_user_can_device_realize\n");

    /* This needs to be added */
    proxy = (VirtIOMMIOProxy *)malloc(sizeof(VirtIOMMIOProxy));
    *proxy = (VirtIOMMIOProxy) {
        .legacy = 1,
    };

    /* VIRTIO_ID_CAN is 36, check virtio_ids.h in linux*/
    virtio_dev_init(vdev, "virtio-can", 36, sizeof(vdev->vhucan->config));
    vhost_user_can_init(global_vdev);

    /* add queues */
    vdev->vhucan->ctrl_vq = virtio_add_queue(vdev, 64,
                                             vhost_user_can_can_handle_output);
    vdev->vhucan->tx_vq = virtio_add_queue(vdev, 64,
                                           vhost_user_can_can_handle_output);
    vdev->vhucan->rx_vq = virtio_add_queue(vdev, 64,
                                           vhost_user_can_can_handle_output);
    vdev->vhucan->vhost_dev->nvqs = 3;
    vdev->vhucan->num_queues = 3;
    vdev->vhucan->queue_size = 64;

    /* NOTE: global_vdev->vqs == vhucan->virtqs */
    vdev->vqs = (VirtQueue **)malloc(sizeof(VirtQueue *)
                                     * global_vdev->vhucan->num_queues);
    vdev->vqs[0] = vdev->vhucan->tx_vq;
    vdev->vqs[1] = vdev->vhucan->rx_vq;
    vdev->vqs[2] = vdev->vhucan->ctrl_vq;

    vdev->vhucan->vhost_vqs = (struct vhost_virtqueue *)malloc(
                                       sizeof(struct vhost_virtqueue) *
                                       vdev->vhucan->num_queues);

    /* Set up vhost device */
    vdev->vhucan->vhost_dev->num_queues = vdev->vhucan->num_queues;
    vdev->vhucan->vhost_dev->nvqs = vdev->vhucan->num_queues;
    vdev->vhucan->vhost_dev->vqs = vdev->vhucan->vhost_vqs;
    vdev->vhucan->vhost_dev->vq_index = 0;
    vdev->vhucan->vhost_dev->backend_features = 0;

    vhost_dev_set_config_notifier(vdev->vhucan->vhost_dev, &can_config_ops);

    /* TODO: Add error handling */
    vhost_dev_init(vdev->vhucan->vhost_dev);

    /* Pass the new obtained features */
    global_vdev->host_features = vdev->vhucan->vhost_dev->features;

    ret = vhost_dev_get_config(vdev->vhucan->vhost_dev,
                               (uint8_t *)&vdev->vhucan->config,
                               sizeof(struct virtio_can_config));
    if (ret < 0) {
        goto vhost_dev_init_failed;
    }

    vdev->vdev_class->print_config((uint8_t *)&vdev->vhucan->config);

    return;

vhost_dev_init_failed:
    DBG("vhost_dev_init_failed\n");
    return;
}

static void vhost_user_can_device_unrealize(VirtIODevice *vdev)
{
    DBG("vhost_user_blk_device_unrealize not yet implemented\n");
}

static struct vhost_dev *vhost_user_can_get_vhost(VirtIODevice *vdev)
{
    VHostUserCan *vhucan = vdev->vhucan;
    return vhucan->vhost_dev;
}

static void print_config_can(uint8_t *config_data)
{
    struct virtio_can_config *config_strct =
        (struct virtio_can_config *)config_data;

    DBG("print_config_can:\n");

    /* # of available physical jacks */
    DBG("\tuint16_t status: %u\n", config_strct->status);
}

static void virtio_dev_class_init(VirtIODevice *vdev)
{
    DBG("virtio_dev_class_init\n");

    vdev->vdev_class = (VirtioDeviceClass *)malloc(sizeof(VirtioDeviceClass));
    vdev->vdev_class->parent = vdev;
    vdev->vdev_class->realize = vhost_user_can_realize;
    vdev->vdev_class->unrealize = vhost_user_can_device_unrealize;
    vdev->vdev_class->get_config = vhost_user_can_get_config;
    vdev->vdev_class->get_features = vhost_user_can_get_features;
    vdev->vdev_class->set_status = vhost_user_can_set_status;
    vdev->vdev_class->update_mem_table = update_mem_table;
    vdev->vdev_class->print_config = print_config_can;
}

static void vhost_user_can_init(VirtIODevice *vdev)
{
    DBG("vhost_user_can_init\n");

    VHostUserCan *vhucan = (VHostUserCan *)malloc(sizeof(VHostUserCan));
    vdev->vhucan = vhucan;
    vdev->nvqs = &vdev->vhdev->nvqs;
    vhucan->parent = vdev;
    vhucan->virtqs = vdev->vqs;
    vhucan->vhost_dev = vdev->vhdev;

    virtio_dev_class_init(vdev);
    virtio_loopback_bus_init(vdev->vbus);
}
