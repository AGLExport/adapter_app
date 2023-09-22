/*
 * Based on vhost-user-sound.c of QEMU project
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


#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sys/param.h>

/* Project header files */
#include "vhost_user_sound.h"

#ifdef DEBUG
#define DBG(...) printf("vhost-user-sound: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */

/***************************** vhost-user-sound ******************************/

/*
 * Features supported by the vhost-user-sound frontend:
 *     VIRTIO_F_VERSION_1,
 *     VIRTIO_RING_F_INDIRECT_DESC,
 *     VIRTIO_RING_F_EVENT_IDX,
 *     VIRTIO_F_RING_RESET,
 *     VIRTIO_F_NOTIFY_ON_EMPTY,
 *     VHOST_INVALID_FEATURE_BIT
 */
static const int user_feature_bits[] = {
    VIRTIO_F_VERSION_1,
    VIRTIO_RING_F_INDIRECT_DESC,
    VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_F_RING_RESET,
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VHOST_INVALID_FEATURE_BIT
};

static void vus_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VHostUserSound *snd = vdev->vhusnd;

    memcpy(config, &snd->config, sizeof(struct virtio_snd_config));
}


static void vus_start(VirtIODevice *vdev)
{
    VHostUserSound *vhusnd = vdev->vhusnd;
    VirtioBus *k = vdev->vbus;
    int ret;
    int i;

    DBG("vus_start(...)\n");

    if (!k->set_guest_notifiers) {
        DBG("binding does not support guest notifiers\n");
        return;
    }

    ret = vhost_dev_enable_notifiers(vhusnd->vhost_dev, vdev);
    if (ret < 0) {
        DBG("Error enabling host notifiers: %d\n", -ret);
        return;
    }

    ret = k->set_guest_notifiers(k->vdev, vhusnd->vhost_dev->nvqs, true);
    if (ret < 0) {
        DBG("Error binding guest notifier: %d\n", -ret);
        goto err_host_notifiers;
    }

    vhusnd->vhost_dev->acked_features = vdev->guest_features;

    ret = vhost_dev_start(vhusnd->vhost_dev, vdev, true);
    if (ret < 0) {
        DBG("Error starting vhost: %d\n", -ret);
        goto err_guest_notifiers;
    }

    /* Wait a bit before set up the vrings in vhost-user-device */
    sleep(1);

    /*
     * guest_notifier_mask/pending not used yet, so just unmask
     * everything here.  virtio-pci will do the right thing by
     * enabling/disabling irqfd.
     */
    for (i = 0; i < vhusnd->vhost_dev->nvqs; i++) {
        vhost_virtqueue_mask(vhusnd->vhost_dev, vdev, i, false);
    }

    /* Wait a bit for the vrings to be set in vhost-user-device */
    sleep(1);

    return;

err_guest_notifiers:
err_host_notifiers:
    DBG("vhu_start error\n");
    return;
}

static void vus_stop(VirtIODevice *vdev)
{
    DBG("vus_stop: not yet implemented\n");
}

static void vus_set_status(VirtIODevice *vdev, uint8_t status)
{
    VHostUserSound *vhusnd = vdev->vhusnd;
    bool should_start = virtio_device_started(vdev, status);
    DBG("vus_set_status\n");

    if (vhusnd->vhost_dev->started == should_start) {
        DBG("snd->vhost_dev->started == should_start\n");
        return;
    }

    if (should_start) {
        vus_start(vdev);
    } else {
        vus_stop(vdev);
    }
}

static uint64_t vus_get_features(VirtIODevice *vdev, uint64_t features)
{
    VHostUserSound *s = vdev->vhusnd;

    DBG("vus_get_features()\n");

    return vhost_get_features(s->vhost_dev, user_feature_bits, features);
}

static void vus_snd_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    /*
     * Not normally called; it's the daemon that handles the queue;
     * however virtio's cleanup path can call this.
     */
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

static int vus_sound_config_change(struct vhost_dev *dev)
{
    VHostUserSound *vhusnd = dev->vdev->vhusnd;
    DBG("vus_sound_config_change\n");

    int ret = vhost_dev_get_config(dev, (uint8_t *)&vhusnd->config,
                                   sizeof(struct virtio_snd_config));
    if (ret < 0) {
        DBG("vus_sound_config_change error\n");
        return -1;
    }

    virtio_notify_config(dev->vdev);

    return 0;
}

const VhostDevConfigOps snd_config_ops = {
    .vhost_dev_config_notifier = vus_sound_config_change,
};

static void vhost_user_snd_init(VirtIODevice *vdev);

void vus_device_realize()
{
    VirtIODevice *vdev = global_vdev;
    int ret;

    DBG("vus_device_realize\n");

    /* This needs to be added */
    proxy = (VirtIOMMIOProxy *)malloc(sizeof(VirtIOMMIOProxy));
    *proxy = (VirtIOMMIOProxy) {
        .legacy = 1,
    };

    /* VIRTIO_ID_SOUND is 25, check virtio_ids.h in linux*/
    virtio_dev_init(vdev, "virtio-sound", 25, sizeof(vdev->vhusnd->config));
    vhost_user_snd_init(global_vdev);

    /* add queues */
    vdev->vhusnd->ctrl_vq = virtio_add_queue(vdev, 64, vus_snd_handle_output);
    vdev->vhusnd->event_vq = virtio_add_queue(vdev, 64, vus_snd_handle_output);
    vdev->vhusnd->tx_vq = virtio_add_queue(vdev, 64, vus_snd_handle_output);
    vdev->vhusnd->rx_vq = virtio_add_queue(vdev, 64, vus_snd_handle_output);
    vdev->vhusnd->vhost_dev->nvqs = 4;
    vdev->vhusnd->num_queues = 4;
    vdev->vhusnd->queue_size = 64;

    /* NOTE: global_vdev->vqs == vhublk->virtqs */
    vdev->vqs = (VirtQueue **)malloc(sizeof(VirtQueue *)
                                     * global_vdev->vhusnd->num_queues);
    vdev->vqs[0] = vdev->vhusnd->ctrl_vq;
    vdev->vqs[1] = vdev->vhusnd->event_vq;
    vdev->vqs[2] = vdev->vhusnd->tx_vq;
    vdev->vqs[3] = vdev->vhusnd->rx_vq;

    vdev->vhusnd->vhost_vqs = (struct vhost_virtqueue *)malloc(
                                       sizeof(struct vhost_virtqueue) *
                                       vdev->vhusnd->num_queues);

    /* Set up vhost device */
    vdev->vhusnd->vhost_dev->num_queues = vdev->vhusnd->num_queues;
    vdev->vhusnd->vhost_dev->nvqs = vdev->vhusnd->num_queues;
    vdev->vhusnd->vhost_dev->vqs = vdev->vhusnd->vhost_vqs;
    vdev->vhusnd->vhost_dev->vq_index = 0;
    vdev->vhusnd->vhost_dev->backend_features = 0;

    vhost_dev_set_config_notifier(vdev->vhusnd->vhost_dev, &snd_config_ops);

    /* TODO: Add error handling */
    vhost_dev_init(vdev->vhusnd->vhost_dev);

    /* Pass the new obtained features */
    global_vdev->host_features = vdev->vhusnd->vhost_dev->features;

    ret = vhost_dev_get_config(vdev->vhusnd->vhost_dev,
                               (uint8_t *)&vdev->vhusnd->config,
                               sizeof(struct virtio_snd_config));
    if (ret < 0) {
        goto vhost_dev_init_failed;
    }

    vdev->vdev_class->print_config((uint8_t *)&vdev->vhusnd->config);

    return;

vhost_dev_init_failed:
    DBG("vhost_dev_init_failed\n");
    return;
}

static void vus_device_unrealize(VirtIODevice *vdev)
{
    DBG("vhost_user_blk_device_unrealize not yet implemented\n");
}

static struct vhost_dev *vus_get_vhost(VirtIODevice *vdev)
{
    VHostUserSound *vhusnd = vdev->vhusnd;
    return vhusnd->vhost_dev;
}

static void print_config_snd(uint8_t *config_data)
{
    struct virtio_snd_config *config_strct =
        (struct virtio_snd_config *)config_data;

    DBG("print_config_snd:\n");

    /* # of available physical jacks */
    DBG("\tuint32_t jacks: %u\n", config_strct->jacks);
    /* # of available PCM streams */
    DBG("\tuint32_t streams: %u\n", config_strct->streams);
    /* # of available channel maps */
    DBG("\tuint32_t chmaps: %u\n", config_strct->chmaps);
}

static void virtio_dev_class_init(VirtIODevice *vdev)
{
    DBG("virtio_dev_class_init\n");

    vdev->vdev_class = (VirtioDeviceClass *)malloc(sizeof(VirtioDeviceClass));
    vdev->vdev_class->parent = vdev;
    vdev->vdev_class->realize = vus_device_realize;
    vdev->vdev_class->unrealize = vus_device_unrealize;
    vdev->vdev_class->get_config = vus_get_config;
    vdev->vdev_class->get_features = vus_get_features;
    vdev->vdev_class->set_status = vus_set_status;
    vdev->vdev_class->update_mem_table = update_mem_table;
    vdev->vdev_class->print_config = print_config_snd;
}

static void vhost_user_snd_init(VirtIODevice *vdev)
{

    DBG("vhost_user_blk_init\n");

    VHostUserSound *vhusnd = (VHostUserSound *)malloc(sizeof(VHostUserSound));
    vdev->vhusnd = vhusnd;
    vdev->nvqs = &vdev->vhdev->nvqs;
    vhusnd->parent = vdev;
    vhusnd->virtqs = vdev->vqs;
    vhusnd->vhost_dev = vdev->vhdev;

    virtio_dev_class_init(vdev);
    virtio_loopback_bus_init(vdev->vbus);
}
