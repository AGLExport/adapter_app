/*
 * Based on vhost-user-blk.c of QEMU project
 *
 *   Copyright(C) 2017 Intel Corporation.
 *
 *   Authors:
 *    Changpeng Liu <changpeng.liu@intel.com>
 *
 *   Largely based on the "vhost-user-scsi.c" and "vhost-scsi.c" implemented by:
 *   Felipe Franciosi <felipe@nutanix.com>
 *   Stefan Hajnoczi <stefanha@linux.vnet.ibm.com>
 *   Nicholas Bellinger <nab@risingtidesystems.com>
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
#include "vhost_user_blk.h"

#ifdef DEBUG
#define DBG(...) printf("vhost-user-blk: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */


#define REALIZE_CONNECTION_RETRIES 3
static uint64_t vhost_user_blk_get_features(VirtIODevice *vdev,
                                            uint64_t features);

static int vhost_user_blk_start(VirtIODevice *vdev)
{
    VHostUserBlk *s = vdev->vhublk;
    VirtioBus *k = vdev->vbus;
    int i, ret;

    DBG("vhost_user_blk_start\n");

    if (!k->set_guest_notifiers) {
        DBG("binding does not support guest notifiers\n");
        return -1;
    }

    ret = vhost_dev_enable_notifiers(s->vhost_dev, vdev);
    if (ret < 0) {
        DBG("Error enabling host notifiers\n");
        return ret;
    }

    ret = k->set_guest_notifiers(k->vdev, s->vhost_dev->nvqs, true);
    if (ret < 0) {
        DBG("Error enabling host notifier\n");
        return ret;
    }

    s->vhost_dev->acked_features = vdev->guest_features;

    /* FIXME: We might do not need that */
    ret = vhost_dev_prepare_inflight(s->vhost_dev, vdev);
    if (ret < 0) {
        DBG("Error setting inflight format\n");
        return ret;
    }

    if (!s->inflight->addr) {
        ret = vhost_dev_get_inflight(s->vhost_dev, s->queue_size, s->inflight);
        if (ret < 0) {
            DBG("Error getting inflight\n");
            return ret;
        }
    }

    ret = vhost_dev_set_inflight(s->vhost_dev, s->inflight);
    if (ret < 0) {
        DBG("Error setting inflight\n");
        return ret;
    }

    DBG("After vhost_dev_set_inflight\n");


    ret = vhost_dev_start(s->vhost_dev, vdev);
    if (ret < 0) {
        DBG("Error starting vhost\n");
        return ret;
    }

    s->started_vu = true;

    DBG("vhost_virtqueue_mask\n");
    /*
     * guest_notifier_mask/pending not used yet, so just unmask
     * everything here. virtio-pci will do the right thing by
     * enabling/disabling irqfd.
     */
    for (i = 0; i < s->vhost_dev->nvqs; i++) {
        vhost_virtqueue_mask(s->vhost_dev, vdev, i, false);
    }

    DBG("vhost_user_blk_start return successfully: %d\n", ret);
    return ret;

}

static void vhost_user_blk_stop(VirtIODevice *vdev)
{
    DBG("Not yet implemented\n");
}

static int vhost_user_blk_handle_config_change(struct vhost_dev *dev)
{
    int ret;
    struct virtio_blk_config blkcfg;
    VHostUserBlk *s = dev->vdev->vhublk;

    DBG("vhost_user_blk_handle_config_change(...)\n");

    ret = vhost_dev_get_config(dev, (uint8_t *)&blkcfg,
                               sizeof(struct virtio_blk_config));
    if (ret < 0) {
        DBG("vhost_dev_get_config\n");
        return ret;
    }

    /* valid for resize only */
    if (blkcfg.capacity != s->blkcfg.capacity) {
        DBG("blkcfg.capacity != s->blkcfg.capacity\n");
        s->blkcfg.capacity = blkcfg.capacity;
        memcpy(dev->vdev->config, &s->blkcfg, sizeof(struct virtio_blk_config));
        DBG("To virtio_notify_config\n");
        virtio_notify_config(dev->vdev);
    }

    return 0;
}


const VhostDevConfigOps blk_ops = {
    .vhost_dev_config_notifier = vhost_user_blk_handle_config_change,
};


static uint64_t vhost_user_blk_get_features(VirtIODevice *vdev,
                                            uint64_t features)
{
    VHostUserBlk *s = vdev->vhublk;

    DBG("vhost_user_blk_get_features()\n");

    /* Turn on pre-defined features */
    virtio_add_feature(&features, VIRTIO_BLK_F_SEG_MAX);
    virtio_add_feature(&features, VIRTIO_BLK_F_GEOMETRY);
    virtio_add_feature(&features, VIRTIO_BLK_F_TOPOLOGY);
    virtio_add_feature(&features, VIRTIO_BLK_F_FLUSH);
    virtio_add_feature(&features, VIRTIO_BLK_F_DISCARD);
    virtio_add_feature(&features, VIRTIO_BLK_F_WRITE_ZEROES);
    virtio_add_feature(&features, VIRTIO_BLK_F_BLK_SIZE);
    virtio_add_feature(&features, VIRTIO_BLK_F_RO);
    /*
     * TODO: Delete if not needed
     * virtio_add_feature(&features, VIRTIO_BLK_F_BLK_SIZE);
     */

    /*
     * The next line makes the blk read only
     *
     * virtio_add_feature(&features, VIRTIO_BLK_F_RO);
     *
     */

    if (s->config_wce) {
        DBG("Add config feature\n");
        virtio_add_feature(&features, VIRTIO_BLK_F_CONFIG_WCE);
    }

    if (s->num_queues > 1) {
        virtio_add_feature(&features, VIRTIO_BLK_F_MQ);
    }

    return vhost_user_get_features(&features);
}

static int vhost_user_blk_connect(VirtIODevice *vdev)
{
    VHostUserBlk *s = vdev->vhublk;
    int ret = 0;

    DBG("vhost_user_blk_connect(...)\n");

    if (s->connected) {
        DBG("s->connected\n");
        return 0;
    }
    s->connected = true;
    s->vhost_dev->num_queues = s->num_queues;
    s->vhost_dev->nvqs = s->num_queues;
    s->vhost_dev->vqs = s->vhost_vqs;
    s->vhost_dev->vq_index = 0;
    s->vhost_dev->backend_features = 0;

    vhost_dev_set_config_notifier(s->vhost_dev, &blk_ops);

    vhost_dev_init(s->vhost_dev);

    /* Pass the new obtained features */
    global_vdev->host_features = s->vhost_dev->features;

    /* Disable VIRTIO_RING_F_INDIRECT_DESC, to be supported in future release */
    global_vdev->host_features &= ~(1ULL << VIRTIO_RING_F_INDIRECT_DESC);

    DBG("After init global_vdev->host_features: 0x%lx\n",
                                global_vdev->host_features);

    /* Restore vhost state */
    if (virtio_device_started(vdev, vdev->status)) {
        ret = vhost_user_blk_start(vdev);
        if (ret < 0) {
            DBG("vhost_user_blk_start failed\n");
            return ret;
        }
    }

    DBG("vhost_user_blk_connect return successfully!\n");

    return 0;
}

static void vhost_user_blk_disconnect(VirtIODevice *dev)
{
    DBG("vhost_user_blk_disconnect not yet implemented\n");
}

static void vhost_user_blk_chr_closed_bh(void *opaque)
{
    DBG("vhost_user_blk_chr_closed_bh not yet implemented\n");
}

static void vhost_user_blk_event(void *opaque)
{
    DBG("vhost_user_blk_event not yet implemented");
}

static int vhost_user_blk_realize_connect(VHostUserBlk *s)
{
    int ret;

    DBG("vhost_user_blk_realize_connect(...)\n");
    s->connected = false;

    DBG("s->vdev: 0x%lx\n", (uint64_t)s->parent);
    DBG("global_vdev: 0x%lx\n", (uint64_t)global_vdev);
    ret = vhost_user_blk_connect(s->parent);
    if (ret < 0) {
        DBG("vhost_user_blk_connect failed\n");
        return ret;
    }
    DBG("s->connected: %d\n", s->connected);

    ret = vhost_dev_get_config(s->vhost_dev, (uint8_t *)&s->blkcfg,
                               sizeof(struct virtio_blk_config));
    if (ret < 0) {
        DBG("vhost_dev_get_config failed\n");
        return ret;
    }

    return 0;
}


static void vhost_user_blk_device_unrealize(VirtIODevice *vdev)
{
    DBG("vhost_user_blk_device_unrealize not yet implemented\n");
}

static void vhost_user_blk_reset(VirtIODevice *vdev)
{
    DBG("vhost_user_blk_reset not yet implemented\n");
}

static void vhost_user_blk_set_config(VirtIODevice *vdev,
                                      const uint8_t *config);


static void vhost_user_blk_update_config(VirtIODevice *vdev, uint8_t *config)
{
    VHostUserBlk *s = vdev->vhublk;

    DBG("vhost_user_blk_update_config(...)\n");

    /* Our num_queues overrides the device backend */
    memcpy(&s->blkcfg.num_queues, &s->num_queues, sizeof(uint64_t));

    memcpy(config, &s->blkcfg, sizeof(struct virtio_blk_config));
}

static void vhost_user_blk_set_config(VirtIODevice *vdev, const uint8_t *config)
{
    VHostUserBlk *s = vdev->vhublk;
    struct virtio_blk_config *blkcfg = (struct virtio_blk_config *)config;
    int ret;

    DBG("vhost_user_blk_set_config(...)\n");


    /*
     * TODO: Disabled for the current release
     * if (blkcfg->wce == s->blkcfg.wce) {
     *     DBG("blkcfg->wce == s->blkcfg.wce\n");
     *     return;
     * }
     */
    if (blkcfg->wce == s->blkcfg.wce) {
        DBG("blkcfg->wce == s->blkcfg.wce\n");
        return;
    }

    ret = vhost_dev_set_config(s->vhost_dev, &blkcfg->wce,
                               offsetof(struct virtio_blk_config, wce),
                               sizeof(blkcfg->wce),
                               VHOST_SET_CONFIG_TYPE_MASTER);
    if (ret) {
        DBG("set device config space failed\n");
        return;
    }

    s->blkcfg.wce = blkcfg->wce;
}


static void vhost_user_blk_set_status(VirtIODevice *vdev, uint8_t status)
{
    VHostUserBlk *s = vdev->vhublk;
    /* Just for testing: bool should_start = true; */
    bool should_start = virtio_device_started(vdev, status);
    int ret;

    DBG("vhost_user_blk_set_status (...)\n");

    /* TODO: Remove if not needed */
    if (!s->connected) {
        DBG("Not connected!\n");
        return;
    }

    DBG("should_start == %d\n", should_start);
    if (s->vhost_dev->started == should_start) {
        DBG("s->dev->started == should_start\n");
        return;
    }

    if (should_start) {
        ret = vhost_user_blk_start(vdev);
        if (ret < 0) {
            DBG("vhost_user_blk_start returned error\n");
        }
    } else {
        DBG("Call vhost_user_blk_stop (not yet in place)\n");
        /* TODO: vhost_user_blk_stop(vdev); */
    }

    DBG("vhost_user_blk_set_status return successfully\n");
}


static void virtio_dev_class_init(VirtIODevice *vdev)
{
    DBG("virtio_dev_class_init\n");

    vdev->vdev_class = (VirtioDeviceClass *)malloc(sizeof(VirtioDeviceClass));
    vdev->vdev_class->parent = vdev;
    vdev->vdev_class->realize = vhost_user_blk_realize;
    vdev->vdev_class->unrealize = vhost_user_blk_device_unrealize;
    vdev->vdev_class->get_config = vhost_user_blk_update_config;
    vdev->vdev_class->set_config = vhost_user_blk_set_config;
    vdev->vdev_class->get_features = vhost_user_blk_get_features;
    vdev->vdev_class->set_status = vhost_user_blk_set_status;
    vdev->vdev_class->reset = vhost_user_blk_reset;
    vdev->vdev_class->update_mem_table = update_mem_table;
}


void vhost_user_blk_init(VirtIODevice *vdev)
{

    DBG("vhost_user_blk_init\n");

    VHostUserBlk *vhublk = (VHostUserBlk *)malloc(sizeof(VHostUserBlk));
    vdev->vhublk = vhublk;
    vdev->nvqs = &dev->nvqs;
    vhublk->parent = vdev;
    vhublk->virtqs = vdev->vqs;
    vhublk->vhost_dev = dev;

    virtio_dev_class_init(vdev);
    virtio_loopback_bus_init(vdev->vbus);
}


static void vhost_user_blk_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    /*
     * Not normally called; it's the daemon that handles the queue;
     * however virtio's cleanup path can call this.
     */
    DBG("vhost_user_blk_handle_output not yet implemented\n");
}


void print_config(uint8_t *config)
{
    struct virtio_blk_config *config_strct = (struct virtio_blk_config *)config;

    DBG("uint64_t capacity: %llu\n", config_strct->capacity);
    DBG("uint32_t size_max: %u\n", config_strct->size_max);
    DBG("uint32_t seg_max: %u\n", config_strct->seg_max);

    DBG("virtio_blk_geometry:\n");
    DBG("    uint16_t cylinders: %u\n",
            config_strct->geometry.cylinders);
    DBG("    uint8_t heads: %u\n",
            config_strct->geometry.heads);
    DBG("    uint8_t sectors: %u\n",
            config_strct->geometry.sectors);

    DBG("uint32_t blk_size: %u\n", config_strct->blk_size);
    DBG("uint8_t physical_block_exp: %u\n",
            config_strct->physical_block_exp);
    DBG("uint8_t alignment_offset: %u\n",
            config_strct->alignment_offset);
    DBG("uint16_t min_io_size: %u\n", config_strct->min_io_size);
    DBG("uint32_t opt_io_size: %u\n", config_strct->opt_io_size);
    DBG("uint8_t wce: %u\n", config_strct->wce);
    DBG("uint8_t unused: %u\n", config_strct->unused);
    DBG("uint16_t num_queues: %u\n", config_strct->num_queues);
    DBG("uint32_t max_discard_sectors: %u\n",
            config_strct->max_discard_sectors);
    DBG("uint32_t max_discard_seg: %u\n", config_strct->max_discard_seg);
    DBG("uint32_t discard_sector_alignment: %u\n",
            config_strct->discard_sector_alignment);
    DBG("uint32_t max_write_zeroes_sectors: %u\n",
            config_strct->max_write_zeroes_sectors);
    DBG("uint32_t max_write_zeroes_seg: %u\n",
            config_strct->max_write_zeroes_seg);
    DBG("uint8_t write_zeroes_may_unmap: %u\n",
            config_strct->write_zeroes_may_unmap);
    DBG("uint8_t unused1[3]: %u\n", config_strct->unused1[0]);
    DBG("uint8_t unused1[3]: %u\n", config_strct->unused1[1]);
    DBG("uint8_t unused1[3]: %u\n", config_strct->unused1[2]);
}

void vhost_user_blk_realize(int queue_num, int queue_size)
{
    int retries;
    int i, ret;

    DBG("vhost_user_blk_realize\n");

    /* This needs to be added */
    proxy = (VirtIOMMIOProxy *)malloc(sizeof(VirtIOMMIOProxy));
    *proxy = (VirtIOMMIOProxy) {
        .legacy = 1,
    };

    /* VIRTIO_ID_BLOCK is 2, check virtio_ids.h in linux */
    virtio_dev_init(global_vdev, "virtio-blk", 2,
                sizeof(struct virtio_blk_config));

    vhost_user_blk_init(global_vdev);

    global_vdev->vhublk->config_wce = 0;

    /* FIXME: We temporarily hardcoded the vrtqueues number */
    global_vdev->vhublk->num_queues = queue_num;

    /* FIXME: We temporarily hardcoded the vrtqueues size */
    global_vdev->vhublk->queue_size = queue_size;

    /* NOTE: global_vdev->vqs == vhublk->virtqs */
    global_vdev->vqs = (VirtQueue **)malloc(sizeof(VirtQueue *)
                                            * global_vdev->vhublk->num_queues);
    for (i = 0; i < global_vdev->vhublk->num_queues; i++) {
        global_vdev->vqs[i] = virtio_add_queue(global_vdev,
                                        global_vdev->vhublk->queue_size,
                                        vhost_user_blk_handle_output);
    }

    global_vdev->vhublk->inflight = (struct vhost_inflight *)malloc(
                                            sizeof(struct vhost_inflight));
    global_vdev->vhublk->vhost_vqs = (struct vhost_virtqueue *)malloc(
                                            sizeof(struct vhost_virtqueue) *
                                            global_vdev->vhublk->num_queues);

    retries = REALIZE_CONNECTION_RETRIES;

    do {
        ret = vhost_user_blk_realize_connect(global_vdev->vhublk);
    } while (ret < 0 && retries--);

    if (ret < 0) {
        DBG("vhost_user_blk_realize_connect: -EPROTO\n");
    }

    DBG("final global_vdev->host_features: 0x%lx\n",
         global_vdev->host_features);

    print_config((uint8_t *)(&global_vdev->vhublk->blkcfg));

    return;

}

