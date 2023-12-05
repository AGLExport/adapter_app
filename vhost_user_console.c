/*
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
#include "vhost_user_console.h"

#ifdef DEBUG
#define DBG(...) printf("vhost-user-console: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */

static const int user_feature_bits[] = {
    VIRTIO_F_VERSION_1,
    VIRTIO_RING_F_INDIRECT_DESC,
    VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_F_RING_RESET,
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VHOST_INVALID_FEATURE_BIT
};

static void vhost_user_console_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VHostUserConsole *console = vdev->vhuconsole;

    DBG("vhost_user_console_get_config: Not yet implemented!\n");

    memcpy(config, &console->config, sizeof(struct virtio_console_config));
}

static void vhost_user_console_start(VirtIODevice *vdev)
{
    VHostUserConsole *vhuconsole = vdev->vhuconsole;
    VirtioBus *k = vdev->vbus;
    int ret;
    int i;

    DBG("vhost_user_console_start(...)\n");

    if (!k->set_guest_notifiers) {
        DBG("binding does not support guest notifiers\n");
        return;
    }

    ret = vhost_dev_enable_notifiers(vhuconsole->vhost_dev, vdev);
    if (ret < 0) {
        DBG("Error enabling host notifiers: %d\n", -ret);
        return;
    }

    ret = k->set_guest_notifiers(k->vdev, vhuconsole->vhost_dev->nvqs, true);
    if (ret < 0) {
        DBG("Error binding guest notifier: %d\n", -ret);
        goto err_host_notifiers;
    }

    vhuconsole->vhost_dev->acked_features = vdev->guest_features;

    ret = vhost_dev_start(vhuconsole->vhost_dev, vdev, true);
    if (ret < 0) {
        DBG("Error starting vhost: %d\n", -ret);
        goto err_guest_notifiers;
    }

    /*
     * guest_notifier_mask/pending not used yet, so just unmask
     * everything here.  virtio-pci will do the right thing by
     * enabling/disabling irqfd.
     */
    for (i = 0; i < vhuconsole->vhost_dev->nvqs; i++) {
        vhost_virtqueue_mask(vhuconsole->vhost_dev, vdev, i, false);
    }

    /* Wait a bit for the vrings to be set in vhost-user-device */
    sleep(1);

    return;

err_guest_notifiers:
err_host_notifiers:
    DBG("vhu_start error\n");
    return;
}

static void vhost_user_console_stop(VirtIODevice *vdev)
{
    DBG("vhost_user_console_stop: not yet implemented\n");
}

static void vhost_user_console_set_status(VirtIODevice *vdev, uint8_t status)
{
    VHostUserConsole *vhuconsole = vdev->vhuconsole;
    bool should_start = virtio_device_started(vdev, status);
    DBG("vhost_user_console_set_status: %d\n", status);

    if (vhuconsole->vhost_dev->started == should_start) {
        DBG("console->vhost_dev->started == should_start\n");
        return;
    }

    if (should_start) {
        vhost_user_console_start(vdev);
    } else {
        vhost_user_console_stop(vdev);
    }
}

static uint64_t vhost_user_console_get_features(VirtIODevice *vdev,
                                                uint64_t features)
{
    VHostUserConsole *s = vdev->vhuconsole;

    DBG("vhost_user_console_get_features()\n");

    return vhost_get_features(s->vhost_dev, user_feature_bits, features);
}

static void vhost_user_console_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    /*
     * Not normally called; it's the daemon that handles the queue;
     * however virtio's cleanup path console call this.
     */
    DBG("vhost_user_console_handle_output: Not yet implemented!\n");
}

static int vhost_user_console_config_change(struct vhost_dev *dev)
{
    VHostUserConsole *vhuconsole = dev->vdev->vhuconsole;
    DBG("vhost_user_console_console_config_change: Not yet implemented!\n");

    int ret = vhost_dev_get_config(dev, (uint8_t *)&vhuconsole->config,
                                   sizeof(struct virtio_console_config));
    if (ret < 0) {
        DBG("vhost_user_console_sound_config_change error\n");
        return -1;
    }

    virtio_notify_config(dev->vdev);

    return 0;
}

const VhostDevConfigOps console_config_ops = {
    .vhost_dev_config_notifier = vhost_user_console_config_change,
};

static void vhost_user_console_init(VirtIODevice *vdev);

void vhost_user_console_realize()
{
    VirtIODevice *vdev = global_vdev;
    int ret;

    DBG("vhost_user_console_device_realize\n");

    /* This needs to be added */
    proxy = (VirtIOMMIOProxy *)malloc(sizeof(VirtIOMMIOProxy));
    *proxy = (VirtIOMMIOProxy) {
        .legacy = 1,
    };

    /* VIRTIO_ID_CAN is 36, check virtio_ids.h in linux*/
    virtio_dev_init(vdev, "virtio-console", 3,
                    sizeof(vdev->vhuconsole->config));
    vhost_user_console_init(global_vdev);

    /* add queues */
    vdev->vhuconsole->rx_vq = virtio_add_queue(vdev, 64,
                                            vhost_user_console_handle_output);
    vdev->vhuconsole->tx_vq = virtio_add_queue(vdev, 64,
                                            vhost_user_console_handle_output);
    vdev->vhuconsole->ctrl_rx_vq = virtio_add_queue(vdev, 64,
                                            vhost_user_console_handle_output);
    vdev->vhuconsole->ctrl_tx_vq = virtio_add_queue(vdev, 64,
                                            vhost_user_console_handle_output);
    vdev->vhuconsole->vhost_dev->nvqs = 4;
    vdev->vhuconsole->num_queues = 4;
    vdev->vhuconsole->queue_size = 64;

    /* NOTE: global_vdev->vqs == vhuconsole->virtqs */
    vdev->vqs = (VirtQueue **)malloc(sizeof(VirtQueue *)
                                     * global_vdev->vhuconsole->num_queues);
    vdev->vqs[0] = vdev->vhuconsole->rx_vq;
    vdev->vqs[1] = vdev->vhuconsole->tx_vq;
    vdev->vqs[2] = vdev->vhuconsole->ctrl_rx_vq;
    vdev->vqs[3] = vdev->vhuconsole->ctrl_tx_vq;

    vdev->vhuconsole->vhost_vqs = (struct vhost_virtqueue *)malloc(
                                       sizeof(struct vhost_virtqueue) *
                                       vdev->vhuconsole->num_queues);

    /* Set up vhost device */
    vdev->vhuconsole->vhost_dev->num_queues = vdev->vhuconsole->num_queues;
    vdev->vhuconsole->vhost_dev->nvqs = vdev->vhuconsole->num_queues;
    vdev->vhuconsole->vhost_dev->vqs = vdev->vhuconsole->vhost_vqs;
    vdev->vhuconsole->vhost_dev->vq_index = 0;
    vdev->vhuconsole->vhost_dev->backend_features = 0;

    vhost_dev_set_config_notifier(vdev->vhuconsole->vhost_dev,
                                  &console_config_ops);

    /* TODO: Add error handling */
    vhost_dev_init(vdev->vhuconsole->vhost_dev);

    /* Pass the new obtained features */
    global_vdev->host_features = vdev->vhuconsole->vhost_dev->features;

    ret = vhost_dev_get_config(vdev->vhuconsole->vhost_dev,
                               (uint8_t *)&vdev->vhuconsole->config,
                               sizeof(struct virtio_console_config));
    if (ret < 0) {
        goto vhost_dev_init_failed;
    }

    vdev->vdev_class->print_config((uint8_t *)&vdev->vhuconsole->config);

    return;

vhost_dev_init_failed:
    DBG("vhost_dev_init_failed\n");
    return;
}

static void vhost_user_console_device_unrealize(VirtIODevice *vdev)
{
    DBG("vhost_user_blk_device_unrealize not yet implemented\n");
}

static struct vhost_dev *vhost_user_console_get_vhost(VirtIODevice *vdev)
{
    VHostUserConsole *vhuconsole = vdev->vhuconsole;
    return vhuconsole->vhost_dev;
}

static void print_config_console(uint8_t *config_data)
{
    struct virtio_console_config *config_strct =
        (struct virtio_console_config *)config_data;

    DBG("print_config_console:\n");
    DBG("\tuint16_t cols: %u\n", config_strct->cols);
    DBG("\tuint16_t rows: %u\n", config_strct->rows);
    DBG("\tuint16_t max_nr_ports: %u\n", config_strct->max_nr_ports);
    DBG("\tuint16_t emerg_wr: %u\n", config_strct->emerg_wr);
}

static void virtio_dev_class_init(VirtIODevice *vdev)
{
    DBG("virtio_dev_class_init\n");

    vdev->vdev_class = (VirtioDeviceClass *)malloc(sizeof(VirtioDeviceClass));
    vdev->vdev_class->parent = vdev;
    vdev->vdev_class->realize = vhost_user_console_realize;
    vdev->vdev_class->unrealize = vhost_user_console_device_unrealize;
    vdev->vdev_class->get_config = vhost_user_console_get_config;
    vdev->vdev_class->get_features = vhost_user_console_get_features;
    vdev->vdev_class->set_status = vhost_user_console_set_status;
    vdev->vdev_class->update_mem_table = update_mem_table;
    vdev->vdev_class->print_config = print_config_console;
}

static void vhost_user_console_init(VirtIODevice *vdev)
{

    DBG("vhost_user_console_init\n");

    VHostUserConsole *vhuconsole =
                        (VHostUserConsole *)malloc(sizeof(VHostUserConsole));
    vdev->vhuconsole = vhuconsole;
    vdev->nvqs = &vdev->vhdev->nvqs;
    vhuconsole->parent = vdev;
    vhuconsole->virtqs = vdev->vqs;
    vhuconsole->vhost_dev = vdev->vhdev;

    virtio_dev_class_init(vdev);
    virtio_loopback_bus_init(vdev->vbus);
}
