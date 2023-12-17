/*
 * Based on vhost-user-gpio.c of QEMU project
 *
 * Copyright (c) 2022 Viresh Kumar <viresh.kumar@linaro.org>
 *
 * Copyright (c) 2023 Virtual Open Systems SAS.
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
#include <errno.h>

/* Project header files */
#include "vhost_user_gpio.h"

#ifdef DEBUG
#define DBG(...) printf("vhost-user-gpio: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */

#define REALIZE_CONNECTION_RETRIES 3
#define VHOST_NVQS 2

static const int feature_bits[] = {
    VIRTIO_F_VERSION_1,
    VIRTIO_F_NOTIFY_ON_EMPTY,
    VIRTIO_RING_F_INDIRECT_DESC,
    VIRTIO_RING_F_EVENT_IDX,
    VIRTIO_GPIO_F_IRQ,
    VIRTIO_F_RING_RESET,
    VHOST_INVALID_FEATURE_BIT
};

static void vu_gpio_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VHostUserGPIO *gpio = dev->vdev->vhugpio;

    DBG("vu_gpio_get_config()\n");
    memcpy(config, &gpio->config, sizeof(gpio->config));
}

static int vu_gpio_config_notifier(struct vhost_dev *dev)
{
    VHostUserGPIO *gpio = dev->vdev->vhugpio;

    DBG("vu_gpio_config_notifier\n");

    memcpy(dev->vdev->config, &gpio->config, sizeof(gpio->config));
    virtio_notify_config(dev->vdev);

    return 0;
}

const VhostDevConfigOps gpio_ops = {
    .vhost_dev_config_notifier = vu_gpio_config_notifier,
};

static int vu_gpio_start(VirtIODevice *vdev)
{
    VirtioBus *k = vdev->vbus;
    VHostUserGPIO *gpio = vdev->vhugpio;
    int ret, i;

    DBG("vu_gpio_start()\n");

    if (!k->set_guest_notifiers) {
        DBG("binding does not support guest notifiers");
        return -ENOSYS;
    }

    ret = vhost_dev_enable_notifiers(gpio->vhost_dev, vdev);
    if (ret < 0) {
        DBG("Error enabling host notifiers: %d", ret);
        return ret;
    }

    ret = k->set_guest_notifiers(k->vdev, gpio->vhost_dev->nvqs, true);
    if (ret < 0) {
        DBG("Error binding guest notifier: %d", ret);
        goto out_with_err_host_notifiers;
    }

    vhost_ack_features(gpio->vhost_dev, feature_bits, vdev->guest_features);

    ret = vhost_dev_start(gpio->vhost_dev, vdev, true);
    if (ret < 0) {
        DBG("Error starting vhost-user-gpio: %d", ret);
        goto out_with_err_guest_notifiers;
    }
    gpio->started_vu = true;

    for (i = 0; i < gpio->vhost_dev->nvqs; i++) {
        vhost_virtqueue_mask(gpio->vhost_dev, vdev, i, false);
    }

    /*
     * TODO: check if we need the following is needed
     * ret = gpio->vhost_dev->vhost_ops->vhost_set_vring_enable(gpio->vhost_dev,
     *                                                          true);
     */

    return 0;

out_with_err_guest_notifiers:
    k->set_guest_notifiers(k->vdev, gpio->vhost_dev->nvqs, false);
out_with_err_host_notifiers:
    /*
     * TODO: implement the following functions:
     * vhost_dev_disable_notifiers(&gpio->vhost_dev, vdev);
     */

    return ret;
}

static void vu_gpio_stop(VirtIODevice *vdev)
{
    DBG("vu_gpio_stop() not yet implemented\n");
}

static void vu_gpio_set_status(VirtIODevice *vdev, uint8_t status)
{
    VHostUserGPIO *gpio = vdev->vhugpio;
    bool should_start = virtio_device_started(vdev, status);

    DBG("vu_gpio_set_status()\n");

    if (!gpio->connected) {
        return;
    }

printf("should_start: %d\n", should_start);
    if (gpio->vhost_dev->started) {
        return;
    }

    if (should_start) {
        if (vu_gpio_start(vdev)) {
            DBG("vu_gpio_start() failed\n");
        }
    } else {
        vu_gpio_stop(vdev);
    }
}

static uint64_t vu_gpio_get_features(VirtIODevice *vdev, uint64_t features)
{
    VHostUserGPIO *gpio = vdev->vhugpio;

    DBG("vu_gpio_get_features()\n");
    return vhost_get_features(gpio->vhost_dev, feature_bits, features);
}

static void vu_gpio_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
    /*
     * Not normally called; it's the daemon that handles the queue;
     * however virtio's cleanup path can call this.
     */
    DBG("vu_gpio_handle_output not yet implemented\n");
}

static void vu_gpio_guest_notifier_mask(VirtIODevice *vdev, int idx, bool mask)
{
    VHostUserGPIO *gpio = vdev->vhugpio;

    DBG("vu_gpio_guest_notifier_mask() not yet implemented\n");

    vhost_virtqueue_mask(gpio->vhost_dev, vdev, idx, mask);
}

static void do_vhost_user_cleanup(VirtIODevice *vdev, VHostUserGPIO *gpio)
{
    DBG("do_vhost_user_cleanup() not yet implemented\n");
}

static int vu_gpio_connect(VirtIODevice *vdev)
{
    VHostUserGPIO *gpio = vdev->vhugpio;
    int ret;

    DBG("vu_gpio_connect()\n");

    if (gpio->connected) {
        return 0;
    }
    gpio->connected = true;

    vhost_dev_set_config_notifier(gpio->vhost_dev, &gpio_ops);
    /*
     * TODO: Investigate if the following is needed
     * gpio->vhost_user.supports_config = true;
     */

    gpio->vhost_dev->nvqs = VHOST_NVQS;
    gpio->vhost_dev->vqs = gpio->vhost_vqs;

    vhost_dev_init(gpio->vhost_dev);
    /*
     * TODO: Add error handling
     * if (ret < 0) {
     *     return ret;
     * }
     */

    /* restore vhost state */
    if (virtio_device_started(vdev, vdev->status)) {
        vu_gpio_start(vdev);
    }

    return 0;
}

static int vu_gpio_realize_connect(VHostUserGPIO *gpio)
{
    int ret;

    DBG("vu_gpio_realize_connect()\n");

    ret = vu_gpio_connect(gpio->parent);
    if (ret < 0) {
        return ret;
    }

    ret = vhost_dev_get_config(gpio->vhost_dev, (uint8_t *)&gpio->config,
                               sizeof(gpio->config));

    if (ret < 0) {
        DBG("vhost-user-gpio: get config failed\n");
        /*
         * TODO: Add cleanup function
         * vhost_dev_cleanup(vhost_dev);
         */
        return ret;
    }

    return 0;
}

static void vu_gpio_device_unrealize(VirtIODevice *vdev)
{
    DBG("vu_gpio_device_unrealize() not yet implemented\n");
}

static void print_config_gpio(uint8_t *config_data)
{
    struct virtio_gpio_config *config =
        (struct virtio_gpio_config *)config_data;

    DBG("ngpio: %hu\n", config->ngpio);
    DBG("gpio_names_size: %u\n", config->gpio_names_size);
}

static void vu_gpio_class_init(VirtIODevice *vdev)
{
    DBG("vu_gpio_class_init()\n");

    vdev->vdev_class = (VirtioDeviceClass *)malloc(sizeof(VirtioDeviceClass));
    if (!vdev->vdev_class) {
        DBG("vdev_class memory allocation failed\n");
        return;
    }
    vdev->vdev_class->realize = vu_gpio_device_realize;
    vdev->vdev_class->unrealize = vu_gpio_device_unrealize;
    vdev->vdev_class->get_features = vu_gpio_get_features;
    vdev->vdev_class->get_config = vu_gpio_get_config;
    vdev->vdev_class->set_status = vu_gpio_set_status;
    vdev->vdev_class->guest_notifier_mask = vu_gpio_guest_notifier_mask;
}

void vu_gpio_init(VirtIODevice *vdev)
{
    DBG("vu_gpio_init()\n");

    VHostUserGPIO *vhugpio = (VHostUserGPIO *)malloc(sizeof(VHostUserGPIO));
    if (!proxy) {
        DBG("proxy memory allocation failed\n");
        goto out;
    }

    vdev->vhugpio = vhugpio;
    vdev->nvqs = &dev->nvqs;
    vhugpio->parent = vdev;
    vhugpio->vhost_dev = dev;

    vu_gpio_class_init(vdev);
    virtio_loopback_bus_init(vdev->vbus);

out:
    return;
}

/* TODO: Add queue_num, queue_size as parameters */
void vu_gpio_device_realize()
{
    int retries, ret;
    int i;

    DBG("vu_gpio_device_realize()\n");

    /* This needs to be added */
    proxy = (VirtIOMMIOProxy *)malloc(sizeof(VirtIOMMIOProxy));
    if (!proxy) {
        DBG("proxy memory allocation failed\n");
        goto out_with_error;
    }

    *proxy = (VirtIOMMIOProxy) {
        .legacy = 1,
    };

    /* VIRTIO_ID_GPIO is 41, check virtio_ids.h in linux */
    virtio_dev_init(global_vdev, "virtio-gpio", 41,
                sizeof(struct virtio_gpio_config));

    vu_gpio_init(global_vdev);
    if (!global_vdev->vhugpio) {
        DBG("vhugpio memory allocation failed\n");
        goto out_with_proxy;
    }

    global_vdev->vhugpio->command_vq = virtio_add_queue(global_vdev, 64,
                                                        vu_gpio_handle_output);
    global_vdev->vhugpio->interrupt_vq = virtio_add_queue(global_vdev, 64,
                                                        vu_gpio_handle_output);

    global_vdev->vhugpio->vhost_vqs = (struct vhost_virtqueue *)
                                malloc(sizeof(struct vhost_virtqueue *));
    if (!global_vdev->vhugpio->vhost_vqs) {
        DBG("vhost_vqs memory allocation failed\n");
        goto out_with_dev;
    }

    global_vdev->vhugpio->connected = false;

    retries = REALIZE_CONNECTION_RETRIES;

    do {
        ret = vu_gpio_realize_connect(global_vdev->vhugpio);
    } while (ret < 0 && retries--);

    if (ret < 0) {
        DBG("vu_gpio_realize_connect(): -EPROTO\n");
        do_vhost_user_cleanup(global_vdev, global_vdev->vhugpio);
    }

    print_config_gpio((uint8_t *)(&global_vdev->vhugpio->config));
    DBG("(realize completed)\n");

    return;

    /* TODO: Fix the following considering also do_vhost_user_cleanup() */
out_with_cmd_vq:
    /* free(global_vdev->vhugpio->command_vq); */
out_with_dev:
    free(global_vdev->vhugpio);
out_with_proxy:
    free(proxy);
out_with_error:
    DBG("Realize funciton return error\n");
    return;
}
