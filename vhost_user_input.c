/*
 * Based on vhost-user-input.c of QEMU project
 *
 * Copyright (c) 2022 Virtual Open Systems SAS.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.  See the COPYING file in the
 * top-level directory.
 */

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include <sys/param.h>

/* Project header files */
#include "vhost_user_input.h"

#ifdef DEBUG
#define DBG(...) printf("vhost-user-input: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */


static int vhost_input_config_change(struct vhost_dev *dev)
{
    DBG("vhost-user-input: unhandled backend config change\n");
    return -1;
}

const VhostDevConfigOps config_ops = {
    .vhost_dev_config_notifier = vhost_input_config_change,
};

static void vhost_input_change_active(VirtIOInput *vinput)
{
    DBG("vhost_input_change_active(...)\n");

    VhostUserInput *vhuinput = global_vdev->vhuinput;

    if (vinput->active) {
        vhost_user_backend_start(global_vdev);
    } else {
        vhost_user_backend_stop(global_vdev);
    }
}

static void vhost_input_get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    DBG("vhost_input_get_config(...)\n");

    VirtIOInput *vinput = vdev->vinput;
    VhostUserInput *vhi = vdev->vhuinput;
    int ret;

    memset(config_data, 0, vinput->cfg_size);

    ret = vhost_dev_get_config(vhi->vhost_dev, config_data, vinput->cfg_size);
    if (ret) {
        DBG("vhost_input_get_config failed\n");
        return;
    }
}

static void vhost_input_set_config(VirtIODevice *vdev,
                                   const uint8_t *config_data)
{
    DBG("vhost_input_set_config(...)\n");

    VhostUserInput *vhi = vdev->vhuinput;
    int ret;

    ret = vhost_dev_set_config(vhi->vhost_dev, config_data,
                               0, sizeof(virtio_input_config),
                               VHOST_SET_CONFIG_TYPE_MASTER);
    if (ret) {
        DBG("vhost_input_set_config failed\n");
        return;
    }

    virtio_notify_config(vdev);
}

static struct vhost_dev *vhost_input_get_vhost(VirtIODevice *vdev)
{
    DBG("vhost_input_get_vhost(...)\n");

    return vdev->vhuinput->vhost_dev;
}

static void vhost_input_class_init(VirtIODevice *vdev)
{
    DBG("vhost_input_class_init(...)\n");


    /* Comment out the following lines to get the local config */
    vdev->vdev_class->get_config = vhost_input_get_config;
    vdev->vdev_class->set_config = vhost_input_set_config;

    vdev->vdev_class->get_vhost = vhost_input_get_vhost;

    vdev->vhuinput->vdev_input->input_class->realize = vhost_user_input_realize;
    vdev->vhuinput->vdev_input->input_class->change_active =
                                            vhost_input_change_active;
}


void vhost_user_input_init(VirtIODevice *vdev)
{

    DBG("vhost_user_input_init(...)\n");

    struct VirtIOInputClass *input_class = (struct VirtIOInputClass *)malloc(
                                            sizeof(struct VirtIOInputClass));
    VirtIOInput *vinput = (VirtIOInput *)malloc(sizeof(VirtIOInput));
    VhostUserInput *vhuinput = (VhostUserInput *)malloc(sizeof(VhostUserInput));

    vdev->vinput = vinput;
    vdev->vinput->input_class = input_class;

    vdev->vhuinput = vhuinput;
    vhuinput->vdev = vdev;
    vhuinput->vhost_dev = dev;
    vhuinput->vdev_input = vinput;

    /*
     * Call first the virtio_input class init to set up
     * the basic functionality.
     */
    virtio_input_class_init(vdev);

    /* Then call the vhost_user class init */
    vhost_input_class_init(vdev);

    /* finally initialize the bus */
    virtio_loopback_bus_init(vdev->vbus);
}


void vhost_user_input_realize()
{
    int nvqs = 2; /* qemu choice: 2 */

    DBG("vhost_user_input_realize()\n");

    vhost_dev_set_config_notifier(global_vdev->vhuinput->vhost_dev,
                                  &config_ops);

    global_vdev->vhuinput->vdev_input->cfg_size =
                                sizeof_field(virtio_input_config, u);

    global_vdev->vhuinput->vhost_dev->vq_index = 0;
    global_vdev->vhuinput->vhost_dev->backend_features = 0;
    global_vdev->vhuinput->vhost_dev->num_queues = nvqs;


    global_vdev->vhuinput->vhost_dev->nvqs = nvqs;
    global_vdev->vhuinput->vhost_dev->vqs = (struct vhost_virtqueue *)malloc(
                                     sizeof(struct vhost_virtqueue) * nvqs);
    vhost_dev_init(global_vdev->vhuinput->vhost_dev);

    /* Pass the new obtained features */
    global_vdev->host_features = global_vdev->vhuinput->vhost_dev->features;
}

void vhost_user_backend_start(VirtIODevice *vdev)
{
    VirtioBus *k = vdev->vbus;
    int ret, i;

    DBG("vhost_user_backend_start(...)\n");

    if (vdev->started) {
        DBG("Device has already been started!\n");
        return;
    }

    if (!k->set_guest_notifiers) {
        DBG("binding does not support guest notifiers\n");
        return;
    }

    ret = vhost_dev_enable_notifiers(vdev->vhuinput->vhost_dev, vdev);
    if (ret < 0) {
        DBG("vhost_dev_enable_notifiers failed!\n");
        return;
    }

    DBG("k->set_guest_notifiers, nvqs: %d\n", vdev->vhuinput->vhost_dev->nvqs);
    ret = k->set_guest_notifiers(vdev, vdev->vhuinput->vhost_dev->nvqs, true);
    if (ret < 0) {
        DBG("Error binding guest notifier\n");
    }

    vdev->vhuinput->vhost_dev->acked_features = vdev->guest_features;
    ret = vhost_dev_start(vdev->vhuinput->vhost_dev, vdev);
    if (ret < 0) {
        DBG("Error start vhost dev\n");
        return;
    }

    /*
     * guest_notifier_mask/pending not used yet, so just unmask
     * everything here.  virtio-pci will do the right thing by
     * enabling/disabling irqfd.
     */
    for (i = 0; i < vdev->vhuinput->vhost_dev->nvqs; i++) {
        vhost_virtqueue_mask(vdev->vhuinput->vhost_dev, vdev,
                             vdev->vhuinput->vhost_dev->vq_index + i, false);
    }

    vdev->started = true;
    return;

}

void vhost_user_backend_stop(VirtIODevice *vdev)
{
    DBG("vhost_user_backend_stop() not yet implemented\n");
}
