/*
 * Based on virtio-input.h of QEMU project
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
#define DBG(...) printf("virtio-input: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */

#define VIRTIO_INPUT_VM_VERSION 1

/* ----------------------------------------------------------------- */

void virtio_input_send(VirtIOInput *vinput, virtio_input_event *event)
{
    DBG("virtio_input_send() not yet implemeted\n");
}

static void virtio_input_handle_evt(VirtIODevice *vdev, VirtQueue *vq)
{
    DBG("virtio_input_handle_evt(...)\n");
    /* nothing */
}

static void virtio_input_handle_sts(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOInputClass *vic = vdev->vinput->input_class;
    VirtIOInput *vinput = vdev->vinput;
    virtio_input_event event;
    VirtQueueElement *elem;
    int len;

    DBG("virtio_input_handle_sts(...)\n");

    for (;;) {
        elem = virtqueue_pop(vinput->sts, sizeof(VirtQueueElement));
        if (!elem) {
            break;
        }

        memset(&event, 0, sizeof(event));
        /* FIXME: add iov_to_buf func */
        len = 1;
        /*
         * TODO: Will be added in a next release
         * len = iov_to_buf(elem->out_sg, elem->out_num,
         *                  0, &event, sizeof(event));
         */
        if (vic->handle_status) {
            vic->handle_status(vinput, &event);
        }
        virtqueue_push(vinput->sts, elem, len);
        munmap(elem, sizeof(VirtQueueElement));
    }
    virtio_notify(vdev, vinput->sts);
}

virtio_input_config *virtio_input_find_config(VirtIOInput *vinput,
                                              uint8_t select,
                                              uint8_t subsel)
{
    DBG("virtio_input_find_config(...)\n");
    VirtIOInputConfig *cfg;

    QTAILQ_FOREACH(cfg, &vinput->cfg_list, node) {
        if (select == cfg->config.select &&
            subsel == cfg->config.subsel) {
            return &cfg->config;
        }
    }
    return NULL;
}

void virtio_input_add_config(VirtIOInput *vinput,
                             virtio_input_config *config)
{
    DBG("virtio_input_add_config(...)\n");
    VirtIOInputConfig *cfg;

    if (virtio_input_find_config(vinput, config->select, config->subsel)) {
        /* should not happen */
        DBG("Error duplicate config: %d/%d\n", config->select, config->subsel);
        exit(1);
    }

    cfg = (VirtIOInputConfig *)malloc(sizeof(VirtIOInputConfig));
    cfg->config = *config;

    QTAILQ_INSERT_TAIL(&vinput->cfg_list, cfg, node);
}

void virtio_input_init_config(VirtIOInput *vinput,
                              virtio_input_config *config)
{
    DBG("virtio_input_init_config(...)\n");
    int i = 0;

    QTAILQ_INIT(&vinput->cfg_list);
    while (config[i].select) {
        virtio_input_add_config(vinput, config + i);
        i++;
    }
}

void virtio_input_idstr_config(VirtIOInput *vinput,
                               uint8_t select, const char *string)
{
    DBG("virtio_input_idstr_config(...)\n");
    virtio_input_config id;

    if (!string) {
        return;
    }
    memset(&id, 0, sizeof(id));
    id.select = select;
    id.size = snprintf(id.u.string, sizeof(id.u.string), "%s", string);
    virtio_input_add_config(vinput, &id);
}

static void virtio_input_get_config(VirtIODevice *vdev, uint8_t *config_data)
{
    DBG("virtio_input_get_config(...)\n");
    VirtIOInput *vinput = vdev->vinput;
    virtio_input_config *config;

    config = virtio_input_find_config(vinput, vinput->cfg_select,
                                      vinput->cfg_subsel);
    if (config) {
        memcpy(config_data, config, vinput->cfg_size);
    } else {
        memset(config_data, 0, vinput->cfg_size);
    }
}

static void virtio_input_set_config(VirtIODevice *vdev,
                                    const uint8_t *config_data)
{
    VirtIOInput *vinput = vdev->vinput;
    virtio_input_config *config = (virtio_input_config *)config_data;

    DBG("virtio_input_set_config(...)\n");

    vinput->cfg_select = config->select;
    vinput->cfg_subsel = config->subsel;
    virtio_notify_config(vdev);
}

static uint64_t virtio_input_get_features(VirtIODevice *vdev, uint64_t f)
{
    DBG("virtio_input_get_features(...)\n");
    return f;
}

static void virtio_input_set_status(VirtIODevice *vdev, uint8_t val)
{
    VirtIOInputClass *vic = vdev->vinput->input_class;
    VirtIOInput *vinput = vdev->vinput;
    bool should_start = virtio_device_started(vdev, val);

    if (should_start) {
        if (!vinput->active) {
            vinput->active = true;
            if (vic->change_active) {
                vic->change_active(vinput);
            }
        }
    }
}

static void virtio_input_reset(VirtIODevice *vdev)
{
    VirtIOInputClass *vic = vdev->vinput->input_class;
    VirtIOInput *vinput = vdev->vinput;

    DBG("virtio_input_reset(...)\n");

    if (vinput->active) {
        vinput->active = false;
        if (vic->change_active) {
            vic->change_active(vinput);
        }
    }
}

static int virtio_input_post_load(void *opaque, int version_id)
{
    VirtIOInput *vinput = global_vdev->vinput;
    VirtIOInputClass *vic = global_vdev->vinput->input_class;
    VirtIODevice *vdev = global_vdev;

    DBG("virtio_input_post_load(...)\n");

    vinput->active = vdev->status & VIRTIO_CONFIG_S_DRIVER_OK;
    if (vic->change_active) {
        vic->change_active(vinput);
    }
    return 0;
}

void virtio_input_device_realize()
{
    VirtIODevice *vdev = global_vdev;
    struct VirtIOInputClass *vic = vdev->vinput->input_class;
    VirtIOInput *vinput = vdev->vinput;
    VirtIOInputConfig *cfg;

    DBG("virtio_input_device_realize(...)\n");

    /* This needs to be added */
    proxy = (VirtIOMMIOProxy *)malloc(sizeof(VirtIOMMIOProxy));
    *proxy = (VirtIOMMIOProxy) {
        .legacy = 1,
    };

    if (vic->realize) {
        vic->realize(vdev);
    }

    virtio_input_idstr_config(vinput, VIRTIO_INPUT_CFG_ID_SERIAL,
                              vinput->serial);

    QTAILQ_FOREACH(cfg, &vinput->cfg_list, node) {
        if (vinput->cfg_size < cfg->config.size) {
            vinput->cfg_size = cfg->config.size;
        }
    }
    vinput->cfg_size += 8;

    virtio_input_init_config(vinput, virtio_keyboard_config);

    virtio_dev_init(vdev, "virtio-input", 18, vinput->cfg_size);
    vinput->evt = virtio_add_queue(vdev, 64, virtio_input_handle_evt);
    vinput->sts = virtio_add_queue(vdev, 64, virtio_input_handle_sts);

    /* FIXME: do we need that? */
    memcpy(global_vdev->vq, vinput->evt, sizeof(VirtQueue));
    memcpy(global_vdev->vq, vinput->sts, sizeof(VirtQueue));

    DBG("global_vdev->guest_features: 0x%lx\n", global_vdev->guest_features);
}

static void virtio_input_finalize(VirtIODevice *vdev)
{
    DBG("virtio_input_finalize not yet implemented");
}

static void virtio_input_device_unrealize(VirtIODevice *vdev)
{
    DBG("virtio_input_device_unrealize not yet implemented");
}


void virtio_input_class_init(VirtIODevice *vdev)
{
    vdev->vdev_class = (VirtioDeviceClass *)malloc(sizeof(VirtioDeviceClass));
    vdev->vdev_class->parent = vdev;

    DBG("virtio_input_class_init(...)\n");

    vdev->vdev_class->realize      = virtio_input_device_realize;
    vdev->vdev_class->get_config   = virtio_input_get_config;
    vdev->vdev_class->set_config   = virtio_input_set_config;
    vdev->vdev_class->get_features = virtio_input_get_features;
    vdev->vdev_class->set_status   = virtio_input_set_status;
    vdev->vdev_class->reset        = virtio_input_reset;
}
