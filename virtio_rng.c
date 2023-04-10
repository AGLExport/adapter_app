/*
 * A virtio device implementing a hardware random number generator.
 *
 * Based on virtio-rng.c of QEMU project
 *  Copyright 2012 Red Hat, Inc.
 *  Copyright 2012 Amit Shah <amit.shah@redhat.com>
 *
 * Copyright 2022 Virtual Open Systems SAS.
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
#include "virtio_loopback.h"
#include "virtio_rng.h"

#ifdef DEBUG
#define DBG(...) printf("virtio-rng: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */

bool is_guest_ready(VirtIORNG *vrng)
{
    VirtIODevice *vdev = vrng->parent_obj;

    if (virtio_queue_ready(vrng->vq)
        && (vdev->status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        return true;
    }
    return false;
}

size_t get_request_size(VirtQueue *vq, unsigned quota)
{
    unsigned int in, out;

    virtqueue_get_avail_bytes(vq, &in, &out, quota, 0);
    return in;
}

void virtio_rng_set_status(VirtIODevice *vdev, uint8_t status)
{
    VirtIORNG *vrng = vdev->vrng;

    vdev->status = status;

    /* Something changed, try to process buffers */
    virtio_rng_process(vrng);
}

/* Send data from a char device over to the guest */
void chr_read(VirtIORNG *vrng, const void *buf, size_t size)
{
    VirtIODevice *vdev = vrng->parent_obj;
    VirtQueueElement *elem;
    size_t len;
    int offset;

    if (!is_guest_ready(vrng)) {
        return;
    }

    vrng->quota_remaining -= size;

    offset = 0;
    while (offset < size) {
        elem = virtqueue_pop(vrng->vq, sizeof(VirtQueueElement));


        if (!elem) {
            break;
        }
        len = qemu_iov_from_buf(elem->in_sg, elem->in_num,
                           0, buf + offset, size - offset);
        offset += len;

        virtqueue_push(vrng->vq, elem, len);

        /*
         * TODO: We need tp free the elem
         *
         * g_free(elem);
         */
    }
    virtio_notify(vdev, vrng->vq);

    if (!virtio_queue_empty(vrng->vq)) {
        /*
         * If we didn't drain the queue, call virtio_rng_process
         * to take care of asking for more data as appropriate.
         */
        virtio_rng_process(vrng);
    }
}

const char test_str[64] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
                           10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
                           20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
                           30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
                           40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
                           50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
                           60, 61, 62, 63};

void virtio_rng_process(VirtIORNG *vrng)
{
    size_t size;
    unsigned quota;

    if (!is_guest_ready(vrng)) {
        return;
    }

    if (vrng->quota_remaining < 0) {
        quota = 0;
    } else {
        quota = MIN((uint64_t)vrng->quota_remaining, (uint64_t)UINT32_MAX);
    }
    size = get_request_size(vrng->vq, quota);
    size = MIN(vrng->quota_remaining, size);

    if (size) {
        chr_read(vrng, &test_str, size);
    }
}

void handle_input(VirtIODevice *vdev, VirtQueue *vq)
{
    virtio_rng_process(vdev->vrng);
}

static void virtio_dev_class_init(VirtIODevice *vdev)
{
    vdev->vdev_class = (VirtioDeviceClass *)malloc(sizeof(VirtioDeviceClass));
    vdev->vdev_class->parent = vdev;
    vdev->vdev_class->set_status = virtio_rng_set_status;
}

void virtio_rng_init(VirtIODevice *vdev)
{
    VirtIORNG *vrng = (VirtIORNG *)malloc(sizeof(VirtIORNG));
    vdev->vrng = vrng;
    vrng->parent_obj = vdev;
    vrng->vq = vdev->vq;
    vrng->quota_remaining = LONG_MAX;

    /* Prepare dev_class */
    virtio_dev_class_init(vdev);
}


void virtio_rng_realize(void)
{
    /* prepare procy and virtio dev*/
    proxy = (VirtIOMMIOProxy *)malloc(sizeof(VirtIOMMIOProxy));

    virtio_dev_init(global_vdev, "virtio-rng", 4, 0);

    virtio_rng_init(global_vdev);

    global_vdev->vq = virtio_add_queue(global_vdev, 8, handle_input);

    global_vdev->host_features = 0x39000000;

    *proxy = (VirtIOMMIOProxy) {
        .legacy = 1,
    };
}

