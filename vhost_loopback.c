/*
 * Based on vhost.c of QEMU project;
 *
 *   Copyright Red Hat, Inc. 2010
 *
 *   Authors:
 *    Michael S. Tsirkin <mst@redhat.com>
 *
 *   Copyright Red Hat, Inc. 2010
 *
 *   Authors:
 *    Michael S. Tsirkin <mst@redhat.com>
 *
 * Copyright 2022-2023 Virtual Open Systems SAS.
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
#include <sys/eventfd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/param.h>
#include <assert.h>

/* For socket */
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

/* Project header files */
#include "virtio_loopback.h"
#include "vhost_user_loopback.h"
#include "event_notifier.h"

/* vhost headers */
#include "vhost_loopback.h"

#ifdef DEBUG
#define DBG(...) printf("vhost-loopback: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */

/*
 * Stop processing guest IO notifications in qemu.
 * Start processing them in vhost in kernel.
 */
int vhost_dev_enable_notifiers(struct vhost_dev *hdev, VirtIODevice *vdev)
{
    int i, r, e;

    /*
     * We will pass the notifiers to the kernel, make sure that QEMU
     * doesn't interfere.
     */

    /* TODO: Check if this is still useful */
    r = virtio_device_grab_ioeventfd(vdev);
    if (r < 0) {
        DBG("binding does not support host notifiers\n");
        goto fail;
    }


    for (i = 0; i < hdev->nvqs; ++i) {
        r = virtio_bus_set_host_notifier(vdev->vbus, hdev->vq_index + i,
                                         true);
        if (r < 0) {
            DBG("vhost VQ %d notifier binding failed: %d", i, r);
            goto fail;
        }
    }

    return 0;

fail:
    DBG("Fail vhost_dev_enable_notifiers\n");
    return r;
}

/* TODO: This needs to be checked if it's still needed */
static int vhost_dev_has_iommu(struct vhost_dev *dev)
{
    VirtIODevice *vdev = dev->vdev;

    /*
     * For vhost, VIRTIO_F_IOMMU_PLATFORM means the backend support
     * incremental memory mapping API via IOTLB API. For platform that
     * does not have IOMMU, there's no need to enable this feature
     * which may cause unnecessary IOTLB miss/update transactions.
     */
    return virtio_bus_device_iommu_enabled(vdev) &&
           virtio_has_feature(vdev->host_features, VIRTIO_F_IOMMU_PLATFORM);
}

static int vhost_dev_set_features(struct vhost_dev *dev,
                                  bool enable_log)
{
    uint64_t features = dev->acked_features;
    int r;

    if (enable_log) {
        features |= 0x1ULL << VHOST_F_LOG_ALL;
    }

    /* TODO: check if this is needed */
    if (!vhost_dev_has_iommu(dev)) {
        features &= ~(0x1ULL << VIRTIO_F_IOMMU_PLATFORM);
    }

    r = vhost_user_set_features(dev, features);
    if (r < 0) {
        DBG("vhost_set_features failed\n");
        goto out;
    }

out:
    return r;
}

static int vhost_virtqueue_set_addr(struct vhost_dev *dev,
                                    struct vhost_virtqueue *vq,
                                    unsigned idx, bool enable_log)
{
    struct vhost_vring_addr addr;
    int r;

    memset(&addr, 0, sizeof(struct vhost_vring_addr));

    addr.desc_user_addr = (uint64_t)(unsigned long)vq->desc_phys;
    addr.avail_user_addr = (uint64_t)(unsigned long)vq->avail_phys;
    addr.used_user_addr = (uint64_t)(unsigned long)vq->used_phys;

    DBG("Print physical addresses of vrings:\n");
    DBG("\tvq->desc_phys: 0x%llx\n", vq->desc_phys);
    DBG("\tvq->avail_phys: 0x%llx\n", vq->avail_phys);
    DBG("\tvq->used_phys: 0x%llx\n", vq->used_phys);

    addr.index = idx;
    addr.log_guest_addr = vq->used_phys;
    addr.flags = enable_log ? (1 << VHOST_VRING_F_LOG) : 0;

    r = vhost_user_set_vring_addr(dev, &addr);
    if (r < 0) {
        DBG("vhost_set_vring_addr failed\n");
    }
    return r;
}

uint64_t vhost_get_features(struct vhost_dev *hdev, const int *feature_bits,
                            uint64_t features)
{
    const int *bit = feature_bits;
    while (*bit != VHOST_INVALID_FEATURE_BIT) {
        uint64_t bit_mask = (1ULL << *bit);
        if (!(hdev->features & bit_mask)) {
            features &= ~bit_mask;
        }
        bit++;
    }
    return features;
}

void vhost_ack_features(struct vhost_dev *hdev, const int *feature_bits,
                        uint64_t features)
{
    const int *bit = feature_bits;
    while (*bit != VHOST_INVALID_FEATURE_BIT) {
        uint64_t bit_mask = (1ULL << *bit);
        if (features & bit_mask) {
            hdev->acked_features |= bit_mask;
        }
        bit++;
    }
}



/* Mask/unmask events from this vq. */
void vhost_virtqueue_mask(struct vhost_dev *hdev, VirtIODevice *vdev, int n,
                         bool mask)
{
    struct VirtQueue *vvq = virtio_get_queue(vdev, n);
    int r, index = n - hdev->vq_index;
    struct vhost_vring_file file;

    if (mask) {
        file.fd = event_notifier_get_wfd(&hdev->vqs[index].masked_notifier);
    } else {
        file.fd = event_notifier_get_wfd(virtio_queue_get_guest_notifier(vvq));
    }

    file.index = vhost_user_get_vq_index(hdev, n);

    r = vhost_user_set_vring_call(&file);
    if (r < 0) {
        DBG("vhost_set_vring_call failed\n");
    }
}

static int vhost_virtqueue_start(struct vhost_dev *dev,
                                struct VirtIODevice *vdev,
                                struct vhost_virtqueue *vq,
                                unsigned idx)
{
    VirtioBus *vbus = vdev->vbus;
    uint64_t s, l, a;
    int r;

    int vhost_vq_index = vhost_user_get_vq_index(dev, idx);
    struct vhost_vring_file file = {
        .index = vhost_vq_index
    };
    struct vhost_vring_state state = {
        .index = vhost_vq_index
    };
    struct VirtQueue *vvq = virtio_get_queue(vdev, idx);

    a = virtio_queue_get_desc_addr(vdev, idx);
    if (a == 0) {
        /* Queue might not be ready for start */
        DBG("Error: Queue (%d) might not be ready for start\n", idx);
        return 0;
    }

    vq->num = state.num = virtio_queue_get_num(vdev, idx);

    r = vhost_user_set_vring_num(dev, &state);
    if (r) {
        DBG("vhost_set_vring_num failed\n");
        return r;
    }

    state.num = virtio_queue_get_last_avail_idx(vdev, idx);
    r = vhost_user_set_vring_base(dev, &state);
    if (r) {
        DBG("vhost_set_vring_base failed\n");
        return r;
    }

    vq->desc_size = s = l = virtio_queue_get_desc_size(vdev, idx);
    vq->desc_phys = vring_phys_addrs[idx] << 12;
    vq->desc = (void *)virtio_queue_get_desc_addr(vdev, idx);
    if (!vq->desc || l != s) {
        DBG("Error : vq->desc = a\n");
        r = -ENOMEM;
        return r;
    }

    vq->avail_size = s = l = virtio_queue_get_avail_size(vdev, idx);
    vq->avail_phys = vq->desc_phys + virtio_queue_get_avail_addr(vdev, idx)
                                   - virtio_queue_get_desc_addr(vdev, idx);
    vq->avail = (void *)virtio_queue_get_avail_addr(vdev, idx);
    if (!vq->avail || l != s) {
        DBG("Error : vq->avail = a\n");
        r = -ENOMEM;
        return r;
    }

    vq->used_size = s = l = virtio_queue_get_used_size(vdev, idx);
    vq->used_phys = a = vq->avail_phys + virtio_queue_get_used_addr(vdev, idx)
                                       - virtio_queue_get_avail_addr(vdev, idx);
    vq->used = (void *)virtio_queue_get_used_addr(vdev, idx);
    if (!vq->used || l != s) {
        DBG("Error : vq->used = a\n");
        r = -ENOMEM;
        return r;
    }

    r = vhost_virtqueue_set_addr(dev, vq, vhost_vq_index, dev->log_enabled);
    if (r < 0) {
        DBG("Fail vhost_virtqueue_set_addr\n");
        return r;
    }

    /* The next line has to be disable for rng */
    /* Clear and discard previous events if any. */
    event_notifier_test_and_clear(virtio_queue_get_host_notifier(vvq));

    file.fd = event_notifier_get_fd(virtio_queue_get_host_notifier(vvq));
    r = vhost_user_set_vring_kick(&file);
    if (r) {
        DBG("vhost_set_vring_kick failed\n");
        return r;
    }

    /* Clear and discard previous events if any. */
    event_notifier_test_and_clear(&vq->masked_notifier);

    /*
     * Init vring in unmasked state, unless guest_notifier_mask
     * will do it later.
     */
    if (!vdev->use_guest_notifier_mask) {
        /* TODO: check and handle errors. */
        vhost_virtqueue_mask(dev, vdev, idx, false);
    }

    return 0;
}

void update_mem_table(VirtIODevice *vdev)
{
    print_mem_table(vdev->vhdev);
    vhost_commit_vqs(vdev->vhdev);
    print_mem_table(vdev->vhdev);
    (void)vhost_user_set_mem_table(vdev->vhdev);
}

static int vhost_dev_set_vring_enable(struct vhost_dev *hdev, int enable)
{
    DBG("vhost_dev_set_vring_enable:\n");

    /*
     * For vhost-user devices, if VHOST_USER_F_PROTOCOL_FEATURES has not
     * been negotiated, the rings start directly in the enabled state, and
     * .vhost_set_vring_enable callback will fail since
     * VHOST_USER_SET_VRING_ENABLE is not supported.
     */
    if (!virtio_has_feature(hdev->backend_features,
                            VHOST_USER_F_PROTOCOL_FEATURES)) {
        DBG("Does not have VHOST_USER_F_PROTOCOL_FEATURES\n");
        return 0;
    }

    return vhost_user_set_vring_enable(hdev, enable);
}

/* Host notifiers must be enabled at this point. */
int vhost_dev_start(struct vhost_dev *hdev, VirtIODevice *vdev, bool vrings)
{
    int i, r;

    hdev->started = true;
    hdev->vdev = vdev;

    r = vhost_dev_set_features(hdev, hdev->log_enabled);
    if (r < 0) {
        return r;
    }

    /* TODO: check if this is needed */
    if (vhost_dev_has_iommu(hdev)) {
        DBG("memory_listener_register?\n");
    }

    vhost_commit_mem_regions(hdev);

    for (i = 0; i < hdev->nvqs; ++i) {
        r = vhost_virtqueue_start(hdev,
                                  vdev,
                                  hdev->vqs + i,
                                  hdev->vq_index + i);
        if (r < 0) {
            DBG("Fail vhost_virtqueue_start\n");
            return r;
        }
    }

    if (vrings) {
        r = vhost_dev_set_vring_enable(hdev, true);
        if (r) {
            DBG("Fail vhost_dev_set_vring_enable\n");
            return r;
        }
    }

    r = vhost_user_dev_start(hdev, true);
    if (r) {
        DBG("Fail vhost_dev_set_vring_enable\n");
        return r;
    }

    return 0;
}


int vhost_dev_get_config(struct vhost_dev *hdev, uint8_t *config,
                         uint32_t config_len)
{
    return vhost_user_get_config(hdev, config, config_len);
}

int vhost_dev_set_config(struct vhost_dev *hdev, const uint8_t *data,
                         uint32_t offset, uint32_t size, uint32_t flags)
{
    return vhost_user_set_config(hdev, data, offset, size, flags);
}

void vhost_dev_set_config_notifier(struct vhost_dev *hdev,
                                   const VhostDevConfigOps *ops)
{
    hdev->config_ops = ops;
}

int vhost_dev_prepare_inflight(struct vhost_dev *hdev, VirtIODevice *vdev)
{
    int r;

    /*
     * TODO: Check if we need that
     * if (hdev->vhost_ops->vhost_get_inflight_fd == NULL ||
     *     hdev->vhost_ops->vhost_set_inflight_fd == NULL) {
     *     return 0;
     * }
     */

    hdev->vdev = vdev;

    r = vhost_dev_set_features(hdev, hdev->log_enabled);
    if (r < 0) {
        DBG("vhost_dev_prepare_inflight failed\n");
        return r;
    }

    return 0;
}

int vhost_dev_set_inflight(struct vhost_dev *dev,
                           struct vhost_inflight *inflight)
{
    int r;

    if (inflight->addr) {
        r = vhost_user_set_inflight_fd(dev, inflight);
        if (r) {
            DBG("vhost_set_inflight_fd failed\n");
            return -1;
        }
    }

    return 0;
}

int vhost_dev_get_inflight(struct vhost_dev *dev, uint16_t queue_size,
                           struct vhost_inflight *inflight)
{
    int r;

    r = vhost_user_get_inflight_fd(dev, queue_size, inflight);
    if (r) {
        DBG("vhost_get_inflight_fd failed\n");
        return -1;
    }

    return 0;
}

