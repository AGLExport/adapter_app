/*
 *
 * Based on:
 *
 *  1) virtio.c of QEMU project
 *
 *     Copyright IBM, Corp. 2007
 *
 *     Authors:
 *      Anthony Liguori   <aliguori@us.ibm.com>
 *
 *
 *  2) virtio-mmio.c of QEMU project
 *
 *     Copyright (c) 2011 Linaro Limited
 *
 *     Author:
 *      Peter Maydell <peter.maydell@linaro.org>
 *
 *
 * Copyright 2022-2023 Virtual Open Systems SAS.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
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

/* For socket */
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

/* Project header files */
#include "virtio_loopback.h"
#include "virtio_rng.h"

#include <stddef.h>
#include <pthread.h>
#include <limits.h>

#ifdef DEBUG
#define DBG(...) printf("virtio-loopback: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */

/* Global variables */

int s; /* To be deleted */
int efd; /* Eventfd file descriptor */
int efd_notify; /* Eventfd file descriptor */
fd_set rfds;
int fd;
int loopback_fd;

virtio_device_info_struct_t device_info;
virtio_neg_t *address;

VirtIOMMIOProxy *proxy;

int eventfd_count;
pthread_mutex_t interrupt_lock;

void virtio_add_feature(uint64_t *features, unsigned int fbit)
{
    *features |= (1ULL << fbit);
}

bool virtio_has_feature(uint64_t features, unsigned int fbit)
{
    return !!(features & (1ULL << fbit));
}

static int virtio_validate_features(VirtIODevice *vdev)
{
    if (virtio_has_feature(vdev->host_features, VIRTIO_F_IOMMU_PLATFORM) &&
        !virtio_has_feature(vdev->guest_features, VIRTIO_F_IOMMU_PLATFORM)) {
        return -EFAULT;
    }

    return 0;
}

bool virtio_device_should_start(VirtIODevice *vdev, uint8_t status)
{
    if (!vdev->vm_running) {
        return false;
    }

    return virtio_device_started(vdev, status);
}

bool virtio_device_started(VirtIODevice *vdev, uint8_t status)
{

    DBG("virtio_device_started: %d\n", status & VIRTIO_CONFIG_S_DRIVER_OK);
    DBG("status: %d\n", status);

    return status & VIRTIO_CONFIG_S_DRIVER_OK;
}


void virtio_set_started(VirtIODevice *vdev, bool started)
{
    if (started) {
        vdev->start_on_kick = false;
    }

    if (vdev->use_started) {
        vdev->started = started;
    }
}

int virtio_set_status(VirtIODevice *vdev, uint8_t val)
{
    VirtioDeviceClass *k = vdev->vdev_class;

    DBG("virtio_set_status(...)\n");

    if (virtio_has_feature(vdev->guest_features, VIRTIO_F_VERSION_1)) {
        if (!(vdev->status & VIRTIO_CONFIG_S_FEATURES_OK) &&
            val & VIRTIO_CONFIG_S_FEATURES_OK) {
            int ret = virtio_validate_features(vdev);

            if (ret) {
                return ret;
            }
        }
    }

    if ((vdev->status & VIRTIO_CONFIG_S_DRIVER_OK) !=
        (val & VIRTIO_CONFIG_S_DRIVER_OK)) {
        virtio_set_started(vdev, val & VIRTIO_CONFIG_S_DRIVER_OK);
    }

    DBG("set vdev->status:%u\n", vdev->status);

    if (k->set_status) {
        DBG("k->set_status\n");
        k->set_status(vdev, val);
    }

    vdev->status = val;

    return 0;
}

uint64_t vring_align(uint64_t addr, unsigned long align)
{
    return QEMU_ALIGN_UP(addr, align);
}

uint64_t virtio_queue_get_desc_size(VirtIODevice *vdev, int n)
{
    return sizeof(VRingDesc) * vdev->vq[n].vring.num;
}

uint64_t virtio_queue_get_desc_addr(VirtIODevice *vdev, int n)
{
    return vdev->vq[n].vring.desc;
}

uint64_t virtio_queue_get_avail_addr(VirtIODevice *vdev, int n)
{
    return vdev->vq[n].vring.avail;
}

uint64_t virtio_queue_get_used_addr(VirtIODevice *vdev, int n)
{
    return vdev->vq[n].vring.used;
}


int virtio_queue_get_num(VirtIODevice *vdev, int n)
{
    return vdev->vq[n].vring.num;
}


uint64_t virtio_queue_get_avail_size(VirtIODevice *vdev, int n)
{
    int s;

    s = virtio_has_feature(vdev->guest_features,
                           VIRTIO_RING_F_EVENT_IDX) ? 2 : 0;
    return offsetof(VRingAvail, ring) +
        sizeof(uint16_t) * vdev->vq[n].vring.num + s;
}

uint64_t virtio_queue_get_used_size(VirtIODevice *vdev, int n)
{
    int s;

    s = virtio_has_feature(vdev->guest_features,
                           VIRTIO_RING_F_EVENT_IDX) ? 2 : 0;
    return offsetof(VRingUsed, ring) +
        sizeof(VRingUsedElem) * vdev->vq[n].vring.num + s;
}

/* virt queue functions */
void virtio_queue_update_rings(VirtIODevice *vdev, int n)
{
    VRing *vring = &vdev->vq[n].vring;

    if (!vring->num || !vring->desc || !vring->align) {
        /* not yet setup -> nothing to do */
        return;
    }
    vring->avail = vring->desc + vring->num * sizeof(VRingDesc);
    vring->used = vring_align(vring->avail +
                              offsetof(VRingAvail, ring[vring->num]),
                              vring->align);
}

static uint16_t virtio_queue_split_get_last_avail_idx(VirtIODevice *vdev,
                                                      int n)
{
    return vdev->vq[n].last_avail_idx;
}


unsigned int virtio_queue_get_last_avail_idx(VirtIODevice *vdev, int n)
{
    return virtio_queue_split_get_last_avail_idx(vdev, n);
}

void virtio_queue_set_num(VirtIODevice *vdev, int n, int num)
{
    /*
     * Don't allow guest to flip queue between existent and
     * nonexistent states, or to set it to an invalid size.
     */
    if (!!num != !!vdev->vq[n].vring.num ||
        num > VIRTQUEUE_MAX_SIZE ||
        num < 0) {
        return;
    }
    vdev->vq[n].vring.num = num;
}

uint64_t virtio_queue_get_addr(VirtIODevice *vdev, int n)
{
    return vdev->vq[n].vring.desc;
}


void virtio_queue_set_addr(VirtIODevice *vdev, int n, uint64_t addr)
{
    if (!vdev->vq[n].vring.num) {
        return;
    }
    vdev->vq[n].vring.desc = addr;
    virtio_queue_update_rings(vdev, n);
}

int virtio_queue_ready(VirtQueue *vq)
{
    return vq->vring.avail != 0;
}


uint16_t vring_avail_idx(VirtQueue *vq)
{
    vq->shadow_avail_idx = ((VRingAvail *)vq->vring.avail)->idx;

    return vq->shadow_avail_idx;
}

uint16_t vring_avail_ring(VirtQueue *vq, int i)
{
    return ((VRingAvail *)vq->vring.avail)->ring[i];
}

int virtio_queue_split_empty(VirtQueue *vq)
{
    bool empty;

    if (!vq->vring.avail) {
        return 1;
    }

    if (vq->shadow_avail_idx != vq->last_avail_idx) {
        return 0;
    }

    empty = vring_avail_idx(vq) == vq->last_avail_idx;
    return empty;
}

int virtio_queue_empty(VirtQueue *vq)
{
    return virtio_queue_split_empty(vq);
}

size_t iov_from_buf_full(const struct iovec *iov, unsigned int iov_cnt,
                         size_t offset, const void *buf, size_t bytes)
{
    size_t done;
    unsigned int i;
    for (i = 0, done = 0; (offset || done < bytes) && i < iov_cnt; i++) {
        if (offset < iov[i].iov_len) {
            size_t len = MIN(iov[i].iov_len - offset, bytes - done);
            memcpy(iov[i].iov_base + offset, buf + done, len);
            done += len;
            offset = 0;
        } else {
            offset -= iov[i].iov_len;
        }
    }
    return done;
}


size_t qemu_iov_from_buf(const struct iovec *iov, unsigned int iov_cnt,
             size_t offset, const void *buf, size_t bytes)
{
    if (__builtin_constant_p(bytes) && iov_cnt &&
        offset <= iov[0].iov_len && bytes <= iov[0].iov_len - offset) {
        memcpy(iov[0].iov_base + offset, buf, bytes);
        return bytes;
    } else {
        return iov_from_buf_full(iov, iov_cnt, offset, buf, bytes);
    }
}


/* Called within rcu_read_lock().  */
static inline uint16_t vring_avail_flags(VirtQueue *vq)
{
    return ((VRingAvail *)vq->vring.avail)->flags;
}

/* Called within rcu_read_lock().  */
static inline uint16_t vring_get_used_event(VirtQueue *vq)
{
    return vring_avail_ring(vq, vq->vring.num);
}

/* The following is used with USED_EVENT_IDX and AVAIL_EVENT_IDX */
/*
 * Assuming a given event_idx value from the other side, if
 * we have just incremented index from old to new_idx,
 * should we trigger an event?
 */
static inline int vring_need_event(uint16_t event_idx,
                                   uint16_t new_idx, uint16_t old)
{
    /*
     * Note: Xen has similar logic for notification hold-off
     * in include/xen/interface/io/ring.h with req_event and req_prod
     * corresponding to event_idx + 1 and new_idx respectively.
     * Note also that req_event and req_prod in Xen start at 1,
     * event indexes in virtio start at 0.
     */
    return (uint16_t)(new_idx - event_idx - 1) < (uint16_t)(new_idx - old);
}

/* Called within rcu_read_lock(). */
static bool virtio_split_should_notify(VirtIODevice *vdev, VirtQueue *vq)
{
    uint16_t old, new;
    bool v;

    /* Always notify when queue is empty (when feature acknowledge) */
    if (virtio_has_feature(vdev->guest_features, VIRTIO_F_NOTIFY_ON_EMPTY) &&
        !vq->inuse && virtio_queue_empty(vq)) {
        return true;
    }

    if (!virtio_has_feature(vdev->guest_features, VIRTIO_RING_F_EVENT_IDX)) {
        return !(vring_avail_flags(vq) & VRING_AVAIL_F_NO_INTERRUPT);
    }

    v = vq->signalled_used_valid;
    vq->signalled_used_valid = true;
    old = vq->signalled_used;
    new = vq->signalled_used = vq->used_idx;
    return !v || vring_need_event(vring_get_used_event(vq), new, old);
}

/* Called within rcu_read_lock().  */
static bool virtio_should_notify(VirtIODevice *vdev, VirtQueue *vq)
{
    return virtio_split_should_notify(vdev, vq);
}


void virtio_set_isr(VirtIODevice *vdev, int value)
{
    uint8_t old = vdev->isr;

    /*
     * Do not write ISR if it does not change, so that its cacheline remains
     * shared in the common case where the guest does not read it.
     */
    if ((old & value) != value) {
        vdev->isr |= value;
    }

    DBG("Update isr: %d\n", vdev->isr);
}

static void virtio_irq(VirtQueue *vq)
{
    virtio_set_isr(vq->vdev, 0x1);
    virtio_notify_vector(vq->vdev);
}

void virtio_notify_config(VirtIODevice *vdev)
{

    DBG("virtio_notify_config\n");

    if (!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK)) {
        return;
    }

    virtio_set_isr(vdev, 0x3);
    vdev->generation++;
    /*
     * MMIO does not use vector parameter:
     * virtio_notify_vector(vdev, vdev->config_vector);
     */
    virtio_notify_vector(vdev);
}

void virtio_notify(VirtIODevice *vdev, VirtQueue *vq)
{
    if (!virtio_should_notify(vdev, vq)) {
        DBG("Do not notify!\n");
        return;
    }
    DBG("Go on and notify!\n");

    virtio_irq(vq);
}

static inline void vring_used_write(VirtQueue *vq, VRingUsedElem *uelem, int i)
{
    VRingUsed *used = (VRingUsed *)vq->vring.used;

    used->ring[i] = *uelem;
}

void virtqueue_split_fill(VirtQueue *vq, const VirtQueueElement *elem,
                    unsigned int len, unsigned int idx)
{
    VRingUsedElem uelem;

    if (!vq->vring.used) {
        return;
    }

    idx = (idx + vq->used_idx) % vq->vring.num;

    uelem.id = elem->index;
    uelem.len = len;
    vring_used_write(vq, &uelem, idx);
}

void virtqueue_fill(VirtQueue *vq, const VirtQueueElement *elem,
                    unsigned int len, unsigned int idx)
{
    virtqueue_split_fill(vq, elem, len, idx);
}

static inline void vring_used_idx_set(VirtQueue *vq, uint16_t val)
{
    ((VRingUsed *)vq->vring.used)->idx = val;
    vq->used_idx = val;
}

static void virtqueue_split_flush(VirtQueue *vq, unsigned int count)
{
    uint16_t old, new;

    if (!vq->vring.used) {
        return;
    }

    old = vq->used_idx;
    new = old + count;
    vring_used_idx_set(vq, new);
    vq->inuse -= count;
    if ((int16_t)(new - vq->signalled_used) < (uint16_t)(new - old)) {
        vq->signalled_used_valid = false;
    }
}

void virtqueue_flush(VirtQueue *vq, unsigned int count)
{
    virtqueue_split_flush(vq, count);
}

void virtqueue_push(VirtQueue *vq, const VirtQueueElement *elem,
                    unsigned int len)
{
    virtqueue_fill(vq, elem, len, 0);
    virtqueue_flush(vq, 1);
}


void vring_set_avail_event(VirtQueue *vq, uint16_t val)
{
    uint16_t *avail;

    avail = (uint16_t *)&((VRingUsed *)vq->vring.used)->ring[vq->vring.num];
    *avail = val;
}

static bool virtqueue_map_desc(VirtIODevice *vdev, unsigned int *p_num_sg,
                               uint64_t *addr, struct iovec *iov,
                               unsigned int max_num_sg, bool is_write,
                               uint64_t pa, size_t sz)
{
    DBG("Not implemented\n");
}

static void *virtqueue_alloc_element(size_t sz, unsigned out_num,
                                     unsigned in_num)
{
    VirtQueueElement *elem;
    size_t in_addr_ofs = QEMU_ALIGN_UP(sz, __alignof__(elem->in_addr[0]));
    size_t out_addr_ofs = in_addr_ofs + in_num * sizeof(elem->in_addr[0]);
    size_t out_addr_end = out_addr_ofs + out_num * sizeof(elem->out_addr[0]);
    size_t in_sg_ofs = QEMU_ALIGN_UP(out_addr_end, __alignof__(elem->in_sg[0]));
    size_t out_sg_ofs = in_sg_ofs + in_num * sizeof(elem->in_sg[0]);
    size_t out_sg_end = out_sg_ofs + out_num * sizeof(elem->out_sg[0]);

    /*
     * TODO: Add check for requested size
     *
     * assert(sz >= sizeof(VirtQueueElement));
     */
    elem = malloc(out_sg_end);
    elem->out_num = out_num;
    elem->in_num = in_num;
    elem->in_addr = (void *)elem + in_addr_ofs;
    elem->out_addr = (void *)elem + out_addr_ofs;
    elem->in_sg = (void *)elem + in_sg_ofs;
    elem->out_sg = (void *)elem + out_sg_ofs;
    return elem;
}

void *virtqueue_split_pop(VirtQueue *vq, size_t sz)
{
    unsigned int i, head, max;
    int64_t len;
    VirtIODevice *vdev = vq->vdev;
    VirtQueueElement *elem = NULL;
    unsigned out_num, in_num, elem_entries;
    uint64_t addr[VIRTQUEUE_MAX_SIZE];
    struct iovec iov[VIRTQUEUE_MAX_SIZE];
    VRingDesc *desc;
    int rc;

    if (virtio_queue_split_empty(vq)) {
        goto done;
    }

    /* When we start there are none of either input nor output. */
    out_num = in_num = elem_entries = 0;

    max = vq->vring.num;

    if (vq->inuse >= vq->vring.num) {
        DBG("Virtqueue size exceeded\n");
        goto done;
    }

    if (!virtqueue_get_head(vq, vq->last_avail_idx++, &head)) {
        goto done;
    }

    if (virtio_has_feature(vdev->guest_features, VIRTIO_RING_F_EVENT_IDX)) {
        vring_set_avail_event(vq, vq->last_avail_idx);
    }

    i = head;

    desc = (VRingDesc *)vq->vring.desc + i;

    /* Collect all the descriptors */
    do {
        bool map_ok;

        if (desc->flags & VRING_DESC_F_WRITE) {
            map_ok = virtqueue_map_desc(vdev, &in_num, addr + out_num,
                                        iov + out_num,
                                        VIRTQUEUE_MAX_SIZE - out_num, true,
                                        desc->addr, desc->len);
        } else {
            if (in_num) {
                DBG("Incorrect order for descriptors\n");
                goto err_undo_map;
            }
            map_ok = virtqueue_map_desc(vdev, &out_num, addr, iov,
                                        VIRTQUEUE_MAX_SIZE, false,
                                        desc->addr, desc->len);
        }
        if (!map_ok) {
            goto err_undo_map;
        }

        /* If we've got too many, that implies a descriptor loop. */
        if (++elem_entries > max) {
            goto err_undo_map;
        }

        rc = virtqueue_split_read_next_desc(vdev, desc, max, &i);
    } while (rc == VIRTQUEUE_READ_DESC_MORE);

    if (rc == VIRTQUEUE_READ_DESC_ERROR) {
        goto err_undo_map;
    }

    /* Now copy what we have collected and mapped */
    elem = virtqueue_alloc_element(sz, out_num, in_num);
    elem->index = head;
    elem->ndescs = 1;
    for (i = 0; i < out_num; i++) {
        elem->out_addr[i] = addr[i];
        elem->out_sg[i] = iov[i];
    }
    for (i = 0; i < in_num; i++) {
        elem->in_addr[i] = addr[out_num + i];
        elem->in_sg[i] = iov[out_num + i];
    }

    vq->inuse++;

done:
    return elem;

err_undo_map:
    goto done;
}

void *virtqueue_pop(VirtQueue *vq, size_t sz)
{
    return virtqueue_split_pop(vq, sz);
}

bool virtqueue_get_head(VirtQueue *vq, unsigned int idx,
                               unsigned int *head)
{

    /*
     * Grab the next descriptor number they're advertising, and increment
     * the index we've seen.
     */
    *head = vring_avail_ring(vq, idx % vq->vring.num);

    /* If their number is silly, that's a fatal mistake. */
    if (*head >= vq->vring.num) {
        DBG("Guest says index %u is available", *head);
        return false;
    }

    return true;
}

uint32_t get_vqs_max_size(VirtIODevice *vdev)
{
    uint32_t vq_max_size = VIRTQUEUE_MAX_SIZE;
    uint32_t total_size, temp_size, total_p2 = 1;
    int i, log_res = 0;

    total_size = VIRTQUEUE_MAX_SIZE * sizeof(VRingDesc);
    total_size += offsetof(VRingAvail, ring) +
                   VIRTQUEUE_MAX_SIZE * sizeof(uint16_t);
    total_size += offsetof(VRingUsed, ring) +
                   VIRTQUEUE_MAX_SIZE * sizeof(uint16_t);

    temp_size = total_size;

    /* Compute log2 of total_size (Needs to be power of 2) */
    while ((temp_size /= 2) > 0) {
        log_res++;
        total_p2 *= 2;
    }

    /* if total_size is not a power of 2: (total_size > 8) -> 16 */
    if (total_size > total_p2) {
        total_size = 2 * total_p2;
    }

    /*
     * Align to page size:  This needed only in case total_size
     * is less than 4096 (PAGE_SIZE)
     */
    if (total_size % PAGE_SIZE > 0) {
        total_size = (total_size / PAGE_SIZE) * PAGE_SIZE + PAGE_SIZE;
    }

    DBG("Total vqs size to mmap is: %u\n", total_size);

    return total_size;
}

int virtqueue_num_heads(VirtQueue *vq, unsigned int idx)
{
    uint16_t num_heads = vring_avail_idx(vq) - idx;

    /* Check it isn't doing very strange things with descriptor numbers. */
    if (num_heads > vq->vring.num) {
        DBG("Guest moved used index from %u to %u",
                     idx, vq->shadow_avail_idx);
        return -EINVAL;
    }

    return num_heads;
}

int virtqueue_split_read_next_desc(VirtIODevice *vdev, VRingDesc *desc,
                                          unsigned int max, unsigned int *next)
{
    /* If this descriptor says it doesn't chain, we're done. */
    if (!(desc->flags & VRING_DESC_F_NEXT)) {
        return VIRTQUEUE_READ_DESC_DONE;
    }

    /* Check they're not leading us off end of descriptors. */
    *next = desc->next;

    if (*next >= max) {
        DBG("Desc next is %u", *next);
        return VIRTQUEUE_READ_DESC_ERROR;
    }

    desc = (VRingDesc *)desc + *next;
    return VIRTQUEUE_READ_DESC_MORE;
}


static void virtqueue_split_get_avail_bytes(VirtQueue *vq,
                            unsigned int *in_bytes, unsigned int *out_bytes,
                            unsigned max_in_bytes, unsigned max_out_bytes)
{
    VirtIODevice *vdev = vq->vdev;
    unsigned int max, idx;
    unsigned int total_bufs, in_total, out_total;
    int64_t len = 0;
    int rc;

    idx = vq->last_avail_idx;
    total_bufs = in_total = out_total = 0;

    max = vq->vring.num;

    while ((rc = virtqueue_num_heads(vq, idx)) > 0) {
        unsigned int num_bufs;
        VRingDesc *desc;
        unsigned int i;

        num_bufs = total_bufs;

        if (!virtqueue_get_head(vq, idx++, &i)) {
            goto err;
        }

        /* there is no need to copy anything form the cache struct */
        desc = (VRingDesc *)vq->vring.desc + i;

        if (desc->flags & VRING_DESC_F_INDIRECT) {
            if (!desc->len || (desc->len % sizeof(VRingDesc))) {
                DBG("Invalid size for indirect buffer table\n");
                goto err;
            }

            /* If we've got too many, that implies a descriptor loop. */
            if (num_bufs >= max) {
                goto err;
            }
        }

        do {
            /* If we've got too many, that implies a descriptor loop. */
            if (++num_bufs > max) {
                goto err;
            }

            if (desc->flags & VRING_DESC_F_WRITE) {
                in_total += desc->len;
            } else {
                out_total += desc->len;
            }
            if (in_total >= max_in_bytes && out_total >= max_out_bytes) {
                goto done;
            }

            rc = virtqueue_split_read_next_desc(vdev, desc, max, &i);
        } while (rc == VIRTQUEUE_READ_DESC_MORE);

        if (rc == VIRTQUEUE_READ_DESC_ERROR) {
            goto err;
        }

        total_bufs = num_bufs;
    }

    if (rc < 0) {
        goto err;
    }

done:
    if (in_bytes) {
        *in_bytes = in_total;
    }
    if (out_bytes) {
        *out_bytes = out_total;
    }
    return;

err:
    in_total = out_total = 0;
    goto done;
}

void virtqueue_get_avail_bytes(VirtQueue *vq, unsigned int *in_bytes,
                               unsigned int *out_bytes,
                               unsigned max_in_bytes, unsigned max_out_bytes)
{
    if (!vq->vring.desc) {
        goto err;
    }

    virtqueue_split_get_avail_bytes(vq, in_bytes, out_bytes,
                                    max_in_bytes, max_out_bytes);

    return;
err:
    if (in_bytes) {
        *in_bytes = 0;
    }
    if (out_bytes) {
        *out_bytes = 0;
    }
}

void print_neg_flag(uint64_t neg_flag, bool read)
{
    if (read) {
        DBG("Read:\t");
    } else {
        DBG("Write:\t");
    }

    switch (neg_flag) {
    case VIRTIO_MMIO_MAGIC_VALUE:           /* 0x000 */
        DBG("VIRTIO_MMIO_MAGIC_VALUE\n");
        break;
    case VIRTIO_MMIO_VERSION:               /* 0x004 */
        DBG("VIRTIO_MMIO_VERSION\n");
        break;
    case VIRTIO_MMIO_DEVICE_ID:             /* 0x008 */
        DBG("VIRTIO_MMIO_DEVICE_ID\n");
        break;
    case VIRTIO_MMIO_VENDOR_ID:             /* 0x00c */
        DBG("VIRTIO_MMIO_VENDOR_ID\n");
        break;
    case VIRTIO_MMIO_DEVICE_FEATURES:       /* 0x010 */
        DBG("VIRTIO_MMIO_DEVICE_FEATURES\n");
        break;
    case VIRTIO_MMIO_DEVICE_FEATURES_SEL:   /* 0x014 */
        DBG("VIRTIO_MMIO_DEVICE_FEATURES_SEL\n");
        break;
    case VIRTIO_MMIO_DRIVER_FEATURES:       /* 0x020 */
        DBG("VIRTIO_MMIO_DRIVER_FEATURES\n");
        break;
    case VIRTIO_MMIO_DRIVER_FEATURES_SEL:   /* 0x024 */
        DBG("VIRTIO_MMIO_DRIVER_FEATURES_SEL\n");
        break;
    case VIRTIO_MMIO_GUEST_PAGE_SIZE:       /* 0x028 */
        DBG("VIRTIO_MMIO_GUEST_PAGE_SIZE\n");
        break;
    case VIRTIO_MMIO_QUEUE_SEL:             /* 0x030 */
        DBG("VIRTIO_MMIO_QUEUE_SEL\n");
        break;
    case VIRTIO_MMIO_QUEUE_NUM_MAX:         /* 0x034 */
        DBG("VIRTIO_MMIO_QUEUE_NUM_MAX\n");
        break;
    case VIRTIO_MMIO_QUEUE_NUM:             /* 0x038 */
        DBG("VIRTIO_MMIO_QUEUE_NUM\n");
        break;
    case VIRTIO_MMIO_QUEUE_ALIGN:           /* 0x03c */
        DBG("VIRTIO_MMIO_QUEUE_ALIGN\n");
        break;
    case VIRTIO_MMIO_QUEUE_PFN:             /* 0x040 */
        DBG("VIRTIO_MMIO_QUEUE_PFN\n");
        break;
    case VIRTIO_MMIO_QUEUE_READY:           /* 0x044 */
        DBG("VIRTIO_MMIO_QUEUE_READY\n");
        break;
    case VIRTIO_MMIO_QUEUE_NOTIFY:          /* 0x050 */
        DBG("VIRTIO_MMIO_QUEUE_NOTIFY\n");
        break;
    case VIRTIO_MMIO_INTERRUPT_STATUS:      /* 0x060 */
        DBG("VIRTIO_MMIO_INTERRUPT_STATUS\n");
        break;
    case VIRTIO_MMIO_INTERRUPT_ACK:         /* 0x064 */
        DBG("VIRTIO_MMIO_INTERRUPT_ACK\n");
        break;
    case VIRTIO_MMIO_STATUS:                /* 0x070 */
        DBG("VIRTIO_MMIO_STATUS\n");
        break;
    case VIRTIO_MMIO_QUEUE_DESC_LOW:        /* 0x080 */
        DBG("VIRTIO_MMIO_QUEUE_DESC_LOW\n");
        break;
    case VIRTIO_MMIO_QUEUE_DESC_HIGH:       /* 0x084 */
        DBG("VIRTIO_MMIO_QUEUE_DESC_HIGH\n");
        break;
    case VIRTIO_MMIO_QUEUE_AVAIL_LOW:       /* 0x090 */
        DBG("VIRTIO_MMIO_QUEUE_AVAIL_LOW\n");
        break;
    case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:      /* 0x094 */
        DBG("VIRTIO_MMIO_QUEUE_AVAIL_HIGH\n");
        break;
    case VIRTIO_MMIO_QUEUE_USED_LOW:        /* 0x0a0 */
        DBG("VIRTIO_MMIO_QUEUE_USED_LOW\n");
        break;
    case VIRTIO_MMIO_QUEUE_USED_HIGH:       /* 0x0a4 */
        DBG("VIRTIO_MMIO_QUEUE_USED_HIGH\n");
        break;
    case VIRTIO_MMIO_SHM_SEL:               /* 0x0ac */
        DBG("VIRTIO_MMIO_SHM_SEL\n");
        break;
    case VIRTIO_MMIO_SHM_LEN_LOW:           /* 0x0b0 */
        DBG("VIRTIO_MMIO_SHM_LEN_LOW\n");
        break;
    case VIRTIO_MMIO_SHM_LEN_HIGH:          /* 0x0b4 */
        DBG("VIRTIO_MMIO_SHM_LEN_HIGH\n");
        break;
    case VIRTIO_MMIO_SHM_BASE_LOW:          /* 0x0b8 */
        DBG("VIRTIO_MMIO_SHM_BASE_LOW\n");
        break;
    case VIRTIO_MMIO_SHM_BASE_HIGH:         /* 0x0bc */
        DBG("VIRTIO_MMIO_SHM_BASE_HIGH\n");
        break;
    case VIRTIO_MMIO_CONFIG_GENERATION:     /* 0x0fc */
        DBG("VIRTIO_MMIO_CONFIG_GENERATION\n");
        break;
    default:
        if (neg_flag >= VIRTIO_MMIO_CONFIG) {
            DBG("\tVIRTIO_MMIO_CONFIG\n");
        } else {
            DBG("\tNegotiation flag Unknown: %ld\n", neg_flag);
        }
        return;
    }
}

int virtio_set_features_nocheck(VirtIODevice *vdev, uint64_t val)
{
    bool bad = (val & ~(vdev->host_features)) != 0;

    val &= vdev->host_features;

    vdev->guest_features |= val;
    return bad ? -1 : 0;
}

int virtio_set_features(VirtIODevice *vdev, uint64_t val)
{
    int ret;
    /*
     * The driver must not attempt to set features after feature negotiation
     * has finished.
     */
    if (vdev->status & VIRTIO_CONFIG_S_FEATURES_OK) {
        DBG("virtio_set_features: vdev->status "
            "& VIRTIO_CONFIG_S_FEATURES_OK\n");
        return -EINVAL;
    }
    ret = virtio_set_features_nocheck(vdev, val);
    return ret;
}


/* TODO: MMIO notifiers -- This might not be needed anymore  */
static void virtio_queue_guest_notifier_read(EventNotifier *n)
{
    VirtQueue *vq = container_of(n, VirtQueue, guest_notifier);
    if (event_notifier_test_and_clear(n)) {
        virtio_irq(vq);
    }
}

void *loopback_event_select(void *_e)
{
    int retval;
    fd_set rfds;
    int s;
    EventNotifier *e = (EventNotifier *)_e;
    int rfd = e->rfd;
    VirtQueue *vq = container_of(e, VirtQueue, guest_notifier);

    DBG("\nWaiting event from vhost-user-device\n");

    FD_ZERO(&rfds);
    FD_SET(rfd, &rfds);

    while (1) {

        retval = select(rfd + 1, &rfds, NULL, NULL, NULL);

        if (retval == -1) {
            DBG("select() error. Exiting...\n");
            exit(1);
        }
        if (retval > 0) {

            DBG("\n\nEvent has come from the vhost-user-device "
                "(eventfd: %d) -> event_count: %d (select value: %d)\n\n",
                                              rfd, eventfd_count, retval);

            if (event_notifier_test_and_clear(e)) {
                if (pthread_mutex_lock(&interrupt_lock) == 0) {
                    eventfd_count++;
                    virtio_irq(vq);
                    pthread_mutex_unlock(&interrupt_lock);
                } else {
                    printf("[ERROR] Locking failed\n");
                    exit(1);
                }
            }
        }
    }
}


void event_notifier_set_handler(EventNotifier *e,
                                void *handler)
{
    int ret;
    pthread_t thread_id;

    if (e->wfd > 0) {
        ret = pthread_create(&thread_id, NULL, loopback_event_select,
                             (void *)e);
        if (ret != 0) {
            exit(1);
        }
    }
}


void virtio_queue_set_guest_notifier_fd_handler(VirtQueue *vq, bool assign,
                                                bool with_irqfd)
{
    if (assign && !with_irqfd) {
        event_notifier_set_handler(&vq->guest_notifier,
                                   virtio_queue_guest_notifier_read);
    } else {
        event_notifier_set_handler(&vq->guest_notifier, NULL);
    }
    if (!assign) {
        /*
         * Test and clear notifier before closing it,
         * in case poll callback didn't have time to run.
         */
        virtio_queue_guest_notifier_read(&vq->guest_notifier);
    }
}

EventNotifier *virtio_queue_get_guest_notifier(VirtQueue *vq)
{
    return &vq->guest_notifier;
}

int virtio_loopback_set_guest_notifier(VirtIODevice *vdev, int n, bool assign,
                                          bool with_irqfd)
{
    VirtioDeviceClass *vdc = vdev->vdev_class;
    VirtQueue *vq = virtio_get_queue(vdev, n);
    EventNotifier *notifier = virtio_queue_get_guest_notifier(vq);

    if (assign) {
        int r = event_notifier_init(notifier, 0);
        if (r < 0) {
            return r;
        }
        virtio_queue_set_guest_notifier_fd_handler(vq, true, with_irqfd);
    } else {
        virtio_queue_set_guest_notifier_fd_handler(vq, false, with_irqfd);
    }

    return 0;
}

int virtio_loopback_set_guest_notifiers(VirtIODevice *vdev, int nvqs,
                                           bool assign)
{
    bool with_irqfd = false;
    int r, n;

    nvqs = MIN(nvqs, VIRTIO_QUEUE_MAX);

    for (n = 0; n < nvqs; n++) {
        if (!virtio_queue_get_num(vdev, n)) {
            break;
        }

        r = virtio_loopback_set_guest_notifier(vdev, n, assign, with_irqfd);
        if (r < 0) {
            goto assign_error;
        }
    }

    return 0;

assign_error:
    DBG("Error return virtio_loopback_set_guest_notifiers\n");
    return r;
}

EventNotifier *virtio_queue_get_host_notifier(VirtQueue *vq)
{
    return &vq->host_notifier;
}

void virtio_queue_set_host_notifier_enabled(VirtQueue *vq, bool enabled)
{
    vq->host_notifier_enabled = enabled;
}

int virtio_bus_set_host_notifier(VirtioBus *vbus, int n, bool assign)
{
    VirtIODevice *vdev = vbus->vdev;
    VirtQueue *vq = virtio_get_queue(vdev, n);

    EventNotifier *notifier = virtio_queue_get_host_notifier(vq);
    int r = 0;


    if (!vbus->ioeventfd_assign) {
        return -ENOSYS;
    }

    if (assign) {
        r = event_notifier_init(notifier, 1);
        if (r < 0) {
            DBG("unable to init event notifier: %d", r);
            return r;
        }
        r = vbus->ioeventfd_assign(proxy, notifier, n, true);
        if (r < 0) {
            DBG("unable to assign ioeventfd: %d", r);
        }
    } else {
        vbus->ioeventfd_assign(proxy, notifier, n, false);
    }

    if (r == 0) {
        virtio_queue_set_host_notifier_enabled(vq, assign);
    }

    return r;
}



/* On success, ioeventfd ownership belongs to the caller.  */
int virtio_bus_grab_ioeventfd(VirtioBus *bus)
{
    /*
     * vhost can be used even if ioeventfd=off in the proxy device,
     * so do not check k->ioeventfd_enabled.
     */
    if (!bus->ioeventfd_assign) {
        return -ENOSYS;
    }

    if (bus->ioeventfd_grabbed == 0 && bus->ioeventfd_started) {
        /*
         * Remember that we need to restart ioeventfd
         * when ioeventfd_grabbed becomes zero.
         */
        bus->ioeventfd_started = true;
    }
    bus->ioeventfd_grabbed++;
    return 0;
}

int virtio_device_grab_ioeventfd(VirtIODevice *vdev)
{
    return virtio_bus_grab_ioeventfd(vdev->vbus);
}

bool virtio_device_disabled(VirtIODevice *vdev)
{
    return vdev->disabled || vdev->broken;
}

static int prev_level;
static int int_count;

void virtio_loopback_update_irq(VirtIODevice *vdev)
{
    int level, irq_num = 44;
    pthread_t my_thread_id;

    if (!vdev) {
        return;
    }

    level = (vdev->isr != 0);

    DBG("level: %d\n", level);
    DBG("prev_level: %d\n", prev_level);

    if (!((level == 1) && (prev_level == 0))) {
        DBG("No interrupt\n");
        prev_level = level;
        return;
    }
    prev_level = level;

    DBG("Trigger interrupt (ioctl)\n");
    DBG("Interrupt counter: %d\n", int_count++);

    (void) ioctl(fd, IRQ, &irq_num);
}

bool enable_virtio_interrupt;

/* virtio device */
void virtio_notify_vector(VirtIODevice *vdev)
{

    /* TODO: Check if this is still needed */
    if (virtio_device_disabled(vdev)) {
        DBG("Device is disabled\n");
        return;
    }

    virtio_loopback_update_irq(vdev);

    /*
     * TODO: substitue the previous line with the
     *       following when it's implemented
     *
     * if (k->notify) {
     *     k->notify(qbus->parent, vector);
     * }
     */
}

void virtio_update_irq(VirtIODevice *vdev)
{
    virtio_notify_vector(vdev);
}

void virtio_queue_notify(VirtIODevice *vdev, int n)
{
    VirtQueue *vq = &vdev->vq[n];

    DBG("virtio_queue_notify(..., vq_n: %d)\n", n);

    if (!vq->vring.desc || vdev->broken) {
        DBG("virtio_queue_notify: broken\n");
        return;
    }

    if (vq->host_notifier_enabled) {
        event_notifier_set(&vq->host_notifier);
    } else if (vq->handle_output) {
        DBG("vq->handle_output\n");
        vq->handle_output(vdev, vq);

        if (vdev->start_on_kick) {
            virtio_set_started(vdev, true);
        }
    }
}

uint32_t virtio_config_readb(VirtIODevice *vdev, uint32_t addr)
{
    VirtioDeviceClass *k = vdev->vdev_class;
    uint8_t val;

    if (addr + sizeof(val) > vdev->config_len) {
        DBG("virtio_config_readb failed\n");
        return (uint32_t)-1;
    }

    k->get_config(vdev, vdev->config);

    memcpy(&val, (uint8_t *)(vdev->config + addr), sizeof(uint8_t));

    return val;
}

uint32_t virtio_config_readw(VirtIODevice *vdev, uint32_t addr)
{
    VirtioDeviceClass *k = vdev->vdev_class;
    uint16_t val;

    if (addr + sizeof(val) > vdev->config_len) {
        DBG("virtio_config_readw failed\n");
        return (uint32_t)-1;
    }

    k->get_config(vdev, vdev->config);

    memcpy(&val, (uint16_t *)(vdev->config + addr), sizeof(uint16_t));
    return val;
}

uint32_t virtio_config_readl(VirtIODevice *vdev, uint32_t addr)
{
    VirtioDeviceClass *k = vdev->vdev_class;
    uint32_t val;

    if (addr + sizeof(val) > vdev->config_len) {
        DBG("virtio_config_readl failed\n");
        return (uint32_t)-1;
    }

    k->get_config(vdev, vdev->config);

    memcpy(&val, (uint32_t *)(vdev->config + addr), sizeof(uint32_t));
    return val;
}

void virtio_config_writeb(VirtIODevice *vdev, uint32_t addr, uint32_t data)
{
    VirtioDeviceClass *k = vdev->vdev_class;
    uint8_t val = data;

    if (addr + sizeof(val) > vdev->config_len) {
        return;
    }

    memcpy((uint8_t *)(vdev->config + addr), &val, sizeof(uint8_t));

    if (k->set_config) {
        k->set_config(vdev, vdev->config);
    }
}

void virtio_config_writew(VirtIODevice *vdev, uint32_t addr, uint32_t data)
{
    VirtioDeviceClass *k = vdev->vdev_class;
    uint16_t val = data;

    if (addr + sizeof(val) > vdev->config_len) {
        return;
    }

    memcpy((uint16_t *)(vdev->config + addr), &val, sizeof(uint16_t));

    if (k->set_config) {
        k->set_config(vdev, vdev->config);
    }
}

void virtio_config_writel(VirtIODevice *vdev, uint32_t addr, uint32_t data)
{
    VirtioDeviceClass *k = vdev->vdev_class;
    uint32_t val = data;

    if (addr + sizeof(val) > vdev->config_len) {
        return;
    }

    memcpy((uint32_t *)(vdev->config + addr), &val, sizeof(uint32_t));

    if (k->set_config) {
        k->set_config(vdev, vdev->config);
    }
}



static uint64_t virtio_loopback_read(VirtIODevice *vdev, uint64_t offset,
                                 unsigned size)
{

    uint64_t ret;

    if (!vdev) {
        /*
         * If no backend is present, we treat most registers as
         * read-as-zero, except for the magic number, version and
         * vendor ID. This is not strictly sanctioned by the virtio
         * spec, but it allows us to provide transports with no backend
         * plugged in which don't confuse Linux's virtio code: the
         * probe won't complain about the bad magic number, but the
         * device ID of zero means no backend will claim it.
         */
        switch (offset) {
        case VIRTIO_MMIO_MAGIC_VALUE:
            return VIRT_MAGIC;
        case VIRTIO_MMIO_VERSION:
            if (proxy->legacy) {
                return VIRT_VERSION_LEGACY;
            } else {
                return VIRT_VERSION;
            }
        case VIRTIO_MMIO_VENDOR_ID:
            return VIRT_VENDOR;
        default:
            return 0;
        }
    }

    if (offset >= VIRTIO_MMIO_CONFIG) {
        offset -= VIRTIO_MMIO_CONFIG;

        if (proxy->legacy) {
            switch (size) {
            case 1:
                ret = virtio_config_readb(vdev, offset);
                break;
            case 2:
                ret = virtio_config_readw(vdev, offset);
                break;
            case 4:
                ret = virtio_config_readl(vdev, offset);
                break;
            default:
                abort();
            }
            DBG("ret: %lu\n", ret);
            return ret;
        }

        return 4;
    }

    if (size != 4) {
        DBG("wrong size access to register!\n");
        return 0;
    }

    switch (offset) {
    case VIRTIO_MMIO_MAGIC_VALUE:
        return VIRT_MAGIC;
    case VIRTIO_MMIO_VERSION:
        DBG("VIRTIO_MMIO_VERSION ->\n");
        if (proxy->legacy) {
            DBG("VIRTIO_MMIO_VERSION -> legacy\n");
            return VIRT_VERSION_LEGACY;
        } else {
            DBG("VIRTIO_MMIO_VERSION -> version\n");
            return VIRT_VERSION;
        }
    case VIRTIO_MMIO_DEVICE_ID:
        return vdev->device_id;
    case VIRTIO_MMIO_VENDOR_ID:
        DBG("READ\n");
        return VIRT_VENDOR;
    case VIRTIO_MMIO_DEVICE_FEATURES:
        if (proxy->legacy) {
            if (proxy->host_features_sel) {
                return vdev->host_features >> 32;
            } else {
                return vdev->host_features & (uint64_t)(((1ULL << 32) - 1));
            }
        } else {
            /* TODO: To be implemented */
        }
    case VIRTIO_MMIO_QUEUE_NUM_MAX:
        /* TODO: To be implemented */
        return VIRTQUEUE_MAX_SIZE;
    case VIRTIO_MMIO_QUEUE_PFN:
        if (!proxy->legacy) {
            DBG("VIRTIO_MMIO_QUEUE_PFN: read from legacy register (0x%lx) "
                "in non-legacy mode\n", offset);
            return 0;
        }
        return virtio_queue_get_addr(vdev, vdev->queue_sel) >>
                                            proxy->guest_page_shift;

    case VIRTIO_MMIO_QUEUE_READY:
        if (proxy->legacy) {
            DBG("VIRTIO_MMIO_QUEUE_READY: read from legacy register (0x%lx) "
                "in non-legacy mode\n", offset);
            return 0;
        }
        /* TODO: To be implemented */
    case VIRTIO_MMIO_INTERRUPT_STATUS:
        return vdev->isr;
    case VIRTIO_MMIO_STATUS:
        DBG("Read VIRTIO_MMIO_STATUS: %d\n", vdev->status);
        return vdev->status;
    case VIRTIO_MMIO_CONFIG_GENERATION:
        if (proxy->legacy) {
            DBG("VIRTIO_MMIO_CONFIG_GENERATION: read from legacy "
                "register (0x%lx) in non-legacy mode\n", offset);
            return 0;
        }
        return vdev->generation;
    case VIRTIO_MMIO_SHM_LEN_LOW:
    case VIRTIO_MMIO_SHM_LEN_HIGH:
        /*
         * VIRTIO_MMIO_SHM_SEL is unimplemented
         * according to the linux driver, if region length is -1
         * the shared memory doesn't exist
         */
        return -1;
    case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
    case VIRTIO_MMIO_DRIVER_FEATURES:
    case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
    case VIRTIO_MMIO_GUEST_PAGE_SIZE:
    case VIRTIO_MMIO_QUEUE_SEL:
    case VIRTIO_MMIO_QUEUE_NUM:
    case VIRTIO_MMIO_QUEUE_ALIGN:
    case VIRTIO_MMIO_QUEUE_NOTIFY:
    case VIRTIO_MMIO_INTERRUPT_ACK:
    case VIRTIO_MMIO_QUEUE_DESC_LOW:
    case VIRTIO_MMIO_QUEUE_DESC_HIGH:
    case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
    case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
    case VIRTIO_MMIO_QUEUE_USED_LOW:
    case VIRTIO_MMIO_QUEUE_USED_HIGH:
        DBG("VIRTIO_MMIO_QUEUE_USED_HIGH: read of write-only "
            "register (0x%lx)\n", offset);
        return 0;
    default:
        DBG("read: bad register offset (0x%lx)\n", offset);
        return 0;
    }
    return 0;
}

uint64_t vring_phys_addrs[10] = {0};
uint32_t vring_phys_addrs_idx;
static int notify_cnt;

void virtio_loopback_write(VirtIODevice *vdev, uint64_t offset,
                       uint64_t value, unsigned size)
{
    if (!vdev) {
        /*
         * If no backend is present, we just make all registers
         * write-ignored. This allows us to provide transports with
         * no backend plugged in.
         */
        return;
    }

    if (offset >= VIRTIO_MMIO_CONFIG) {
        offset -= VIRTIO_MMIO_CONFIG;

        if (proxy->legacy) {
            switch (size) {
            case 1:
                virtio_config_writeb(vdev, offset, value);
                break;
            case 2:
                virtio_config_writew(vdev, offset, value);
                break;
            case 4:
                virtio_config_writel(vdev, offset, value);
                break;
            default:
                DBG("VIRTIO_MMIO_CONFIG abort\n");
                abort();
            }
            return;
        }

        return;
    }
    if (size != 4) {
        DBG("write: wrong size access to register!\n");
        return;
    }
    switch (offset) {
    case VIRTIO_MMIO_DEVICE_FEATURES_SEL:
        DBG("VIRTIO_MMIO_DEVICE_FEATURES_SEL: 0x%lx\n", value);
        if (value) {
            proxy->host_features_sel = 1;
        } else {
            proxy->host_features_sel = 0;
        }
        break;
    case VIRTIO_MMIO_DRIVER_FEATURES:
        if (proxy->legacy) {
            if (proxy->guest_features_sel) {
                DBG("attempt to write guest features with "
                       "guest_features_sel > 0 in legacy mode\n");
                DBG("Set driver features: 0x%lx\n", value << 32);
                virtio_set_features(vdev, value << 32);
            } else {
                DBG("Set driver features: 0x%lx\n", value);
                virtio_set_features(vdev, value);
            }
        } else {
            /* TODO: To be implemented */
        }
        break;
    case VIRTIO_MMIO_DRIVER_FEATURES_SEL:
        if (value) {
            proxy->guest_features_sel = 1;
        } else {
            proxy->guest_features_sel = 0;
        }
        break;
    case VIRTIO_MMIO_GUEST_PAGE_SIZE:
        if (!proxy->legacy) {
            DBG("write to legacy register (0x%lx"
                    ") in non-legacy mode\n", offset);
            return;
        }
        if (proxy->guest_page_shift > 31) {
            proxy->guest_page_shift = 0;
        }
        break;
    case VIRTIO_MMIO_QUEUE_SEL:
        if (value < VIRTIO_QUEUE_MAX) {
            vdev->queue_sel = value;
        }
        break;
    case VIRTIO_MMIO_QUEUE_NUM:
        DBG("VIRTIO_MMIO_QUEUE_NUM: %lu\n", value);

        virtio_queue_set_num(vdev, vdev->queue_sel, value);

        if (proxy->legacy) {
            virtio_queue_update_rings(vdev, vdev->queue_sel);
        } else {
            /* TODO: To be implemented */
            exit(1);
        }
        break;
    case VIRTIO_MMIO_QUEUE_ALIGN:
        if (!proxy->legacy) {
            DBG("write to legacy register (0x%lx) in "
                "non-legacy mode\n", offset);
            return;
        }
        /* TODO: To be implemented */
        break;
    case VIRTIO_MMIO_QUEUE_PFN:
        if (!proxy->legacy) {
            DBG("write to legacy register (0x%lx) in "
                "non-legacy mode\n", offset);
            return;
        }
        if (value == 0) {
            /* TODO: To be implemented */
        } else {

            DBG("desc_addr: 0x%lx\n", value);
            vring_phys_addrs[vring_phys_addrs_idx++] = value;

            uint64_t desc_addr;
            uint32_t vqs_size = get_vqs_max_size(global_vdev);

            ioctl(fd, SHARE_VQS, &vdev->queue_sel);

            desc_addr = (uint64_t)mmap(NULL, vqs_size,
                                       PROT_READ | PROT_WRITE,
                                       MAP_SHARED, fd, 0);

            virtio_queue_set_addr(vdev, vdev->queue_sel,
                                  desc_addr);
        }
        break;
    case VIRTIO_MMIO_QUEUE_READY:
        if (proxy->legacy) {
            DBG("write to non-legacy register (0x%lx) in "
                "legacy mode\n", offset);
            return;
        }
        /* TODO: To be implemented */
        break;
    case VIRTIO_MMIO_QUEUE_NOTIFY:
        DBG("VIRTIO_MMIO_QUEUE_NOTIFY: vq_index -> %d, notify_cnt: %d\n",
            value, notify_cnt++);
        if (value < VIRTIO_QUEUE_MAX) {
            virtio_queue_notify(vdev, value);
        }
        break;
    case VIRTIO_MMIO_INTERRUPT_ACK:
        vdev->isr = vdev->isr & ~value;
        virtio_update_irq(vdev);
        break;
    case VIRTIO_MMIO_STATUS:

        /*
         * TODO: Add it in a future release later
         *
         * if (!(value & VIRTIO_CONFIG_S_DRIVER_OK)) {
         *     virtio_loopback_stop_ioeventfd(proxy);
         * }
         */

        if (!proxy->legacy && (value & VIRTIO_CONFIG_S_FEATURES_OK)) {
            virtio_set_features(vdev,
                                ((uint64_t)proxy->guest_features[1]) << 32 |
                                proxy->guest_features[0]);
        }

        virtio_set_status(vdev, value & 0xff);

        DBG("STATUS -> %ld\n", value);

        /*
         * TODO: Check if this is still needed
         *
         * if (vdev->status == 0) {
         *     virtio_reset(vdev);
         *     virtio_loopback_soft_reset(proxy);
         * }
         */

        break;
    case VIRTIO_MMIO_QUEUE_DESC_LOW:
        if (proxy->legacy) {
            DBG("write to non-legacy register (0x%lx) in "
                "legacy mode\n", offset);
            return;
        }
        /* TODO: To be implemented */
        break;
    case VIRTIO_MMIO_QUEUE_DESC_HIGH:
        if (proxy->legacy) {
            DBG("write to non-legacy register (0x%lx) in "
                "legacy mode\n", offset);
            return;
        }
        /* TODO: To be implemented */
        break;
    case VIRTIO_MMIO_QUEUE_AVAIL_LOW:
        if (proxy->legacy) {
            DBG("write to non-legacy register (0x%lx) in "
                "legacy mode\n", offset);
            return;
        }
        /* TODO: To be implemented */
        break;
    case VIRTIO_MMIO_QUEUE_AVAIL_HIGH:
        if (proxy->legacy) {
            DBG("write to non-legacy register (0x%lx) in "
                "legacy mode\n", offset);
            return;
        }
        /* TODO: To be implemented */
        break;
    case VIRTIO_MMIO_QUEUE_USED_LOW:
        if (proxy->legacy) {
            DBG("write to non-legacy register (0x%lx) in "
                "legacy mode\n", offset);
            return;
        }
        /* TODO: To be implemented */
        break;
    case VIRTIO_MMIO_QUEUE_USED_HIGH:
        if (proxy->legacy) {
            DBG("write to non-legacy register (0x%lx) in "
                "legacy mode\n", offset);
            return;
        }
        /* TODO: To be implemented */
        break;
    case VIRTIO_MMIO_MAGIC_VALUE:
    case VIRTIO_MMIO_VERSION:
    case VIRTIO_MMIO_DEVICE_ID:
    case VIRTIO_MMIO_VENDOR_ID:
    case VIRTIO_MMIO_DEVICE_FEATURES:
    case VIRTIO_MMIO_QUEUE_NUM_MAX:
    case VIRTIO_MMIO_INTERRUPT_STATUS:
    case VIRTIO_MMIO_CONFIG_GENERATION:
        /* TODO: To be implemented */
        break;
    default:
        DBG("bad register offset (0x%lx)\n", offset);
    }
}

VirtIODevice *global_vdev;
VirtioBus *global_vbus;

void adapter_read_write_cb(void)
{
    /*
     * Enabling the next line, all the incoming
     * read/write events will be printed:
     *
     * print_neg_flag (address->notification, address->read);
     */
    print_neg_flag(address->notification, address->read);

    if (address->read) {
        address->data = virtio_loopback_read(global_vdev,
                                         address->notification, address->size);
    } else {
        virtio_loopback_write(global_vdev, address->notification,
                                       address->data, address->size);
    }

    DBG("Return to the driver\n");

    /*
     * Note the driver that we have done
     * All the required actions.
     */
    (void)ioctl(fd, WAKEUP);

}

void *driver_event_select(void *data)
{
    int retval;
    uint64_t eftd_ctr;
    int efd = *(int *)data;

    DBG("\nWaiting for loopback read/write events\n");

    FD_ZERO(&rfds);
    FD_SET(efd, &rfds);

    while (1) {

        retval = select(efd + 1, &rfds, NULL, NULL, NULL);

        if (retval == -1) {
            DBG("\nselect() error. Exiting...");
            exit(EXIT_FAILURE);
        } else if (retval > 0) {

            s = read(efd, &eftd_ctr, sizeof(uint64_t));
            if (s != sizeof(uint64_t)) {
                DBG("\neventfd read error. Exiting...");
                exit(1);
            } else {
                adapter_read_write_cb();
            }

        } else if (retval == 0) {
            DBG("\nselect() says that no data was available");
        }
    }
}

void create_rng_struct(void)
{
    device_info.magic = 0x74726976;
    device_info.version = 0x1;
    device_info.device_id = 0x4;
    device_info.vendor = 0x554d4551;
}

VirtQueue *virtio_get_queue(VirtIODevice *vdev, int n)
{
    return vdev->vq + n;
}

VirtQueue *virtio_add_queue(VirtIODevice *vdev, int queue_size,
                            VirtIOHandleOutput handle_output)
{
    int i;

    for (i = 0; i < VIRTIO_QUEUE_MAX; i++) {
        if (vdev->vq[i].vring.num == 0) {
            break;
        }
    }

    if (i == VIRTIO_QUEUE_MAX || queue_size > VIRTQUEUE_MAX_SIZE) {
        DBG("Error: queue_size > VIRTQUEUE_MAX_SIZE\n");
        exit(1);
    }

    vdev->vq[i].vring.num = queue_size;
    vdev->vq[i].vring.num_default = queue_size;
    vdev->vq[i].vring.align = VIRTIO_PCI_VRING_ALIGN;
    vdev->vq[i].handle_output = handle_output;
    vdev->vq[i].used_elems = (VirtQueueElement *)malloc(sizeof(VirtQueueElement)
                                                        * queue_size);

    return &vdev->vq[i];
}

void virtio_dev_init(VirtIODevice *vdev, const char *name,
                 uint16_t device_id, size_t config_size)
{
    int i;

    DBG("virtio_dev_init\n");

    /* Initialize global variables */
    prev_level = 0;
    int_count = 0;
    eventfd_count = 0;
    enable_virtio_interrupt = false;
    vring_phys_addrs_idx = 0;
    notify_cnt = 0;

    /* Initialize interrupt mutex */
    if (pthread_mutex_init(&interrupt_lock, NULL) != 0) {
        printf("[ERROR] mutex init has failed\n");
        exit(1);
    }

    vdev->start_on_kick = false;
    vdev->started = false;
    vdev->device_id = device_id;
    vdev->status = 0;
    vdev->queue_sel = 0;
    vdev->config_vector = VIRTIO_NO_VECTOR;
    /* TODO: check malloc return value */
    vdev->vq = (VirtQueue *) malloc(sizeof(VirtQueue) * VIRTIO_QUEUE_MAX);
    vdev->vm_running = false;
    vdev->broken = false;
    for (i = 0; i < VIRTIO_QUEUE_MAX; i++) {
        vdev->vq[i].vector = VIRTIO_NO_VECTOR;
        vdev->vq[i].vdev = vdev;
        vdev->vq[i].queue_index = i;
        vdev->vq[i].host_notifier_enabled = false;
    }

    vdev->name = name;
    vdev->config_len = config_size;
    if (vdev->config_len) {
        vdev->config = (void *) malloc(config_size);
    } else {
        vdev->config = NULL;
    }

    vdev->use_guest_notifier_mask = true;
    DBG("virtio_dev_init return\n");
}

static bool virtio_loopback_ioeventfd_enabled(VirtIODevice *d)
{
    return (proxy->flags & VIRTIO_IOMMIO_FLAG_USE_IOEVENTFD) != 0;
}

/* TODO: This function might not be needed anymore */
static int virtio_loopback_ioeventfd_assign(VirtIOMMIOProxy *d,
                                        EventNotifier *notifier,
                                        int n, bool assign)
{
    return 0;
}

bool virtio_bus_device_iommu_enabled(VirtIODevice *vdev)
{
    VirtioBus *k = vdev->vbus;

    if (!k->iommu_enabled) {
        return false;
    }

    return k->iommu_enabled(vdev);
}

void virtio_loopback_bus_init(VirtioBus *k)
{
    DBG("virtio_loopback_bus_init(...)\n");
    k->set_guest_notifiers = virtio_loopback_set_guest_notifiers;
    k->ioeventfd_enabled = virtio_loopback_ioeventfd_enabled;
    k->ioeventfd_assign = virtio_loopback_ioeventfd_assign;
    DBG("virtio_loopback_bus_init(...) return\n");
}


int virtio_loopback_start(void)
{
    efd_data_t info;
    pthread_t thread_id;
    int ret = -1;
    int flags;

    fd = open("/dev/loopback", O_RDWR);
    if (fd < 0) {
        perror("Open call failed");
        return -1;
    }
    loopback_fd = fd;

    /* Create eventfd */
    efd = eventfd(0, 0);
    if (efd == -1) {
        DBG("\nUnable to create eventfd! Exiting...\n");
        exit(EXIT_FAILURE);
    }

    info.pid = getpid();
    info.efd[0] = efd;

    /*
     * Send the appropriate information to the driver
     * so to be able to trigger an eventfd
     */
    (void)ioctl(fd, EFD_INIT, &info);

    /* Map communication mechanism */
    (void)ioctl(fd, SHARE_COM_STRUCT);
    address = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (address == MAP_FAILED) {
        perror("mmap operation failed");
        return -1;
    }

    /* Wait the eventfd */
    ret = pthread_create(&thread_id, NULL, driver_event_select, (void *)&efd);
    if (ret != 0) {
        exit(1);
    }

    /* Start loopback transport */
    (void)ioctl(fd, START_LOOPBACK, &device_info);

    ret = pthread_join(thread_id, NULL);
    if (ret != 0) {
        exit(1);
    }

    DBG("\nClosing eventfd. Exiting...\n");
    close(efd);

    exit(EXIT_SUCCESS);
}
