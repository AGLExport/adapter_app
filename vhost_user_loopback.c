/*
 * Based on libvhost-user.c of QEMU project
 *
 *   Copyright IBM, Corp. 2007
 *   Copyright (c) 2016 Red Hat, Inc.
 *
 *   Authors:
 *    Anthony Liguori <aliguori@us.ibm.com>
 *    Marc-André Lureau <mlureau@redhat.com>
 *    Victor Kaplansky <victork@redhat.com>
 *
 * Copyright 2022 Virtual Open Systems SAS.
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
#include "vhost_loopback.h"
#include "event_notifier.h"

#ifdef DEBUG
#define DBG(...) printf("vhost-user-loopback: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */


bool vhost_user_one_time_request(VhostUserRequest request)
{
    switch (request) {
    case VHOST_USER_SET_OWNER:
    case VHOST_USER_RESET_OWNER:
    case VHOST_USER_SET_MEM_TABLE:
    case VHOST_USER_GET_QUEUE_NUM:
    case VHOST_USER_NET_SET_MTU:
        return true;
    default:
        return false;
    }
}


void vmsg_close_fds(VhostUserMsg *vmsg)
{
    int i;

    for (i = 0; i < vmsg->fd_num; i++) {
        close(vmsg->fds[i]);
    }
}


bool vu_message_write(int conn_fd, VhostUserMsg *vmsg)
{
    int rc;
    uint8_t *p = (uint8_t *)vmsg;
    size_t fdsize;
    char control[CMSG_SPACE(VHOST_MEMORY_BASELINE_NREGIONS * sizeof(int))] = {};
    struct iovec iov = {
        .iov_base = (char *)vmsg,
        .iov_len = VHOST_USER_HDR_SIZE,
    };

    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
    };
    struct cmsghdr *cmsg;

    if (vhost_user_one_time_request(vmsg->request) && dev->vq_index != 0) {
        vmsg->flags &= ~VHOST_USER_NEED_REPLY_MASK;
        return 0;
    }

    memset(control, 0, sizeof(control));
    if (vmsg->fd_num > 0) {
        fdsize = vmsg->fd_num * sizeof(int);
        msg.msg_controllen = CMSG_SPACE(fdsize);
        cmsg = CMSG_FIRSTHDR(&msg);
        cmsg->cmsg_len = CMSG_LEN(fdsize);
        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        memcpy(CMSG_DATA(cmsg), vmsg->fds, fdsize);
    } else {
        msg.msg_controllen = 0;
    }

    do {
        rc = sendmsg(conn_fd, &msg, 0);
    } while (rc < 0 && (errno == EINTR || errno == EAGAIN));

    if (vmsg->size) {
        do {
            if (vmsg->data) {
                rc = write(conn_fd, vmsg->data, vmsg->size);
            } else {
                rc = write(conn_fd, p + VHOST_USER_HDR_SIZE, vmsg->size);
            }
        } while (rc < 0 && (errno == EINTR || errno == EAGAIN));
    }

    if (rc <= 0) {
        DBG("Error while writing\n");
        return false;
    }

    return true;
}


bool vu_message_read(int conn_fd, VhostUserMsg *vmsg)
{
    char control[CMSG_SPACE(VHOST_MEMORY_BASELINE_NREGIONS * sizeof(int))] = {};
    struct iovec iov = {
        .iov_base = (char *)vmsg,
        .iov_len = VHOST_USER_HDR_SIZE,
    };
    struct msghdr msg = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = control,
        .msg_controllen = sizeof(control),
    };
    size_t fd_size;
    struct cmsghdr *cmsg;
    int rc;

    do {
        rc = recvmsg(conn_fd, &msg, 0);
    } while (rc < 0 && (errno == EINTR || errno == EAGAIN));

    if (rc < 0) {
        DBG("Error while recvmsg\n");
        return false;
    }

    vmsg->fd_num = 0;
    for (cmsg = CMSG_FIRSTHDR(&msg);
         cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg))
    {
        if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
            fd_size = cmsg->cmsg_len - CMSG_LEN(0);
            vmsg->fd_num = fd_size / sizeof(int);
            memcpy(vmsg->fds, CMSG_DATA(cmsg), fd_size);
            break;
        }
    }

    if (vmsg->size > sizeof(vmsg->payload)) {
        DBG(
                 "Error: too big message request: %d, size: vmsg->size: %u, "
                 "while sizeof(vmsg->payload) = %zu\n",
                 vmsg->request, vmsg->size, sizeof(vmsg->payload));
        goto fail;
    }

    if (vmsg->size) {
        do {
            rc = read(conn_fd, &vmsg->payload, vmsg->size);
        } while (rc < 0 && (errno == EINTR || errno == EAGAIN));

        if (rc <= 0) {
            DBG("Error while reading\n");
            goto fail;
        }
    }

    return true;

fail:
    vmsg_close_fds(vmsg);

    return false;
}

int vhost_user_set_owner(void)
{
    VhostUserMsg msg = {
        .request = VHOST_USER_SET_OWNER,
        .flags = VHOST_USER_VERSION,
    };

    return vu_message_write(client_sock, &msg);
}

int process_message_reply(const VhostUserMsg *msg)
{
    int ret;
    VhostUserMsg msg_reply;

    if ((msg->flags & VHOST_USER_NEED_REPLY_MASK) == 0) {
        DBG("Don't wait for any reply!\n");
        return 0;
    }

    ret = vu_message_read(client_sock, &msg_reply);
    if (ret < 0) {
        return ret;
    }

    if (msg_reply.request != msg->request) {
        DBG("Received unexpected msg type. "
                     "Expected %d received %d\n",
                     msg->request, msg_reply.request);
        return -EPROTO;
    }

    return msg_reply.payload.u64 ? -EIO : 0;
}

int vhost_user_get_u64(int request, uint64_t *u64)
{
    int ret;
    VhostUserMsg msg = {
        .request = request,
        .flags = VHOST_USER_VERSION,
    };

    print_vhost_user_messages(request);

    if (vhost_user_one_time_request(request) && dev->vq_index != 0) {
        return 0;
    }

    ret = vu_message_write(client_sock, &msg);
    if (ret < 0) {
        return ret;
    }

    ret = vu_message_read(client_sock, &msg);
    if (ret < 0) {
        return ret;
    }

    if (msg.request != request) {
        DBG("Received unexpected msg type. Expected %d received %d\n",
                     request, msg.request);
        return -EPROTO;
    }

    if (msg.size != sizeof(msg.payload.u64)) {
        DBG("Received bad msg size.\n");
        return -EPROTO;
    }

    *u64 = msg.payload.u64;
    DBG("\tGet value: 0x%lx\n", msg.payload.u64);

    return 0;
}


int vhost_user_get_features(uint64_t *features)
{
    if (vhost_user_get_u64(VHOST_USER_GET_FEATURES, features) < 0) {
        return -EPROTO;
    }

    return 0;
}

int enforce_reply(const VhostUserMsg *msg)
{
    uint64_t dummy;

    if (msg->flags & VHOST_USER_NEED_REPLY_MASK) {
        return process_message_reply(msg);
    }

   /*
    * We need to wait for a reply but the backend does not
    * support replies for the command we just sent.
    * Send VHOST_USER_GET_FEATURES which makes all backends
    * send a reply.
    */
    return vhost_user_get_features(&dummy);
}

int vhost_user_set_u64(int request, uint64_t u64, bool wait_for_reply)
{
    VhostUserMsg msg = {
        .request = request,
        .flags = VHOST_USER_VERSION,
        .payload.u64 = u64,
        .size = sizeof(msg.payload.u64),
    };
    int ret;

    print_vhost_user_messages(request);
    DBG("\tSet value: 0x%lx\n", u64);

    if (wait_for_reply) {
        bool reply_supported = virtio_has_feature(dev->protocol_features,
                                          VHOST_USER_PROTOCOL_F_REPLY_ACK);

        if (reply_supported) {
            msg.flags |= VHOST_USER_NEED_REPLY_MASK;
        }
    }

    ret = vu_message_write(client_sock, &msg);
    if (ret < 0) {
        return ret;
    }

    if (wait_for_reply) {
        return enforce_reply(&msg);
    }

    return 0;
}

int vhost_user_set_features(struct vhost_dev *dev,
                                   uint64_t features)
{
    /*
     * wait for a reply if logging is enabled to make sure
     * backend is actually logging changes
     */
    bool log_enabled = features & (0x1ULL << VHOST_F_LOG_ALL);

    (void) dev;

    /* Pass hdev as parameter! */
    DBG("vhost_user_set_features: 0x%lx\n", features | dev->backend_features);
    return vhost_user_set_u64(VHOST_USER_SET_FEATURES,
                              features | dev->backend_features, log_enabled);
}

int vhost_user_set_protocol_features(uint64_t features)
{
    return vhost_user_set_u64(VHOST_USER_SET_PROTOCOL_FEATURES, features,
                              false);
}

int vhost_user_get_max_memslots(uint64_t *max_memslots)
{
    uint64_t backend_max_memslots;
    int err;

    err = vhost_user_get_u64(VHOST_USER_GET_MAX_MEM_SLOTS,
                             &backend_max_memslots);
    if (err < 0) {
        return err;
    }

    *max_memslots = backend_max_memslots;

    return 0;
}



int vhost_setup_slave_channel(struct vhost_dev *dev)
{
    VhostUserMsg msg = {
        .request = VHOST_USER_SET_SLAVE_REQ_FD,
        .flags = VHOST_USER_VERSION,
    };
    int sv[2], ret = 0;
    bool reply_supported = virtio_has_feature(dev->protocol_features,
                                              VHOST_USER_PROTOCOL_F_REPLY_ACK);

    if (!virtio_has_feature(dev->protocol_features,
                            VHOST_USER_PROTOCOL_F_SLAVE_REQ)) {
        return 0;
    }

    if (socketpair(PF_UNIX, SOCK_STREAM, 0, sv) == -1) {
        int saved_errno = errno;
        DBG("socketpair() failed\n");
        return -saved_errno;
    }

    memcpy(msg.fds, &sv[1], sizeof(int));
    msg.fd_num = 1;


    /* FIXME: something missing here */


    if (reply_supported) {
        msg.flags |= VHOST_USER_NEED_REPLY_MASK;
    }

    ret = vu_message_write(client_sock, &msg);
    if (!ret) {
        DBG("Go out\n");
        goto out;
    }

    if (reply_supported) {
        ret = process_message_reply(&msg);
        DBG("Reply is done!\n");
    }

out:
    /* TODO: Close slave channel and fd in case of error */
    /*
     * close(sv[1]);
     * if (ret) {
     *     close_slave_channel(u);
     * }
     */

    return ret;
}


int vhost_user_get_vq_index(struct vhost_dev *dev, int idx)
{
    /*
     * TODO: Add a assert to check the requested index
     *
     * assert(idx >= dev->vq_index && idx < dev->vq_index + (int)dev->nvqs);
     */
    return idx;
}

int vhost_set_vring_file(VhostUserRequest request,
                                struct vhost_vring_file *file)
{
    int fds[VHOST_USER_MAX_RAM_SLOTS];
    size_t fd_num = 0;
    VhostUserMsg msg = {
        .request = request,
        .flags = VHOST_USER_VERSION,
        .payload.u64 = file->index & VHOST_USER_VRING_IDX_MASK,
        .size = sizeof(msg.payload.u64),
    };

    if (ioeventfd_enabled() && file->fd > 0) {
        fds[fd_num++] = file->fd;
    } else {
        msg.payload.u64 |= VHOST_USER_VRING_NOFD_MASK;
    }

    /*
     * TODO: Check if we need to remove the VHOST_USER_NEED_REPLY_MASK flag
     *
     * msg.flags &= ~VHOST_USER_NEED_REPLY_MASK;
     */

    (void)fds;
    (void)fd_num;

    msg.fd_num = fd_num;
    memcpy(msg.fds, &fds, fd_num * sizeof(int));

    return !vu_message_write(client_sock, &msg);
}

int vhost_user_set_vring_kick(struct vhost_vring_file *file)
{
    DBG("Call vhost_user_set_vring_kick()\n");
    return vhost_set_vring_file(VHOST_USER_SET_VRING_KICK, file);
}

int vhost_user_set_vring_call(struct vhost_vring_file *file)
{
    DBG("Call vhost_user_set_vring_call()\n");
    return vhost_set_vring_file(VHOST_USER_SET_VRING_CALL, file);
}

static int vhost_set_vring(struct vhost_dev *dev,
                           unsigned long int request,
                           struct vhost_vring_state *ring)
{
    VhostUserMsg msg = {
        .request = request,
        .flags = VHOST_USER_VERSION,
        .payload.state = *ring,
        .size = sizeof(msg.payload.state),
    };

    return !vu_message_write(client_sock, &msg);
}

int vhost_user_set_vring_num(struct vhost_dev *dev,
                                    struct vhost_vring_state *ring)
{
    return vhost_set_vring(dev, VHOST_USER_SET_VRING_NUM, ring);
}

int vhost_user_set_vring_base(struct vhost_dev *dev,
                                     struct vhost_vring_state *ring)
{
    return vhost_set_vring(dev, VHOST_USER_SET_VRING_BASE, ring);
}


int vhost_user_set_vring_addr(struct vhost_dev *dev,
                                     struct vhost_vring_addr *addr)
{
    int ret;
    VhostUserMsg msg = {
        .request = VHOST_USER_SET_VRING_ADDR,
        .flags = VHOST_USER_VERSION,
        .payload.addr = *addr,
        .size = sizeof(msg.payload.addr),
    };

    bool reply_supported = virtio_has_feature(dev->protocol_features,
                                              VHOST_USER_PROTOCOL_F_REPLY_ACK);

    /*
     * wait for a reply if logging is enabled to make sure
     * backend is actually logging changes
     */
    bool wait_for_reply = addr->flags & (1 << VHOST_VRING_F_LOG);

    if (reply_supported && wait_for_reply) {
        msg.flags |= VHOST_USER_NEED_REPLY_MASK;
    }

    ret = vu_message_write(client_sock, &msg);
    if (ret < 0) {
        DBG("Fail vhost_user_set_vring_addr\n");
        return ret;
    }

    if (wait_for_reply) {
        return enforce_reply(&msg);
    }

    return 0;
}


int vhost_virtqueue_init(struct vhost_dev *dev,
                         struct vhost_virtqueue *vq, int n)
{
    int vhost_vq_index = (int)vhost_user_get_vq_index(dev, n);

    struct vhost_vring_file file = {
        .index = vhost_vq_index,
    };

    int r = event_notifier_init(&vq->masked_notifier, 0);
    if (r < 0) {
        return r;
    }

    file.fd = event_notifier_get_wfd(&vq->masked_notifier);

    r = vhost_user_set_vring_call(&file);
    if (r) {
        DBG("vhost_set_vring_call failed\n");
        return r;
    }

    vq->dev = dev;

    return 0;
}

int vhost_user_get_config(struct vhost_dev *dev, uint8_t *config,
                          uint32_t config_len)
{
    int ret;
    VhostUserMsg msg = {
        .request = VHOST_USER_GET_CONFIG,
        .flags = VHOST_USER_VERSION,
        .size = VHOST_USER_CONFIG_HDR_SIZE + config_len,
    };

    DBG("dev->protocol_features: 0x%lx\n", dev->protocol_features);
    DBG("VHOST_USER_PROTOCOL_F_CONFIG: 0x%x\n", VHOST_USER_PROTOCOL_F_CONFIG);

    if (!virtio_has_feature(dev->protocol_features,
                VHOST_USER_PROTOCOL_F_CONFIG)) {
        DBG("VHOST_USER_PROTOCOL_F_CONFIG not supported\n");
        return -1;
    }

    msg.payload.config.offset = 0;
    msg.payload.config.size = config_len;
    ret = vu_message_write(client_sock, &msg);
    DBG("vu_message_write return: %d\n", ret);
    if (ret < 0) {
        DBG("vhost_get_config failed\n");
        return -1;
    }

    ret = vu_message_read(client_sock, &msg);
    if (ret < 0) {
        DBG("vhost_get_config failed\n");
        return -1;
    }

    if (msg.request != VHOST_USER_GET_CONFIG) {
        DBG("Received unexpected msg type. Expected %d received %d",
            VHOST_USER_GET_CONFIG, msg.request);
        return -1;
    }

    if (msg.size != VHOST_USER_CONFIG_HDR_SIZE + config_len) {
        DBG("Received bad msg size.\n");
        return -1;
    }

    memcpy(config, msg.payload.config.region, config_len);

    DBG("Received config: %u, config_len: %u\n", *config, config_len);

    DBG("vhost_user_get_config return successfully\n");

    return 0;
}

int vhost_user_set_config(struct vhost_dev *dev, const uint8_t *data,
                          uint32_t offset, uint32_t size, uint32_t flags)
{
    int ret;
    uint8_t *p;
    bool reply_supported = virtio_has_feature(dev->protocol_features,
                                              VHOST_USER_PROTOCOL_F_REPLY_ACK);

    VhostUserMsg msg = {
        .request = VHOST_USER_SET_CONFIG,
        .flags = VHOST_USER_VERSION,
        .size = VHOST_USER_CONFIG_HDR_SIZE + size,
    };

    if (!virtio_has_feature(dev->protocol_features,
                VHOST_USER_PROTOCOL_F_CONFIG)) {
        DBG("VHOST_USER_PROTOCOL_F_CONFIG not supported\n");
        return -ENOTSUP;
    }

    if (reply_supported) {
        msg.flags |= VHOST_USER_NEED_REPLY_MASK;
    }

    if (size > VHOST_USER_MAX_CONFIG_SIZE) {
        return -EINVAL;
    }

    msg.payload.config.offset = offset,
    msg.payload.config.size = size,
    msg.payload.config.flags = flags,
    p = msg.payload.config.region;
    memcpy(p, data, size);

    ret = vu_message_write(client_sock, &msg);
    DBG("vu_message_write return: %d\n", ret);
    if (ret < 0) {
        return ret;
    }

    if (reply_supported) {
        return process_message_reply(&msg);
        DBG("Reply is done!\n");
    }

    return 0;
}


int vhost_user_get_inflight_fd(struct vhost_dev *dev,
                               uint16_t queue_size,
                               struct vhost_inflight *inflight)
{
    void *addr;
    int fd;
    int ret;
    VhostUserMsg msg = {
        .request = VHOST_USER_GET_INFLIGHT_FD,
        .flags = VHOST_USER_VERSION,
        .payload.inflight.num_queues = dev->nvqs,
        .payload.inflight.queue_size = queue_size,
        .size = sizeof(msg.payload.inflight),
    };

    DBG("vhost_user_get_inflight_fd\n");

    if (!virtio_has_feature(dev->protocol_features,
                            VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD)) {
        return 0;
    }

    /* NOTE: This stays here as a reference */
    ret = vu_message_write(client_sock, &msg);
    if (ret < 0) {
        DBG("vhost_user_get_inflight_fd\n\t->write error\n");
        return ret;
    }

    /* NOTE: This stays here as a reference */
    ret = vu_message_read(client_sock, &msg);
    if (ret < 0) {
        DBG("vhost_user_get_inflight_fd\n\t->read error\n");
        return ret;
    }

    if (msg.request != VHOST_USER_GET_INFLIGHT_FD) {
        DBG("Received unexpected msg type. "
            "Expected %d received %d\n",
            VHOST_USER_GET_INFLIGHT_FD, msg.request);
        return -1;
    }

    if (msg.size != sizeof(msg.payload.inflight)) {
        DBG("Received bad msg size.\n");
        return -1;
    }

    if (!msg.payload.inflight.mmap_size) {
        DBG("!msg.payload.inflight.mmap_size\n");
        return 0;
    }

    /* FIXME: This needs to be checked */
    memcpy(&fd, msg.fds, sizeof(int));
    if (fd < 0) {
        DBG("Failed to get mem fd\n");
        return -1;
    }

    addr = mmap(0, msg.payload.inflight.mmap_size, PROT_READ | PROT_WRITE,
                MAP_SHARED, fd, msg.payload.inflight.mmap_offset);

    if (addr == MAP_FAILED) {
        DBG("Failed to mmap mem fd\n");
        close(fd);
        return -1;
    }

    inflight->addr = addr;
    inflight->fd = fd;
    inflight->size = msg.payload.inflight.mmap_size;
    inflight->offset = msg.payload.inflight.mmap_offset;
    inflight->queue_size = queue_size;

    return 0;
}


int vhost_user_set_inflight_fd(struct vhost_dev *dev,
                               struct vhost_inflight *inflight)
{
    VhostUserMsg msg = {
        .request = VHOST_USER_SET_INFLIGHT_FD,
        .flags = VHOST_USER_VERSION,
        .payload.inflight.mmap_size = inflight->size,
        .payload.inflight.mmap_offset = inflight->offset,
        .payload.inflight.num_queues = dev->nvqs,
        .payload.inflight.queue_size = inflight->queue_size,
        .size = sizeof(msg.payload.inflight),
    };

    DBG("vhost_user_set_inflight_fd\n");

    if (!virtio_has_feature(dev->protocol_features,
                            VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD)) {
        return 0;
    }

    msg.fd_num = 1;
    memcpy(msg.fds, &inflight->fd, msg.fd_num * sizeof(int));

    return !vu_message_write(client_sock, &msg); /* Returns true or false*/
}


/* -------------------- Mem regions functions -------------------- */


static MemoryRegion *vhost_user_get_mr_data(struct vhost_memory_region *reg,
                                            ram_addr_t *offset, int *fd)
{
    MemoryRegion *mr;

    *offset = 0;
    *fd = loopback_fd;

    return mr;
}

static void vhost_user_fill_msg_region(VhostUserMemoryRegion *dst,
                                       struct vhost_memory_region *src,
                                       uint64_t mmap_offset)
{
    assert(src != NULL && dst != NULL);
    dst->userspace_addr = src->userspace_addr;
    dst->memory_size = src->memory_size;
    dst->guest_phys_addr = src->guest_phys_addr;
    dst->mmap_offset = mmap_offset;
}

static int vhost_user_fill_set_mem_table_msg(struct vhost_user *u,
                                             struct vhost_dev *dev,
                                             VhostUserMsg *msg,
                                             int *fds, size_t *fd_num,
                                             bool track_ramblocks)
{
    int i, fd;
    ram_addr_t offset;
    MemoryRegion *mr;
    struct vhost_memory_region *reg;
    VhostUserMemoryRegion region_buffer;

    msg->request = VHOST_USER_SET_MEM_TABLE;

    for (i = 0; i < dev->mem->nregions; ++i) {
        reg = dev->mem->regions + i;

        mr = vhost_user_get_mr_data(reg, &offset, &fd);
        if (fd > 0) {
            if (track_ramblocks) {
                u->region_rb_offset[i] = offset;
                u->region_rb[i] = mr->ram_block;
            } else if (*fd_num == VHOST_MEMORY_BASELINE_NREGIONS) {
                DBG("Failed preparing vhost-user memory table msg: %d\n", *fd_num);
                return -1;
            }
            vhost_user_fill_msg_region(&region_buffer, reg, offset);
            msg->payload.memory.regions[*fd_num] = region_buffer;
            fds[(*fd_num)++] = fd;
        } else if (track_ramblocks) {
            u->region_rb_offset[i] = 0;
            u->region_rb[i] = NULL;
        }
    }

    msg->payload.memory.nregions = *fd_num;
    if (!*fd_num) {
        DBG("Failed initializing vhost-user memory map, "
            "consider using -object memory-backend-file share=on\n");
        return -1;
    }

    msg->size = sizeof(msg->payload.memory.nregions);
    msg->size += sizeof(msg->payload.memory.padding);
    msg->size += *fd_num * sizeof(VhostUserMemoryRegion);

    return 1;
}

static inline bool reg_equal(struct vhost_memory_region *shadow_reg,
                             struct vhost_memory_region *vdev_reg)
{
    return shadow_reg->guest_phys_addr == vdev_reg->guest_phys_addr &&
        shadow_reg->userspace_addr == vdev_reg->userspace_addr &&
        shadow_reg->memory_size == vdev_reg->memory_size;
}


/* Sync the two region lists (device / adapter) */
static void scrub_shadow_regions(struct vhost_dev *dev,
                                 struct scrub_regions *add_reg,
                                 int *nr_add_reg,
                                 struct scrub_regions *rem_reg,
                                 int *nr_rem_reg, uint64_t *shadow_pcb,
                                 bool track_ramblocks)
{
    struct vhost_user *u = adev->vudev;
    bool found[VHOST_USER_MAX_RAM_SLOTS] = {};
    struct vhost_memory_region *reg, *shadow_reg;
    int i, j, fd, add_idx = 0, rm_idx = 0, fd_num = 0;
    ram_addr_t offset;
    MemoryRegion *mr;
    bool matching;

    /*
     * Find memory regions present in our shadow state which are not in
     * the device's current memory state.
     *
     * Mark regions in both the shadow and device state as "found".
     */
    for (i = 0; i < u->num_shadow_regions; i++) {
        shadow_reg = &u->shadow_regions[i];
        matching = false;

        for (j = 0; j < dev->mem->nregions; j++) {
            reg = &dev->mem->regions[j];

            mr = vhost_user_get_mr_data(reg, &offset, &fd);

            if (reg_equal(shadow_reg, reg)) {
                matching = true;
                found[j] = true;
                break;
            }
        }

        /*
         * If the region was not found in the current device memory state
         * create an entry for it in the removed list.
         */
        if (!matching) {
            rem_reg[rm_idx].region = shadow_reg;
            rem_reg[rm_idx++].reg_idx = i;
        }
    }

    /*
     * For regions not marked "found", create entries in the added list.
     *
     * Note their indexes in the device memory state and the indexes of their
     * file descriptors.
     */

    DBG("For regions not marked 'found', create entries in the added list\n");
    DBG("dev->mem->nregions: %d\n", dev->mem->nregions);

    for (i = 0; i < dev->mem->nregions; i++) {

        reg = &dev->mem->regions[i];

        mr = vhost_user_get_mr_data(reg, &offset, &fd);

        /*
         * If the region was in both the shadow and device state we don't
         * need to send a VHOST_USER_ADD_MEM_REG message for it.
         */
        if (found[i]) {
            continue;
        }

        add_reg[add_idx].region = reg;
        add_reg[add_idx].reg_idx = i;
        add_reg[add_idx++].fd_idx = fd_num;

    }
    *nr_rem_reg = rm_idx;
    *nr_add_reg = add_idx;

    return;
}


static int send_remove_regions(struct vhost_dev *dev,
                               struct scrub_regions *remove_reg,
                               int nr_rem_reg, VhostUserMsg *msg,
                               bool reply_supported)
{
    struct vhost_user *u = adev->vudev;
    struct vhost_memory_region *shadow_reg;
    int i, fd, shadow_reg_idx, ret;
    ram_addr_t offset;
    VhostUserMemoryRegion region_buffer;

    /*
     * The regions in remove_reg appear in the same order they do in the
     * shadow table. Therefore we can minimize memory copies by iterating
     * through remove_reg backwards.
     */
    for (i = nr_rem_reg - 1; i >= 0; i--) {
        shadow_reg = remove_reg[i].region;
        shadow_reg_idx = remove_reg[i].reg_idx;

        DBG("Try to remove: 0x%llx\n", remove_reg[i].region->guest_phys_addr);

        (void)vhost_user_get_mr_data(shadow_reg, &offset, &fd);

        if (fd > 0) {
            msg->request = VHOST_USER_REM_MEM_REG;
            vhost_user_fill_msg_region(&region_buffer, shadow_reg, offset);
            msg->payload.memreg.region = region_buffer;

            msg->fd_num = 1;
            memcpy(msg->fds, &loopback_fd, sizeof(int));

            if (vu_message_write(client_sock, msg) < 0) {
                return -1;
            }

            if (reply_supported) {
                msg->flags |= VHOST_USER_NEED_REPLY_MASK;
                ret = process_message_reply(msg);

                /*
                 * TODO: For this release do not process the message:
                 * if (ret) {
                 *     return ret;
                 * }
                 */
            }
        }

    }

    return 0;
}

static int send_add_regions(struct vhost_dev *dev,
                            struct scrub_regions *add_reg, int nr_add_reg,
                            VhostUserMsg *msg, uint64_t *shadow_pcb,
                            bool reply_supported, bool track_ramblocks)
{
    struct vhost_user *u = adev->vudev;
    int i, fd, ret, reg_idx, reg_fd_idx;
    struct vhost_memory_region *reg;
    MemoryRegion *mr;
    ram_addr_t offset;
    VhostUserMsg msg_reply;
    VhostUserMemoryRegion region_buffer;

    for (i = 0; i < nr_add_reg; i++) {
        reg = add_reg[i].region;
        reg_idx = add_reg[i].reg_idx;
        reg_fd_idx = add_reg[i].fd_idx;

        DBG("Try to add: 0x%llx\n", add_reg[i].region->guest_phys_addr);

        mr = vhost_user_get_mr_data(reg, &offset, &fd);

        if (fd > 0) {

            msg->request = VHOST_USER_ADD_MEM_REG;
            vhost_user_fill_msg_region(&region_buffer, reg, offset);
            msg->payload.memreg.region = region_buffer;

            msg->fd_num = 1;
            memcpy(msg->fds, &loopback_fd, sizeof(int));

            if (vu_message_write(client_sock, msg) < 0) {
                DBG("send_add_regions -> write failed\n");
                return -1;
            }

            if (reply_supported) {
                msg->flags |= VHOST_USER_NEED_REPLY_MASK;
                ret = process_message_reply(msg);

                /*
                 * TODO: For this release do not process the message:
                 * if (ret) {
                 *     return ret;
                 * }
                 */
            }
        } else if (track_ramblocks) {
            u->region_rb_offset[reg_idx] = 0;
            u->region_rb[reg_idx] = NULL;
        }
    }

    return 0;
}

static int vhost_user_add_remove_regions(struct vhost_dev *dev,
                                         VhostUserMsg *msg,
                                         bool reply_supported,
                                         bool track_ramblocks)
{
    struct vhost_user *u = adev->vudev;
    struct scrub_regions add_reg[VHOST_USER_MAX_RAM_SLOTS];
    struct scrub_regions rem_reg[VHOST_USER_MAX_RAM_SLOTS];
    uint64_t shadow_pcb[VHOST_USER_MAX_RAM_SLOTS] = {};
    int nr_add_reg, nr_rem_reg;

    msg->size = sizeof(msg->payload.memreg);

    /* Find the regions which need to be removed or added. */
    scrub_shadow_regions(dev, add_reg, &nr_add_reg, rem_reg, &nr_rem_reg,
                         shadow_pcb, track_ramblocks);

    if (nr_rem_reg && send_remove_regions(dev, rem_reg, nr_rem_reg, msg,
                reply_supported) < 0)
    {
        DBG("send_remove_regions failed\n");
        goto err;
    }

    if (nr_add_reg && send_add_regions(dev, add_reg, nr_add_reg, msg,
                shadow_pcb, reply_supported, track_ramblocks) < 0)
    {
        DBG("send_add_regions failed\n");
        goto err;
    }


    /* TODO: At this point we need to update the shadow list */
    u->num_shadow_regions = dev->mem->nregions;
    memcpy(u->shadow_regions, dev->mem->regions,
                dev->mem->nregions * sizeof(struct vhost_memory_region));

    return 0;

err:
    DBG("vhost_user_add_remove_regions failed\n");
    return -1;
}


/* TODO: This funciton might be implemented in a later release */
static int vhost_user_set_mem_table_postcopy(struct vhost_dev *dev,
                                             bool reply_supported,
                                             bool config_mem_slots)
{
    DBG("vhost_user_set_mem_table_postcopy(...) not yet implemented\n");
    return 0;
}


/*
 * TODO: This function is not yet fully optimized because in the current release
 *  it is not used. t will be implemented or deleted in a later release.
 */
int vhost_user_set_mem_table(struct vhost_dev *dev)
{
    int fds[VHOST_MEMORY_BASELINE_NREGIONS];
    size_t fd_num = 0;
    bool reply_supported = virtio_has_feature(dev->protocol_features,
                                              VHOST_USER_PROTOCOL_F_REPLY_ACK);
    bool config_mem_slots =
        virtio_has_feature(dev->protocol_features,
                           VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS);
    int ret;
    struct vhost_user *u = adev->vudev;
    bool do_postcopy = false;

    if (do_postcopy) {
        /*
         * Postcopy has enough differences that it's best done in it's own
         * version
         */
        return vhost_user_set_mem_table_postcopy(dev, reply_supported,
                                                        config_mem_slots);
    }

    VhostUserMsg msg = {
        .flags = VHOST_USER_VERSION,
    };

    if (reply_supported) {
        msg.flags |= VHOST_USER_NEED_REPLY_MASK;
    }

    if (config_mem_slots) {
        DBG("vonfig_mem_slots is enabled\n");
        if (vhost_user_add_remove_regions(dev, &msg, reply_supported,
                                          false) < 0) {
            return -1;
        }
    } else {

        if (vhost_user_fill_set_mem_table_msg(u, dev, &msg, fds, &fd_num,
                                              false) < 0) {
            DBG("vhost_user_fill_set_mem_table_msg error\n");
            return -1;
        }

        /* Update message parameters */
        DBG("\nfd_num: %d\n", fd_num);
        msg.fd_num = fd_num;
        memcpy(msg.fds, fds, fd_num * sizeof(int));

        if (vu_message_write(client_sock, &msg) < 0) {
            DBG("vhost_user_set_mem_table failed write msg\n");
            return -1;
        }

        if (reply_supported) {
            return process_message_reply(&msg);
        }
    }

    return 0;
}



void print_mem_table(struct vhost_dev *dev)
{
    struct vhost_memory_region *cur_vmr;
    int i;

    DBG("print_mem_table:\n");

    for (i = 0; i < dev->n_mem_sections; i++) {

        cur_vmr = dev->mem->regions + i;
        DBG("regions[%d]->guest_phys_addr: 0x%llx\n",
                                i, cur_vmr->guest_phys_addr);
        DBG("regions[%d]->memory_size: 0x%llu\n",
                                i, cur_vmr->memory_size);
        DBG("regions[%d]->userspace_addr: 0x%llx\n",
                                i, cur_vmr->userspace_addr);
        DBG("regions[%d]->flags_padding: 0x%llx\n",
                                i, cur_vmr->flags_padding);

    }
}

static void vhost_add_reg(struct vhost_dev *dev, uint64_t hpa, uint64_t len)
{
    size_t regions_size, old_regions_size;
    struct vhost_memory *temp_mem;
    struct vhost_memory_region *cur_vmr;

    DBG("vhost_add_reg (hpa: 0x%lx, len: %lu)\n", hpa, len);

    /* Rebuild the regions list from the new sections list */
    regions_size = offsetof(struct vhost_memory, regions) +
                       (dev->mem->nregions + 1) * sizeof dev->mem->regions[0];
    temp_mem = (struct vhost_memory *)malloc(regions_size);

    /* Copy the old mem structure */
    old_regions_size = offsetof(struct vhost_memory, regions) +
                       (dev->mem->nregions) * sizeof dev->mem->regions[0];
    memcpy(temp_mem, dev->mem, old_regions_size);

    /* Increase the regions' counter */
    temp_mem->nregions = dev->mem->nregions + 1;
    dev->n_mem_sections = temp_mem->nregions;

    /* Clear the previous structure */
    free(dev->mem);

    /* Point to the new one */
    dev->mem = temp_mem;

    /* Init the new region */
    cur_vmr = dev->mem->regions + (dev->mem->nregions - 1);
    cur_vmr->guest_phys_addr = hpa;
    cur_vmr->memory_size = len;
    cur_vmr->userspace_addr  = hpa;
    cur_vmr->flags_padding   = 0;
}

static bool find_reg(struct vhost_dev *dev, uint64_t hpa, uint64_t len)
{
    struct vhost_memory_region *cur_vmr;
    int i;

    DBG("Try to find hpa: 0x%lx\n", hpa);

    for (i = dev->nvqs; i < dev->n_mem_sections; i++) {

        cur_vmr = dev->mem->regions + i;
        if ((hpa >= cur_vmr->guest_phys_addr) &&
            ((hpa + len) <= (cur_vmr->guest_phys_addr
                             + cur_vmr->memory_size))) {
            DBG("Find region with hpa: 0x%llx, and len: %lld\n",
                    cur_vmr->guest_phys_addr, cur_vmr->memory_size);
            return true;
        }
    }

    DBG("Did not find region with hpa: 0x%lx\n", hpa);
    return false;
}

int last_avail = -1;

void find_add_new_reg(struct vhost_dev *dev)
{
    int sglist_elem_num;
    int i;

    DBG("Total nvqs: %d\n", dev->nvqs);
    for (int i = 0; i < dev->nvqs; i++) {

        VRing *vring = &dev->vdev->vq[i].vring;
        uint64_t vring_num = vring->num;

        DBG("For vq[%d]:\n", i);
        DBG("vqs[%u] hpa 0x%lx\n", i, vring_phys_addrs[i]);
        DBG("vq[%d].vring.num: %ld\n", i, vring_num);
        DBG("We got avail buf: %d\n",
                ((VRingAvail *)(dev->vdev->vq[i].vring.avail))->idx);

        int avail_diff = ((VRingAvail *)(dev->vdev->vq[i].vring.avail))->idx
                                                                - last_avail;

        for (int j = 0; j < vring_num; j++) {

            uint64_t desc_addr = dev->vdev->vq[i].vring.desc;
            VRingDesc desc_p = ((VRingDesc *)desc_addr)[j];
            uint64_t sg_addr = desc_p.addr;
            uint64_t sg_len = desc_p.len;

            if (desc_p.addr == 0) {
                sglist_elem_num = j;
                DBG("We got avail buf: %d\n",
                        ((VRingAvail *)(dev->vdev->vq[i].vring.avail))->idx);
                DBG("We got sglist_ele_num: %d\n", sglist_elem_num);
                break;
            }

            DBG("desc[%u] 0x%lx\n", j, desc_addr);
            DBG("desc[%u].addr 0x%lx\n", j, sg_addr);
            DBG("desc[%u].len 0x%lu\n", j, sg_len);
            DBG("desc[%u].flags 0x%u\n", j, desc_p.flags);

            if (!find_reg(dev, sg_addr, sg_len)) {
                vhost_add_reg(dev, sg_addr, sg_len);
            }

        }
        DBG("We got avail buf: %d\n",
                ((VRingAvail *)(dev->vdev->vq[i].vring.avail))->idx);

        last_avail = ((VRingAvail *)(dev->vdev->vq[i].vring.avail))->idx;
        sglist_elem_num = 3 * avail_diff;
    }
}

void vhost_commit_init_vqs(struct vhost_dev *dev)
{
    MemoryRegionSection *old_sections;
    int n_old_sections;
    uint64_t log_size;
    size_t regions_size;
    int r;
    int i;
    bool changed = false;
    int sglist_elem_num;

    dev->n_mem_sections = dev->nvqs;

    /* Rebuild the regions list from the new sections list */
    regions_size = offsetof(struct vhost_memory, regions) +
                       dev->n_mem_sections * sizeof dev->mem->regions[0];
    dev->mem = (struct vhost_memory *)malloc(regions_size);
    dev->mem->nregions = dev->n_mem_sections;

    for (i = 0; i < dev->nvqs; i++) {
        struct vhost_memory_region *cur_vmr = dev->mem->regions + i;

        cur_vmr->guest_phys_addr = vring_phys_addrs[i] << PAGE_SHIFT;
        cur_vmr->memory_size = get_vqs_max_size(global_vdev);
        cur_vmr->userspace_addr  = 0;
        cur_vmr->flags_padding   = 0;
    }
}

void vhost_commit_vqs(struct vhost_dev *dev)
{
    free(dev->mem);
    vhost_commit_init_vqs(dev);
    find_add_new_reg(dev);
}

void vhost_commit_mem_regions(struct vhost_dev *dev)
{
    uint64_t mmap_pa_req;
    int i;

    /* Create and add all ram memory regions */
    for (i = 0; i < VHOST_USER_MAX_RAM_SLOTS; i++) {

        /* Calculate new Physical Address */
        mmap_pa_req = INIT_PA + i * 1 * OFFSET_1GB;

        /* Add a new region */
        vhost_add_reg(dev, mmap_pa_req, 1 * OFFSET_1GB);
    }

   /* Send new region */
   if (vhost_user_set_mem_table(dev) < 0) {
        DBG("vhost_user_set_mem_table -> Error\n");
        exit(1);
   }
}

/* -------------------- End of Mem regions functions -------------------- */

int vhost_user_backend_init(struct vhost_dev *vhdev)
{
    uint64_t features, protocol_features, ram_slots;
    int err;

    DBG("vhost_user_backend_init (...)\n");

    err = vhost_user_get_features(&features);
    if (err < 0) {
        DBG("vhost_backend_init failed\n");
        return err;
    }

    if (virtio_has_feature(features, VHOST_USER_F_PROTOCOL_FEATURES)) {
        vhdev->backend_features |= 1ULL << VHOST_USER_F_PROTOCOL_FEATURES;

        err = vhost_user_get_u64(VHOST_USER_GET_PROTOCOL_FEATURES,
                                 &protocol_features);
        if (err < 0) {
            DBG("vhost_backend_init failed\n");
            return -EPROTO;
        }

        vhdev->protocol_features =
            protocol_features & VHOST_USER_PROTOCOL_FEATURE_MASK;

        /*
         * FIXME: Disable VHOST_USER_PROTOCOL_F_SLAVE_REQ for the moment
         * vhdev->protocol_features &=
         *         ~(1ULL << VHOST_USER_PROTOCOL_F_SLAVE_REQ);
         */

        /* FIXME: Disable VHOST_USER_GET_INFLIGHT_FD for the moment */
        vhdev->protocol_features &=
                ~(1ULL << VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD);

        if (!vhdev->config_ops ||
                !vhdev->config_ops->vhost_dev_config_notifier) {
            DBG("There is no config_ops or vhost_dev_config_notifier\n");
            /* Don't acknowledge CONFIG feature if device doesn't support it */
            dev->protocol_features &= ~(1ULL << VHOST_USER_PROTOCOL_F_CONFIG);
        } else if (!(protocol_features &
                    (1ULL << VHOST_USER_PROTOCOL_F_CONFIG))) {
            DBG("Device expects VHOST_USER_PROTOCOL_F_CONFIG "
                "but backend does not support it.\n");
            return -EINVAL;
        }

        err = vhost_user_set_protocol_features(vhdev->protocol_features);
        if (err < 0) {
            DBG("vhost_backend_init failed\n");
            return -EPROTO;
        }

        /* query the max queues we support if backend supports Multiple Queue */
        if (vhdev->protocol_features & (1ULL << VHOST_USER_PROTOCOL_F_MQ)) {
            err = vhost_user_get_u64(VHOST_USER_GET_QUEUE_NUM,
                                     &vhdev->max_queues);
            if (err < 0) {
                DBG("vhost_backend_init failed\n");
                return -EPROTO;
            }
        } else {
            vhdev->max_queues = 1;
        }

        if (vhdev->num_queues && vhdev->max_queues < vhdev->num_queues) {
            DBG("The maximum number of queues supported by the "
                       "backend is %ld\n", vhdev->max_queues);
            return -EINVAL;
        }

        if (virtio_has_feature(features, VIRTIO_F_IOMMU_PLATFORM) &&
                !(virtio_has_feature(vhdev->protocol_features,
                    VHOST_USER_PROTOCOL_F_SLAVE_REQ) &&
                 virtio_has_feature(vhdev->protocol_features,
                    VHOST_USER_PROTOCOL_F_REPLY_ACK))) {
                DBG("IOMMU support requires reply-ack and "
                       "slave-req protocol features.\n");
            return -EINVAL;
        }

        /* get max memory regions if backend supports configurable RAM slots */
        if (!virtio_has_feature(vhdev->protocol_features,
                                VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS)) {
            vhdev->memory_slots = VHOST_MEMORY_BASELINE_NREGIONS;
        } else {
            err = vhost_user_get_max_memslots(&ram_slots);
            if (err < 0) {
                DBG("vhost_backend_init failed\n");
                return -EPROTO;
            }

            if (ram_slots < vhdev->memory_slots) {
                DBG("The backend specified a max ram slots limit "
                       "of %ld, when the prior validated limit was "
                       "%ld. This limit should never decrease.\n", ram_slots,
                           vhdev->memory_slots);
                return -EINVAL;
            }

            vhdev->memory_slots = MIN(ram_slots, VHOST_USER_MAX_RAM_SLOTS);
        }
    }

    if (vhdev->migration_blocker == NULL &&
        !virtio_has_feature(vhdev->protocol_features,
                            VHOST_USER_PROTOCOL_F_LOG_SHMFD)) {
        DBG("Migration disabled: vhost-user backend lacks "
               "VHOST_USER_PROTOCOL_F_LOG_SHMFD feature.\n");
    }

    if (vhdev->vq_index == 0) {
        err = vhost_setup_slave_channel(vhdev);
        if (err < 0) {
            DBG("vhost_backend_init failed\n");
            return -EPROTO;
        }
    }

    /*
     * TODO: We might need to set up a postcopy_notifier in a future release:
     *
     * u->postcopy_notifier.notify = vhost_user_postcopy_notifier;
     * postcopy_add_notifier(&u->postcopy_notifier);
     */

    return 0;
}

/* TODO: Return an error code */
void vhost_dev_init(struct vhost_dev *vhdev)
{
    uint64_t features;
    int r, n_initialized_vqs = 0;
    unsigned int i;

    DBG("vhost_dev_init(...)\n");

    /* Vhost conf */
    vhdev->migration_blocker = NULL;

    (void)vhost_user_backend_init(vhdev);

    r = vhost_user_set_owner();
    if (r < 0) {
        DBG("vhost_set_owner failed\n");
    }

    r = vhost_user_get_features(&features);
    if (r < 0) {
        DBG("vhost_get_features failed\n");
    }
    DBG("Print vhost_dev_init->features: 0x%lx\n", features);


    for (i = 0; i < vhdev->nvqs; ++i, ++n_initialized_vqs) {
        r = vhost_virtqueue_init(vhdev, vhdev->vqs + i, vhdev->vq_index + i);
        if (r < 0) {
            DBG("Failed to initialize virtqueue %d", i);
        }
    }

    vhdev->mem = (struct vhost_memory *)malloc(sizeof(struct vhost_memory));
    vhdev->mem->nregions = 0;

    vhdev->n_mem_sections = 0;
    vhdev->mem_sections = NULL;
    vhdev->log = NULL;
    vhdev->log_size = 0;
    vhdev->log_enabled = false;
    vhdev->started = false;


    /*
     * TODO: busyloop == 0 in rng case, but we might need it for new devices:
     *
     * if (busyloop_timeout) {
     *     for (i = 0; i < dev->nvqs; ++i) {
     *         r = vhost_virtqueue_set_busyloop_timeout(dev, dev->vq_index + i,
     *                                                  busyloop_timeout);
     *         if (r < 0) {
     *             DBG("Failed to set busyloop timeout\n");
     *             return -1;
     *         }
     *     }
     * }
     */

    vhdev->features = features;
    DBG("vhdev->backend_features 0x%llx\n", vhdev->backend_features);
    DBG("vhdev->features 0x%llx\n", vhdev->features);
}

int vhost_user_set_vring_enable(struct vhost_dev *dev, int enable)
{
    int i;
    DBG("vhost_user_set_vring_enable not yet implemented\n");

    if (!virtio_has_feature(dev->features, VHOST_USER_F_PROTOCOL_FEATURES)) {
        DBG("Does not have VHOST_USER_F_PROTOCOL_FEATURES\n");
        return -EINVAL;
    }

    for (i = 0; i < dev->nvqs; ++i) {
        int ret;
        struct vhost_vring_state state = {
            .index = dev->vq_index + i,
            .num   = enable,
        };

        ret = vhost_set_vring(dev, VHOST_USER_SET_VRING_ENABLE, &state);
        if (ret < 0) {
            /*
             * Restoring the previous state is likely infeasible, as well as
             * proceeding regardless the error, so just bail out and hope for
             * the device-level recovery.
             */
            return ret;
        }
    }

    return 0;
}

static int vhost_user_set_status(struct vhost_dev *dev, uint8_t status)
{
    return vhost_user_set_u64(VHOST_USER_SET_STATUS, status, false);
}

static int vhost_user_get_status(struct vhost_dev *dev, uint8_t *status)
{
    uint64_t value;
    int ret;

    ret = vhost_user_get_u64(VHOST_USER_GET_STATUS, &value);
    if (ret < 0) {
        return ret;
    }
    *status = value;

    return 0;
}

static int vhost_user_add_status(struct vhost_dev *dev, uint8_t status)
{
    uint8_t s;
    int ret;

    ret = vhost_user_get_status(dev, &s);
    if (ret < 0) {
        return ret;
    }

    if ((s & status) == status) {
        return 0;
    }
    s |= status;

    return vhost_user_set_status(dev, s);
}

int vhost_user_dev_start(struct vhost_dev *dev, bool started)
{
    DBG("vhost_user_dev_start(...)\n");
    if (!virtio_has_feature(dev->protocol_features,
                            VHOST_USER_PROTOCOL_F_STATUS)) {
        DBG("VHOST_USER_PROTOCOL_F_STATUS not in features\n");
        return 0;
    }

    /* Set device status only for last queue pair */
    if (dev->vq_index + dev->nvqs != dev->vq_index_end) {
        return 0;
    }

    if (started) {
        return vhost_user_add_status(dev, VIRTIO_CONFIG_S_ACKNOWLEDGE |
                                          VIRTIO_CONFIG_S_DRIVER |
                                          VIRTIO_CONFIG_S_DRIVER_OK);
    } else {
        return 0;
    }
}

void print_vhost_user_messages(int request)
{
    switch (request) {
    case VHOST_USER_GET_FEATURES:
        DBG("VHOST_USER_GET_FEATURES\n");
        break;
    case VHOST_USER_SET_FEATURES:
        DBG("VHOST_USER_SET_FEATURES\n");
        break;
    case VHOST_USER_GET_PROTOCOL_FEATURES:
        DBG("VHOST_USER_GET_PROTOCOL_FEATURES\n");
        break;
    case VHOST_USER_SET_PROTOCOL_FEATURES:
        DBG("VHOST_USER_SET_PROTOCOL_FEATURES\n");
        break;
    case VHOST_USER_SET_OWNER:
        DBG("VHOST_USER_SET_OWNER\n");
        break;
    case VHOST_USER_RESET_OWNER:
        DBG("VHOST_USER_RESET_OWNER\n");
        break;
    case VHOST_USER_SET_MEM_TABLE:
        DBG("VHOST_USER_SET_MEM_TABLE\n");
        break;
    case VHOST_USER_SET_LOG_BASE:
        DBG("VHOST_USER_SET_LOG_BASE\n");
        break;
    case VHOST_USER_SET_LOG_FD:
        DBG("VHOST_USER_SET_LOG_FD\n");
        break;
    case VHOST_USER_SET_VRING_NUM:
        DBG("VHOST_USER_SET_VRING_NUM\n");
        break;
    case VHOST_USER_SET_VRING_ADDR:
        DBG("VHOST_USER_SET_VRING_ADDR\n");
        break;
    case VHOST_USER_SET_VRING_BASE:
        DBG("VHOST_USER_SET_VRING_BASE\n");
        break;
    case VHOST_USER_GET_VRING_BASE:
        DBG("VHOST_USER_GET_VRING_BASE\n");
        break;
    case VHOST_USER_SET_VRING_KICK:
        DBG("VHOST_USER_SET_VRING_KICK\n");
        break;
    case VHOST_USER_SET_VRING_CALL:
        DBG("VHOST_USER_SET_VRING_CALL\n");
        break;
    case VHOST_USER_SET_VRING_ERR:
        DBG("VHOST_USER_SET_VRING_ERR\n");
        break;
    case VHOST_USER_GET_QUEUE_NUM:
        DBG("VHOST_USER_GET_QUEUE_NUM\n");
        break;
    case VHOST_USER_SET_VRING_ENABLE:
        DBG("VHOST_USER_SET_VRING_ENABLE\n");
        break;
    case VHOST_USER_SET_SLAVE_REQ_FD:
        DBG("VHOST_USER_SET_SLAVE_REQ_FD\n");
        break;
    case VHOST_USER_GET_CONFIG:
        DBG("VHOST_USER_GET_CONFIG\n");
        break;
    case VHOST_USER_SET_CONFIG:
        DBG("VHOST_USER_SET_CONFIG\n");
        break;
    case VHOST_USER_NONE:
        DBG("VHOST_USER_NONE\n");
        break;
    case VHOST_USER_POSTCOPY_ADVISE:
        DBG("VHOST_USER_POSTCOPY_ADVISE\n");
        break;
    case VHOST_USER_POSTCOPY_LISTEN:
        DBG("VHOST_USER_POSTCOPY_LISTEN\n");
        break;
    case VHOST_USER_POSTCOPY_END:
        DBG("VHOST_USER_POSTCOPY_END\n");
        break;
    case VHOST_USER_GET_INFLIGHT_FD:
        DBG("VHOST_USER_GET_INFLIGHT_FD\n");
        break;
    case VHOST_USER_SET_INFLIGHT_FD:
        DBG("VHOST_USER_SET_INFLIGHT_FD\n");
        break;
    case VHOST_USER_VRING_KICK:
        DBG("VHOST_USER_VRING_KICK\n");
        break;
    case VHOST_USER_GET_MAX_MEM_SLOTS:
        DBG("VHOST_USER_GET_MAX_MEM_SLOTS\n");
        break;
    case VHOST_USER_ADD_MEM_REG:
        DBG("VHOST_USER_ADD_MEM_REG\n");
        break;
    case VHOST_USER_REM_MEM_REG:
        DBG("VHOST_USER_REM_MEM_REG\n");
        break;
    default:
        DBG("Unhandled request: %d\n", request);
    }
}
