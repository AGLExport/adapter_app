/*
 * Based on libvhost-user.c of Qemu project
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
    return vhost_user_set_u64(VHOST_USER_SET_FEATURES, features,
                              log_enabled);
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
    /* TODO: Add a assert to check the requested index
     *
     * assert(idx >= dev->vq_index && idx < dev->vq_index + (int)dev->nvqs);
     */
    return idx;
}

void vhost_user_share_fd(void)
{
    size_t fd_num = 1;
    VhostUserMsg msg = {
        .request = (VhostUserRequest) VHOST_USER_SHARE_LOOPBACK_FD,
        .flags = VHOST_USER_VERSION,
        .payload.u64 = ((uint64_t)getpid() << 32) | (uint64_t)loopback_fd,
        .size = sizeof(msg.payload.u64),
    };

    msg.fd_num = 1;
    memcpy(msg.fds, &loopback_fd, fd_num * sizeof(int));

    /* TODO: Check if we need to remove the VHOST_USER_NEED_REPLY_MASK flag
     *
     * msg.flags &= ~VHOST_USER_NEED_REPLY_MASK;
     */

    (void)vu_message_write(client_sock, &msg);
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

    /* TODO: Check if we need to remove the VHOST_USER_NEED_REPLY_MASK flag
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
    return vhost_set_vring_file(VHOST_USER_SET_VRING_KICK, file);
}

int vhost_user_set_vring_call(struct vhost_vring_file *file)
{
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

    //ret = vhost_user_write(dev, &msg, NULL, 0);
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


/* -------------------- Vring functions -------------------- */

/* TODO: This funciton might be implemented in a later release */
static int vhost_user_set_mem_table_postcopy(struct vhost_dev *dev,
                                             bool reply_supported,
                                             bool config_mem_slots)
{
    return 0;
}


/* TODO: This function is not yet fully optimized because in the current release
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

    return 0;
}

/* ----------------- End of Vring functions ---------------- */

int vhost_user_backend_init(struct vhost_dev *vhdev)
{
    uint64_t features, protocol_features, ram_slots;
    int err;

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

        /* TODO: Disable config bit for the rng, this might be usefull
         *       when new devices are added*/
        vhdev->protocol_features &= ~(1ULL << VHOST_USER_PROTOCOL_F_CONFIG);

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

    /* TODO: We might need to set up a postcopy_notifier in a future release:
     *
     * u->postcopy_notifier.notify = vhost_user_postcopy_notifier;
     * postcopy_add_notifier(&u->postcopy_notifier);
     */

    return 0;
}


void vhost_dev_init(struct vhost_dev *vhdev) {

    uint64_t features;
    int r, n_initialized_vqs = 0;
    unsigned int i;

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

    for (i = 0; i < vhdev->nvqs; ++i, ++n_initialized_vqs) {
        r = vhost_virtqueue_init(vhdev, vhdev->vqs + i, vhdev->vq_index + i);
        if (r < 0) {
            DBG("Failed to initialize virtqueue %d", i);
        }
    }

    /* TODO: busyloop == 0 in rng case, but we might need it for new devices:
     *
     * if (busyloop_timeout) {
     *     for (i = 0; i < dev->nvqs; ++i) {
     *         r = vhost_virtqueue_set_busyloop_timeout(dev, dev->vq_index + i,
     *                                                  busyloop_timeout);
     *         if (r < 0) {
     *             DBG("Failed to set busyloop timeout\n");
     *             //goto fail_busyloop;
     *         }
     *     }
     * }
     */

    vhdev->features = features;
}
