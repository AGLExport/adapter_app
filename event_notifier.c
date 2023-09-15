/*
 * Based on:
 *  1) file-posix.c of QEMU Project
 *
 *     Copyright (c) 2006 Fabrice Bellard
 *
 *  2) event_notifier-posix.c of QEMU Project
 *
 *     Copyright Red Hat, Inc. 2010
 *
 *     Authors:
 *      Michael S. Tsirkin <mst@redhat.com>
 *
 *  3) os-posix-lib.c of QEMU project
 *
 *     Copyright (c) 2003-2008 Fabrice Bellard
 *     Copyright (c) 2010 Red Hat, Inc.
 *
 * Copyright 2023 Virtual Open Systems SAS.
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
#include "vhost_user_loopback.h"


/* Sets a specific flag */
int fcntl_setfl(int fd, int flag)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        return -errno;
    }

    if (fcntl(fd, F_SETFL, flags | flag) == -1) {
        return -errno;
    }

    return 0;
}

void qemu_set_cloexec(int fd)
{
    int f;
    f = fcntl(fd, F_GETFD);
    f = fcntl(fd, F_SETFD, f | FD_CLOEXEC);
}

/*
 * Creates a pipe with FD_CLOEXEC set on both file descriptors
 */
int qemu_pipe(int pipefd[2])
{
    int ret;

#ifdef CONFIG_PIPE2
    ret = pipe2(pipefd, O_CLOEXEC);
    if (ret != -1 || errno != ENOSYS) {
        return ret;
    }
#endif
    ret = pipe(pipefd);
    if (ret == 0) {
        qemu_set_cloexec(pipefd[0]);
        qemu_set_cloexec(pipefd[1]);
    }

    return ret;
}

int event_notifier_get_fd(const EventNotifier *e)
{
    return e->rfd;
}

int event_notifier_get_wfd(const EventNotifier *e)
{
    return e->wfd;
}

int event_notifier_set(EventNotifier *e)
{
    static const uint64_t value = 1;
    ssize_t ret;

    if (!e->initialized) {
        return -1;
    }

    do {
        ret = write(e->wfd, &value, sizeof(value));
    } while (ret < 0 && errno == EINTR);

    /* EAGAIN is fine, a read must be pending.  */
    if (ret < 0 && errno != EAGAIN) {
        return -errno;
    }
    return 0;
}

int event_notifier_init(EventNotifier *e, int active)
{
    int fds[2];
    int ret;

    ret = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

    if (ret >= 0) {
        e->rfd = e->wfd = ret;
    } else {
        if (errno != ENOSYS) {
            return -errno;
        }
        if (qemu_pipe(fds) < 0) {
            return -errno;
        }
        ret = fcntl_setfl(fds[0], O_NONBLOCK);
        if (ret < 0) {
            ret = -errno;
            goto fail;
        }
        ret = fcntl_setfl(fds[1], O_NONBLOCK);
        if (ret < 0) {
            ret = -errno;
            goto fail;
        }
        e->rfd = fds[0];
        e->wfd = fds[1];
    }
    e->initialized = true;
    if (active) {
        event_notifier_set(e);
    }
    return 0;

fail:
    close(fds[0]);
    close(fds[1]);
    return ret;
}

bool ioeventfd_enabled(void)
{
    /*
     * TODO: Delete if not needed:
     * return !kvm_enabled() || kvm_eventfds_enabled();
     */
    return 1;
}

int event_notifier_test_and_clear(EventNotifier *e)
{
    int value;
    ssize_t len;
    char buffer[512];

    if (!e->initialized) {
        return 0;
    }

    /* Drain the notify pipe.  For eventfd, only 8 bytes will be read.  */
    value = 0;
    do {
        len = read(e->rfd, buffer, sizeof(buffer));
        value |= (len > 0);
    } while ((len == -1 && errno == EINTR) || len == sizeof(buffer));

    return value;
}
