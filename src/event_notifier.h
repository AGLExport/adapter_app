/*
 * Based on event_notifier.h of QEMU project
 *
 *   Copyright Red Hat, Inc. 2010
 *
 *   Authors:
 *    Michael S. Tsirkin <mst@redhat.com>
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


#ifndef EVENT_NOT_H
#define EVENT_NOT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <poll.h>
#include <pthread.h>

typedef struct EventNotifier {
    int rfd;
    int wfd;
    bool initialized;
} EventNotifier;


int fcntl_setfl(int fd, int flag);
void qemu_set_cloexec(int fd);
int qemu_pipe(int pipefd[2]);
int event_notifier_get_fd(const EventNotifier *e);
int event_notifier_get_wfd(const EventNotifier *e);
int event_notifier_set(EventNotifier *e);
int event_notifier_init(EventNotifier *e, int active);
bool ioeventfd_enabled(void);
int event_notifier_test_and_clear(EventNotifier *e);


#endif /* EVENT_NOT_H */
