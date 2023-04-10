/*
 * Copyright 2022 Virtual Open Systems SAS.
 *
 * Authors:
 *  Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
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
#include "virtio_rng.h"
#include "vhost_user_rng.h"
#include "vhost_user_blk.h"
#include "vhost_user_input.h"


#ifdef DEBUG
#define DBG(...) printf("adapter: " __VA_ARGS__)
#else
#define DBG(...)
#endif /* DEBUG */


/* Global variables */
int client_sock;
struct vhost_dev *dev;
struct adapter_dev *adev;
struct vhost_user *vudev;


void vhost_user_adapter_init(void)
{

    DBG("Setup adapter data structures\n");

    /* Init vhost-user device */
    vudev = (struct vhost_user *)malloc(sizeof(struct vhost_user));

    /* Init vhost device */
    dev = (struct vhost_dev *)malloc(sizeof(struct vhost_dev));

    /* Init virtio device */
    global_vdev = (VirtIODevice *)malloc(sizeof(VirtIODevice));

    /* Init virtio bus */
    global_vbus = (VirtioBus *)malloc(sizeof(VirtioBus));
    global_vbus->vdev = global_vdev;
    global_vdev->vbus = global_vbus;
    global_vdev->vhdev = dev;


    /* Store virtio_dev reference into vhost_dev struct*/
    dev->vdev = global_vdev;

    /* Init adapter device */
    adev = (struct adapter_dev *)malloc(sizeof(struct adapter_dev));
    adev->vdev = dev;
    adev->vudev = vudev;
    adev->virtio_dev = global_vdev;
    adev->vbus = global_vbus;
}


void client(char *sock_path)
{
    int rc, len;
    struct sockaddr_un client_sockaddr;

    DBG("Create shared socket with vhost-user-device\n");

    /* Initialize the struct to zero */
    memset(&client_sockaddr, 0, sizeof(struct sockaddr_un));

    /*
     * Create a UNIX socket
     */
    client_sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (client_sock == -1) {
        DBG("SOCKET ERROR\n");
        exit(1);
    }

    /*
     * Set up the UNIX sockaddr structure
     * by using AF_UNIX for the family and
     * giving it a filepath to connect.
     */
    client_sockaddr.sun_family = AF_UNIX;
    strcpy(client_sockaddr.sun_path, sock_path);
    len = sizeof(client_sockaddr);
    rc = connect(client_sock, (struct sockaddr *) &client_sockaddr, len);
    if (rc == -1) {
        printf("CONNECT ERROR: Check the \"-s\" parameter\n");
        close(client_sock);
        exit(1);
    }
}

static void help_args(void)
{
    printf("Run example:\n\t./adapter -s /path_to_socket/rng.sock\n"
           "\t\t  -d device_name\n"
           "\t\t  [ -qn number of queues ]\n"
           "\t\t  [ -qs size of queues ]\n"
           "The 'device_name' can be one of the following:\n"
           "\tvrng, vhurng, vhublk, vhuinput\n");
}

int find_arg(int argc, char **argv, char *str)
{
    int i;

    for (i = 0; i < argc; i++) {
        if (!strcmp(argv[i], str)) {
            return i + 1;
        }
    }
    return -1;
}

int val_device_arg(char *str)
{
    char *adapter_devices[] = {"vrng", "vhurng", "vhublk", "vhuinput"};
    char *vhu_devices[] = {"vhurng", "vhublk", "vhuinput"};
    int adapter_devices_num = 4, i;

    for (i = 0; i < adapter_devices_num; i++) {
        if (!strcmp(adapter_devices[i], str)) {
            return i + 1;
        }
    }

    return 0;
}

bool check_vhu_device(char *str)
{
    char *vhu_devices[] = {"vhurng", "vhublk", "vhuinput"};
    int vhu_devices_num = 3, i;

    for (i = 0; i < vhu_devices_num; i++) {
        if (!strcmp(vhu_devices[i], str)) {
            return true;
        }
    }

    return false;
}

void get_queue_num_size_args(int argc, char **argv,
                             int *eval_queue_num, int *eval_queue_size)
{
    int queue_num, queue_size, queue_num_id, queue_size_id;

    if (argc < 9) {
        return;
    }

    queue_num_id = find_arg(argc, argv, "-qn");
    queue_size_id = find_arg(argc, argv, "-qs");

    /* Check if both qs ans qn exist */
    if (queue_num_id < 0 || queue_size_id < 0) {
        return;
    }

    queue_num = atoi(argv[queue_num_id]);
    queue_size = atoi(argv[queue_size_id]);

    /* Evaluate number of queues */
    if (queue_num <= 0 || queue_num > 16) {
        return;
    }

    /* Evaluate queues' size */
    if (queue_size <= 0 || queue_size > 1024) {
        return;
    }

    *eval_queue_num = queue_num;
    *eval_queue_size = queue_size;
}


int main(int argc, char **argv)
{
    int socket_idx, device_idx, device_id;
    bool vhost_user_enabled;
    /* Assign default queue num and size */
    int queue_num = 1, queue_size = 1024;

    /*
     * Check if the user has provided all the required arguments.
     * If not, print the help messages.
     */

    if (argc < 5) {
        goto error_args;
    }

    device_idx = find_arg(argc, argv, "-d");

    if (device_idx < 0) {
        printf("You have not specified parameter \"-d\"\n");
        goto error_args;
    }

    /* Validate the argumetns */
    device_id = val_device_arg(argv[device_idx]);

    if (device_id == 0) {
        goto error_args;
    }

    /* Check if this is a vhost-user device */
    vhost_user_enabled = check_vhu_device(argv[device_idx]);


    /* Check if a socket is needed and provided */

    socket_idx = find_arg(argc, argv, "-s");

    if ((socket_idx  < 0) && (vhost_user_enabled)) {
        printf("You have not specified parameter \"-s\"\n");
        goto error_args;
    }

    /*
     * Create the socket and connect to the backend.
     * Enabled on vhost-user case
     */
    if (vhost_user_enabled) {
        client(argv[socket_idx]);
    }

    /* Initialize the adapter data structures */
    vhost_user_adapter_init();


    /* Initialize the virtio/vhost-user device */
    switch (device_id) {
    case 1:
        virtio_rng_realize();
        break;
    case 2:
        vhost_user_rng_realize();
        break;
    case 3:
        get_queue_num_size_args(argc, argv, &queue_num, &queue_size);
        printf("Running vhublk with num %d and size %d\n",
                                            queue_num, queue_size);
        vhost_user_blk_realize(queue_num, queue_size);
        break;
    case 4:
        vhost_user_input_init(global_vdev);
        virtio_input_device_realize();
        break;
    default:
        exit(1);
    }

    /*
     * Start loopback trasnport layer and communiation with the loopback driver
     */
    virtio_loopback_start();

    return 0;

error_args:
    help_args();
    return 1;
}
