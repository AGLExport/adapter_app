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
        DBG("CONNECT ERROR\n");
        close(client_sock);
        exit(1);
    }

}

static void help_args(void)
{
    printf("Run example:\n\t./adapter -s /path_to_socket/rng.sock\n");
}

int main(int argc, char **argv)
{
#ifdef VHOST_USER
    /*
     * Check if the user has provided a socket path.
     * If not, print the help messages.
     */
    if ((argc <= 2) || (strcmp(argv[1], "-s") != 0)) {
        goto error_args;
    }

    /*
     * Create the socket and connect to the backend.
     * Enabled on vhost-user case
     */
    client(argv[2]);
#endif

    /* Initialize the adapter data structures */
    vhost_user_adapter_init();


    /* Initialize the virtio/vhost-user device */
#ifdef VHOST_USER

#ifdef VHOST_USER_INPUT_DEV
    vhost_user_input_init(global_vdev); /* <-- Enable that for vhost-user-rng */
    virtio_input_device_realize();
#endif /* VHOST_USER_INPUT_DEV */

#ifdef VHOST_USER_BLK_DEV
    vhost_user_blk_realize(); /* <-- Enable that for vhost-user-blk */
#endif /* VHOST_USER_BLK_DEV */

#ifdef VHOST_USER_RNG_DEV
    vhost_user_rng_realize(); /* <-- Enable that for vhost-user-rng */
#endif /* VHOST_USER_RNG_DEV */

#else /* VHOST_USER */

#ifdef VIRTIO_RNG
    virtio_rng_realize(); /* <-- Enable that for simple rng */
#else /* VIRTIO_RNG */
    DBG("You have not defined any device\n");
    exit(1);
#endif /* VIRTIO_RNG */

#endif /* VHOST_USER */

    /*
     * Start loopback trasnport layer and communiation with the loopback driver
     */
    virtio_loopback_start();

    return 0;

error_args:
    help_args();
    return 1;
}
