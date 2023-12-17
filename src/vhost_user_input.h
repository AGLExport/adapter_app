/*
 * Based on virtio-input.h of QEMU project
 *
 * Copyright (c) 2022-2023 Virtual Open Systems SAS.
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.  See the COPYING file in the
 * top-level directory.
 */

#ifndef VHOST_USER_INPUT
#define VHOST_USER_INPUT

#include "vhost_loopback.h"
#include "vhost_user_loopback.h"
#include "virtio_loopback.h"
#include <linux/virtio_input.h>
#include "queue.h"
#include <sys/mman.h>

/* ----------------------------------------------------------------- */
/* virtio input protocol                                             */

typedef struct virtio_input_absinfo virtio_input_absinfo;
typedef struct virtio_input_config virtio_input_config;
typedef struct virtio_input_event virtio_input_event;

/* ----------------------------------------------------------------- */
/* qemu internals                                                    */

#define TYPE_VIRTIO_INPUT "virtio-input-device"
#define TYPE_VIRTIO_INPUT_HID "virtio-input-hid-device"
#define TYPE_VIRTIO_KEYBOARD  "virtio-keyboard-device"
#define TYPE_VIRTIO_MOUSE     "virtio-mouse-device"
#define TYPE_VIRTIO_TABLET    "virtio-tablet-device"

#define TYPE_VIRTIO_INPUT_HOST   "virtio-input-host-device"

#define TYPE_VHOST_USER_INPUT   "vhost-user-input"

typedef struct VirtIOInputConfig {
    virtio_input_config               config;
    QTAILQ_ENTRY(VirtIOInputConfig)   node;
} VirtIOInputConfig;

struct VirtIOInputClass;

typedef struct VirtIOInput {
    VirtIODevice                      *parent_dev;
    struct VirtIOInputClass           *input_class;
    uint8_t                           cfg_select;
    uint8_t                           cfg_subsel;
    uint32_t                          cfg_size;
    QTAILQ_HEAD(, VirtIOInputConfig)  cfg_list;
    VirtQueue                         *evt, *sts;
    char                              *serial;
    struct {
        virtio_input_event event;
        VirtQueueElement *elem;
    }                                 *queue;
    uint32_t                          qindex, qsize;
    bool                              active;

} VirtIOInput;

typedef struct VirtIOInputClass {
    VirtioDeviceClass *parent_class;
    void (*realize)();
    void (*unrealize)(VirtIODevice *dev);
    void (*change_active)(VirtIOInput *vinput);
    void (*handle_status)(VirtIOInput *vinput, virtio_input_event *event);
} VirtIOInputClass;

struct VirtIOInputHID {
    VirtIOInput                       parent_obj;
    char                              *display;
    uint32_t                          head;
    int                               ledstate;
    bool                              wheel_axis;
};

struct VirtIOInputHost {
    VirtIOInput                       parent_obj;
    char                              *evdev;
    int                               fd;
};

typedef struct VhostUserInput {
    VirtIOInput *vdev_input;
    struct vhost_dev *vhost_dev;
    VirtIODevice *vdev;
    bool started;
    bool completed;
} VhostUserInput;

#define VIRTIO_ID_NAME_KEYBOARD "QEMU Virtio Keyboard"
#define BUS_VIRTUAL     0x06


/*
 * Event types
 */

#define EV_SYN          0x00
#define EV_KEY          0x01
#define EV_REL          0x02
#define EV_ABS          0x03
#define EV_MSC          0x04
#define EV_SW           0x05
#define EV_LED          0x11
#define EV_SND          0x12
#define EV_REP          0x14
#define EV_FF           0x15
#define EV_PWR          0x16
#define EV_FF_STATUS        0x17
#define EV_MAX          0x1f
#define EV_CNT          (EV_MAX + 1)

/*
 * LEDs
 */

#define LED_NUML        0x00
#define LED_CAPSL       0x01
#define LED_SCROLLL     0x02
#define LED_COMPOSE     0x03
#define LED_KANA        0x04
#define LED_SLEEP       0x05
#define LED_SUSPEND     0x06
#define LED_MUTE        0x07
#define LED_MISC        0x08
#define LED_MAIL        0x09
#define LED_CHARGING        0x0a
#define LED_MAX         0x0f
#define LED_CNT         (LED_MAX + 1)

/*
 * Keys and buttons
 *
 * Most of the keys/buttons are modeled after USB HUT 1.12
 * (see http://www.usb.org/developers/hidpage).
 * Abbreviations in the comments:
 * AC - Application Control
 * AL - Application Launch Button
 * SC - System Control
 */
#define KEY_G           34

static struct virtio_input_config virtio_keyboard_config[] = {
    {
        .select    = VIRTIO_INPUT_CFG_ID_NAME,
        .size      = sizeof(VIRTIO_ID_NAME_KEYBOARD),
        .u.string  = VIRTIO_ID_NAME_KEYBOARD,
    },{
        .select    = VIRTIO_INPUT_CFG_ID_DEVIDS,
        .size      = sizeof(struct virtio_input_devids),
        .u.ids     = {
            .bustype = (BUS_VIRTUAL),
            .vendor  = (0x0627), /* same we use for usb hid devices */
            .product = (0x0001),
            .version = (0x0001),
        },
    },{
        .select    = VIRTIO_INPUT_CFG_EV_BITS,
        .subsel    = EV_KEY,
        .size      = 1,
        .u.bitmap  = {
             KEY_G,
        },
    },
    {}, /* End of list */
};

void vhost_user_backend_start(VirtIODevice *vdev);
void vhost_user_backend_stop(VirtIODevice *vdev);

void virtio_input_init_config(VirtIOInput *vinput,
                              virtio_input_config *config);
void virtio_input_class_init(VirtIODevice *vdev);
void virtio_input_device_realize();

void vhost_user_input_init(VirtIODevice *vdev);
void vhost_user_input_realize();

#endif /* VHOST_USER_INPUT */
