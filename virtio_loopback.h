/*
 * Based on:
 *  1) virtio.h of QEMU project
 *
 *     Copyright IBM, Corp. 2007
 *
 *     Authors:
 *      Anthony Liguori   <aliguori@us.ibm.com>
 *
 *  2) virtio-mmio.h of QEMU project
 *
 *     Copyright (c) 2011 Linaro Limited
 *
 *     Author:
 *      Peter Maydell <peter.maydell@linaro.org>
 *
 *  3) vhost.h of QEMU project
 *
 * Copyright 2022 Virtual Open Systems SAS.
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

/*
 * Control registers
 */
#ifndef VIRTIO_LOOPBACK
#define VIRTIO_LOOPBACK

#include "event_notifier.h"

#define sizeof_field(type, field) sizeof(((type *)0)->field)

/* Magic value ("virt" string) - Read Only */
#define VIRTIO_MMIO_MAGIC_VALUE     0x000

/* Virtio device version - Read Only */
#define VIRTIO_MMIO_VERSION     0x004

/* Virtio device ID - Read Only */
#define VIRTIO_MMIO_DEVICE_ID       0x008

/* Virtio vendor ID - Read Only */
#define VIRTIO_MMIO_VENDOR_ID       0x00c

/*
 * Bitmask of the features supported by the device (host)
 * (32 bits per set) - Read Only
 */
#define VIRTIO_MMIO_DEVICE_FEATURES 0x010

/* Device (host) features set selector - Write Only */
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014

/*
 * Bitmask of features activated by the driver (guest)
 * (32 bits per set) - Write Only
 */
#define VIRTIO_MMIO_DRIVER_FEATURES 0x020

/* Activated features set selector - Write Only */
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024

/* Guest's memory page size in bytes - Write Only */
#define VIRTIO_MMIO_GUEST_PAGE_SIZE 0x028

/* Queue selector - Write Only */
#define VIRTIO_MMIO_QUEUE_SEL       0x030

/* Maximum size of the currently selected queue - Read Only */
#define VIRTIO_MMIO_QUEUE_NUM_MAX   0x034

/* Queue size for the currently selected queue - Write Only */
#define VIRTIO_MMIO_QUEUE_NUM       0x038


/* Used Ring alignment for the currently selected queue - Write Only */
#define VIRTIO_MMIO_QUEUE_ALIGN     0x03c

/* Guest's PFN for the currently selected queue - Read Write */
#define VIRTIO_MMIO_QUEUE_PFN       0x040

/* Ready bit for the currently selected queue - Read Write */
#define VIRTIO_MMIO_QUEUE_READY     0x044

/* Queue notifier - Write Only */
#define VIRTIO_MMIO_QUEUE_NOTIFY    0x050

/* Interrupt status - Read Only */
#define VIRTIO_MMIO_INTERRUPT_STATUS    0x060

/* Interrupt acknowledge - Write Only */
#define VIRTIO_MMIO_INTERRUPT_ACK   0x064

/* Device status register - Read Write */
#define VIRTIO_MMIO_STATUS      0x070

/* Selected queue's Descriptor Table address, 64 bits in two halves */
#define VIRTIO_MMIO_QUEUE_DESC_LOW  0x080
#define VIRTIO_MMIO_QUEUE_DESC_HIGH 0x084

/* Selected queue's Available Ring address, 64 bits in two halves */
#define VIRTIO_MMIO_QUEUE_AVAIL_LOW 0x090
#define VIRTIO_MMIO_QUEUE_AVAIL_HIGH    0x094

/* Selected queue's Used Ring address, 64 bits in two halves */
#define VIRTIO_MMIO_QUEUE_USED_LOW  0x0a0
#define VIRTIO_MMIO_QUEUE_USED_HIGH 0x0a4

/* Shared memory region id */
#define VIRTIO_MMIO_SHM_SEL             0x0ac

/* Shared memory region length, 64 bits in two halves */
#define VIRTIO_MMIO_SHM_LEN_LOW         0x0b0
#define VIRTIO_MMIO_SHM_LEN_HIGH        0x0b4

/* Shared memory region base address, 64 bits in two halves */
#define VIRTIO_MMIO_SHM_BASE_LOW        0x0b8
#define VIRTIO_MMIO_SHM_BASE_HIGH       0x0bc

/* Configuration atomicity value */
#define VIRTIO_MMIO_CONFIG_GENERATION   0x0fc

/*
 * The config space is defined by each driver as
 * the per-driver configuration space - Read Write
 */
#define VIRTIO_MMIO_CONFIG      0x100

/*
 * Interrupt flags (re: interrupt status & acknowledge registers)
 */
#define VIRTIO_MMIO_INT_VRING       (1 << 0)
#define VIRTIO_MMIO_INT_CONFIG      (1 << 1)

#define VIRTIO_IOMMIO_FLAG_USE_IOEVENTFD_BIT 1
#define VIRTIO_IOMMIO_FLAG_USE_IOEVENTFD \
        (1 << VIRTIO_IOMMIO_FLAG_USE_IOEVENTFD_BIT)


/* Virtio loopback driver related */

/* QEMU defines */
#define VIRT_MAGIC 0x74726976 /* 'virt' */
#define VIRT_VERSION 2
#define VIRT_VERSION_LEGACY 1
#define VIRT_VENDOR 0x554D4551 /* 'QEMU' */

#define VIRTQUEUE_MAX_SIZE 1024
#define VIRTIO_QUEUE_MAX 1024
#define VIRTIO_NO_VECTOR 0xffff
#define TYPE_VIRTIO_DEVICE "virtio-device"

/* Loopback negotiation code */

#define PAGE_SHIFT    12
#define PAGE_SIZE     4096

#define EFD_INIT _IOC(_IOC_WRITE, 'k', 1, sizeof(efd_data_t))
#define WAKEUP _IOC(_IOC_WRITE, 'k', 2, 0)
#define START_LOOPBACK _IOC(_IOC_WRITE, 'k', 3, \
                            sizeof(virtio_device_info_struct_t))
#define IRQ _IOC(_IOC_WRITE, 'k', 4, sizeof(int))
#define SHARE_VQS _IOC(_IOC_WRITE, 'k', 5, 0)
#define SHARE_BUF _IOC(_IOC_WRITE, 'k', 6, sizeof(uint64_t))
#define USED_INFO _IOC(_IOC_WRITE, 'k', 7, 0)
#define DATA_INFO _IOC(_IOC_WRITE, 'k', 8, 0)
#define MAP_BLK _IOC(_IOC_WRITE, 'k', 9, 0)
#define BARRIER _IOC(_IOC_WRITE, 'k', 10, 0)

#define VIRTIO_PCI_VRING_ALIGN         4096

typedef struct VirtIOMMIOProxy {
    /* Generic */
    bool legacy;
    uint32_t flags;
    /* Guest accessible state needing migration and reset */
    uint32_t host_features_sel;
    uint32_t guest_features_sel;
    uint32_t guest_page_shift;
    /* virtio-bus */
    bool format_transport_address;
    /* Fields only used for non-legacy (v2) devices */
    uint32_t guest_features[2];
} VirtIOMMIOProxy;


/* Vring specific */
/* This marks a buffer as continuing via the next field. */
#define VRING_DESC_F_NEXT   1
/* This marks a buffer as write-only (otherwise read-only). */
#define VRING_DESC_F_WRITE  2
/* This means the buffer contains a list of buffer descriptors. */
#define VRING_DESC_F_INDIRECT   4

/*
 * Mark a descriptor as available or used in packed ring.
 * Notice: they are defined as shifts instead of shifted values.
 */
#define VRING_PACKED_DESC_F_AVAIL   7
#define VRING_PACKED_DESC_F_USED    15

/*
 * The Host uses this in used->flags to advise the Guest: don't kick me when
 * you add a buffer.  It's unreliable, so it's simply an optimization.  Guest
 * will still kick if it's out of buffers.
 */
#define VRING_USED_F_NO_NOTIFY  1
/*
 * The Guest uses this in avail->flags to advise the Host: don't interrupt me
 * when you consume a buffer.  It's unreliable, so it's simply an
 * optimization.
 */
#define VRING_AVAIL_F_NO_INTERRUPT  1

/* Enable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_ENABLE  0x0
/* Disable events in packed ring. */
#define VRING_PACKED_EVENT_FLAG_DISABLE 0x1
/*
 * Enable events for a specific descriptor in packed ring.
 * (as specified by Descriptor Ring Change Event Offset/Wrap Counter).
 * Only valid if VIRTIO_RING_F_EVENT_IDX has been negotiated.
 */
#define VRING_PACKED_EVENT_FLAG_DESC    0x2

/*
 * Wrap counter bit shift in event suppression structure
 * of packed ring.
 */
#define VRING_PACKED_EVENT_F_WRAP_CTR   15

/* We support indirect buffer descriptors */
#define VIRTIO_RING_F_INDIRECT_DESC 28

/*
 * The Guest publishes the used index for which it expects an interrupt
 * at the end of the avail ring. Host should ignore the avail->flags field.
 */
/*
 * The Host publishes the avail index for which it expects a kick
 * at the end of the used ring. Guest should ignore the used->flags field.
 */
#define VIRTIO_RING_F_EVENT_IDX     29

/*
 * Alignment requirements for vring elements.
 * When using pre-virtio 1.0 layout, these fall out naturally.
 */
#define VRING_AVAIL_ALIGN_SIZE 2
#define VRING_USED_ALIGN_SIZE 4
#define VRING_DESC_ALIGN_SIZE 16
/******************/


extern uint64_t vring_phys_addrs[2];
extern uint32_t vring_phys_addrs_idx;

typedef struct VRing {
    unsigned int num;
    unsigned int num_default;
    unsigned int align;
    uint64_t desc;
    uint64_t avail;
    uint64_t used;
} VRing;

typedef struct VRingDesc {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} VRingDesc;

typedef struct VRingPackedDesc {
    uint64_t addr;
    uint32_t len;
    uint16_t id;
    uint16_t flags;
} VRingPackedDesc;

typedef struct VRingAvail {
    uint16_t flags;
    uint16_t idx;
    uint16_t ring[];
} VRingAvail;

typedef struct VRingUsedElem {
    uint32_t id;
    uint32_t len;
} VRingUsedElem;

typedef struct VRingUsed {
    uint16_t flags;
    uint16_t idx;
    VRingUsedElem ring[];
} VRingUsed;

typedef struct VirtQueueElement {
    unsigned int index;
    unsigned int len;
    unsigned int ndescs;
    unsigned int out_num;
    unsigned int in_num;
    uint64_t *in_addr;
    uint64_t *out_addr;
    struct iovec *in_sg;
    struct iovec *out_sg;
} VirtQueueElement;

typedef struct VirtIODevice VirtIODevice;
typedef struct VirtQueue VirtQueue;
typedef void (*VirtIOHandleOutput)(VirtIODevice *, VirtQueue *);

typedef struct VirtQueue {
    VRing vring;
    VirtQueueElement *used_elems;

    /* Next head to pop */
    uint16_t last_avail_idx;
    bool last_avail_wrap_counter;

    /* Last avail_idx read from VQ. */
    uint16_t shadow_avail_idx;
    bool shadow_avail_wrap_counter;

    uint16_t used_idx;
    bool used_wrap_counter;

    /* Last used index value we have signalled on */
    uint16_t signalled_used;

    /* Last used index value we have signalled on */
    bool signalled_used_valid;

    /* Notification enabled? */
    bool notification;

    uint16_t queue_index;

    unsigned int inuse;

    uint16_t vector;
    VirtIOHandleOutput handle_output;
    VirtIODevice *vdev;

    EventNotifier guest_notifier;
    EventNotifier host_notifier;
    bool host_notifier_enabled;
} VirtQueue;

typedef struct VirtIORNG VirtIORNG;
typedef struct VirtIOInput VirtIOInput;
typedef struct VHostUserRNG VHostUserRNG;
typedef struct VirtioDeviceClass VirtioDeviceClass;
typedef struct VHostUserBlk VHostUserBlk;
typedef struct VhostUserInput VhostUserInput;
typedef struct VirtioBus VirtioBus;

typedef struct VirtIODevice {
    VirtioBus *vbus;
    VirtioDeviceClass *vdev_class;
    struct vhost_dev *vhdev;
    const char *name;
    uint8_t status;
    uint8_t isr;
    uint16_t queue_sel;
    uint64_t guest_features;
    uint64_t host_features;
    uint64_t backend_features;
    size_t config_len;
    void *config;
    uint16_t config_vector;
    uint32_t generation;
    int nvectors;
    VirtQueue *vq;
    VirtQueue **vqs;
    int *nvqs;
    uint16_t device_id;
    bool vm_running;
    bool broken; /* device in invalid state, needs reset */
    bool use_disabled_flag; /* allow use of 'disable' flag when needed */
    bool disabled; /* device in temporarily disabled state */
    bool use_started;
    bool started;
    bool start_on_kick; /* when virtio 1.0 feature has not been negotiated */
    bool disable_legacy_check;
    char *bus_name;
    uint8_t device_endian;
    bool use_guest_notifier_mask;
    VirtIORNG *vrng;
    VirtIOInput *vinput;
    VHostUserRNG *vhrng;
    VHostUserBlk *vhublk;
    VhostUserInput *vhuinput;
} VirtIODevice;

typedef struct efd_data {
    int efd;
    int pid;
} efd_data_t;

typedef struct virtio_device_info_struct {
    unsigned long magic;
    unsigned long version;
    unsigned long device_id;
    unsigned long vendor;

} virtio_device_info_struct_t;


/* Negotiation structs */

typedef struct { int counter; } atomic_t;

typedef struct virtio_neg {
    uint64_t notification;
    uint64_t data;
    uint64_t size;
    bool read;
    atomic_t done;
} virtio_neg_t;


/* This is left here as a reference, might be useful in the future */
/*
 * static void virtio_mmio_bus_class_init(ObjectClass *klass, void *data)
 * {
 *     BusClass *bus_class = BUS_CLASS(klass);
 *     VirtioBusClass *k = VIRTIO_BUS_CLASS(klass);
 *
 *     k->notify = virtio_mmio_update_irq;
 *     k->save_config = virtio_mmio_save_config;
 *     k->load_config = virtio_mmio_load_config;
 *     k->save_extra_state = virtio_mmio_save_extra_state;
 *     k->load_extra_state = virtio_mmio_load_extra_state;
 *     k->has_extra_state = virtio_mmio_has_extra_state;
 *     k->set_guest_notifiers = virtio_mmio_set_guest_notifiers;
 *     k->ioeventfd_enabled = virtio_mmio_ioeventfd_enabled;
 *     k->ioeventfd_assign = virtio_mmio_ioeventfd_assign;
 *     k->pre_plugged = virtio_mmio_pre_plugged;
 *     k->vmstate_change = virtio_mmio_vmstate_change;
 *     k->has_variable_vring_alignment = true;
 *     bus_class->max_dev = 1;
 *     bus_class->get_dev_path = virtio_mmio_bus_get_dev_path;
 * }
 *
 */


typedef struct VirtioBus {

    VirtIODevice *vdev;
    void (*notify)(VirtIODevice *d, uint16_t vector);
    bool (*has_extra_state)(VirtIODevice *d);
    bool (*query_guest_notifiers)(VirtIODevice *d);
    int (*set_guest_notifiers)(VirtIODevice *d, int nvqs, bool assign);
    void (*vmstate_change)(VirtIODevice *d, bool running);
    void (*pre_plugged)(VirtIODevice *d);
    void (*device_plugged)(VirtIODevice *d);
    /*
     * transport independent exit function.
     * This is called by virtio-bus just before the device is unplugged.
     */
    void (*device_unplugged)(VirtIODevice *d);
    int (*query_nvectors)(VirtIODevice *d);
    /*
     * ioeventfd handling: if the transport implements ioeventfd_assign,
     * it must implement ioeventfd_enabled as well.
     */
    /* Returns true if the ioeventfd is enabled for the device. */
    bool (*ioeventfd_enabled)(VirtIODevice *d);
    /*
     * Assigns/deassigns the ioeventfd backing for the transport on
     * the device for queue number n. Returns an error value on
     * failure.
     */
    int (*ioeventfd_assign)(VirtIOMMIOProxy *d, EventNotifier *notifier,
                            int n, bool assign);
    /*
     * Whether queue number n is enabled.
     */
    bool (*queue_enabled)(VirtIODevice *d, int n);
    /*
     * Does the transport have variable vring alignment?
     * (ie can it ever call virtio_queue_set_align()?)
     * Note that changing this will break migration for this transport.
     */
    bool has_variable_vring_alignment;
    bool (*iommu_enabled)(VirtIODevice *d);

    /*
     * Set if ioeventfd has been started.
     */
    bool ioeventfd_started;

    /*
     * Set if ioeventfd has been grabbed by vhost.  When ioeventfd
     * is grabbed by vhost, we track its started/stopped state (which
     * depends in turn on the virtio status register), but do not
     * register a handler for the ioeventfd.  When ioeventfd is
     * released, if ioeventfd_started is true we finally register
     * the handler so that QEMU's device model can use ioeventfd.
     */
    int ioeventfd_grabbed;
} VirtioBus;


typedef struct VirtioDeviceClass {
    /*< private >*/
    VirtIODevice *parent;
    /*< public >*/
    /* This is what a VirtioDevice must implement */
    uint64_t (*get_features)(VirtIODevice *vdev,
                             uint64_t requested_features);
    uint64_t (*bad_features)(VirtIODevice *vdev);
    void (*set_features)(VirtIODevice *vdev, uint64_t val);
    int (*validate_features)(VirtIODevice *vdev);
    void (*get_config)(VirtIODevice *vdev, uint8_t *config);
    void (*set_config)(VirtIODevice *vdev, const uint8_t *config);
    void (*reset)(VirtIODevice *vdev);
    void (*set_status)(VirtIODevice *vdev, uint8_t val);
    void (*realize)(void);
    void (*unrealize)(VirtIODevice *vdev);
    /*
     * For transitional devices, this is a bitmap of features
     * that are only exposed on the legacy interface but not
     * the modern one.
     */
    uint64_t legacy_features;
    /*
     * Test and clear event pending status.
     * Should be called after unmask to avoid losing events.
     * If backend does not support masking,
     * must check in frontend instead.
     */
    bool (*guest_notifier_pending)(VirtIODevice *vdev, int n);
    /*
     * Mask/unmask events from this vq. Any events reported
     * while masked will become pending.
     * If backend does not support masking,
     * must mask in frontend instead.
     */
    void (*guest_notifier_mask)(VirtIODevice *vdev, int n, bool mask);
    int (*start_ioeventfd)(VirtIODevice *vdev);
    void (*stop_ioeventfd)(VirtIODevice *vdev);
    /*
     * Saving and loading of a device; trying to deprecate save/load
     * use vmsd for new devices.
     */
    /*
     * Post load hook in vmsd is called early while device is processed, and
     * when VirtIODevice isn't fully initialized.  Devices should use this
     * instead, unless they specifically want to verify the migration stream
     * as it's processed, e.g. for bounds checking.
     */
    int (*post_load)(VirtIODevice *vdev);
    bool (*primary_unplug_pending)(void *opaque);

    void (*update_mem_table)(VirtIODevice *vdev);

    struct vhost_dev *(*get_vhost)(VirtIODevice *vdev);
} VirtioDeviceClass;

/* Global variables */
extern int fd;
extern int loopback_fd;

void handle_input(VirtIODevice *vdev, VirtQueue *vq);
void *my_select(void *data);
void *wait_read_write(void *data);
void virtio_notify_config(VirtIODevice *vdev);
void create_rng_struct(void);
void print_neg_flag(uint64_t neg_flag, bool read);
void adapter_read_write_cb(void);
int virtio_loopback_start(void);

int virtio_queue_ready(VirtQueue *vq);
void virtqueue_get_avail_bytes(VirtQueue *vq, unsigned int *in_bytes,
                               unsigned int *out_bytes,
                               unsigned max_in_bytes, unsigned max_out_bytes);
void virtio_add_feature(uint64_t *features, unsigned int fbit);
bool virtio_has_feature(uint64_t features, unsigned int fbit);
bool virtio_device_started(VirtIODevice *vdev, uint8_t status);

int virtio_queue_empty(VirtQueue *vq);
void *virtqueue_pop(VirtQueue *vq, size_t sz);
void virtqueue_push(VirtQueue *vq, const VirtQueueElement *elem,
                    unsigned int len);
size_t iov_from_buf(const struct iovec *iov, unsigned int iov_cnt,
             size_t offset, const void *buf, size_t bytes);
bool virtqueue_get_head(VirtQueue *vq, unsigned int idx,
                               unsigned int *head);
void virtio_notify_vector(VirtIODevice *vdev);

enum {
    VIRTQUEUE_READ_DESC_ERROR = -1,
    VIRTQUEUE_READ_DESC_DONE = 0,   /* end of chain */
    VIRTQUEUE_READ_DESC_MORE = 1,   /* more buffers in chain */
};

size_t qemu_iov_from_buf(const struct iovec *iov, unsigned int iov_cnt,
             size_t offset, const void *buf, size_t bytes);
VirtQueue *virtio_add_queue(VirtIODevice *vdev, int queue_size,
                            VirtIOHandleOutput handle_output);
VirtQueue *virtio_get_queue(VirtIODevice *vdev, int n);
void virtio_dev_init(VirtIODevice *vdev, const char *name,
                 uint16_t device_id, size_t config_size);
void virtio_loopback_bus_init(VirtioBus *k);
int virtio_bus_set_host_notifier(VirtioBus *vbus, int n, bool assign);
EventNotifier *virtio_queue_get_host_notifier(VirtQueue *vq);
EventNotifier *virtio_queue_get_guest_notifier(VirtQueue *vq);
uint64_t virtio_queue_get_desc_addr(VirtIODevice *vdev, int n);
uint64_t virtio_queue_get_avail_addr(VirtIODevice *vdev, int n);
uint64_t virtio_queue_get_used_addr(VirtIODevice *vdev, int n);
int virtio_queue_get_num(VirtIODevice *vdev, int n);
unsigned int virtio_queue_get_last_avail_idx(VirtIODevice *vdev, int n);
uint64_t virtio_queue_get_desc_size(VirtIODevice *vdev, int n);
uint64_t virtio_queue_get_avail_size(VirtIODevice *vdev, int n);
uint64_t virtio_queue_get_used_size(VirtIODevice *vdev, int n);
void virtio_set_isr(VirtIODevice *vdev, int value);
int virtio_device_grab_ioeventfd(VirtIODevice *vdev);
bool virtio_bus_device_iommu_enabled(VirtIODevice *vdev);
size_t iov_from_buf_full(const struct iovec *iov, unsigned int iov_cnt,
                         size_t offset, const void *buf, size_t bytes);
void event_notifier_set_handler(EventNotifier *e,
                                void *handler);
void virtio_notify(VirtIODevice *vdev, VirtQueue *vq);
int virtqueue_split_read_next_desc(VirtIODevice *vdev, VRingDesc *desc,
                                   unsigned int max, unsigned int *next);
void print_config(uint8_t *config);
uint32_t get_vqs_max_size(VirtIODevice *vdev);

/*
 * Do we get callbacks when the ring is completely used, even if we've
 * suppressed them?
 */
#define VIRTIO_F_NOTIFY_ON_EMPTY         24
#define VIRTIO_CONFIG_S_FEATURES_OK      8
#define VIRTIO_CONFIG_S_DRIVER_OK        4
#define VIRTIO_F_VERSION_1               32
#define VIRTIO_F_ACCESS_PLATFORM         33
/*
 * Legacy name for VIRTIO_F_ACCESS_PLATFORM
 * (for compatibility with old userspace)
 */
#define VIRTIO_F_IOMMU_PLATFORM          33

/* QEMU Aligned functions */
/*
 * Round number down to multiple. Safe when m is not a power of 2 (see
 * ROUND_DOWN for a faster version when a power of 2 is guaranteed).
 */
#define QEMU_ALIGN_DOWN(n, m) ((n) / (m) * (m))

/*
 * Round number up to multiple. Safe when m is not a power of 2 (see
 * ROUND_UP for a faster version when a power of 2 is guaranteed).
 */
#define QEMU_ALIGN_UP(n, m) QEMU_ALIGN_DOWN((n) + (m) - 1, (m))

/* Check if n is a multiple of m */
#define QEMU_IS_ALIGNED(n, m) (((n) % (m)) == 0)

/* n-byte align pointer down */
#define QEMU_ALIGN_PTR_DOWN(p, n) \
    ((typeof(p))QEMU_ALIGN_DOWN((uintptr_t)(p), (n)))

/* n-byte align pointer up */
#define QEMU_ALIGN_PTR_UP(p, n) \
    ((typeof(p))QEMU_ALIGN_UP((uintptr_t)(p), (n)))

/* Check if pointer p is n-bytes aligned */
#define QEMU_PTR_IS_ALIGNED(p, n) QEMU_IS_ALIGNED((uintptr_t)(p), (n))

extern VirtIODevice *global_vdev;
extern VirtIOMMIOProxy *proxy;
extern VirtioBus *global_vbus;

#endif /* VIRTIO_LOOPBACK */

