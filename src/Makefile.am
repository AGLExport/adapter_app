AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

bin_PROGRAMS = adapter

adapter_SOURCES = \
	event_notifier.c \
	vhost_user_loopback.c \
	virtio_loopback.c \
	vhost_loopback.c \
	adapter.c

if ENABLE_VHOST_RNG
adapter_SOURCES   += \
	virtio_rng.c
endif

if ENABLE_VHOST_USER_RNG
adapter_SOURCES   += \
	vhost_user_rng.c
endif

if ENABLE_VHOST_USER_BLK
adapter_SOURCES   += \
	vhost_user_blk.c
endif

if ENABLE_VHOST_USER_INPUT
adapter_SOURCES   += \
	virtio_input.c \
	vhost_user_input.c
endif

if ENABLE_VHOST_USER_GPIO
adapter_SOURCES   += \
	vhost_user_gpio.c
endif

if ENABLE_VHOST_USER_SOUND
adapter_SOURCES   += \
	vhost_user_sound.c
endif

# options
# Additional library
adapter_LDADD =

# C compiler options
adapter_CFLAGS = \
	-g -Wall -Wno-unused-but-set-variable \
	-lpthread \
	-D_GNU_SOURCE

# Linker options
adapter_LDFLAGS = 


# configure option
if ENABLE_VHOST_RNG
CFLAGS   += -DENABLE_VHOST_RNG
endif

if ENABLE_VHOST_USER_RNG
CFLAGS   += -DENABLE_VHOST_USER_RNG
endif

if ENABLE_VHOST_USER_BLK
CFLAGS   += -DENABLE_VHOST_USER_BLK
endif

if ENABLE_VHOST_USER_INPUT
CFLAGS   += -DENABLE_VHOST_USER_INPUT
endif

if ENABLE_VHOST_USER_GPIO
CFLAGS   += -DENABLE_VHOST_USER_GPIO
endif

if ENABLE_VHOST_USER_SOUND
CFLAGS   += -DENABLE_VHOST_USER_SOUND
endif

if ENABLE_ADDRESS_SANITIZER
CFLAGS   += -fsanitize=address
endif

if ENABLE_GCOV
CFLAGS   += -coverage
endif

if ENABLE_DEBUG
adapter_CFLAGS   += -DDEBUG
endif

CLEANFILES = *.gcda *.gcno
