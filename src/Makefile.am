AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}

bin_PROGRAMS = adapter

adapter_SOURCES = \
	event_notifier.c \
	vhost_user_loopback.c \
	virtio_loopback.c \
	virtio_rng.c \
	virtio_input.c \
	vhost_user_input.c \
	vhost_user_blk.c \
	vhost_user_rng.c \
	vhost_user_sound.c \
	vhost_user_gpio.c \
	vhost_loopback.c \
	adapter.c

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
