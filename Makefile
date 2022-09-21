# Copyright 2022 Virtual Open Systems SAS.
#
# Authors:
#  Timos Ampelikiotis <t.ampelikiotis@virtualopensystems.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.


#CFLAGS := -Wall -Wextra -Werror
#CFLAGS := -Wall -Wextra -Wno-unused-variable -Wno-unused-function
CFLAGS := -Wno-unused-variable -Wno-unused-function
CFLAGS += -DSERVER
CC =

ifeq ($(ARCH), arm64)
 # arm64
 CC = aarch64-linux-gnu-gcc
else
 CC = gcc
endif

ifeq ($(VHOST_USER_RNG), 1)
 CFLAGS += -DVHOST_USER_RNG_DEV
endif

INCL += -I .
DEPS = adapter.h vhost_user_loopback.h event_notifier.h virtio_loopback.h
SRC_C = event_notifier.c vhost_user_loopback.c virtio_loopback.c virtio_rng.c vhost_user_rng.c vhost_loopback.c adapter.c

OBJS = $(SRC_C:.c=.o)
BINS = adapter

ifeq ($(DEBUG), 1)
 CFLAGS += -DDEBUG
endif

all: $(BINS)

$(BINS): $(OBJS)
	@echo -e "CC\t$@"
	$(CC) $(CFLAGS) $(INCL) $^ -o $@ -lpthread -static

%.o: %.c
	@echo -e "CC\t$@"
	$(CC) $(CFLAGS) $(INCL) -c $< -o $@

clean:
	rm -f *.o *~ $(BINS)

.PHONY: all
