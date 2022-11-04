/*      $NetBSD: queue.h,v 1.52 2009/04/20 09:56:08 mschuett Exp $ */

/*
 * QEMU version: Copy from netbsd, removed debug code, removed some of
 * the implementations.  Left in singly-linked lists, lists, simple
 * queues, and tail queues.
 */

/*
 * Based on queue.h of QEMU project
 *
 *   Copyright (c) 1991, 1993
 *    The Regents of the University of California.  All rights reserved.
 *
 * Copyright (c) 2022 Virtual Open Systems SAS.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *      @(#)queue.h     8.5 (Berkeley) 8/20/94
 */

#ifndef QEMU_SYS_QUEUE_H
#define QEMU_SYS_QUEUE_H

/*
 * This file defines four types of data structures: singly-linked lists,
 * lists, simple queues, and tail queues.
 *
 * A singly-linked list is headed by a single forward pointer. The
 * elements are singly linked for minimum space and pointer manipulation
 * overhead at the expense of O(n) removal for arbitrary elements. New
 * elements can be added to the list after an existing element or at the
 * head of the list.  Elements being removed from the head of the list
 * should use the explicit macro for this purpose for optimum
 * efficiency. A singly-linked list may only be traversed in the forward
 * direction.  Singly-linked lists are ideal for applications with large
 * datasets and few or no removals or for implementing a LIFO queue.
 *
 * A list is headed by a single forward pointer (or an array of forward
 * pointers for a hash table header). The elements are doubly linked
 * so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before
 * or after an existing element or at the head of the list. A list
 * may only be traversed in the forward direction.
 *
 * A simple queue is headed by a pair of pointers, one the head of the
 * list and the other to the tail of the list. The elements are singly
 * linked to save space, so elements can only be removed from the
 * head of the list. New elements can be added to the list after
 * an existing element, at the head of the list, or at the end of the
 * list. A simple queue may only be traversed in the forward direction.
 *
 * A tail queue is headed by a pair of pointers, one to the head of the
 * list and the other to the tail of the list. The elements are doubly
 * linked so that an arbitrary element can be removed without a need to
 * traverse the list. New elements can be added to the list before or
 * after an existing element, at the head of the list, or at the end of
 * the list. A tail queue may be traversed in either direction.
 *
 * For details on the use of these macros, see the queue(3) manual page.
 */


typedef struct QTailQLink {
    void *tql_next;
    struct QTailQLink *tql_prev;
} QTailQLink;

/*
 * Tail queue definitions.  The union acts as a poor man template, as if
 * it were QTailQLink<type>.
 */
#define QTAILQ_HEAD(name, type)                                     \
union name {                                                        \
    struct type *tqh_first;                                         \
    QTailQLink tqh_circ;                                            \
}

#define QTAILQ_HEAD_INITIALIZER(head)                               \
    { .tqh_circ = { NULL, &(head).tqh_circ } }

#define QTAILQ_ENTRY(type)                                          \
union {                                                             \
    struct type *tqe_next;                                          \
    QTailQLink tqe_circ;                                            \
}

/*
 * Tail queue functions.
 */
#define QTAILQ_INIT(head) do {                                      \
    (head)->tqh_first = NULL;                                       \
    (head)->tqh_circ.tql_prev = &(head)->tqh_circ;                  \
} while (0)

#define QTAILQ_INSERT_TAIL(head, elm, field) do {                   \
    (elm)->field.tqe_next = NULL;                                   \
    (elm)->field.tqe_circ.tql_prev = (head)->tqh_circ.tql_prev;     \
    (head)->tqh_circ.tql_prev->tql_next = (elm);                    \
    (head)->tqh_circ.tql_prev = &(elm)->field.tqe_circ;             \
} while (0)


#define QTAILQ_FOREACH(var, head, field)                            \
    for ((var) = ((head)->tqh_first);                               \
            (var);                                                  \
            (var) = ((var)->field.tqe_next))

/*
 * Tail queue access methods.
 */
#define QTAILQ_EMPTY(head)               ((head)->tqh_first == NULL)
#define QTAILQ_FIRST(head)               ((head)->tqh_first)
#define QTAILQ_NEXT(elm, field)          ((elm)->field.tqe_next)

#define field_at_offset(base, offset, type)                                \
    ((type *) (((char *) (base)) + (offset)))


#endif /* QEMU_SYS_QUEUE_H */
