/*
 *
 * DATUM Gateway
 * Decentralized Alternative Templates for Universal Mining
 *
 * This file is part of OCEAN's Bitcoin mining decentralization
 * project, DATUM.
 *
 * https://ocean.xyz
 *
 * ---
 *
 * Copyright (c) 2024 Bitcoin Ocean, LLC & Jason Hughes
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef _DATUM_QUEUE_H_
#define _DATUM_QUEUE_H_

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct {
	volatile bool initialized;
	int max_entries;
	pthread_rwlock_t active_buffer_rwlock;
	int active_buffer;
	uint64_t active_buffer_version;
	pthread_rwlock_t buffer_rwlock[2];
	int queue_next[2];
	uint64_t queue_version[2];
	size_t item_size;
	int buf_idx[2];
	void *buffer[2];
	// pointer to processor function
	int (*item_handler)(void *);
} DATUM_QUEUE;

int datum_queue_prep(DATUM_QUEUE *q, const int max_items, const int item_size, int (*item_handler)(void *));
int datum_queue_process(DATUM_QUEUE *q);
int datum_queue_add_item(DATUM_QUEUE *q, void *item);
int datum_queue_free(DATUM_QUEUE *q);

#endif
