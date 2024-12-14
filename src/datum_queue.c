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

// Generic threaded queue implementation.
// Used for DATUM Protocol share submissions.
// TODO: Use for share logger?

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>
#include <inttypes.h>
#include <stdbool.h>
#include <pthread.h>

#include "datum_queue.h"
#include "datum_logger.h"
#include "datum_utils.h"

int datum_queue_free(DATUM_QUEUE *q) {
	if (!q->initialized) return -1;
	
	pthread_rwlock_wrlock(&q->active_buffer_rwlock);
	pthread_rwlock_wrlock(&q->buffer_rwlock[0]);
	pthread_rwlock_wrlock(&q->buffer_rwlock[1]);
	
	if (q->buffer[0]) {
		free(q->buffer[0]);
	}
	
	q->initialized = false;
	q->buffer[0] = 0;
	
	pthread_rwlock_unlock(&q->buffer_rwlock[1]);
	pthread_rwlock_unlock(&q->buffer_rwlock[0]);
	pthread_rwlock_unlock(&q->active_buffer_rwlock);
	
	pthread_rwlock_destroy(&q->active_buffer_rwlock);
	pthread_rwlock_destroy(&q->buffer_rwlock[0]);
	pthread_rwlock_destroy(&q->buffer_rwlock[1]);
	
	memset(q, 0, sizeof(DATUM_QUEUE));
	
	return 0;
}

int datum_queue_prep(DATUM_QUEUE *q, const int max_items, const int item_size, int (*item_handler)(void *)) {
	memset(q, 0, sizeof(DATUM_QUEUE));
	
	q->initialized = false;
	
	if (pthread_rwlock_init(&q->active_buffer_rwlock, NULL) != 0) {
		DLOG_FATAL("Could not initialize lock 1");
		return -1;
	}
	
	if (pthread_rwlock_init(&q->buffer_rwlock[0], NULL) != 0) {
		DLOG_FATAL("Could not initialize lock 2");
		return -1;
	}
	
	if (pthread_rwlock_init(&q->buffer_rwlock[1], NULL) != 0) {
		DLOG_FATAL("Could not initialize lock 3");
		return -1;
	}
	
	q->max_entries = max_items;
	q->queue_version[1] = 10;
	
	q->buffer[0] = calloc((max_items + 16)*2, item_size);
	if (!q->buffer[0]) {
		DLOG_FATAL("Could not allocate memory for queue items! (%d bytes)", (max_items + 16)*2*item_size);
		return -1;
	}
	q->buffer[1] = ((char *)q->buffer[0]) + ((max_items + 16) * item_size);
	
	q->item_size = item_size;
	
	// handler function pointer
	q->item_handler = item_handler;
	q->initialized = true;
	
	return 0;
}

int datum_queue_add_item(DATUM_QUEUE *q, void *item) {
	int buffer_id, i;
	uint64_t buffer_version;
	void *out;
	
	if (!q->initialized) return -1;
	
	// Add the msg to the logger queue
	// this is probably overkill...
	for (i=0;i<10000000;i++) {
		if (i < 9999999) { // ensure we don't get the lock on the last try and forget to unlock and crash
			
			// get the active buffer ID
			pthread_rwlock_rdlock(&q->active_buffer_rwlock);
			buffer_id = q->active_buffer;
			buffer_version = q->active_buffer_version;
			pthread_rwlock_unlock(&q->active_buffer_rwlock);
			
			// get a write lock for that buffer
			pthread_rwlock_wrlock(&q->buffer_rwlock[buffer_id]);
			
			// check for race condition on buffer swap
			if (buffer_version != q->queue_version[buffer_id]) {
				// Race condition!
				pthread_rwlock_unlock(&q->buffer_rwlock[buffer_id]);
			} else {
				// no race condition, we're good
				break;
			}
		}
	}
	
	if (i >= 10000000) {
		// we have no locks, but we also couldn't sync up on the rare race condition after 10000000 attempts
		// means something very bad is probably happening.
		DLOG_ERROR("Could not satisfy queue race condition. Is there anything consuming this queue? Likely a bug!");
		return -1;
	}
	
	if (q->queue_next[buffer_id] >= q->max_entries) {
		pthread_rwlock_unlock(&q->buffer_rwlock[buffer_id]);
		DLOG_ERROR("Queue overflow! Is there anything consuming this queue? Likely a bug!");
		return -1;
	}
	
	out = ((char *)q->buffer[buffer_id]) + (q->queue_next[buffer_id] * q->item_size);
	memcpy(out, item, q->item_size);
	q->queue_next[buffer_id]++; // bounds check is above, since we can potentially delay to wait for the writer instead of failing here
	pthread_rwlock_unlock(&q->buffer_rwlock[buffer_id]);
	//DLOG_DEBUG("QUEUE ADD @ %p", out);
	return 0;
}

int datum_queue_process(DATUM_QUEUE *q) {
	// process any items in the specified queue
	// only one thread should ever call this, realistically.
	// if more than one thread needs to process a queue, this will need a good bit of modification.
	
	int buffer_id,offline_buffer_id;
	int i;
	void *item;
	
	if (!q->initialized) return -1;
	
	// We don't need to read lock to read this, as we're the only thread that writes to it.
	buffer_id = q->active_buffer;
	
	pthread_rwlock_rdlock(&q->buffer_rwlock[buffer_id]);
	i = q->queue_next[buffer_id];
	pthread_rwlock_unlock(&q->buffer_rwlock[buffer_id]);
	
	if (!i) {
		// nothing in queue
		return 0;
	}
	
	// there are msgs to write.
	// switch the writers over to the other buffer, and then work on that
	
	// this lock prevents msgs from being queued and holds up all other threads
	// we need to release it ASAP
	pthread_rwlock_wrlock(&q->active_buffer_rwlock);
	
	// we'll get a lock on writing to the current buffer.
	pthread_rwlock_wrlock(&q->buffer_rwlock[buffer_id]);
	
	// at this point we could have threads waiting on the buffer ID, and
	// we also could have threads waiting to write to the buffer we just got a
	// write lock on if the beat the race to lock the buffer_id
	// so we must increment the version of the current buffer, which will signal it's stale
	q->queue_version[buffer_id]++;
	
	// no one should be waiting to write the other buffer
	offline_buffer_id = buffer_id?0:1;
	pthread_rwlock_wrlock(&q->buffer_rwlock[offline_buffer_id]);
	
	// we now have write locks on everything
	// increment version again, just in case
	q->queue_version[offline_buffer_id]++;
	
	// store the new offline buffer ID as the active
	q->active_buffer_version = q->queue_version[offline_buffer_id];
	
	// make the offline buffer the active one
	q->active_buffer = offline_buffer_id;
	
	// just in case
	q->queue_next[offline_buffer_id] = 0;
	
	// release the lock on the offline
	pthread_rwlock_unlock(&q->buffer_rwlock[offline_buffer_id]);
	
	// release the lock on the buffer index... which releases any threads waiting to write
	pthread_rwlock_unlock(&q->active_buffer_rwlock);
	
	for(i=0;i<q->queue_next[buffer_id];i++) {
		// process items
		item = ((char *)q->buffer[buffer_id]) + (i * q->item_size);
		q->item_handler(item);
		// TODO: Handle errors from handler?
		// If such a thing is needed in the future, implement it here so as not to break other things using these queues.
	}
	
	// all done
	q->queue_next[buffer_id] = 0;
	pthread_rwlock_unlock(&q->buffer_rwlock[buffer_id]);
	
	return i;
}
