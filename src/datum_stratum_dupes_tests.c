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
 * Copyright (c) 2026 Bitcoin Ocean, LLC and individual contributors
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

#include <stdlib.h>

#include "datum_conf.h"
#include "datum_stratum.h"
#include "datum_stratum_dupes.h"
#include "datum_utils.h"

// Fill the table past max_items, which is the only way the cleanup/expand path runs.
// Nothing else in the suite reaches it.
static void datum_dupe_table_fill_tests(void) {
	const int saved_clients = datum_config.stratum_v1_max_clients_per_thread;
	const int saved_shares = datum_config.stratum_v1_vardiff_target_shares_min;
	const int saved_stale = datum_config.stratum_v1_share_stale_seconds;

	// max_items = clients * shares_min * (stale/60) * 16, so this is a 16 slot table
	datum_config.stratum_v1_max_clients_per_thread = 1;
	datum_config.stratum_v1_vardiff_target_shares_min = 1;
	datum_config.stratum_v1_share_stale_seconds = 60;

	T_DATUM_STRATUM_THREADPOOL_DATA * const thread_data = calloc(1, sizeof(*thread_data));
	datum_test(thread_data != NULL);
	if (!thread_data) return;
	datum_stratum_dupes_init(thread_data);

	// One live job. Nothing ages out, so the cleanup has nothing to prune and takes the
	// expand path, which is what a busy thread does between block changes.
	T_DATUM_STRATUM_JOB * const job = calloc(1, sizeof(*job));
	T_DATUM_STRATUM_JOB * const saved_job = global_cur_stratum_jobs[1];
	datum_test(job != NULL);
	if (!job) { free(thread_data); return; }
	job->tsms = current_time_millis();
	global_cur_stratum_jobs[1] = job;

	// Eight byte aligned. datum_stratum_add_new_dupe on this branch reads the extranonce
	// back through a uint64_t cast, which is a misaligned load on a plain char array and
	// something UBSan reports. That is a separate issue from what these tests cover.
	uint64_t extranonce_storage[2] = {0};
	unsigned char * const extranonce = (unsigned char *)extranonce_storage;

	// Distinct low 16 bits, so every share lands in a bucket of its own and each insert
	// is the "first nonce of its kind" case.
	for (int i = 0; i < 64; ++i) {
		const unsigned int nonce = ((unsigned int)i << 16) | (unsigned int)((i * 7) + 1);
		datum_test(!datum_stratum_check_for_dupe(thread_data, nonce, 1, 1000 + i, 0, extranonce));
	}

	// The table has to have actually grown, or nothing above went through the path this
	// test exists for and the assertions below prove nothing.
	T_DATUM_STRATUM_DUPES * const dupes = thread_data->dupes;
	datum_test(dupes->max_items > 16);
	datum_test(dupes->current_items <= dupes->max_items);

	// Every one of those is a duplicate now. Re-probing walks each bucket from its index
	// entry, which is where a pointer left over from before a reallocation is read.
	for (int i = 0; i < 64; ++i) {
		const unsigned int nonce = ((unsigned int)i << 16) | (unsigned int)((i * 7) + 1);
		datum_test(datum_stratum_check_for_dupe(thread_data, nonce, 1, 1000 + i, 0, extranonce));
	}

	global_cur_stratum_jobs[1] = saved_job;
	free(dupes->ptr);
	free(thread_data->dupes);
	free(thread_data);
	free(job);

	datum_config.stratum_v1_max_clients_per_thread = saved_clients;
	datum_config.stratum_v1_vardiff_target_shares_min = saved_shares;
	datum_config.stratum_v1_share_stale_seconds = saved_stale;
}

// Every pointer reachable from the bucket index must name a live entry, and no chain may
// loop. A chain that loops never terminates in datum_stratum_check_for_dupe, which runs on
// the stratum thread with that thread's clients waiting on it.
static void datum_dupe_index_is_sound(const T_DATUM_STRATUM_DUPES *dupes) {
	for (int b = 0; b < 65536; ++b) {
		const T_DATUM_STRATUM_DUPE_ITEM *i = dupes->index[b];
		int walked = 0;
		while (i) {
			const ptrdiff_t slot = i - dupes->ptr;
			// Named rather than asserted inline, because datum_test reports the expression
			// it was given and these are what the reader wants to see in a failure
			const bool bucket_points_at_a_live_entry =
				slot >= 0 && slot < dupes->current_items;
			if (!datum_test(bucket_points_at_a_live_entry)) return;
			const bool bucket_chain_terminates = ++walked <= dupes->current_items;
			if (!datum_test(bucket_chain_terminates)) return;
			i = i->next;
		}
	}
}

// The other half of the cleanup, and the half a gateway actually reaches: entries old
// enough to age out are pruned rather than the array being grown. The prune sorts the
// array, which moves every entry, so an insertion point taken before it is stale after it
// in the same way a reallocation makes one stale.
static void datum_dupe_table_prune_tests(void) {
	const int saved_clients = datum_config.stratum_v1_max_clients_per_thread;
	const int saved_shares = datum_config.stratum_v1_vardiff_target_shares_min;
	const int saved_stale = datum_config.stratum_v1_share_stale_seconds;

	datum_config.stratum_v1_max_clients_per_thread = 1;
	datum_config.stratum_v1_vardiff_target_shares_min = 1;
	datum_config.stratum_v1_share_stale_seconds = 60;

	T_DATUM_STRATUM_THREADPOOL_DATA * const thread_data = calloc(1, sizeof(*thread_data));
	datum_test(thread_data != NULL);
	if (!thread_data) return;
	datum_stratum_dupes_init(thread_data);
	T_DATUM_STRATUM_DUPES * const dupes = thread_data->dupes;

	// Job 1 is current, job 2 is old enough for its shares to age out. A real gateway has
	// both at once: the jobs it is handing out now, and the ones from a few minutes ago.
	T_DATUM_STRATUM_JOB * const fresh = calloc(1, sizeof(*fresh));
	T_DATUM_STRATUM_JOB * const old = calloc(1, sizeof(*old));
	T_DATUM_STRATUM_JOB * const saved_fresh = global_cur_stratum_jobs[1];
	T_DATUM_STRATUM_JOB * const saved_old = global_cur_stratum_jobs[2];
	datum_test(fresh != NULL && old != NULL);
	if (!fresh || !old) { free(fresh); free(old); free(thread_data); return; }
	fresh->tsms = current_time_millis();
	old->tsms = current_time_millis() - 600000;
	global_cur_stratum_jobs[1] = fresh;
	global_cur_stratum_jobs[2] = old;

	// Eight byte aligned. datum_stratum_add_new_dupe on this branch reads the extranonce
	// back through a uint64_t cast, which is a misaligned load on a plain char array and
	// something UBSan reports. That is a separate issue from what these tests cover.
	uint64_t extranonce_storage[2] = {0};
	unsigned char * const extranonce = (unsigned char *)extranonce_storage;

	// Mostly stale, so the cleanup frees well over its 5% and takes the prune path
	for (int i = 0; i < 256; ++i) {
		const unsigned int nonce = ((unsigned int)i << 16) | (unsigned int)((i * 11) + 3);
		const unsigned short job = (i % 8) ? 2 : 1;
		datum_stratum_check_for_dupe(thread_data, nonce, job, 2000 + i, 0, extranonce);
		datum_dupe_index_is_sound(dupes);
	}

	global_cur_stratum_jobs[1] = saved_fresh;
	global_cur_stratum_jobs[2] = saved_old;
	free(dupes->ptr);
	free(thread_data->dupes);
	free(thread_data);
	free(fresh);
	free(old);

	datum_config.stratum_v1_max_clients_per_thread = saved_clients;
	datum_config.stratum_v1_vardiff_target_shares_min = saved_shares;
	datum_config.stratum_v1_share_stale_seconds = saved_stale;
}

// Many cleanup cycles of both kinds, against the invariant the insert now relies on:
// datum_stratum_check_for_dupe must leave room for the next entry, every time. If it ever
// does not, datum_stratum_add_new_dupe refuses a share's dupe record and says so in the
// log, which is a thing an operator should never see.
//
// Both kinds matter because they fail differently. A prune sorts the array in place and an
// expand reallocates it, and before the fix each left a different flavour of stale pointer
// in the bucket index.
static void datum_dupe_table_cycle_tests(void) {
	const int saved_clients = datum_config.stratum_v1_max_clients_per_thread;
	const int saved_shares = datum_config.stratum_v1_vardiff_target_shares_min;
	const int saved_stale = datum_config.stratum_v1_share_stale_seconds;

	datum_config.stratum_v1_max_clients_per_thread = 2;
	datum_config.stratum_v1_vardiff_target_shares_min = 2;
	datum_config.stratum_v1_share_stale_seconds = 60;

	T_DATUM_STRATUM_THREADPOOL_DATA * const thread_data = calloc(1, sizeof(*thread_data));
	datum_test(thread_data != NULL);
	if (!thread_data) return;
	datum_stratum_dupes_init(thread_data);
	T_DATUM_STRATUM_DUPES * const dupes = thread_data->dupes;
	const int initial_max = dupes->max_items;

	// Job 0 included deliberately. It is a real job slot on a running gateway, and a zeroed
	// table entry reads as job_index 0, so the sort consults job 0 for entries that are not
	// entries. Keeping it live here is the arrangement that would expose that if it bit.
	T_DATUM_STRATUM_JOB * const jobs = calloc(4, sizeof(*jobs));
	T_DATUM_STRATUM_JOB *saved[4];
	datum_test(jobs != NULL);
	if (!jobs) { free(thread_data); return; }
	for (int j = 0; j < 4; ++j) {
		saved[j] = global_cur_stratum_jobs[j];
		global_cur_stratum_jobs[j] = &jobs[j];
	}

	// Eight byte aligned. datum_stratum_add_new_dupe on this branch reads the extranonce
	// back through a uint64_t cast, which is a misaligned load on a plain char array and
	// something UBSan reports. That is a separate issue from what these tests cover.
	uint64_t extranonce_storage[2] = {0};
	unsigned char * const extranonce = (unsigned char *)extranonce_storage;
	bool saw_expand = false;

	for (int i = 0; i < 20000; ++i) {
		// Jobs age as the run goes on, so cleanups alternate between having plenty to
		// prune and having nothing to prune and needing to grow.
		const uint64_t now = current_time_millis();
		jobs[0].tsms = now;
		jobs[1].tsms = now;
		jobs[2].tsms = (i % 3) ? now - 600000 : now;
		jobs[3].tsms = (i % 7) ? now - 600000 : now;

		const unsigned int nonce = ((unsigned int)i * 2654435761u) ^ ((unsigned int)i << 13);
		extranonce[0] = (unsigned char)i;
		extranonce[11] = (unsigned char)(i >> 8);

		// A table that is not yet full cannot clean up during the call, so a share that is
		// not a duplicate has to become exactly one new entry. Anything else means the
		// insert refused it, which is the only way the fix can go wrong quietly: the share
		// is still accepted, but nothing remembers it and a real resubmission slips past.
		const int before = dupes->current_items;
		const bool had_room = before < dupes->max_items;
		const bool dupe = datum_stratum_check_for_dupe(thread_data, nonce,
			(unsigned short)(i & 3), 3000 + (i & 0xff), (unsigned int)i, extranonce);
		if (had_room && !dupe) {
			const bool the_new_share_became_an_entry =
				dupes->current_items == before + 1;
			datum_test(the_new_share_became_an_entry);
		}

		// Never past the end of the array, cleanup or no cleanup
		const bool entries_fit_the_array = dupes->current_items <= dupes->max_items;
		datum_test(entries_fit_the_array);
		if (dupes->max_items > initial_max) saw_expand = true;
	}

	datum_dupe_index_is_sound(dupes);
	datum_test(saw_expand);

	for (int j = 0; j < 4; ++j) global_cur_stratum_jobs[j] = saved[j];
	free(dupes->ptr);
	free(thread_data->dupes);
	free(thread_data);
	free(jobs);

	datum_config.stratum_v1_max_clients_per_thread = saved_clients;
	datum_config.stratum_v1_vardiff_target_shares_min = saved_shares;
	datum_config.stratum_v1_share_stale_seconds = saved_stale;
}

void datum_stratum_dupes_tests(void) {
	datum_dupe_table_fill_tests();
	datum_dupe_table_prune_tests();
	datum_dupe_table_cycle_tests();
}
