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
 * Copyright (c) 2025 Bitcoin Ocean, LLC & Jason Hughes
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
#include <string.h>

#include "datum_blocktemplates.h"
#include "datum_conf.h"
#include "datum_protocol.h"
#include "datum_stratum.h"
#include "datum_utils.h"

// Recognizable, non-repeating field values, so a mis-ordered or mis-sized
// field shows up as a mismatch rather than a coincidence.
static void datum_protocol_tests_fill_job(T_DATUM_STRATUM_JOB *job, T_DATUM_TEMPLATE_DATA *tmpl) {
	int i, k;
	
	memset(job, 0, sizeof(T_DATUM_STRATUM_JOB));
	memset(tmpl, 0, sizeof(T_DATUM_TEMPLATE_DATA));
	
	for (i = 0; i < 32; i++) job->prevhash_bin[i] = (unsigned char)(0x40 + i);
	for (i = 0; i < 4; i++) job->nbits_bin[i] = (unsigned char)(0xE0 + i);
	
	job->target_pot_index = 0x1234;
	job->datum_coinbaser_id = 0x5A;
	job->height = 0x000A1B2C;
	job->coinbase_value = 0x0102030405060708ULL;
	
	tmpl->txn_count = 0x11223344;
	tmpl->txn_total_weight = 0x55667788;
	tmpl->txn_total_size = 0x99AABBCC;
	tmpl->txn_total_sigops = 0xDDEEFF00;
	job->block_template = tmpl;
	
	job->merklebranch_count = 3;
	for (k = 0; k < 3; k++) {
		for (i = 0; i < 32; i++) job->merklebranches_bin[k][i] = (unsigned char)((k * 32) + i);
	}
	
	for (k = 0; k < MAX_COINBASE_TYPES; k++) {
		job->coinbase[k].coinb1_len = 4 + k;
		job->coinbase[k].coinb2_len = 7 + k;
		for (i = 0; i < job->coinbase[k].coinb1_len; i++) job->coinbase[k].coinb1_bin[i] = (unsigned char)(0xA0 + (k * 16) + i);
		for (i = 0; i < job->coinbase[k].coinb2_len; i++) job->coinbase[k].coinb2_bin[i] = (unsigned char)(0xC0 + (k * 16) + i);
	}
	
	job->subsidy_only_coinbase.coinb1_len = 5;
	job->subsidy_only_coinbase.coinb2_len = 6;
	for (i = 0; i < 5; i++) job->subsidy_only_coinbase.coinb1_bin[i] = (unsigned char)(0x10 + i);
	for (i = 0; i < 6; i++) job->subsidy_only_coinbase.coinb2_bin[i] = (unsigned char)(0x20 + i);
}

// The reference encoding, written longhand as the share path built it before
// datum_protocol_append_job_data was factored out. The pool parses these
// bytes, so drift here is a wire protocol break.
static int datum_protocol_tests_reference_job_data(unsigned char *msg, int i, const T_DATUM_STRATUM_JOB *sjob, uint16_t target_byte_index) {
	msg[i] = 0x01; i++;
	memcpy(&msg[i], sjob->prevhash_bin, 32); i+=32;
	pk_u16le(msg, i, target_byte_index); i += 2;
	memcpy(&msg[i], &sjob->nbits_bin[0], sizeof(sjob->nbits_bin)); i += sizeof(sjob->nbits_bin);
	msg[i] = sjob->datum_coinbaser_id; i++;
	pk_u32le(msg, i, sjob->height); i += 4;
	pk_u64le(msg, i, sjob->coinbase_value); i += 8;
	
	pk_u32le(msg, i, sjob->block_template->txn_count); i += 4;
	pk_u32le(msg, i, sjob->block_template->txn_total_weight); i += 4;
	pk_u32le(msg, i, sjob->block_template->txn_total_size); i += 4;
	pk_u32le(msg, i, sjob->block_template->txn_total_sigops); i += 4;
	
	msg[i] = sjob->merklebranch_count; i++;
	
	memcpy(&msg[i], &sjob->merklebranches_bin[0][0], sjob->merklebranch_count * 32);
	i+=sjob->merklebranch_count * 32;
	
	return i;
}

static int datum_protocol_tests_reference_coinbase_data(unsigned char *msg, int i, const T_DATUM_STRATUM_COINBASE *coinbase, unsigned char coinbase_id) {
	msg[i] = 0x02; i++;
	msg[i] = coinbase_id; i++;
	pk_u16le(msg, i, coinbase->coinb1_len); i += 2;
	pk_u16le(msg, i, coinbase->coinb2_len); i += 2;
	memcpy(&msg[i], coinbase->coinb1_bin, coinbase->coinb1_len);
	i+=coinbase->coinb1_len;
	memcpy(&msg[i], coinbase->coinb2_bin, coinbase->coinb2_len);
	i+=coinbase->coinb2_len;
	
	return i;
}

// The share path and the announce path must hand the pool the same bytes for
// the same job, and those bytes must match what shipped before the refactor.
static void datum_protocol_tests_job_data_encoding(void) {
	T_DATUM_STRATUM_JOB job;
	T_DATUM_TEMPLATE_DATA tmpl;
	unsigned char got[4096], want[4096];
	int got_len, want_len, k;
	
	datum_protocol_tests_fill_job(&job, &tmpl);
	
	memset(got, 0, sizeof(got));
	memset(want, 0, sizeof(want));
	
	got_len = datum_protocol_append_job_data(got, 0, &job, job.target_pot_index);
	want_len = datum_protocol_tests_reference_job_data(want, 0, &job, job.target_pot_index);
	
	// 1 tag + 32 prevhash + 2 target index + 4 nbits + 1 coinbaser id + 4 height
	// + 8 value + 16 template counters + 1 branch count + 3 branches
	datum_test(want_len == 69 + (3 * 32));
	if (datum_test(got_len == want_len)) {
		datum_test(memcmp(got, want, want_len) == 0);
	}
	
	// Offsetting the write must not change the encoding, only where it lands.
	memset(got, 0, sizeof(got));
	datum_test(datum_protocol_append_job_data(got, 7, &job, job.target_pot_index) == want_len + 7);
	datum_test(memcmp(&got[7], want, want_len) == 0);
	
	for (k = 0; k < MAX_COINBASE_TYPES; k++) {
		memset(got, 0, sizeof(got));
		memset(want, 0, sizeof(want));
		got_len = datum_protocol_append_coinbase_data(got, 0, &job.coinbase[k], k);
		want_len = datum_protocol_tests_reference_coinbase_data(want, 0, &job.coinbase[k], k);
		datum_test(want_len == 6 + job.coinbase[k].coinb1_len + job.coinbase[k].coinb2_len);
		if (datum_test(got_len == want_len)) {
			datum_test(memcmp(got, want, want_len) == 0);
		}
	}
	
	// The subsidy only coinbase rides the same sub-block under id 0xFF.
	memset(got, 0, sizeof(got));
	memset(want, 0, sizeof(want));
	got_len = datum_protocol_append_coinbase_data(got, 0, &job.subsidy_only_coinbase, 0xFF);
	want_len = datum_protocol_tests_reference_coinbase_data(want, 0, &job.subsidy_only_coinbase, 0xFF);
	datum_test(got[1] == 0xFF);
	if (datum_test(got_len == want_len)) {
		datum_test(memcmp(got, want, want_len) == 0);
	}
}

// A field can sit in the config struct without ever being wired into the
// options table, in which case setting it in the config file silently does
// nothing. Pin the option to the field it is supposed to drive.
static void datum_protocol_tests_announce_option(void) {
	const T_DATUM_CONFIG_ITEM *opt = datum_config_get_option_info2("datum", "announce_jobs");

	if (datum_test(opt != NULL)) {
		datum_test(opt->var_type == DATUM_CONF_BOOL);
		datum_test(opt->ptr == &datum_config.datum_announce_jobs);
		// Sharing every template costs bandwidth, so this stays opt-in.
		datum_test(opt->default_bool == false);
	}
}

void datum_protocol_tests(void) {
	datum_protocol_tests_job_data_encoding();
	datum_protocol_tests_announce_option();
}
