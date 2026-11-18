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
 * Copyright (c) 2025 Bitcoin Ocean, LLC & Luke Dashjr
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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "datum_jsonrpc.h"
#include "datum_logger.h"
#include "datum_protocol.h"
#include "datum_queue.h"
#include "datum_stratum_dupes.h"
#include "datum_stratum.h"
#include "datum_utils.h"

void datum_stratum_mod_username_tests() {
	const char * const s_umods = "{\"x\":{\"addrA\": 0.3}, \"abc\":{\"addrB\":0.3,\"addrC\":0.3},\":)\":{\"\":0.5}}";
	json_error_t err;
	json_t * const j_umods = JSON_LOADS(s_umods, &err);
	assert(j_umods);
	struct datum_username_mod *umods = NULL;
	int ret = datum_config_parse_username_mods(&umods, j_umods, false);
	assert(ret == 1);
	json_decref(j_umods);
	datum_config.stratum_username_mod = umods;
	
	char buf[0x100];
	char * const pool_addr = datum_config.mining_pool_address;
	char *s, *modname;
	const char *res, *a1, *a2;
	
	strcpy(pool_addr, "dummy");
	
	s = "def~G";
	modname = &s[4];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 1) == s);
	
	s = "def~x";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 1) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 1) == pool_addr);
	
	s = "def~abc";
	modname = &s[4];
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3);
	if (0 == strcmp(res, "addrB")) {  // jansson doesn't order keys'
		a1 = "addrB";
		a2 = "addrC";
	} else {
		a1 = "addrC";
		a2 = "addrB";
	}
	datum_test(0 == strcmp(res, a1));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 3);
	datum_test(0 == strcmp(res, a1));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 3);
	datum_test(0 == strcmp(res, a2));
	memset(buf, 0, 5);
	res = datum_stratum_mod_username(s, buf, sizeof(buf), 0x9999, modname, 3);
	datum_test(0 == strcmp(res, a2));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x999a, modname, 3) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 3) == pool_addr);
	
	s = "def.ghi~abc";
	modname = &s[8];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a1, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccc, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a1, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x4ccd, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a2, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	memset(buf, 0, 8);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x9999, modname, 3) == buf);
	datum_test(0 == strncmp(buf, a2, 5));
	datum_test(0 == strcmp(&buf[5], ".ghi"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x999a, modname, 3) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 3) == pool_addr);
	
	s = "def.ghi~:)";
	modname = &s[8];
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0, modname, 2) == buf);
	datum_test(0 == strcmp(buf, "def.ghi"));
	memset(buf, 0, 7);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x7fff, modname, 2) == buf);
	datum_test(0 == strcmp(buf, "def.ghi"));
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0x8000, modname, 2) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, sizeof(buf), 0xffff, modname, 2) == pool_addr);
	
	// Intentionally overflow buf with address: we lose the worker name, but get the full address via its umod buffer
	s = "def.ghi~x";
	modname = &s[8];
	memset(buf, 0x0e, 8);
	res = datum_stratum_mod_username(s, buf, 2, 0, modname, 1);
	datum_test(res != buf);
	datum_test(res != pool_addr);
	datum_test(buf[2] == 0x0e);
	datum_test(0 == strcmp(res, "addrA"));
	res = datum_stratum_mod_username(s, buf, 2, 0x4ccc, modname, 1);
	datum_test(0 == strcmp(res, "addrA"));
	datum_test(datum_stratum_mod_username(s, buf, 2, 0x4ccd, modname, 1) == pool_addr);
	datum_test(datum_stratum_mod_username(s, buf, 2, 0xffff, modname, 1) == pool_addr);
	datum_test(buf[2] == 0x0e);
	datum_test(buf[6] == 0x0e);
	res = datum_stratum_mod_username(s, buf, 6, 0, modname, 1);
	datum_test(res == buf);
	datum_test(res != pool_addr);
	datum_test(buf[6] == 0x0e);
	datum_test(0 == strcmp(res, "addrA"));
	memset(buf, 0x0e, 9);
	datum_test(datum_stratum_mod_username(s, buf, 7, 0, modname, 1) == buf);
	datum_test(buf[8] == 0x0e);
	datum_test(0 == strcmp(res, "addrA."));
	memset(buf, 0x0e, 10);
	datum_test(datum_stratum_mod_username(s, buf, 8, 0, modname, 1) == buf);
	datum_test(buf[9] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.g"));
	memset(buf, 0x0e, 11);
	datum_test(datum_stratum_mod_username(s, buf, 9, 0, modname, 1) == buf);
	datum_test(buf[10] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.gh"));
	memset(buf, 0x0e, 12);
	datum_test(datum_stratum_mod_username(s, buf, 10, 0, modname, 1) == buf);
	datum_test(buf[11] == 0x0e);
	datum_test(0 == strcmp(res, "addrA.ghi"));
	s = "def.ghi~:)";
	modname = &s[8];
	memset(buf, 0x0e, 9);
	datum_test(datum_stratum_mod_username(s, buf, 2, 0, modname, 2) == buf);
	datum_test(buf[2] == 0x0e);
	datum_test(0 == strcmp(res, "d"));
	datum_test(datum_stratum_mod_username(s, buf, 6, 0, modname, 2) == buf);
	datum_test(buf[6] == 0x0e);
	datum_test(0 == strcmp(res, "def.g"));
	datum_test(datum_stratum_mod_username(s, buf, 7, 0, modname, 2) == buf);
	datum_test(buf[7] == 0x0e);
	datum_test(0 == strcmp(res, "def.gh"));
	datum_test(datum_stratum_mod_username(s, buf, 8, 0, modname, 2) == buf);
	datum_test(buf[8] == 0x0e);
	datum_test(0 == strcmp(res, "def.ghi"));
}

// A share for an older job, once a harder difficulty is served, gets the served difficulty if
// it meets it and nothing otherwise.
static void datum_stratum_share_credit_tests(void) {
	unsigned char t_easy[32], t_hard[32];
	get_target_from_diff(t_easy, 1024);
	get_target_from_diff(t_hard, 16384);
	datum_test(datum_stratum_share_credit_diff(t_hard, 1024, 16384) == 16384);
	datum_test(datum_stratum_share_credit_diff(t_easy, 1024, 16384) == 0);
	datum_test(datum_stratum_share_credit_diff(t_easy, 1024, 1024) == 1024);
	datum_test(datum_stratum_share_credit_diff(t_hard, 16384, 1024) == 16384);
}

static T_DATUM_CLIENT_DATA *datum_stratum_test_client(void) {
	T_DATUM_MINER_DATA * const m = calloc(1, sizeof(T_DATUM_MINER_DATA));
	T_DATUM_STRATUM_THREADPOOL_DATA * const sd = calloc(1, sizeof(T_DATUM_STRATUM_THREADPOOL_DATA));
	T_DATUM_CLIENT_DATA * const c = calloc(1, sizeof(T_DATUM_CLIENT_DATA));
	T_DATUM_THREAD_DATA * const t = calloc(1, sizeof(T_DATUM_THREAD_DATA));
	assert(m && sd && c && t);
	m->sdata = sd;
	c->app_client_data = m;
	c->datum_thread = t;
	c->cid = 1;
	t->app_thread_data = sd;
	return c;
}

static void datum_stratum_test_client_free(T_DATUM_CLIENT_DATA *c) {
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	free(c->datum_thread);
	free(m->sdata);
	free(m);
	free(c);
}

static const char *datum_stratum_test_take(T_DATUM_CLIENT_DATA *c) {
	c->w_buffer[c->out_buf] = 0;
	c->out_buf = 0;
	return c->w_buffer;
}

// Vardiff measures the rate at the difficulty now served.
static void datum_stratum_vardiff_measure_tests(void) {
	const global_config_t saved = datum_config;
	datum_config.stratum_v1_vardiff_min = 1024;
	datum_config.stratum_v1_vardiff_target_shares_min = 1;
	datum_config.stratum_v1_vardiff_quickdiff_count = 8;
	datum_config.stratum_v1_vardiff_quickdiff_delta = 8;
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_client();
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	m->sdata->loop_tsms = 1000000;
	m->current_diff = m->last_sent_diff = 8192;
	
	// A new difficulty starts a new measurement.
	m->share_count_since_snap = 250;
	m->share_count_below_diff_since_snap = 3;
	m->current_diff = 16384;
	datum_test(send_mining_set_difficulty(c) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"mining.set_difficulty\",\"params\":[16384]") != NULL);
	datum_test(m->share_count_since_snap == 0 && m->share_count_below_diff_since_snap == 0);
	
	// A share credited at nothing is not counted; one credited at the served difficulty is.
	datum_stratum_count_vardiff_share(m, 0);
	datum_test(m->share_count_since_snap == 0 && m->share_count_below_diff_since_snap == 1);
	datum_stratum_count_vardiff_share(m, 16384);
	datum_test(m->share_count_since_snap == 1 && m->share_diff_since_snap == 16384);
	
	// Uncounted shares alone don't trigger a quickdiff, and a minute of only them is not
	// silence: a fresh minute starts and the count is cleared...
	reset_vardiff_stats(c);
	m->share_snap_tsms = m->sdata->loop_tsms - 2000;
	for (int i = 0; i < 9; ++i) datum_stratum_count_vardiff_share(m, 0);
	stratum_update_vardiff(c, false);
	datum_test(m->current_diff == 16384);
	m->share_snap_tsms = m->sdata->loop_tsms - 70000;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 16384);
	datum_test(m->share_count_below_diff_since_snap == 0);
	// ...and a miner that then finds nothing is stepped down a minute later, as before.
	m->share_snap_tsms = m->sdata->loop_tsms - 70000;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 8192);
	
	datum_stratum_test_client_free(c);
	datum_config = saved;
}

// A pooled job whose coinbase target byte sits at index 4 of a 20-byte coinb1 of 0x11s,
// with a template that accepts any ntime, and no share or block meeting its targets unless
// a test opens them up.
static T_DATUM_STRATUM_JOB *datum_stratum_test_pooled_job(void) {
	T_DATUM_STRATUM_JOB * const j = calloc(1, sizeof(*j));
	T_DATUM_TEMPLATE_DATA * const t = calloc(1, sizeof(*t));
	assert(j && t);
	j->is_datum_job = true;
	strcpy(j->job_id, "0000000000c0de");
	memset(j->prevhash, '0', 64);
	strcpy(j->version, "20000000");
	strcpy(j->nbits, "1d00ffff");
	strcpy(j->ntime, "6625406b");
	strcpy(j->merklebranches_full, "[]");
	j->target_pot_index = 4;
	j->coinbase[0].coinb1_len = 20;
	memset(j->coinbase[0].coinb1_bin, 0x11, 20);
	memset(j->coinbase[0].coinb1, '1', 40);
	memset(j->coinbase[0].coinb2, '2', 16);
	t->curtime = 0xffffff00;
	j->block_template = t;
	return j;
}

static void datum_stratum_test_pooled_job_free(T_DATUM_STRATUM_JOB *j) {
	free(j->block_template);
	free(j);
}

// Captures what client_mining_submit sends to the pool, via the real POW queue.
extern DATUM_QUEUE pow_queue;
extern int log_level_console;
static int datum_stratum_test_pow_handler(void *arg) { (void)arg; return 0; }

static int datum_stratum_test_pow_count(bool *last_is_block) {
	const int buf = pow_queue.active_buffer;
	const int n = pow_queue.queue_next[buf];
	if (n && last_is_block) *last_is_block = ((T_DATUM_PROTOCOL_POW *)pow_queue.buffer[buf])[n - 1].is_block;
	return n;
}

// Settings an accepted share needs (vardiff runs on each one).
static void datum_stratum_test_submit_config(void) {
	datum_config.stratum_v1_share_stale_seconds = 120;
	datum_config.stratum_v1_vardiff_min = 1024;
	datum_config.stratum_v1_vardiff_target_shares_min = 8;
	datum_config.stratum_v1_vardiff_quickdiff_count = 8;
	datum_config.stratum_v1_vardiff_quickdiff_delta = 8;
}

// A subscribed connection on job index 0, ready for client_mining_submit.
static T_DATUM_CLIENT_DATA *datum_stratum_test_submit_client(T_DATUM_STRATUM_JOB *job) {
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_client();
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	datum_stratum_dupes_init(m->sdata);
	m->sdata->loop_tsms = 1000000;
	job->tsms = m->sdata->loop_tsms;
	m->subscribed = true;
	m->current_diff = m->last_sent_diff = 1024;
	m->stratum_job_diffs[0] = 1024;
	return c;
}

static void datum_stratum_test_submit_client_free(T_DATUM_CLIENT_DATA *c) {
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	T_DATUM_STRATUM_DUPES * const dupes = m->sdata->dupes;
	free(dupes->ptr);
	free(dupes);
	datum_stratum_test_client_free(c);
}

// Submits extranonce2 0 with the given ntime and nonce. Every accepted share needs a hash whose
// top 32 bits are zero (H-not-zero), so the tests use ntime/nonce pairs found for their header.
static int datum_stratum_test_submit(T_DATUM_CLIENT_DATA *c, const char *job_id, uint32_t ntime, uint32_t nonce) {
	char req[160];
	snprintf(req, sizeof(req), "[\"w\", \"%s\", \"0000000000000000\", \"%08x\", \"%08x\"]", job_id, (unsigned)ntime, (unsigned)nonce);
	json_error_t err;
	json_t * const params = json_loads(req, 0, &err);
	assert(params);
	const int ret = client_mining_submit(c, 1, params);
	json_decref(params);
	return ret;
}

// A quickdiff (Q) share is only for the job its quickdiff notify was sent for, and the check
// comes after the block check, so a block in such a share is still submitted. One ntime/nonce
// serves all three shares: a refused Q share never reaches the dupe check.
#define Q_NTIME 0x6625406c
#define Q_NONCE 0xcfbde4b9
static void datum_stratum_quickdiff_job_tests(void) {
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	T_DATUM_STRATUM_JOB * const job = datum_stratum_test_pooled_job();
	T_DATUM_STRATUM_JOB * const saved_job0 = global_cur_stratum_jobs[0];
	global_cur_stratum_jobs[0] = job;
	datum_test(datum_queue_prep(&pow_queue, 16, sizeof(T_DATUM_PROTOCOL_POW), datum_stratum_test_pow_handler) == 0);
	bool is_block = false;
	
	T_DATUM_CLIENT_DATA *c = datum_stratum_test_submit_client(job);
	T_DATUM_MINER_DATA *m = c->app_client_data;
	m->quickdiff_value = 4096;
	memset(m->quickdiff_target, 0xff, 32);
	
	// A Q share for another job is refused, and nothing is sent upstream.
	m->quickdiff_job_index = 7;
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", Q_NTIME, Q_NONCE) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") == NULL);
	datum_test(m->share_count_rejected == 1 && m->share_count_accepted == 0);
	datum_test(datum_stratum_test_pow_count(NULL) == 0);
	
	// A Q share for its own job is accepted and forwarded.
	m->quickdiff_job_index = 0;
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", Q_NTIME, Q_NONCE) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_rejected == 1 && m->share_count_accepted == 1);
	datum_test(datum_stratum_test_pow_count(&is_block) == 1 && !is_block);
	
	// A block in a Q share for another job is still submitted, then the share is refused. The
	// node submission fails at once (no RPC URL); its logging is muted.
	memset(job->block_target, 0xff, 32);
	m->quickdiff_job_index = 7;
	datum_config.bitcoind_rpcurl[0] = 0;
	const int saved_log_level = log_level_console;
	log_level_console = DLOG_LEVEL_FATAL;
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", Q_NTIME, Q_NONCE) == 0);
	log_level_console = saved_log_level;
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") == NULL);
	datum_test(m->share_count_rejected == 2 && m->share_count_accepted == 1);
	datum_test(datum_stratum_test_pow_count(&is_block) == 2 && is_block);
	memset(job->block_target, 0, 32);
	
	datum_stratum_test_submit_client_free(c);
	datum_queue_free(&pow_queue);
	global_cur_stratum_jobs[0] = saved_job0;
	datum_stratum_test_pooled_job_free(job);
	datum_config = saved;
}
// The quickdiff is bound to the job it was sent for whatever its index: here job index 1,
// through send_mining_notify, and a Q share for it is accepted.
static void datum_stratum_quickdiff_job_index_tests(void) {
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	T_DATUM_STRATUM_JOB * const job = datum_stratum_test_pooled_job();
	strcpy(job->job_id, "0000000000c0df");
	job->global_index = 1;
	T_DATUM_STRATUM_JOB * const saved_job1 = global_cur_stratum_jobs[1];
	global_cur_stratum_jobs[1] = job;
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_submit_client(job);
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	m->sdata->cur_stratum_job = job;
	m->share_snap_tsms = m->sdata->loop_tsms;
	
	datum_test(send_mining_notify(c, true, false, false) == 0);
	m->current_diff = 4096;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"mining.notify\",\"params\":[\"Q0000000000c0df00") != NULL);
	datum_test(m->quickdiff_job_index == 1 && m->quickdiff_value == 4096);
	// (Its target is opened up: no share meeting 4096 can be found in a test.)
	memset(m->quickdiff_target, 0xff, 32);
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0df00", Q_NTIME, Q_NONCE) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_accepted == 1 && m->share_count_rejected == 0);
	
	datum_stratum_test_submit_client_free(c);
	global_cur_stratum_jobs[1] = saved_job1;
	datum_stratum_test_pooled_job_free(job);
	datum_config = saved;
}
#undef Q_NTIME
#undef Q_NONCE

// A Q share not bound to the current quickdiff fails H-not-zero (it is rebuilt with the wrong
// target byte) and is answered as unknown work at the difficulty now served, not as a high
// hash. A bound share failing H-not-zero is refused for what it is.
static void datum_stratum_unbound_quickdiff_tests(void) {
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	T_DATUM_STRATUM_JOB * const job = datum_stratum_test_pooled_job();
	T_DATUM_STRATUM_JOB * const saved_job0 = global_cur_stratum_jobs[0];
	global_cur_stratum_jobs[0] = job;
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_submit_client(job);
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	
	// With no quickdiff sent (the job index matches the empty entry's 0).
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", 0x6625406b, 1) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "unknown-work") != NULL);
	datum_test(m->share_count_rejected == 1 && m->share_diff_rejected == 1024);
	
	// For another job, and failing H-not-zero (nonce 1 is far from a valid share).
	m->quickdiff_value = 4096;
	m->quickdiff_job_index = 7;
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", 0x6625406b, 1) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "unknown-work") != NULL);
	datum_test(m->share_count_rejected == 2 && m->share_diff_rejected == 2048);
	
	// Bound to the current quickdiff: refused as H-not-zero, at the quickdiff difficulty.
	m->quickdiff_job_index = 0;
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", 0x6625406b, 1) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "H-not-zero") != NULL);
	datum_test(m->share_count_rejected == 3 && m->share_diff_rejected == 2048 + 4096);
	
	datum_stratum_test_submit_client_free(c);
	global_cur_stratum_jobs[0] = saved_job0;
	datum_stratum_test_pooled_job_free(job);
	datum_config = saved;
}

// A connection that has subscribed (and been told 1024) to pooled work whose pool minimum,
// 2^20, is far above the local floor.
static T_DATUM_CLIENT_DATA *datum_stratum_pool_min_client(T_DATUM_STRATUM_JOB *job) {
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_client();
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	m->sdata->cur_stratum_job = job;
	m->current_diff = m->last_sent_diff = 1024;
	return c;
}

static void datum_stratum_vardiff_below_pool_min_tests(void) {
	const global_config_t saved = datum_config;
	T_DATUM_STRATUM_JOB * const job = datum_stratum_test_pooled_job();
	const uint64_t pool_min = UINT64_C(1) << 20;
	datum_config.stratum_v1_vardiff_min = 1024;
	datum_config.override_vardiff_min = pool_min;
	datum_config.stratum_v1_vardiff_target_shares_min = 1;
	datum_config.stratum_v1_vardiff_quickdiff_count = 8;
	datum_config.stratum_v1_vardiff_quickdiff_delta = 8;
	const char *out;
	// coinb1 as sent: target byte 0x14 (2^20) at index 4, whatever the miner is served.
	const char * const committed_cb1 = "\"1111111114111111";
	
	// Off (the default): the miner is raised to the pool minimum, as before.
	datum_config.stratum_v1_vardiff_below_pool_min = false;
	T_DATUM_CLIENT_DATA *c = datum_stratum_pool_min_client(job);
	T_DATUM_MINER_DATA *m = c->app_client_data;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	out = datum_stratum_test_take(c);
	datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[1048576]") != NULL);
	datum_test(m->stratum_job_diffs[0] == pool_min);
	datum_test(m->stratum_job_commit_pots[0] == 0);
	datum_test(strstr(out, committed_cb1) != NULL);
	datum_stratum_test_client_free(c);
	
	// Off, while the protocol thread holds a raw minimum that isn't a power of two: exactly as
	// before, raised to the raw value and committed at it, with no separate commitment.
	datum_config.override_vardiff_min = 3 * (UINT64_C(1) << 18);
	c = datum_stratum_pool_min_client(job);
	m = c->app_client_data;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"1111111113111111") != NULL);
	datum_test(m->stratum_job_diffs[0] == 3 * (UINT64_C(1) << 18));
	datum_test(m->stratum_job_commit_pots[0] == 0);
	datum_stratum_test_client_free(c);
	datum_config.override_vardiff_min = pool_min;
	
	// On: the miner keeps its own difficulty, and the work is still committed to the minimum.
	datum_config.stratum_v1_vardiff_below_pool_min = true;
	c = datum_stratum_pool_min_client(job);
	m = c->app_client_data;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	out = datum_stratum_test_take(c);
	datum_test(strstr(out, "mining.set_difficulty") == NULL);
	datum_test(m->stratum_job_diffs[0] == 1024);
	datum_test(m->stratum_job_commit_pots[0] == 20);
	datum_test(strstr(out, committed_cb1) != NULL);
	
	// A quickdiff stays new work (the 0x5144 marker ends coinb1) and keeps the commitment.
	m->current_diff = 16384;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	out = datum_stratum_test_take(c);
	datum_test(strstr(out, "\"mining.set_difficulty\",\"params\":[16384]") != NULL);
	datum_test(strstr(out, "\"mining.notify\",\"params\":[\"Q") != NULL);
	datum_test(strstr(out, "11111111111111114451\"") != NULL);
	datum_test(strstr(out, committed_cb1) != NULL);
	datum_test(m->quickdiff_value == 16384);
	datum_test(m->quickdiff_commit_pot == 20);
	datum_test(m->quickdiff_job_index == 0);
	
	datum_stratum_test_client_free(c);
	
	// Served exactly at the minimum: committed at its own difficulty, with no separate commitment.
	c = datum_stratum_pool_min_client(job);
	m = c->app_client_data;
	m->current_diff = m->last_sent_diff = pool_min;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	datum_test(m->stratum_job_commit_pots[0] == 0);
	datum_test(strstr(datum_stratum_test_take(c), committed_cb1) != NULL);
	datum_stratum_test_client_free(c);
	
	// Served above the minimum: committed at the served difficulty, as without the option.
	c = datum_stratum_pool_min_client(job);
	m = c->app_client_data;
	m->current_diff = m->last_sent_diff = UINT64_C(1) << 22;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	datum_test(m->stratum_job_commit_pots[0] == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"1111111116111111") != NULL);
	datum_stratum_test_client_free(c);
	
	// A raw pool minimum that is not a power of two is rounded up, as the pool applies it:
	// 3*2^18 commits at 2^20, never at 2^19.
	datum_config.override_vardiff_min = 3 * (UINT64_C(1) << 18);
	datum_test(datum_stratum_pool_min_diff() == pool_min);
	c = datum_stratum_pool_min_client(job);
	m = c->app_client_data;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	datum_test(m->stratum_job_commit_pots[0] == 20);
	datum_test(strstr(datum_stratum_test_take(c), committed_cb1) != NULL);
	datum_stratum_test_client_free(c);
	datum_config.override_vardiff_min = UINT64_MAX;
	datum_test(datum_stratum_pool_min_diff() == (UINT64_C(1) << 63));
	datum_config.override_vardiff_min = pool_min;
	
	// Switched off at runtime: the next job, and the next quickdiff, carry no separate commitment.
	c = datum_stratum_pool_min_client(job);
	m = c->app_client_data;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	datum_test(m->stratum_job_commit_pots[0] == 20);
	m->current_diff = 16384;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	datum_test(m->quickdiff_commit_pot == 20);
	datum_config.stratum_v1_vardiff_below_pool_min = false;
	datum_test(send_mining_notify(c, true, false, false) == 0);
	datum_test(m->stratum_job_commit_pots[0] == 0);
	strcpy(job->job_id, "0000000100c0de");  // new work, so the quickdiff goes out
	datum_test(send_mining_notify(c, true, true, false) == 0);
	datum_test(m->quickdiff_commit_pot == 0);
	(void)datum_stratum_test_take(c);
	strcpy(job->job_id, "0000000000c0de");
	datum_config.stratum_v1_vardiff_below_pool_min = true;
	datum_stratum_test_client_free(c);
	
	// The forwarding decision.
	unsigned char served[32], committed[32];
	get_target_from_diff(served, 1024);
	get_target_from_diff(committed, pool_min);
	datum_test(datum_stratum_share_forwardable(committed, 20));
	datum_test(!datum_stratum_share_forwardable(served, 20));
	datum_test(datum_stratum_share_forwardable(served, 0));
	datum_test(!datum_stratum_share_forwardable(committed, 64));
	
	datum_stratum_test_pooled_job_free(job);
	datum_config = saved;
}

// Through client_mining_submit: a share between the served and committed targets is accepted
// but not sent to the pool, and a share for work committed at its own difficulty is sent.
// A share meeting a 2^20 commitment can't be found in a test, so that case is covered by
// datum_stratum_share_forwardable above. The served target is opened up so that any hash
// passing H-not-zero is accepted.
static void datum_stratum_submit_forwarding_tests(void) {
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	datum_config.stratum_v1_vardiff_below_pool_min = true;
	T_DATUM_STRATUM_JOB * const job = datum_stratum_test_pooled_job();
	T_DATUM_STRATUM_JOB * const saved_job0 = global_cur_stratum_jobs[0];
	global_cur_stratum_jobs[0] = job;
	datum_test(datum_queue_prep(&pow_queue, 16, sizeof(T_DATUM_PROTOCOL_POW), datum_stratum_test_pow_handler) == 0);
	bool is_block = true;
	
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_submit_client(job);
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	memset(m->stratum_job_targets[0], 0xff, 32);
	
	// Served 1024, committed 2^20: accepted, kept local.
	m->stratum_job_commit_pots[0] = 20;
	datum_test(datum_stratum_test_submit(c, "0000000000c0de00", 0x6625406c, 0x3623e3a7) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_accepted == 1);
	datum_test(datum_stratum_test_pow_count(NULL) == 0);
	
	// Served at 2^20 and committed there (no separate commitment, the same coinbase): accepted
	// and forwarded. The same ntime/nonce is resubmitted, so start a fresh dupe table.
	T_DATUM_STRATUM_DUPES * const dupes = m->sdata->dupes;
	free(dupes->ptr);
	free(dupes);
	datum_stratum_dupes_init(m->sdata);
	m->stratum_job_commit_pots[0] = 0;
	m->current_diff = m->last_sent_diff = m->stratum_job_diffs[0] = UINT64_C(1) << 20;
	datum_test(datum_stratum_test_submit(c, "0000000000c0de00", 0x6625406c, 0x3623e3a7) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_accepted == 2);
	datum_test(datum_stratum_test_pow_count(&is_block) == 1 && !is_block);
	
	// Both were credited at their job's difficulty, in the connection totals and the stats.
	const uint64_t credited = 1024 + (UINT64_C(1) << 20);
	datum_test(m->share_diff_accepted == credited);
	datum_test(m->stats.diff_accepted[0] + m->stats.diff_accepted[1] == credited);
	
	// After a step up to 2^22, the same share for the 2^20 job misses the served target: accepted,
	// and credited at nothing (see datum_stratum_share_credit_diff).
	free(m->sdata->dupes ? ((T_DATUM_STRATUM_DUPES *)m->sdata->dupes)->ptr : NULL);
	free(m->sdata->dupes);
	datum_stratum_dupes_init(m->sdata);
	m->current_diff = m->last_sent_diff = UINT64_C(1) << 22;
	datum_test(datum_stratum_test_submit(c, "0000000000c0de00", 0x6625406c, 0x3623e3a7) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_accepted == 3);
	datum_test(m->share_diff_accepted == credited);
	datum_test(m->stats.diff_accepted[0] + m->stats.diff_accepted[1] == credited);
	
	datum_stratum_test_submit_client_free(c);
	datum_queue_free(&pow_queue);
	global_cur_stratum_jobs[0] = saved_job0;
	datum_stratum_test_pooled_job_free(job);
	datum_config = saved;
}

// A quickdiff that lifts the miner above the pool minimum is committed at its own difficulty,
// though the job it is for was committed at the minimum: its Q share is rebuilt with the
// quickdiff's target byte (2^22), not the job's (2^20).
static void datum_stratum_quickdiff_above_min_tests(void) {
	const global_config_t saved = datum_config;
	datum_stratum_test_submit_config();
	datum_config.stratum_v1_vardiff_below_pool_min = true;
	datum_config.override_vardiff_min = UINT64_C(1) << 20;
	T_DATUM_STRATUM_JOB * const job = datum_stratum_test_pooled_job();
	T_DATUM_STRATUM_JOB * const saved_job0 = global_cur_stratum_jobs[0];
	global_cur_stratum_jobs[0] = job;
	T_DATUM_CLIENT_DATA * const c = datum_stratum_test_submit_client(job);
	T_DATUM_MINER_DATA * const m = c->app_client_data;
	m->sdata->cur_stratum_job = job;
	m->share_snap_tsms = m->sdata->loop_tsms;
	
	datum_test(send_mining_notify(c, true, false, false) == 0);
	datum_test(m->stratum_job_commit_pots[0] == 20);
	m->current_diff = UINT64_C(1) << 22;
	datum_test(send_mining_notify(c, true, true, false) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"mining.notify\",\"params\":[\"Q") != NULL);
	datum_test(m->quickdiff_commit_pot == 0);
	// (Its target is opened up: no share meeting 2^22 can be found in a test.)
	memset(m->quickdiff_target, 0xff, 32);
	datum_test(datum_stratum_test_submit(c, "Q0000000000c0de00", 0x6625406c, 0x98f742c1) == 0);
	datum_test(strstr(datum_stratum_test_take(c), "\"result\":true") != NULL);
	datum_test(m->share_count_accepted == 1 && m->share_count_rejected == 0);
	
	datum_stratum_test_submit_client_free(c);
	global_cur_stratum_jobs[0] = saved_job0;
	datum_stratum_test_pooled_job_free(job);
	datum_config = saved;
}

void datum_stratum_tests(void) {
	datum_stratum_mod_username_tests();
	datum_stratum_share_credit_tests();
	datum_stratum_vardiff_measure_tests();
	datum_stratum_quickdiff_job_tests();
	datum_stratum_quickdiff_job_index_tests();
	datum_stratum_unbound_quickdiff_tests();
	datum_stratum_vardiff_below_pool_min_tests();
	datum_stratum_submit_forwarding_tests();
	datum_stratum_quickdiff_above_min_tests();
}
