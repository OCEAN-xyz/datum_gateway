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
#include "datum_stratum.h"
#include "datum_utils.h"

int client_mining_subscribe(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj);

void stratum_update_vardiff(T_DATUM_CLIENT_DATA *c, bool no_quick);

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

static void datum_stratum_password_opts_tests(void) {
	T_DATUM_MINER_DATA m;
	const int saved_client_min = datum_config.stratum_v1_vardiff_client_min;
	const int saved_vardiff_min = datum_config.stratum_v1_vardiff_min;
	const bool saved_password_difficulty = datum_config.stratum_v1_password_difficulty;

	datum_config.stratum_v1_vardiff_client_min = 1024;
	datum_config.stratum_v1_vardiff_min = 16384;

	// Off unless the operator turns it on. Before this the password was discarded, and
	// nobody knows what miners already put in it, so a password that happens to read as
	// a request must change nothing on a Gateway that has not opted in.
	datum_config.stratum_v1_password_difficulty = false;
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_stratum_apply_password_opts(&m, "d=8192");
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	datum_stratum_apply_password_opts(&m, "fd=8192");
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	datum_test(m.client_fixed_diff == false);

	datum_config.stratum_v1_password_difficulty = true;

	// The password miners already send. DATUM ignored it before this existed and must
	// keep ignoring it, or every existing miner's difficulty would move on upgrade.
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_stratum_apply_password_opts(&m, "x");
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	datum_test(m.client_fixed_diff == false);

	// Neither an absent password nor an empty one is a request for anything.
	datum_stratum_apply_password_opts(&m, NULL);
	datum_test(m.client_min_diff == 0);
	datum_stratum_apply_password_opts(&m, "");
	datum_test(m.client_min_diff == 0);

	// d= sets the starting difficulty and the floor. The floor is the point: without
	// it the first downward vardiff step would clamp back to vardiff_min.
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_stratum_apply_password_opts(&m, "d=8192");
	datum_test(m.client_min_diff == 8192);
	datum_test(m.current_diff == 8192);
	datum_test(m.client_fixed_diff == false);

	// fd= is the same value, held. stratum_update_vardiff returns early on this flag.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "fd=8192");
	datum_test(m.client_min_diff == 8192);
	datum_test(m.client_fixed_diff == true);

	// vardiff steps by halving and doubling, so a request that is not a power of two
	// rounds down: erring toward more shares rather than fewer.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=5000");
	datum_test(m.client_min_diff == 4096);

	// A rented rig cannot ask for difficulty 1 and bury the gateway in shares.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=1");
	datum_test(m.client_min_diff == 1024);

	// But the limit on requests must not be stricter than what the gateway already
	// gives every client unasked. A Gateway serving small BLAKE2b miners runs
	// vardiff_min at 64 so a slow hasher produces shares on connect; refusing to let
	// one ASK for 512 there would deny a request for strictly less load than the
	// default, which is the wrong way round.
	datum_config.stratum_v1_vardiff_min = 64;
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=512");
	datum_test(m.client_min_diff == 512);
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=1");
	datum_test(m.client_min_diff == 64);
	datum_config.stratum_v1_vardiff_min = 16384;

	// Rounding happens before the clamp, so a value just above the client floor
	// cannot round down through it.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=1500");
	datum_test(m.client_min_diff == 1024);

	// Asking above vardiff_min is allowed too: this is a floor, not just a way down.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=1048576");
	datum_test(m.client_min_diff == 1048576);

	// A client fingerprinted as needing high difficulty keeps it. That is a
	// compatibility workaround rather than an operator preference, and
	// stratum.fingerprint_miners already exists to turn it off.
	memset(&m, 0, sizeof(m));
	m.forced_high_min_diff = 524288;
	datum_stratum_apply_password_opts(&m, "d=8192");
	datum_test(m.client_min_diff == 524288);

	// Unparseable values leave the client where it was rather than at some default.
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_stratum_apply_password_opts(&m, "d=abc");
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	datum_stratum_apply_password_opts(&m, "d=");
	datum_test(m.client_min_diff == 0);
	datum_stratum_apply_password_opts(&m, "d=0");
	datum_test(m.client_min_diff == 0);

	// Keys this version does not know are skipped rather than aborting the parse, so
	// a newer miner talking to an older gateway still gets the part it understands.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "foo=1,d=8192,bar");
	datum_test(m.client_min_diff == 8192);

	// Both separators, and leading whitespace around a pair.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "u=whatever; d=2048");
	datum_test(m.client_min_diff == 2048);

	// A password longer than the parse buffer must not run off the end of it.
	{
		char big[1024];
		memset(big, 'a', sizeof(big) - 1);
		big[sizeof(big) - 1] = 0;
		memset(&m, 0, sizeof(m));
		datum_stratum_apply_password_opts(&m, big);
		datum_test(m.client_min_diff == 0);
	}

	// An unusable request is ignored rather than clamped to the bound, so the client
	// keeps ordinary vardiff instead of being parked at a difficulty a floor would
	// never let it come back down from.
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_stratum_apply_password_opts(&m, "d=35184372088832");   // 2^45
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	// strtoull saturates rather than failing, so a long run of digits arrives as
	// 2^64-1 and must not reach the target maths.
	datum_stratum_apply_password_opts(&m, "d=99999999999999999999999999");
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	// and the same for a fixed request
	datum_stratum_apply_password_opts(&m, "fd=35184372088832");
	datum_test(m.client_min_diff == 0);
	datum_test(m.client_fixed_diff == false);
	// The bound does not intrude on anything real. A miner running at an exahash
	// wants roughly 1.4e10 for a share a minute, far below this.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=1099511627776");   // 2^40
	datum_test(m.client_min_diff == (1ULL << 40));

	// The key has to be exactly "d" or "fd". A password that merely starts with those
	// letters and happens to contain digits must not be read as a difficulty: without
	// the check on the separator, "d12345" parses as a request for 345.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "diff=8192");
	datum_test(m.client_min_diff == 0);
	datum_stratum_apply_password_opts(&m, "d12345");
	datum_test(m.client_min_diff == 0);
	datum_stratum_apply_password_opts(&m, "fd12345");
	datum_test(m.client_min_diff == 0);
	datum_test(m.client_fixed_diff == false);

	datum_config.stratum_v1_vardiff_client_min = saved_client_min;
	datum_config.stratum_v1_vardiff_min = saved_vardiff_min;
	datum_config.stratum_v1_password_difficulty = saved_password_difficulty;
}

// A client that asked for a low difficulty has to keep it. Parsing the password is
// only half the feature: vardiff clamps every downward step to a floor, so without a
// per-client floor the request is undone on the first adjustment, which is to say it
// would do nothing for exactly the small miners it is meant to serve.
//
// Only the two downward paths are exercised here. They halve and clamp and return
// without touching a job, so they can be driven with a bare client; the upward and
// quickdiff paths send work and would need the whole template machinery.
static void datum_stratum_client_vardiff_floor_tests(void) {
	const int saved_client_min = datum_config.stratum_v1_vardiff_client_min;
	const int saved_vardiff_min = datum_config.stratum_v1_vardiff_min;
	const int saved_shares_min = datum_config.stratum_v1_vardiff_target_shares_min;

	T_DATUM_MINER_DATA * const m = calloc(1, sizeof(T_DATUM_MINER_DATA));
	T_DATUM_STRATUM_THREADPOOL_DATA * const sd = calloc(1, sizeof(T_DATUM_STRATUM_THREADPOOL_DATA));
	T_DATUM_CLIENT_DATA * const c = calloc(1, sizeof(T_DATUM_CLIENT_DATA));
	assert(m && sd && c);

	datum_config.stratum_v1_vardiff_client_min = 1024;
	datum_config.stratum_v1_vardiff_min = 16384;
	datum_config.stratum_v1_vardiff_target_shares_min = 8;

	m->sdata = sd;
	c->app_client_data = m;

	// Sixty seconds with no shares is the "difficulty is too high" path.
	sd->loop_tsms = 61000;

	// A client that asked for nothing still gets the operator's floor, unchanged.
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 0;
	m->current_diff = m->last_sent_diff = 32768;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 16384);

	// and does not fall through it on the next step either.
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 0;
	m->current_diff = m->last_sent_diff = 16384;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 16384);

	// A client that asked for 1024 keeps 1024. Before the per-client floor existed
	// this clamped back up to vardiff_min, which is the bug this feature is about.
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 0;
	m->client_min_diff = 1024;
	m->current_diff = m->last_sent_diff = 2048;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 1024);

	// and it is a floor, so it stops there rather than halving on forever.
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 0;
	m->current_diff = m->last_sent_diff = 1024;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 1024);

	// fd= holds the difficulty exactly, so this path does not run at all.
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 0;
	m->client_min_diff = 1024;
	m->client_fixed_diff = true;
	m->current_diff = m->last_sent_diff = 8192;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 8192);
	m->client_fixed_diff = false;

	// The other downward path: shares arriving slower than twice the target interval.
	// Target is 8 shares/minute, so 7500ms each; 40s per share is far slower.
	m->client_min_diff = 1024;
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 1;
	sd->loop_tsms = 40000;
	m->current_diff = m->last_sent_diff = 2048;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 1024);

	// and a fingerprinted client still keeps its compatibility floor on that path.
	m->client_min_diff = 1024;
	m->forced_high_min_diff = 524288;
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 1;
	m->current_diff = m->last_sent_diff = 1048576;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 524288);

	free(c);
	free(sd);
	free(m);

	datum_config.stratum_v1_vardiff_client_min = saved_client_min;
	datum_config.stratum_v1_vardiff_min = saved_vardiff_min;
	datum_config.stratum_v1_vardiff_target_shares_min = saved_shares_min;
}

// Nothing makes a miner subscribe before it authorizes, and some send authorize
// first. Subscribe used to reset the difficulty to vardiff_min unconditionally, so a
// password request read at authorize was lost, and fd=N was lost for good, because a
// fixed difficulty is never varied back. Driven through the real subscribe.
static void datum_stratum_password_before_subscribe_tests(void) {
	const int saved_client_min = datum_config.stratum_v1_vardiff_client_min;
	const int saved_vardiff_min = datum_config.stratum_v1_vardiff_min;
	const bool saved_password_difficulty = datum_config.stratum_v1_password_difficulty;
	const char * const pws[] = {"fd=65536", "d=8192", "x"};
	const uint64_t want[] = {65536, 8192, 16384};

	datum_config.stratum_v1_vardiff_client_min = 1024;
	datum_config.stratum_v1_vardiff_min = 16384;
	datum_config.stratum_v1_password_difficulty = true;

	for (size_t i = 0; i < sizeof(pws) / sizeof(pws[0]); ++i) {
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

		datum_stratum_apply_password_opts(m, pws[i]);
		datum_test(client_mining_subscribe(c, 1, NULL) == 0);
		datum_test(m->current_diff == want[i]);

		free(t);
		free(c);
		free(sd);
		free(m);
	}

	datum_config.stratum_v1_vardiff_client_min = saved_client_min;
	datum_config.stratum_v1_vardiff_min = saved_vardiff_min;
	datum_config.stratum_v1_password_difficulty = saved_password_difficulty;
}

void datum_stratum_tests(void) {
	datum_stratum_password_opts_tests();
	datum_stratum_password_before_subscribe_tests();
	datum_stratum_client_vardiff_floor_tests();
	datum_stratum_mod_username_tests();
}
