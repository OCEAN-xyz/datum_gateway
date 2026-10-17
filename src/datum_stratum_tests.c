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
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "datum_jsonrpc.h"
#include "datum_stratum.h"
#include "datum_utils.h"

int client_mining_subscribe(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj);
int client_mining_configure(T_DATUM_CLIENT_DATA *c, uint64_t id, json_t *params_obj);
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

// A request can only raise difficulty, rounds up, and never lands below vardiff_min.
static void datum_stratum_request_min_diff_tests(void) {
	T_DATUM_MINER_DATA m;
	const int saved_vardiff_min = datum_config.stratum_v1_vardiff_min;
	
	datum_config.stratum_v1_vardiff_min = 16384;
	
	// at or above the floor, a power of two is taken as is
	memset(&m, 0, sizeof(m));
	datum_test(datum_stratum_request_min_diff(&m, 65536));
	datum_test(m.client_min_diff == 65536);
	datum_test(m.current_diff == 65536);
	
	// anything else rounds UP, so the client never gets less than it asked for
	memset(&m, 0, sizeof(m));
	datum_test(datum_stratum_request_min_diff(&m, 40000));
	datum_test(m.client_min_diff == 65536);
	memset(&m, 0, sizeof(m));
	datum_test(datum_stratum_request_min_diff(&m, 32768.5));
	datum_test(m.client_min_diff == 65536);
	
	// below the floor becomes the floor: a client cannot cost more shares than the
	// operator already allows every client
	memset(&m, 0, sizeof(m));
	datum_test(datum_stratum_request_min_diff(&m, 1));
	datum_test(m.client_min_diff == 16384);
	memset(&m, 0, sizeof(m));
	datum_test(datum_stratum_request_min_diff(&m, 8192));
	datum_test(m.client_min_diff == 16384);
	
	// a client fingerprinted as needing a high difficulty keeps it
	memset(&m, 0, sizeof(m));
	m.forced_high_min_diff = 524288;
	datum_test(datum_stratum_request_min_diff(&m, 65536));
	datum_test(m.client_min_diff == 524288);
	
	// unusable values change nothing
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_test(!datum_stratum_request_min_diff(&m, 0));
	datum_test(!datum_stratum_request_min_diff(&m, 0.5));
	datum_test(!datum_stratum_request_min_diff(&m, -2048));
	datum_test(!datum_stratum_request_min_diff(&m, NAN));
	datum_test(!datum_stratum_request_min_diff(&m, INFINITY));
	// beyond the bound is ignored rather than clamped, so the client keeps vardiff
	datum_test(!datum_stratum_request_min_diff(&m, (double)(1ULL << 45)));
	datum_test(!datum_stratum_request_min_diff(&m, 1e30));
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	// the bound itself is fine; an exahash miner wants about 1.4e10
	datum_test(datum_stratum_request_min_diff(&m, (double)(1ULL << 44)));
	datum_test(m.client_min_diff == (1ULL << 44));
	
	datum_config.stratum_v1_vardiff_min = saved_vardiff_min;
}

static void datum_stratum_password_opts_tests(void) {
	T_DATUM_MINER_DATA m;
	const int saved_vardiff_min = datum_config.stratum_v1_vardiff_min;
	const bool saved_password_difficulty = datum_config.stratum_v1_password_difficulty;
	
	datum_config.stratum_v1_vardiff_min = 16384;
	
	// Off unless the operator turns it on. The password was always discarded, and a
	// password that happens to read as a request must change nothing by default.
	datum_config.stratum_v1_password_difficulty = false;
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_stratum_apply_password_opts(&m, "d=65536");
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	
	datum_config.stratum_v1_password_difficulty = true;
	
	// the passwords miners already send mean nothing
	memset(&m, 0, sizeof(m));
	m.current_diff = 16384;
	datum_stratum_apply_password_opts(&m, "x");
	datum_stratum_apply_password_opts(&m, "");
	datum_stratum_apply_password_opts(&m, NULL);
	datum_test(m.client_min_diff == 0);
	datum_test(m.current_diff == 16384);
	
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=65536");
	datum_test(m.client_min_diff == 65536);
	datum_test(m.current_diff == 65536);
	
	// same rules as any other request
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=40000");
	datum_test(m.client_min_diff == 65536);
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "d=1");
	datum_test(m.client_min_diff == 16384);
	
	// unknown keys are skipped, with either separator and leading whitespace
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "foo=1,d=65536,bar");
	datum_test(m.client_min_diff == 65536);
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "u=whatever; d=131072");
	datum_test(m.client_min_diff == 131072);
	
	// The key has to be exactly "d", and the value only digits. "d12345" would
	// otherwise read as a request, and strtoull would take a sign or a space.
	memset(&m, 0, sizeof(m));
	datum_stratum_apply_password_opts(&m, "diff=65536");
	datum_stratum_apply_password_opts(&m, "d12345");
	datum_stratum_apply_password_opts(&m, "fd=65536");
	datum_stratum_apply_password_opts(&m, "d=-65536");
	datum_stratum_apply_password_opts(&m, "d= 65536");
	datum_stratum_apply_password_opts(&m, "d=65536x");
	datum_stratum_apply_password_opts(&m, "d=");
	datum_stratum_apply_password_opts(&m, "d=0");
	datum_test(m.client_min_diff == 0);
	
	// strtoull saturates rather than failing on a long run of digits
	datum_stratum_apply_password_opts(&m, "d=99999999999999999999999999");
	datum_test(m.client_min_diff == 0);
	
	// a password longer than the parse buffer must not run off the end of it
	{
		char big[1024];
		memset(big, 'a', sizeof(big) - 1);
		big[sizeof(big) - 1] = 0;
		memset(&m, 0, sizeof(m));
		datum_stratum_apply_password_opts(&m, big);
		datum_test(m.client_min_diff == 0);
	}
	
	datum_config.stratum_v1_vardiff_min = saved_vardiff_min;
	datum_config.stratum_v1_password_difficulty = saved_password_difficulty;
}

// The request is a floor: vardiff clamps every downward step, so without a per-client
// floor the first step down would undo it. Only the two downward paths are driven
// here; they halve and clamp without touching a job.
static void datum_stratum_client_vardiff_floor_tests(void) {
	const int saved_vardiff_min = datum_config.stratum_v1_vardiff_min;
	const int saved_shares_min = datum_config.stratum_v1_vardiff_target_shares_min;
	
	T_DATUM_MINER_DATA * const m = calloc(1, sizeof(T_DATUM_MINER_DATA));
	T_DATUM_STRATUM_THREADPOOL_DATA * const sd = calloc(1, sizeof(T_DATUM_STRATUM_THREADPOOL_DATA));
	T_DATUM_CLIENT_DATA * const c = calloc(1, sizeof(T_DATUM_CLIENT_DATA));
	assert(m && sd && c);
	
	datum_config.stratum_v1_vardiff_min = 16384;
	datum_config.stratum_v1_vardiff_target_shares_min = 8;
	m->sdata = sd;
	c->app_client_data = m;
	
	// sixty seconds with no shares is the "difficulty is too high" path
	sd->loop_tsms = 61000;
	
	// a client that asked for nothing still stops at vardiff_min
	m->current_diff = m->last_sent_diff = 32768;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 16384);
	
	// a client that asked for 131072 stops there
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 0;
	m->client_min_diff = 131072;
	m->current_diff = m->last_sent_diff = 262144;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 131072);
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 0;
	m->current_diff = m->last_sent_diff = 131072;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 131072);
	
	// the other downward path: shares far slower than the target interval
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 1;
	sd->loop_tsms = 40000;
	m->current_diff = m->last_sent_diff = 131072;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 131072);
	
	// raising vardiff_min while running still applies to a client that asked for less
	datum_config.stratum_v1_vardiff_min = 262144;
	m->share_snap_tsms = 0;
	m->share_count_since_snap = 1;
	m->current_diff = m->last_sent_diff = 262144;
	stratum_update_vardiff(c, true);
	datum_test(m->current_diff == 262144);
	
	free(c);
	free(sd);
	free(m);
	datum_config.stratum_v1_vardiff_min = saved_vardiff_min;
	datum_config.stratum_v1_vardiff_target_shares_min = saved_shares_min;
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

// mining.configure's minimum-difficulty, and a request made before subscribe surviving
// it. Nothing makes a miner subscribe first, and subscribe used to reset the
// difficulty to vardiff_min unconditionally.
static void datum_stratum_configure_min_diff_tests(void) {
	const int saved_vardiff_min = datum_config.stratum_v1_vardiff_min;
	const bool saved_password_difficulty = datum_config.stratum_v1_password_difficulty;
	json_error_t err;
	json_t *params;
	T_DATUM_CLIENT_DATA *c;
	T_DATUM_MINER_DATA *m;
	
	datum_config.stratum_v1_vardiff_min = 16384;
	datum_config.stratum_v1_password_difficulty = false;
	
	// taken, answered true, and kept through subscribe. Independent of the password
	// option: the miner asked explicitly, and it can only raise its own difficulty.
	c = datum_stratum_test_client();
	m = c->app_client_data;
	params = json_loads("[[\"version-rolling\",\"minimum-difficulty\"],{\"version-rolling.mask\":\"1fffe000\",\"minimum-difficulty.value\":100000}]", 0, &err);
	assert(params);
	datum_test(client_mining_configure(c, 7, params) == 0);
	datum_test(NULL != strstr(c->w_buffer, "\"minimum-difficulty\":true"));
	datum_test(m->client_min_diff == 131072);
	datum_test(client_mining_subscribe(c, 8, NULL) == 0);
	datum_test(m->current_diff == 131072);
	json_decref(params);
	datum_stratum_test_client_free(c);
	
	// an unusable value is refused, and the reply says so
	c = datum_stratum_test_client();
	m = c->app_client_data;
	params = json_loads("[[\"version-rolling\",\"minimum-difficulty\"],{\"minimum-difficulty.value\":0}]", 0, &err);
	assert(params);
	datum_test(client_mining_configure(c, 7, params) == 0);
	datum_test(NULL != strstr(c->w_buffer, "\"minimum-difficulty\":false"));
	datum_test(m->client_min_diff == 0);
	json_decref(params);
	datum_stratum_test_client_free(c);
	
	// minimum-difficulty without version-rolling must still be valid JSON; this used
	// to produce {"result":{,"minimum-difficulty":false}}
	c = datum_stratum_test_client();
	params = json_loads("[[\"minimum-difficulty\"],{\"minimum-difficulty.value\":65536}]", 0, &err);
	assert(params);
	datum_test(client_mining_configure(c, 7, params) == 0);
	{
		json_t * const reply = json_loads(c->w_buffer, JSON_DISABLE_EOF_CHECK, &err);
		datum_test(reply != NULL);
		if (reply) {
			datum_test(json_is_true(json_object_get(json_object_get(reply, "result"), "minimum-difficulty")));
			json_decref(reply);
		}
	}
	json_decref(params);
	datum_stratum_test_client_free(c);
	
	// a password read before subscribe survives it too
	datum_config.stratum_v1_password_difficulty = true;
	c = datum_stratum_test_client();
	m = c->app_client_data;
	datum_stratum_apply_password_opts(m, "d=65536");
	datum_test(client_mining_subscribe(c, 8, NULL) == 0);
	datum_test(m->current_diff == 65536);
	datum_stratum_test_client_free(c);
	
	// and a client that asked for nothing starts at vardiff_min, as before
	c = datum_stratum_test_client();
	m = c->app_client_data;
	datum_stratum_apply_password_opts(m, "x");
	datum_test(client_mining_subscribe(c, 8, NULL) == 0);
	datum_test(m->current_diff == 16384);
	datum_stratum_test_client_free(c);
	
	datum_config.stratum_v1_vardiff_min = saved_vardiff_min;
	datum_config.stratum_v1_password_difficulty = saved_password_difficulty;
}

void datum_stratum_tests(void) {
	datum_stratum_request_min_diff_tests();
	datum_stratum_password_opts_tests();
	datum_stratum_client_vardiff_floor_tests();
	datum_stratum_configure_min_diff_tests();
	datum_stratum_mod_username_tests();
}
