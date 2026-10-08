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
 * Copyright (c) 2026 Bitcoin Ocean, LLC & Luke Dashjr
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
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <curl/curl.h>
#include <jansson.h>

#include "datum_blocktemplates.h"
#include "datum_conf.h"
#include "datum_gateway.h"
#include "datum_logger.h"
#include "datum_queue.h"
#include "datum_rsk.h"
#include "datum_stratum.h"
#include "datum_utils.h"

pthread_rwlock_t rsk_commitment_rwlock = PTHREAD_RWLOCK_INITIALIZER;
static char rsk_commitment_hex_unterminated[RSK_COMMITMENT_SIZE * 2];
static uint8_t rsk_target[RSK_TARGET_SIZE];

static DATUM_QUEUE rsk_block_queue;

struct datum_rsk_pow {
	char rsk_commitment_hex_unterminated[RSK_COMMITMENT_SIZE * 2];
	uint8_t block_header[80];
	uint8_t full_cb_txn[MAX_COINBASE_TXN_SIZE_BYTES];
	size_t full_cb_txn_len;
	char merklebranches_hex_for_rsk[24 * 65];
	size_t merklebranches_hex_for_rsk_len;
	uint32_t block_txn_count;
};

#define DATUM_RSK_RECV_BUF_SIZE 0x200
#define DATUM_RSK_SEND_BUF_SIZE (0  \
	+ 82 /* prefix */  \
	+ (RSK_COMMITMENT_SIZE * 2) \
	+ 3 \
	+ (80 * 2) /* block header */ \
	+ 3 \
	+ (MAX_COINBASE_TXN_SIZE_BYTES * 2) \
	+ 3 \
	+ ((MAX_MERKLE_BRANCHES * 0x41) - 1) \
	+ 3 \
	+ 4 /* hex number of transactions */ \
	+ 2 /* suffix */ \
)

struct datum_rsk_state {
	CURLM *curlm;
	CURL *curl;
	char curl_error[CURL_ERROR_SIZE];
	bool standoff;
	uint64_t next_update_mono_ms;
	struct {
		unsigned int len;
		char buf[DATUM_RSK_RECV_BUF_SIZE];
	} recv_buf;
	struct {
		unsigned int offset;
		unsigned int len;
		char buf[DATUM_RSK_SEND_BUF_SIZE];
	} send_buf;
};

static struct datum_rsk_state *g_rsk_state;

#define DATUM_RSK_CURL_ERROR_FMT " (error=%llu %s%s%s)"
#define DATUM_RSK_CURL_ERROR_VARS_C (unsigned long long)cresult, curl_easy_strerror(cresult), state->curl_error[0] ? ": " : "", state->curl_error
#define DATUM_RSK_CURL_ERROR_VARS_M (unsigned long long)mresult, curl_multi_strerror(mresult), state->curl_error[0] ? ": " : "", state->curl_error

static
CURL *datum_rsk_create_curl(const global_config_t * const cfg, struct datum_rsk_state * const state) {
	CURLcode cresult;
	CURLMcode mresult;
	CURL * const curl = curl_easy_init();
	
	state->curl_error[0] = '\0';
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, state->curl_error);
	
	cresult = curl_easy_setopt(curl, CURLOPT_URL, cfg->rsk_wsurl);
	if (cresult != CURLE_OK) {
		DLOG_ERROR("%s: curl_easy_setopt CURLOPT_URL failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_C);
		curl_easy_cleanup(curl);
		return NULL;
	}
	
	cresult = curl_easy_setopt(curl, CURLOPT_CONNECT_ONLY, 2L);
	if (cresult != CURLE_OK) {
		DLOG_ERROR("%s: curl_easy_setopt CURLOPT_CONNECT_ONLY failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_C);
		curl_easy_cleanup(curl);
		return NULL;
	}
	
	mresult = curl_multi_add_handle(state->curlm, curl);
	if (mresult != CURLM_OK) {
		DLOG_ERROR("%s: curl_multi_add_handle failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_M);
		curl_easy_cleanup(curl);
		return NULL;
	}
	
	return curl;
}

static
void datum_rsk_disconnect(struct datum_rsk_state * const state) {
	curl_multi_remove_handle(state->curlm, state->curl);
	size_t sent;
	curl_ws_send(state->curl, "", 0, &sent, 0, CURLWS_CLOSE);
	curl_easy_cleanup(state->curl);
	state->curl = NULL;
}

static
void datum_rsk_handle_message(const global_config_t * const cfg, struct datum_rsk_state * const state) {
	const json_t *j;
	json_error_t jerr;
	const json_t * const jmsg = json_loadb(state->recv_buf.buf, state->recv_buf.len, 0, &jerr);
	if (!jmsg) {
		DLOG_ERROR("%s: json_loadb failed (error=%s)", __func__, jerr.text);
		datum_rsk_disconnect(state);
		return;
	}
	state->recv_buf.len = 0;
	
	j = json_object_get(jmsg, "method");
	if (j) {
		if (0 == strcmp(json_string_value(j), "eth_subscription")) {
			// New block, update work ASAP
			state->next_update_mono_ms = 0;
		}
		return;
	}
	j = json_object_get(jmsg, "id");
	if (json_integer_value(j) == 1) {
		j = json_object_get(jmsg, "result");
		if (json_array_size(j) < 3) {
			DLOG_ERROR("%s: Invalid getwork result (%s)", __func__, "fewer than 3 array items");
			return;
		}
		
		const json_t * const j_pow_hash = json_array_get(j, 0);
		if (json_string_length(j_pow_hash) != RSK_COMMITMENT_SIZE * 2) {
			DLOG_ERROR("%s: Invalid getwork result (%s)", __func__, "wrong PoW hash size");
			return;
		}
		const char * const pow_hash_hex = json_string_value(j_pow_hash);
		if (!is_all_hex(pow_hash_hex, RSK_COMMITMENT_SIZE * 2)) {
			DLOG_ERROR("%s: Invalid getwork result (%s)", __func__, "non-hex PoW hash");
			return;
		}
		
		if (0 == memcmp(rsk_commitment_hex_unterminated, pow_hash_hex, RSK_COMMITMENT_SIZE)) {
			// No change
			return;
		}
		
		const json_t * const j_target = json_array_get(j, 2);
		uint8_t rsk_target_new[RSK_TARGET_SIZE];
		if (!hex_to_bin_checked(json_string_value(j_target), rsk_target_new)) {
			DLOG_ERROR("%s: Invalid getwork result (%s)", __func__, "invalid target");
			return;
		}
		
		pthread_rwlock_wrlock(&rsk_commitment_rwlock);
		memcpy(rsk_commitment_hex_unterminated, pow_hash_hex, RSK_COMMITMENT_SIZE);
		memcpy(rsk_target, rsk_target_new, RSK_TARGET_SIZE);
		pthread_rwlock_unlock(&rsk_commitment_rwlock);
		
		if (!cfg->rsk_update_job) {
			return;
		}
		
		T_DATUM_TEMPLATE_DATA *tmpl = NULL;
		int sjob_index;
		pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
		sjob_index = global_latest_stratum_job_index;
		if (sjob_index >= 0 && sjob_index < MAX_STRATUM_JOBS) {
			tmpl = global_cur_stratum_jobs[sjob_index]->block_template;
		}
		pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
		update_stratum_job(tmpl, /*new_block=*/ false, JOB_STATE_FULL_PRIORITY_WAIT_COINBASER);
	}
}

static
bool datum_rsk_handle_recv(const global_config_t * const cfg, struct datum_rsk_state * const state) {
	CURLcode cresult;
	
	size_t rlen;
	const struct curl_ws_frame *meta;
	cresult = curl_ws_recv(state->curl, &state->recv_buf.buf[state->recv_buf.len], DATUM_RSK_RECV_BUF_SIZE - state->recv_buf.len, &rlen, &meta);
	if (cresult != CURLE_OK) {
		if (cresult == CURLE_AGAIN) return true;
		
		DLOG_ERROR("%s: curl_ws_recv failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_C);
		return false;
	}
	
	assert(rlen < DATUM_RSK_RECV_BUF_SIZE - state->recv_buf.len);
	state->recv_buf.len += rlen;
	if (meta->bytesleft == 0) {
		datum_rsk_handle_message(cfg, state);
	} else if (meta->bytesleft > DATUM_RSK_RECV_BUF_SIZE - state->recv_buf.len) {
		DLOG_ERROR("%s: receive buffer overflow (%zu bytes in %zu-byte buffer, %llu bytes remaining)", __func__, (size_t)state->recv_buf.len, (size_t)DATUM_RSK_RECV_BUF_SIZE, (unsigned long long)meta->bytesleft);
		datum_rsk_disconnect(state);
		return false;
	}
	
	return true;
}

static inline
bool datum_rsk_handle_send(struct datum_rsk_state * const state) {
	CURLcode cresult;
	
	size_t sent;
	cresult = curl_ws_send(state->curl, &state->send_buf.buf[state->send_buf.offset], state->send_buf.len, &sent, 0, CURLWS_TEXT);
	if (cresult != CURLE_OK) {
		if (cresult == CURLE_AGAIN) return true;
		
		DLOG_ERROR("%s: curl_ws_send failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_C);
		datum_rsk_disconnect(state);
		return false;
	}
	state->send_buf.offset += sent;
	state->send_buf.len -= sent;
	return true;
}

static
void datum_rsk_wait(struct datum_rsk_state * const state, int timeout_ms) {
	CURLMcode mresult;
	
	if (state->curl) {
		const uint64_t start_mono_ms = monotonic_time_millis();
		datum_update_timeout(&timeout_ms, state->next_update_mono_ms, start_mono_ms);
	}
	
	mresult = curl_multi_poll(state->curlm, NULL, 0, timeout_ms, NULL);
	if (mresult != CURLM_OK) {
		DLOG_ERROR("%s: curl_multi_poll failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_M);
		sleep(1);
	}
}

// CAUTION: Overwrites any previous queued send! Websocket is packet-based, so we can only send one at a time.
static inline
void datum_rsk_queue_send(struct datum_rsk_state * const state, const char * const msg, const size_t msg_len) {
	assert(msg_len <= DATUM_RSK_SEND_BUF_SIZE);
	static_assert(DATUM_RSK_SEND_BUF_SIZE < UINT_MAX);
	state->send_buf.offset = 0;
	state->send_buf.len = (unsigned int)msg_len;
	memcpy(state->send_buf.buf, msg, msg_len);
}

static inline
int datum_rsk_pow_handler(void * const p) {
	struct datum_rsk_pow * const pow = p;
	assert(g_rsk_state->send_buf.len == 0);
	
	static const char pre[] = "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"mnr_submitBitcoinBlockPartialMerkle\",\"params\":[\"";
	char * const buf = g_rsk_state->send_buf.buf;
	size_t pos = 0;
	memcpy(&buf[pos], pre, sizeof(pre) - 1); pos += sizeof(pre) - 1;
	memcpy(&buf[pos], pow->rsk_commitment_hex_unterminated, RSK_COMMITMENT_SIZE * 2); pos += RSK_COMMITMENT_SIZE * 2;
	strcpy(&buf[pos], "\",\""); pos += 3;
	bin2hex(&buf[pos], pow->block_header, 80, /*terminate=*/ false); pos += 80 * 2;
	strcpy(&buf[pos], "\",\""); pos += 3;
	bin2hex(&buf[pos], pow->full_cb_txn, pow->full_cb_txn_len, /*terminate=*/ false); pos += pow->full_cb_txn_len * 2;
	strcpy(&buf[pos], "\",\""); pos += 3;
	memcpy(&buf[pos], pow->merklebranches_hex_for_rsk, pow->merklebranches_hex_for_rsk_len); pos += pow->merklebranches_hex_for_rsk_len;
	strcpy(&buf[pos], "\",\""); pos += 3;
	pos += (unsigned long)sprintf(&buf[pos], "%lu]}", (unsigned long)pow->block_txn_count);
	
	assert(pos <= DATUM_RSK_SEND_BUF_SIZE);  // we're in trouble already if not!
	static_assert(DATUM_RSK_SEND_BUF_SIZE < UINT_MAX);
	g_rsk_state->send_buf.offset = 0;
	g_rsk_state->send_buf.len = (unsigned int)pos;
	
	return 0;
}

static
void datum_rsk_process(const global_config_t * const cfg, struct datum_rsk_state * const state) {
	CURLcode cresult;
	CURLMcode mresult;
	
	if (!state->curl) state->curl = datum_rsk_create_curl(cfg, state->curlm);
	
	int still_connecting;
	mresult = curl_multi_perform(state->curlm, &still_connecting);
	if (mresult != CURLM_OK) {
		DLOG_ERROR("%s: curl_multi_perform failed" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_M);
	}
	
	if (still_connecting) {
		return;
	}
	
	int msgs_in_queue;
	CURLMsg *msg;
	while ( (msg = curl_multi_info_read(state->curlm, &msgs_in_queue)) ) {
		switch (msg->msg) {
			case CURLMSG_DONE:
			{
				cresult = msg->data.result;
				if (msg->data.result == CURLE_OK) {
					// Connected, so subscribe
					static const char sub_req[] = "{\"jsonrpc\":\"2.0\",\"id\":0,\"method\":\"eth_subscribe\",\"params\":[\"newHeads\"]}";
					datum_rsk_queue_send(state, sub_req, sizeof(sub_req) - 1);
					state->next_update_mono_ms = 0;
					state->recv_buf.len = 0;
				} else {
					DLOG_ERROR("%s: Error connecting to Rootstock node" DATUM_RSK_CURL_ERROR_FMT, __func__, DATUM_RSK_CURL_ERROR_VARS_C);
					sleep(1);
				}
				break;
			}
			default: ;
		}
	}
	
	if (state->curl) {
		if (datum_rsk_handle_recv(cfg, state)) {
			if (state->send_buf.len == 0) {
				datum_queue_process(&rsk_block_queue);
			}
			if (state->send_buf.len == 0) {
				const uint64_t now_mono_ms = monotonic_time_millis();
				if (now_mono_ms >= state->next_update_mono_ms) {
					static const char getwork_req[] = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"mnr_getWork\",\"params\":[]}";
					datum_rsk_queue_send(state, getwork_req, sizeof(getwork_req) - 1);
					state->next_update_mono_ms = now_mono_ms + ((uint64_t)cfg->rsk_work_update_seconds * 1000);
				}
			}
			
			if (state->send_buf.len > 0) {
				if (!datum_rsk_handle_send(state)) {
					goto curl_err;
				}
			}
			
			state->standoff = false;
		} else {
curl_err:
			if (state->standoff) sleep(1);
			state->standoff = true;
		}
	}
}

static
void *datum_rsk_thread(void * const p) {
	const global_config_t * const cfg = p;
	
	if (datum_queue_prep(&rsk_block_queue, /*max_items=*/ 4, sizeof(struct datum_rsk_pow), datum_rsk_pow_handler) != 0) {
		DLOG_ERROR("%s: Could not setup work submission queue! Rootstock functionality disabled", __func__);
		return NULL;
	}
	
	g_rsk_state = calloc(1, sizeof(*g_rsk_state));
	struct datum_rsk_state * const state = g_rsk_state;
	state->curlm = curl_multi_init();
	if (!state->curlm) {
		DLOG_ERROR("%s: curl_multi_init failed; Rootstock functionality disabled", __func__);
		return NULL;
	}
	
	while (1) {
		datum_rsk_process(cfg, state);
		datum_rsk_wait(state, INT_MAX);
	}
}

bool datum_rsk_init(const global_config_t * const cfg) {
	pthread_t pthread_datum_rsk_thread;
	int result = pthread_create(&pthread_datum_rsk_thread, NULL, datum_rsk_thread, NULL);

	if (result != 0) {
		DLOG_ERROR("%s: pthread_create failed with code %d (%s); Rootstock functionality disabled", __func__, result, strerror(result));
		return false;
	}

	return true;
}

void datum_rsk_get_current_work(char * const out_rsk_commitment_hex_unterminated, uint8_t * const out_target) {
	pthread_rwlock_rdlock(&rsk_commitment_rwlock);
	memcpy(out_rsk_commitment_hex_unterminated, rsk_commitment_hex_unterminated, RSK_COMMITMENT_SIZE);
	memcpy(out_target, rsk_target, RSK_TARGET_SIZE);
	pthread_rwlock_unlock(&rsk_commitment_rwlock);
}

int datum_rsk_pow_submit(const T_DATUM_STRATUM_JOB * const job, const unsigned char * const block_header, const unsigned char * const full_cb_txn, const size_t full_cb_txn_len) {
	CURLMcode mresult;
	struct datum_rsk_pow pow;
	
	memcpy(pow.rsk_commitment_hex_unterminated, job->rsk_commitment_hex_unterminated, RSK_COMMITMENT_SIZE * 2);
	memcpy(pow.block_header, block_header, 80);
	memcpy(pow.full_cb_txn, full_cb_txn, full_cb_txn_len);
	pow.full_cb_txn_len = full_cb_txn_len;
	for (unsigned char i = 0; i < job->merklebranch_count; ++i) {
		memcpy(&pow.merklebranches_hex_for_rsk[i * 0x41], job->merklebranches_hex[i], 0x40);
		pow.merklebranches_hex_for_rsk[(i * 0x41) + 0x40] = (i == job->merklebranch_count - 1) ? '\0' : ' ';
	}
	pow.merklebranches_hex_for_rsk_len = (job->merklebranch_count * 0x41) - 1;
	pow.block_txn_count = job->block_template->txn_count;
	
	const int rv = datum_queue_add_item(&rsk_block_queue, &pow);
	
	struct datum_rsk_state * const state = g_rsk_state;
	mresult = curl_multi_wakeup(state->curlm);
	if (mresult != CURLM_OK) {
		DLOG_ERROR("%s: curl_multi_wakeup failed" DATUM_RSK_CURL_ERROR_FMT ", potentially delaying Rootstock block submission", __func__, DATUM_RSK_CURL_ERROR_VARS_M);
	}
	
	return rv;
}
