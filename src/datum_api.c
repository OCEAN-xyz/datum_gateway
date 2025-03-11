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

// This is quick and dirty for now.  Will be improved over time.

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <inttypes.h>
#include <jansson.h>

#include "datum_api.h"
#include "datum_blocktemplates.h"
#include "datum_conf.h"
#include "datum_gateway.h"
#include "datum_jsonrpc.h"
#include "datum_utils.h"
#include "datum_stratum.h"
#include "datum_sockets.h"
#include "datum_protocol.h"

#include "web_resources.h"

const char * const homepage_html_end = "</body></html>";

#define DATUM_API_HOMEPAGE_MAX_SIZE 128000

const char *cbnames[] = {
	"Blank",
	"Tiny",
	"Default",
	"Respect",
	"Yuge",
	"Antmain2"
};

typedef struct MHD_Response *(*create_response_func_t)();

static struct MHD_Response *datum_api_create_empty_mhd_response() {
	return MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
}

static void html_leading_zeros(char * const buffer, const size_t buffer_size, const char * const numstr) {
	int zeros = 0;
	while (numstr[zeros] == '0') {
		++zeros;
	}
	if (zeros) {
		snprintf(buffer, buffer_size, "<span class='leading_zeros'>%.*s</span>%s", zeros, numstr, &numstr[zeros]);
	}
}

void datum_api_var_DATUM_SHARES_ACCEPTED(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%llu  (%llu diff)", (unsigned long long)datum_accepted_share_count, (unsigned long long)datum_accepted_share_diff);
}
void datum_api_var_DATUM_SHARES_REJECTED(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%llu  (%llu diff)", (unsigned long long)datum_rejected_share_count, (unsigned long long)datum_rejected_share_diff);
}
void datum_api_var_DATUM_CONNECTION_STATUS(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	const char *colour = "lime";
	const char *s, *s2 = "";
	const char * const bt_err = datum_blocktemplates_error;
	if (bt_err) {
		colour = "red";
		s = "ERROR: ";
		s2 = bt_err;
	} else if (!vardata->sjob) {
		colour = "silver";
		s = "Initialising...";
	} else if (datum_protocol_is_active()) {
		s = "Connected and Ready";
	} else if (datum_config.datum_pooled_mining_only && datum_config.datum_pool_host[0]) {
		colour = "red";
		s = "Not Ready";
	} else {
		if (datum_config.datum_pool_host[0]) {
			colour = "yellow";
		}
		s = "Non-Pooled Mode";
	}
	snprintf(buffer, buffer_size, "<svg viewBox='0 0 100 100' role='img' style='width:1em;height:1em'><circle cx='50' cy='60' r='35' style='fill:%s' /></svg> %s%s", colour, s, s2);
}
void datum_api_var_DATUM_POOL_HOST(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	if (datum_config.datum_pool_host[0]) {
		snprintf(buffer, buffer_size, "%s:%u", datum_config.datum_pool_host, (unsigned)datum_config.datum_pool_port);
	} else {
		snprintf(buffer, buffer_size, "N/A");
	}
}
void datum_api_var_DATUM_POOL_TAG(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	size_t i;
	buffer[0] = '"';
	i = strncpy_html_escape(&buffer[1], datum_protocol_is_active()?datum_config.override_mining_coinbase_tag_primary:datum_config.mining_coinbase_tag_primary, buffer_size-3);
	buffer[i+1] = '"';
	buffer[i+2] = 0;
}
void datum_api_var_DATUM_MINER_TAG(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	size_t i;
	buffer[0] = '"';
	i = strncpy_html_escape(&buffer[1], datum_config.mining_coinbase_tag_secondary, buffer_size-3);
	buffer[i+1] = '"';
	buffer[i+2] = 0;
}
void datum_api_var_DATUM_POOL_DIFF(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%llu", (unsigned long long)datum_config.override_vardiff_min);
}
void datum_api_var_DATUM_POOL_PUBKEY(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%s", datum_config.datum_pool_pubkey);
}
void datum_api_var_STRATUM_ACTIVE_THREADS(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%d", vardata->STRATUM_ACTIVE_THREADS);
}
void datum_api_var_STRATUM_TOTAL_CONNECTIONS(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%d", vardata->STRATUM_TOTAL_CONNECTIONS);
}
void datum_api_var_STRATUM_TOTAL_SUBSCRIPTIONS(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%d", vardata->STRATUM_TOTAL_SUBSCRIPTIONS);
}
void datum_api_var_STRATUM_HASHRATE_ESTIMATE(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%.2f Th/sec", vardata->STRATUM_HASHRATE_ESTIMATE);
}
void datum_api_var_DATUM_PROCESS_UPTIME(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	uint64_t uptime_seconds = get_process_uptime_seconds();
	uint64_t days = uptime_seconds / (24 * 3600);
	unsigned int hours = (uptime_seconds % (24 * 3600)) / 3600;
	unsigned int minutes = (uptime_seconds % 3600) / 60;
	unsigned int seconds = uptime_seconds % 60;
	
	if (days > 0) {
		snprintf(buffer, buffer_size, "%"PRIu64" days, %u hours, %u minutes, %u seconds",
			days, hours, minutes, seconds);
	} else if (hours > 0) {
		snprintf(buffer, buffer_size, "%u hours, %u minutes, %u seconds",
			hours, minutes, seconds);
	} else if (minutes > 0) {
		snprintf(buffer, buffer_size, "%u minutes, %u seconds",
			minutes, seconds);
	} else {
		snprintf(buffer, buffer_size, "%u seconds", seconds);
	}
}
void datum_api_var_STRATUM_JOB_INFO(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	if (!vardata->sjob) return;
	snprintf(buffer, buffer_size, "%s (%d) @ %.3f", vardata->sjob->job_id, vardata->sjob->global_index, (double)vardata->sjob->tsms / 1000.0);
}
void datum_api_var_STRATUM_JOB_BLOCK_HEIGHT(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%llu", (unsigned long long)vardata->sjob->block_template->height);
}
void datum_api_var_STRATUM_JOB_BLOCK_VALUE(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%.8f BTC", (double)vardata->sjob->block_template->coinbasevalue / (double)100000000.0);
}
void datum_api_var_STRATUM_JOB_TARGET(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	html_leading_zeros(buffer, buffer_size, vardata->sjob->block_template->block_target_hex);
}
void datum_api_var_STRATUM_JOB_PREVBLOCK(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	html_leading_zeros(buffer, buffer_size, vardata->sjob->block_template->previousblockhash);
}
void datum_api_var_STRATUM_JOB_WITNESS(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%s", vardata->sjob->block_template->default_witness_commitment);
}
void datum_api_var_STRATUM_JOB_DIFF(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%.3Lf", calc_network_difficulty(vardata->sjob->nbits));
}
void datum_api_var_STRATUM_JOB_VERSION(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%s (%u)", vardata->sjob->version, (unsigned)vardata->sjob->version_uint);
}
void datum_api_var_STRATUM_JOB_BITS(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%s", vardata->sjob->nbits);
}
void datum_api_var_STRATUM_JOB_TIMEINFO(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "Current: %llu / Min: %llu", (unsigned long long)vardata->sjob->block_template->curtime, (unsigned long long)vardata->sjob->block_template->mintime);
}
void datum_api_var_STRATUM_JOB_LIMITINFO(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "Size: %lu, Weight: %lu, SigOps: %lu", (unsigned long)vardata->sjob->block_template->sizelimit, (unsigned long)vardata->sjob->block_template->weightlimit, (unsigned long)vardata->sjob->block_template->sigoplimit);
}
void datum_api_var_STRATUM_JOB_SIZE(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%lu", (unsigned long)vardata->sjob->block_template->txn_total_size);
}
void datum_api_var_STRATUM_JOB_WEIGHT(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%lu", (unsigned long)vardata->sjob->block_template->txn_total_weight);
}
void datum_api_var_STRATUM_JOB_SIGOPS(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%lu", (unsigned long)vardata->sjob->block_template->txn_total_sigops);
}
void datum_api_var_STRATUM_JOB_TXNCOUNT(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%u", (unsigned)vardata->sjob->block_template->txn_count);
}


DATUM_API_VarEntry var_entries[] = {
	{"DATUM_SHARES_ACCEPTED", datum_api_var_DATUM_SHARES_ACCEPTED},
	{"DATUM_SHARES_REJECTED", datum_api_var_DATUM_SHARES_REJECTED},
	{"DATUM_CONNECTION_STATUS", datum_api_var_DATUM_CONNECTION_STATUS},
	{"DATUM_POOL_HOST", datum_api_var_DATUM_POOL_HOST},
	{"DATUM_POOL_TAG", datum_api_var_DATUM_POOL_TAG},
	{"DATUM_MINER_TAG", datum_api_var_DATUM_MINER_TAG},
	{"DATUM_POOL_DIFF", datum_api_var_DATUM_POOL_DIFF},
	{"DATUM_POOL_PUBKEY", datum_api_var_DATUM_POOL_PUBKEY},
	{"DATUM_PROCESS_UPTIME", datum_api_var_DATUM_PROCESS_UPTIME},
	
	{"STRATUM_ACTIVE_THREADS", datum_api_var_STRATUM_ACTIVE_THREADS},
	{"STRATUM_TOTAL_CONNECTIONS", datum_api_var_STRATUM_TOTAL_CONNECTIONS},
	{"STRATUM_TOTAL_SUBSCRIPTIONS", datum_api_var_STRATUM_TOTAL_SUBSCRIPTIONS},
	{"STRATUM_HASHRATE_ESTIMATE", datum_api_var_STRATUM_HASHRATE_ESTIMATE},
	
	{"STRATUM_JOB_INFO", datum_api_var_STRATUM_JOB_INFO},
	{"STRATUM_JOB_BLOCK_HEIGHT", datum_api_var_STRATUM_JOB_BLOCK_HEIGHT},
	{"STRATUM_JOB_BLOCK_VALUE", datum_api_var_STRATUM_JOB_BLOCK_VALUE},
	{"STRATUM_JOB_PREVBLOCK", datum_api_var_STRATUM_JOB_PREVBLOCK},
	{"STRATUM_JOB_TARGET", datum_api_var_STRATUM_JOB_TARGET},
	{"STRATUM_JOB_WITNESS", datum_api_var_STRATUM_JOB_WITNESS},
	{"STRATUM_JOB_DIFF", datum_api_var_STRATUM_JOB_DIFF},
	{"STRATUM_JOB_VERSION", datum_api_var_STRATUM_JOB_VERSION},
	{"STRATUM_JOB_BITS", datum_api_var_STRATUM_JOB_BITS},
	{"STRATUM_JOB_TIMEINFO", datum_api_var_STRATUM_JOB_TIMEINFO},
	{"STRATUM_JOB_LIMITINFO", datum_api_var_STRATUM_JOB_LIMITINFO},
	{"STRATUM_JOB_SIZE", datum_api_var_STRATUM_JOB_SIZE},
	{"STRATUM_JOB_WEIGHT", datum_api_var_STRATUM_JOB_WEIGHT},
	{"STRATUM_JOB_SIGOPS", datum_api_var_STRATUM_JOB_SIGOPS},
	{"STRATUM_JOB_TXNCOUNT", datum_api_var_STRATUM_JOB_TXNCOUNT},
	
	{NULL, NULL} // Mark the end of the array
};

DATUM_API_VarFunc datum_api_find_var_func(const char * const var_start, const size_t var_name_len) {
	for (int i = 0; var_entries[i].var_name != NULL; i++) {
		if (strncmp(var_entries[i].var_name, var_start, var_name_len) == 0 && !var_entries[i].var_name[var_name_len]) {
			return var_entries[i].func;
		}
	}
	return NULL; // Variable not found
}

size_t datum_api_fill_var(const char * const var_start, const size_t var_name_len, char * const replacement, const size_t replacement_max_len, const T_DATUM_API_DASH_VARS * const vardata) {
	DATUM_API_VarFunc func = datum_api_find_var_func(var_start, var_name_len);
	if (!func) {
		DLOG_ERROR("%s: Unknown variable '%.*s'", __func__, (int)var_name_len, var_start);
		return 0;
	}
	
	// Skip running STRATUM_JOB functions if there's no sjob
	if (var_start[8] == 'J' && !vardata->sjob) {
		// Leave blank for now
		return 0;
	}
	
	assert(replacement_max_len > 0);
	replacement[0] = 0;
	func(replacement, replacement_max_len, vardata);
	return strlen(replacement);
}

size_t datum_api_fill_vars(const char *input, char *output, size_t max_output_size, const DATUM_API_VarFillFunc var_fill_func, const T_DATUM_API_DASH_VARS *vardata) {
	const char* p = input;
	size_t output_len = 0;
	size_t var_name_len = 0;
	const char *var_start;
	const char *var_end;
	
	while (*p && output_len < max_output_size - 1) {
		if (strncmp(p, "${", 2) == 0) {
			p += 2; // Skip "${"
			var_start = p;
			var_end = strchr(p, '}');
			if (!var_end) {
				DLOG_ERROR("%s: Missing closing } for variable", __func__);
				break;
			}
			var_name_len = var_end - var_start;
			
			char * const replacement = &output[output_len];
			size_t replacement_max_len = max_output_size - output_len;
			if (replacement_max_len > 256) replacement_max_len = 256;
			const size_t replacement_len = var_fill_func(var_start, var_name_len, replacement, replacement_max_len, vardata);
			output_len += replacement_len;
			output[output_len] = 0;
			p = var_end + 1; // Move past '}'
		} else {
			output[output_len++] = *p++;
			output[output_len] = 0;
		}
	}
	
	output[output_len] = 0;
	
	return output_len;
}

size_t strncpy_html_escape(char *dest, const char *src, size_t n) {
	size_t i = 0;
	
	while (*src && i < n) {
		switch (*src) {
			case '&':
				if (i + 5 <= n) { // &amp;
					dest[i++] = '&';
					dest[i++] = 'a';
					dest[i++] = 'm';
					dest[i++] = 'p';
					dest[i++] = ';';
				} else {
					return i; // Stop if there's not enough space
				}
				break;
			case '<':
				if (i + 4 <= n) { // &lt;
					dest[i++] = '&';
					dest[i++] = 'l';
					dest[i++] = 't';
					dest[i++] = ';';
				} else {
					return i; // Stop if there's not enough space
				}
				break;
			case '>':
				if (i + 4 <= n) { // &gt;
					dest[i++] = '&';
					dest[i++] = 'g';
					dest[i++] = 't';
					dest[i++] = ';';
				} else {
					return i; // Stop if there's not enough space
				}
				break;
			case '"':
				if (i + 6 <= n) { // &quot;
					dest[i++] = '&';
					dest[i++] = 'q';
					dest[i++] = 'u';
					dest[i++] = 'o';
					dest[i++] = 't';
					dest[i++] = ';';
				} else {
					return i; // Stop if there's not enough space
				}
				break;
			default:
				dest[i++] = *src;
				break;
		}
		src++;
	}
	
	// Null-terminate the destination string if there's space
	if (i < n) {
		dest[i] = '\0';
	}
	
	return i;
}

static void http_resp_prevent_caching(struct MHD_Response * const response) {
	MHD_add_response_header(response, "Cache-Control", "no-cache, no-store, must-revalidate");
	MHD_add_response_header(response, "Pragma", "no-cache");
	MHD_add_response_header(response, "Expires", "0");
}

static enum MHD_Result datum_api_formdata_to_json_cb(void * const cls, const enum MHD_ValueKind kind, const char * const key, const char * const filename, const char * const content_type, const char * const transfer_encoding, const char * const data, const uint64_t off, const size_t size) {
	if (!key) return MHD_YES;
	if (off) return MHD_YES;
	
	assert(cls);
	json_t * const j = cls;
	
	json_object_set_new(j, key, json_stringn(data, size));
	
	return MHD_YES;
}

bool datum_api_formdata_to_json(struct MHD_Connection * const connection, char * const post, const int len, json_t * const j) {
	struct MHD_PostProcessor * const pp = MHD_create_post_processor(connection, 32768, datum_api_formdata_to_json_cb, j);
	if (!pp) {
		return false;
	}
	if (MHD_YES != MHD_post_process(pp, post, len)) {
		MHD_destroy_post_processor(pp);
		return false;
	}
	MHD_destroy_post_processor(pp);
	return true;
}

int datum_api_submit_uncached_response(struct MHD_Connection * const connection, const unsigned int status_code, struct MHD_Response * const response) {
	http_resp_prevent_caching(response);
	int ret = MHD_queue_response(connection, status_code, response);
	MHD_destroy_response(response);
	return ret;
}

int datum_api_do_error(struct MHD_Connection * const connection, const unsigned int status_code) {
	struct MHD_Response *response = datum_api_create_empty_mhd_response();
	return datum_api_submit_uncached_response(connection, status_code, response);
}

bool datum_api_check_admin_password_only(struct MHD_Connection * const connection, const char * const password, const create_response_func_t auth_failure_response_creator) {
	if (datum_secure_strequals(datum_config.api_admin_password, datum_config.api_admin_password_len, password) && datum_config.api_admin_password_len) {
		return true;
	}
	DLOG_DEBUG("Wrong password in request");
	datum_api_submit_uncached_response(connection, MHD_HTTP_FORBIDDEN, auth_failure_response_creator());
	return false;
}

bool datum_api_check_admin_password_httponly(struct MHD_Connection * const connection, const create_response_func_t auth_failure_response_creator) {
	int ret;
	
	char * const username = MHD_digest_auth_get_username(connection);
	const char * const realm = "DATUM Gateway";
	if (username) {
		ret = MHD_digest_auth_check2(connection, realm, username, datum_config.api_admin_password, 300, MHD_DIGEST_ALG_SHA256);
		free(username);
	} else {
		ret = MHD_NO;
	}
	if (ret != MHD_YES) {
		DLOG_DEBUG("Wrong password in HTTP authentication");
		struct MHD_Response * const response = auth_failure_response_creator();
		ret = MHD_queue_auth_fail_response2(connection, realm, datum_config.api_csrf_token, response, (ret == MHD_INVALID_NONCE) ? MHD_YES : MHD_NO, MHD_DIGEST_ALG_SHA256);
		MHD_destroy_response(response);
		return false;
	}
	
	return true;
}

bool datum_api_check_admin_password(struct MHD_Connection * const connection, const json_t * const j, const create_response_func_t auth_failure_response_creator) {
	const json_t * const j_password = json_object_get(j, "password");
	if (json_is_string(j_password)) {
		return datum_api_check_admin_password_only(connection, json_string_value(j_password), auth_failure_response_creator);
	}
	
	// Only accept HTTP authentication if there's an anti-CSRF token
	const json_t * const j_csrf = json_object_get(j, "csrf");
	if (!json_is_string(j_csrf)) {
		DLOG_DEBUG("Missing CSRF token in request");
		datum_api_submit_uncached_response(connection, MHD_HTTP_FORBIDDEN, auth_failure_response_creator());
		return false;
	}
	if (!datum_secure_strequals(datum_config.api_csrf_token, sizeof(datum_config.api_csrf_token)-1, json_string_value(j_csrf))) {
		DLOG_DEBUG("Wrong CSRF token in request");
		datum_api_submit_uncached_response(connection, MHD_HTTP_FORBIDDEN, auth_failure_response_creator());
		return false;
	}
	
	return datum_api_check_admin_password_httponly(connection, auth_failure_response_creator);
}

static int datum_api_asset(struct MHD_Connection * const connection, const char * const mimetype, const char * const data, const size_t datasz, const char * const etag) {
	const char * const if_none_match_header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "If-None-Match");
	if (if_none_match_header && 0 == strcmp(if_none_match_header, etag)) {
		struct MHD_Response *response = datum_api_create_empty_mhd_response();
		MHD_add_response_header(response, "Etag", etag);
		int ret = MHD_queue_response(connection, MHD_HTTP_NOT_MODIFIED, response);
		MHD_destroy_response(response);
		return ret;
	}
	struct MHD_Response * const response = MHD_create_response_from_buffer(datasz, (void*)data, MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(response, "Content-Type", mimetype);
	MHD_add_response_header(response, "Etag", etag);
	const int ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
}

void datum_api_cmd_empty_thread(int tid) {
	if (global_stratum_app && (tid >= 0) && (tid < global_stratum_app->max_threads)) {
		DLOG_WARN("API Request to empty stratum thread %d!", tid);
		global_stratum_app->datum_threads[tid].empty_request = true;
	}
}

void datum_api_cmd_kill_client(int tid, int cid) {
	if (global_stratum_app && (tid >= 0) && (tid < global_stratum_app->max_threads)) {
		if ((cid >= 0) && (cid < global_stratum_app->max_clients_thread)) {
			DLOG_WARN("API Request to disconnect stratum client %d/%d!", tid, cid);
			global_stratum_app->datum_threads[tid].client_data[cid].kill_request = true;
			global_stratum_app->datum_threads[tid].has_client_kill_request = true;
		}
	}
}

void datum_api_cmd_kill_client2(const char * const data, const size_t size, const char ** const redirect_p) {
	const char * const end = &data[size];
	const char *underscore_pos = memchr(data, '_', size);
	if (!underscore_pos) return;
	const size_t tid_size = underscore_pos - data;
	const int tid = datum_atoi_strict(data, tid_size);
	const char *p = &underscore_pos[1];
	underscore_pos = memchr(p, '_', end - p);
	if (!underscore_pos) underscore_pos = end;
	const int cid = datum_atoi_strict(p, underscore_pos - p);
	
	// Valid input; unconditionally redirect back to clients dashboard
	*redirect_p = "/clients";
	
	if (tid < 0 || tid >= global_stratum_app->max_threads || cid < 0 || cid >= global_stratum_app->max_clients_thread) {
		return;
	}
	
	if (underscore_pos != end) {
		// Check it's the same client intended
		p = &underscore_pos[1];
		underscore_pos = memchr(p, '_', end - p);
		if (!underscore_pos) underscore_pos = end;
		const uint64_t connect_tsms = datum_atoi_strict_u64(p, underscore_pos - p);
		const T_DATUM_MINER_DATA * const m = global_stratum_app->datum_threads[tid].client_data[cid].app_client_data;
		if (connect_tsms != m->connect_tsms) {
			DLOG_WARN("API Request to disconnect FORMER stratum client %d/%d (ignored; connect tsms req=%lu vs cur=%lu)", tid, cid, (unsigned long)connect_tsms, (unsigned long)m->connect_tsms);
			return;
		}
		p = &underscore_pos[1];
		const uint64_t unique_id = datum_atoi_strict_u64(p, end - p);
		if (unique_id != m->unique_id) {
			DLOG_WARN("API Request to disconnect FORMER stratum client %d/%d (ignored; unique id req=%lu vs cur=%lu)", tid, cid, (unsigned long)unique_id, (unsigned long)m->unique_id);
			return;
		}
	}
	datum_api_cmd_kill_client(tid, cid);
}

int datum_api_cmd(struct MHD_Connection *connection, char *post, int len) {
	struct MHD_Response *response;
	char output[1024];
	int sz = 0;
	json_t *root, *cmd, *param;
	json_error_t error;
	const char *cstr;
	int tid,cid;
	
	if ((len) && (post)) {
		DLOG_DEBUG("POST DATA: %s", post);
		
		if (post[0] == '{') {
			// attempt to parse JSON command
			root = json_loadb(post, len, 0, &error);
			if (root) {
				if (json_is_object(root) && (cmd = json_object_get(root, "cmd"))) {
					if (!datum_api_check_admin_password(connection, root, datum_api_create_empty_mhd_response)) {
						json_decref(root);
						return MHD_YES;
					}
					
					if (json_is_string(cmd)) {
						cstr = json_string_value(cmd);
						DLOG_DEBUG("JSON CMD: %s",cstr);
						switch(cstr[0]) {
							case 'e': {
								if (!strcmp(cstr,"empty_thread")) {
									param = json_object_get(root, "tid");
									if (json_is_integer(param)) {
										datum_api_cmd_empty_thread(json_integer_value(param));
									}
									break;
								}
								break;
							}
							case 'k': {
								if (!strcmp(cstr,"kill_client")) {
									param = json_object_get(root, "tid");
									if (json_is_integer(param)) {
										tid = json_integer_value(param);
										param = json_object_get(root, "cid");
										if (json_is_integer(param)) {
											cid = json_integer_value(param);
											datum_api_cmd_kill_client(tid,cid);
										}
									}
									break;
								}
								break;
							}
							default: break;
						}
					}
				}
				json_decref(root);
			}
		} else {
			root = json_object();
			if (!datum_api_formdata_to_json(connection, post, len, root)) {
				json_decref(root);
				return datum_api_do_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
			}
			
			if (!datum_api_check_admin_password(connection, root, datum_api_create_empty_mhd_response)) {
				json_decref(root);
				return MHD_YES;
			}
			
			const char *redirect = "/";
			
			param = json_object_get(root, "empty_thread");
			if (param) {
				tid = datum_atoi_strict(json_string_value(param), json_string_length(param));
				if (tid != -1) {
					datum_api_cmd_empty_thread(tid);
					redirect = "/threads";
				}
			}
			
			param = json_object_get(root, "kill_client");
			if (param) {
				const char * const data = json_string_value(param);
				const size_t size = json_string_length(param);
				datum_api_cmd_kill_client2(data, size, &redirect);
			}
			
			response = datum_api_create_empty_mhd_response();
			MHD_add_response_header(response, "Location", redirect);
			return datum_api_submit_uncached_response(connection, MHD_HTTP_FOUND, response);
		}
	}
	
	sprintf(output, "{}");
	response = MHD_create_response_from_buffer (sz, (void *) output, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "application/json");
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

int datum_api_coinbaser(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	T_DATUM_STRATUM_JOB *sjob;
	int j, i, max_sz = 0, sz = 0;
	char tempaddr[256];
	uint64_t tv = 0;
	char *output = NULL;
	
	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	j = global_latest_stratum_job_index;
	sjob = (j >= 0 && j < MAX_STRATUM_JOBS) ? global_cur_stratum_jobs[j] : NULL;
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
	
	max_sz = www_coinbaser_top_html_sz + www_foot_html_sz + (sjob ? (sjob->available_coinbase_outputs_count * 512) : 0) + 2048; // approximate max size of each row
	output = calloc(max_sz+16,1);
	if (!output) {
		return MHD_NO;
	}
	
	sz = snprintf(output, max_sz-1-sz, "%s", www_coinbaser_top_html);
	sz += snprintf(&output[sz], max_sz-1-sz, "<TABLE><TR><TD><U>Value</U></TD>  <TD><U>Address</U></TD></TR>");
	
	if (sjob) {
		for(i=0;i<sjob->available_coinbase_outputs_count;i++) {
			output_script_2_addr(sjob->available_coinbase_outputs[i].output_script, sjob->available_coinbase_outputs[i].output_script_len, tempaddr);
			sz += snprintf(&output[sz], max_sz-1-sz, "<TR><TD>%.8f BTC</TD><TD>%s</TD></TR>", (double)sjob->available_coinbase_outputs[i].value_sats / (double)100000000.0, tempaddr);
			tv += sjob->available_coinbase_outputs[i].value_sats;
		}
		
		if (tv < sjob->coinbase_value) {
			output_script_2_addr(sjob->pool_addr_script, sjob->pool_addr_script_len, tempaddr);
			sz += snprintf(&output[sz], max_sz-1-sz, "<TR><TD>%.8f BTC</TD><TD>%s</TD></TR>", (double)(sjob->coinbase_value - tv) / (double)100000000.0, tempaddr);
		}
	}
	
	sz += snprintf(&output[sz], max_sz-1-sz, "</TABLE>");
	sz += snprintf(&output[sz], max_sz-1-sz, "%s", www_foot_html);
	
	response = MHD_create_response_from_buffer (sz, (void *) output, MHD_RESPMEM_MUST_FREE);
	MHD_add_response_header(response, "Content-Type", "text/html");
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

int datum_api_thread_dashboard(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	int sz=0, max_sz = 0, j, ii;
	char *output = NULL;
	T_DATUM_MINER_DATA *m = NULL;
	uint64_t tsms;
	double hr;
	unsigned char astat;
	double thr = 0.0;
	int subs,conns;
	
	const int max_threads = global_stratum_app ? global_stratum_app->max_threads : 0;
	
	max_sz = www_threads_top_html_sz + www_foot_html_sz + (max_threads * 512) + 2048; // approximate max size of each row
	output = calloc(max_sz+16,1);
	if (!output) {
		return MHD_NO;
	}
	
	const bool have_admin = datum_config.api_admin_password_len;
	
	tsms = current_time_millis();
	
	sz = snprintf(output, max_sz-1-sz, "%s", www_threads_top_html);
	sz += snprintf(&output[sz], max_sz-1-sz, "<form action='/cmd' method='post'><input type='hidden' name='csrf' value='%s' /><TABLE><TR><TD><U>TID</U></TD>  <TD><U>Connection Count</U></TD>  <TD><U>Sub Count</U></TD> <TD><U>Approx. Hashrate</U></TD> <TD><U>Command</U></TD></TR>", datum_config.api_csrf_token);
	for (j = 0; j < max_threads; ++j) {
		thr = 0.0;
		subs = 0;
		conns = 0;
		
		for(ii=0;ii<global_stratum_app->max_clients_thread;ii++) {
			if (global_stratum_app->datum_threads[j].client_data[ii].fd > 0) {
				conns++;
				m = (T_DATUM_MINER_DATA *)global_stratum_app->datum_threads[j].client_data[ii].app_client_data;
				if (m->subscribed) {
					subs++;
					astat = m->stats.active_index?0:1; // inverted
					hr = 0.0;
					if ((m->stats.last_swap_ms > 0) && (m->stats.diff_accepted[astat] > 0)) {
						hr = ((double)m->stats.diff_accepted[astat] / (double)((double)m->stats.last_swap_ms/1000.0)) * 0.004294967296; // Th/sec based on shares/sec
					}
					if (((double)(tsms - m->stats.last_swap_tsms)/1000.0) < 180.0) {
						thr += hr;
					}
				}
			}
		}
		if (conns) {
			sz += snprintf(&output[sz], max_sz-1-sz, "<TR><TD>%d</TD>  <TD>%d</TD>  <TD>%d</TD> <TD>%.2f Th/s</TD><TD><button ", j, conns, subs, thr);
			if (have_admin) {
				sz += snprintf(&output[sz], max_sz-1-sz, "name='empty_thread' value='%d' onclick=\"sendPostRequest('/cmd', {cmd:'empty_thread',tid:%d}); return false;\"", j, j);
			} else {
				sz += snprintf(&output[sz], max_sz-1-sz, "disabled");
			}
			sz += snprintf(&output[sz], max_sz-1-sz, ">Disconnect All</button></TD></TR>");
		}
	}
	sz += snprintf(&output[sz], max_sz-1-sz, "</TABLE></form>");
	if (have_admin) {
		sz += snprintf(&output[sz], max_sz-1-sz, "<script>function sendPostRequest(url, data){data.csrf='%s';fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});}</script>", datum_config.api_csrf_token);
	}
	sz += snprintf(&output[sz], max_sz-1-sz, "%s", www_foot_html);
	
	response = MHD_create_response_from_buffer (sz, (void *) output, MHD_RESPMEM_MUST_FREE);
	MHD_add_response_header(response, "Content-Type", "text/html");
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

int datum_api_client_dashboard(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	int connected_clients = 0;
	int i, sz = 0, max_sz = 0, j, ii;
	char *output = NULL;
	T_DATUM_MINER_DATA *m = NULL;
	uint64_t tsms;
	double hr;
	unsigned char astat;
	double thr = 0.0;
	
	const int max_threads = global_stratum_app ? global_stratum_app->max_threads : 0;
	
	for (i = 0; i < max_threads; ++i) {
		connected_clients+=global_stratum_app->datum_threads[i].connected_clients;
	}
	
	max_sz = www_clients_top_html_sz + www_foot_html_sz + (connected_clients * 1024) + 2048; // approximate max size of each row
	output = calloc(max_sz+16,1);
	if (!output) {
		return MHD_NO;
	}
	
	tsms = current_time_millis();
	
	sz = snprintf(output, max_sz-1-sz, "%s", www_clients_top_html);
	
	if (!datum_config.api_admin_password_len) {
		sz += snprintf(&output[sz], max_sz-1-sz, "This page requires admin access (not configured)");
		sz += snprintf(&output[sz], max_sz-1-sz, "%s", www_foot_html);
		
		response = MHD_create_response_from_buffer(sz, output, MHD_RESPMEM_MUST_FREE);
		MHD_add_response_header(response, "Content-Type", "text/html");
		return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
	}
	if (!datum_api_check_admin_password_httponly(connection, datum_api_create_empty_mhd_response)) {
		return MHD_YES;
	}
	
	sz += snprintf(&output[sz], max_sz-1-sz, "<form action='/cmd' method='post'><input type='hidden' name='csrf' value='%s' /><TABLE><TR><TD><U>TID/CID</U></TD>  <TD><U>RemHost</U></TD>  <TD><U>Auth Username</U></TD> <TD><U>Subbed</U></TD> <TD><U>Last Accepted</U></TD> <TD><U>VDiff</U></TD> <TD><U>DiffA (A)</U></TD> <TD><U>DiffR (R)</U></TD> <TD><U>Hashrate (age)</U></TD> <TD><U>Coinbase</U></TD> <TD><U>UserAgent</U> </TD><TD><U>Command</U></TD></TR>", datum_config.api_csrf_token);
	
	for (j = 0; j < max_threads; ++j) {
		for(ii=0;ii<global_stratum_app->max_clients_thread;ii++) {
			if (global_stratum_app->datum_threads[j].client_data[ii].fd > 0) {
				m = (T_DATUM_MINER_DATA *)global_stratum_app->datum_threads[j].client_data[ii].app_client_data;
				sz += snprintf(&output[sz], max_sz-1-sz, "<TR><TD>%d/%d</TD>", j,ii);
				
				sz += snprintf(&output[sz], max_sz-1-sz, "<TD>%s</TD>", global_stratum_app->datum_threads[j].client_data[ii].rem_host);
				
				sz += snprintf(&output[sz], max_sz-1-sz, "<TD>");
				sz += strncpy_html_escape(&output[sz], m->last_auth_username, max_sz-1-sz);
				sz += snprintf(&output[sz], max_sz-1-sz, "</TD>");
				
				if (m->subscribed) {
					sz += snprintf(&output[sz], max_sz-1-sz, "<TD> <span style=\"font-family: monospace;\">%4.4x</span> %.1fs</TD>", m->sid, (double)(tsms - m->subscribe_tsms)/1000.0);
					
					if (m->stats.last_share_tsms) {
						sz += snprintf(&output[sz], max_sz-1-sz, "<TD>%.1fs</TD>", (double)(tsms - m->stats.last_share_tsms)/1000.0);
					} else {
						sz += snprintf(&output[sz], max_sz-1-sz, "<TD>N/A</TD>");
					}
					
					sz += snprintf(&output[sz], max_sz-1-sz, "<TD>%"PRIu64"</TD>", m->current_diff);
					sz += snprintf(&output[sz], max_sz-1-sz, "<TD>%"PRIu64" (%"PRIu64")</TD>", m->share_diff_accepted, m->share_count_accepted);
					
					hr = 0.0;
					if (m->share_diff_accepted > 0) {
						hr = ((double)m->share_diff_rejected / (double)(m->share_diff_accepted + m->share_diff_rejected))*100.0;
					}
					sz += snprintf(&output[sz], max_sz-1-sz, "<TD>%"PRIu64" (%"PRIu64") %.2f%%</TD>", m->share_diff_rejected, m->share_count_rejected, hr);
					
					astat = m->stats.active_index?0:1; // inverted
					hr = 0.0;
					if ((m->stats.last_swap_ms > 0) && (m->stats.diff_accepted[astat] > 0)) {
						hr = ((double)m->stats.diff_accepted[astat] / (double)((double)m->stats.last_swap_ms/1000.0)) * 0.004294967296; // Th/sec based on shares/sec
					}
					if (((double)(tsms - m->stats.last_swap_tsms)/1000.0) < 180.0) {
						thr += hr;
					}
					if (m->share_diff_accepted > 0) {
						sz += snprintf(&output[sz], max_sz-1-sz, "<TD>%.2f Th/s (%.1fs)</TD>", hr, (double)(tsms - m->stats.last_swap_tsms)/1000.0);
					} else {
						sz += snprintf(&output[sz], max_sz-1-sz, "<TD>N/A</TD>");
					}
					
					if (m->coinbase_selection < (sizeof(cbnames) / sizeof(cbnames[0]))) {
						sz += snprintf(&output[sz], max_sz-1-sz, "<TD>%s</TD>", cbnames[m->coinbase_selection]);
					} else {
						sz += snprintf(&output[sz], max_sz-1-sz, "<TD>Unknown</TD>");
					}
					
					sz += snprintf(&output[sz], max_sz-1-sz, "<TD>");
					sz += strncpy_html_escape(&output[sz], m->useragent, max_sz-1-sz);
					sz += snprintf(&output[sz], max_sz-1-sz, "</TD>");
				} else {
					sz += snprintf(&output[sz], max_sz-1-sz, "<TD COLSPAN=\"8\">Not Subscribed</TD>");
				}
				
				sz += snprintf(&output[sz], max_sz-1-sz, "<TD><button name='kill_client' value='%d_%d_%lu_%lu' onclick=\"sendPostRequest('/cmd', {cmd:'kill_client',tid:%d,cid:%d,t:%lu,id:%lu}); return false;\">Kick</button></TD></TR>", j, ii, (unsigned long)m->connect_tsms, (unsigned long)m->unique_id, j, ii, (unsigned long)m->connect_tsms, (unsigned long)m->unique_id);
			}
		}
	}
	
	sz += snprintf(&output[sz], max_sz-1-sz, "</TABLE></form><p class=\"table-footer\">Total active hashrate estimate: %.2f Th/s</p><script>function sendPostRequest(url, data){data.csrf='%s';fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});}</script>", thr, datum_config.api_csrf_token);
	sz += snprintf(&output[sz], max_sz-1-sz, "%s", www_foot_html);
	
	// return the home page with some data and such
	response = MHD_create_response_from_buffer (sz, (void *) output, MHD_RESPMEM_MUST_FREE);
	MHD_add_response_header(response, "Content-Type", "text/html");
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

size_t datum_api_fill_config_var(const char *var_start, const size_t var_name_len, char * const replacement, const size_t replacement_max_len, const T_DATUM_API_DASH_VARS * const vardata) {
	const char *colon_pos = memchr(var_start, ':', var_name_len);
	const char *var_start_2 = colon_pos ? &colon_pos[1] : var_start;
	const char * const var_end = &var_start[var_name_len];
	const size_t var_name_len_2 = var_end - var_start_2;
	const char * const underscore_pos = memchr(var_start_2, '_', var_name_len_2);
	int val;
	if (var_name_len_2 == 3 && 0 == strncmp(var_start_2, "*ro", 3)) {
		val = !datum_config.api_modify_conf;
		if (!colon_pos) {
			var_start = "readonly:";
			colon_pos = &var_start[8];
		}
	} else if (var_name_len_2 == 24 && 0 == strncmp(var_start_2, "*datum_pool_pass_workers", 24)) {
		val = datum_config.datum_pool_pass_workers && !datum_config.datum_pool_pass_full_users;
	} else if (var_name_len_2 == 16 && 0 == strncmp(var_start_2, "*datum_pool_host", 16)) {
		const char *s = NULL;
		if (datum_config.datum_pool_host[0]) {
			s = datum_config.datum_pool_host;
		} else if (datum_config.config_json) {
			const json_t * const config = datum_config.config_json;
			json_t *j = json_object_get(config, "datum");
			if (j) j = json_is_object(j) ? json_object_get(j, "pool_host(old)") : NULL;
			if (j && json_is_string(j) && json_string_length(j) <= 1023) {
				s = json_string_value(j);
			}
		}
		if (!s) {
			const T_DATUM_CONFIG_ITEM * const cfginfo = datum_config_get_option_info("datum", 5, "pool_host", 9);
			s = cfginfo->default_string[0];
		}
		size_t copy_sz = strlen(s);
		if (copy_sz >= replacement_max_len) copy_sz = replacement_max_len - 1;
		memcpy(replacement, s, copy_sz);
		return copy_sz;
	} else if (var_name_len_2 == 27 && 0 == strncmp(var_start_2, "*username_behaviour_private", 27)) {
		val = !(datum_config.datum_pool_pass_workers || datum_config.datum_pool_pass_full_users);
	} else if (var_name_len_2 == 22 && 0 == strncmp(var_start_2, "*reward_sharing_prefer", 22)) {
		val = (!datum_config.datum_pooled_mining_only) && datum_config.datum_pool_host[0];
	} else if (var_name_len_2 == 21 && 0 == strncmp(var_start_2, "*reward_sharing_never", 21)) {
		val = (!datum_config.datum_pooled_mining_only) && !datum_config.datum_pool_host[0];
	} else if (var_name_len_2 == 34 && 0 == strncmp(var_start_2, "*mining_coinbase_tag_secondary_max", 34)) {
		val = 88 - strlen(datum_config.mining_coinbase_tag_primary);
		if (val > 60) val = 60;
	} else if (var_name_len_2 == 11 && 0 == strncmp(var_start_2, "*CSRF_TOKEN", 11)) {
		size_t copy_sz = strlen(datum_config.api_csrf_token);
		if (copy_sz >= replacement_max_len) copy_sz = replacement_max_len - 1;
		memcpy(replacement, datum_config.api_csrf_token, copy_sz);
		return copy_sz;
	} else if (underscore_pos) {
		const T_DATUM_CONFIG_ITEM * const item = datum_config_get_option_info(var_start_2, underscore_pos - var_start_2, &underscore_pos[1], var_end - &underscore_pos[1]);
		if (item) {
			switch (item->var_type) {
				case DATUM_CONF_INT: {
					val = *((int *)item->ptr);
					break;
				}
				case DATUM_CONF_BOOL: {
					val = *((bool *)item->ptr);
					if ((!colon_pos) && replacement_max_len > 5) {
						const size_t len = val ? 4 : 5;
						memcpy(replacement, val ? "true" : "false", len);
						return len;
					}
					break;
				}
				case DATUM_CONF_STRING: {
					const char * const s = (char *)item->ptr;
					if (colon_pos) {
						DLOG_ERROR("%s: '%.*s' modifier not implemented for %s", __func__, (int)(colon_pos - var_start), var_start, "DATUM_CONF_STRING");
						break;
					}
					size_t copy_sz = strlen(s);
					if (copy_sz >= replacement_max_len) copy_sz = replacement_max_len - 1;
					memcpy(replacement, s, copy_sz);
					return copy_sz;
				}
				case DATUM_CONF_STRING_ARRAY: {
					DLOG_ERROR("%s: %s not implemented", __func__, "DATUM_CONF_STRING_ARRAY");
					break;
				}
			}
		} else {
			DLOG_ERROR("%s: '%.*s' not implemented", __func__, (int)(var_end - var_start_2), var_start_2);
			return 0;
		}
	} else {
		DLOG_ERROR("%s: '%.*s' not implemented", __func__, (int)(var_end - var_start_2), var_start_2);
		return 0;
	}
	
	assert(replacement_max_len > 0);
	
	if (colon_pos) {
		if (0 == strncmp(var_start, "readonly:", 9) || 0 == strncmp(var_start, "selected:", 9) || 0 == strncmp(var_start, "checked:", 8) || 0 == strncmp(var_start, "disabled:", 9)) {
			size_t attr_len;
			if (val) {
				attr_len = colon_pos - var_start;
				if (attr_len + 2 > replacement_max_len) attr_len = replacement_max_len - 2;
				replacement[0] = ' ';
				memcpy(&replacement[1], var_start, attr_len);
				++attr_len;
			} else {
				attr_len = 0;
			}
			return attr_len;
		} else if (0 == strncmp(var_start, "msg:", 4)) {
			if (val) {
				static const char * const msg = "<br/><em>Config file disallows editing</em>";
				const size_t len = strlen(msg);
				memcpy(replacement, msg, len);
				return len;
			} else {
				return 0;
			}
		} else {
			DLOG_ERROR("%s: '%.*s' modifier not implemented", __func__, (int)(colon_pos - var_start), var_start);
			return 0;
		}
	}
	
	return snprintf(replacement, replacement_max_len, "%d", val);
}

int datum_api_config_dashboard(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	size_t sz = 0, max_sz = 0;
	char *output = NULL;
	
	max_sz = www_config_html_sz * 2;
	output = malloc(max_sz);
	if (!output) {
		return MHD_NO;
	}
	
	sz += datum_api_fill_vars(www_config_html, output, max_sz, datum_api_fill_config_var, NULL);
	
	response = MHD_create_response_from_buffer(sz, output, MHD_RESPMEM_MUST_FREE);
	MHD_add_response_header(response, "Content-Type", "text/html");
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

#ifndef JSON_PRESERVE_ORDER
#define JSON_PRESERVE_ORDER 0
#endif

// Only modifies config_json; writing is done later
void datum_api_json_modify_new(const char * const category, const char * const key, json_t * const val) {
	json_t * const config = datum_config.config_json;
	assert(config);
	
	json_t *j = json_object_get(config, category);
	if (!j) {
		j = json_object();
		json_object_set_new(config, category, j);
	}
	json_object_set_new(j, key, val);
}

bool datum_api_json_write() {
	json_t * const config = datum_config.config_json;
	assert(config);
	assert(datum_gateway_config_filename);
	
	char buf[0x100];
	int rv = snprintf(buf, sizeof(buf) - 4, "%s", datum_gateway_config_filename);
	assert(rv > 0);
	strcpy(&buf[rv], ".new");
	
	if (json_dump_file(config, buf, JSON_PRESERVE_ORDER | JSON_INDENT(4))) {
		DLOG_ERROR("Failed to write new config to %s", buf);
		return false;
	}
	if (rename(buf, datum_gateway_config_filename)) {
		DLOG_ERROR("Failed to rename new config %s to %s", buf, datum_gateway_config_filename);
		return false;
	}
	DLOG_INFO("Wrote new config to %s", datum_gateway_config_filename);
	return true;
}

struct datum_api_config_set_status {
	json_t *errors;
	bool modified_config;
	bool need_restart;
};

// This does several steps:
// - If the value is unchanged, return true without doing anything
// - Validate the value without changing anything
// - Change the runtime dataum_config (and ensure it goes live)
// - Modify the config file
// If anything fails (including validation), errors is appended and false is returned
bool datum_api_config_set(const char * const key, const char * const val, struct datum_api_config_set_status * const status) {
	json_t * const errors = status->errors;
	if (0 == strcmp(key, "mining_pool_address")) {
		if (0 == strcmp(val, datum_config.mining_pool_address)) return true;
		unsigned char dummy[64];
		if (!addr_2_output_script(val, &dummy[0], 64)) {
			json_array_append_new(errors, json_string_nocheck("Invalid Bitcoin Address"));
			return false;
		}
		strcpy(datum_config.mining_pool_address, val);
		datum_api_json_modify_new("mining", "pool_address", json_string(val));
	} else if (0 == strcmp(key, "username_behaviour")) {
		if (0 == strcmp(val, "datum_pool_pass_full_users")) {
			if (datum_config.datum_pool_pass_full_users) return true;
			datum_config.datum_pool_pass_full_users = true;
			// datum_pool_pass_workers doesn't matter with datum_pool_pass_full_users enabled
		} else if (0 == strcmp(val, "datum_pool_pass_workers")) {
			if (datum_config.datum_pool_pass_workers && !datum_config.datum_pool_pass_full_users) return true;
			datum_config.datum_pool_pass_full_users = false;
			datum_config.datum_pool_pass_workers = true;
		} else if (0 == strcmp(val, "private")) {
			if (!(datum_config.datum_pool_pass_workers || datum_config.datum_pool_pass_full_users)) return true;
			datum_config.datum_pool_pass_full_users = false;
			datum_config.datum_pool_pass_workers = false;
		} else {
			json_array_append_new(errors, json_string_nocheck("Invalid option for \"Send Miner Usernames To Pool\""));
			return false;
		}
		datum_api_json_modify_new("datum", "pool_pass_full_users", json_boolean(datum_config.datum_pool_pass_full_users));
		if (!datum_config.datum_pool_pass_full_users) {
			datum_api_json_modify_new("datum", "pool_pass_workers", json_boolean(datum_config.datum_pool_pass_workers));
		}
	} else if (0 == strcmp(key, "mining_coinbase_tag_secondary")) {
		if (0 == strcmp(val, datum_config.mining_coinbase_tag_secondary)) return true;
		size_t len_limit = 88 - strlen(datum_config.mining_coinbase_tag_primary);
		if (len_limit > 60) len_limit = 60;
		if (strlen(val) > len_limit) {
			json_array_append_new(errors, json_string_nocheck("Coinbase Tag is too long"));
			return false;
		}
		strcpy(datum_config.mining_coinbase_tag_secondary, val);
		datum_api_json_modify_new("mining", "coinbase_tag_secondary", json_string(val));
	} else if (0 == strcmp(key, "mining_coinbase_unique_id")) {
		const int val_int = datum_atoi_strict(val, strlen(val));
		if (val_int == datum_config.coinbase_unique_id) return true;
		if (val_int > 65535 || val_int < 0) {
			json_array_append_new(errors, json_string_nocheck("Unique Gateway ID must be between 0 and 65535"));
			return false;
		}
		datum_config.coinbase_unique_id = val_int;
		datum_api_json_modify_new("mining", "coinbase_unique_id", json_integer(val_int));
	} else if (0 == strcmp(key, "reward_sharing")) {
		json_t * const config = datum_config.config_json;
		assert(config);
		
		bool want_datum_pool_host = false;
		if (0 == strcmp(val, "require")) {
			if (datum_config.datum_pool_host[0] && datum_config.datum_pooled_mining_only) return true;
			datum_config.datum_pooled_mining_only = true;
			want_datum_pool_host = true;
		} else if (0 == strcmp(val, "prefer")) {
			if (datum_config.datum_pool_host[0] && !datum_config.datum_pooled_mining_only) return true;
			datum_config.datum_pooled_mining_only = false;
			want_datum_pool_host = true;
		} else if (0 == strcmp(val, "never")) {
			if (!(datum_config.datum_pool_host[0] || datum_config.datum_pooled_mining_only)) return true;
			datum_config.datum_pooled_mining_only = false;
			datum_config.datum_pool_host[0] = '\0';
			
			// Only copy the old value if it's in the config file
			json_t *j = json_object_get(config, "datum");
			if (j) j = json_is_object(j) ? json_object_get(j, "pool_host") : NULL;
			if (j) {
				datum_api_json_modify_new("datum", "pool_host(old)", json_incref(j));
			}
			
			datum_api_json_modify_new("datum", "pool_host", json_string_nocheck(""));
		} else {
			json_array_append_new(errors, json_string_nocheck("Invalid option for \"Collaborative reward sharing\""));
			return false;
		}
		if (want_datum_pool_host && !datum_config.datum_pool_host[0]) {
			json_t *j = json_object_get(config, "datum");
			if (j) j = json_is_object(j) ? json_object_get(j, "pool_host(old)") : NULL;
			if (j && json_is_string(j) && json_string_length(j) <= 1023) {
				strcpy(datum_config.datum_pool_host, json_string_value(j));
				json_object_del(j, "pool_host(old)");
				datum_api_json_modify_new("datum", "pool_host", json_string(datum_config.datum_pool_host));
			} else {
				const T_DATUM_CONFIG_ITEM * const cfginfo = datum_config_get_option_info("datum", 5, "pool_host", 9);
				strcpy(datum_config.datum_pool_host, cfginfo->default_string[0]);
				
				// Avoiding using null here because older versions handled it poorly
				json_t *j = json_object_get(config, "datum");
				if (j) json_object_del(j, "pool_host");
			}
		}
		datum_api_json_modify_new("datum", "pooled_mining_only", json_boolean(datum_config.datum_pooled_mining_only));
		// TODO: apply change without restarting
		status->need_restart = true;
	} else if (0 == strcmp(key, "datum_pool_host")) {
		if (0 == strcmp(val, datum_config.datum_pool_host)) return true;
		if (strlen(val) > 1023) {
			json_array_append_new(errors, json_string_nocheck("Pool Host is too long"));
			return false;
		}
		if (datum_config.datum_pool_host[0]) {
			strcpy(datum_config.datum_pool_host, val);
			datum_api_json_modify_new("datum", "pool_host", json_string(val));
			// TODO: apply change without restarting
			// TODO: switch pools smoother (keep old connection alive for share submissions until those jobs expire)
			status->need_restart = true;
		} else {
			json_t * const config = datum_config.config_json;
			assert(config);
			json_t *j = json_object_get(config, "datum");
			if (j) j = json_is_object(j) ? json_object_get(j, "pool_host(old)") : NULL;
			const T_DATUM_CONFIG_ITEM * const cfginfo = datum_config_get_option_info("datum", 5, "pool_host", 9);
			// Avoid setting the default host in the config file, unless something else was already there
			if (0 != strcmp(val, cfginfo->default_string[0]) || json_is_string(j)) {
				datum_api_json_modify_new("datum", "pool_host(old)", json_string(val));
			}
		}
	} else if (0 == strcmp(key, "datum_pool_port")) {
		const int val_int = datum_atoi_strict(val, strlen(val));
		if (val_int == datum_config.datum_pool_port) return true;
		if (val_int > 65535 || val_int < 1) {
			json_array_append_new(errors, json_string_nocheck("Pool Port must be between 1 and 65535"));
			return false;
		}
		datum_config.datum_pool_port = val_int;
		datum_api_json_modify_new("datum", "pool_port", json_integer(val_int));
		// TODO: apply change without restarting
		// TODO: switch pools smoother (keep old connection alive for share submissions until those jobs expire)
		status->need_restart = true;
	} else if (0 == strcmp(key, "datum_pool_pubkey")) {
		if (0 == strcmp(val, datum_config.datum_pool_pubkey)) return true;
		if (strlen(val) > 1023) {
			json_array_append_new(errors, json_string_nocheck("Pool Pubkey is too long"));
			return false;
		}
		strcpy(datum_config.datum_pool_pubkey, val);
		datum_api_json_modify_new("datum", "pool_pubkey", json_string(val));
		// TODO: apply change without restarting
		// TODO: switch pools smoother (keep old connection alive for share submissions until those jobs expire)
		status->need_restart = true;
	} else if (0 == strcmp(key, "stratum_fingerprint_miners")) {
		bool val_bool;
		if (!datum_str_to_bool_strict(val, &val_bool)) {
			json_array_append_new(errors, json_string_nocheck("\"Fingerprint and workaround known miner bugs\" must be 0 or 1"));
			return false;
		}
		if (val_bool == datum_config.stratum_v1_fingerprint_miners) return true;
		datum_config.stratum_v1_fingerprint_miners = val_bool;
		datum_api_json_modify_new("stratum", "fingerprint_miners", json_boolean(val_bool));
		// TODO: apply change to connected miners?
	} else if (0 == strcmp(key, "datum_always_pay_self")) {
		bool val_bool;
		if (!datum_str_to_bool_strict(val, &val_bool)) {
			json_array_append_new(errors, json_string_nocheck("\"Always pay self\" must be 0 or 1"));
			return false;
		}
		if (val_bool == datum_config.datum_always_pay_self) return true;
		datum_config.datum_always_pay_self = val_bool;
		datum_api_json_modify_new("datum", "always_pay_self", json_boolean(val_bool));
	} else if (0 == strcmp(key, "bitcoind_work_update_seconds")) {
		const int val_int = datum_atoi_strict(val, strlen(val));
		if (val_int == datum_config.bitcoind_work_update_seconds) return true;
		if (val_int > 120 || val_int < 5) {
			json_array_append_new(errors, json_string_nocheck("bitcoind work update interval must be between 5 and 120"));
			return false;
		}
		datum_config.bitcoind_work_update_seconds = val_int;
		datum_api_json_modify_new("bitcoind", "work_update_seconds", json_integer(val_int));
		if (datum_config.bitcoind_work_update_seconds >= datum_config.datum_protocol_global_timeout - 5) {
			datum_config.datum_protocol_global_timeout = val_int + 5;
			datum_api_json_modify_new("datum", "protocol_global_timeout", json_integer(val_int + 5));
		}
		// TODO: apply change without restarting (and don't interfere with existing jobs)
		status->need_restart = true;
	} else if (0 == strcmp(key, "bitcoind_rpcurl")) {
		if (0 == strcmp(val, datum_config.bitcoind_rpcurl)) return true;
		if (strlen(val) > 128) {
			json_array_append_new(errors, json_string_nocheck("bitcoind RPC URL is too long"));
			return false;
		}
		strcpy(datum_config.bitcoind_rpcurl, val);
		datum_api_json_modify_new("bitcoind", "rpcurl", json_string(val));
	} else if (0 == strcmp(key, "bitcoind_rpcuser")) {
		if (0 == strcmp(val, datum_config.bitcoind_rpcuser)) return true;
		if (strlen(val) > 128) {
			json_array_append_new(errors, json_string_nocheck("bitcoind RPC user is too long"));
			return false;
		}
		strcpy(datum_config.bitcoind_rpcuser, val);
		datum_api_json_modify_new("bitcoind", "rpcuser", json_string(val));
		update_rpc_auth(&datum_config);
	} else if (0 == strcmp(key, "bitcoind_rpcpassword")) {
		if (0 == strcmp(val, datum_config.bitcoind_rpcpassword)) return true;
		if (!val[0]) return true;  // no password change
		if (strlen(val) > 128) {
			json_array_append_new(errors, json_string_nocheck("bitcoind RPC password is too long"));
			return false;
		}
		strcpy(datum_config.bitcoind_rpcpassword, val);
		datum_api_json_modify_new("bitcoind", "rpcpassword", json_string(val));
		update_rpc_auth(&datum_config);
	} else {
		char err[0x100];
		snprintf(err, sizeof(err), "Unknown setting '%s'", key);
		json_array_append_new(errors, json_string_nocheck(err));
		DLOG_ERROR("%s: '%s' not implemented", __func__, key);
		return false;
	}
	status->modified_config = true;
	return true;
}

static const char datum_api_config_errors_fmt[] = "<div class='err'>%s</div>";

size_t datum_api_fill_config_errors(const char *var_start, const size_t var_name_len, char * const replacement, const size_t replacement_max_len, const T_DATUM_API_DASH_VARS * const vardata) {
	const json_t * const errors = (void*)vardata;
	size_t index, sz = 0;
	json_t *j_it;
	
	json_array_foreach(errors, index, j_it) {
		sz += snprintf(&replacement[sz], replacement_max_len, datum_api_config_errors_fmt, json_string_value(j_it));
	}
	
	return sz;
}

void *datum_restart_thread(void *ptr) {
	// Give logger some time
	usleep(500000);
	
	// Wait for the response to actually get delivered
	// FIXME: css/svg/etc might fail (we don't support caching them yet)
	struct MHD_Daemon * const mhd = ptr;
	MHD_quiesce_daemon(mhd);
	while (MHD_get_daemon_info(mhd, MHD_DAEMON_INFO_CURRENT_CONNECTIONS)->num_connections > 0) {
		usleep(100);
	}
	MHD_stop_daemon(mhd);
	
	datum_reexec();
	abort();  // impossible to get here
}

int datum_api_config_post(struct MHD_Connection * const connection, char * const post, const int len) {
	struct MHD_Response *response;
	int ret;
	const char *key;
	json_t *j_it;
	
	if (!datum_config.api_modify_conf) {
		return datum_api_do_error(connection, MHD_HTTP_FORBIDDEN);
	}
	
	json_t * const j = json_object();
	if (!datum_api_formdata_to_json(connection, post, len, j)) {
		json_decref(j);
		return datum_api_do_error(connection, MHD_HTTP_INTERNAL_SERVER_ERROR);
	}
	
	if (!datum_api_check_admin_password(connection, j, datum_api_create_empty_mhd_response)) {
		json_decref(j);
		return MHD_YES;
	}
	json_object_del(j, "csrf");
	json_object_del(j, "password");
	
	{
		// Unchecked checkboxes are simply omitted, so a hidden field is used to convey them
		const json_t * const j_checkboxes = json_object_get(j, "checkboxes");
		const char * const checkboxes = json_string_value(j_checkboxes);
		const size_t checkboxes_len = json_string_length(j_checkboxes);
		const char *p = checkboxes;
		char buf[0x100];
		while (p[0] != '\0') {
			const char *p2 = strchr(p, ' ');
			if (!p2) p2 = &checkboxes[checkboxes_len];
			const size_t i_len = p2 - p;
			if (i_len < sizeof(buf)) {
				memcpy(buf, p, i_len);
				buf[i_len] = '\0';
				
				json_t * const j_cb = json_object_get(j, buf);
				if ((!j_cb) || json_is_null(j_cb)) {
					json_object_set_new_nocheck(j, buf, json_string_nocheck("0"));
				}
			}
			p = *p2 ? &p2[1] : p2;
		}
		json_object_del(j, "checkboxes");
	}
	
	json_t * const errors = json_array();
	struct datum_api_config_set_status status = {
		.errors = errors,
	};
	json_object_foreach(j, key, j_it) {
		datum_api_config_set(key, json_string_value(j_it), &status);
	}
	
	json_decref(j);
	
	if (status.modified_config) {
		if (!datum_api_json_write()) {
			if (status.need_restart) {
				json_array_append_new(errors, json_string_nocheck("Error writing new config file (changes will be lost)"));
			} else {
				json_array_append_new(errors, json_string_nocheck("Error writing new config file (changes will be lost at restart)"));
			}
		}
	}
	
	if (json_array_size(errors) > 0) {
		if (status.need_restart) {
			json_array_insert_new(errors, 0, json_string_nocheck("NOTE: Other changes require a gateway restart. Please wait a few seconds before trying again."));
		}
		
		size_t index, max_sz;
		max_sz = www_config_errors_html_sz;
		json_array_foreach(errors, index, j_it) {
			max_sz += json_string_length(j_it) + sizeof(datum_api_config_errors_fmt);
		}
		
		char * const output = malloc(max_sz);
		if (!output) {
			return MHD_NO;
		}
		const size_t sz = datum_api_fill_vars(www_config_errors_html, output, max_sz, datum_api_fill_config_errors, (void*)errors);
		
		response = MHD_create_response_from_buffer(sz, output, MHD_RESPMEM_MUST_FREE);
		MHD_add_response_header(response, "Content-Type", "text/html");
	} else if (status.need_restart) {
		response = MHD_create_response_from_buffer(www_config_restart_html_sz, (void*)www_config_restart_html, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", "text/html");
	} else {
		response = datum_api_create_empty_mhd_response();
		MHD_add_response_header(response, "Location", "/config");
	}
	json_decref(errors);

	ret = datum_api_submit_uncached_response(connection, MHD_HTTP_FOUND, response);
	
	if (status.need_restart) {
		DLOG_INFO("Config change requires restarting gateway, proceeding");
		struct MHD_Daemon * const mhd = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_DAEMON)->daemon;
		pthread_t pthread_datum_restart_thread;
		pthread_create(&pthread_datum_restart_thread, NULL, datum_restart_thread, mhd);
	}
	
	return ret;
}

int datum_api_homepage(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	char output[DATUM_API_HOMEPAGE_MAX_SIZE];
	int j, k = 0, kk = 0, ii;
	T_DATUM_MINER_DATA *m;
	T_DATUM_API_DASH_VARS vardata;
	unsigned char astat;
	double thr = 0.0;
	double hr;
	uint64_t tsms;
	
	memset(&vardata, 0, sizeof(T_DATUM_API_DASH_VARS));

	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	j = global_latest_stratum_job_index;
	vardata.sjob = (j >= 0 && j < MAX_STRATUM_JOBS) ? global_cur_stratum_jobs[j] : NULL;
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);

	tsms = current_time_millis();
	
	if (global_stratum_app) {
		k = 0;
		kk = 0;
		for(j=0;j<global_stratum_app->max_threads;j++) {
			k+=global_stratum_app->datum_threads[j].connected_clients;
			for(ii=0;ii<global_stratum_app->max_clients_thread;ii++) {
				if (global_stratum_app->datum_threads[j].client_data[ii].fd > 0) {
					m = (T_DATUM_MINER_DATA *)global_stratum_app->datum_threads[j].client_data[ii].app_client_data;
					if (m->subscribed) {
						kk++;
						astat = m->stats.active_index?0:1; // inverted
						hr = 0.0;
						if ((m->stats.last_swap_ms > 0) && (m->stats.diff_accepted[astat] > 0)) {
							hr = ((double)m->stats.diff_accepted[astat] / (double)((double)m->stats.last_swap_ms/1000.0)) * 0.004294967296; // Th/sec based on shares/sec
						}
						if (((double)(tsms - m->stats.last_swap_tsms)/1000.0) < 180.0) {
							thr += hr;
						}
					}
				}
			}
		}
		vardata.STRATUM_ACTIVE_THREADS = global_stratum_app->datum_active_threads;
		vardata.STRATUM_TOTAL_CONNECTIONS = k;
		vardata.STRATUM_TOTAL_SUBSCRIPTIONS = kk;
		vardata.STRATUM_HASHRATE_ESTIMATE = thr;
	} else {
		vardata.STRATUM_ACTIVE_THREADS = 0;
		vardata.STRATUM_TOTAL_CONNECTIONS = 0;
		vardata.STRATUM_TOTAL_SUBSCRIPTIONS = 0;
		vardata.STRATUM_HASHRATE_ESTIMATE = 0.0;
	}
	
	output[0] = 0;
	datum_api_fill_vars(www_home_html, output, DATUM_API_HOMEPAGE_MAX_SIZE, datum_api_fill_var, &vardata);
	
	// return the home page with some data and such
	response = MHD_create_response_from_buffer (strlen(output), (void *) output, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "text/html");
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

int datum_api_OK(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	const char *ok_response = "OK";
	response = MHD_create_response_from_buffer(strlen(ok_response), (void *)ok_response, MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(response, "Content-Type", "text/html");
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

int datum_api_testnet_fastforward(struct MHD_Connection * const connection) {
	const char *time_str;
	
	time_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "password");
	if (!datum_api_check_admin_password_only(connection, time_str, datum_api_create_empty_mhd_response)) {
		return MHD_YES;
	}
	
	// Get the time parameter from the URL query
	time_str = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "ts");
	
	uint32_t t = -1000;
	if (time_str != NULL) {
		// Convert the time parameter to uint32_t
		t = (int)strtoul(time_str, NULL, 10);
	}
	
	datum_blocktemplates_notifynew("T", t);
	return datum_api_OK(connection);
}

struct ConnectionInfo {
	char *data;
	size_t data_size;
};

static void datum_api_request_completed(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {
	struct ConnectionInfo *con_info = *con_cls;
	
	if (con_info != NULL) {
		if (con_info->data != NULL) free(con_info->data);
		free(con_info);
	}
	*con_cls = NULL;
}

enum MHD_Result datum_api_answer(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
	char *user;
	char *pass;
	enum MHD_Result ret;
	struct MHD_Response *response;
	struct ConnectionInfo *con_info = *con_cls;
	int int_method = 0;
	int uds = 0;
	
	if (strcmp(method, "GET") == 0) {
		int_method = 1;
	}
	
	if (strcmp(method, "POST") == 0) {
		int_method = 2;
	}
	
	if (!int_method) {
		const char *error_response = "<H1>Method not allowed.</H1>";
		response = MHD_create_response_from_buffer(strlen(error_response), (void *)error_response, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", "text/html");
		ret = MHD_queue_response(connection, MHD_HTTP_METHOD_NOT_ALLOWED, response);
		MHD_destroy_response(response);
		return ret;
	}
	
	if (int_method == 2) {
		if (!con_info) {
			// Allocate memory for connection info
			con_info = malloc(sizeof(struct ConnectionInfo));
			if (!con_info) {
				return MHD_NO;
			}
			
			con_info->data = calloc(16384,1);
			con_info->data_size = 0;
			
			if (!con_info->data) {
				free(con_info);
				return MHD_NO;
			}
			
			*con_cls = (void *)con_info;
			
			return MHD_YES;
		}
		
		if (*upload_data_size) {
			// Accumulate data
			
			// max 1 MB? seems reasonable
			if (con_info->data_size + *upload_data_size > (1024*1024)) return MHD_NO;
			
			con_info->data = realloc(con_info->data, con_info->data_size + *upload_data_size + 1);
			if (!con_info->data) {
				return MHD_NO;
			}
			memcpy(&(con_info->data[con_info->data_size]), upload_data, *upload_data_size);
			con_info->data_size += *upload_data_size;
			con_info->data[con_info->data_size] = '\0';
			*upload_data_size = 0;
			
			return MHD_YES;
		} else if (!con_info->data_size) {
			const char *error_response = "<H1>Invalid request.</H1>";
			response = MHD_create_response_from_buffer(strlen(error_response), (void *)error_response, MHD_RESPMEM_PERSISTENT);
			MHD_add_response_header(response, "Content-Type", "text/html");
			ret = MHD_queue_response(connection, MHD_HTTP_BAD_REQUEST, response);
			MHD_destroy_response(response);
			return ret;
		}
		
		uds = *upload_data_size;
	}
	
	const union MHD_ConnectionInfo *conn_info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
	char *client_ip = inet_ntoa(((struct sockaddr_in*)conn_info->client_addr)->sin_addr);
	
	DLOG_DEBUG("REQUEST: %s, %s, %s, %d", client_ip, method, url, uds);
	
	pass = NULL;
	user = MHD_basic_auth_get_username_password (connection, &pass);
	
	/////////////////////////
	// TODO: Implement API key or auth or something similar
	
	if (user) MHD_free(user);
	if (pass) MHD_free(pass);
	
	if (int_method == 1 && url[0] == '/' && url[1] == 0) {
		// homepage
		return datum_api_homepage(connection);
	}
	
	switch (url[1]) {
		case 'N': {
			if (!strcmp(url, "/NOTIFY")) {
				// TODO: Implement faster notifies with hash+height
				datum_blocktemplates_notifynew(NULL, 0);
				return datum_api_OK(connection);
			}
			break;
		}
		
		case 'a': {
			if (!strcmp(url, "/assets/icons/datum_logo.svg")) {
				return datum_api_asset(connection, "image/svg+xml", www_assets_icons_datum_logo_svg, www_assets_icons_datum_logo_svg_sz, www_assets_icons_datum_logo_svg_etag);
			} else if (!strcmp(url, "/assets/icons/favicon.ico")) {
				return datum_api_asset(connection, "image/x-icon", www_assets_icons_favicon_ico, www_assets_icons_favicon_ico_sz, www_assets_icons_favicon_ico_etag);
			} else if (!strcmp(url, "/assets/style.css")) {
				return datum_api_asset(connection, "text/css", www_assets_style_css, www_assets_style_css_sz, www_assets_style_css_etag);
			}
			break;
		}
		
		case 'c': {
			if (!strcmp(url, "/clients")) {
				return datum_api_client_dashboard(connection);
			}
			if (!strcmp(url, "/coinbaser")) {
				return datum_api_coinbaser(connection);
			}
			if (!strcmp(url, "/config")) {
				if (int_method == 2 && con_info) {
					return datum_api_config_post(connection, con_info->data, con_info->data_size);
				} else {
					return datum_api_config_dashboard(connection);
				}
			}
			if ((int_method==2) && (!strcmp(url, "/cmd"))) {
				if (con_info) {
					return datum_api_cmd(connection, con_info->data, con_info->data_size);
				} else {
					return MHD_NO;
				}
			}
			break;
		}
		
		case 'f': {
			if (!strcmp(url, "/favicon.ico")) {
				return datum_api_asset(connection, "image/x-icon", www_assets_icons_favicon_ico, www_assets_icons_favicon_ico_sz, www_assets_icons_favicon_ico_etag);
			}
			break;
		}
		
		case 't': {
			if (!strcmp(url, "/threads")) {
				return datum_api_thread_dashboard(connection);
			}
			if (!strcmp(url, "/testnet_fastforward")) {
				return datum_api_testnet_fastforward(connection);
			}
			break;
		}
		
		default: break;
	}
	
	const char *error_response = "<H1>Not found</H1>";
	response = MHD_create_response_from_buffer(strlen(error_response), (void *)error_response, MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(response, "Content-Type", "text/html");
	ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
	MHD_destroy_response (response);
	return ret;
}

static struct MHD_Daemon *datum_api_try_start(unsigned int flags, const int sock) {
	flags |= MHD_USE_AUTO;  // event loop API
	flags |= MHD_USE_INTERNAL_POLLING_THREAD;
	return MHD_start_daemon(
	                          flags,
	                          datum_config.api_listen_port,
	                          NULL, NULL,  // accept policy filter
	                          &datum_api_answer, NULL,  // default URI handler
	                          MHD_OPTION_LISTEN_SOCKET, sock,
	                          MHD_OPTION_CONNECTION_LIMIT, 128,
	                          MHD_OPTION_NOTIFY_COMPLETED, datum_api_request_completed, NULL,
	                          MHD_OPTION_LISTENING_ADDRESS_REUSE, (unsigned int)1,
	                          MHD_OPTION_END);
}

void *datum_api_thread(void *ptr) {
	struct MHD_Daemon *daemon;
	
	if (!datum_config.api_listen_port) {
		DLOG_INFO("No API port configured. API disabled.");
		return NULL;
	}
	
	int listen_socks[1];
	size_t listen_socks_len = 1;
	if (!datum_sockets_setup_listening_sockets("API", datum_config.api_listen_addr, datum_config.api_listen_port, listen_socks, &listen_socks_len)) {
		return NULL;
	}
	
	daemon = datum_api_try_start(0, listen_socks[0]);
	
	if (!daemon) {
		DLOG_FATAL("Unable to start daemon for API");
		panic_from_thread(__LINE__);
		return NULL;
	}
	
	DLOG_INFO("API listening on address %s port %d", datum_config.api_listen_addr[0] ? datum_config.api_listen_addr : "(any)", datum_config.api_listen_port);
	
	while(1) {
		sleep(3);
	}
}

int datum_api_init(void) {
	pthread_t pthread_datum_api_thread;
	
	if (!datum_config.api_listen_port) {
		DLOG_INFO("INFO: No API port configured. API disabled.");
		return 0;
	}
	pthread_create(&pthread_datum_api_thread, NULL, datum_api_thread, NULL);
	
	return 0;
}
