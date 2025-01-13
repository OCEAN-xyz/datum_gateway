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

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <inttypes.h>
#include <jansson.h>

#include "datum_api.h"
#include "datum_conf.h"
#include "datum_utils.h"
#include "datum_stratum.h"
#include "datum_sockets.h"
#include "datum_protocol.h"

#include "web_resources.h"

const char * const homepage_html_end = "</body></html>";

#define DATUM_API_HOMEPAGE_MAX_SIZE 128000
#define DATUM_API_VAR_MAX_SIZE 128

const char *cbnames[] = {
	"Blank",
	"Tiny",
	"Default",
	"Respect",
	"Yuge",
	"Antmain2"
};

static void html_leading_zeros(char * const buffer, const size_t buffer_size, const char * const numstr) {
	int zeros = 0;
	while (numstr[zeros] == '0') {
		++zeros;
	}
	if (zeros) {
		snprintf(buffer, buffer_size, "<span class='leading_zeros'>%.*s</span>%s", zeros, numstr, &numstr[zeros]);
	}
}

#define MAKE_API_D(api_var, val)  \
	static void datum_api_var_ ## api_var(char * const buffer, const size_t buffer_size, const T_DATUM_API_DASH_VARS * const vardata) {  \
		snprintf(buffer, buffer_size, "%d", (int)(val));  \
	}  \
// end of MAKE_API_D
#define MAKE_API_LLU(api_var, val)  \
	static void datum_api_var_ ## api_var(char * const buffer, const size_t buffer_size, const T_DATUM_API_DASH_VARS * const vardata) {  \
		snprintf(buffer, buffer_size, "%llu", (unsigned long long)(val));  \
	}  \
// end of MAKE_API_LLU
#define MAKE_API_S(api_var, val)  \
	static void datum_api_var_ ## api_var(char * const buffer, const size_t buffer_size, const T_DATUM_API_DASH_VARS * const vardata) {  \
		snprintf(buffer, buffer_size, "%s", (val));  \
	}  \
// end of MAKE_API_S

MAKE_API_LLU(DATUM_SHARES_ACCEPTED_ABSOLUTE, datum_accepted_share_count)
MAKE_API_LLU(DATUM_SHARES_ACCEPTED_WEIGHED, datum_accepted_share_diff)
MAKE_API_LLU(DATUM_SHARES_REJECTED_ABSOLUTE, datum_rejected_share_count)
MAKE_API_LLU(DATUM_SHARES_REJECTED_WEIGHED, datum_rejected_share_diff)
void datum_api_var_DATUM_CONNECTION_STATUS_INDICATOR_COLOUR(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	const char *colour;
	if (datum_protocol_is_active() || !datum_config.datum_pool_host[0]) {
		colour = "lime";
	} else if (datum_config.datum_pooled_mining_only) {
		colour = "red";
	} else {
		colour = "yellow";
	}
	snprintf(buffer, buffer_size, "%s", colour);
}
void datum_api_var_DATUM_CONNECTION_STATUS_DESCRIPTION(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	const char *s;
	if (datum_protocol_is_active()) {
		s = "Connected and Ready";
	} else if (datum_config.datum_pooled_mining_only && datum_config.datum_pool_host[0]) {
		s = "Not Ready";
	} else {
		s = "Non-Pooled Mode";
	}
	snprintf(buffer, buffer_size, "%s", s);
}
void datum_api_var_DATUM_POOL_HOST_OR_NA(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	if (datum_config.datum_pool_host[0]) {
		snprintf(buffer, buffer_size, "%s:%u", datum_config.datum_pool_host, (unsigned)datum_config.datum_pool_port);
	} else {
		snprintf(buffer, buffer_size, "N/A");
	}
}
void datum_api_var_DATUM_POOL_HOST(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	if (datum_config.datum_pool_host[0]) {
		snprintf(buffer, buffer_size, "%s:%u", datum_config.datum_pool_host, (unsigned)datum_config.datum_pool_port);
	} else {
		snprintf(buffer, buffer_size, "");
	}
}
void datum_api_var_DATUM_POOL_TAG_FORMATTED(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	size_t i;
	buffer[0] = '"';
	i = strncpy_html_escape(&buffer[1], datum_protocol_is_active()?datum_config.override_mining_coinbase_tag_primary:datum_config.mining_coinbase_tag_primary, buffer_size-3);
	buffer[i+1] = '"';
	buffer[i+2] = 0;
}
MAKE_API_S(DATUM_POOL_TAG, datum_protocol_is_active() ? datum_config.override_mining_coinbase_tag_primary : datum_config.mining_coinbase_tag_primary)
void datum_api_var_DATUM_MINER_TAG_FORMATTED(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	size_t i;
	buffer[0] = '"';
	i = strncpy_html_escape(&buffer[1], datum_config.mining_coinbase_tag_secondary, buffer_size-3);
	buffer[i+1] = '"';
	buffer[i+2] = 0;
}
MAKE_API_S(DATUM_MINER_TAG, datum_config.mining_coinbase_tag_secondary)
MAKE_API_LLU(DATUM_POOL_DIFF, datum_config.override_vardiff_min)
MAKE_API_S(DATUM_POOL_PUBKEY, datum_config.datum_pool_pubkey)
MAKE_API_D(STRATUM_ACTIVE_THREADS, vardata->STRATUM_ACTIVE_THREADS)
MAKE_API_D(STRATUM_TOTAL_CONNECTIONS, vardata->STRATUM_TOTAL_CONNECTIONS)
MAKE_API_D(STRATUM_TOTAL_SUBSCRIPTIONS, vardata->STRATUM_TOTAL_SUBSCRIPTIONS)
void datum_api_var_STRATUM_HASHRATE_ESTIMATE_FORMATTED(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%.2f Th/sec", vardata->STRATUM_HASHRATE_ESTIMATE);
}
void datum_api_var_STRATUM_HASHRATE_ESTIMATE(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%.0f", vardata->STRATUM_HASHRATE_ESTIMATE * 1e12);
}
void datum_api_var_STRATUM_JOB_INFO(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%s (%d) @ %.3f", vardata->sjob->job_id, vardata->sjob->global_index, (double)vardata->sjob->tsms / 1000.0);
}
MAKE_API_S(STRATUM_JOB_ID, vardata->sjob->job_id)
MAKE_API_D(STRATUM_JOB_INDEX, vardata->sjob->global_index)
void datum_api_var_STRATUM_JOB_TIMESTAMP(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%.3f", (double)vardata->sjob->tsms / 1000.0);
}
MAKE_API_LLU(STRATUM_JOB_BLOCK_HEIGHT, vardata->sjob->block_template->height)
void datum_api_var_STRATUM_JOB_BLOCK_VALUE_FORMATTED(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%.8f BTC", (double)vardata->sjob->block_template->coinbasevalue / (double)100000000.0);
}
MAKE_API_LLU(STRATUM_JOB_BLOCK_VALUE, vardata->sjob->block_template->coinbasevalue)
void datum_api_var_STRATUM_JOB_TARGET_FORMATTED(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	html_leading_zeros(buffer, buffer_size, vardata->sjob->block_template->block_target_hex);
}
MAKE_API_S(STRATUM_JOB_TARGET, vardata->sjob->block_template->block_target_hex)
void datum_api_var_STRATUM_JOB_PREVBLOCK_FORMATTED(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	html_leading_zeros(buffer, buffer_size, vardata->sjob->block_template->previousblockhash);
}
MAKE_API_S(STRATUM_JOB_PREVBLOCK, vardata->sjob->block_template->previousblockhash)
MAKE_API_S(STRATUM_JOB_WITNESS, vardata->sjob->block_template->default_witness_commitment)
void datum_api_var_STRATUM_JOB_DIFF(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	snprintf(buffer, buffer_size, "%.3Lf", calc_network_difficulty(vardata->sjob->nbits));
}
MAKE_API_S(STRATUM_JOB_VERSION_HEX, vardata->sjob->version)
MAKE_API_LLU(STRATUM_JOB_VERSION, vardata->sjob->version_uint)
MAKE_API_S(STRATUM_JOB_BITS, vardata->sjob->nbits)
MAKE_API_LLU(STRATUM_JOB_CURTIME, vardata->sjob->block_template->curtime)
MAKE_API_LLU(STRATUM_JOB_MINTIME, vardata->sjob->block_template->mintime)
MAKE_API_LLU(STRATUM_JOB_SIZE_LIMIT, vardata->sjob->block_template->sizelimit)
MAKE_API_LLU(STRATUM_JOB_WEIGHT_LIMIT, vardata->sjob->block_template->weightlimit)
MAKE_API_LLU(STRATUM_JOB_SIGOP_LIMIT, vardata->sjob->block_template->sigoplimit)
MAKE_API_LLU(STRATUM_JOB_SIZE, vardata->sjob->block_template->txn_total_size)
MAKE_API_LLU(STRATUM_JOB_WEIGHT, vardata->sjob->block_template->txn_total_weight)
MAKE_API_LLU(STRATUM_JOB_SIGOPS, vardata->sjob->block_template->txn_total_sigops)
MAKE_API_LLU(STRATUM_JOB_TXNCOUNT, vardata->sjob->block_template->txn_count)


DATUM_API_VarEntry var_entries[] = {
	{"DATUM_SHARES_ACCEPTED_ABSOLUTE", datum_api_var_DATUM_SHARES_ACCEPTED_ABSOLUTE},
	{"DATUM_SHARES_ACCEPTED_WEIGHED", datum_api_var_DATUM_SHARES_ACCEPTED_WEIGHED},
	{"DATUM_SHARES_REJECTED_ABSOLUTE", datum_api_var_DATUM_SHARES_REJECTED_ABSOLUTE},
	{"DATUM_SHARES_REJECTED_WEIGHED", datum_api_var_DATUM_SHARES_REJECTED_WEIGHED},
	{"DATUM_CONNECTION_STATUS_INDICATOR_COLOUR", datum_api_var_DATUM_CONNECTION_STATUS_INDICATOR_COLOUR},
	{"DATUM_CONNECTION_STATUS_DESCRIPTION", datum_api_var_DATUM_CONNECTION_STATUS_DESCRIPTION},
	{"DATUM_POOL_HOST_OR_NA", datum_api_var_DATUM_POOL_HOST_OR_NA},
	{"DATUM_POOL_HOST", datum_api_var_DATUM_POOL_HOST},
	{"DATUM_POOL_TAG_FORMATTED", datum_api_var_DATUM_POOL_TAG_FORMATTED},
	{"DATUM_POOL_TAG", datum_api_var_DATUM_POOL_TAG},
	{"DATUM_MINER_TAG_FORMATTED", datum_api_var_DATUM_MINER_TAG_FORMATTED},
	{"DATUM_MINER_TAG", datum_api_var_DATUM_MINER_TAG},
	{"DATUM_POOL_DIFF", datum_api_var_DATUM_POOL_DIFF},
	{"DATUM_POOL_PUBKEY", datum_api_var_DATUM_POOL_PUBKEY},
	
	{"STRATUM_ACTIVE_THREADS", datum_api_var_STRATUM_ACTIVE_THREADS},
	{"STRATUM_TOTAL_CONNECTIONS", datum_api_var_STRATUM_TOTAL_CONNECTIONS},
	{"STRATUM_TOTAL_SUBSCRIPTIONS", datum_api_var_STRATUM_TOTAL_SUBSCRIPTIONS},
	{"STRATUM_HASHRATE_ESTIMATE_FORMATTED", datum_api_var_STRATUM_HASHRATE_ESTIMATE_FORMATTED},
	{"STRATUM_HASHRATE_ESTIMATE", datum_api_var_STRATUM_HASHRATE_ESTIMATE},
	
	{"STRATUM_JOB_INFO", datum_api_var_STRATUM_JOB_INFO},
	{"STRATUM_JOB_ID", datum_api_var_STRATUM_JOB_ID},
	{"STRATUM_JOB_INDEX", datum_api_var_STRATUM_JOB_INDEX},
	{"STRATUM_JOB_TIMESTAMP", datum_api_var_STRATUM_JOB_TIMESTAMP},
	{"STRATUM_JOB_BLOCK_HEIGHT", datum_api_var_STRATUM_JOB_BLOCK_HEIGHT},
	{"STRATUM_JOB_BLOCK_VALUE_FORMATTED", datum_api_var_STRATUM_JOB_BLOCK_VALUE_FORMATTED},
	{"STRATUM_JOB_BLOCK_VALUE", datum_api_var_STRATUM_JOB_BLOCK_VALUE},
	{"STRATUM_JOB_PREVBLOCK_FORMATTED", datum_api_var_STRATUM_JOB_PREVBLOCK_FORMATTED},
	{"STRATUM_JOB_PREVBLOCK", datum_api_var_STRATUM_JOB_PREVBLOCK},
	{"STRATUM_JOB_TARGET_FORMATTED", datum_api_var_STRATUM_JOB_TARGET_FORMATTED},
	{"STRATUM_JOB_TARGET", datum_api_var_STRATUM_JOB_TARGET},
	{"STRATUM_JOB_WITNESS", datum_api_var_STRATUM_JOB_WITNESS},
	{"STRATUM_JOB_DIFF", datum_api_var_STRATUM_JOB_DIFF},
	{"STRATUM_JOB_VERSION", datum_api_var_STRATUM_JOB_VERSION},
	{"STRATUM_JOB_VERSION_HEX", datum_api_var_STRATUM_JOB_VERSION_HEX},
	{"STRATUM_JOB_BITS", datum_api_var_STRATUM_JOB_BITS},
	{"STRATUM_JOB_CURTIME", datum_api_var_STRATUM_JOB_CURTIME},
	{"STRATUM_JOB_MINTIME", datum_api_var_STRATUM_JOB_MINTIME},
	{"STRATUM_JOB_SIZE_LIMIT", datum_api_var_STRATUM_JOB_SIZE_LIMIT},
	{"STRATUM_JOB_WEIGHT_LIMIT", datum_api_var_STRATUM_JOB_WEIGHT_LIMIT},
	{"STRATUM_JOB_SIGOP_LIMIT", datum_api_var_STRATUM_JOB_SIGOP_LIMIT},
	{"STRATUM_JOB_SIZE", datum_api_var_STRATUM_JOB_SIZE},
	{"STRATUM_JOB_WEIGHT", datum_api_var_STRATUM_JOB_WEIGHT},
	{"STRATUM_JOB_SIGOPS", datum_api_var_STRATUM_JOB_SIGOPS},
	{"STRATUM_JOB_TXNCOUNT", datum_api_var_STRATUM_JOB_TXNCOUNT},
	
	{NULL, NULL} // Mark the end of the array
};

DATUM_API_VarFunc datum_api_find_var_func(const char *var_name) {
	for (int i = 0; var_entries[i].var_name != NULL; i++) {
		if (strcmp(var_entries[i].var_name, var_name) == 0) {
			return var_entries[i].func;
		}
	}
	return NULL; // Variable not found
}

void datum_api_fill_vars(const char *input, char *output, size_t max_output_size, const T_DATUM_API_DASH_VARS *vardata) {
	const char* p = input;
	size_t output_len = 0;
	size_t var_name_len = 0;
	char var_name[256];
	char replacement[256];
	size_t replacement_len;
	size_t remaining;
	size_t to_copy;
	const char *var_start;
	const char *var_end;
	size_t total_var_len;
	char temp_var[260];
	
	while (*p && output_len < max_output_size - 1) {
		if (strncmp(p, "${", 2) == 0) {
			p += 2; // Skip "${"
			var_start = p;
			var_end = strchr(p, '}');
			if (!var_end) {
				// No closing '}', copy rest of the input to output
				remaining = strlen(p);
				to_copy = (remaining < max_output_size - output_len - 1) ? remaining : max_output_size - output_len - 1;
				strncpy(&output[output_len], p, to_copy);
				output_len += to_copy;
				break;
			}
			var_name_len = var_end - var_start;
			
			if (var_name_len >= sizeof(var_name)-1) {
				output[output_len] = 0;
				return;
			}
			strncpy(var_name, var_start, var_name_len);
			var_name[var_name_len] = 0;
			
			DATUM_API_VarFunc func = datum_api_find_var_func(var_name);
			if (func) {
				replacement[0] = 0;
				// Skip running STRATUM_JOB functions if there's no sjob
				if (var_name[8] != 'J' || vardata->sjob) {
					func(replacement, sizeof(replacement), vardata);
				}
				replacement_len = strlen(replacement);
				if (replacement_len) {
					to_copy = (replacement_len < max_output_size - output_len - 1) ? replacement_len : max_output_size - output_len - 1;
					strncpy(&output[output_len], replacement, to_copy);
					output_len += to_copy;
				}
				output[output_len] = 0;
			} else {
				// Not sure what this is... so just leave it
				total_var_len = var_name_len + 3;
				snprintf(temp_var, sizeof(temp_var), "${%s}", var_name);
				to_copy = (total_var_len < max_output_size - output_len - 1) ? total_var_len : max_output_size - output_len - 1;
				strncpy(&output[output_len], temp_var, to_copy);
				output_len += to_copy;
				output[output_len] = 0;
			}
			p = var_end + 1; // Move past '}'
		} else {
			output[output_len++] = *p++;
			output[output_len] = 0;
		}
	}
	
	output[output_len] = 0;
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

static int datum_api_asset(struct MHD_Connection * const connection, const char * const mimetype, const char * const data, const size_t datasz) {
	struct MHD_Response * const response = MHD_create_response_from_buffer(datasz, (void*)data, MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(response, "Content-Type", mimetype);
	const int ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
}

void datum_api_cmd_empty_thread(int tid) {
	if ((tid >= 0) && (tid < global_stratum_app->max_threads)) {
		DLOG_WARN("API Request to empty stratum thread %d!", tid);
		global_stratum_app->datum_threads[tid].empty_request = true;
	}
}

void datum_api_cmd_kill_client(int tid, int cid) {
	if ((tid >= 0) && (tid < global_stratum_app->max_threads)) {
		if ((cid >= 0) && (cid < global_stratum_app->max_clients_thread)) {
			DLOG_WARN("API Request to disconnect stratum client %d/%d!", tid, cid);
			global_stratum_app->datum_threads[tid].client_data[cid].kill_request = true;
			global_stratum_app->datum_threads[tid].has_client_kill_request = true;
		}
	}
}

int datum_api_cmd(struct MHD_Connection *connection, char *post, int len) {
	struct MHD_Response *response;
	char output[1024];
	int ret, sz=0;
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
			}
		}
	}
	
	sprintf(output, "{}");
	response = MHD_create_response_from_buffer (sz, (void *) output, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "application/json");
	http_resp_prevent_caching(response);
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
}

int datum_api_coinbaser(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	T_DATUM_STRATUM_JOB *sjob;
	int j,i,max_sz = 0,sz=0,ret;
	char tempaddr[256];
	uint64_t tv = 0;
	char *output = NULL;
	
	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	j = global_latest_stratum_job_index;
	sjob = (j >= 0 && j < MAX_STRATUM_JOBS) ? global_cur_stratum_jobs[j] : NULL;
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
	
	if (!sjob) return MHD_NO;
	
	max_sz = www_coinbaser_top_html_sz + www_foot_html_sz + (sjob->available_coinbase_outputs_count * 512) + 2048; // approximate max size of each row
	output = calloc(max_sz+16,1);
	if (!output) {
		return MHD_NO;
	}
	
	sz = snprintf(output, max_sz-1-sz, "%s", www_coinbaser_top_html);
	sz += snprintf(&output[sz], max_sz-1-sz, "<TABLE><TR><TD><U>Value</U></TD>  <TD><U>Address</U></TD></TR>");
	
	for(i=0;i<sjob->available_coinbase_outputs_count;i++) {
		output_script_2_addr(sjob->available_coinbase_outputs[i].output_script, sjob->available_coinbase_outputs[i].output_script_len, tempaddr);
		sz += snprintf(&output[sz], max_sz-1-sz, "<TR><TD>%.8f BTC</TD><TD>%s</TD></TR>", (double)sjob->available_coinbase_outputs[i].value_sats / (double)100000000.0, tempaddr);
		tv += sjob->available_coinbase_outputs[i].value_sats;
	}
	
	if (tv < sjob->coinbase_value) {
		output_script_2_addr(sjob->pool_addr_script, sjob->pool_addr_script_len, tempaddr);
		sz += snprintf(&output[sz], max_sz-1-sz, "<TR><TD>%.8f BTC</TD><TD>%s</TD></TR>", (double)(sjob->coinbase_value - tv) / (double)100000000.0, tempaddr);
	}
	
	sz += snprintf(&output[sz], max_sz-1-sz, "</TABLE>");
	sz += snprintf(&output[sz], max_sz-1-sz, "%s", www_foot_html);
	
	response = MHD_create_response_from_buffer (sz, (void *) output, MHD_RESPMEM_MUST_FREE);
	MHD_add_response_header(response, "Content-Type", "text/html");
	http_resp_prevent_caching(response);
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
}

int datum_api_thread_dashboard(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	int sz=0, ret, max_sz = 0, j, ii;
	char *output = NULL;
	T_DATUM_MINER_DATA *m = NULL;
	uint64_t tsms;
	double hr;
	unsigned char astat;
	double thr = 0.0;
	int subs,conns;
	
	max_sz = www_threads_top_html_sz + www_foot_html_sz + (global_stratum_app->max_threads * 512) + 2048; // approximate max size of each row
	output = calloc(max_sz+16,1);
	if (!output) {
		return MHD_NO;
	}
	
	tsms = current_time_millis();
	
	sz = snprintf(output, max_sz-1-sz, "%s", www_threads_top_html);
	sz += snprintf(&output[sz], max_sz-1-sz, "<TABLE><TR><TD><U>TID</U></TD>  <TD><U>Connection Count</U></TD>  <TD><U>Sub Count</U></TD> <TD><U>Approx. Hashrate</U></TD> <TD><U>Command</U></TD></TR>");
	for(j=0;j<global_stratum_app->max_threads;j++) {
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
			sz += snprintf(&output[sz], max_sz-1-sz, "<TR><TD>%d</TD>  <TD>%d</TD>  <TD>%d</TD> <TD>%.2f Th/s</TD> <TD><button onclick=\"sendPostRequest('/cmd', {cmd:'empty_thread',tid:%d})\">Disconnect All</button></TD></TR>", j, conns, subs, thr, j);
		}
	}
	sz += snprintf(&output[sz], max_sz-1-sz, "</TABLE>");
	sz += snprintf(&output[sz], max_sz-1-sz, "<script>function sendPostRequest(url, data){fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});}</script>");
	sz += snprintf(&output[sz], max_sz-1-sz, "%s", www_foot_html);
	
	response = MHD_create_response_from_buffer (sz, (void *) output, MHD_RESPMEM_MUST_FREE);
	MHD_add_response_header(response, "Content-Type", "text/html");
	http_resp_prevent_caching(response);
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
}

int datum_api_client_dashboard(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	int connected_clients = 0;
	int i,sz=0,ret,max_sz = 0,j,ii;
	char *output = NULL;
	T_DATUM_MINER_DATA *m = NULL;
	uint64_t tsms;
	double hr;
	unsigned char astat;
	double thr = 0.0;
	
	for(i=0;i<global_stratum_app->max_threads;i++) {
		connected_clients+=global_stratum_app->datum_threads[i].connected_clients;
	}
	
	max_sz = www_clients_top_html_sz + www_foot_html_sz + (connected_clients * 1024) + 2048; // approximate max size of each row
	output = calloc(max_sz+16,1);
	if (!output) {
		return MHD_NO;
	}
	
	tsms = current_time_millis();
	
	sz = snprintf(output, max_sz-1-sz, "%s", www_clients_top_html);
	sz += snprintf(&output[sz], max_sz-1-sz, "<TABLE><TR><TD><U>TID/CID</U></TD>  <TD><U>RemHost</U></TD>  <TD><U>Auth Username</U></TD> <TD><U>Subbed</U></TD> <TD><U>Last Accepted</U></TD> <TD><U>VDiff</U></TD> <TD><U>DiffA (A)</U></TD> <TD><U>DiffR (R)</U></TD> <TD><U>Hashrate (age)</U></TD> <TD><U>Coinbase</U></TD> <TD><U>UserAgent</U> </TD><TD><U>Command</U></TD></TR>");
	
	for(j=0;j<global_stratum_app->max_threads;j++) {
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
				
				sz += snprintf(&output[sz], max_sz-1-sz, "<TD><button onclick=\"sendPostRequest('/cmd', {cmd:'kill_client',tid:%d,cid:%d})\">Kick</button></TD></TR>", j, ii);
			}
		}
	}
	
	sz += snprintf(&output[sz], max_sz-1-sz, "</TABLE><p class=\"table-footer\">Total active hashrate estimate: %.2f Th/s</p>", thr);
	sz += snprintf(&output[sz], max_sz-1-sz, "<script>function sendPostRequest(url, data){fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});}</script>");
	sz += snprintf(&output[sz], max_sz-1-sz, "%s", www_foot_html);
	
	// return the home page with some data and such
	response = MHD_create_response_from_buffer (sz, (void *) output, MHD_RESPMEM_MUST_FREE);
	MHD_add_response_header(response, "Content-Type", "text/html");
	http_resp_prevent_caching(response);
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
}

static void datum_api_prepare_vardata(T_DATUM_API_DASH_VARS * const vardata) {
	int j, k = 0, kk = 0, ii;
	T_DATUM_MINER_DATA *m;
	unsigned char astat;
	double thr = 0.0;
	double hr;
	uint64_t tsms;
	
	memset(vardata, 0, sizeof(T_DATUM_API_DASH_VARS));
	
	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	j = global_latest_stratum_job_index;
	vardata->sjob = (j >= 0 && j < MAX_STRATUM_JOBS) ? global_cur_stratum_jobs[j] : NULL;
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
		vardata->STRATUM_ACTIVE_THREADS = global_stratum_app->datum_active_threads;
		vardata->STRATUM_TOTAL_CONNECTIONS = k;
		vardata->STRATUM_TOTAL_SUBSCRIPTIONS = kk;
		vardata->STRATUM_HASHRATE_ESTIMATE = thr;
	} else {
		vardata->STRATUM_ACTIVE_THREADS = 0;
		vardata->STRATUM_TOTAL_CONNECTIONS = 0;
		vardata->STRATUM_TOTAL_SUBSCRIPTIONS = 0;
		vardata->STRATUM_HASHRATE_ESTIMATE = 0.0;
	}
}

int datum_api_homepage(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	char output[DATUM_API_HOMEPAGE_MAX_SIZE];
	int ret;
	T_DATUM_API_DASH_VARS vardata;
	
	datum_api_prepare_vardata(&vardata);
	
	output[0] = 0;
	datum_api_fill_vars(www_home_html, output, DATUM_API_HOMEPAGE_MAX_SIZE, &vardata);
	
	// return the home page with some data and such
	response = MHD_create_response_from_buffer (strlen(output), (void *) output, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "text/html");
	http_resp_prevent_caching(response);
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
}

int datum_api_OK(struct MHD_Connection *connection) {
	enum MHD_Result ret;
	struct MHD_Response *response;
	const char *ok_response = "OK";
	response = MHD_create_response_from_buffer(strlen(ok_response), (void *)ok_response, MHD_RESPMEM_PERSISTENT);
	MHD_add_response_header(response, "Content-Type", "text/html");
	http_resp_prevent_caching(response);
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
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
	const char *time_str;
	
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
	
	while (!global_stratum_app) {
		sleep(1);
	}
	
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
				return datum_api_asset(connection, "image/svg+xml", www_assets_icons_datum_logo_svg, www_assets_icons_datum_logo_svg_sz);
			} else if (!strcmp(url, "/assets/icons/favicon.ico")) {
				return datum_api_asset(connection, "image/x-icon", www_assets_icons_favicon_ico, www_assets_icons_favicon_ico_sz);
			} else if (!strcmp(url, "/assets/style.css")) {
				return datum_api_asset(connection, "text/css", www_assets_style_css, www_assets_style_css_sz);
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
				return datum_api_asset(connection, "image/x-icon", www_assets_icons_favicon_ico, www_assets_icons_favicon_ico_sz);
			}
			break;
		}
		
		case 't': {
			if (!strcmp(url, "/threads")) {
				return datum_api_thread_dashboard(connection);
			}
			if (!strcmp(url, "/testnet_fastforward")) {
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
			break;
		}
		
		case 'v': {
			if (!strncmp(url, "/v1/", 4)) {
				if (strlen(&url[3]) > DATUM_API_VAR_MAX_SIZE) break;
				char var_name[DATUM_API_VAR_MAX_SIZE];
				for (size_t i = 0; ; ++i) {
					var_name[i] = toupper(url[4 + i]);
					if (!var_name[i]) break;
				}
				DATUM_API_VarFunc func = datum_api_find_var_func(var_name);
				if (!func) break;
				
				T_DATUM_API_DASH_VARS vardata;
				datum_api_prepare_vardata(&vardata);
				
				// Skip running STRATUM_JOB functions if there's no sjob
				if (var_name[8] == 'J' && !vardata.sjob) {
					response = MHD_create_response_from_buffer(0, "", MHD_RESPMEM_PERSISTENT);
					http_resp_prevent_caching(response);
					ret = MHD_queue_response(connection, MHD_HTTP_NO_CONTENT, response);
					MHD_destroy_response(response);
					return ret;
				}
				
				char val[DATUM_API_VAR_MAX_SIZE];
				val[0] = 0;
				func(val, sizeof(val), &vardata);
				
				response = MHD_create_response_from_buffer (strlen(val), val, MHD_RESPMEM_MUST_COPY);
				MHD_add_response_header(response, "Content-Type", "text/plain");
				http_resp_prevent_caching(response);
				ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
				MHD_destroy_response(response);
				return ret;
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

void *datum_api_thread(void *ptr) {
	struct MHD_Daemon *daemon;
	
	if (!datum_config.api_listen_port) {
		DLOG_INFO("No API port configured. API disabled.");
		return NULL;
	}
	
	daemon = MHD_start_daemon(MHD_USE_AUTO | MHD_USE_INTERNAL_POLLING_THREAD, datum_config.api_listen_port, NULL, NULL, &datum_api_answer, NULL,
	                          MHD_OPTION_CONNECTION_LIMIT, 128,
	                          MHD_OPTION_NOTIFY_COMPLETED, datum_api_request_completed, NULL,
	                          MHD_OPTION_END);
	
	if (!daemon) {
		DLOG_FATAL("Unable to start daemon for API");
		panic_from_thread(__LINE__);
		return NULL;
	}
	
	DLOG_INFO("API listening on port %d", datum_config.api_listen_port);
	
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
