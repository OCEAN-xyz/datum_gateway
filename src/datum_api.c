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

const char *cbnames[] = {
	"Blank",
	"Tiny",
	"Default",
	"Respect",
	"Yuge",
	"Antmain2"
};

static void leading_zeros(char * const buffer, const size_t buffer_size, const char * const numstr) {
	int zeros = 0;
	while (numstr[zeros] == '0') {
		++zeros;
	}
	if (zeros) {
		snprintf(buffer, buffer_size, "%.*s%s", zeros, numstr, &numstr[zeros]);
	}
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
	const char *s;
	if (datum_protocol_is_active()) {
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
	snprintf(buffer, buffer_size, "<svg viewBox='0 0 100 100' role='img' style='width:1em;height:1em'><circle cx='50' cy='60' r='35' style='fill:%s' /></svg> %s", colour, s);
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
	leading_zeros(buffer, buffer_size, vardata->sjob->block_template->block_target_hex);
}
void datum_api_var_STRATUM_JOB_PREVBLOCK(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata) {
	leading_zeros(buffer, buffer_size, vardata->sjob->block_template->previousblockhash);
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

DATUM_API_VarFunc datum_api_find_var_func(const char *var_name) {
	for (int i = 0; var_entries[i].var_name != NULL; i++) {
		if (strcmp(var_entries[i].var_name, var_name) == 0) {
			return var_entries[i].func;
		}
	}
	return NULL; // Variable not found
}

void datum_api_use_webresource(const char *input, char *output, size_t max_output_size) {

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
				func(replacement, sizeof(replacement), vardata);
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
	int ret;

	response = MHD_create_response_from_buffer (strlen(www_coinbaser_html), (void *) www_coinbaser_html, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "text/html");
	http_resp_prevent_caching(response);
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
}

int datum_api_thread_dashboard(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	int ret;

	response = MHD_create_response_from_buffer (strlen(www_threads_html), (void *) www_threads_html, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "text/html");
	http_resp_prevent_caching(response);
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
}

int datum_api_json_response(struct MHD_Connection *connection, const char *url, const char *method) {
	struct MHD_Response *response;
	enum MHD_Result ret;
	T_DATUM_API_DASH_VARS vardata;
	T_DATUM_MINER_DATA *m;

	memset(&vardata, 0, sizeof(T_DATUM_API_DASH_VARS));
	char *json_output;

	int j,i,sz = 0;

	char buffer[1024];  // Adjust size as needed

	int k = 0, kk = 0, ii;
	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	j = global_latest_stratum_job_index;
	vardata.sjob = (j >= 0 && j < MAX_STRATUM_JOBS) ? global_cur_stratum_jobs[j] : NULL;
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);

    // Helper macro to reduce repetition
	#define ADD_JSON_VALUE(obj, key, func, type) \
    do { \
        buffer[0] = 0; \
        func(buffer, sizeof(buffer), &vardata); \
        if (buffer[0] != 0) { \
            json_t *json_value; \
            if (strcmp(type, "string") == 0) { \
                json_value = json_string(buffer); \
            } else if (strcmp(type, "integer") == 0) { \
                json_value = json_integer(atoll(buffer)); \
            } else if (strcmp(type, "boolean") == 0) { \
                json_value = json_boolean(atoi(buffer)); \
            } else { \
                json_value = json_string(buffer); /* Default to string */ \
            } \
            if (json_value) { \
                json_object_set_new(obj, key, json_value); \
            } \
        } \
    } while(0)


	if (!strcmp(url, "/api/v1/client_stats")) {
	    json_t *datum = json_object();

		json_object_set_new(datum, "IS_ACTIVE", json_boolean(datum_protocol_is_active()));
		json_object_set_new(datum, "POOL_TAG", json_string(datum_protocol_is_active()?datum_config.override_mining_coinbase_tag_primary:datum_config.mining_coinbase_tag_primary));
		json_object_set_new(datum, "MINER_TAG", json_string(datum_config.mining_coinbase_tag_secondary));
		ADD_JSON_VALUE(datum, "SHARES_ACCEPTED", datum_api_var_DATUM_SHARES_ACCEPTED, "integer");
		ADD_JSON_VALUE(datum, "SHARES_REJECTED", datum_api_var_DATUM_SHARES_REJECTED, "integer");
		json_object_set_new(datum, "IS_ACTIVE", json_boolean(datum_protocol_is_active()));
		ADD_JSON_VALUE(datum, "POOL_HOST", datum_api_var_DATUM_POOL_HOST, "string");
		ADD_JSON_VALUE(datum, "POOL_DIFF", datum_api_var_DATUM_POOL_DIFF, "integer");
		ADD_JSON_VALUE(datum, "POOL_PUBKEY", datum_api_var_DATUM_POOL_PUBKEY, "string");

		char *json_output = json_dumps(datum, JSON_COMPACT);
		json_decref(datum);

		if (!json_output) {
			// Handle error: JSON encoding failed
			return MHD_NO;
		}

		 response = MHD_create_response_from_buffer(
			strlen(json_output),
			(void*)json_output,
			MHD_RESPMEM_MUST_FREE
		);

		
	} else if (!strcmp(url, "/api/v1/stratum_server_info")) {
		uint64_t tsms = current_time_millis();
		unsigned char astat;
		double thr = 0.0;
		double hr;

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

	    json_t *stratum = json_object();

		ADD_JSON_VALUE(stratum, "ACTIVE_THREADS", datum_api_var_STRATUM_ACTIVE_THREADS, "integer");
		ADD_JSON_VALUE(stratum, "TOTAL_CONNECTIONS", datum_api_var_STRATUM_TOTAL_CONNECTIONS, "integer");
		ADD_JSON_VALUE(stratum, "TOTAL_SUBSCRIPTIONS", datum_api_var_STRATUM_TOTAL_SUBSCRIPTIONS, "integer");
		ADD_JSON_VALUE(stratum, "HASHRATE_ESTIMATE", datum_api_var_STRATUM_HASHRATE_ESTIMATE, "string");
		char *json_output = json_dumps(stratum, JSON_COMPACT);
		json_decref(stratum);

		if (!json_output) {
			// Handle error: JSON encoding failed
			return MHD_NO;
		}

		 response = MHD_create_response_from_buffer(
			strlen(json_output),
			(void*)json_output,
			MHD_RESPMEM_MUST_FREE
		);
	} else if (!strcmp(url, "/api/v1/current_stratum_job")) {
	    json_t *stratum_job = json_object();

		ADD_JSON_VALUE(stratum_job, "INFO", datum_api_var_STRATUM_JOB_INFO, "string");
		ADD_JSON_VALUE(stratum_job, "BLOCK_HEIGHT", datum_api_var_STRATUM_JOB_BLOCK_HEIGHT, "integer");
		ADD_JSON_VALUE(stratum_job, "BLOCK_VALUE", datum_api_var_STRATUM_JOB_BLOCK_VALUE, "string");
		ADD_JSON_VALUE(stratum_job, "PREVBLOCK", datum_api_var_STRATUM_JOB_PREVBLOCK, "string");
		ADD_JSON_VALUE(stratum_job, "TARGET", datum_api_var_STRATUM_JOB_TARGET, "string");
		ADD_JSON_VALUE(stratum_job, "WITNESS", datum_api_var_STRATUM_JOB_WITNESS, "string");
		ADD_JSON_VALUE(stratum_job, "DIFF", datum_api_var_STRATUM_JOB_DIFF, "string");
		ADD_JSON_VALUE(stratum_job, "VERSION", datum_api_var_STRATUM_JOB_VERSION, "string");
		ADD_JSON_VALUE(stratum_job, "BITS", datum_api_var_STRATUM_JOB_BITS, "string");
		ADD_JSON_VALUE(stratum_job, "TIMEINFO", datum_api_var_STRATUM_JOB_TIMEINFO, "string");
		ADD_JSON_VALUE(stratum_job, "LIMITINFO", datum_api_var_STRATUM_JOB_LIMITINFO, "string");
		ADD_JSON_VALUE(stratum_job, "SIZE", datum_api_var_STRATUM_JOB_SIZE, "integer");
		ADD_JSON_VALUE(stratum_job, "WEIGHT", datum_api_var_STRATUM_JOB_WEIGHT, "integer");
		ADD_JSON_VALUE(stratum_job, "SIGOPS", datum_api_var_STRATUM_JOB_SIGOPS, "integer");
		ADD_JSON_VALUE(stratum_job, "TXNCOUNT", datum_api_var_STRATUM_JOB_TXNCOUNT, "integer");

		char *json_output = json_dumps(stratum_job, JSON_COMPACT);
		json_decref(stratum_job);

		if (!json_output) {
			// Handle error: JSON encoding failed
			return MHD_NO;
		}

		 response = MHD_create_response_from_buffer(
			strlen(json_output),
			(void*)json_output,
			MHD_RESPMEM_MUST_FREE
		);
	} else if (!strcmp(url, "/api/v1/clients")) {
		int connected_clients = 0;
		for(i=0;i<global_stratum_app->max_threads;i++) {
			connected_clients+=global_stratum_app->datum_threads[i].connected_clients;
		}

		json_t *root = json_object();
		json_t *clients = json_array();
		uint64_t tsms = current_time_millis();
		unsigned char astat;
		double thr = 0.0;
		double hr;

		for (int j = 0; j < global_stratum_app->max_threads; j++) {
			for (int ii = 0; ii < global_stratum_app->max_clients_thread; ii++) {
				if (global_stratum_app->datum_threads[j].client_data[ii].fd > 0) {
					T_DATUM_MINER_DATA *m = (T_DATUM_MINER_DATA *)global_stratum_app->datum_threads[j].client_data[ii].app_client_data;
					json_t *client = json_object();

					json_object_set_new(client, "tid", json_integer(j));
					json_object_set_new(client, "cid", json_integer(ii));
					json_object_set_new(client, "rem_host", json_string(global_stratum_app->datum_threads[j].client_data[ii].rem_host));
					json_object_set_new(client, "auth_username", json_string(m->last_auth_username));
					json_object_set_new(client, "subbed", json_boolean(m->subscribed));

					if (m->subscribed) {
						json_object_set_new(client, "sid", json_integer(m->sid));
						json_object_set_new(client, "subscribe_age", json_real((double)(tsms - m->subscribe_tsms)/1000.0));

						if (m->stats.last_share_tsms) {
							json_object_set_new(client, "last_accepted", json_real((double)(tsms - m->stats.last_share_tsms)/1000.0));
						} else {
							json_object_set_new(client, "last_accepted", json_null());
						}

						json_object_set_new(client, "v_diff", json_integer(m->current_diff));
						json_object_set_new(client, "diff_A", json_integer(m->share_diff_accepted));
						json_object_set_new(client, "shares_A", json_integer(m->share_count_accepted));
						json_object_set_new(client, "diff_R", json_integer(m->share_diff_rejected));
						json_object_set_new(client, "shares_R", json_integer(m->share_count_rejected));

						double hr = 0.0;
						if (m->share_diff_accepted > 0) {
							hr = ((double)m->share_diff_rejected / (double)(m->share_diff_accepted + m->share_diff_rejected))*100.0;
						}
						json_object_set_new(client, "reject_rate", json_real(hr));

						int astat = m->stats.active_index ? 0 : 1; // inverted
						hr = 0.0;
						if ((m->stats.last_swap_ms > 0) && (m->stats.diff_accepted[astat] > 0)) {
							hr = ((double)m->stats.diff_accepted[astat] / (double)((double)m->stats.last_swap_ms/1000.0)) * 0.004294967296; // Th/sec based on shares/sec
						}
						if (((double)(tsms - m->stats.last_swap_tsms)/1000.0) < 180.0) {
							thr += hr;
						}
						json_object_set_new(client, "hashrate", json_real(hr));
						json_object_set_new(client, "last_updated", json_real((double)(tsms - m->stats.last_swap_tsms)/1000.0));

						if (m->coinbase_selection < (sizeof(cbnames) / sizeof(cbnames[0]))) {
							json_object_set_new(client, "coinbase", json_string(cbnames[m->coinbase_selection]));
						} else {
							json_object_set_new(client, "coinbase", json_string("Unknown"));
						}

						json_object_set_new(client, "useragent", json_string(m->useragent));
					}

					json_array_append_new(clients, client);
				}
			}
		}

		json_object_set_new(root, "clients", clients);
		json_object_set_new(root, "total_hashrate", json_real(thr));
		
		char *json_output = json_dumps(root, JSON_COMPACT);
		json_decref(root);

		if (!json_output) {
			// Handle error: JSON encoding failed
			return MHD_NO;
		}

		response = MHD_create_response_from_buffer(
			strlen(json_output),
			(void*)json_output,
			MHD_RESPMEM_MUST_FREE
		);
	} else if (!strcmp(url, "/api/v1/threads")) {
		json_t *root = json_object();
		json_t *threads = json_array();
		uint64_t tsms = current_time_millis();

		for (int j = 0; j < global_stratum_app->max_threads; j++) {
			double thr = 0.0;
			int subs = 0;
			int conns = 0;

			for (int ii = 0; ii < global_stratum_app->max_clients_thread; ii++) {
				if (global_stratum_app->datum_threads[j].client_data[ii].fd > 0) {
					conns++;
					T_DATUM_MINER_DATA *m = (T_DATUM_MINER_DATA *)global_stratum_app->datum_threads[j].client_data[ii].app_client_data;
					if (m->subscribed) {
						subs++;
						unsigned char astat = m->stats.active_index ? 0 : 1; // inverted
						double hr = 0.0;
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
				json_t *thread = json_object();
				json_object_set_new(thread, "tid", json_integer(j));
				json_object_set_new(thread, "connection_count", json_integer(conns));
				json_object_set_new(thread, "sub_count", json_integer(subs));
				json_object_set_new(thread, "approx_hashrate", json_real(thr));
				json_array_append_new(threads, thread);
			}
		}

//		json_object_set_new(root, "threads", threads);

		char *json_output = json_dumps(threads, JSON_COMPACT);
		json_decref(root);

		if (!json_output) {
			// Handle error: JSON encoding failed
			return MHD_NO;
		}

		response = MHD_create_response_from_buffer(
			strlen(json_output),
			(void*)json_output,
			MHD_RESPMEM_MUST_FREE
		);
	} else if (!strcmp(url, "/api/v1/coinbaser")) {
		T_DATUM_STRATUM_JOB *sjob;

		char tempaddr[256];
		uint64_t tv = 0;

		pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
		j = global_latest_stratum_job_index;
		sjob = (j >= 0 && j < MAX_STRATUM_JOBS) ? global_cur_stratum_jobs[j] : NULL;
		pthread_rwlock_unlock(&stratum_global_job_ptr_lock);

		if (!sjob) {
			// Handle error: no valid job available
			return MHD_NO;
		}

	    json_t *root = json_array();

		for (int i = 0; i < sjob->available_coinbase_outputs_count; i++) {
			output_script_2_addr(sjob->available_coinbase_outputs[i].output_script, 
								sjob->available_coinbase_outputs[i].output_script_len, 
								tempaddr);

			json_t *output = json_object();
			json_object_set_new(output, "address", json_string(tempaddr));
			json_object_set_new(output, "value", json_real((double)sjob->available_coinbase_outputs[i].value_sats / 100000000.0));
			json_array_append_new(root, output);

			tv += sjob->available_coinbase_outputs[i].value_sats;
		}

		if (tv < sjob->coinbase_value) {
			output_script_2_addr(sjob->pool_addr_script, sjob->pool_addr_script_len, tempaddr);

			json_t *output = json_object();
			json_object_set_new(output, "address", json_string(tempaddr));
			json_object_set_new(output, "value", json_real((double)(sjob->coinbase_value - tv) / 100000000.0));
			json_array_append_new(root, output);
		}

		char *json_output = json_dumps(root, JSON_COMPACT);
		json_decref(root);

		if (!json_output) {
			// Handle error: JSON encoding failed
			return MHD_NO;
		}

		response = MHD_create_response_from_buffer(strlen(json_output), 
                                               (void *)json_output, 
                                               MHD_RESPMEM_MUST_FREE);
		
	} else {
		const char *error_response = "{\"error\": \"Not found\"}";
		response = MHD_create_response_from_buffer(strlen(error_response), (void *)error_response, MHD_RESPMEM_PERSISTENT);
		MHD_add_response_header(response, "Content-Type", "application/json");
		ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
		MHD_destroy_response (response);
		return ret;
	}

	if (!response) {
		free(json_output);
		return MHD_NO;
	}

	MHD_add_response_header(response, "Content-Type", "application/json");
	http_resp_prevent_caching(response);
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
}


int datum_api_client_dashboard(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	int ret;
	
	// return the home page with some data and such
	response = MHD_create_response_from_buffer (strlen(www_clients_html), (void *) www_clients_html, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "text/html");
	http_resp_prevent_caching(response);
	ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
	MHD_destroy_response (response);
	return ret;
}

int datum_api_homepage(struct MHD_Connection *connection) {
	struct MHD_Response *response;
	int ret;

	response = MHD_create_response_from_buffer (strlen(www_home_html), (void *) www_home_html, MHD_RESPMEM_MUST_COPY);
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
			if (strstr(url, "/api/") != NULL) {
				return datum_api_json_response(connection, url, method);
			} else if (!strcmp(url, "/assets/icons/datum_logo.svg")) {
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
