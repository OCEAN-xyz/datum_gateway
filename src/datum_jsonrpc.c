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
 * Copyright (c) 2024-2025 Bitcoin Ocean, LLC & Jason Hughes
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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <jansson.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>

#include "datum_conf.h"
#include "datum_jsonrpc.h"
#include "datum_utils.h"

// TODO: Clean this up.  Most of this is very old code from other parts of Eligius/OCEAN internal tools and needs
// a solid makeover.
// However, it's all quite functional, so not a top priority.

static void databuf_free(struct data_buffer *db) {
	if (!db) {
		return;
	}
	
	free(db->buf);
	memset(db, 0, sizeof(*db));
}

static size_t all_data_cb(const void *ptr, size_t size, size_t nmemb, void *user_data) {
	struct data_buffer *db = user_data;
	size_t len, oldlen, newlen;
	void *newmem;
	
	if (SIZE_MAX / size < nmemb) abort();
	len = size * nmemb;
	
	oldlen = db->len;
	if (SIZE_MAX - oldlen < len) abort();
	newlen = oldlen + len;
	
	newmem = realloc(db->buf, newlen + 1);
	if (!newmem) {
		return 0;
	}
	
	db->buf = newmem;
	db->len = newlen;
	memcpy(&((char *)db->buf)[oldlen], ptr, len);
	((char *)db->buf)[newlen] = 0;
	
	return len;
}

static size_t upload_data_cb(void *ptr, size_t size, size_t nmemb, void *user_data) {
	struct upload_buffer *ub = user_data;
	size_t len;
	if (SIZE_MAX / size < nmemb) nmemb = SIZE_MAX / size;
	len = size * nmemb;
	
	if (len > ub->len) len = ub->len;
	
	if (len) {
		memcpy(ptr, ub->buf, len);
		ub->buf = &((const char *)ub->buf)[len];
		ub->len -= len;
	}
	
	return len;
}

char *basic_http_call(CURL *curl, const char *url) {
	CURLcode rc;
	struct data_buffer all_data = { };
	char curl_err_str[CURL_ERROR_SIZE];
	char *out;
	
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5); // quick timeout!
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5); // quick timeout!
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	
	rc = curl_easy_perform(curl);
	if (rc) {
		DLOG_DEBUG("HTTP request failed: %s", curl_err_str);
		goto err_out;
	}
	
	out = calloc(strlen(all_data.buf)+20,1);
	if (!out) goto err_out;
	
	strcpy(out, all_data.buf);
	
	databuf_free(&all_data);
	curl_easy_reset(curl);
	return out;

err_out:
	databuf_free(&all_data);
	curl_easy_reset(curl);
	return NULL;
}

json_t *json_rpc_call_full(CURL *curl, const char *url, const char *userpass, const char *rpc_req, const char *extra_header, long * const http_resp_code_out) {
	json_t *val, *err_val, *res_val;
	CURLcode rc;
	struct data_buffer all_data = { };
	struct upload_buffer upload_data;
	json_error_t err = { };
	struct curl_slist *headers = NULL;
	char len_hdr[64];
	char curl_err_str[CURL_ERROR_SIZE];
	bool check_for_result = true;
	
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_ENCODING, "");
	curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
	curl_easy_setopt(curl, CURLOPT_TCP_NODELAY, 1);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, all_data_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &all_data);
	curl_easy_setopt(curl, CURLOPT_READFUNCTION, upload_data_cb);
	curl_easy_setopt(curl, CURLOPT_READDATA, &upload_data);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_err_str);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5); // quick timeout!
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5); // quick timeout!
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	
	if (userpass) {
		curl_easy_setopt(curl, CURLOPT_USERPWD, userpass);
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
	}
	
	curl_easy_setopt(curl, CURLOPT_POST, 1);
	
	upload_data.buf = rpc_req;
	upload_data.len = strlen(rpc_req);
	sprintf(len_hdr, "Content-Length: %lu",(unsigned long) upload_data.len);
	
	headers = curl_slist_append(headers, "Content-type: application/json");
	headers = curl_slist_append(headers, len_hdr);
	headers = curl_slist_append(headers, "Expect:");
	
	if (extra_header) {
		headers = curl_slist_append(headers, extra_header);
		check_for_result = false;
	}
	
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	
	rc = curl_easy_perform(curl);
	if (rc) {
		if (http_resp_code_out) curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, http_resp_code_out);
		DLOG_DEBUG("json_rpc_call: HTTP request failed: %s", curl_err_str);
		DLOG_DEBUG("json_rpc_call: Request was: %s",rpc_req);
		goto err_out;
	}
	
	val = JSON_LOADS(all_data.buf, &err);
	if (!val) {
		DLOG_DEBUG("JSON decode failed(%d): %s", err.line, err.text);
		goto err_out;
	}
	
	if (check_for_result) {
		res_val = json_object_get(val, "result");
		err_val = json_object_get(val, "error");
		
		if (!res_val || json_is_null(res_val) || (err_val && !json_is_null(err_val))) {
			char *s;
			
			if (err_val) {
				s = json_dumps(err_val, JSON_INDENT(3));
			} else {
				s = strdup("(unknown reason)");
			}
			
			DLOG_DEBUG("JSON-RPC call failed: %s", s);
			
			free(s);
			
			goto err_out;
		}
	}
	
	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return val;

err_out:
	databuf_free(&all_data);
	curl_slist_free_all(headers);
	curl_easy_reset(curl);
	return NULL;
}

json_t *json_rpc_call(CURL *curl, const char *url, const char *userpass, const char *rpc_req) {
	return json_rpc_call_full(curl, url, userpass, rpc_req, NULL, NULL);
}

bool update_rpc_cookie(global_config_t * const cfg) {
	assert(!cfg->bitcoind_rpcuser[0]);
	FILE * const F = fopen(cfg->bitcoind_rpccookiefile, "r");
	if (!F) {
		DLOG_ERROR("Cannot %s cookie file %s", "open", datum_config.bitcoind_rpccookiefile);
		return false;
	}
	if (!(fgets(cfg->bitcoind_rpcuserpass, sizeof(cfg->bitcoind_rpcuserpass), F) && cfg->bitcoind_rpcuserpass[0])) {
		DLOG_ERROR("Cannot %s cookie file %s", "read", datum_config.bitcoind_rpccookiefile);
		return false;
	}
	return true;
}

void update_rpc_auth(global_config_t * const cfg) {
	if (datum_config.bitcoind_rpccookiefile[0] && !cfg->bitcoind_rpcuser[0]) {
		update_rpc_cookie(cfg);
	} else {
		snprintf(datum_config.bitcoind_rpcuserpass, sizeof(datum_config.bitcoind_rpcuserpass), "%s:%s", datum_config.bitcoind_rpcuser, datum_config.bitcoind_rpcpassword);
	}
}

json_t *bitcoind_json_rpc_call(CURL * const curl, global_config_t * const cfg, const char * const rpc_req) {
	long http_resp_code = -1;
	json_t *j = json_rpc_call_full(curl, cfg->bitcoind_rpcurl, cfg->bitcoind_rpcuserpass, rpc_req, NULL, &http_resp_code);
	if (j) return j;
	if (cfg->bitcoind_rpcuser[0]) return NULL;
	if (http_resp_code != 401) return NULL;

	// Authentication failure using cookie; reload cookie file and try again
	if (!update_rpc_cookie(cfg)) return NULL;
	return json_rpc_call(curl, cfg->bitcoind_rpcurl, cfg->bitcoind_rpcuserpass, rpc_req);
}

// ========== Multi-Node Failover Implementation ==========

#include <pthread.h>
#include <limits.h>

// Mutex for protecting node state updates
static pthread_mutex_t bitcoind_nodes_mutex = PTHREAD_MUTEX_INITIALIZER;

// Mutex for serializing failover operations to prevent duplicate logging from concurrent calls
static pthread_mutex_t bitcoind_failover_mutex = PTHREAD_MUTEX_INITIALIZER;

// Background recovery thread and control variables
static pthread_t recovery_thread;
static bool recovery_thread_running = false;
static pthread_mutex_t recovery_thread_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t recovery_thread_cond = PTHREAD_COND_INITIALIZER;
static global_config_t *recovery_config = NULL;

T_BITCOIND_NODE_CONFIG* bitcoind_get_active_node(global_config_t *cfg) {
	if (cfg->bitcoind_current_node_index < 0 ||
	    cfg->bitcoind_current_node_index >= cfg->bitcoind_node_count) {
		return NULL;
	}
	return &cfg->bitcoind_nodes[cfg->bitcoind_current_node_index];
}

json_t *bitcoind_json_rpc_call_single(CURL *curl, T_BITCOIND_NODE_CONFIG *node, const char *rpc_req) {
	char userpass[512];
	long http_resp_code = -1;

	// Build userpass from node config
	if (node->rpcuser[0] != '\0' && node->rpcpassword[0] != '\0') {
		snprintf(userpass, sizeof(userpass), "%s:%s", node->rpcuser, node->rpcpassword);
	} else if (node->rpccookiefile[0] != '\0') {
		// Try to read cookie file
		FILE *F = fopen(node->rpccookiefile, "r");
		if (!F || !(fgets(userpass, sizeof(userpass), F) && userpass[0])) {
			if (F) fclose(F);
			return NULL;
		}
		fclose(F);
	} else {
		userpass[0] = '\0';
	}

	// Call with faster timeout (2 seconds instead of 5)
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2);

	json_t *j = json_rpc_call_full(curl, node->rpcurl, userpass, rpc_req, NULL, &http_resp_code);

	// Reset to default timeout
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);

	if (j) return j;

	// If authentication failed using cookie, try to reload it
	if (http_resp_code == 401 && node->rpccookiefile[0] != '\0' && !node->rpcuser[0]) {
		FILE *F = fopen(node->rpccookiefile, "r");
		if (F && fgets(userpass, sizeof(userpass), F) && userpass[0]) {
			fclose(F);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 2);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 2);

			j = json_rpc_call(curl, node->rpcurl, userpass, rpc_req);

			curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5);
			curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5);

			return j;
		}
		if (F) fclose(F);
	}

	return NULL;
}

void bitcoind_mark_node_failed(global_config_t *cfg, int node_index) {
	if (node_index < 0 || node_index >= cfg->bitcoind_node_count) return;

	pthread_mutex_lock(&bitcoind_nodes_mutex);

	T_BITCOIND_NODE_CONFIG *node = &cfg->bitcoind_nodes[node_index];
	node->last_failure_time = current_time_millis();
	node->consecutive_failures++;
	node->total_failures++;

	pthread_mutex_unlock(&bitcoind_nodes_mutex);
}

void bitcoind_mark_node_success(global_config_t *cfg, int node_index) {
	if (node_index < 0 || node_index >= cfg->bitcoind_node_count) return;

	pthread_mutex_lock(&bitcoind_nodes_mutex);

	T_BITCOIND_NODE_CONFIG *node = &cfg->bitcoind_nodes[node_index];
	node->last_success_time = current_time_millis();
	node->consecutive_failures = 0;  // Reset on success
	node->total_successes++;

	pthread_mutex_unlock(&bitcoind_nodes_mutex);
}

int bitcoind_get_next_node(global_config_t *cfg, int current_index) {
	// Find next enabled node in failover sequence (next higher priority number)
	uint64_t now = current_time_millis();
	int best_index = -1;
	int best_priority = INT_MAX;
	int fallback_index = -1;  // Node in cooldown, but available as fallback
	int fallback_priority = INT_MAX;
	int current_priority = cfg->bitcoind_nodes[current_index].priority;

	pthread_mutex_lock(&bitcoind_nodes_mutex);

	// First pass: Try to find nodes with higher priority numbers (lower priority) than current
	// Prefer nodes not in cooldown, but track nodes in cooldown as fallback
	for (int i = 0; i < cfg->bitcoind_node_count; i++) {
		if (i == current_index) continue;  // Skip current node

		T_BITCOIND_NODE_CONFIG *node = &cfg->bitcoind_nodes[i];

		if (!node->enabled) continue;

		// Only consider nodes with higher priority numbers (lower priority) than current
		if (node->priority <= current_priority) continue;

		// Check cooldown period
		bool in_cooldown = false;
		if (node->consecutive_failures > 0) {
			uint64_t time_since_failure = now - node->last_failure_time;
			uint64_t cooldown_ms = cfg->bitcoind_failover_cooldown_sec * 1000;

			if (time_since_failure < cooldown_ms) {
				in_cooldown = true;
				// Track as fallback - prefer forward progress over cycling back
				if (node->priority < fallback_priority) {
					fallback_priority = node->priority;
					fallback_index = i;
				}
				continue;  // Skip for now, but remember it
			}
		}

		// Choose node with lowest priority number among candidates (highest priority in this tier)
		if (node->priority < best_priority) {
			best_priority = node->priority;
			best_index = i;
		}
	}

	pthread_mutex_unlock(&bitcoind_nodes_mutex);

	// If no nodes out of cooldown, use the fallback (node in cooldown)
	// This ensures forward progress even if nodes are in cooldown
	if (best_index < 0 && fallback_index >= 0) {
		return fallback_index;
	}

	return best_index;
}

bool bitcoind_should_try_higher_priority(global_config_t *cfg) {
	if (!cfg->bitcoind_try_higher_priority) return false;

	int current_index = cfg->bitcoind_current_node_index;
	if (current_index <= 0) return false;  // Already on highest priority

	pthread_mutex_lock(&bitcoind_nodes_mutex);

	// Check if any higher-priority nodes are available (enabled and out of cooldown)
	uint64_t now = current_time_millis();
	uint64_t cooldown_ms = cfg->bitcoind_failover_cooldown_sec * 1000;

	for (int i = 0; i < current_index; i++) {
		T_BITCOIND_NODE_CONFIG *node = &cfg->bitcoind_nodes[i];

		if (!node->enabled) continue;

		// Check if out of cooldown
		if (node->consecutive_failures > 0) {
			uint64_t time_since_failure = now - node->last_failure_time;
			if (time_since_failure < cooldown_ms) {
				continue;
			}
		}

		// Found a higher-priority node that's available
		pthread_mutex_unlock(&bitcoind_nodes_mutex);
		return true;
	}

	pthread_mutex_unlock(&bitcoind_nodes_mutex);
	return false;
}

// Background thread function to check for higher-priority node recovery
void *bitcoind_recovery_thread_func(void *arg) {
	DLOG_INFO("Background recovery thread started");

	while (true) {
		pthread_mutex_lock(&recovery_thread_mutex);

		// Check if we should exit
		if (!recovery_thread_running) {
			pthread_mutex_unlock(&recovery_thread_mutex);
			break;
		}

		global_config_t *cfg = recovery_config;
		if (!cfg) {
			pthread_mutex_unlock(&recovery_thread_mutex);
			break;
		}

		pthread_mutex_unlock(&recovery_thread_mutex);

		// Check if we should try higher-priority nodes
		if (cfg->bitcoind_try_higher_priority) {
			int current_index = cfg->bitcoind_current_node_index;

			// Only check if we're on a backup node
			if (current_index > 0) {
				// Check each higher-priority node
				pthread_mutex_lock(&bitcoind_nodes_mutex);

				uint64_t now = current_time_millis();
				uint64_t cooldown_ms = cfg->bitcoind_failover_cooldown_sec * 1000;

				for (int i = 0; i < current_index; i++) {
					T_BITCOIND_NODE_CONFIG *node = &cfg->bitcoind_nodes[i];

					if (!node->enabled) continue;

					// Check if this node was failed and is now out of cooldown
					if (node->consecutive_failures > 0) {
						uint64_t time_since_failure = now - node->last_failure_time;
						if (time_since_failure >= cooldown_ms) {
							// This node is ready to be tested
							DLOG_DEBUG("Recovery thread: Testing node %d (priority %d) after cooldown", i, node->priority);
							pthread_mutex_unlock(&bitcoind_nodes_mutex);

							// Silently try to connect (no logging of failure)
							CURL *test_curl = curl_easy_init();
							if (!test_curl) {
								pthread_mutex_lock(&bitcoind_nodes_mutex);
								continue;
							}

							// Try a simple getblockcount call to test connectivity
							const char *test_rpc = "{\"method\":\"getblockcount\",\"params\":[],\"id\":1}";
							json_t *test_result = bitcoind_json_rpc_call_single(test_curl, node, test_rpc);

							curl_easy_cleanup(test_curl);

							if (test_result) {
								// Success! Mark the node as recovered
								json_decref(test_result);

								pthread_mutex_lock(&bitcoind_nodes_mutex);
								// Directly update node state (we already hold the mutex)
								node->last_success_time = current_time_millis();
								node->consecutive_failures = 0;  // Reset on success
								node->total_successes++;
								pthread_mutex_unlock(&bitcoind_nodes_mutex);

								// Log only the successful recovery
								DLOG_INFO("Bitcoin node %d (priority %d) has recovered and is now available: %s",
								         i, node->priority, node->rpcurl);
							}

							// Re-acquire the lock to continue checking other nodes
							pthread_mutex_lock(&bitcoind_nodes_mutex);
						}
					}
				}

				pthread_mutex_unlock(&bitcoind_nodes_mutex);
			}
		}

		// Sleep for the cooldown period before checking again
		// Use pthread_cond_timedwait for interruptible sleep
		pthread_mutex_lock(&recovery_thread_mutex);

		if (!recovery_thread_running) {
			pthread_mutex_unlock(&recovery_thread_mutex);
			break;
		}

		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += recovery_config->bitcoind_failover_cooldown_sec;

		int wait_result = pthread_cond_timedwait(&recovery_thread_cond, &recovery_thread_mutex, &ts);

		// If signaled (not timeout), we're shutting down
		if (wait_result != ETIMEDOUT) {
			pthread_mutex_unlock(&recovery_thread_mutex);
			break;
		}

		pthread_mutex_unlock(&recovery_thread_mutex);
	}

	DLOG_INFO("Background recovery thread stopped");
	return NULL;
}

// Start the background recovery thread
void bitcoind_recovery_thread_start(global_config_t *cfg) {
	pthread_mutex_lock(&recovery_thread_mutex);

	if (recovery_thread_running) {
		pthread_mutex_unlock(&recovery_thread_mutex);
		return;  // Already running
	}

	recovery_config = cfg;
	recovery_thread_running = true;

	if (pthread_create(&recovery_thread, NULL, bitcoind_recovery_thread_func, NULL) != 0) {
		DLOG_ERROR("Failed to create background recovery thread");
		recovery_thread_running = false;
		recovery_config = NULL;
		pthread_mutex_unlock(&recovery_thread_mutex);
		return;
	}

	pthread_mutex_unlock(&recovery_thread_mutex);
}

// Stop the background recovery thread
void bitcoind_recovery_thread_stop(void) {
	pthread_mutex_lock(&recovery_thread_mutex);

	if (!recovery_thread_running) {
		pthread_mutex_unlock(&recovery_thread_mutex);
		return;  // Not running
	}

	recovery_thread_running = false;
	pthread_cond_signal(&recovery_thread_cond);  // Wake up the thread

	pthread_mutex_unlock(&recovery_thread_mutex);

	// Wait for thread to finish
	pthread_join(recovery_thread, NULL);

	recovery_config = NULL;
}

json_t *bitcoind_json_rpc_call_with_failover(CURL *curl, global_config_t *cfg, const char *rpc_req, int *node_index_out) {
	// Serialize failover operations to prevent duplicate logging from concurrent calls
	pthread_mutex_lock(&bitcoind_failover_mutex);

	json_t *result = NULL;
	int starting_index = cfg->bitcoind_current_node_index;
	int current_index = starting_index;
	int current_node_attempts = 0;  // Attempts on current node
	int total_nodes_tried = 0;      // Total different nodes tried
	bool already_retried_all = false;  // Track if we've already done a full retry cycle
	uint64_t now = current_time_millis();
	uint64_t cooldown_ms = cfg->bitcoind_failover_cooldown_sec * 1000;

	DLOG_DEBUG("Starting GBT fetch with failover (current node: %d)", starting_index);

	// If try_higher_priority is enabled and we're not on the highest priority node,
	// check if any higher-priority nodes have been marked as recovered (by background thread)
	if (cfg->bitcoind_try_higher_priority && starting_index > 0) {
		pthread_mutex_lock(&bitcoind_nodes_mutex);
		for (int i = 0; i < starting_index; i++) {
			T_BITCOIND_NODE_CONFIG *node = &cfg->bitcoind_nodes[i];
			// Check if this higher-priority node is enabled and has been marked as recovered
			if (node->enabled && node->consecutive_failures == 0) {
				// Switch to this higher-priority recovered node
				current_index = i;
				DLOG_INFO("Switching to recovered higher-priority node %d (priority %d): %s",
				         i, node->priority, node->rpcurl);
				break;
			}
		}
		pthread_mutex_unlock(&bitcoind_nodes_mutex);
	}

	// Try nodes in priority order
	while (total_nodes_tried < cfg->bitcoind_node_count) {
		T_BITCOIND_NODE_CONFIG *node = &cfg->bitcoind_nodes[current_index];

		// Skip disabled nodes
		if (!node->enabled) {
			DLOG_DEBUG("Node %d is disabled, skipping", current_index);
			current_index = bitcoind_get_next_node(cfg, current_index);
			if (current_index < 0) break;  // No more nodes
			total_nodes_tried++;
			current_node_attempts = 0;
			continue;
		}

		// Check cooldown period for failed nodes (only on first attempt of this node in this call)
		if (current_node_attempts == 0 && node->consecutive_failures > 0) {
			uint64_t time_since_failure = now - node->last_failure_time;
			if (time_since_failure < cooldown_ms) {
				DLOG_DEBUG("Node %d still in cooldown period (%llu ms remaining)",
				          current_index,
				          (unsigned long long)(cooldown_ms - time_since_failure));
				int next_index = bitcoind_get_next_node(cfg, current_index);
				if (next_index < 0) {
					// No more nodes available that aren't in cooldown
					// As a last resort, try this cooled-down node anyway - mining must continue!
					DLOG_WARN("All available nodes are in cooldown or failed. Retrying node %d despite cooldown.", current_index);
					// Don't skip - fall through to try this node
				} else {
					current_index = next_index;
					total_nodes_tried++;
					current_node_attempts = 0;
					continue;
				}
			} else {
				DLOG_INFO("Node %d cooldown expired, retrying", current_index);
			}
		}

		// Try this node
		DLOG_DEBUG("Attempting GBT from node %d (priority %d, attempt %d/%d): %s",
		           current_index, node->priority, current_node_attempts + 1,
		           cfg->bitcoind_max_consecutive_failures, node->rpcurl);

		result = bitcoind_json_rpc_call_single(curl, node, rpc_req);

		if (result) {
			// Success!
			bitcoind_mark_node_success(cfg, current_index);

			// Log message if we switched nodes
			if (current_index != starting_index) {
				if (current_index < starting_index) {
					DLOG_INFO("Recovered to higher-priority Bitcoin node %d (priority %d): %s",
					         current_index, node->priority, node->rpcurl);
				} else {
					DLOG_INFO("Failed over to Bitcoin node %d (priority %d): %s",
					         current_index, node->priority, node->rpcurl);
				}
			}

			cfg->bitcoind_current_node_index = current_index;
			if (node_index_out) *node_index_out = current_index;
			pthread_mutex_unlock(&bitcoind_failover_mutex);
			return result;
		}

		// Failed - increment attempt counter
		current_node_attempts++;

		DLOG_WARN("Bitcoin node %d failed (attempt %d/%d): %s",
		         current_index, current_node_attempts, cfg->bitcoind_max_consecutive_failures,
		         node->rpcurl);

		// Check if we've exhausted retries for this node
		if (current_node_attempts >= cfg->bitcoind_max_consecutive_failures) {
			// Mark node as failed only when we've exhausted all retries
			bitcoind_mark_node_failed(cfg, current_index);

			DLOG_WARN("Node %d exceeded failure threshold (%d/%d, consecutive failures: %d), switching to next node",
			         current_index, current_node_attempts, cfg->bitcoind_max_consecutive_failures,
			         node->consecutive_failures);

			// Move to next node
			int next_index = bitcoind_get_next_node(cfg, current_index);
			if (next_index < 0) {
				// No more nodes available - try cycling through all nodes again ignoring cooldown
				// but only once to prevent infinite loop
				if (!already_retried_all) {
					DLOG_WARN("No more nodes available. Will retry all nodes from the beginning.");
					current_index = 0;
					current_node_attempts = 0;
					total_nodes_tried = 0;  // Reset to try all nodes again
					already_retried_all = true;  // Mark that we've done a retry cycle
					now = current_time_millis();  // Update time for fresh cooldown checks
					continue;
				} else {
					// Already retried all nodes once, give up
					DLOG_ERROR("All nodes failed after retry cycle");
					break;
				}
			}

			current_index = next_index;
			current_node_attempts = 0;
			total_nodes_tried++;
		}
		// Otherwise, retry the same node
	}

	// All nodes failed
	DLOG_ERROR("All %d Bitcoin nodes failed to respond!", cfg->bitcoind_node_count);
	pthread_mutex_unlock(&bitcoind_failover_mutex);
	return NULL;
}

void bitcoind_get_node_stats(global_config_t *cfg, int node_index, char *stats_json_out, size_t max_len) {
	if (node_index < 0 || node_index >= cfg->bitcoind_node_count) {
		snprintf(stats_json_out, max_len, "{\"error\":\"invalid node index\"}");
		return;
	}

	pthread_mutex_lock(&bitcoind_nodes_mutex);

	T_BITCOIND_NODE_CONFIG *node = &cfg->bitcoind_nodes[node_index];

	const char *status;
	if (!node->enabled) {
		status = "disabled";
	} else if (node_index == cfg->bitcoind_current_node_index) {
		status = "active";
	} else if (node->consecutive_failures > 0) {
		uint64_t now = current_time_millis();
		uint64_t time_since_failure = now - node->last_failure_time;
		uint64_t cooldown_ms = cfg->bitcoind_failover_cooldown_sec * 1000;

		if (time_since_failure < cooldown_ms) {
			status = "failed";
		} else {
			status = "available";
		}
	} else {
		status = "available";
	}

	double success_rate = 0.0;
	uint32_t total_requests = node->total_successes + node->total_failures;
	if (total_requests > 0) {
		success_rate = (double)node->total_successes / (double)total_requests * 100.0;
	}

	snprintf(stats_json_out, max_len,
	    "{"
	    "\"index\":%d,"
	    "\"priority\":%d,"
	    "\"rpcurl\":\"%s\","
	    "\"enabled\":%s,"
	    "\"status\":\"%s\","
	    "\"consecutive_failures\":%u,"
	    "\"total_successes\":%u,"
	    "\"total_failures\":%u,"
	    "\"success_rate\":%.2f,"
	    "\"last_success_time\":%llu,"
	    "\"last_failure_time\":%llu"
	    "}",
	    node_index,
	    node->priority,
	    node->rpcurl,
	    node->enabled ? "true" : "false",
	    status,
	    node->consecutive_failures,
	    node->total_successes,
	    node->total_failures,
	    success_rate,
	    (unsigned long long)node->last_success_time,
	    (unsigned long long)node->last_failure_time
	);

	pthread_mutex_unlock(&bitcoind_nodes_mutex);
}
