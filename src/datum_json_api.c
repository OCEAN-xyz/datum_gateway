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
 * Copyright (c) 2026 Bitcoin Ocean, LLC & Léo Haf
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

#include <string.h>
#include <jansson.h>
#include <microhttpd.h>

#include "datum_api.h"
#include "datum_conf.h"
#include "datum_json_api.h"
#include "datum_jsonrpc.h"
#include "datum_protocol.h"
#include "datum_utils.h"

int datum_api_json_check_password(struct MHD_Connection * const connection) {
	int ret;
	char * const username = MHD_digest_auth_get_username(connection);
	const bool have_username = (username != NULL);
	const char * const realm = "DATUM Gateway";
	if (username) {
		ret = MHD_digest_auth_check2(connection, realm, username, datum_config.api_admin_password, 300, MHD_DIGEST_ALG_SHA256);
		free(username);
	} else {
		ret = MHD_NO;
	}
	
	if (ret != MHD_YES) {
		const bool nonce_is_stale = (ret == MHD_INVALID_NONCE);
		if (have_username && !nonce_is_stale) {
			DLOG_DEBUG("Wrong password in HTTP authentication");
		}
		json_t *json_response = json_object();
		json_object_set_new(json_response, "error", json_string("HTTP auth failed"));
		char *json_response_string = json_dumps(json_response, JSON_INDENT(0));
		json_decref(json_response);
		struct MHD_Response * const response = MHD_create_response_from_buffer(strlen(json_response_string), (void *)json_response_string, MHD_RESPMEM_MUST_COPY);
		free(json_response_string);
		ret = MHD_queue_auth_fail_response2(connection, realm, datum_config.api_csrf_token, response, nonce_is_stale ? MHD_YES : MHD_NO, MHD_DIGEST_ALG_SHA256);
		MHD_destroy_response(response);
		return false;
	}
	
	return true;
}

int datum_api_json_decentralized_client_stats(struct MHD_Connection * const connection) {
	json_t *dcs = json_object();
	T_DATUM_API_DASH_VARS vardata;
	
	datum_api_dash_stats(&vardata);
	
	json_object_set_new(dcs, "acceptedShares", json_integer((unsigned long long)datum_accepted_share_count));
	json_object_set_new(dcs, "acceptedSharesDiff", json_integer((unsigned long long)datum_accepted_share_diff));
	json_object_set_new(dcs, "rejectedShares", json_integer((unsigned long long)datum_rejected_share_count));
	json_object_set_new(dcs, "rejectedSharesDiff", json_integer((unsigned long long)datum_rejected_share_diff));
	json_object_set_new(dcs, "ready", (!datum_blocktemplates_error && vardata.sjob)?json_true():json_false());
	if (datum_config.datum_pool_host[0]) {
		char host[2048];
		
		snprintf(host, sizeof(host), "%s:%u", datum_config.datum_pool_host, (unsigned)datum_config.datum_pool_port);
		json_object_set_new(dcs, "poolHost", json_string(host));
	} else {
		json_object_set_new(dcs, "poolHost", json_string("N/A"));
	}
	json_object_set_new(dcs, "poolTag", json_string(datum_protocol_is_active()?datum_config.override_mining_coinbase_tag_primary:datum_config.mining_coinbase_tag_primary));
	json_object_set_new(dcs, "minerTag", json_string(datum_config.mining_coinbase_tag_secondary));
	json_object_set_new(dcs, "poolMinDiff", json_integer(datum_config.override_vardiff_min));
	json_object_set_new(dcs, "poolPubKey", json_string(datum_config.datum_pool_pubkey));
	json_object_set_new(dcs, "uptime", json_integer(get_process_uptime_seconds()));
	
	char *json_string = json_dumps(dcs, JSON_INDENT(0));
	json_decref(dcs);
	
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_string), (void *)json_string, MHD_RESPMEM_MUST_COPY);
	free(json_string);
	MHD_add_response_header(response, "Content-Type", "application/json");
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

int datum_api_json_stratum_server_info(struct MHD_Connection * const connection) {
	json_t *sst = json_object();
	T_DATUM_API_DASH_VARS vardata;
	
	datum_api_dash_stats(&vardata);
	
	json_object_set_new(sst, "activeThread", json_integer(vardata.STRATUM_ACTIVE_THREADS));
	json_object_set_new(sst, "totalConnections", json_integer(vardata.STRATUM_TOTAL_CONNECTIONS));
	json_object_set_new(sst, "totalWorkSubscriptions", json_integer(vardata.STRATUM_TOTAL_SUBSCRIPTIONS));
	json_object_set_new(sst, "estimatedHashrate", json_real(vardata.STRATUM_HASHRATE_ESTIMATE));
	
	char *json_string = json_dumps(sst, JSON_INDENT(0));
	json_decref(sst);
	
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_string), (void *)json_string, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "application/json");
	free(json_string);
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

int datum_api_json_current_stratum_job(struct MHD_Connection * const connection) {
	json_t *csj = json_object();
	T_DATUM_API_DASH_VARS vardata;
	char *json_text = NULL;
	char *goto_error;
	
	datum_api_dash_stats(&vardata);
	
	if (!vardata.sjob) {
		goto_error = "No stratum job";
		goto error;
	}
	
	json_object_set_new(csj, "block_height", json_integer(vardata.sjob->block_template->height));
	json_object_set_new(csj, "block_value", json_integer(vardata.sjob->block_template->coinbasevalue));
	json_object_set_new(csj, "previous_block", json_string(vardata.sjob->block_template->previousblockhash));
	json_object_set_new(csj, "block_target", json_string(vardata.sjob->block_template->block_target_hex));
	json_object_set_new(csj, "witness_commitment", json_string(vardata.sjob->block_template->default_witness_commitment));
	json_object_set_new(csj, "block_difficulty", json_real(calc_network_difficulty(vardata.sjob->nbits)));
	json_object_set_new(csj, "block_version", json_object());
	json_object_set_new(json_object_get(csj, "block_version"), "int", json_integer(vardata.sjob->version_uint));
	json_object_set_new(json_object_get(csj, "block_version"), "hex", json_string(vardata.sjob->version));
	json_object_set_new(csj, "bits", json_string(vardata.sjob->nbits));
	json_object_set_new(csj, "time", json_object());
	json_object_set_new(json_object_get(csj, "time"), "current", json_integer(vardata.sjob->block_template->curtime));
	json_object_set_new(json_object_get(csj, "time"), "minimum", json_integer(vardata.sjob->block_template->mintime));
	json_object_set_new(csj, "limits", json_object());
	json_object_set_new(json_object_get(csj, "limits"), "size", json_integer(vardata.sjob->block_template->sizelimit));
	json_object_set_new(json_object_get(csj, "limits"), "weight", json_integer(vardata.sjob->block_template->weightlimit));
	json_object_set_new(json_object_get(csj, "limits"), "sigops", json_integer(vardata.sjob->block_template->sigoplimit));
	json_object_set_new(csj, "size", json_integer(vardata.sjob->block_template->txn_total_size));
	json_object_set_new(csj, "weight", json_integer(vardata.sjob->block_template->txn_total_weight));
	json_object_set_new(csj, "sigops", json_integer(vardata.sjob->block_template->txn_total_sigops));
	json_object_set_new(csj, "tx_count", json_integer(vardata.sjob->block_template->txn_count));
	
	char *json_dump = json_dumps(csj, JSON_INDENT(0));
	json_decref(csj);
	
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_dump), (void *)json_dump, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "application/json");
	free(json_dump);
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
	
	error:
		json_object_set_new(csj, "error", json_string(goto_error));
		
		json_text = json_dumps(csj, JSON_INDENT(0));
		json_decref(csj);
		
		response = MHD_create_response_from_buffer(strlen(json_text), (void *)json_text, MHD_RESPMEM_MUST_COPY);
		MHD_add_response_header(response, "Content-Type", "application/json");
		free(json_text);
		return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

int datum_api_json_coinbaser(struct MHD_Connection * const connection) {
	json_t *coinbase = json_object();
	int j, i;
	uint64_t tv = 0;
	char outputaddr[256];
	T_DATUM_STRATUM_JOB *sjob;
	T_DATUM_API_DASH_VARS vardata;
	
	datum_api_dash_stats(&vardata);
	
	pthread_rwlock_rdlock(&stratum_global_job_ptr_lock);
	j = global_latest_stratum_job_index;
	sjob = (j >= 0 && j < MAX_STRATUM_JOBS) ? global_cur_stratum_jobs[j] : NULL;
	pthread_rwlock_unlock(&stratum_global_job_ptr_lock);
	
	if (sjob) {
		for(i=0;i<sjob->available_coinbase_outputs_count;i++) {
			output_script_2_addr(sjob->available_coinbase_outputs[i].output_script, sjob->available_coinbase_outputs[i].output_script_len, outputaddr);
			json_object_set_new(coinbase, outputaddr, json_integer(sjob->available_coinbase_outputs[i].value_sats));
			tv += sjob->available_coinbase_outputs[i].value_sats;
		}
		
		if (tv < sjob->coinbase_value) {
			output_script_2_addr(sjob->pool_addr_script, sjob->pool_addr_script_len, outputaddr);
			json_object_set_new(coinbase, outputaddr, json_integer(sjob->coinbase_value - tv));
		}
	}
	
	char *json_string = json_dumps(coinbase, JSON_INDENT(0));
	json_decref(coinbase);
	
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_string), (void *)json_string, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "application/json");
	free(json_string);
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

int datum_api_json_thread_stats(struct MHD_Connection * const connection) {
	json_t *thread = json_object();
	int j, ii;
	int subs,conns;
	double hr;
	double thr = 0.0;
	unsigned char astat;
	uint64_t tsms;
	T_DATUM_MINER_DATA *m = NULL;
	
	const int max_threads = global_stratum_app ? global_stratum_app->max_threads : 0;
	tsms = current_time_millis();
	
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
			char TID[16];
			snprintf(TID, sizeof(TID), "%d", j);
			json_object_set_new(thread, TID, json_object());
			json_object_set_new(json_object_get(thread, TID), "connection_count", json_integer(conns));
			json_object_set_new(json_object_get(thread, TID), "subscription_count", json_integer(subs));
			json_object_set_new(json_object_get(thread, TID), "approx_hashrate", json_real(thr));
		}
	}
	
	char *json_string = json_dumps(thread, JSON_INDENT(0));
	json_decref(thread);
	
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_string), (void *)json_string, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "application/json");
	free(json_string);
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

int datum_api_json_stratum_client_list(struct MHD_Connection * const connection) {
	json_t *client = json_object();
	int j, ii;
	T_DATUM_MINER_DATA *m = NULL;
	uint64_t tsms;
	double hr;
	unsigned char astat;
	
	if (!datum_config.api_admin_password_len) {
		json_object_set_new(client, "error", json_string("This api requires admin access (add \"admin_password\" to \"api\" section of config file)"));
		
		char *json_string = json_dumps(client, JSON_INDENT(0));
		json_decref(client);
		
		struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_string), (void *)json_string, MHD_RESPMEM_MUST_COPY);
		MHD_add_response_header(response, "Content-Type", "application/json");
		free(json_string); 
		return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
	}
	if (!datum_api_json_check_password(connection)) {
		return MHD_YES;
	}
	
	const int max_threads = global_stratum_app ? global_stratum_app->max_threads : 0;
	tsms = current_time_millis();
	
	for (j = 0; j < max_threads; ++j) {
		for(ii=0;ii<global_stratum_app->max_clients_thread;ii++) {
			if (global_stratum_app->datum_threads[j].client_data[ii].fd > 0) {
				char TID[256];
				char CID[256];
				json_t *current_client;
				snprintf(TID, sizeof(TID), "%d", j);
				snprintf(CID, sizeof(CID), "%d", ii);
				
				m = (T_DATUM_MINER_DATA *)global_stratum_app->datum_threads[j].client_data[ii].app_client_data;
				
				if (!json_is_object(json_object_get(client, TID))) {
					json_object_set_new(client, TID, json_object());
				}
				json_object_set_new(json_object_get(client, TID), CID, json_object());
				current_client = json_object_get(json_object_get(client, TID), CID);
				
				json_object_set_new(current_client, "remote_host", json_string(global_stratum_app->datum_threads[j].client_data[ii].rem_host));
				json_object_set_new(current_client, "auth_username", json_string(m->last_auth_username));
				
				if (m->subscribed) {
					json_object_set_new(current_client, "subscribed", json_true());
					
					char SID[32];
					snprintf(SID, sizeof(SID), "%4.4x", m->sid);
					
					json_object_set_new(current_client, "sid", json_string(SID));
					json_object_set_new(current_client, "sid_time", json_real((double)(tsms - m->subscribe_tsms)/1000.0));
					
					if (m->stats.last_share_tsms) {
						json_object_set_new(current_client, "last_share", json_real((double)(tsms - m->stats.last_share_tsms)/1000.0));
					} else {
						json_object_set_new(current_client, "last_share", json_real(-1.0));
					}
					
					json_object_set_new(current_client, "vdiff", json_integer(m->current_diff));
					json_object_set_new(current_client, "accepted_diff", json_integer(m->share_diff_accepted));
					json_object_set_new(current_client, "accepted_count", json_integer(m->share_count_accepted));
					
					hr = 0.0;
					if (m->share_diff_accepted > 0) {
						hr = ((double)m->share_diff_rejected / (double)(m->share_diff_accepted + m->share_diff_rejected))*100.0;
					}
					
					json_object_set_new(current_client, "rejected_diff", json_integer(m->share_diff_rejected));
					json_object_set_new(current_client, "rejected_count", json_integer(m->share_count_rejected));
					json_object_set_new(current_client, "rejected_percentage", json_real(hr));
					
					astat = m->stats.active_index?0:1; // inverted
					hr = 0.0;
					if ((m->stats.last_swap_ms > 0) && (m->stats.diff_accepted[astat] > 0)) {
						hr = ((double)m->stats.diff_accepted[astat] / (double)((double)m->stats.last_swap_ms/1000.0)) * 0.004294967296; // Th/sec based on shares/sec
					}
					if (m->share_diff_accepted > 0) {
						char hashrate[512];
						snprintf(hashrate, 512, "%.2f", hr);
						json_object_set_new(current_client, "hash_rate", json_string(hashrate));
						json_object_set_new(current_client, "hash_rate_age", json_real((double)(tsms - m->stats.last_swap_tsms)/1000.0));
					} else {
						json_object_set_new(current_client, "hash_rate", json_string("N/A"));
						json_object_set_new(current_client, "hash_rate_age", json_real(-1.0));
					}
					
					if (m->coinbase_selection < cbnames_count) {
						json_object_set_new(current_client, "coinbase", json_string(cbnames[m->coinbase_selection]));
					} else {
						json_object_set_new(current_client, "coinbase", json_string("Unknown"));
					}
					
					json_object_set_new(current_client, "useragent", json_string(m->useragent));
				} else {
					json_object_set_new(current_client, "subscribed", json_false());
				}
			}
		}
	}
	
	char *json_string = json_dumps(client, JSON_INDENT(0));
	json_decref(client);
	
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_string), (void *)json_string, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "application/json");
	free(json_string);
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

int datum_api_json_configuration(struct MHD_Connection * const connection) {
	json_t *config = json_object();
	
	if (!datum_config.api_admin_password_len) {
		json_object_set_new(config, "error", json_string("This api requires admin access (add \"admin_password\" to \"api\" section of config file)"));
		
		char *json_string = json_dumps(config, JSON_INDENT(0));
		json_decref(config);
		
		struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_string), (void *)json_string, MHD_RESPMEM_MUST_COPY);
		MHD_add_response_header(response, "Content-Type", "application/json");
		free(json_string);
		return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
	}
	if (!datum_api_json_check_password(connection)) {
		return MHD_YES;
	}
	
	json_object_set_new(config, "pool_address", json_string(datum_config.mining_pool_address));
	json_object_set_new(config, "miner_username_behavior", json_object());
	json_object_set_new(json_object_get(config, "miner_username_behavior"), "pool_pass_workers", json_boolean(datum_config.datum_pool_pass_workers));
	json_object_set_new(json_object_get(config, "miner_username_behavior"), "pool_pass_full_users", json_boolean(datum_config.datum_pool_pass_full_users));
	json_object_set_new(config, "coinbase_tag_secondary", json_string(datum_config.mining_coinbase_tag_secondary));
	json_object_set_new(config, "coinbase_unique_id", json_integer(datum_config.coinbase_unique_id));
	if (datum_config.datum_pool_host[0] && datum_config.datum_pooled_mining_only){
		json_object_set_new(config, "reward_sharing", json_string("require"));
	} else if (datum_config.datum_pool_host[0] && !datum_config.datum_pooled_mining_only) {
		json_object_set_new(config, "reward_sharing", json_string("prefer"));
	} else if (!(datum_config.datum_pool_host[0] || datum_config.datum_pooled_mining_only)) {
		json_object_set_new(config, "reward_sharing", json_string("never"));
	}
	json_object_set_new(config, "pool", json_object());
	json_object_set_new(json_object_get(config, "pool"), "host", json_string(datum_config.datum_pool_host));
	json_object_set_new(json_object_get(config, "pool"), "port", json_integer(datum_config.datum_pool_port));
	json_object_set_new(json_object_get(config, "pool"), "pubkey", json_string(datum_config.datum_pool_pubkey));
	json_object_set_new(config, "fingerprint_miners", json_boolean(datum_config.stratum_v1_fingerprint_miners));
	json_object_set_new(config, "always_pay_self", json_boolean(datum_config.datum_always_pay_self));
	json_object_set_new(config, "work_update_seconds", json_integer(datum_config.bitcoind_work_update_seconds));
	json_object_set_new(config, "rpcurl", json_string(datum_config.bitcoind_rpcurl));
	json_object_set_new(config, "rpcuser", json_string(datum_config.bitcoind_rpcuser));
	json_object_set_new(config, "rpcpassword_set", json_boolean(datum_config.bitcoind_rpcpassword[0]));
	
	char *json_string = json_dumps(config, JSON_INDENT(0));
	json_decref(config);
	
	struct MHD_Response *response = MHD_create_response_from_buffer(strlen(json_string), (void *)json_string, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "application/json");
	free(json_string);
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

int datum_api_json_set_configuration(struct MHD_Connection * const connection, char *post, int len) {
	struct MHD_Response *response = NULL;
	json_t *config, *current_val = NULL;
	json_error_t error;
	char *json_text = NULL;
	char *goto_error;
	bool need_restart = false;
	
	if (!datum_config.api_admin_password_len) {
		goto_error = "This api requires admin access (add \"admin_password\" to \"api\" section of config file)";
		goto error;
	}
	if (!datum_api_json_check_password(connection)) {
		return MHD_YES;
	}
	
	
	config = json_loadb(post, len, 0, &error);
	
	if (!config) {
		config = json_object();
		json_object_set_new(config, "error", json_string(error.text[0] ? error.text : "Unable to decode JSON"));
	} else {
		current_val = json_object_get(config, "pool_address");
		if (current_val) {
			const char *address = json_string_value(current_val);
			if (address != NULL) {
				if (strcmp(address, datum_config.mining_pool_address) != 0){
					unsigned char dummy[64];
					if (addr_2_output_script(address, &dummy[0], 64)) {
						strcpy(datum_config.mining_pool_address, address);
						datum_api_json_modify_new("mining", "pool_address", current_val);
					} else {
						goto_error = "invalid address";
						goto error;
					}
				}
			} else {
				goto_error = "couldn't stringify the address";
				goto error;
			}
		}
		
		current_val = json_object_get(json_object_get(config, "miner_username_behavior"), "pool_pass_workers");
		if (current_val) {
			if (json_is_boolean(current_val)){
				if (datum_config.datum_pool_pass_workers != json_boolean_value(current_val)) {
					datum_config.datum_pool_pass_workers = json_boolean_value(current_val);
					datum_api_json_modify_new("datum", "pool_pass_workers", json_boolean(datum_config.datum_pool_pass_workers));
				}
			} else {
				goto_error = "pool_pass_workers is not a boolean";
				goto error;
			}
		}
		
		current_val = json_object_get(json_object_get(config, "miner_username_behavior"), "pool_pass_full_users");
		if (current_val) {
			if (json_is_boolean(current_val)){
				if (datum_config.datum_pool_pass_full_users != json_boolean_value(current_val)) {
					datum_config.datum_pool_pass_full_users = json_boolean_value(current_val);
					datum_api_json_modify_new("datum", "pool_pass_full_users", json_boolean(datum_config.datum_pool_pass_full_users));
				}
			} else {
				goto_error = "pool_pass_full_users is not a boolean";
				goto error;
			}
		}
		
		current_val = json_object_get(config, "coinbase_tag_secondary");
		if (current_val) {
			const char *coinbase_tag = json_string_value(current_val);
			if (coinbase_tag != NULL){
				if (strcmp(coinbase_tag, datum_config.mining_coinbase_tag_secondary) != 0) {
					size_t len_limit = 88 - strlen(datum_config.mining_coinbase_tag_primary);
					if (len_limit > 60) len_limit = 60;
					if (strlen(coinbase_tag) > len_limit) {
						goto_error = "Coinbase Tag is too long";
						goto error;
					}
					strcpy(datum_config.mining_coinbase_tag_secondary, coinbase_tag);
					datum_api_json_modify_new("mining", "coinbase_tag_secondary", current_val);
				}
			} else {
				goto_error = "couldn't stringify the coinbase tag";
				goto error;
			}
		}
		
		current_val = json_object_get(config, "coinbase_unique_id");
		if (current_val) {
			if (json_is_integer(current_val)) {
				int coinbase_id = json_integer_value(current_val);
				if (coinbase_id != datum_config.coinbase_unique_id){
					if (coinbase_id <= 65535 && coinbase_id >= 0) {
						datum_config.coinbase_unique_id = coinbase_id;
						datum_api_json_modify_new("mining", "coinbase_unique_id", current_val);
					} else {
						goto_error = "Unique Gateway ID must be between 0 and 65535";
						goto error;
					}
				}
			} else {
				goto_error = "coinbase_unique_id is not an integer";
				goto error;
			}
		}
		
		current_val = json_object_get(json_object_get(config, "pool"), "host");
		if (current_val) {
			const char *host = json_string_value(current_val);
			if (host != NULL) {
				if (strcmp(host, datum_config.datum_pool_host) != 0) {
					if (strlen(host) > 1023) {
						goto_error = "Pool Host is too long";
						goto error;
					}
					strcpy(datum_config.datum_pool_host, host);
					datum_api_json_modify_new("datum", "pool_host", current_val);
					need_restart = true;
				}
			} else {
				goto_error = "couldn't stringify the pool host";
				goto error;
			}
		}
		
		current_val = json_object_get(json_object_get(config, "pool"), "port");
		if (current_val) {
			if (json_is_integer(current_val)) {
				int port = json_integer_value(current_val);
				if (port != datum_config.datum_pool_port) {
					if (port <= 65535 && port > 0) {
						datum_config.datum_pool_port = port;
						datum_api_json_modify_new("datum", "pool_port", current_val);
						need_restart = true;
					} else {
						goto_error = "Pool Port must be between 1 and 65535";
						goto error;
					}
				}
			} else {
				goto_error = "port is not an integer";
				goto error;
			}
		}
		
		current_val = json_object_get(json_object_get(config, "pool"), "pubkey");
		if (current_val) {
			const char *pubkey = json_string_value(current_val);
			if (pubkey != NULL) {
				if (strcmp(pubkey, datum_config.datum_pool_pubkey) != 0) {
					if (strlen(pubkey) > 1023) {
						goto_error = "Pool Pubkey is too long";
						goto error;
					}
					strcpy(datum_config.datum_pool_pubkey, pubkey);
					datum_api_json_modify_new("datum", "pool_pubkey", current_val);
					need_restart = true;
				}
			} else {
				goto_error = "couldn't stringify the pool pubkey";
				goto error;
			}
		}
		
		current_val = json_object_get(config, "fingerprint_miners");
		if (current_val) {
			if (json_is_boolean(current_val)){
				if (json_boolean_value(current_val) != datum_config.stratum_v1_fingerprint_miners) {
					datum_config.stratum_v1_fingerprint_miners = json_boolean_value(current_val);
					datum_api_json_modify_new("stratum", "fingerprint_miners", current_val);
				}
			} else {
				goto_error = "fingerprint_miners is not a boolean";
				goto error;
			}
		}
		
		current_val = json_object_get(config, "always_pay_self");
		if (current_val) {
			if (json_is_boolean(current_val)){
				if (json_boolean_value(current_val) != datum_config.datum_always_pay_self) {
					datum_config.datum_always_pay_self = json_boolean_value(current_val);
					datum_api_json_modify_new("datum", "always_pay_self", current_val);
				}
			} else {
				goto_error = "always_pay_self is not a boolean";
				goto error;
			}
		}
		
		current_val = json_object_get(config, "reward_sharing");
		if (current_val) {
			const char *reward_sharing = json_string_value(current_val);
			if (reward_sharing != NULL) {
				if (0 == strcmp(reward_sharing, "require")){
					if (datum_config.datum_pool_host[0] == '\0') {
						goto_error = "You specified that pooled mining is required but you provided no pool host";
						goto error;
					}
					datum_config.datum_pooled_mining_only = true;
					datum_api_json_modify_new("datum", "pooled_mining_only", json_boolean(true));
					need_restart = true;
				} else if (0 == strcmp(reward_sharing, "prefer")) {
					if (datum_config.datum_pool_host[0] == '\0') {
						goto_error = "You specified that pooled mining is prefered but you provided no pool host";
						goto error;
					}
					datum_config.datum_pooled_mining_only = false;
					datum_api_json_modify_new("datum", "pooled_mining_only", json_boolean(false));
					need_restart = true;
				} else if (0 == strcmp(reward_sharing, "never")) {
					datum_config.datum_pooled_mining_only = false;
					datum_api_json_modify_new("datum", "pooled_mining_only", json_boolean(false));
					datum_config.datum_pool_host[0] = '\0';
					datum_api_json_modify_new("datum", "pool_host", json_string_nocheck(""));
					need_restart = true;
				} else {
					goto_error = "Invalid reward_sharing value";
					goto error;
				}
			} else {
				goto_error = "couldn't stringify the reward mode";
				goto error;
			}
		}
		
		current_val = json_object_get(config, "work_update_seconds");
		if (current_val) {
			if (json_is_integer(current_val)) {
				int work_seconds = json_integer_value(current_val);
				if (work_seconds != datum_config.bitcoind_work_update_seconds){
					if (work_seconds <= 120 && work_seconds >= 5) {
						datum_config.bitcoind_work_update_seconds = work_seconds;
						datum_api_json_modify_new("bitcoind", "work_update_seconds", current_val);
						if (datum_config.bitcoind_work_update_seconds >= datum_config.datum_protocol_global_timeout - 5) {
							datum_config.datum_protocol_global_timeout = work_seconds + 5;
							datum_api_json_modify_new("datum", "protocol_global_timeout", json_integer(work_seconds + 5));
						}
						need_restart = true;
					} else {
						goto_error = "bitcoind work update interval must be between 5 and 120";
						goto error;
					}
				}
			} else {
				goto_error = "work_update_seconds is not an integer";
				goto error;
			}
		}
		
		current_val = json_object_get(config, "rpcurl");
		if (current_val) {
			const char *rpcurl = json_string_value(current_val);
			if (rpcurl != NULL) {
				if (strcmp(rpcurl, datum_config.bitcoind_rpcurl) != 0){
					if (strlen(rpcurl) > 128) {
						goto_error = "bitcoind RPC URL is too long";
						goto error;
					}
					strcpy(datum_config.bitcoind_rpcurl, rpcurl);
					datum_api_json_modify_new("bitcoind", "rpcurl", current_val);
				}
			} else {
				goto_error = "couldn't stringify the RPC url";
				goto error;
			}
		}
		
		current_val = json_object_get(config, "rpcpassword");
		if (current_val) {
			const char *rpcpassword = json_string_value(current_val);
			if (rpcpassword != NULL) {
				if (strcmp(rpcpassword, datum_config.bitcoind_rpcpassword) != 0){
					if (strlen(rpcpassword) >= 128) {
						goto_error = "bitcoind RPC password is too long";
						goto error;
					}
					strcpy(datum_config.bitcoind_rpcpassword, rpcpassword);
					datum_api_json_modify_new("bitcoind", "rpcpassword", current_val);
					update_rpc_auth(&datum_config);
				}
			} else {
				goto_error = "couldn't stringify the RPC password";
				goto error;
			}
		}
		
		current_val = json_object_get(config, "rpcuser");
		if (current_val) {
			const char *rpcuser = json_string_value(current_val);
			if (rpcuser != NULL) {
				if (strcmp(rpcuser, datum_config.bitcoind_rpcuser) != 0){
					if (strlen(rpcuser) >= 128) {
						goto_error = "bitcoind RPC user is too long";
						goto error;
					}
					strcpy(datum_config.bitcoind_rpcuser, rpcuser);
					datum_api_json_modify_new("bitcoind", "rpcuser", current_val);
					update_rpc_auth(&datum_config);
				}
			} else {
				goto_error = "couldn't stringify the RPC user";
				goto error;
			}
		}
	}
	
	if (!datum_api_json_write()) {
		if (need_restart) {
			goto_error = "Error writing new config file (changes will be lost)";
			goto error;
		} else {
			goto_error = "Error writing new config file (changes will be lost at restart)";
			goto error;
		}
	}
	
	if (need_restart) {
		DLOG_INFO("Config change requires restarting gateway, proceeding");
		struct MHD_Daemon * const mhd = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_DAEMON)->daemon;
		pthread_t pthread_datum_restart_thread;
		if (pthread_create(&pthread_datum_restart_thread, NULL, datum_restart_thread, mhd) == 0) {
			pthread_detach(pthread_datum_restart_thread);
		}
	}
	
	json_text = json_dumps(config, JSON_INDENT(0));
	json_decref(config);
	
	response = MHD_create_response_from_buffer(strlen(json_text), (void *)json_text, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "application/json");
	free(json_text);
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
	
	error:
		config = json_object();
		json_object_set_new(config, "error", json_string(goto_error));
		
		json_text = json_dumps(config, JSON_INDENT(0));
		json_decref(config);
		
		response = MHD_create_response_from_buffer(strlen(json_text), (void *)json_text, MHD_RESPMEM_MUST_COPY);
		MHD_add_response_header(response, "Content-Type", "application/json");
		free(json_text);
		return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}

#ifdef DATUM_API_FOR_UMBREL
int datum_api_umbrel_widget(struct MHD_Connection * const connection) {
	char json_response[512];
	T_DATUM_API_DASH_VARS umbreldata;
	const char *hash_unit;
	int json_response_len;
	
	datum_api_dash_stats(&umbreldata);
	
	hash_unit = dynamic_hash_unit(&umbreldata.STRATUM_HASHRATE_ESTIMATE);
	
	json_response_len = snprintf(json_response, sizeof(json_response), "{"
		"\"type\": \"three-stats\","
		"\"refresh\": \"30s\","
		"\"link\": \"\","
		"\"items\": ["
			"{\"title\": \"Connections\", \"text\": \"%d\", \"subtext\": \"Worker\"},"
			"{\"title\": \"Hashrate\", \"text\": \"%.2f\", \"subtext\": \"%s\"}"
		"]"
	"}", umbreldata.STRATUM_TOTAL_CONNECTIONS, umbreldata.STRATUM_HASHRATE_ESTIMATE, hash_unit);
	
	if (json_response_len >= sizeof(json_response)) json_response_len = sizeof(json_response) - 1;
	struct MHD_Response *response = MHD_create_response_from_buffer(json_response_len, (void *)json_response, MHD_RESPMEM_MUST_COPY);
	MHD_add_response_header(response, "Content-Type", "application/json");
	return datum_api_submit_uncached_response(connection, MHD_HTTP_OK, response);
}
#endif