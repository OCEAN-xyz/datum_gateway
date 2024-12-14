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

// Custom configurator and help output generator

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <jansson.h>

#include "datum_conf.h"
#include "datum_utils.h"
#include "datum_sockets.h"

global_config_t datum_config;

const char *datum_conf_var_type_text[] = { "N/A", "boolean", "integer", "string", "string_array" };

const T_DATUM_CONFIG_ITEM datum_config_options[] = {
	// Bitcoind configs
	{ .var_type = DATUM_CONF_STRING, 	.category = "bitcoind", 	.name = "rpcuser",					.description = "RPC username for communication with local bitcoind.",
		.required = true, .ptr = datum_config.bitcoind_rpcuser, .max_string_len = 128 },
	{ .var_type = DATUM_CONF_STRING, 	.category = "bitcoind", 	.name = "rpcpassword",				.description = "RPC password for communication with local bitcoind.",
		.required = true, .ptr = datum_config.bitcoind_rpcpassword, .max_string_len = 128 },
	{ .var_type = DATUM_CONF_STRING, 	.category = "bitcoind", 	.name = "rpcurl",					.description = "RPC URL for communication with local bitcoind. (GBT Template Source)",
		.required = true, .ptr = datum_config.bitcoind_rpcurl, .max_string_len = 128 },
	{ .var_type = DATUM_CONF_INT,	 	.category = "bitcoind", 	.name = "work_update_seconds",		.description = "How many seconds between normal work updates?  (5-120, 40 suggested)",
		.required = false, .ptr = &datum_config.bitcoind_work_update_seconds, .default_int = 40 },
	{ .var_type = DATUM_CONF_BOOL,	 	.category = "bitcoind", 	.name = "notify_fallback",			.description = "Fall back to less efficient methods for new block notifications. Can disable if you use blocknotify.",
		.required = false, .ptr = &datum_config.bitcoind_notify_fallback, .default_bool = true },
	
	// stratum v1 server configs
	{ .var_type = DATUM_CONF_INT, 		.category = "stratum", 		.name = "listen_port",				.description = "Listening port for Stratum Gateway",
		.required = false, .ptr = &datum_config.stratum_v1_listen_port, 				.default_int = 23334 },
	{ .var_type = DATUM_CONF_INT, 		.category = "stratum", 		.name = "max_clients_per_thread",	.description = "Maximum clients per Stratum server thread",
		.required = false, .ptr = &datum_config.stratum_v1_max_clients_per_thread, 		.default_int = 128 },
	{ .var_type = DATUM_CONF_INT, 		.category = "stratum", 		.name = "max_threads",				.description = "Maximum Stratum server threads",
		.required = false, .ptr = &datum_config.stratum_v1_max_threads,					.default_int = 8 },
	{ .var_type = DATUM_CONF_INT, 		.category = "stratum", 		.name = "max_clients",				.description = "Maximum total Stratum clients before rejecting connections",
		.required = false, .ptr = &datum_config.stratum_v1_max_clients, 				.default_int = 1024 },
	{ .var_type = DATUM_CONF_INT, 		.category = "stratum", 		.name = "vardiff_min",				.description = "Work difficulty floor",
		.required = false, .ptr = &datum_config.stratum_v1_vardiff_min, 				.default_int = 16384 },
	{ .var_type = DATUM_CONF_INT, 		.category = "stratum", 		.name = "vardiff_target_shares_min",.description = "Adjust work difficulty to target this many shares per minute",
		.required = false, .ptr = &datum_config.stratum_v1_vardiff_target_shares_min, 	.default_int = 8 },
	{ .var_type = DATUM_CONF_INT, 		.category = "stratum", 		.name = "vardiff_quickdiff_count",	.description = "How many shares before considering a quick diff update",
		.required = false, .ptr = &datum_config.stratum_v1_vardiff_quickdiff_count, 	.default_int = 8 },
	{ .var_type = DATUM_CONF_INT, 		.category = "stratum", 		.name = "vardiff_quickdiff_delta",	.description = "How many times faster than our target does the miner have to be before we enforce a quick diff bump",
		.required = false, .ptr = &datum_config.stratum_v1_vardiff_quickdiff_delta, 	.default_int = 8 },
	{ .var_type = DATUM_CONF_INT, 		.category = "stratum", 		.name = "share_stale_seconds",		.description = "How many seconds after a job is generated before a share submission is considered stale?",
		.required = false, .ptr = &datum_config.stratum_v1_share_stale_seconds, 		.default_int = 120 },
	{ .var_type = DATUM_CONF_BOOL, 		.category = "stratum", 		.name = "fingerprint_miners",		.description = "Attempt to fingerprint miners for better use of coinbase space",
		.required = false, .ptr = &datum_config.stratum_v1_fingerprint_miners, 			.default_bool = true },
	{ .var_type = DATUM_CONF_INT, 		.category = "stratum", 		.name = "idle_timeout_no_subscribe",.description = "Seconds we allow a connection to be idle without seeing a work subscription? (0 disables)",
		.required = false, .ptr = &datum_config.stratum_v1_idle_timeout_no_subscribe, 	.default_int = 15 },
	{ .var_type = DATUM_CONF_INT, 		.category = "stratum", 		.name = "idle_timeout_no_shares",	.description = "Seconds we allow a subscribed connection to be idle without seeing at least one accepted share? (0 disables)",
		.required = false, .ptr = &datum_config.stratum_v1_idle_timeout_no_share, 	.default_int = 7200 },
	{ .var_type = DATUM_CONF_INT, 		.category = "stratum", 		.name = "idle_timeout_max_last_work",	.description = "Seconds we allow a subscribed connection to be idle since its last accepted share? (0 disables)",
		.required = false, .ptr = &datum_config.stratum_v1_idle_timeout_max_last_work, 	.default_int = 0 },
	
	// mining settings
	{ .var_type = DATUM_CONF_STRING, 	.category = "mining", 		.name = "pool_address",				.description = "Bitcoin address used for mining rewards.",
		.required = true, .ptr = datum_config.mining_pool_address, .max_string_len = 128 },
	{ .var_type = DATUM_CONF_STRING, 	.category = "mining", 		.name = "coinbase_tag_primary",		.description = "Text to have in the primary coinbase tag when not using pool (overridden by DATUM Pool)",
		.required = false, .ptr = datum_config.mining_coinbase_tag_primary,				.default_string[0] = "DATUM Gateway", .max_string_len = 64 },
	{ .var_type = DATUM_CONF_STRING, 	.category = "mining", 		.name = "coinbase_tag_secondary",	.description = "Text to have in the secondary coinbase tag (Short name/identifier)",
		.required = false, .ptr = datum_config.mining_coinbase_tag_secondary,			.default_string[0] = "DATUM User", .max_string_len = 64 },
	{ .var_type = DATUM_CONF_INT, 		.category = "mining", 		.name = "coinbase_unique_id",		.description = "A unique ID between 1 and 65535. This is appended to the coinbase. Make unique per instance of datum with the same coinbase tags.",
		.required = false, .ptr = &datum_config.coinbase_unique_id, 		.default_int = 4242 },
	{ .var_type = DATUM_CONF_STRING, 	.category = "mining", 		.name = "save_submitblocks_dir",	.description = "Directory to save all submitted blocks to as submitblock JSON files",
		.required = false, .ptr = datum_config.mining_save_submitblocks_dir,			.default_string[0] = "", .max_string_len = 256 },
	
	// API/dashboard
	{ .var_type = DATUM_CONF_INT, 		.category = "api",	 		.name = "listen_port",				.description = "Port to listen for API/dashboard requests (0=disabled)",
		.required = false, .ptr = &datum_config.api_listen_port, 						.default_int = 0 },
	
	// extra block submissions list
	{ .var_type = DATUM_CONF_STRING_ARRAY, 	.category = "extra_block_submissions", 	.name = "urls",		.description = "Array of bitcoind RPC URLs to submit our blocks to directly.  Include auth info: http://user:pass@IP",
		.required = false, .ptr = datum_config.extra_block_submissions_urls[0],		.max_string_len = 512 },
	
	// logger
	{ .var_type = DATUM_CONF_BOOL, 		.category = "logger", 		.name = "log_to_console",			.description = "Enable logging of messages to the console",
		.required = false, .ptr = &datum_config.clog_to_console, 	.default_bool = true },
	{ .var_type = DATUM_CONF_BOOL, 		.category = "logger", 		.name = "log_to_stderr",			.description = "Log console messages to stderr *instead* of stdout",
		.required = false, .ptr = &datum_config.clog_to_stderr, 	.default_bool = false },
	{ .var_type = DATUM_CONF_BOOL, 		.category = "logger", 		.name = "log_to_file",				.description = "Enable logging of messages to a file",
		.required = false, .ptr = &datum_config.clog_to_file, 		.default_bool = false },
	{ .var_type = DATUM_CONF_STRING, 	.category = "logger", 		.name = "log_file",					.description = "Path to file to write log messages, when enabled",
		.required = false, .ptr = datum_config.clog_file,			.default_string[0] = "", .max_string_len = 1023 },
	{ .var_type = DATUM_CONF_BOOL, 		.category = "logger", 		.name = "log_rotate_daily",			.description = "Rotate the message log file at midnight",
		.required = false, .ptr = &datum_config.clog_rotate_daily, 		.default_bool = true },
	{ .var_type = DATUM_CONF_BOOL, 		.category = "logger", 		.name = "log_calling_function",		.description = "Log the name of the calling function when logging",
		.required = false, .ptr = &datum_config.clog_calling_function, 		.default_bool = true },
	{ .var_type = DATUM_CONF_INT, 		.category = "logger",	.name = "log_level_console",			.description = "Minimum log level for console messages (0=All, 1=Debug, 2=Info, 3=Warn, 4=Error, 5=Fatal)",
		.required = false, .ptr = &datum_config.clog_level_console, .default_int = 2 },
	{ .var_type = DATUM_CONF_INT, 		.category = "logger",	.name = "log_level_file",				.description = "Minimum log level for log file messages (0=All, 1=Debug, 2=Info, 3=Warn, 4=Error, 5=Fatal)",
		.required = false, .ptr = &datum_config.clog_level_file, .default_int = 1 },
	
	// datum options
	{ .var_type = DATUM_CONF_STRING, 	.category = "datum", 		.name = "pool_host",					.description = "Remote DATUM server host/ip to use for decentralized pooled mining (set to \"\" to disable pooled mining)",
		.required = false, .ptr = datum_config.datum_pool_host,			.default_string[0] = "datum-beta1.mine.ocean.xyz", .max_string_len = 1023 },
	{ .var_type = DATUM_CONF_INT, 		.category = "datum",		.name = "pool_port",					.description = "Remote DATUM server port",
		.required = false, .ptr = &datum_config.datum_pool_port, .default_int = 28915 },
	{ .var_type = DATUM_CONF_STRING, 	.category = "datum", 		.name = "pool_pubkey",					.description = "Public key of the DATUM server for initiating encrypted connection. Get from secure location, or set to empty to auto-fetch.",
		.required = false, .ptr = datum_config.datum_pool_pubkey,		.default_string[0] = "f21f2f0ef0aa1970468f22bad9bb7f4535146f8e4a8f646bebc93da3d89b1406f40d032f09a417d94dc068055df654937922d2c89522e3e8f6f0e649de473003", .max_string_len = 1023 },
	{ .var_type = DATUM_CONF_BOOL, 		.category = "datum", 		.name = "pool_pass_workers",			.description = "Pass stratum miner usernames as sub-worker names to the pool (pool_username.miner's username)",
		.required = false, .ptr = &datum_config.datum_pool_pass_workers, 		.default_bool = true },
	{ .var_type = DATUM_CONF_BOOL, 		.category = "datum", 		.name = "pool_pass_full_users",			.description = "Pass stratum miner usernames as raw usernames to the pool (use if putting multiple payout addresses on miners behind this gateway)",
		.required = false, .ptr = &datum_config.datum_pool_pass_full_users, 	.default_bool = true },
	{ .var_type = DATUM_CONF_BOOL, 		.category = "datum", 		.name = "always_pay_self",				.description = "Always include my datum.pool_username payout in my blocks if possible",
		.required = false, .ptr = &datum_config.datum_always_pay_self, 	.default_bool = true },
	{ .var_type = DATUM_CONF_BOOL, 		.category = "datum", 		.name = "pooled_mining_only",			.description = "If the DATUM pool server becomes unavailable, terminate miner connections (otherwise, 100% of any blocks you find pay mining.pool_address)",
		.required = false, .ptr = &datum_config.datum_pooled_mining_only, 	.default_bool = true },
	{ .var_type = DATUM_CONF_INT, 		.category = "datum", 		.name = "protocol_global_timeout",		.description = "If no valid messages are received from the DATUM server in this many seconds, give up and try to reconnect",
		.required = false, .ptr = &datum_config.datum_protocol_global_timeout, 	.default_int = 60 },
};

#define NUM_CONFIG_ITEMS (sizeof(datum_config_options) / sizeof(datum_config_options[0]))

json_t *load_json_from_file(const char *file_path) {
	json_error_t error;
	json_t *root = json_load_file(file_path, 0, &error);
	
	if(!root) {
		DLOG_ERROR("Error parsing JSON file: %s", error.text);
		return NULL;
	}
	
	return root;
}

void datum_config_set_default(const T_DATUM_CONFIG_ITEM *c) {
	// set the default
	switch(c->var_type) {
		case DATUM_CONF_INT: {
			*((int *)c->ptr) = c->default_int;
			break;
		}
		
		case DATUM_CONF_BOOL: {
			*((bool *)c->ptr) = c->default_bool;
			break;
		}
		
		case DATUM_CONF_STRING: {
			strncpy((char *)c->ptr, c->default_string[0], c->max_string_len-1);
			((char *)c->ptr)[c->max_string_len-1] = 0;
			break;
		}
		
		case DATUM_CONF_STRING_ARRAY: {
			// TODO: For now, these won't have a default. the first string will just be empty
			((char *)c->ptr)[0] = 0;
			break;
		}
		
		default: break;
	}
}

int datum_config_parse_value(const T_DATUM_CONFIG_ITEM *c, json_t *item) {
	switch(c->var_type) {
		case DATUM_CONF_INT: {
			if (json_is_null(item)) {
				*((int *)c->ptr) = 0; // set to zero if "NULL" ... probably not ideal, but better than failing
				return 1;
			}
			if (!json_is_integer(item)) return -1;
			const json_int_t value = json_integer_value(item);
			if (value > INT_MAX || value < INT_MIN) return -1;
			*((int *)c->ptr) = value;
			return 1;
		}
		
		case DATUM_CONF_BOOL: {
			if (json_is_null(item)) {
				*((bool *)c->ptr) = false; // set to false if "NULL" ... probably not ideal, but better than failing
				return 1;
			}
			if (!json_is_boolean(item)) return -1;
			*((bool *)c->ptr) = json_boolean_value(item)?true:false;
			return 1;
		}
		
		case DATUM_CONF_STRING: {
			if (json_is_null(item)) {
				((char *)c->ptr)[0] = 0;  // Set c->ptr to an empty string if the js is actually NULL
				return 1;
			}
			if (!json_is_string(item)) return -1;
			strncpy((char *)c->ptr, json_string_value(item), c->max_string_len-1);
			((char *)c->ptr)[c->max_string_len-1] = 0;
			return 1;
		}
		
		case DATUM_CONF_STRING_ARRAY: {
			if (!json_is_array(item)) return -1;
			
			size_t index;
			json_t *value;
			int i = 0;
			
			json_array_foreach(item, index, value) {
				if (!json_is_string(value)) return -1;
				if (i < (DATUM_CONFIG_MAX_ARRAY_ENTRIES-1)) {
					strncpy(((char (*)[1024])c->ptr)[i], json_string_value(value), c->max_string_len-1);
					((char (*)[1024])c->ptr)[i][c->max_string_len-1] = 0;
					i++;
				}
			}
			((char (*)[1024])c->ptr)[i][0] = 0;
			return 1;
		}
		
		default: break;
	}
	
	return -1;
}

int datum_read_config(const char *conffile) {
	json_t *config = NULL;
	json_t *cat, *item;
	
	unsigned int i;
	int j;
	
	memset(&datum_config, 0, sizeof(global_config_t));
	
	config = load_json_from_file(conffile);
	
	if (!config) {
		DLOG_FATAL("Could not read configuration JSON file!");
		return -1;
	}
	
	for (i=0;i<NUM_CONFIG_ITEMS;i++) {
		item = NULL; cat = NULL;
		cat = json_object_get(config, datum_config_options[i].category);
		if (cat) {
			item = json_object_get(cat, datum_config_options[i].name);
		}
		if ((!cat) || (!item)) {
			if (datum_config_options[i].required) {
				DLOG_ERROR("Required configuration option (%s.%s) not found in config file:", datum_config_options[i].category, datum_config_options[i].name);
				DLOG_ERROR("--- Config description: \"%s\"", datum_config_options[i].description);
				return 0;
			} else {
				datum_config_set_default(&datum_config_options[i]);
			}
			continue;
		}
		
		// item might be valid
		j = datum_config_parse_value(&datum_config_options[i], item);
		if (j != 1) {
			DLOG_ERROR("Could not parse configuration option %s.%s.  Type should be %s", datum_config_options[i].category, datum_config_options[i].name, (datum_config_options[i].var_type<DATUM_CONF_TYPES)?datum_conf_var_type_text[datum_config_options[i].var_type]:"UNKNOWN");
		}
	}
	
	if (config) {
		json_decref(config);
	}
	
	// pass configuration options to the logger
	datum_logger_config(datum_config.clog_to_file, datum_config.clog_to_console, datum_config.clog_level_console, datum_config.clog_level_file, datum_config.clog_calling_function, datum_config.clog_to_stderr, datum_config.clog_rotate_daily, datum_config.clog_file);
	
	i = 0;
	for(i=0;i<DATUM_CONFIG_MAX_ARRAY_ENTRIES;i++) {
		if (datum_config.extra_block_submissions_urls[i][0] == 0) { break; }
	}
	datum_config.extra_block_submissions_count = i;
	
	if (datum_config.bitcoind_work_update_seconds < 5) {
		datum_config.bitcoind_work_update_seconds = 5;
	}
	if (datum_config.bitcoind_work_update_seconds > 120) {
		datum_config.bitcoind_work_update_seconds = 120;
	}
	
	if (datum_config.stratum_v1_max_threads > MAX_THREADS) {
		DLOG_FATAL("Maximum threads must be less than %d.", MAX_THREADS);
		return 0;
	}
	
	if (datum_config.stratum_v1_max_clients_per_thread > MAX_CLIENTS_THREAD) {
		DLOG_FATAL("Maximum clients per thread must be less than %d.",MAX_CLIENTS_THREAD);
		return 0;
	}
	
	if ((strlen(datum_config.mining_coinbase_tag_primary)+strlen(datum_config.mining_coinbase_tag_secondary)) > 88) {
		DLOG_FATAL("Length of coinbase tags can not exceed 88 bytes total.");
		return 0;
	}
	
	if ((strlen(datum_config.mining_coinbase_tag_primary) > 60) || (strlen(datum_config.mining_coinbase_tag_secondary) > 60)) {
		DLOG_FATAL("Length of coinbase tags can not exceed 88 bytes total or 60 bytes each.");
		return 0;
	}
	
	if (datum_config.stratum_v1_vardiff_target_shares_min < 1) {
		DLOG_FATAL("Stratum server stratum.vardiff_target_shares_min must be at least 1");
		return 0;
	}
	
	if (datum_config.stratum_v1_vardiff_quickdiff_count < 4) {
		DLOG_FATAL("Stratum server stratum.vardiff_quickdiff_count must be at least 4");
		return 0;
	}
	
	if (datum_config.stratum_v1_vardiff_quickdiff_delta < 3) {
		DLOG_FATAL("Stratum server stratum.vardiff_quickdiff_delta must be at least 3");
		return 0;
	}
	
	if (roundDownToPowerOfTwo_64(datum_config.stratum_v1_vardiff_min) != datum_config.stratum_v1_vardiff_min) {
		const int nv = roundDownToPowerOfTwo_64(datum_config.stratum_v1_vardiff_min);
		DLOG_WARN("stratum.stratum_v1_vardiff_min MUST be a power of two. adjusting from %d to %d", datum_config.stratum_v1_vardiff_min, nv);
		datum_config.stratum_v1_vardiff_min = nv;
	}
	
	if (datum_config.stratum_v1_vardiff_min < 1) {
		DLOG_FATAL("Stratum server stratum.stratum_v1_vardiff_min must be at least 1 (suggest at least 1024, but more likely 32768)");
		return 0;
	}
	
	if (datum_config.stratum_v1_max_clients > (datum_config.stratum_v1_max_clients_per_thread*datum_config.stratum_v1_max_threads)) {
		DLOG_FATAL("Stratum server configuration error. Max clients too high for thread settings");
		return 0;
	}
	
	if (datum_config.datum_protocol_global_timeout < (datum_config.bitcoind_work_update_seconds+5)) {
		DLOG_FATAL("DATUM protocol global timeout must be at least the work update interval plus 5 seconds.");
		return 0;
	}
	
	if (datum_config.stratum_v1_share_stale_seconds < 60) {
		DLOG_FATAL("Stratum server stratum.stratum_v1_share_stale_seconds must be at least 60 (suggest 120)");
		return 0;
	}

	if (datum_config.stratum_v1_share_stale_seconds > 150) {
		DLOG_FATAL("Stratum server stratum.stratum_v1_share_stale_seconds must not exceed 150 (suggest 120)");
		return 0;
	}

	// Save some multiplication later
	datum_config.datum_protocol_global_timeout_ms = datum_config.datum_protocol_global_timeout * 1000;
	
	// Just in case
	strcpy(datum_config.override_mining_coinbase_tag_primary, datum_config.mining_coinbase_tag_primary);
	
	return 1;
}

void datum_gateway_help(void) {
	unsigned int i;
	int p;
	char lastcat[512] = { 0 };
	char paddots[64];
	
	strcpy(paddots, "...............................................................");
	
	printf("usage: datum_gateway [OPTION...]\n\n");
	printf("Command line options:\n\n");
	printf("    -c, --config=FILE ..................... Path to configuration JSON file (default: ./datum_gateway_config.json)\n");
	printf("    -?, --help ............................ Print this help\n");
	printf("    --version ............................. Print this software's name and version\n");
	puts("");
	printf("Configuration file options:\n\n   {\n");
	for (i=0;i<NUM_CONFIG_ITEMS;i++) {
		if (strcmp(datum_config_options[i].category, lastcat)) {
			if (i) { printf("     },\n"); }
			printf("     \"%s\":{\n", datum_config_options[i].category);
			strcpy(lastcat, datum_config_options[i].category);
		}
		p = 30 - strlen(datum_config_options[i].name);
		if (p < 0) p = 0;
		if (p > 62) p = 62;
		paddots[p] = 0;
		printf("         \"%s\": %s %s (%s", datum_config_options[i].name, paddots, datum_config_options[i].description, (datum_config_options[i].var_type<DATUM_CONF_TYPES)?datum_conf_var_type_text[datum_config_options[i].var_type]:"UNKNOWN");
		paddots[p] = '.';
		if (datum_config_options[i].required) {
			printf(", REQUIRED)\n");
		} else {
			switch(datum_config_options[i].var_type) {
				case DATUM_CONF_INT: {
					printf(", default: %d)\n",datum_config_options[i].default_int);
					break;
				}
				
				case DATUM_CONF_BOOL: {
					printf(", default: %s)\n",datum_config_options[i].default_bool?"true":"false");
					break;
				}
				
				case DATUM_CONF_STRING: {
					printf(", default: \"%s\")\n",datum_config_options[i].default_string[0]);
					break;
				}
				
				default: {
					printf(")\n");
					break;
				}
			}
		}
	}
	printf("     }\n   }\n\n");
}
