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

// NOTE: Everything about this software assumes compilation for little endian underlying hardware operations.
// This *will* break on big endian hardware and not perform expected operations correctly.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <jansson.h>
#include <inttypes.h>
#include <curl/curl.h>
#include <argp.h>
#include <signal.h>

#include "datum_gateway.h"
#include "datum_jsonrpc.h"
#include "datum_utils.h"
#include "datum_blocktemplates.h"
#include "datum_stratum.h"
#include "datum_conf.h"
#include "datum_sockets.h"
#include "datum_api.h"
#include "datum_coinbaser.h"
#include "datum_protocol.h"

const char *datum_gateway_config_filename = NULL;

// ARGP stuff
const char *argp_program_version = "datum_gateway " DATUM_PROTOCOL_VERSION;
const char *argp_program_bug_address = "<jason@ocean.xyz>";
static char doc[] = "Decentralized Alternative Templates for Universal Mining - Pool Gateway";
static char args_doc[] = "";
static struct argp_option options[] = {
	{"help", '?', 0, 0, "Show custom help", 0},
	{"example-conf", 0x100, NULL, 0, "Print an example configuration JSON file", 0},
	{"test", 0x101, NULL, 0, "Run tests only", 0},
	{"usage", '?', 0, 0, "Show custom help", 0},
	{"config", 'c', "FILE", 0, "Configuration JSON file"},
	{0}
};

struct arguments {
	char *config_file;
};

void datum_stratum_tests(void);
void datum_conf_tests(void);
void datum_utils_tests(void);

static error_t parse_opt(int key, char *arg, struct argp_state *state) {
	struct arguments *arguments = state->input;
	switch (key) {
		case '?': {
			datum_print_banner();
			datum_gateway_help(state->argv[0]);
			exit(0);
			break;
		}
		case 'c': {
			arguments->config_file = arg;
			break;
		}
		case 0x100:  // example-conf
			datum_gateway_example_conf();
			exit(0);
			break;
		case 0x101:  // test
			datum_utils_tests();
			datum_conf_tests();
			datum_stratum_tests();
			exit(datum_test_failed);
		default:
			return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static struct argp argp = {options, parse_opt, args_doc, doc};
// END ARGP Stuff

void datum_print_banner(void) {
	puts("");
	puts(" *****************************************************************");
	puts(" * DATUM Gateway --- Copyright (c) 2024-2025 Bitcoin Ocean, LLC, *");
	puts(" *                     Jason Hughes, and individual contributors *");
	printf(" * git commit: %-49s *\n", GIT_COMMIT_HASH);
	puts(" *****************************************************************");
	puts("");
	fflush(stdout);
}

void handle_sigusr1(int sig) {
	datum_blocktemplates_notifynew_sighandler();
}

const char * const *datum_argv;

int main(const int argc, const char * const * const argv) {
	datum_argv = argv;
	
	struct arguments arguments;
	pthread_t pthread_datum_stratum_v1;
	pthread_t pthread_datum_gateway_template;
	int i;
	int fail_retries=0;
	struct sigaction sa;
	uint64_t last_datum_protocol_connect_tsms = 0;
	bool rejecting_stratum = false;
	uint32_t next_reconnect_attempt_ms = 5000;
	
	// listen for block notifications
	// set this up early so a notification doesn't break our init
	sa.sa_handler = handle_sigusr1;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	
	if (sigaction(SIGUSR1, &sa, NULL) == -1) {
		datum_print_banner();
		DLOG_FATAL("Could not setup signal handler!");
		perror("sigaction");
		usleep(100000);
		exit(1);
	}
	
	// Ignore SIGPIPE. This is instead handled gracefully by datum_sockets
	signal(SIGPIPE, SIG_IGN);
	
	srand(time(NULL)); // Not used for anything secure, so this is fine.
	
	curl_global_init(CURL_GLOBAL_ALL);
	datum_utils_init();
	
	arguments.config_file = "datum_gateway_config.json";  // Default config file
	if (argp_parse(&argp, argc, datum_deepcopy_charpp(argv), 0, 0, &arguments) != 0) {
		datum_print_banner();
		DLOG_FATAL("Error parsing arguments. Check --help");
		exit(1);
	}
	datum_print_banner();
	
	if (datum_read_config(arguments.config_file) != 1) {
		DLOG_FATAL("Error reading config file. Check --help");
		exit(1);
	}
	datum_gateway_config_filename = arguments.config_file;
	
	// Initialize logger thread
	datum_logger_init();
	
	if (datum_protocol_init()) {
		DLOG_FATAL("Error initializing the DATUM protocol!");
		usleep(100000);
		exit(1);
	}
	last_datum_protocol_connect_tsms = current_time_millis();
	
#ifdef ENABLE_API
	if (datum_api_init()) {
		DLOG_FATAL("Error initializing API interface");
		usleep(100000);
		exit(1);
	}
#endif
	
	if (datum_coinbaser_init()) {
		DLOG_FATAL("Error initializing coinbaser thread");
		usleep(100000);
		exit(1);
	}
	
	// Try to connect to the DATUM server, if setup to do so.
	if (datum_config.datum_pool_host[0] != 0) {
		while((current_time_millis()-15000 < last_datum_protocol_connect_tsms) && (!datum_protocol_is_active())) {
			DLOG_INFO("Waiting on DATUM server... %d", (int)((last_datum_protocol_connect_tsms-(current_time_millis()-15000))/1000));
			sleep(1);
			if ((datum_config.datum_pool_host[0] != 0) && (!datum_protocol_thread_is_active())) {
				datum_protocol_start_connector();
			}
		}
	}
	
	// TODO: Churn and continue to try and connect while leaving the Stratum server down if pooled mining only
	if (datum_config.datum_pooled_mining_only && (!datum_protocol_is_active())) {
		DLOG_ERROR("DATUM server connection could not be established.");
		fflush(stdout);
	}

	// Start background recovery thread for multi-node failover
	if (datum_config.bitcoind_node_count > 1 && datum_config.bitcoind_try_higher_priority) {
		DLOG_INFO("Starting Bitcoin node background recovery thread (cooldown: %d seconds)",
		         datum_config.bitcoind_failover_cooldown_sec);
		bitcoind_recovery_thread_start(&datum_config);
	}

	DLOG_DEBUG("Starting template fetcher thread");
	pthread_create(&pthread_datum_gateway_template, NULL, datum_gateway_template_thread, NULL);
	
	// Note: The stratum thread will wait for a template to be available for some time before panicking.
	DLOG_DEBUG("Starting Stratum v1 server");
	pthread_create(&pthread_datum_stratum_v1, NULL, datum_stratum_v1_socket_server, NULL);
	
	// Randomize the reconnect delay from 5 to 20 seconds to prevent hammering the server
	next_reconnect_attempt_ms = ( 5000 + (rand() % 15001) );

	i=0;
	while(1) {
		if (panic_mode) {
			DLOG_FATAL("*** PANIC TRIGGERED: EXITING IMMEDIATELY ***");
			printf("PANIC EXIT.\n");
			bitcoind_recovery_thread_stop();  // Clean shutdown of recovery thread
			sleep(1); // almost immediately, wait a second for the logger!
			fflush(stdout);
			usleep(2000);
			exit(1);
		}
		usleep(500000);
		i++;
		if (i>=600) { // Roughly every 5 minutes spit out some stats to the log
			i = datum_stratum_v1_global_subscriber_count();
			DLOG_INFO("Server stats: %d client%s / %.2f Th/s", i, (i!=1)?"s":"", datum_stratum_v1_est_total_th_sec());
			i=0;
		}
		
		if (fail_retries > 0) {
			if (datum_protocol_is_active()) {
				fail_retries = 0;
			}
		}
		
		if (datum_config.datum_pooled_mining_only && (fail_retries >= 2) && (!datum_protocol_is_active())) {
			if (!rejecting_stratum) {
				DLOG_WARN("Configured for pooled mining only, and connection lost to DATUM server!  Shutting down Stratum v1 server until DATUM connection reestablished.");
				rejecting_stratum = true;
				datum_stratum_v1_shutdown_all();
			}
		} else {
			rejecting_stratum = false;
		}
		
		if ((datum_config.datum_pool_host[0] != 0) && (!datum_protocol_thread_is_active())) {
			// DATUM thread is dead, and it shouldn't be.
			if (last_datum_protocol_connect_tsms < (current_time_millis()-next_reconnect_attempt_ms)) {
				datum_protocol_start_connector();
				last_datum_protocol_connect_tsms = current_time_millis();
				fail_retries++;
				// Randomize the reconnect delay from 5 to 20 seconds to prevent hammering the server
				next_reconnect_attempt_ms = ( 5000 + (rand() % 15001) );
			}
		}
	}
	
	return 0;
}
