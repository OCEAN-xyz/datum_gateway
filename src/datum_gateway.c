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
#include <getopt.h>
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

void datum_print_banner(void) {
	printf("\n **************************************************************************\n");
	printf(" * DATUM Gateway --- Copyright (c) 2024 Bitcoin Ocean, LLC & Jason Hughes *\n");
	printf(" * git commit: %-58s *\n", GIT_COMMIT_HASH);
	printf(" **************************************************************************\n\n");
	fflush(stdout);
}

void print_help(const char *prog_name) {
	datum_print_banner();
	printf("Usage: %s [OPTIONS]\n", prog_name);
	printf("Options:\n");
	printf("  -c, --config FILE      Use specified configuration file (default: datum_gateway_config.json)\n");
	printf("      --example-conf     Print an example configuration JSON file\n");
	printf("  -h, --help             Show this help message\n");
}

void handle_sigusr1(int sig) {
	datum_blocktemplates_notifynew(NULL, 0);
}

const char * const *datum_argv;

int main(int argc, char *argv[]) {

	datum_argv = (const char * const * const)argv;
	
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

	if (strcmp(argv[1], "--version") == 0) {
		printf("datum_gateway %s\n", DATUM_PROTOCOL_VERSION);
		return 0;
	}

	char *config_file = "datum_gateway_config.json";  // Default config file

	static struct option long_options[] = {
		{"config", required_argument, 0, 'c'},
		{"example-conf", no_argument, 0, 1000},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}
	};

	int opt;
	int option_index = 0;
	while ((opt = getopt_long(argc, argv, "c:h", long_options, &option_index)) != -1) {
		switch (opt) {
		case 'c':
			config_file = optarg;
			break;
		case 'h':
			DLOG_FATAL("Error parsing arguments. Check --help");
			print_help(argv[0]);
			exit(0);
			break;
		case 1000:
			datum_gateway_example_conf();
			exit(0);
			break;
		default:
			DLOG_FATAL("Error parsing arguments. Check --help");
			print_help(argv[0]);
			exit(1);
		}
	}

	datum_print_banner();
	
	if (datum_read_config(config_file) != 1) {
		DLOG_FATAL("Error reading config file. Check --help");
		exit(1);
	}
	datum_gateway_config_filename = config_file;
	
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
