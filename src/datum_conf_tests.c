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
 * Copyright (c) 2024 Bitcoin Ocean, LLC & Luke Dashjr
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
#include "datum_conf.h"
#include "datum_utils.h"

void datum_conf_test_expected_n_global_nonstale_shares(void) {
	global_config_t cfg = {
		.stratum_v1_max_clients_per_thread = 1,
		.stratum_v1_vardiff_target_shares_min = 1,
		.stratum_v1_share_stale_seconds = 60,
	};
	datum_test(datum_expected_n_global_nonstale_shares(&cfg) == 16);
	
	cfg.stratum_v1_max_clients_per_thread = 128;
	cfg.stratum_v1_vardiff_target_shares_min = 8;
	cfg.stratum_v1_share_stale_seconds = 120;
	datum_test(datum_expected_n_global_nonstale_shares(&cfg) == 32768);
	
	cfg.stratum_v1_max_clients_per_thread = 4096;
	cfg.stratum_v1_vardiff_target_shares_min = 8096;
	cfg.stratum_v1_share_stale_seconds = 150;
	datum_test(datum_expected_n_global_nonstale_shares(&cfg) == 1326448640UL);
}

void datum_conf_tests(void) {
	datum_conf_test_expected_n_global_nonstale_shares();
}
