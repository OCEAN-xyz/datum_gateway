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

#include <stddef.h>
#include <string.h>

#include "datum_conf.h"
#include "datum_protocol.h"
#include "datum_utils.h"

int datum_protocol_submit_username(char * const username, const size_t username_sz, const global_config_t * const cfg, const char * const input_username);

void datum_protocol_submit_username_tests() {
	const char addr[] = "1someaddress";
	const size_t addr_len = sizeof(addr) - 1;
	const char addr_2[] = "2anotheraddress";
	const size_t addr_2_len = sizeof(addr_2) - 1;
	const char addr_2w[] = "2anotheraddress.worker";
	const size_t addr_2w_len = sizeof(addr_2w) - 1;
	const char noaddr_w[] = ".Worker";
	const size_t noaddr_w_len = sizeof(noaddr_w) - 1;
	global_config_t cfg = {
		.datum_pool_pass_full_users = true,
		.datum_pool_pass_workers = true,
	};
	strcpy(cfg.mining_pool_address, addr);
	char buf[386];
	
	// "passthrough" tests:
	datum_test(datum_protocol_submit_username(buf, sizeof(buf), &cfg, "") == addr_len);
	datum_test(0 == strcmp(buf, addr));
	datum_test(datum_protocol_submit_username(buf, sizeof(buf), &cfg, addr_2) == addr_2_len);
	datum_test(0 == strcmp(buf, addr_2));
	datum_test(datum_protocol_submit_username(buf, sizeof(buf), &cfg, addr_2w) == addr_2w_len);
	datum_test(0 == strcmp(buf, addr_2w));
	datum_test(datum_protocol_submit_username(buf, sizeof(buf), &cfg, noaddr_w) == addr_len + noaddr_w_len);
	datum_test(0 == memcmp(buf, addr, addr_len));
	datum_test(0 == strcmp(&buf[addr_len], noaddr_w));
	
	// "worker" tests:
	cfg.datum_pool_pass_full_users = false;
	datum_test(datum_protocol_submit_username(buf, sizeof(buf), &cfg, "") == addr_len);
	datum_test(0 == strcmp(buf, addr));
	datum_test(datum_protocol_submit_username(buf, sizeof(buf), &cfg, addr_2) == addr_len + 1 + addr_2_len);
	datum_test(0 == memcmp(buf, addr, addr_len));
	datum_test('.' == buf[addr_len]);
	datum_test(0 == strcmp(&buf[addr_len + 1], addr_2));
	datum_test(datum_protocol_submit_username(buf, sizeof(buf), &cfg, addr_2w) == addr_len + 1 + addr_2w_len);
	datum_test(0 == memcmp(buf, addr, addr_len));
	datum_test('.' == buf[addr_len]);
	datum_test(0 == strcmp(&buf[addr_len + 1], addr_2w));
	datum_test(datum_protocol_submit_username(buf, sizeof(buf), &cfg, noaddr_w) == addr_len + noaddr_w_len);
	datum_test(0 == memcmp(buf, addr, addr_len));
	datum_test(0 == strcmp(&buf[addr_len], noaddr_w));
	
	// "ignore" tests:
	cfg.datum_pool_pass_workers = false;
	datum_test(datum_protocol_submit_username(buf, sizeof(buf), &cfg, "") == addr_len);
	datum_test(0 == strcmp(buf, addr));
	datum_test(datum_protocol_submit_username(buf, sizeof(buf), &cfg, addr_2) == addr_len);
	datum_test(0 == strcmp(buf, addr));
	datum_test(datum_protocol_submit_username(buf, sizeof(buf), &cfg, addr_2w) == addr_len);
	datum_test(0 == strcmp(buf, addr));
	datum_test(datum_protocol_submit_username(buf, sizeof(buf), &cfg, noaddr_w) == addr_len);
	datum_test(0 == strcmp(buf, addr));
}

void datum_protocol_tests(void) {
	datum_protocol_submit_username_tests();
}
