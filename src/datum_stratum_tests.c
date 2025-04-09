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
#include <string.h>

#include "datum_conf.h"
#include "datum_stratum.h"

void datum_stratum_relevant_username_tests() {
	char buf[0x100];
	char * const pool_addr = datum_config.mining_pool_address;
	char *s;
	
	strcpy(pool_addr, "dummy");
	s = "abc";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == s);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == s);
	s = "";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == s);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == s);
	s = "abc%def";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == s);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == s);
	s = "abc%0%def";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == &s[6]);
	s = "abc%0%def%ghi";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == &s[6]);
	s = "abc%0%def%0%ghi";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == &s[12]);
	s = "abc%0%def%1%ghi";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "def"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x28e) == buf);
	assert(!strcmp(buf, "def"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x28f) == &s[12]);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == &s[12]);
	s = "abc%1%def%1%ghi";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x28e) == buf);
	assert(!strcmp(buf, "abc"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x28f) == buf);
	assert(!strcmp(buf, "def"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x51d) == buf);
	assert(!strcmp(buf, "def"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x51e) == &s[12]);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == &s[12]);
	s = "abc%1%def%1%ghi%1";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x28e) == buf);
	assert(!strcmp(buf, "abc"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x28f) == buf);
	assert(!strcmp(buf, "def"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x51d) == buf);
	assert(!strcmp(buf, "def"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x51e) == buf);
	assert(!strcmp(buf, "ghi"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x7ac) == buf);
	assert(!strcmp(buf, "ghi"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x7ad) == pool_addr);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == pool_addr);
	s = "abc%.01%def";
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 5) == buf);
	assert(!strcmp(buf, "abc"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 6) == &s[8]);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == &s[8]);
	s = "abc%55.%def";
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x8ccb) == buf);
	assert(!strcmp(buf, "abc"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x8ccc) == &s[8]);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == &s[8]);
	s = "abc%55.55%def";
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x8e34) == buf);
	assert(!strcmp(buf, "abc"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0x8e35) == &s[10]);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == &s[10]);
	s = "abc%99.99%def";
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xfff8) == buf);
	assert(!strcmp(buf, "abc"));
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xfff9) == &s[10]);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == &s[10]);
	s = "abc%100%def";
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0) == buf);
	assert(!strcmp(buf, "abc"));
	memset(buf, 5, 5);
	assert(datum_stratum_relevant_username(s, buf, sizeof(buf), 0xffff) == buf);
	assert(!strcmp(buf, "abc"));
}

void datum_stratum_tests(void) {
	datum_stratum_relevant_username_tests();
}
