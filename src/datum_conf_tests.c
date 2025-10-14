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
 * Copyright (c) 2025 Bitcoin Ocean, LLC & Luke Dashjr
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
#include "datum_jsonrpc.h"
#include "datum_utils.h"

struct datum_test_username_mods_range {
	const char *addr;
	uint16_t max;
};

struct datum_test_username_mods {
	const char *modname;
	struct datum_test_username_mods_range *ranges;
};

void datum_conf_test_parse_username_mods__(const unsigned int code_line, json_t * const j_input, const char * const input, const int expected_ret, const struct datum_test_username_mods *expected_umods) {
	struct datum_username_mod *umods = NULL;
	int ret = datum_config_parse_username_mods(&umods, j_input, false);
	json_decref(j_input);
	datum_test_(ret == expected_ret, input, code_line, "return value");
	if (ret != 1) {
		assert(!umods);
		assert(!expected_umods);
		return;
	}
	
	datum_test_(!datum_username_mods_find(umods, "MISSING", 7), input, code_line, "modname search: non-existent");
	
	struct datum_username_mod *umod = umods;
	while (expected_umods && expected_umods->modname) {
		if (!datum_test_(umod, input, code_line, "premature end of result umods")) {
			break;
		}
		
		if (datum_test_(strlen(expected_umods->modname) == umod->modname_len, input, code_line, "modname length")) {
			datum_test_(strncmp(expected_umods->modname, umod->modname, umod->modname_len) == 0, input, code_line, "modname content");
		}
		datum_test_(datum_username_mods_find(umods, expected_umods->modname, umod->modname_len) == umod, input, code_line, "modname search");
		struct datum_addr_range *range = umod->ranges;
		assert(range);
		char *last_p = &umod->modname[umod->modname_len];
		for (struct datum_test_username_mods_range *expected_range = expected_umods->ranges; expected_range->addr; ++expected_range) {
			if (!datum_test_(range->addr, input, code_line, "premature end of range list")) {
				break;
			}
			datum_test_(expected_range->max == range->max, input, code_line, "range max");
			if (datum_test_(strlen(expected_range->addr) == range->addr_len, input, code_line, "range addr length")) {
				datum_test_(strncmp(expected_range->addr, range->addr, range->addr_len) == 0, input, code_line, "range addr content");
				datum_test_(range->addr[range->addr_len] == '\0', input, code_line, "range addr trailing null");
				datum_test_(range->addr == last_p, input, code_line, "expected range addr location");
				last_p = &range->addr[range->addr_len + 1];
			}
			++range;
		}
		datum_test_(!range->addr, input, code_line, "extra range");
		datum_test_(umod->sz == datum_align_sz((uint8_t*)last_p - (uint8_t*)umod, _Alignof(struct datum_username_mod)), input, code_line, "umod sz mismatch");
		
		umod = datum_username_mods_next(umod);
		++expected_umods;
	}
	datum_test_(!umod, input, code_line, "extra result umods");
	free(umods);
}

void datum_conf_test_parse_username_mods_(const unsigned int code_line, const char * const input, const int expected_ret, const struct datum_test_username_mods *expected_umods) {
	json_error_t err;
	json_t * const j_input = JSON_LOADS(input, &err);
	assert(j_input);
	datum_conf_test_parse_username_mods__(code_line, j_input, input, expected_ret, expected_umods);
}

#define datum_conf_test_parse_username_mods(...)  datum_conf_test_parse_username_mods_(__LINE__, __VA_ARGS__)

#define MODS (struct datum_test_username_mods[])
#define RANGES (struct datum_test_username_mods_range[])
#define NO_RANGES_AT_ALL RANGES{{NULL}}

void datum_conf_username_mods_tests() {
	datum_conf_test_parse_username_mods__(__LINE__, json_null(), "null", 1, NULL);
	datum_conf_test_parse_username_mods("{}", 1, NULL);
	datum_conf_test_parse_username_mods("[]", -1, NULL);
	datum_conf_test_parse_username_mods("{\"y\":[]}", -1, NULL);
	datum_conf_test_parse_username_mods("{\"y\":42}", -1, NULL);
	datum_conf_test_parse_username_mods("{\"y\":\"z\"}", -1, NULL);
	datum_conf_test_parse_username_mods("{\"y\":true}", -1, NULL);
	datum_conf_test_parse_username_mods("{\"y\":false}", -1, NULL);
	datum_conf_test_parse_username_mods("{\"z\":{\"a\":[]}}", -1, NULL);
	datum_conf_test_parse_username_mods("{\"z\":{\"a\":{}}}", -1, NULL);
	datum_conf_test_parse_username_mods("{\"z\":{\"a\":\"z\"}}", -1, NULL);
	datum_conf_test_parse_username_mods("{\"z\":{\"a\":true}}", -1, NULL);
	datum_conf_test_parse_username_mods("{\"z\":{\"a\":false}}", -1, NULL);
	
	datum_conf_test_parse_username_mods("{\"x\":null}", 1, MODS{
		{NULL}
	});
	datum_conf_test_parse_username_mods("{\"x\":{}}", 1, MODS{
		{"x", NO_RANGES_AT_ALL},
		{NULL}
	});
	datum_conf_test_parse_username_mods("{\"x\":{\"addr\": 0}}", 1, MODS{
		{"x", NO_RANGES_AT_ALL},
		{NULL},
	});
	datum_conf_test_parse_username_mods("{\"x\":{\"addr\": 0.00001}}", 1, MODS{
		{"x", RANGES{{"addr", 0}, {NULL}}},
		{NULL},
	});
	datum_conf_test_parse_username_mods("{\"x\":{\"addr\": 1}}", 1, MODS{
		{"x", RANGES{{"addr", 0xffff}, {NULL}}},
		{NULL}
	});
	datum_conf_test_parse_username_mods("{\"x\":{\"addr\": -1}}", -1, NULL);
	datum_conf_test_parse_username_mods("{\"x\":{\"addr\": 2.3}}", 1, MODS{
		{"x", RANGES{{"addr", 0xffff}, {NULL}}},
		{NULL}
	});
	datum_conf_test_parse_username_mods("{\"x\":{\"addrA\": 0.3, \"addrB\":0.7}}", 1, MODS{
		{"x", RANGES{
			{"addrA", 0x4ccc},
			{"addrB", 0xffff},
			{NULL}
		}},
		{NULL}
	});
	datum_conf_test_parse_username_mods("{\"x\":{\"addrA\": 0.3, \"addrB\":0.3,\"addrC\":0.3}}", 1, MODS{
		{"x", RANGES{
			{"addrA", 0x4ccc},
			{"addrB", 0x9999},
			{"addrC", 0xe666},
			{NULL}
		}},
		{NULL}
	});
	datum_conf_test_parse_username_mods("{\"x\":{\"addrA\": 0.3, \"\":0.3,\"addrC\":0.3}}", 1, MODS{
		{"x", RANGES{
			{"addrA", 0x4ccc},
			{"", 0x9999},
			{"addrC", 0xe666},
			{NULL}
		}},
		{NULL}
	});
	datum_conf_test_parse_username_mods("{\"x\":{\"addrA\": 0.3, \"\":null,\"addrC\":0.3}}", 1, MODS{
		{"x", RANGES{
			{"addrA", 0x4ccc},
			{"addrC", 0x9999},
			{NULL}
		}},
		{NULL}
	});
	datum_conf_test_parse_username_mods("{\"x\":{\"addrA\": null, \"\":null,\"addrC\":null}}", 1, MODS{
		{"x", NO_RANGES_AT_ALL},
		{NULL}
	});
	datum_conf_test_parse_username_mods("{\"x\":{\"addrA\": 0.3}, \"abc\":{\"addrB\":0.3,\"addrC\":0.3}}", 1, MODS{
		{"x", RANGES{
			{"addrA", 0x4ccc},
			{NULL}
		}},
		{"abc", RANGES{
			{"addrB", 0x4ccc},
			{"addrC", 0x9999},
			{NULL}
		}},
		{NULL}
	});
}

void datum_conf_tests(void) {
	datum_conf_username_mods_tests();
}
