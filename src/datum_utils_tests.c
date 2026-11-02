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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include "datum_utils.h"

void datum_utils_tests_hex_to_bin(const uint8_t c, char * const x, const char * const fmt) {
	unsigned char b[3];
	datum_test(2 == snprintf(&x[2], 3, fmt, c));
	datum_test(c == hex2bin_uchar(&x[2]));
	memcpy(x, "00", 2);
	b[2] = 0x0e;
	hex_to_bin(x, b);
	datum_test(b[0] == 0);
	datum_test(b[1] == c);
	datum_test(b[2] == 0x0e);
	b[2] = 0x0e;
	hex_to_bin_le(x, b);
	datum_test(b[0] == c);
	datum_test(b[1] == 0);
	datum_test(b[2] == 0x0e);
}

void datum_utils_tests_hex(void) {
	char x[6], x2[6];
	strcpy(&x[2], "00");
	for (unsigned int c = 0; ; ++c) {
		datum_utils_tests_hex_to_bin(c, &x2[1], "%2.2X");
		datum_test(strcasecmp(&x[2], &x2[3]) == 0);
		datum_utils_tests_hex_to_bin(c, x2, "%2.2X");
		datum_utils_tests_hex_to_bin(c, &x[1], "%2.2x");
		datum_test(strcasecmp(&x[3], &x2[2]) == 0);
		datum_utils_tests_hex_to_bin(c, x, "%2.2x");
		datum_test(strcasecmp(&x[2], &x2[2]) == 0);
		
		x2[2] = 0x0e;
		uchar_to_hex(x2, c);
		datum_test(memcmp(&x[2], x2, 2) == 0);
		datum_test(x2[2] == 0x0e);
		x2[3] = 0x0e;
		uchar_to_hex(&x2[1], c);
		datum_test(memcmp(&x[2], &x2[1], 2) == 0);
		datum_test(x2[3] == 0x0e);
		
		if (c == 255) break;
		
		if (x[3] == 'f') {
			x[3] = '0';
			if (x[2] == '9') {
				x[2] = 'a';
			} else {
				++x[2];
			}
		} else if (x[3] == '9') {
			x[3] = 'a';
		} else {
			++x[3];
		}
	}
}

void datum_utils_tests_secure_strequals(void) {
	const char * const secret = "abc";
	const size_t secret_len = strlen(secret);
	
	/* equal strings */
	datum_test(datum_secure_strequals(secret, secret_len, "abc"));
	
	/* guess longer than secret */
	datum_test(!datum_secure_strequals(secret, secret_len, "abcd"));
	
	/* guess shorter than secret */
	datum_test(!datum_secure_strequals(secret, secret_len, "ab"));
	
	/* guess repeats secret but is longer */
	datum_test(!datum_secure_strequals(secret, secret_len, "abcabc"));
	
	/* zero-length secret matches only on empty guess, and doesn't dereference NULL */
	datum_test(!datum_secure_strequals(NULL, 0, "anything"));
	datum_test(datum_secure_strequals(NULL, 0, ""));
}

void datum_utils_tests_nbits_to_target_(const uint32_t nbits, const bool expect_ok, const uint8_t * const expected, const unsigned int line) {
	static const uint8_t zero[32] = { 0 };
	uint8_t target[32];
	
	memset(target, 0xaa, sizeof(target));
	datum_test_(nbits_to_target(nbits, target) == expect_ok, "nbits_to_target(nbits, target) == expect_ok", line, __func__);
	datum_test_(memcmp(target, expect_ok ? expected : zero, sizeof(target)) == 0, "memcmp(target, expected, 32) == 0", line, __func__);
}
#define nbits_ok(nbits, ...)  datum_utils_tests_nbits_to_target_(nbits, true, (const uint8_t[32]){ __VA_ARGS__ }, __LINE__)
#define nbits_bad(nbits)  datum_utils_tests_nbits_to_target_(nbits, false, NULL, __LINE__)

void datum_utils_tests_nbits_to_target(void) {
	// Target bytes are little-endian.
	
	/* zero mantissa */
	nbits_bad(0x00000000);
	nbits_bad(0x03000000);
	nbits_bad(0x1d000000);
	nbits_bad(0x20000000);
	
	/* negative (sign bit set) */
	nbits_bad(0x03800000);
	nbits_bad(0x04800000);
	nbits_bad(0x1d800001);
	nbits_bad(0x1dffffff);
	nbits_bad(0x20800000);
	
	/* small exponents: shift truncates the value to zero */
	nbits_bad(0x007fffff);
	nbits_bad(0x0100ffff);
	nbits_bad(0x01000001);
	nbits_bad(0x020000ff);
	nbits_bad(0x02000001);
	
	/* small exponents: shift leaves a nonzero value */
	nbits_ok(0x01010000, [0] = 0x01);
	nbits_ok(0x01123456, [0] = 0x12);
	nbits_ok(0x02000100, [0] = 0x01);
	nbits_ok(0x02008000, [0] = 0x80);
	nbits_ok(0x02123456, [0] = 0x34, [1] = 0x12);
	nbits_ok(0x03000001, [0] = 0x01);
	nbits_ok(0x03123456, [0] = 0x56, [1] = 0x34, [2] = 0x12);
	nbits_ok(0x04123456, [1] = 0x56, [2] = 0x34, [3] = 0x12);
	
	/* typical value (genesis block) */
	nbits_ok(0x1d00ffff, [26] = 0xff, [27] = 0xff);
	
	/* exponent 32: any non-negative mantissa fits */
	nbits_ok(0x20000001, [29] = 0x01);
	nbits_ok(0x20010000, [31] = 0x01);
	nbits_ok(0x207fffff, [29] = 0xff, [30] = 0xff, [31] = 0x7f);
	
	/* exponent 33: mantissa must fit in 2 bytes */
	nbits_ok(0x21000001, [30] = 0x01);
	nbits_ok(0x2100ffff, [30] = 0xff, [31] = 0xff);
	nbits_bad(0x21010000);
	nbits_bad(0x217fffff);
	
	/* exponent 34: mantissa must fit in 1 byte */
	nbits_ok(0x22000001, [31] = 0x01);
	nbits_ok(0x220000ff, [31] = 0xff);
	nbits_bad(0x22000100);
	nbits_bad(0x22010000);
	
	/* exponent 35 and above: always overflows */
	nbits_bad(0x23000001);
	nbits_bad(0x230000ff);
	nbits_bad(0xff000001);
}

#undef nbits_ok
#undef nbits_bad

void datum_utils_tests_output_script_addr(void) {
	// Issue #232: a tb1 payout was re-encoded as a different bc1 address.
	static const char tb1[] = "tb1qts77l4e4phqlljs9nn29dmy3tk2h3ysvh2wdej";
	static const char bc1_same[] = "bc1qts77l4e4phqlljs9nn29dmy3tk2h3ysvav47zp";
	static const char bc1_bip173[] = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
	static const char genesis[] = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
	unsigned char script[64];
	unsigned char other[64];
	char addr[256];
	char encoded_tb[256];
	char encoded_bc[256];
	int n, n_other;
	
	n = addr_2_output_script(tb1, script, (int)sizeof(script));
	datum_test(n == 22);
	
	datum_test(output_script_2_addr(script, n, addr, "bc") > 0);
	datum_test(strcmp(addr, bc1_same) == 0);
	datum_test(strcmp(addr, tb1) != 0);
	
	datum_test(output_script_2_addr(script, n, addr, "tb") > 0);
	datum_test(strcmp(addr, tb1) == 0);
	
	datum_test(output_script_2_display_addr(script, n, addr, sizeof(addr), tb1) > 0);
	datum_test(strcmp(addr, tb1) == 0);
	
	n_other = addr_2_output_script(bc1_bip173, other, (int)sizeof(other));
	datum_test(n_other == 22);
	datum_test(output_script_2_addr(other, n_other, addr, NULL) > 0);
	datum_test(strcmp(addr, bc1_bip173) == 0);
	
	// A different output on a testnet gateway must stay tb1, not the configured address and not bc1.
	datum_test(output_script_2_addr(other, n_other, encoded_tb, "tb") > 0);
	datum_test(output_script_2_addr(other, n_other, encoded_bc, "bc") > 0);
	datum_test(strcmp(encoded_tb, encoded_bc) != 0);
	datum_test(output_script_2_display_addr(other, n_other, addr, sizeof(addr), tb1) > 0);
	datum_test(strcmp(addr, encoded_tb) == 0);
	datum_test(strcmp(addr, tb1) != 0);
	datum_test(strncmp(addr, "tb1", 3) == 0);
	
	datum_test(output_script_2_display_addr(other, n_other, addr, sizeof(addr), bc1_bip173) > 0);
	datum_test(strcmp(addr, bc1_bip173) == 0);
	
	// Legacy scripts have no network byte. Version follows the payout HRP.
	n = addr_2_output_script(genesis, script, (int)sizeof(script));
	datum_test(n == 25);
	datum_test(output_script_2_addr(script, n, addr, NULL) > 0);
	datum_test(strcmp(addr, genesis) == 0);
	datum_test(output_script_2_addr(script, n, addr, "tb") > 0);
	datum_test(strcmp(addr, genesis) != 0);
	datum_test(addr[0] == 'm' || addr[0] == 'n');
	datum_test(output_script_2_display_addr(script, n, addr, sizeof(addr), tb1) > 0);
	datum_test(addr[0] == 'm' || addr[0] == 'n');
}

void datum_utils_tests(void) {
	datum_utils_tests_hex();
	datum_utils_tests_secure_strequals();
	datum_utils_tests_nbits_to_target();
	datum_utils_tests_output_script_addr();
}
