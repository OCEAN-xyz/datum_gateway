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

void datum_utils_tests(void) {
	datum_utils_tests_hex();
	datum_utils_tests_secure_strequals();
}
