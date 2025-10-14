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
#include <string.h>

#include "datum_utils.h"

void datum_utils_tests(void) {
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
