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
#include "datum_utils.h"

void datum_utils_test_strtoi_strict_2d2(void) {
	const char *s, *endptr;
	assert(datum_strtoi_strict_2d2("", 0, NULL) == -1);
	assert(datum_strtoi_strict_2d2("", 0, &endptr) == -1);
	s = "0";
	assert(datum_strtoi_strict_2d2(s, 1, NULL) == 0);
	endptr = NULL;
	assert(datum_strtoi_strict_2d2(s, 1, &endptr) == 0);
	assert(endptr == &s[1]);
	assert(datum_strtoi_strict_2d2(s, 2, NULL) == -1);
	endptr = NULL;
	assert(datum_strtoi_strict_2d2(s, 2, &endptr) == 0);
	assert(endptr == &s[1]);
	s = "0x";
	assert(datum_strtoi_strict_2d2(s, 2, NULL) == -1);
	endptr = NULL;
	assert(datum_strtoi_strict_2d2(s, 2, &endptr) == 0);
	assert(endptr == &s[1]);
	assert(datum_strtoi_strict_2d2(s, 1, NULL) == 0);
	endptr = NULL;
	assert(datum_strtoi_strict_2d2(s, 1, &endptr) == 0);
	assert(endptr == &s[1]);
	s = "0.1";
	assert(datum_strtoi_strict_2d2(s, 1, NULL) == 0);
	endptr = NULL;
	assert(datum_strtoi_strict_2d2(s, 1, &endptr) == 0);
	assert(endptr == &s[1]);
	assert(datum_strtoi_strict_2d2(s, 2, NULL) == 0);
	assert(datum_strtoi_strict_2d2(s, 2, &endptr) == 0);
	assert(endptr == &s[2]);
	assert(datum_strtoi_strict_2d2(s, 3, NULL) == 10);
	assert(datum_strtoi_strict_2d2(s, 3, &endptr) == 10);
	assert(endptr == &s[3]);
	assert(datum_strtoi_strict_2d2(s, 4, NULL) == -1);
	endptr = NULL;
	assert(datum_strtoi_strict_2d2(s, 4, &endptr) == 10);
	assert(endptr == &s[3]);
	s = "0.02";
	assert(datum_strtoi_strict_2d2(s, 3, NULL) == 0);
	endptr = NULL;
	assert(datum_strtoi_strict_2d2(s, 3, &endptr) == 0);
	assert(endptr == &s[3]);
	assert(datum_strtoi_strict_2d2(s, 4, NULL) == 2);
	assert(datum_strtoi_strict_2d2(s, 4, &endptr) == 2);
	assert(endptr == &s[4]);
	assert(datum_strtoi_strict_2d2(s, 5, NULL) == -1);
	endptr = NULL;
	assert(datum_strtoi_strict_2d2(s, 5, &endptr) == 2);
	assert(endptr == &s[4]);
	s = ".02";
	assert(datum_strtoi_strict_2d2(s, 2, NULL) == 0);
	assert(datum_strtoi_strict_2d2(s, 2, &endptr) == 0);
	assert(endptr == &s[2]);
	assert(datum_strtoi_strict_2d2(s, 3, NULL) == 2);
	assert(datum_strtoi_strict_2d2(s, 3, &endptr) == 2);
	assert(endptr == &s[3]);
	assert(datum_strtoi_strict_2d2(s, 4, NULL) == -1);
	endptr = NULL;
	assert(datum_strtoi_strict_2d2(s, 4, &endptr) == 2);
	assert(endptr == &s[3]);
	s = "12.34";
	assert(datum_strtoi_strict_2d2(s, 0, NULL) == -1);
	assert(datum_strtoi_strict_2d2(s, 1, NULL) == 100);
	assert(datum_strtoi_strict_2d2(s, 1, &endptr) == 100);
	assert(endptr == &s[1]);
	assert(datum_strtoi_strict_2d2(s, 2, NULL) == 1200);
	assert(datum_strtoi_strict_2d2(s, 2, &endptr) == 1200);
	assert(endptr == &s[2]);
	assert(datum_strtoi_strict_2d2(s, 3, NULL) == 1200);
	assert(datum_strtoi_strict_2d2(s, 3, &endptr) == 1200);
	assert(endptr == &s[3]);
	assert(datum_strtoi_strict_2d2(s, 4, NULL) == 1230);
	assert(datum_strtoi_strict_2d2(s, 4, &endptr) == 1230);
	assert(endptr == &s[4]);
	assert(datum_strtoi_strict_2d2(s, 5, NULL) == 1234);
	assert(datum_strtoi_strict_2d2(s, 5, &endptr) == 1234);
	assert(endptr == &s[5]);
	assert(datum_strtoi_strict_2d2(s, 6, NULL) == -1);
	endptr = NULL;
	assert(datum_strtoi_strict_2d2(s, 6, &endptr) == 1234);
	assert(endptr == &s[5]);
	s = "2.345";
	assert(datum_strtoi_strict_2d2(s, 5, NULL) == -1);
	assert(datum_strtoi_strict_2d2(s, 5, &endptr) == -1);
	s = "2.34.5";
	assert(datum_strtoi_strict_2d2(s, 6, NULL) == -1);
	assert(datum_strtoi_strict_2d2(s, 6, &endptr) == 234);
	assert(endptr == &s[4]);
}

void datum_utils_tests(void) {
	datum_utils_test_strtoi_strict_2d2();
}
