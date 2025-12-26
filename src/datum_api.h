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

#ifndef _DATUM_API_H_
#define _DATUM_API_H_

#include "datum_stratum.h"

#define DATUM_API_CONNECTION_LIMIT 128

typedef struct {
	int STRATUM_ACTIVE_THREADS;
	int STRATUM_TOTAL_CONNECTIONS;
	int STRATUM_TOTAL_SUBSCRIPTIONS;
	double STRATUM_HASHRATE_ESTIMATE;
	
	T_DATUM_STRATUM_JOB *sjob;
} T_DATUM_API_DASH_VARS;

typedef void (*DATUM_API_VarFunc)(char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata);
typedef size_t (*DATUM_API_VarFillFunc)(const char *var_start, size_t var_name_len, char *buffer, size_t buffer_size, const T_DATUM_API_DASH_VARS *vardata);

typedef struct {
	const char *var_name;
	DATUM_API_VarFunc func;
} DATUM_API_VarEntry;


int datum_api_init(void);
size_t strncpy_html_escape(char *dest, const char *src, size_t n);

#endif
