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
 * Copyright (c) 2026 Bitcoin Ocean, LLC & Léo Haf
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

#include <microhttpd.h>

#ifndef _DATUM_JSON_API_H_
#define _DATUM_JSON_API_H_

int datum_api_json_decentralized_client_stats(struct MHD_Connection * const connection);
int datum_api_json_stratum_server_info(struct MHD_Connection * const connection);
int datum_api_json_current_stratum_job(struct MHD_Connection * const connection);
int datum_api_json_coinbaser(struct MHD_Connection * const connection);
int datum_api_json_thread_stats(struct MHD_Connection * const connection);
int datum_api_json_stratum_client_list(struct MHD_Connection * const connection);
int datum_api_json_configuration(struct MHD_Connection * const connection);
int datum_api_json_set_configuration(struct MHD_Connection * const connection, char *post, int len);

#ifdef DATUM_API_FOR_UMBREL
int datum_api_umbrel_widget(struct MHD_Connection * const connection);
#endif

#endif