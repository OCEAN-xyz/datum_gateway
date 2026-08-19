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
 * Copyright (c) 2026 Bitcoin Ocean, LLC and individual contributors
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

#include <jansson.h>
#include <stdint.h>
#include <string.h>

#include "datum_blocktemplates.h"
#include "datum_conf.h"
#include "datum_jsonrpc.h"
#include "datum_stratum.h"
#include "datum_coinbaser.h"
#include "datum_utils.h"

static json_t *coinbaseaux_fixture(const char *json) {
	json_error_t error;
	json_t *root = JSON_LOADS(json, &error);
	datum_test(root != NULL);
	return root;
}

static size_t generated_input(const T_DATUM_TEMPLATE_DATA *template, unsigned char *out, int *target_pot_index) {
	T_DATUM_STRATUM_JOB job = {
		.block_template = (T_DATUM_TEMPLATE_DATA *)template,
		.height = template->height,
	};
	char hex[MAX_COINBASE_SCRIPTSIG_SIZE * 2 + 1];
	const int len = generate_coinbase_input(&job, hex, target_pot_index);
	datum_test(len >= 0);
	if (len < 0) return 0;
	for (int i = 0; i < len; ++i) out[i] = hex2bin_uchar(&hex[i << 1]);
	return len;
}

static size_t count_bytes(const unsigned char *haystack, const size_t haystack_len, const unsigned char *needle, const size_t needle_len) {
	size_t count = 0;
	if (!needle_len || needle_len > haystack_len) return 0;
	for (size_t i = 0; i <= haystack_len - needle_len; ++i) {
		if (!memcmp(&haystack[i], needle, needle_len)) ++count;
	}
	return count;
}

static void datum_blocktemplates_coinbaseaux_parse_tests(void) {
	T_DATUM_TEMPLATE_DATA template = { .height = 840000 };
	json_t *root;

	// Missing coinbaseaux retains the legacy empty representation.
	datum_test(datum_gbt_parse_coinbaseaux(&template, NULL));
	datum_test(template.coinbaseaux_len == 0);

	root = coinbaseaux_fixture("{\"coinbaseaux\":{\"flags\":\"deadbeef\"}}");
	datum_test(datum_gbt_parse_coinbaseaux(&template, json_object_get(root, "coinbaseaux")));
	datum_test(template.coinbaseaux_len == 4);
	datum_test(!memcmp(template.coinbaseaux, "\xde\xad\xbe\xef", 4));
	json_decref(root);

	// Jansson exposes object entries in received order; preserve that order.
	root = coinbaseaux_fixture("{\"coinbaseaux\":{\"first\":\"a1b2c3d4\",\"second\":\"e5f60718\"}}");
	datum_test(datum_gbt_parse_coinbaseaux(&template, json_object_get(root, "coinbaseaux")));
	datum_test(template.coinbaseaux_len == 8);
	datum_test(!memcmp(template.coinbaseaux, "\xa1\xb2\xc3\xd4\xe5\xf6\x07\x18", 8));
	json_decref(root);

	root = coinbaseaux_fixture("{\"coinbaseaux\":null}");
	datum_test(!datum_gbt_parse_coinbaseaux(&template, json_object_get(root, "coinbaseaux")));
	json_decref(root);

	root = coinbaseaux_fixture("{\"coinbaseaux\":{\"bad\":1}}");
	datum_test(!datum_gbt_parse_coinbaseaux(&template, json_object_get(root, "coinbaseaux")));
	json_decref(root);

	root = coinbaseaux_fixture("{\"coinbaseaux\":{\"bad\":\"0g\"}}");
	datum_test(!datum_gbt_parse_coinbaseaux(&template, json_object_get(root, "coinbaseaux")));
	json_decref(root);

	root = coinbaseaux_fixture("{\"coinbaseaux\":{\"bad\":\"abc\"}}");
	datum_test(!datum_gbt_parse_coinbaseaux(&template, json_object_get(root, "coinbaseaux")));
	json_decref(root);

	// 87 bytes need 2 push bytes; height + aux + DATUM ID would need 101.
	char oversized_hex[87 * 2 + 1];
	memset(oversized_hex, 'a', sizeof(oversized_hex) - 1);
	oversized_hex[sizeof(oversized_hex) - 1] = '\0';
	root = json_object();
	json_object_set_new(root, "oversized", json_string(oversized_hex));
	datum_test(!datum_gbt_parse_coinbaseaux(&template, root));
	json_decref(root);
}

static void datum_blocktemplates_coinbaseaux_generation_tests(void) {
	char saved_primary[sizeof(datum_config.mining_coinbase_tag_primary)];
	char saved_secondary[sizeof(datum_config.mining_coinbase_tag_secondary)];
	const int saved_unique_id = datum_config.coinbase_unique_id;
	const uint32_t saved_prime_id = datum_config.prime_id;
	T_DATUM_TEMPLATE_DATA template = { .height = 840000 };
	unsigned char input[MAX_COINBASE_SCRIPTSIG_SIZE];
	int target_pot_index = -1;
	json_t *root;

	memcpy(saved_primary, datum_config.mining_coinbase_tag_primary, sizeof(saved_primary));
	memcpy(saved_secondary, datum_config.mining_coinbase_tag_secondary, sizeof(saved_secondary));
	strcpy(datum_config.mining_coinbase_tag_primary, "A");
	strcpy(datum_config.mining_coinbase_tag_secondary, "B");
	datum_config.coinbase_unique_id = 0x1234;
	datum_config.prime_id = 0;

	// No coinbaseaux must remain byte-for-byte identical to the legacy layout.
	const unsigned char legacy[] = {
		0x03, 0x40, 0xd1, 0x0c, // BIP34 height 840000
		0x04, 'A', 0x0f, 'B', 0x00,
		0x03, 0xff, 0x34, 0x12,
	};
	size_t input_len = generated_input(&template, input, &target_pot_index);
	datum_test(input_len == sizeof(legacy));
	datum_test(!memcmp(input, legacy, sizeof(legacy)));

	root = coinbaseaux_fixture("{\"flags\":\"deadbeef\"}");
	datum_test(datum_gbt_parse_coinbaseaux(&template, root));
	json_decref(root);
	input_len = generated_input(&template, input, &target_pot_index);
	datum_test(input_len <= MAX_COINBASE_SCRIPTSIG_SIZE);
	datum_test(input[4] == 4);
	datum_test(!memcmp(&input[5], "\xde\xad\xbe\xef", 4));

	root = coinbaseaux_fixture("{\"first\":\"a1b2c3d4\",\"second\":\"e5f60718\"}");
	datum_test(datum_gbt_parse_coinbaseaux(&template, root));
	json_decref(root);
	input_len = generated_input(&template, input, &target_pot_index);
	const unsigned char first[] = { 0xa1, 0xb2, 0xc3, 0xd4 };
	const unsigned char second[] = { 0xe5, 0xf6, 0x07, 0x18 };
	datum_test(input[4] == sizeof(first) + sizeof(second));
	datum_test(!memcmp(&input[5], first, sizeof(first)));
	datum_test(!memcmp(&input[5 + sizeof(first)], second, sizeof(second)));
	datum_test(count_bytes(input, input_len, first, sizeof(first)) == 1);
	datum_test(count_bytes(input, input_len, second, sizeof(second)) == 1);

	// Long local tags yield space before required auxiliary data does.
	char long_aux_hex[80 * 2 + 1];
	memset(long_aux_hex, '1', sizeof(long_aux_hex) - 1);
	long_aux_hex[sizeof(long_aux_hex) - 1] = '\0';
	root = json_object();
	json_object_set_new(root, "required", json_string(long_aux_hex));
	datum_test(datum_gbt_parse_coinbaseaux(&template, root));
	json_decref(root);
	memset(datum_config.mining_coinbase_tag_primary, 'P', 60);
	datum_config.mining_coinbase_tag_primary[60] = '\0';
	memset(datum_config.mining_coinbase_tag_secondary, 'S', 28);
	datum_config.mining_coinbase_tag_secondary[28] = '\0';
	datum_config.prime_id = 0x01020304;
	input_len = generated_input(&template, input, &target_pot_index);
	datum_test(input_len == MAX_COINBASE_SCRIPTSIG_SIZE);
	datum_test(input[4] == 0x4c && input[5] == 80);
	for (size_t i = 0; i < 80; ++i) datum_test(input[6 + i] == 0x11);
	datum_test(input[86] == 5);
	for (size_t i = 0; i < 4; ++i) datum_test(input[87 + i] == 'P');
	datum_test(input[91] == 0);
	datum_test(count_bytes(input, input_len, (const unsigned char *)"S", 1) == 0);

	// Match Knots PR #359's activation-template shape without key-specific code.
	root = coinbaseaux_fixture("{\"coinbaseaux\":{\"blake2b_headline\":\"424c414b4532622066756e6374696f6e616c207465737420686561646c696e65\"}}");
	datum_test(datum_gbt_parse_coinbaseaux(&template, json_object_get(root, "coinbaseaux")));
	datum_test(template.coinbaseaux_len == strlen("BLAKE2b functional test headline"));
	datum_test(!memcmp(template.coinbaseaux, "BLAKE2b functional test headline", template.coinbaseaux_len));
	json_decref(root);
	input_len = generated_input(&template, input, &target_pot_index);
	datum_test(input[4] == template.coinbaseaux_len);
	datum_test(!memcmp(&input[5], "BLAKE2b functional test headline", template.coinbaseaux_len));
	datum_test(input_len <= MAX_COINBASE_SCRIPTSIG_SIZE);

	memcpy(datum_config.mining_coinbase_tag_primary, saved_primary, sizeof(saved_primary));
	memcpy(datum_config.mining_coinbase_tag_secondary, saved_secondary, sizeof(saved_secondary));
	datum_config.coinbase_unique_id = saved_unique_id;
	datum_config.prime_id = saved_prime_id;
}

void datum_blocktemplates_tests(void) {
	datum_blocktemplates_coinbaseaux_parse_tests();
	datum_blocktemplates_coinbaseaux_generation_tests();
}
