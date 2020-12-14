// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * @file trn_cli_ep.c
 * @author Sherif Abdelwahab (@zasherif)
 *         Phu Tran          (@phudtran)
 *
 * @brief CLI subcommands related to endpoints
 *
 * @copyright Copyright (c) 2019 The Authors.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
#include "trn_cli.h"

int trn_cli_parse_ep_key(const cJSON *jsonobj,
			 struct rpc_trn_endpoint_key_t *epk)
{

	if (trn_cli_parse_json_number(jsonobj, "vni", (int *)&epk->vni)) {
		return -EINVAL;
	}

	if (trn_cli_parse_json_ip(jsonobj, "ip", &epk->ip)) {
		return -EINVAL;
	}

	return 0;
}

int trn_cli_parse_ep(const cJSON *jsonobj, rpc_trn_endpoint_batch_t *batch)
{
	cJSON *eps = cJSON_GetObjectItem(jsonobj, "eps");

	if (trn_cli_parse_json_number(jsonobj, "size",
		(int *)&batch->rpc_trn_endpoint_batch_t_len)) {
		return -EINVAL;
	} else if (batch->rpc_trn_endpoint_batch_t_len >= TRAN_MAX_EP_BATCH_SIZE) {
		print_err("Too many elements in batch\n");
		return -EINVAL;
	}

	rpc_trn_endpoint_t *items = (rpc_trn_endpoint_t *)malloc(
		sizeof(rpc_trn_endpoint_t) * batch->rpc_trn_endpoint_batch_t_len);
	if (!items) {
		print_err("Failed to allocate RPC message\n");
		return -EINVAL;
	}

	int i = 0;
	rpc_trn_endpoint_t *item = items;
	cJSON *ep;
	cJSON_ArrayForEach(ep, eps)
	{
		if (i >= batch->rpc_trn_endpoint_batch_t_len) {
			print_err("More items in array than claimed in size\n");
			goto cleanup;
		}

		if (trn_cli_parse_json_number(ep, "vni", (int *)&item->vni)) {
			goto cleanup;
		}

		if (trn_cli_parse_json_ip(ep, "ip", &item->ip)) {
			goto cleanup;
		}

		if (trn_cli_parse_json_ip(ep, "hip", &item->hip)) {
			goto cleanup;
		}

		if (trn_cli_parse_json_mac(ep, "mac", &item->mac[0])) {
			goto cleanup;
		}

		if (trn_cli_parse_json_mac(ep, "hmac", &item->hmac[0])) {
			goto cleanup;
		}

		item++;
		i++;
	}

	batch->rpc_trn_endpoint_batch_t_val = items;
	return 0;
cleanup:
	free(items);
	return -EINVAL;
}

int trn_cli_update_ep_subcmd(CLIENT *clnt, int argc, char *argv[])
{
	ketopt_t om = KETOPT_INIT;
	struct cli_conf_data_t conf;
	cJSON *json_str = NULL;

	if (trn_cli_read_conf_str(&om, argc, argv, &conf)) {
		return -EINVAL;
	}

	char *buf = conf.conf_str;
	json_str = trn_cli_parse_json(buf);

	if (json_str == NULL) {
		return -EINVAL;
	}

	int *rc;
	rpc_trn_endpoint_batch_t ep_batch = {0, NULL};
	char rpc[] = "update_ep_1";

	int err = trn_cli_parse_ep(json_str, &ep_batch);
	cJSON_Delete(json_str);

	if (err != 0) {
		print_err("Error: parsing endpoint config batch.\n");
		return -EINVAL;
	}

	rc = update_ep_1(&ep_batch, clnt);

	if (ep_batch.rpc_trn_endpoint_batch_t_val) {
		free(ep_batch.rpc_trn_endpoint_batch_t_val);
	}

	if (rc == (int *)NULL) {
		print_err("RPC Error: client call failed: update_ep_1.\n");
		return -EINVAL;
	}

	if (*rc != 0) {
		print_err(
			"Error: %s fatal daemon error, see transitd logs for details.\n",
			rpc);
		return -EINVAL;
	}

	print_msg("update_ep_1 successful\n");
	return 0;
}

int trn_cli_get_ep_subcmd(CLIENT *clnt, int argc, char *argv[])
{
	ketopt_t om = KETOPT_INIT;
	struct cli_conf_data_t conf;
	cJSON *json_str = NULL;

	if (trn_cli_read_conf_str(&om, argc, argv, &conf)) {
		return -EINVAL;
	}

	char *buf = conf.conf_str;
	json_str = trn_cli_parse_json(buf);

	if (json_str == NULL) {
		return -EINVAL;
	}

	rpc_trn_endpoint_key_t epkey;
	rpc_trn_endpoint_t *ep;
	char rpc[] = "get_ep_1";

	int err = trn_cli_parse_ep_key(json_str, &epkey);
	cJSON_Delete(json_str);

	if (err != 0) {
		print_err("Error: parsing endpoint config.\n");
		return -EINVAL;
	}

	ep = get_ep_1(&epkey, clnt);
	if (ep == NULL) {
		print_err("RPC Error: client call failed: get_ep_1.\n");
		return -EINVAL;
	}

	dump_ep(ep);
	print_msg(
		"get_ep_1 successfully queried endpoint 0x%08x.\n", ep->ip);

	return 0;
}

int trn_cli_delete_ep_subcmd(CLIENT *clnt, int argc, char *argv[])
{
	ketopt_t om = KETOPT_INIT;
	struct cli_conf_data_t conf;
	cJSON *json_str = NULL;

	if (trn_cli_read_conf_str(&om, argc, argv, &conf)) {
		return -EINVAL;
	}

	char *buf = conf.conf_str;
	json_str = trn_cli_parse_json(buf);

	if (json_str == NULL) {
		return -EINVAL;
	}

	int *rc;
	rpc_trn_endpoint_key_t ep_key;
	char rpc[] = "delete_ep_1";

	int err = trn_cli_parse_ep_key(json_str, &ep_key);
	cJSON_Delete(json_str);

	if (err != 0) {
		print_err("Error: parsing endpoint config.\n");
		return -EINVAL;
	}

	rc = delete_ep_1(&ep_key, clnt);
	if (rc == (int *)NULL) {
		print_err("RPC Error: client call failed: delete_ep_1.\n");
		return -EINVAL;
	}

	if (*rc != 0) {
		print_err(
			"Error: %s fatal daemon error, see transitd logs for details.\n",
			rpc);
		return -EINVAL;
	}

	print_msg(
		"delete_ep_1 successfully deleted endpoint 0x%08x.\n", ep_key.ip);

	return 0;
}

void dump_ep(struct rpc_trn_endpoint_t *ep)
{
	int i;

	print_msg("VNI: %d\n", ep->vni);
	print_msg("IP: 0x%x\n", ep->ip);
	print_msg("MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		ep->mac[0],ep->mac[1],ep->mac[2],ep->mac[3],ep->mac[4],ep->mac[5]);
	print_msg("Host IP: 0x%x\n", ep->hip);
	print_msg("Host MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
		ep->hmac[0],ep->hmac[1],ep->hmac[2],ep->hmac[3],ep->hmac[4],ep->hmac[5]);
}
