// SPDX-License-Identifier: GPL-2.0-or-later
/**
 * @file trn_cli_ep.c
 * @author Bin Liang (@liangbin)
 *
 * @brief CLI subcommands related to droplets
 *
 * @copyright Copyright (c) 2019 The Authors.
 *
 */
#include "trn_cli.h"

/* Parse cJSON into struct */
int trn_cli_parse_droplet(const cJSON *jsonobj, struct rpc_trn_droplet_t *droplet)
{
	cJSON *interface = cJSON_GetObjectItem(jsonobj, "interface");
	cJSON *role = cJSON_GetObjectItem(jsonobj, "role");
	cJSON *num_entrances = cJSON_GetObjectItem(jsonobj, "num_entrances");
	cJSON *entrances = cJSON_GetObjectItem(jsonobj, "entrances");

	if (interface == NULL) {
		print_err("Error: Missing interface\n");
		return -EINVAL;
	} else {
		strcpy(droplet->interface, interface->valuestring);
	}

	if (role == NULL) {
		print_err("Error: Missing role\n");
		return -EINVAL;
	} else if (!cJSON_IsNumber(role)) {
		print_err("Error: role should be number type\n");
		return -EINVAL;
	} else {
		droplet->role = role->valueint;
	}

	if (num_entrances == NULL) {
		print_err("Error: Missing num_entrances\n");
		return -EINVAL;
	} else if (!cJSON_IsNumber(num_entrances)) {
		print_err("Error: num_entrances should be number type\n");
		return -EINVAL;
	} else if (num_entrances->valueint >= TRAN_MAX_ZGC_ENTRANCES) {
		print_err("Error: num_entrances over limit %d\n", TRAN_MAX_ZGC_ENTRANCES);
		return -EINVAL;
	} else {
		droplet->num_entrances = num_entrances->valueint;
	}

	if (entrances == NULL) {
		print_err("Error: Missing entrances\n");
		return -EINVAL;
	} else if (!cJSON_IsArray(entrances)) {
		print_err("Error: entrances should be array type\n");
		return -EINVAL;
	} else if (cJSON_GetArraySize(entrances) != droplet->num_entrances){
		print_err("Error: entrances array size not match\n");
		return -EINVAL;
	}

	int i = 0;
	cJSON *entrance;
	cJSON_ArrayForEach(entrance, entrances)	{
		cJSON *ip = cJSON_GetObjectItem(entrance, "ip");
		cJSON *mac = cJSON_GetObjectItem(entrance, "mac");

		if (ip == NULL) {
			print_err("Error: Missing entrance ip\n");
			return -EINVAL;
		} else {
			strcpy(droplet->entrances[i].ip, ip->valuestring);
		}

		if (mac == NULL) {
			print_err("Error: Missing entrance mac\n");
			return -EINVAL;
		} else {
			strcpy(droplet->entrances[i].mac, mac->valuestring);
		}
		i++;
	}

	return 0;
}

int trn_cli_update_droplet_subcmd(CLIENT *clnt, int argc, char *argv[])
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
	rpc_trn_droplet_t droplet;
	char rpc[] = "update_droplet_1";

	int err = trn_cli_parse_droplet(json_str, &droplet);
	cJSON_Delete(json_str);

	if (err != 0) {
		print_err("Error: parsing droplet config.\n");
		return -EINVAL;
	}

	rc = update_droplet_1(&droplet, clnt);
	if (rc == (int *)NULL) {
		print_err("RPC Error: client call failed: update_droplet_1.\n");
		return -EINVAL;
	}

	if (*rc != 0) {
		print_err(
			"Error: %s fatal daemon error, see transitd logs for details.\n",
			rpc);
		return -EINVAL;
	}

	dump_droplet(&droplet);
	print_msg("update_droplet_1 successfully updated droplet.\n");
	return 0;
}

void dump_droplet(struct rpc_trn_droplet_t *droplet)
{
	int i;

	print_msg("Interface: %s\n", droplet->interface);
	print_msg("Role: %d\n", droplet->role);
	print_msg("Num of entrances: %d\n", droplet->num_entrances);
	print_msg("Entrances: [");
	for (i = 0; i < droplet->num_entrances; i++) {
		print_msg("ip: %s mac: %s",
			droplet->entrances[i].ip, droplet->entrances[i].mac);
	}
	print_msg("]\n");
}
