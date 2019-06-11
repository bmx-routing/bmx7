/*
 * Copyright (c) 2010  Axel Neumann
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <json-c/json.h>
//#include <dirent.h>
//#include <sys/inotify.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "key.h"
#include "sec.h"
#include "metrics.h"
#include "link.h"
#include "msg.h"
#include "desc.h"
#include "content.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "json.h"
#include "ip.h"
#include "allocate.h"
#include "prof.h"
#include "iptools.h"
#include "../bmx7_topology/topology.h"


#define CODE_CATEGORY_NAME "json"

static int32_t json_update_interval = DEF_JSON_UPDATE;
static int32_t current_update_interval = 0;

static char *json_dir = NULL;
static char *json_desc_dir = NULL;
static char *json_orig_dir = NULL;
static char *json_netjson_dir = NULL;

STATIC_FUNC
json_object * fields_dbg_json(uint8_t relevance, uint8_t force_array, uint16_t data_size, uint8_t *data,
	uint16_t min_msg_size, const struct field_format *format)
{
	assertion(-501300, (format && data));

	uint32_t msgs_size = 0;
	uint32_t columns = field_format_get_items(format);

	struct field_iterator it = { .format = format, .data = data, .data_size = data_size, .min_msg_size = min_msg_size };

	json_object *jfields = NULL;
	json_object *jarray = NULL;

	while ((msgs_size = field_iterate(&it)) == SUCCESS) {

		assertion(-501301, IMPLIES(it.field == 0, !jfields));
		/*
		if (it.field == 0 && jfields) {
			jarray = jarray ? jarray : json_object_new_array();
			json_object_array_add(jarray, jfields);
			jfields = NULL;
		}
		 */

		if (format[it.field].field_relevance >= relevance) {

			json_object *jfield_val;

			if (format[it.field].field_type == FIELD_TYPE_UINT && it.field_bits <= 32) {
				jfield_val = json_object_new_int(
					field_get_value(&format[it.field], min_msg_size, data, it.field_bit_pos, it.field_bits));
			} else {
				jfield_val = json_object_new_string(
					field_dbg_value(&format[it.field], min_msg_size, data, it.field_bit_pos, it.field_bits));
			}

			jfields = jfields ? jfields : json_object_new_object();

			json_object_object_add(jfields, format[it.field].field_name, jfield_val);
		}

		if (force_array && it.field == (columns - 1)) {
			jarray = jarray ? jarray : json_object_new_array();
			json_object_array_add(jarray, jfields);
			jfields = NULL;
		}

	}

	assertion(-501302, (data_size ? msgs_size == data_size : msgs_size == min_msg_size));

	return jarray ? jarray : jfields;

	/*
		if (jfields && (force_array || jarray)) {
			jarray = jarray ? jarray : json_object_new_array();
			json_object_array_add(jarray, jfields);
			return jarray;
		}

		return jfields;
	 */
}

STATIC_FUNC
void json_write_file(json_object *jobj, char *dirName, char *fileName)
{

	assertion(-501275, (dirName));
	char path_name[MAX_PATH_SIZE];
	sprintf(path_name, "%s/%s", dirName, fileName);

	if (jobj) {
		int fd;

		if ((fd = open(path_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) >= 0) { //check permissions of generated file
			dbgf_all(DBGT_INFO, "writing json data to: %s", path_name);
			dprintf(fd, "%s\n", json_object_to_json_string(jobj));
			close(fd);
		} else {
			dbgf_sys(DBGT_ERR, "could not open %s - %s", path_name, strerror(errno));
		}
	} else {
		if (remove(path_name) != 0) {
			dbgf_sys(DBGT_ERR, "could not remove %s: %s \n", path_name, strerror(errno));
		} else {
			dbgf_all(DBGT_INFO, "removing destroyed json-description=%s", path_name);
		}
	}
}

STATIC_FUNC
int32_t update_json_options(IDM_T show_options, IDM_T show_parameters, char *file_name)
{

	struct opt_type * p_opt = NULL;
	json_object *jopts = json_object_new_array();

	while ((p_opt = list_iterate(&opt_list, p_opt))) {

		if ((!show_options && !p_opt->d.parents_instance_list.items) || p_opt->parent_name)
			continue;

		assertion(-501303, (p_opt->name));

		json_object *jopt = json_object_new_object();

		json_object *jopt_name = json_object_new_string(p_opt->name);
		json_object_object_add(jopt, "name", jopt_name);

		if (show_options) {

			json_object *jopt_relevance = json_object_new_int(p_opt->relevance);
			json_object_object_add(jopt, "relevance", jopt_relevance);

			json_object *jopt_configurable = json_object_new_int(p_opt->cfg_t == A_CFA);
			json_object_object_add(jopt, "configurable", jopt_configurable);

			json_object *jopt_dynamic = json_object_new_int(p_opt->dyn_t == A_DYN || p_opt->dyn_t == A_DYI);
			json_object_object_add(jopt, "dynamic", jopt_dynamic);

			json_object *jopt_multi = json_object_new_int(p_opt->opt_t == A_PM1N);
			json_object_object_add(jopt, "multioption", jopt_multi);


			if (p_opt->opt_t != A_PS0 && p_opt->imin != p_opt->imax) {

				json_object *jopt_min = json_object_new_int(p_opt->imin);
				json_object_object_add(jopt, "min", jopt_min);
				json_object *jopt_max = json_object_new_int(p_opt->imax);
				json_object_object_add(jopt, "max", jopt_max);
				json_object *jopt_def = json_object_new_int(p_opt->idef);
				json_object_object_add(jopt, "def", jopt_def);

			} else if (p_opt->sdef) {

				json_object *jopt_def = json_object_new_string(p_opt->sdef);
				json_object_object_add(jopt, "def", jopt_def);
			}

			if (p_opt->syntax) {
				json_object *jopt_syntax = json_object_new_string(p_opt->syntax);
				json_object_object_add(jopt, "syntax", jopt_syntax);
			}

			if (p_opt->help) {
				json_object *jopt_help = json_object_new_string(p_opt->help);
				json_object_object_add(jopt, "help", jopt_help);
			}

			if (p_opt->d.childs_type_list.items) {
				struct opt_type *c_opt = NULL;
				json_object *jchilds = json_object_new_array();

				while ((c_opt = list_iterate(&p_opt->d.childs_type_list, c_opt))) {

					assertion(-501304, (c_opt->parent_name && c_opt->name));

					json_object *jchild = json_object_new_object();

					json_object *jopt_name = json_object_new_string(c_opt->name);
					json_object_object_add(jchild, "name", jopt_name);

					if (c_opt->imin != c_opt->imax) {

						json_object *jopt_min = json_object_new_int(c_opt->imin);
						json_object_object_add(jchild, "min", jopt_min);
						json_object *jopt_max = json_object_new_int(c_opt->imax);
						json_object_object_add(jchild, "max", jopt_max);
						json_object *jopt_def = json_object_new_int(c_opt->idef);
						json_object_object_add(jchild, "def", jopt_def);

					} else if (c_opt->sdef) {

						json_object *jopt_def = json_object_new_string(c_opt->sdef);
						json_object_object_add(jchild, "def", jopt_def);
					}

					if (c_opt->syntax) {
						json_object *jopt_syntax = json_object_new_string(c_opt->syntax);
						json_object_object_add(jchild, "syntax", jopt_syntax);
					}

					if (c_opt->help) {
						json_object *jopt_help = json_object_new_string(c_opt->help);
						json_object_object_add(jchild, "help", jopt_help);
					}

					json_object_array_add(jchilds, jchild);
				}
				json_object_object_add(jopt, "CHILD_OPTIONS", jchilds);
			}
		}

		if (show_parameters && p_opt->d.parents_instance_list.items) {

			struct opt_parent *p = NULL;
			json_object *jps = json_object_new_array();

			while ((p = list_iterate(&p_opt->d.parents_instance_list, p))) {

				assertion(-501305, (p_opt->name && p_opt->cfg_t != A_ARG));
				json_object *jp = json_object_new_object();

				json_object *jp_val = json_object_new_string(p->val);
				json_object_object_add(jp, "value", jp_val);

				if (p->ref) {
					json_object *jp_from = json_object_new_string(p->ref);
					json_object_object_add(jp, "from", jp_from);
				}

				if (p->childs_instance_list.items) {

					struct opt_child *c = NULL;
					json_object *jcs = json_object_new_array();

					while ((c = list_iterate(&p->childs_instance_list, c))) {

						json_object *jc = json_object_new_object();

						json_object *jc_name = json_object_new_string(c->opt->name);
						json_object_object_add(jc, "name", jc_name);

						json_object *jc_val = json_object_new_string(c->val);
						json_object_object_add(jc, "value", jc_val);

						if (c->ref) {
							json_object *jc_from = json_object_new_string(c->ref);
							json_object_object_add(jp, "from", jc_from);
						}
						json_object_array_add(jcs, jc);
					}
					json_object_object_add(jp, "CHILD_INSTANCES", jcs);
				}
				json_object_array_add(jps, jp);
			}
			json_object_object_add(jopt, "INSTANCES", jps);
		}
		json_object_array_add(jopts, jopt);
	}

	json_object * jobj = json_object_new_object();

	json_object_object_add(jobj, "OPTIONS", jopts);

	json_write_file(jobj, json_dir, file_name);

	json_object_put(jobj);
	return SUCCESS;
}

STATIC_FUNC
json_object *json_netjson_create_networkHeader(char *typeStr, char *labelStr)
{
	assertion(-500000, (typeStr));

	json_object *jObj = json_object_new_object();

	// Create header:
	json_object_object_add(jObj, "type", json_object_new_string(typeStr));
	if (labelStr)
		json_object_object_add(jObj, "label", json_object_new_string(labelStr));
	json_object_object_add(jObj, "protocol", json_object_new_string(BMX_BRANCH));
	json_object_object_add(jObj, "version", json_object_new_string(BRANCH_VERSION));
	char revision[8];
	snprintf(revision, sizeof(revision), "%.7x", bmx_git_rev_u32);
	json_object_object_add(jObj, "revision", json_object_new_string(revision));
	json_object_object_add(jObj, "metric", json_object_new_string("MBitTime"));
	json_object_object_add(jObj, "router_id", json_object_new_string(cryptShaAsString(&myKey->kHash)));

	return jObj;
}

STATIC_FUNC
void json_netjson_create_networkGraph(void)
{
	json_object *jgraph = json_netjson_create_networkHeader("NetworkGraph", "BMX7 network");

	// Create nodes array:
	json_object *jnodes = json_object_new_array();
	struct orig_node *on;
	for (on = NULL; (on = avl_next_item(&orig_tree, (on ? &on->k.nodeId : NULL)));) {

		json_object *jnode = json_object_new_object();
		json_object_object_add(jnode, "id", json_object_new_string(cryptShaAsString(&on->k.nodeId)));

		char label[MAX_HOSTNAME_LEN + 10];
		snprintf(label, sizeof(label), "%s.%s", on->k.hostname, cryptShaAsShortStr(&on->k.nodeId));
		json_object_object_add(jnode, "label", json_object_new_string(label));

		json_object *jaddresses = json_object_new_array();
		json_object_array_add(jaddresses, json_object_new_string(ip6AsStr(&on->primary_ip)));
		json_object_object_add(jnode, "local_addresses", jaddresses);

		json_object *jproperties = json_object_new_object();
		json_object_object_add(jproperties, "hostname", json_object_new_string(on->k.hostname));
		json_object_object_add(jproperties, "lastRef", json_object_new_int((bmx_time - on->dc->referred_by_others_timestamp) / 1000));
		json_object_object_add(jproperties, "descSqn", json_object_new_int(on->dc->descSqn));
		json_object_object_add(jnode, "properties", jproperties);

		json_object_array_add(jnodes, jnode);
	}
	json_object_object_add(jgraph, "nodes", jnodes);

	// Create links array:
	json_object *jlinks = json_object_new_array();
	struct status_handl *topoHandl;
	uint32_t topoLen;
	if ((topoHandl = get_status_handl(ARG_TOPOLOGY)) &&
		(topoLen = ((*(topoHandl->frame_creator))(topoHandl, NULL)))) {

		assertion(-502770, (topoHandl->min_msg_size == sizeof(struct topology_status)));
		assertion(-502771, (!(topoLen % sizeof(struct topology_status))));

		struct topology_status *s = (struct topology_status *) topoHandl->data;
		uint32_t topoMsgs = topoLen / sizeof(struct topology_status);
		uint32_t m;

		for (m = 0; m < topoMsgs; m++) {
			json_object *jlink = json_object_new_object();
			json_object_object_add(jlink, "source", json_object_new_string(cryptShaAsString(s[m].id)));
			json_object_object_add(jlink, "target", json_object_new_string(cryptShaAsString(s[m].neighId)));
			json_object_object_add(jlink, "cost", json_object_new_double(((double) (1000 * 1000)) / ((double) (s[m].txRate))));
			char costText[20];
			snprintf(costText, sizeof(costText), "1/%sb/s", umetric_to_human(s[m].txRate));
			json_object_object_add(jlink, "cost_text", json_object_new_string(costText));
			json_object_array_add(jlinks, jlink);
		}
	}
	json_object_object_add(jgraph, "links", jlinks);

	json_write_file(jgraph, json_netjson_dir, "network-graph.json");
	json_object_put(jgraph);
}


STATIC_FUNC
void json_netjson_create_networkRoutes(void)
{

	json_object *jNetworkRoutes = json_netjson_create_networkHeader("NetworkRoutes", NULL);

	// Create routes array:
	json_object *jRoutes = json_object_new_array();
	struct orig_node *on;
	for (on = NULL; (on = avl_next_item(&orig_tree, (on ? &on->k.nodeId : NULL)));) {

		LinkNode *link = on->neighPath.link;
		if (link && link->k.myDev) {

			json_object *jRoute = json_object_new_object();

			json_object_object_add(jRoute, "destination", json_object_new_string(ip6AsStr(&on->primary_ip)));
			json_object_object_add(jRoute, "destination_id", json_object_new_string(cryptShaAsString(&on->k.nodeId)));
			char label[MAX_HOSTNAME_LEN + 10];
			snprintf(label, sizeof(label), "%s.%s", on->k.hostname, cryptShaAsShortStr(&on->k.nodeId));
			json_object_object_add(jRoute, "destination_label", json_object_new_string(label));

			json_object_object_add(jRoute, "next", json_object_new_string(ip6AsStr(&link->k.linkDev->key.llocal_ip)));
			json_object_object_add(jRoute, "next_id", json_object_new_string(cryptShaAsString(&link->k.linkDev->key.local->on->k.nodeId)));
			char nextLabel[MAX_HOSTNAME_LEN + 10];
			snprintf(nextLabel, sizeof(nextLabel), "%s.%s",
				strlen(link->k.linkDev->key.local->on->k.hostname) ? link->k.linkDev->key.local->on->k.hostname : DBG_NIL,
				cryptShaAsShortStr(&link->k.linkDev->key.local->on->k.nodeId));
			json_object_object_add(jRoute, "next_label", json_object_new_string(nextLabel));

			json_object_object_add(jRoute, "cost", json_object_new_double(((double) (1000 * 1000)) / ((double) (on->neighPath.um))));
			char costText[20];
			snprintf(costText, sizeof(costText), "1/%sb/s", umetric_to_human(on->neighPath.um));
			json_object_object_add(jRoute, "cost_text", json_object_new_string(costText));
			json_object_object_add(jRoute, "hops", json_object_new_int(on->ogmHopCount));

			json_object_object_add(jRoute, "device", json_object_new_string(link->k.myDev->ifname_device.str));

			json_object_array_add(jRoutes, jRoute);
		}

	}
	json_object_object_add(jNetworkRoutes, "routes", jRoutes);

	json_write_file(jNetworkRoutes, json_netjson_dir, "network-routes.json");
	json_object_put(jNetworkRoutes);
}

STATIC_FUNC
void json_generic_event_hook(char *statusKey)
{
	if (!json_update_interval || terminating)
		return;

	char path_name[MAX_PATH_SIZE];
	sprintf(path_name, "%s/%s", json_dir, statusKey);
	int fd;

	if ((fd = open(path_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) >= 0) {
		struct ctrl_node *cn = create_ctrl_node(fd, NULL, YES/*we are root*/);
		check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_JSON_STATUS), statusKey, cn);
		close_ctrl_node(CTRL_CLOSE_STRAIGHT, cn);
	} else {
		dbgf_sys(DBGT_ERR, "could not open %s - %s", path_name, strerror(errno));
	}
}

STATIC_FUNC
void json_dev_event_hook(int32_t cb_id, void* data)
{
	json_generic_event_hook(ARG_INTERFACES);
}

STATIC_FUNC
void json_config_event_hook(int32_t cb_id, void *data)
{
	if (!json_update_interval || terminating)
		return;

	update_json_options(0, 1, JSON_PARAMETERS_FILE);
	json_generic_event_hook(ARG_INTERFACES);
}

STATIC_FUNC
void json_status_event_hook(int32_t cb_id, void* data)
{
	json_generic_event_hook(ARG_STATUS);
}

STATIC_FUNC
void json_links_event_hook(int32_t cb_id, void* data)
{
	json_generic_event_hook(ARG_LINKS);
}

STATIC_FUNC
void json_originator_event_hook(int32_t cb_id, struct orig_node *orig)
{
	assertion(-501272, (json_orig_dir));
	assertion(-501347, (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY || cb_id == PLUGIN_CB_DESCRIPTION_CREATED));

	struct orig_node *on;

	if (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY) {

		if ((on = orig))
			json_write_file(NULL, json_orig_dir, cryptShaAsString(&on->k.nodeId));

	} else {

		struct avl_node *it = NULL;
		while ((on = orig ? orig : avl_iterate_item(&orig_tree, &it))) {

			struct status_handl *handl;
			uint32_t data_len;
			json_object *jorig_fields;

			if ((handl = get_status_handl(ARG_ORIGINATORS)) &&
				(data_len = ((*(handl->frame_creator))(handl, on->kn))) &&
				(jorig_fields = fields_dbg_json(FIELD_RELEVANCE_MEDI, NO,
				data_len, handl->data, handl->min_msg_size, handl->format))) {

				json_write_file(jorig_fields, json_orig_dir, cryptShaAsString(&on->k.nodeId));
				json_object_put(jorig_fields);
			}

			if (orig)
				break;
		}
	}
}

STATIC_FUNC
void json_route_change_hook(uint8_t del, struct orig_node *on)
{
	if (!del) {
		json_originator_event_hook(PLUGIN_CB_DESCRIPTION_CREATED, on);
		json_netjson_create_networkRoutes();
	}
}


STATIC_FUNC
void json_netjson_event_hook(void)
{
	json_netjson_create_networkGraph();
	json_netjson_create_networkRoutes();
}


STATIC_FUNC
void json_description_event_hook(int32_t cb_id, struct orig_node *on)
{
	assertion(-501306, (on));
	assertion(-501273, (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY || cb_id == PLUGIN_CB_DESCRIPTION_CREATED));
	assertion(-501274, IMPLIES(initializing, cb_id == PLUGIN_CB_DESCRIPTION_CREATED));
	assertion(-501275, (json_desc_dir));

	dbgf_all(DBGT_INFO, "cb_id=%d", cb_id);

	if (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY) {

		json_write_file(NULL, json_desc_dir, cryptShaAsString(&on->k.nodeId));

	} else {
		json_object *jorig = json_object_new_object();
		json_object_object_add(jorig, "descSha", json_object_new_string(cryptShaAsString(&on->dc->dHash)));

		struct desc_content *dc = on->dc;
		if (dc && dc->contentRefs_tree.items && !dc->unresolvedContentCounter) {

			dbgf_track(DBGT_INFO, "descSha=%s nodeId=%s name=%s state=%s contents=%d/%d neighRefs=%d:",
				cryptShaAsString(&dc->dHash), cryptShaAsString(dc ? &dc->kn->kHash : NULL),
				dc && dc->on ? dc->on->k.hostname : NULL, dc ? dc->kn->bookedState->secName : NULL,
				dc ? dc->contentRefs_tree.items : 0, dc ? (int) (dc->unresolvedContentCounter + dc->contentRefs_tree.items) : -1,
				dc->kn->neighRefs_tree.items);


			struct rx_frame_iterator it = { .caller = __func__, .on = NULL, .dcOp = dc,
				.op = TLV_OP_PLUGIN_MIN, .db = description_tlv_db, .process_filter = DEF_DESCRIPTION_TYPE, .f_type = -1, };

			int32_t result;
			json_object *jextensions = NULL;
			while ((result = rx_frame_iterate(&it)) > TLV_RX_DATA_DONE) {

				dbgf_track(DBGT_INFO, "%s=%d (%s%s length=%d%s):",
					it.f_handl ? it.f_handl->name : "DSC_UNKNOWN", it.f_type_expanded,
					dc->final[it.f_type].desc_tlv_body_len ? "inline" : "ref=",
					dc->final[it.f_type].desc_tlv_body_len ? "" : cryptShaAsString(&dc->final[it.f_type].u.cun->k.content->chash),
					dc->final[it.f_type].desc_tlv_body_len ? dc->final[it.f_type].desc_tlv_body_len : dc->final[it.f_type].u.cun->k.content->f_body_len,
					it.f_handl && it.f_handl->msg_format ? "" : " UNKNOWN_FORMAT"
					);

				if (it.f_msg && it.f_handl && it.f_msgs_len) {
					json_object * jext_fields;

					if (it.f_handl->msg_format && it.f_handl->min_msg_size && (jext_fields = fields_dbg_json(
						FIELD_RELEVANCE_MEDI, YES, it.f_msgs_len, it.f_msg, it.f_handl->min_msg_size, it.f_handl->msg_format))) {

						json_object *jext = json_object_new_object();
						json_object_object_add(jext, it.f_handl->name, jext_fields);
						jextensions = jextensions ? jextensions : json_object_new_array();
						json_object_array_add(jextensions, jext);

					} /*else {
						json_object *jext = json_object_new_object();
						jext_fields = json_object_new_string(memAsHexStringSep(it.f_msg, it.f_msgs_len, it.f_handl->min_msg_size, " "));
						json_object_object_add(jext, it.f_handl->name, jext_fields);
						jextensions = jextensions ? jextensions : json_object_new_array();
						json_object_array_add(jextensions, jext);
					}*/

				}
			}
			if (jextensions)
				json_object_object_add(jorig, "extensions", jextensions);

		}

		json_write_file(jorig, json_desc_dir, cryptShaAsString(&on->k.nodeId));

		json_object_put(jorig);
	}

	json_originator_event_hook(cb_id, on);
	json_netjson_event_hook();
}

STATIC_FUNC
void update_json_status(void *data)
{
	prof_start(update_json_status, main);
	assertion(-501276, (json_dir));
	assertion(-501307, (json_update_interval));

	task_register(json_update_interval, update_json_status, NULL, -300378);

	json_status_event_hook(0, NULL);
	json_dev_event_hook(0, NULL);
	json_links_event_hook(0, NULL);
	json_originator_event_hook(PLUGIN_CB_DESCRIPTION_CREATED, NULL);
	json_netjson_create_networkRoutes();
	prof_stop();
}

STATIC_FUNC
int32_t opt_json_status(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
	if (cmd == OPT_CHECK || cmd == OPT_APPLY) {

		int8_t relevance = get_opt_child_val_int(opt, patch, ARG_RELEVANCE, FAILURE);
		struct status_handl *handl = NULL;

		if ((handl = get_status_handl(patch->val))) {

			uint32_t data_len;

			if (cmd == OPT_APPLY && (data_len = ((*(handl->frame_creator))(handl, NULL)))) {

				json_object *jstat = json_object_new_object();
				json_object *jstat_fields = NULL;

				if ((jstat_fields = fields_dbg_json(relevance, handl->multiline,
					data_len, handl->data, handl->min_msg_size, handl->format))) {

					json_object_object_add(jstat, handl->status_name, jstat_fields);
				}

				if (cn)
					dbg_printf(cn, "%s\n", json_object_to_json_string(jstat));

				json_object_put(jstat);
			}

		} else {
			return FAILURE;
		}
	}

	return SUCCESS;
}

STATIC_FUNC
int32_t opt_json_update_interval(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	// this function is used to initialize all json directories

	if (initializing && !json_dir && (cmd == OPT_CHECK || cmd == OPT_APPLY || cmd == OPT_SET_POST)) {

		static char tmp_json_dir[MAX_PATH_SIZE];
		static char tmp_desc_dir[MAX_PATH_SIZE];
		static char tmp_orig_dir[MAX_PATH_SIZE];
		static char tmp_netjson_dir[MAX_PATH_SIZE];

		assertion(-501277, (strlen(run_dir) > 3));

		sprintf(tmp_json_dir, "%s/%s", run_dir, DEF_JSON_SUBDIR);
		sprintf(tmp_orig_dir, "%s/%s", tmp_json_dir, DEF_JSON_ORIG_SUBDIR);
		sprintf(tmp_desc_dir, "%s/%s", tmp_json_dir, DEF_JSON_DESC_SUBDIR);
		sprintf(tmp_netjson_dir, "%s/%s", tmp_json_dir, DEF_JSON_NETJSON_SUBDIR);

		if (check_dir(run_dir, YES/*create*/, YES/*writable*/, NO) == FAILURE)
			return FAILURE;

		if (check_dir(tmp_json_dir, YES/*create*/, YES/*writable*/, NO) == FAILURE)
			return FAILURE;

		if (check_dir(tmp_orig_dir, YES/*create*/, YES/*writable*/, NO) == FAILURE)
			return FAILURE;

		if (check_dir(tmp_desc_dir, YES/*create*/, YES/*writable*/, NO) == FAILURE)
			return FAILURE;

		if (check_dir(tmp_netjson_dir, YES/*create*/, YES/*writable*/, NO) == FAILURE)
			return FAILURE;

		json_dir = tmp_json_dir;
		json_orig_dir = tmp_orig_dir;
		json_desc_dir = tmp_desc_dir;
		json_netjson_dir = tmp_netjson_dir;
	}

	if (initializing && cmd == OPT_SET_POST) {

		assertion(-501308, (json_dir && json_orig_dir && json_desc_dir && json_netjson_dir));

		if (rm_dir_content(json_orig_dir, NULL) == FAILURE)
			return FAILURE;

		if (rm_dir_content(json_desc_dir, NULL) == FAILURE)
			return FAILURE;

		if (rm_dir_content(json_netjson_dir, NULL) == FAILURE)
			return FAILURE;

		update_json_options(1, 0, JSON_OPTIONS_FILE);
	}

	if (cmd == OPT_SET_POST && current_update_interval != json_update_interval) {

		if (current_update_interval) {
			task_remove(update_json_status, NULL);
			set_route_change_hooks(json_route_change_hook, DEL);
		}

		if (json_update_interval) {
			task_register(XMAX(10, json_update_interval), update_json_status, NULL, -300379);
			set_route_change_hooks(json_route_change_hook, ADD);
		}

		current_update_interval = json_update_interval;
	}

	return SUCCESS;
}


static struct opt_type json_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	
	{ODI,0,ARG_JSON_UPDATE,		0,  9,2,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&json_update_interval,	MIN_JSON_UPDATE,MAX_JSON_UPDATE,DEF_JSON_UPDATE,0,opt_json_update_interval,
                ARG_VALUE_FORM, "disable or periodically update json-status files every given milliseconds."}
        ,
	{ODI,0,ARG_JSON_STATUS,		0,  9,2,A_PS1N,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_json_status,
			0,		"show status in json format\n"}
        ,
	{ODI,ARG_JSON_STATUS,ARG_RELEVANCE,'r',9,1,A_CS1,A_USR,A_DYI,A_ARG,A_ANY,0,	       MIN_RELEVANCE,   MAX_RELEVANCE,  FIELD_RELEVANCE_MEDI,0, opt_json_status,
			ARG_VALUE_FORM,	HLP_ARG_RELEVANCE}
};
static void json_cleanup(void)
{
	if (current_update_interval) {
		set_route_change_hooks(json_route_change_hook, DEL);
	}
}

static int32_t json_init(void)
{
	register_options_array(json_options, sizeof( json_options), CODE_CATEGORY_NAME);

	return SUCCESS;
}

struct plugin* get_plugin(void)
{
	static struct plugin json_plugin;

	memset(&json_plugin, 0, sizeof( struct plugin));

	json_plugin.plugin_name = CODE_CATEGORY_NAME;
	json_plugin.plugin_size = sizeof( struct plugin);
	json_plugin.cb_init = json_init;
	json_plugin.cb_cleanup = json_cleanup;
	json_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_CREATED] = (void (*) (int32_t, void*)) json_description_event_hook;
	json_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_DESTROY] = (void (*) (int32_t, void*)) json_description_event_hook;
	json_plugin.cb_plugin_handler[PLUGIN_CB_CONF] = json_config_event_hook;
	json_plugin.cb_plugin_handler[PLUGIN_CB_BMX_DEV_EVENT] = json_dev_event_hook;
	json_plugin.cb_plugin_handler[PLUGIN_CB_STATUS] = json_status_event_hook;
	json_plugin.cb_plugin_handler[PLUGIN_CB_LINKS_EVENT] = json_links_event_hook;

	return &json_plugin;
}
