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
#include <json/json.h>
#include <dirent.h>
#include <sys/inotify.h>

#include "bmx.h"
#include "msg.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "ip.h"
#include "json.h"
#include "hna.h"


#define CODE_CATEGORY_NAME "json"

static int32_t json_update_interval = DEF_JSON_UPDATE;
static int32_t current_update_interval = 0;

static char *json_dir = NULL;
static char *json_desc_dir = NULL;
static char *json_orig_dir = NULL;
static char *json_smsTx_dir = NULL;
static char *json_smsRx_dir = NULL;

static int extensions_fd = -1;
static int extensions_wd = -1;


static AVL_TREE(json_sms_tree, struct description_msg_json_sms, name );


STATIC_FUNC
json_object * fields_dbg_json(uint16_t relevance, uint16_t data_size, uint8_t *data,
                    uint16_t min_msg_size, const struct field_format *format)
{
        TRACE_FUNCTION_CALL;
        assertion(-501247, (format && data ));

        uint32_t msgs_size = 0;
        uint32_t msgs = 0;
        struct field_iterator it = {.format = format, .data = data, .data_size = data_size, .min_msg_size = min_msg_size};

        json_object *jfields = NULL;
        json_object *jarray = NULL;

        while ((msgs_size = field_iterate(&it)) == SUCCESS) {

                if (format[it.field].field_relevance >= relevance) {

                        if (it.field == 0) {
                                msgs++;

                                if (msgs >= 2) {
                                        jarray = jarray ? jarray : json_object_new_array();
                                        json_object_array_add(jarray, jfields);
                                        jfields = NULL;
                                }
                        }

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
        }

        assertion(-501248, (data_size ? msgs_size == data_size : msgs_size == min_msg_size));

        if ( msgs == 1 ) {

                return jfields;

        } else if (msgs >= 2) {

                json_object_array_add(jarray, jfields);
                return jarray;
        }

        return NULL;
}

STATIC_FUNC
IDM_T rm_dir_content(char* dir_name)
{

        struct dirent *d;
        DIR *dir = opendir(dir_name);

        while ((d = readdir(dir))) {

                char rm_file[MAX_PATH_SIZE];
                sprintf(rm_file, "%s/%s", dir_name, d->d_name);

                if (validate_name_string(d->d_name, strlen(d->d_name) + 1) == SUCCESS) {

                        dbgf_sys(DBGT_WARN, "removing stale josn file: %s \n", rm_file);

                        if (remove(rm_file) != 0) {
                                dbgf_sys(DBGT_ERR, "could not remove json file %s: %s \n", rm_file, strerror(errno));
                                return FAILURE;
                        }

                } else {
                        dbgf_all(DBGT_ERR, "keeping non-json file: %s\n", rm_file);
                }
        }

        return SUCCESS;
}






STATIC_FUNC
void check_for_changed_sms(void)
{
        uint16_t found_sms = 0;
        uint16_t matching_sms = 0;

        struct opt_type *opt = get_option( 0, 0, ARG_JSON_SMS );
        struct opt_parent *p = NULL;
        struct json_sms * sms = NULL;
        struct avl_node *an = NULL;

        char name[MAX_JSON_SMS_NAME_LEN];
        char data[MAX_JSON_SMS_DATA_LEN + 1];

        while ((sms = avl_iterate_item(&json_sms_tree, &an))) {
                sms->stale = 1;
        }

        while ((p = list_iterate(&opt->d.parents_instance_list, p))) {

                int len = 0;

                memset(name, 0, sizeof (name));
                strcpy(name, p->p_val);

                int fd = -1;
                char path_name[MAX_PATH_SIZE + 20] = "";
                sprintf(path_name, "%s/%s", json_smsTx_dir, p->p_val);



                if ((fd = open(path_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {

                        dbgf_sys(DBGT_INFO, "could not open %s - %s", path_name, strerror(errno));
                        continue;

                } else if ((len = read(fd, data, sizeof (data))) < 0 || len > MAX_JSON_SMS_DATA_LEN) {

                        dbgf_sys(DBGT_ERR, "sms=%s data_len=%d too big or: %s", path_name, len, strerror(errno));
                        close(fd);
                        continue;

                } else if ((sms = avl_find_item(&json_sms_tree, name)) && sms->text_len == len && !strcmp(sms->text, data)) {

                        matching_sms++;
                        sms->stale = 0;

                } else {

                        if (sms) {
                                avl_remove(&json_sms_tree, sms->name, -300378);
                                debugFree(sms, -300369);
                        }

                        sms = debugMalloc(sizeof (struct description_msg_json_sms) +len, -300370);
                        memset(sms, 0, sizeof (struct description_msg_json_sms) +len);
                        strcpy(sms->name, name);
                        sms->text_len = len;
                        sms->stale = 0;
                        memcpy(sms->text, data, len);
                        avl_insert(&json_sms_tree, sms, -300371);

                }

                found_sms++;
        }


        if (found_sms != matching_sms || found_sms != json_sms_tree.items) {

                memset(name, 0, sizeof (name));
                while ((sms = avl_next_item(&json_sms_tree, name))) {
                        memcpy(name, sms->name, sizeof (sms->name));
                        if (sms->stale) {
                                avl_remove(&json_sms_tree, sms->name, -300373);
                                debugFree(sms, -300374);
                        }
                }

                my_description_changed = YES;
        }
}


STATIC_FUNC
void json_inotify_event_hook(int fd)
{
        TRACE_FUNCTION_CALL;

        dbgf_track(DBGT_INFO, "detected changes in directory: %s", json_smsTx_dir);

        assertion(-501258, (fd > -1 && fd == extensions_fd));

        int ilen = 1024;
        char *ibuff = debugMalloc(ilen, -300375);
        int rcvd;
        int processed = 0;

        while ((rcvd = read(fd, ibuff, ilen)) == 0 || rcvd == EINVAL) {

                ibuff = debugRealloc(ibuff, (ilen = ilen * 2), -300376);
                assertion(-501259, (ilen <= (1024 * 16)));
        }

        if (rcvd > 0) {

                while (processed < rcvd) {

                        struct inotify_event *ievent = (struct inotify_event *) &ibuff[processed];

                        processed += (sizeof (struct inotify_event) +ievent->len);

                        if (ievent->mask & (IN_DELETE_SELF | IN_DELETE)) {
                                dbgf_sys(DBGT_ERR, "directory %s has been removed \n", json_smsTx_dir);
                                cleanup_all(-501260);
                        }
                }

        } else {
                dbgf_sys(DBGT_ERR, "read()=%d: \n", rcvd, strerror(errno));
        }

        debugFree(ibuff, -300377);

        check_for_changed_sms();
}


STATIC_FUNC
int create_description_sms(struct tx_frame_iterator *it)
{

        struct avl_node *an = NULL;
        struct json_sms *sms;

        uint8_t *data = tx_iterator_cache_msg_ptr(it);
        uint16_t max_size = tx_iterator_cache_data_space(it);
        int pos = 0;

        if (!json_sms_tree.items)
                return TLV_TX_DATA_IGNORED;

        while ((sms = avl_iterate_item(&json_sms_tree, &an))) {

                if (pos + sizeof (struct description_msg_json_sms) +sms->text_len > max_size) {
                        dbgf_sys(DBGT_ERR, "Failed adding descriptionExtensionSms=%s/%s", json_smsTx_dir, sms->name);
                        continue;
                }

                struct description_msg_json_sms *msg = (struct description_msg_json_sms*) (data + pos);

                memset(msg, 0, sizeof (struct description_msg_json_sms));
                strcpy(msg->name, sms->name);
                msg->text_len = htons(sms->text_len);
                memcpy(msg->text, sms->text, sms->text_len);

                pos += sms->text_len;
        }

        return pos;
}

STATIC_FUNC
int process_description_sms(struct rx_frame_iterator *it)
{
        struct orig_node *on = it->on;
        uint8_t op = it->op;

        int pos = 0;
        int mlen;

        do {

                if (pos + (int)sizeof ( struct description_msg_json_sms) > it->frame_msgs_length)
                        return TLV_RX_DATA_FAILURE;

                struct description_msg_json_sms *sms = (struct description_msg_json_sms *) (it->frame_data + pos);
                mlen = sizeof ( struct description_msg_json_sms) +ntohs(sms->text_len);

                if (pos + mlen > it->frame_msgs_length)
                        return TLV_RX_DATA_FAILURE;

                if (validate_name_string(sms->name, sizeof (sms->name)) != SUCCESS)
                        return TLV_RX_DATA_FAILURE;

                char path_name[MAX_PATH_SIZE];
                sprintf(path_name, "%s/%s:%s", json_smsRx_dir, globalIdAsString(&on->global_id), sms->name);
                int fd;

                if (op == TLV_OP_DEL) {

                        if (remove(path_name) != 0) {
                                dbgf_sys(DBGT_ERR, "could not remove %s: %s \n", path_name, strerror(errno));
                        }

                } else if (op == TLV_OP_ADD) {


                        if ((fd = open(path_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {

                                dbgf_sys(DBGT_ERR, "could not open %s - %s", path_name, strerror(errno));

                        } else {

                                int written = write(fd, sms->text, ntohs(sms->text_len));
                                if (written != ntohs(sms->text_len)) {
                                        dbgf_sys(DBGT_ERR, "write=%d of %d bytes to %s: %s",
                                                written, ntohs(sms->text_len), path_name, strerror(errno));
                                }
                                close(fd);
                        }
                }

        } while ((pos = pos + mlen) < it->frame_msgs_length);

        return pos;
}







STATIC_FUNC
int32_t update_json_options(IDM_T show_options, IDM_T show_parameters, char *file_name)
{
        assertion(-501254, (json_dir));

        int fd;
        char path_name[MAX_PATH_SIZE + 20] = "";

        sprintf(path_name, "%s/%s", json_dir, file_name);

        if ((fd = open(path_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) { //check permissions of generated file

		dbgf_sys(DBGT_ERR, "could not open %s - %s", path_name, strerror(errno) );
		return FAILURE;
	}


        struct opt_type * p_opt = NULL;
        json_object *jopts = json_object_new_array();

        while ((p_opt = list_iterate(&opt_list, p_opt))) {

                if ((!show_options && !p_opt->d.parents_instance_list.items) || p_opt->parent_name)
                        continue;

                assertion(-501240, (p_opt->long_name));

                json_object *jopt = json_object_new_object();

                json_object *jopt_name = json_object_new_string(p_opt->long_name);
                json_object_object_add(jopt, "name", jopt_name);

                if (show_options) {

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

                                        assertion(-501241, (c_opt->parent_name && c_opt->long_name));

                                        json_object *jchild = json_object_new_object();

                                        json_object *jopt_name = json_object_new_string(c_opt->long_name);
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

                                assertion(-501231, (p_opt->long_name && p_opt->cfg_t != A_ARG));
                                json_object *jp = json_object_new_object();

                                json_object *jp_val = json_object_new_string(p->p_val);
                                json_object_object_add(jp, "value", jp_val);

                                if (p->p_ref) {
                                        json_object *jp_from = json_object_new_string(p->p_ref);
                                        json_object_object_add(jp, "from", jp_from);
                                }

                                if (p->childs_instance_list.items) {

                                        struct opt_child *c = NULL;
                                        json_object *jcs = json_object_new_array();

                                        while ((c = list_iterate(&p->childs_instance_list, c))) {

                                                json_object *jc = json_object_new_object();

                                                json_object *jc_name = json_object_new_string(c->c_opt->long_name);
                                                json_object_object_add(jc, "name", jc_name);

                                                json_object *jc_val = json_object_new_string(c->c_val);
                                                json_object_object_add(jc, "value", jc_val);

                                                if (c->c_ref) {
                                                        json_object *jc_from = json_object_new_string(c->c_ref);
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

        dprintf(fd, "%s\n", json_object_to_json_string(jobj));

        json_object_put(jobj);
        close(fd);
 	return SUCCESS;
}









STATIC_FUNC
void json_dev_event_hook(int32_t cb_id, void* data)
{

        if (!json_update_interval || terminating)
                return;

        TRACE_FUNCTION_CALL;

        int fd;
        char path_name[MAX_PATH_SIZE + 20] = "";
        sprintf(path_name, "%s/%s", json_dir, ARG_INTERFACES);

        if ((fd = open(path_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {

                dbgf_sys(DBGT_ERR, "could not open %s - %s", path_name, strerror(errno));

        } else {

                struct ctrl_node *cn = create_ctrl_node(fd, NULL, YES/*we are root*/);

                check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_JSON_INTERFACES), 0, cn);

                close_ctrl_node(CTRL_CLOSE_STRAIGHT, cn);
        }
}

STATIC_FUNC
void json_config_event_hook(int32_t cb_id, void *data)
{
        if (!json_update_interval || terminating)
                return;

        TRACE_FUNCTION_CALL;

        update_json_options(0, 1, JSON_PARAMETERS_FILE);

        json_dev_event_hook(cb_id, data);
}

STATIC_FUNC
void json_status_event_hook(int32_t cb_id, void* data)
{
        if (!json_update_interval || terminating)
                return;

        TRACE_FUNCTION_CALL;

        int fd;
        char path_name[MAX_PATH_SIZE + 20] = "";
        sprintf(path_name, "%s/%s", json_dir, ARG_STATUS);

        if ((fd = open(path_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {

                dbgf_sys(DBGT_ERR, "could not open %s - %s", path_name, strerror(errno));

        } else {

                struct ctrl_node *cn = create_ctrl_node(fd, NULL, YES/*we are root*/);

                check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_JSON_STATUS), 0, cn);

                close_ctrl_node(CTRL_CLOSE_STRAIGHT, cn);
        }
}

STATIC_FUNC
void json_links_event_hook(int32_t cb_id, void* data)
{
        if (!json_update_interval || terminating)
                return;

        TRACE_FUNCTION_CALL;

        int fd;
        char path_name[MAX_PATH_SIZE + 20] = "";
        sprintf(path_name, "%s/%s", json_dir, ARG_LINKS);

        if ((fd = open(path_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {

                dbgf_sys(DBGT_ERR, "could not open %s - %s", path_name, strerror(errno));

        } else {

                struct ctrl_node *cn = create_ctrl_node(fd, NULL, YES/*we are root*/);

                check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_JSON_LINKS), 0, cn);

                close_ctrl_node(CTRL_CLOSE_STRAIGHT, cn);
        }
}

STATIC_FUNC
void json_originator_event_hook(int32_t cb_id, struct orig_node *orig)
{
        struct orig_node *on;
        char path_name[MAX_PATH_SIZE];
        assertion(-501252, (json_orig_dir));

        if (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY) {

                if ((on = orig)) {
                        dbgf_track(DBGT_WARN, "removing destroyed json-description of orig=%s",
                                globalIdAsString(&on->global_id));

                        sprintf(path_name, "%s/%s", json_orig_dir, globalIdAsString(&on->global_id));
                        if (remove(path_name) != 0) {
                                dbgf_sys(DBGT_ERR, "could not remove %s: %s \n", path_name, strerror(errno));
                        }
                }
                return;

        } else {

                struct avl_node *it = NULL;
                while (orig ? (on = orig) : (on = avl_iterate_item(&orig_tree, &it))) {

                        int fd;
                        sprintf(path_name, "%s/%s", json_orig_dir, globalIdAsString(&on->global_id));

                        if ((fd = open(path_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) {

                                dbgf_sys(DBGT_ERR, "could not open %s - %s", path_name, strerror(errno));

                        } else {

                                struct ctrl_node *cn = create_ctrl_node(fd, NULL, YES/*we are root*/);

                                struct status_handl *handl = NULL;
                                uint32_t data_len;

                                char status_name[sizeof (((struct status_handl *) NULL)->status_name)] = ARG_ORIGINATORS;

                                if ((handl = avl_find_item(&status_tree, status_name)) &&
                                        (data_len = ((*(handl->frame_creator))(handl, on)))) {

                                        json_object *jorig = json_object_new_object();
                                        json_object *jdesc_fields = NULL;

                                        if ((jdesc_fields = fields_dbg_json(
                                                FIELD_RELEVANCE_HIGH, data_len, handl->data, handl->min_msg_size, handl->format))) {

                                                json_object_object_add(jorig, handl->status_name, jdesc_fields);
                                        }

                                        const char * data = json_object_to_json_string(jorig);

                                        if (cn)
                                                dbg_printf(cn, "%s\n", data);

                                        json_object_put(jorig);
                                }


                                close_ctrl_node(CTRL_CLOSE_STRAIGHT, cn);
                        }

                        if (orig)
                                break;
                }
        }
}


STATIC_FUNC
void json_route_change_hook(uint8_t del, struct orig_node *on)
{
        json_originator_event_hook(0, on);
}

STATIC_FUNC
void json_description_event_hook(int32_t cb_id, struct orig_node *on)
{
        TRACE_FUNCTION_CALL;

        assertion(-501261, (on));
        assertion(-501249, IMPLIES(cb_id == PLUGIN_CB_DESCRIPTION_CREATED, (on && on->desc)));
        assertion(-501250, (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY || cb_id == PLUGIN_CB_DESCRIPTION_CREATED));
        assertion(-501251, IMPLIES(initializing, cb_id == PLUGIN_CB_DESCRIPTION_CREATED));
        assertion(-501252, (json_desc_dir));

        dbgf_all(DBGT_INFO, "cb_id=%d", cb_id);

        if (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY) {

                char rm_file[MAX_PATH_SIZE];
                sprintf(rm_file, "%s/%s", json_desc_dir, globalIdAsString(&on->global_id));

                dbgf_track(DBGT_WARN, "removing destroyed json-description %s", rm_file);

                if (remove(rm_file) != 0) {
                        dbgf_sys(DBGT_ERR, "could not remove %s: %s \n", rm_file, strerror(errno));
                }

        } else {

                int fd;
                char file_name[MAX_PATH_SIZE] = "";

                sprintf(file_name, "%s/%s", json_desc_dir, globalIdAsString(&on->global_id));

                if ((fd = open(file_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) { //check permissions of generated file

                        dbgf_sys(DBGT_ERR, "could not open %s - %s", file_name, strerror(errno));
                        return;
                }

                json_object *jorig = json_object_new_object();

                json_object *jhash = json_object_new_string(memAsHexString(((char*) &(on->dhn->dhash)), sizeof (on->dhn->dhash)));
                
                json_object_object_add(jorig, "descSha", jhash);

                json_object *jblocked = json_object_new_int(on->blocked);
                json_object_object_add(jorig, "blocked", jblocked);

                uint16_t tlvs_len = ntohs(on->desc->extensionLen);
                struct msg_description_adv * desc_buff =
                        debugMalloc(sizeof (struct msg_description_adv) +tlvs_len, -300361);

                desc_buff->transmitterIID4x = htons(on->dhn->myIID4orig);
                memcpy(&desc_buff->desc, on->desc, sizeof (struct description) +tlvs_len);

                json_object *jdesc_fields = NULL;

                if ((jdesc_fields = fields_dbg_json(
                        FIELD_RELEVANCE_MEDI, sizeof (struct msg_description_adv) +tlvs_len, (uint8_t*) desc_buff,
                        packet_frame_handler[FRAME_TYPE_DESC_ADV].min_msg_size,
                        packet_frame_handler[FRAME_TYPE_DESC_ADV].msg_format))) {

                        if (tlvs_len) {

                                struct rx_frame_iterator it = {
                                        .caller = __FUNCTION__, .on = on, .cn = NULL, .op = TLV_OP_PLUGIN_MIN,
                                        .handls = description_tlv_handl, .handl_max = BMX_DSC_TLV_MAX,
                                        .process_filter = FRAME_TYPE_PROCESS_ALL,
                                        .frames_in = (((uint8_t*) on->desc) + sizeof (struct description)),
                                        .frames_length = tlvs_len
                                };

                                json_object *jextensions = NULL;

                                while (rx_frame_iterate(&it) > TLV_RX_DATA_DONE) {
                                        json_object * jext_fields;

                                        if ((jext_fields = fields_dbg_json(
                                                FIELD_RELEVANCE_MEDI, it.frame_msgs_length, it.msg,
                                                it.handls[it.frame_type].min_msg_size,
                                                it.handls[it.frame_type].msg_format))) {

                                                json_object *jext = json_object_new_object();
                                                json_object_object_add(jext, it.handls[it.frame_type].name, jext_fields);

                                                jextensions = jextensions ? jextensions : json_object_new_array();

                                                json_object_array_add(jextensions, jext);
                                        }
                                }
                                if (jextensions)
                                        json_object_object_add(jdesc_fields, "extensions", jextensions);
                        }
                        json_object_object_add(jorig, packet_frame_handler[FRAME_TYPE_DESC_ADV].name, jdesc_fields);
                }

                dprintf(fd, "%s\n", json_object_to_json_string(jorig));

                json_object_put(jorig);
                debugFree(desc_buff, -300362);
                close(fd);
        }

        json_originator_event_hook(cb_id, on);
}






STATIC_FUNC
void update_json_status(void *data)
{
        assertion(-501254, (json_dir));
        assertion(-501262, (json_update_interval));

        task_register(json_update_interval, update_json_status, NULL, -300378);

        json_status_event_hook(0, NULL);
        json_dev_event_hook(0, NULL);
        json_links_event_hook(0, NULL);
        json_originator_event_hook(0, NULL);
/*
        check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_JSON_STATUS), 0, NULL);
        check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_JSON_INTERFACES), 0, NULL);
        check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_JSON_LINKS), 0, NULL);
        check_apply_parent_option(ADD, OPT_APPLY, 0, get_option(0, 0, ARG_JSON_ORIGINATORS), 0, NULL);
*/
}





STATIC_FUNC
int32_t opt_json_status(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

        if ( cmd == OPT_APPLY ) {

                struct status_handl *handl = NULL;
                uint32_t data_len;

                char status_name[sizeof (((struct status_handl *) NULL)->status_name)] = {0};
                strcpy(status_name, &opt->long_name[strlen("json_")]);

                if ((handl = avl_find_item(&status_tree, status_name)) && (data_len = ((*(handl->frame_creator))(handl, NULL)))) {

                        json_object *jorig = json_object_new_object();
                        json_object *jdesc_fields = NULL;

                        if ((jdesc_fields = fields_dbg_json(
                                FIELD_RELEVANCE_HIGH, data_len, handl->data, handl->min_msg_size, handl->format))) {

                                json_object_object_add(jorig, handl->status_name, jdesc_fields);
                        }

                        const char * data = json_object_to_json_string(jorig);

                        if (cn)
                                dbg_printf(cn, "%s\n", data);

                        json_object_put(jorig);
                }
	}
	return SUCCESS;
}


STATIC_FUNC
int32_t opt_json_update_interval(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{


        if (cmd == OPT_SET_POST && current_update_interval != json_update_interval) {

                if(current_update_interval) {
                        task_remove(update_json_status, NULL);
                        set_route_change_hooks(json_route_change_hook, DEL);
                }

                if (json_update_interval){
                        task_register(MAX(10, json_update_interval), update_json_status, NULL, -300379);
                        set_route_change_hooks(json_route_change_hook, ADD);
                }

                current_update_interval = json_update_interval;

        }

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_json_sms(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

        // this function is used to initialize all json directories

        static char tmp_json_dir[MAX_PATH_SIZE];
        static char tmp_desc_dir[MAX_PATH_SIZE];
        static char tmp_orig_dir[MAX_PATH_SIZE];
        static char tmp_sms_tx_dir[MAX_PATH_SIZE];
        static char tmp_sms_rx_dir[MAX_PATH_SIZE];

        if (initializing && !json_dir && (cmd == OPT_CHECK || cmd == OPT_APPLY || cmd == OPT_SET_POST)) {

                assertion(-501255, (strlen(run_dir) > 3));


                sprintf(tmp_json_dir, "%s/%s", run_dir, DEF_JSON_SUBDIR);

                if (check_dir(tmp_json_dir, YES/*create*/, YES/*writable*/) == FAILURE)
			return FAILURE;



                sprintf(tmp_orig_dir, "%s/%s", tmp_json_dir, DEF_JSON_ORIG_SUBDIR);

                if (check_dir(tmp_orig_dir, YES/*create*/, YES/*writable*/) == FAILURE)
                        return FAILURE;

                else if (rm_dir_content(tmp_orig_dir) == FAILURE)
                        return FAILURE;



                sprintf(tmp_desc_dir, "%s/%s", tmp_json_dir, DEF_JSON_DESC_SUBDIR);

                if (check_dir(tmp_desc_dir, YES/*create*/, YES/*writable*/) == FAILURE)
                        return FAILURE;

                else if (rm_dir_content(tmp_desc_dir) == FAILURE)
                        return FAILURE;



                sprintf(tmp_sms_rx_dir, "%s/%s", tmp_json_dir, DEF_JSON_SMS_RX_SUBDIR);

                if (check_dir(tmp_sms_rx_dir, YES/*create*/, YES/*writable*/) == FAILURE)
                        return FAILURE;

                else if (rm_dir_content(tmp_sms_rx_dir) == FAILURE)
                        return FAILURE;



                sprintf(tmp_sms_tx_dir, "%s/%s", tmp_json_dir, DEF_JSON_SMS_TX_SUBDIR);

                if (check_dir(tmp_sms_tx_dir, YES/*create*/, YES/*writable*/) == FAILURE) {

                        return FAILURE;

                } else if ((extensions_fd = inotify_init1(IN_NONBLOCK)) < 0) {

                        dbgf_sys(DBGT_ERR, "inotify_init() failed: %s \n", strerror(errno));
                        return FAILURE;

                } else if ((extensions_wd = inotify_add_watch(extensions_fd, tmp_sms_tx_dir,
                        IN_CREATE | IN_DELETE | IN_DELETE_SELF | IN_MODIFY | IN_MOVE_SELF | IN_MOVED_FROM | IN_MOVED_TO)) < 0) {

                        dbgf_sys(DBGT_ERR, "inotify_add_watch(%s) failed: %s \n", tmp_sms_tx_dir, strerror(errno));
                        return FAILURE;
                }


                json_dir =  tmp_json_dir;
                json_desc_dir = tmp_desc_dir;
                json_orig_dir = tmp_orig_dir;
                json_smsTx_dir = tmp_sms_tx_dir;
                json_smsRx_dir = tmp_sms_rx_dir;
        }



        if (cmd == OPT_SET_POST && initializing) {

                update_json_options(1, 0, JSON_OPTIONS_FILE);

                assertion(-501263, (extensions_fd > 0));
                set_fd_hook(extensions_fd, json_inotify_event_hook, ADD);

        }


        if (cmd == OPT_CHECK || cmd == OPT_APPLY) {

                if (!json_smsTx_dir)
                        return FAILURE;

                if (strlen(patch->p_val) >= MAX_JSON_SMS_NAME_LEN)
                        return FAILURE;

                if (validate_name_string(patch->p_val, strlen(patch->p_val) + 1) != SUCCESS)
                        return FAILURE;

        }

        if (cmd == OPT_SET_POST) {

                check_for_changed_sms();
        }



        return SUCCESS;
}

static struct opt_type json_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	
	{ODI,0,ARG_JSON_UPDATE,		0,  5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	&json_update_interval,	MIN_JSON_UPDATE,MAX_JSON_UPDATE,DEF_JSON_UPDATE,0,opt_json_update_interval,
                ARG_VALUE_FORM, "disable or periodically update json-status files every given milliseconds."}
        ,
	{ODI,0,ARG_JSON_SMS,	        0,  5,A_PM1N,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0,		0,		0,0,		opt_json_sms,
			ARG_PREFIX_FORM,"add arbitrary ascii data to description"}
        ,
	{ODI,0,ARG_JSON_STATUS,		0,  5,A_PS0,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_json_status,
			0,		"show status in json format\n"}
        ,
	{ODI,0,ARG_JSON_INTERFACES,	0,  5,A_PS0,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_json_status,
			0,		"show interfaces in json format\n"}
        ,
	{ODI,0,ARG_JSON_LINKS,	        0,  5,A_PS0,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_json_status,
			0,		"show links in json format\n"}
        ,
	{ODI,0,ARG_JSON_ORIGINATORS,	0,  5,A_PS0,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_json_status,
			0,		"show originators in json format\n"}


	
};


static void json_cleanup( void )
{

        if (current_update_interval) {
                set_route_change_hooks(json_route_change_hook, DEL);
        }

        if (extensions_fd > -1) {

                if( extensions_wd > -1) {
                        inotify_rm_watch(extensions_fd, extensions_wd);
                        extensions_wd = -1;
                }

                set_fd_hook(extensions_fd, json_inotify_event_hook, DEL);

                close(extensions_fd);
                extensions_fd = -1;
        }
}



static int32_t json_init( void ) {

        register_options_array(json_options, sizeof ( json_options), CODE_CATEGORY_NAME);

        static const struct field_format json_extension_format[] = DESCRIPTION_MSG_JSON_SMS_FORMAT;
        struct frame_handl tlv_handl;

        memset( &tlv_handl, 0, sizeof(tlv_handl));
        tlv_handl.min_msg_size = sizeof (struct description_msg_json_sms);
        tlv_handl.fixed_msg_size = 0;
        tlv_handl.is_relevant = 0;
        tlv_handl.name = "JSON_EXTENSION";
        tlv_handl.tx_frame_handler = create_description_sms;
        tlv_handl.rx_frame_handler = process_description_sms;
        tlv_handl.msg_format = json_extension_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_JSON_SMS, &tlv_handl);

	return SUCCESS;
}


struct plugin* get_plugin( void ) {
	
	static struct plugin json_plugin;
	
	memset( &json_plugin, 0, sizeof ( struct plugin ) );
	

	json_plugin.plugin_name = CODE_CATEGORY_NAME;
	json_plugin.plugin_size = sizeof ( struct plugin );
        json_plugin.plugin_code_version = CODE_VERSION;
	json_plugin.cb_init = json_init;
	json_plugin.cb_cleanup = json_cleanup;
        json_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_CREATED] = (void (*) (int32_t, void*)) json_description_event_hook;
        json_plugin.cb_plugin_handler[PLUGIN_CB_DESCRIPTION_DESTROY] = (void (*) (int32_t, void*)) json_description_event_hook;
        json_plugin.cb_plugin_handler[PLUGIN_CB_CONF] = json_config_event_hook;
//      json_plugin.cb_plugin_handler[PLUGIN_CB_CONF] = json_dev_event_hook;
        json_plugin.cb_plugin_handler[PLUGIN_CB_BMX_DEV_EVENT] = json_dev_event_hook;
        json_plugin.cb_plugin_handler[PLUGIN_CB_STATUS] = json_status_event_hook;
        json_plugin.cb_plugin_handler[PLUGIN_CB_LINKS_EVENT] = json_links_event_hook;

	return &json_plugin;
}


