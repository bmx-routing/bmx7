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

#include "bmx.h"
#include "msg.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "ip.h"
#include "json.h"


#define CODE_CATEGORY_NAME "json"


static char json_dir[MAX_PATH_SIZE] = JSON_ILLEGAL_DIR;
static char json_desc_dir[MAX_PATH_SIZE] = JSON_ILLEGAL_DIR;


STATIC_FUNC
json_object * fields_dbg_json(uint16_t relevance, uint16_t data_size, uint8_t *data,
                    uint16_t min_msg_size, const struct field_format *format)
{
        TRACE_FUNCTION_CALL;
        assertion(-501247, (format && data ));

        uint32_t msgs_size = 0;
        struct field_iterator it = {.format = format, .data = data, .data_size = data_size, .min_msg_size = min_msg_size};
        
        json_object *jfields = NULL;


        while ((msgs_size = field_iterate(&it)) == SUCCESS) {

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
        }

        assertion(-501248, (data_size ? msgs_size == data_size : msgs_size == min_msg_size));
        return jfields;
}



STATIC_FUNC
void json_description_event_hook(int32_t cb_id, struct orig_node *on)
{
        TRACE_FUNCTION_CALL;

        assertion(-500000, (on));
        assertion(-501249, IMPLIES(cb_id == PLUGIN_CB_DESCRIPTION_CREATED, (on && on->desc)));
        assertion(-501250, (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY || cb_id == PLUGIN_CB_DESCRIPTION_CREATED));
        assertion(-501251, IMPLIES(initializing, cb_id == PLUGIN_CB_DESCRIPTION_CREATED));
        assertion(-501252, (strcmp(json_desc_dir, JSON_ILLEGAL_DIR)));

        dbgf_all(DBGT_INFO, "cb_id=%d", cb_id);

        if (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY) {
                dbgf_track(DBGT_WARN, "removing destroyed json-description of orig=%s", globalIdAsString(&on->global_id));
                char rm_file[MAX_PATH_SIZE];
                sprintf(rm_file, "%s/%s", json_desc_dir, globalIdAsString(&on->global_id));
                if (remove(rm_file) != 0) {
                        dbgf_sys(DBGT_ERR, "could not remove %s: %s \n", rm_file, strerror(errno));
                }
                return;
        }

        int fd;
        char file_name[MAX_PATH_SIZE] = "";

        sprintf(file_name, "%s/%s", json_desc_dir, globalIdAsString(&on->global_id));

        if ((fd = open(file_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) { //check permissions of generated file

		dbgf_sys(DBGT_ERR, "could not open %s - %s", file_name, strerror(errno) );
                return;
	}

        json_object *jorig = json_object_new_object();

        json_object *jhash = json_object_new_string(memAsHexString(((char*) &(on->dhn->dhash)), sizeof (on->dhn->dhash)));
        json_object_object_add(jorig, "sha", jhash);

        json_object *jblocked = json_object_new_int(on->blocked);
        json_object_object_add(jorig, "blocked", jblocked);

        uint16_t tlvs_len = ntohs(on->desc->dsc_tlvs_len);
        struct msg_description_adv * desc_buff = debugMalloc(sizeof (struct msg_description_adv) +tlvs_len, -300361);
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
                                .handls = description_tlv_handl, .handl_max = BMX_DSC_TLV_MAX, .process_filter = FRAME_TYPE_PROCESS_ALL,
                                .frames_in = (((uint8_t*) on->desc) + sizeof (struct description)), .frames_length = tlvs_len
                        };

                        json_object *jextensions = NULL;

                        while (rx_frame_iterate(&it) > TLV_RX_DATA_DONE) {
                                json_object * jext_fields;

                                if ((jext_fields = fields_dbg_json(
                                        FIELD_RELEVANCE_MEDI, it.frame_msgs_length, it.msg,
                                        it.handls[it.frame_type].min_msg_size, it.handls[it.frame_type].msg_format))) {

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

STATIC_FUNC
int32_t update_json_parameters(void)
{
        assertion(-501253, (strcmp(json_dir, JSON_ILLEGAL_DIR)));

}


STATIC_FUNC
int32_t update_json_help(void)
{
        assertion(-501254, (strcmp(json_dir, JSON_ILLEGAL_DIR)));

        int fd;
        char file_name[MAX_PATH_SIZE + 20] = "";

        sprintf(file_name, "%s/%s", json_dir, JSON_OPTIONS_FILE);

        if ((fd = open(file_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) { //check permissions of generated file

		dbgf_sys(DBGT_ERR, "could not open %s - %s", file_name, strerror(errno) );
		return FAILURE;
	}


        struct opt_type * p_opt = NULL;
        json_object *jopts = json_object_new_array();

        while ((p_opt = list_iterate(&opt_list, p_opt))) {

                if (p_opt->parent_name)
                        continue;

                assertion(-501240, (p_opt->long_name));

                json_object *jopt = json_object_new_object();

                json_object *jopt_name = json_object_new_string(p_opt->long_name);
                json_object_object_add(jopt, "name", jopt_name);

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

                                json_object *jopt_name = json_object_new_string(p_opt->long_name);
                                json_object_object_add(jchild, "name", jopt_name);



                                json_object_array_add(jchilds, jchild);
                        }
                        json_object_object_add(jopt, "child_options", jchilds);
                }
                json_object_array_add(jopts, jopt);
        }

        json_object * jobj = json_object_new_object();

        json_object_object_add(jobj, "options", jopts);

        dprintf(fd, "%s\n", json_object_to_json_string(jobj));

        json_object_put(jobj);

        close(fd);

	return SUCCESS;
}





STATIC_FUNC
int32_t opt_json_dir(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        if (cmd == OPT_CHECK || cmd == OPT_APPLY) {

                if (strcmp(patch->p_val, opt->sdef))
                        return FAILURE;
        }


        if (cmd == OPT_SET_POST && initializing) {

                char tmp_dir[MAX_PATH_SIZE];
                char tmp_desc_dir[MAX_PATH_SIZE];

                assertion(-501255, (strlen(run_dir) > 3));

                sprintf(tmp_dir, "%s/%s", run_dir, DEF_JSON_SUBDIR);

                if (check_dir(tmp_dir, YES/*create*/, YES/*writable*/) == FAILURE)
			return FAILURE;

                sprintf(tmp_desc_dir, "%s/%s", tmp_dir, DEF_JSON_DESC_SUBDIR);

                if (check_dir(tmp_desc_dir, YES/*create*/, YES/*writable*/) == FAILURE) {

                        return FAILURE;

                } else {

                        struct dirent *d;
                        DIR *dir = opendir(tmp_desc_dir);

                        while ((d = readdir(dir))) {
                                
                                char rm_file[MAX_PATH_SIZE];
                                sprintf(rm_file, "%s/%s", tmp_desc_dir, d->d_name);

                                if (validate_name_string(d->d_name, strlen(d->d_name)+1) == SUCCESS) {

                                        dbgf_sys(DBGT_WARN, "removing stale json file: %s \n", rm_file);

                                        if (remove(rm_file) != 0) {
                                                dbgf_sys(DBGT_ERR, "could not remove %s: %s \n", rm_file, strerror(errno));
                                                return FAILURE;
                                        }

                                } else {
                                        dbgf_all(DBGT_ERR, "keeping non-json file: %s\n", rm_file);
                                }
                        }
                }

                strcpy(json_dir, tmp_dir);
                strcpy(json_desc_dir, tmp_desc_dir);

                update_json_help();
                update_json_parameters();

        }
	return SUCCESS;
}






static struct opt_type json_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	
	{ODI,0,ARG_JSON_SUBDIR,		0,5, A_PS1N,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_JSON_SUBDIR,	opt_json_dir,
                ARG_DIR_FORM, "set json subdirectorywithing runtime_dir (currently only default value allowed)"}

	
};


static void json_cleanup( void ) {
	
	
}

static int32_t json_init( void ) {

        register_options_array(json_options, sizeof ( json_options), CODE_CATEGORY_NAME);
	
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

	return &json_plugin;
}


