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


#include "bmx.h"
#include "msg.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "ip.h"
#include "json.h"


#define CODE_CATEGORY_NAME "json"

static char json_dir[MAX_PATH_SIZE] = DEF_JSON_DIR;
static char json_desc_dir[MAX_PATH_SIZE];

STATIC_FUNC
uint32_t fields_dbg_json(int fd, uint16_t relevance, uint16_t data_size, uint8_t *data,
                    uint16_t min_msg_size, const struct field_format *format)
{
        TRACE_FUNCTION_CALL;
        assertion(-500000, (format && data && fd));

        uint32_t msgs_size = 0;
        struct field_iterator it = {.format = format, .data = data, .data_size = data_size, .min_msg_size = min_msg_size};

        while ((msgs_size = field_iterate(&it)) == SUCCESS) {

                if (format[it.field].field_relevance >= relevance) {
                        dprintf(fd, " %s=%s", format[it.field].field_name,
                                field_dbg_value(&format[it.field], min_msg_size, data, it.field_bit_pos, it.field_bits));
                }

                if (format[it.field + 1].field_type == FIELD_TYPE_END)
                        dprintf(fd, "\n");


        }

        assertion(-500000, (data_size ? msgs_size == data_size : msgs_size == min_msg_size));

        return msgs_size;
}



STATIC_FUNC
void json_description_event_hook(int32_t cb_id, struct orig_node *on)
{
        TRACE_FUNCTION_CALL;

        assertion(-500000, (on && on->desc));
        assertion(-500000, (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY || cb_id == PLUGIN_CB_DESCRIPTION_CREATED));
        assertion(-500000, IMPLIES(initializing, cb_id == PLUGIN_CB_DESCRIPTION_CREATED));

        dbgf_all(DBGT_INFO, "cb_id=%d", cb_id);

        if (cb_id == PLUGIN_CB_DESCRIPTION_DESTROY) {
                dbgf_track(DBGT_WARN, "keeping destroyed json-description of orig=%s", globalIdAsString(&on->global_id));
                return;
        }

        int fd;
        char file_name[MAX_PATH_SIZE] = "";

        sprintf(file_name, "%s/%s", json_desc_dir, globalIdAsString(&on->global_id));

        if ((fd = open(file_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) { //check permissions of generated file

		dbgf_sys(DBGT_ERR, "could not open %s - %s", file_name, strerror(errno) );
                return;
	}

        dprintf(fd, "dhash=%s blocked=%d :\n", memAsHexString(((char*) &(on->dhn->dhash)), 4), on->blocked ? 1 : 0);

        uint16_t tlvs_len = ntohs(on->desc->dsc_tlvs_len);
        struct msg_description_adv * desc_buff = debugMalloc(sizeof (struct msg_description_adv) +tlvs_len, -300361);
        desc_buff->transmitterIID4x = htons(on->dhn->myIID4orig);
        memcpy(&desc_buff->desc, on->desc, sizeof (struct description) +tlvs_len);

        dprintf(fd, "%s:\n", packet_frame_handler[FRAME_TYPE_DESC_ADV].name);

        fields_dbg_json(fd, FIELD_RELEVANCE_MEDI, sizeof (struct msg_description_adv) +tlvs_len, (uint8_t*) desc_buff,
                packet_frame_handler[FRAME_TYPE_DESC_ADV].min_msg_size,
                packet_frame_handler[FRAME_TYPE_DESC_ADV].msg_format);

        debugFree(desc_buff, -300362);

        struct rx_frame_iterator it = {
                .caller = __FUNCTION__, .on = on, .cn = NULL, .op = TLV_OP_PLUGIN_MIN,
                .handls = description_tlv_handl, .handl_max = BMX_DSC_TLV_MAX, .process_filter = FRAME_TYPE_PROCESS_ALL,
                .frames_in = (((uint8_t*) on->desc) + sizeof (struct description)), .frames_length = tlvs_len
        };

        while (rx_frame_iterate(&it) > TLV_RX_DATA_DONE) {

                dprintf(fd, "%s:\n", it.handls[it.frame_type].name);

                fields_dbg_json(fd, FIELD_RELEVANCE_MEDI, it.frame_msgs_length, it.msg,
                        it.handls[it.frame_type].min_msg_size, it.handls[it.frame_type].msg_format);
        }

        dprintf(fd, "\n");
        close(fd);
}

STATIC_FUNC
int32_t update_json_help(void)
{
        int fd;
        char file_name[MAX_PATH_SIZE + 20] = "";

        sprintf(file_name, "%s/%s", json_dir, JSON_OPTIONS_FILE);

        if ((fd = open(file_name, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)) < 0) { //check permissions of generated file

		dbgf_sys(DBGT_ERR, "could not open %s - %s", file_name, strerror(errno) );
		return FAILURE;
	}


        struct opt_type * p_opt = NULL;
        json_object * jobj = json_object_new_object();
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

        json_object_object_add(jobj, "options", jopts);

        dprintf(fd, "%s\n", json_object_to_json_string(jobj));

        json_object_put(jobj);

        close(fd);

	return SUCCESS;
}






STATIC_FUNC
int32_t opt_json_dir(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	char tmp_dir[MAX_PATH_SIZE];
        strcpy(tmp_dir, json_dir);

        assertion(-500000, IMPLIES((cmd == OPT_CHECK || cmd == OPT_APPLY), initializing));


	if ( cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {

		if ( wordlen( patch->p_val )+1 >= MAX_PATH_SIZE  ||  patch->p_val[0] != '/' )
			return FAILURE;

		snprintf( tmp_dir, wordlen(patch->p_val)+1, "%s", patch->p_val );
        }

        if (cmd == OPT_CHECK || cmd == OPT_APPLY || (cmd == OPT_SET_POST && initializing)) {

                if (check_dir(tmp_dir, YES/*create*/, YES/*writable*/) == FAILURE)
			return FAILURE;


                sprintf(json_desc_dir, "%s/%s", tmp_dir, DEF_JSON_DESC_DIR);

                if (check_dir(json_desc_dir, YES/*create*/, YES/*writable*/) == FAILURE)
			return FAILURE;
        }


        if (cmd == OPT_APPLY) {

                strcpy(json_dir, tmp_dir);
        }

        if (cmd == OPT_SET_POST && initializing) {

                update_json_help();
        }

	return SUCCESS;
}






static struct opt_type json_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	
	{ODI,0,ARG_JSON_DIR,		0,5, A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_JSON_DIR,	opt_json_dir,
			ARG_DIR_FORM,	"set DIR of json related files and subdirectories"}

	
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


