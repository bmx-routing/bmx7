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


STATIC_FUNC
int32_t opt_json_test(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if ( cmd != OPT_APPLY )
		return SUCCESS;
        if (!cn)
		return FAILURE;

        static char test[10];

        json_object * jobj = json_object_new_object();
        json_object *jopts = json_object_new_array();


        json_object *jopt;
        json_object *jopt_name;

        sprintf(test, "A");
        jopt = json_object_new_object();
        jopt_name = json_object_new_string(test);
        json_object_object_add(jopt, "name", jopt_name);
        json_object_array_add(jopts, jopt);

        sprintf(test, "B");
        jopt = json_object_new_object();
        jopt_name = json_object_new_string(test);
        json_object_object_add(jopt, "name", jopt_name);
        json_object_array_add(jopts, jopt);

        sprintf(test, "C");

        json_object_object_add(jobj, "options", jopts);

        dbg_printf(cn, "%s\n", json_object_to_json_string(jobj));

        json_object_put(jobj);

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_json_descriptions(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd != OPT_APPLY )
		return SUCCESS;

        assertion(-500000, (cn));

        struct avl_node *an = NULL;
        struct orig_node *on;
        char *name = NULL;


        while ((on = avl_iterate_item(&orig_tree, &an))) {

                assertion(-500361, (!on || on->desc));

                if (name && strcmp(name, on->desc->global_id.name))
                        continue;

                dbg_printf(cn, "dhash=%s blocked=%d :\n",
                        memAsHexString(((char*) &(on->dhn->dhash)), 4), on->blocked ? 1 : 0);

                uint16_t tlvs_len = ntohs(on->desc->dsc_tlvs_len);
                struct msg_description_adv * desc_buff = debugMalloc(sizeof (struct msg_description_adv) +tlvs_len, -300361);
                desc_buff->transmitterIID4x = htons(on->dhn->myIID4orig);
                memcpy(&desc_buff->desc, on->desc, sizeof (struct description) +tlvs_len);

                dbg_printf(cn, "%s:\n", packet_frame_handler[FRAME_TYPE_DESC_ADV].name);

                fields_dbg(cn, FIELD_RELEVANCE_MEDI, sizeof (struct msg_description_adv) +tlvs_len, (uint8_t*) desc_buff,
                        packet_frame_handler[FRAME_TYPE_DESC_ADV].min_msg_size,
                        packet_frame_handler[FRAME_TYPE_DESC_ADV].msg_format);

                debugFree(desc_buff, -300362);

                struct rx_frame_iterator it = {
                        .caller = __FUNCTION__, .on = on, .cn = cn, .op = TLV_OP_PLUGIN_MIN,
                        .handls = description_tlv_handl, .handl_max = BMX_DSC_TLV_MAX, .process_filter = FRAME_TYPE_PROCESS_ALL,
                        .frames_in = (((uint8_t*) on->desc) + sizeof (struct description)), .frames_length = tlvs_len
                };

                while (rx_frame_iterate(&it) > TLV_RX_DATA_DONE) {

                        dbg_printf(it.cn, "%s:\n", it.handls[it.frame_type].name);

                        fields_dbg(it.cn, FIELD_RELEVANCE_MEDI, it.frame_msgs_length, it.msg,
                                it.handls[it.frame_type].min_msg_size, it.handls[it.frame_type].msg_format);
                }
        }

        dbg_printf(cn, "\n");

	return SUCCESS;
}


STATIC_FUNC
int32_t opt_json_help(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	if ( cmd != OPT_APPLY )
		return SUCCESS;

        assertion(-500000, (cn));

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

        dbg_printf(cn, "%s\n", json_object_to_json_string(jobj));

        json_object_put(jobj);


	if ( initializing )
		cleanup_all(CLEANUP_SUCCESS);

	return SUCCESS;
}

static struct opt_type json_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	
	{ODI, 0, ARG_JSON_DESCRIPTIONS,	0,5, A_PS0,A_USR,A_DYN,A_ARG,A_ANY,     0,              0,              0,              0,0,           opt_json_descriptions,
			0,		HLP_DESCRIPTIONS}
        ,
	{ODI,0,ARG_JSON_HELP,		0,0,A_PS0,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_json_help,
			0,		"summarize available parameters and options"}
                        ,
	{ODI,0,ARG_JSON_TEST,		0,0,A_PS0,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_json_test,
			0,		"test json options"}

	
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
	
	return &json_plugin;
}


