/*
 * Copyright (C) 2010 BMX contributors:
 * Axel Neumann, Agusti Moll
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
 *
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


#include "bmx.h"
#include "plugin.h"
#include "metrics.h"
#include "ip.h"
#include "tools.h"

#define CODE_CATEGORY_NAME "gsf_map"

#define GSF_MAP_MYNAME 		"gsf_map_name"
#define GSF_MAP_LONGITUDE	"gsf_map_longitude"
#define GSF_MAP_LATITUDE	"gsf_map_latitude"
#define GSF_MAP_HW		"gsf_map_hw"
#define GSF_MAP_EMAIL		"gsf_map_email"
#define GSF_MAP_COMMENT		"gsf_map_comment"
#define GSF_MAP_LOCAL_JSON	"gsf_map_local"
#define GSF_MAP_WORLD_JSON	"gsf_map_world"


#define DEF_GSF_MAP_MYNAME 	"anonymous"
#define DEF_GSF_MAP_LONGITUDE	"0"
#define DEF_GSF_MAP_LATITUDE	"0"
#define DEF_GSF_MAP_HW		"undefined"
#define DEF_GSF_MAP_EMAIL	"anonymous@mesh.bmx"
#define DEF_GSF_MAP_COMMENT	"no-comment"

#define GSF_HELP_WORD "<WORD>"

static int32_t opt_gsf_map_local ( uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn ) {
	
	if ( cmd == OPT_APPLY  &&  cn ) {
			
		struct opt_parent *p;
		char *gsf_map_name      = (p=get_opt_parent_val( get_option( 0,0,GSF_MAP_MYNAME),    0)) ? p->p_val : DEF_GSF_MAP_MYNAME;
		char *gsf_map_longitude = (p=get_opt_parent_val( get_option( 0,0,GSF_MAP_LONGITUDE), 0)) ? p->p_val : DEF_GSF_MAP_LONGITUDE;
		char *gsf_map_latitude  = (p=get_opt_parent_val( get_option( 0,0,GSF_MAP_LATITUDE),  0)) ? p->p_val : DEF_GSF_MAP_LATITUDE;
		char *gsf_map_hw	= (p=get_opt_parent_val( get_option( 0,0,GSF_MAP_HW),        0)) ? p->p_val : DEF_GSF_MAP_HW;
		char *gsf_map_email     = (p=get_opt_parent_val( get_option( 0,0,GSF_MAP_EMAIL),     0)) ? p->p_val : DEF_GSF_MAP_EMAIL;
		//char *gsf_map_comment   = (p=get_opt_parent_val( get_option( 0,0,GSF_MAP_COMMENT),   0)) ? p->p_val : DEF_GSF_MAP_COMMENT;

                dbg_printf(cn, "Content-type: application/json\r\n\r\n");

                dbg_printf(cn,
                        //uncomment following line to get the node back
                        //"\nnode = {\n"
                        "'%s' : {\n"
                        "  'name' : '%s', 'long' : %s, 'lat' : %s, 'hw' : '%s', 'email' : '%s' , 'links' : {\n",
                        primary_dev_cfg->ip_global_str,
                        gsf_map_name, gsf_map_longitude, gsf_map_latitude, gsf_map_hw, gsf_map_email);

                struct avl_node *local_an = NULL;
                struct local_node *local;
		int count=0;



                struct avl_node *it;
                struct link_node *link;

                dbg_printf(cn, "\n");

                while ((local = avl_iterate_item(&local_tree, &local_an))) {

                        if (!(local->neigh && local->neigh->dhn && local->neigh->dhn->on))
                                continue;

                        struct orig_node *orig = local->neigh->dhn->on;

                        for (it = NULL; (link = avl_iterate_item(&local->link_tree, &it));) {

                                struct link_dev_node *lndev = NULL;

                                while ((lndev = list_iterate(&link->lndev_list, lndev))) {

                                        if (count++)
                                                dbg_printf(cn, ",\n");

                                        dbg_printf(cn, "    '%i' : {\n"
                                                "neighLocalIp: '%s', dev: '%s', rp: %3ju, tp: %3ju, "
                                                "lseq: %5i, lvld: %d, bestRp: %d, bestTp: %d, "
                                                "neighGlobalIp: '%s', neighIdName: '%s', neighIdRand: %jX"
                                                "} ",
                                                count,
                                                ipXAsStr(af_cfg, &link->link_ip),
                                                lndev->key.dev->label_cfg.str,
                                                ((lndev->timeaware_rx_probe * 100) / UMETRIC_MAX),
                                                ((lndev->timeaware_tx_probe * 100) / UMETRIC_MAX),
                                                link->rp_hello_sqn_max,
                                                ((TIME_T) (bmx_time - link->rp_time_max/*lndev->key.link->local->rp_adv_time*/)) / 1000,
                                                (lndev == link->local->best_rp_lndev ? 1 : 0),
                                                (lndev == link->local->best_tp_lndev ? 1 : 0),
                                                orig->primary_ip_str, orig->id.name, orig->id.rand.u64[0]
                                                );

                                }

                        }

		}
		dbg_printf( cn,
		         //",\n      '' : {}"
		            "\n    }\n  }\n\n"
		         //uncomment following line to get final closing bracket back
		         //"}\n\n" 
		          );
		
	}
	
	return SUCCESS;
}


static int32_t opt_gsf_map_global ( uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn ) {
	
	if ( cmd == OPT_APPLY  &&  cn ) {

                struct orig_node *on;
                struct avl_node *orig_an = NULL;
                uint32_t count = 0;

                dbg_printf(cn, "HTTP/1.1 200 OK\r\n");
                dbg_printf(cn, "Content-type: application/json\r\n\r\n");

                dbg_printf(cn, "\nall_nodes = {\n" "  '%s' : {\n", self.primary_ip_str);

                while ((on = avl_iterate_item(&orig_tree, &orig_an))) {

                        if (!on->curr_rt_local)
                                continue;

                        if (!(on->curr_rt_local->local_key && on->curr_rt_local->local_key->neigh &&
                                on->curr_rt_local->local_key->neigh->dhn && on->curr_rt_local->local_key->neigh->dhn->on))
                                continue;

                                struct orig_node * onn = on->curr_rt_local->local_key->neigh->dhn->on;

                        if (count++)
                                dbg_printf(cn, ",\n");

                        dbg_printf(cn, "    '%s' : {\n", on->primary_ip_str);

                        dbg_printf(cn,
				"      "
				"dev: '%s', via: '%s', viaPub: '%s', metric: %ju, lseq: %i, lastUpd: %i, lastValid: %i }",
                                on->curr_rt_lndev && on->curr_rt_lndev->key.dev ? on->curr_rt_lndev->key.dev->label_cfg.str : "",
                                on->curr_rt_lndev && on->curr_rt_lndev->key.link ? ipXAsStr(af_cfg, &on->curr_rt_lndev->key.link->link_ip) : "",
				onn->primary_ip_str,
                                on->curr_rt_local ? on->curr_rt_local->mr.umetric : (on == &self ? UMETRIC_MAX : 0),
				on->ogmSqn_next,
                                (bmx_time - on->updated_timestamp) / 1000,
                                (bmx_time - on->dhn->referred_by_me_timestamp) / 1000
				); 

	}
	dbg_printf( cn,
			//",\n      '' : {}"
			"\n  }\n}\n\n" );

	}

	return SUCCESS;
}


static int32_t opt_gsf_map_args ( uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn ) {
	
	if ( cmd == OPT_CHECK  ||  cmd == OPT_APPLY ) {
		
		char tmp_arg[MAX_ARG_SIZE]="0";
		
		if( wordlen( patch->p_val ) + 1 >= MAX_ARG_SIZE ) {
			dbg_cn( cn, DBGL_SYS, DBGT_ERR, "opt_gsf_map_args(): arguments: %s to long", patch->p_val );
			return FAILURE;
		}
		
		wordCopy( tmp_arg, patch->p_val );
		
		if( strpbrk( tmp_arg, "*'\"#\\/~?^°,;|<>()[]{}$%&=`´" ) ) {
			dbg_cn( cn, DBGL_SYS, DBGT_ERR, 
			        "opt_gsf_map_args(): argument: %s contains illegal symbols", tmp_arg );
			return FAILURE;
		
		}
		
		if ( patch->p_diff == ADD ) {
			
			if ( !strcmp( opt->long_name, GSF_MAP_LONGITUDE )  ||  
			     !strcmp( opt->long_name, GSF_MAP_LATITUDE ) ) 
			{
				
				char **endptr = NULL;
				errno = 0;
				
				if ( strtod( tmp_arg, endptr ) == 0  ||  errno )
					return FAILURE;
			
			}
		}
	}
	
	return SUCCESS;
}



static struct opt_type gsf_map_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	
	{ODI,0,0,			0,   5,0,0,0,0,0,				0,		0,		0,		0,		0,
			0,		"\nGraciaSenseFils (GSF) Map options:"},
		
	{ODI,0,GSF_MAP_MYNAME,	        0,   5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0, 		0,		0, 		opt_gsf_map_args,
			GSF_HELP_WORD,	"set gsf-map name"},
		
	{ODI,0,GSF_MAP_LONGITUDE,	0,   5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0, 		0,		0, 		opt_gsf_map_args,
			GSF_HELP_WORD, 	"set gsf-map longitude" },
		
	{ODI,0,GSF_MAP_LATITUDE,	0,   5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0, 		0,		0, 		opt_gsf_map_args,
			GSF_HELP_WORD, "set gsf-map latitude" },
		
	{ODI,0,GSF_MAP_HW,		0,   5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0, 		0,		0, 		opt_gsf_map_args,
			GSF_HELP_WORD, "set gsf-map hw" },
		
	{ODI,0,GSF_MAP_EMAIL,		0,   5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0, 		0,		0, 		opt_gsf_map_args,
			GSF_HELP_WORD, "set gsf-map email" },
		
	{ODI,0,GSF_MAP_COMMENT,	        0,   5,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,	0,		0, 		0,		0, 		opt_gsf_map_args,
			GSF_HELP_WORD, "set gsf-map comment (use _ between several words)" },
		
	{ODI,0,GSF_MAP_LOCAL_JSON,	0,   5,A_PS0,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0, 		opt_gsf_map_local,
			0,		"show myself and local neighborhood in JSON format" },
	
	{ODI,0,GSF_MAP_WORLD_JSON,	0,   5,A_PS0,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0, 		opt_gsf_map_global,
			0,		"show all my reachable nodes in JSON format" },
	
};


static void gsf_map_cleanup( void ) {
	
	//	remove_options_array( gsf_map_options );
	
}

static int32_t gsf_map_init( void ) {
	
	register_options_array( gsf_map_options, sizeof( gsf_map_options ), CODE_CATEGORY_NAME );
	
	return SUCCESS;
	
}


struct plugin* get_plugin( void ) {
	
	static struct plugin gsf_map_plugin;
	
	memset( &gsf_map_plugin, 0, sizeof ( struct plugin ) );
	
	gsf_map_plugin.plugin_name = "bmx_gsf_map_plugin";
	gsf_map_plugin.plugin_size = sizeof ( struct plugin );
        gsf_map_plugin.plugin_code_version = CODE_VERSION;
	gsf_map_plugin.cb_init = gsf_map_init;
	gsf_map_plugin.cb_cleanup = gsf_map_cleanup;
	
	return &gsf_map_plugin;
	
}
