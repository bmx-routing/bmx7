/*
 * Copyright (c) 2015  Axel Neumann
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
#include <stdarg.h>
#include <syslog.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <paths.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <dirent.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "metrics.h"
#include "msg.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "ip.h"
#include "allocate.h"
#include "capacity.h"


#define CODE_CATEGORY_NAME "capacity"


int32_t linkProbeInterval = DEF_LINK_PROBE_IVAL;



STATIC_FUNC
int32_t opt_capacity(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd != OPT_APPLY )
		return SUCCESS;

	LinkNode *link;
	struct avl_node *an = NULL;

	while ((link = avl_iterate_item(&link_tree, &an))) {

		struct dirent *baseDirEnt;
		DIR *baseDirDIR;
		char *baseDirName = ATH_RC_STATS_BASE_DIR;
		int okTx = 0;
		float tptfM = 0;
		UMETRIC_T tptib = 0;


		dbg_printf(cn, "trying opendir=%s\n", baseDirName);

		if ((baseDirDIR = opendir(baseDirName))) {

			while ((baseDirEnt = readdir(baseDirDIR))) {

				dbg_printf(cn, "trying dirent=%s\n", baseDirEnt->d_name);

				if (!strncmp(baseDirEnt->d_name, ATH_RC_STATS_PHY_PREFIX, strlen(ATH_RC_STATS_PHY_PREFIX))) {

					FILE *fpA = NULL, *fpB = NULL;
					char *line = NULL;
					size_t len = 0;
					ssize_t read;
					char txtFileNameA[MAX_PATH_SIZE];
					char txtFileNameB[MAX_PATH_SIZE];
					uint8_t *m = &link->k.linkDev->key.llocal_ip.s6_addr[0];

					sprintf(txtFileNameA, "%s/%s/%s%s/%s/%.2x:%.2x:%.2x:%.2x:%.2x:%.2x/%s",
						baseDirName, baseDirEnt->d_name, ATH_RC_STATS_DEVS_DIR, link->k.myDev->label_cfg.str, ATH_RC_STATS_MACS_DIR,
						m[8], m[9], m[10], m[13], m[14], m[15],
						ATH_RC_STATS_FILE_TXT);

					sprintf(txtFileNameB, "%s/%s/%s%s/%s/%.2x:%.2x:%.2x:%.2x:%.2x:%.2x/%s",
						baseDirName, baseDirEnt->d_name, ATH_RC_STATS_DEVS_DIR, link->k.myDev->label_cfg.str, ATH_RC_STATS_MACS_DIR,
						(m[8] & 0xFD), m[9], m[10], m[13], m[14], m[15],
						ATH_RC_STATS_FILE_TXT);

					dbg_printf(cn, "trying fopen A=%s B=%s\n", txtFileNameA, txtFileNameB);


					if ((fpA = fopen(txtFileNameA, "r")) || (fpB = fopen(txtFileNameB, "r"))) {

						FILE *fp = fpA ? fpA : fpB;
						dbg_printf(cn, "succeeded file=%s\n", fpA ? txtFileNameA : txtFileNameB);

						while ((read = getline(&line, &len, fp)) != -1) {

							dbgf_all(DBGT_INFO, "Retrieved len=%3zu %3zu: %s", read, len, line);
							if ((read >= ATH_RC_STATS_FILE_TXT_LEN) && (len > ATH_RC_STATS_FILE_TXT_LEN) &&
								(line[ATH_RC_STATS_FILE_TXT_POS_P] == 'P') && (line[ATH_RC_STATS_FILE_TXT_POS_OE] == '(') &&
								((line[ATH_RC_STATS_FILE_TXT_POS_OE] = 0) || 1) &&
								(sscanf(&line[ATH_RC_STATS_FILE_TXT_POS_O], "%d", &okTx)) &&
								(sscanf(&line[ATH_RC_STATS_FILE_TXT_POS_T], "%f", &tptfM)) &&
								(tptib = 1000*1000*((UMETRIC_T)tptfM))
								) {

								dbg_printf(cn, "above ok=%d tptfM=%f tptib=%d\n", okTx, tptfM, tptib);
								break;
							}
						}

						dbg_printf(cn, "\n");

						fclose(fp);
						if (line)
							free(line);

					}
				}
			}
			closedir(baseDirDIR);
		}
	}

        return SUCCESS;
}


static struct opt_type capacity_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	{ODI,0,ARG_LINK_PROBE_IVAL,     0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkProbeInterval,MIN_LINK_PROBE_IVAL,MAX_LINK_PROBE_IVAL,DEF_LINK_PROBE_IVAL,0,0,
			ARG_VALUE_FORM, HLP_LINK_PROBE_IVAL},
	{ODI,0,ARG_ATH_STATS,		0,9,2,A_PS0,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_capacity,
			0,		"show ath link statistics"},

};


static void capacity_cleanup( void )
{
}



static int32_t capacity_init( void )
{


        register_options_array(capacity_options, sizeof ( capacity_options), CODE_CATEGORY_NAME);

	return SUCCESS;
}


struct plugin* get_plugin( void ) {
	
	static struct plugin capacity_plugin;
	
	memset( &capacity_plugin, 0, sizeof ( struct plugin ) );
	

	capacity_plugin.plugin_name = CODE_CATEGORY_NAME;
	capacity_plugin.plugin_size = sizeof ( struct plugin );
	capacity_plugin.cb_init = capacity_init;
	capacity_plugin.cb_cleanup = capacity_cleanup;

	return &capacity_plugin;
}


