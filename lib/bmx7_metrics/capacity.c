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
#include "key.h"
#include "sec.h"
#include "metrics.h"
#include "ogm.h"
#include "msg.h"
#include "desc.h"
#include "content.h"
#include "plugin.h"
#include "schedule.h"
#include "tools.h"
#include "iptools.h"
#include "ip.h"
#include "allocate.h"
#include "capacity.h"


#define CODE_CATEGORY_NAME "capacity"


int32_t linkProbeInterval = DEF_LINK_PROBE_IVAL;
int32_t linkProbeSize = DEF_LINK_PROBE_SIZE;

void upd_ath_capacity(LinkNode *link, struct ctrl_node *cn)
{

	struct dirent *baseDirEnt;
	DIR *baseDirDIR;
	char *baseDirName = ATH_RC_STATS_BASE_DIR;
	uint32_t okTx = 0;
	float tptfM = 0;

	dbgf_cn(cn, DBGL_CHANGES, DBGT_INFO, "trying opendir=%s\n", baseDirName);

	if ((baseDirDIR = opendir(baseDirName))) {

		while ((baseDirEnt = readdir(baseDirDIR))) {

			dbgf_cn(cn, DBGL_CHANGES, DBGT_INFO, "trying dirent=%s\n", baseDirEnt->d_name);

			if (!strncmp(baseDirEnt->d_name, ATH_RC_STATS_PHY_PREFIX, strlen(ATH_RC_STATS_PHY_PREFIX))) {

				FILE *fpA = NULL;
				char *line = NULL;
				size_t len = 0;
				ssize_t read;
				char txtFileName[MAX_PATH_SIZE];
				char *mac = strToLower(memAsHexStringSep(ip6Eui64ToMac(&link->k.linkDev->key.llocal_ip, NULL), 6, 1, ":"));
				IFNAME_T phy_name = link->k.myDev->name_phy_cfg;
				char *dotPtr;
				if ((dotPtr = strchr(phy_name.str, '.')) != NULL)
					*dotPtr = '\0';

				sprintf(txtFileName, "%s/%s/%s%s/%s/%s/%s",
					baseDirName, baseDirEnt->d_name, ATH_RC_STATS_DEVS_DIR, phy_name.str, ATH_RC_STATS_MACS_DIR, mac, ATH_RC_STATS_FILE_TXT);

				dbgf_cn(cn, DBGL_CHANGES, DBGT_INFO, "trying fopen A=%s \n", txtFileName);

				if ((fpA = fopen(txtFileName, "r"))) {

					dbg_printf(cn, "succeeded file=%s\n", txtFileName);

					while ((read = getline(&line, &len, fpA)) != -1) {

						dbgf_all(DBGT_INFO, "Retrieved len=%3zu %3zu: %s", read, len, line);
						if ((read >= ATH_RC_STATS_FILE_TXT_LEN) && (len > ATH_RC_STATS_FILE_TXT_LEN) &&
							(line[ATH_RC_STATS_FILE_TXT_POS_P] == 'P') && (line[ATH_RC_STATS_FILE_TXT_POS_OE] == '(') &&
							((line[ATH_RC_STATS_FILE_TXT_POS_OE] = 0) || 1) &&
							(sscanf(&line[ATH_RC_STATS_FILE_TXT_POS_O], "%u", &okTx)) &&
							(sscanf(&line[ATH_RC_STATS_FILE_TXT_POS_T], "%f", &tptfM))
							) {

							UMETRIC_T tptib = ((UMETRIC_T) (1000 * 1000 * tptfM));

								dbgf_cn(cn, DBGL_CHANGES, DBGT_INFO, "above tx=%u prevTx=%u tptfM=%f tptib=%ju\n", okTx, link->macTxPackets, tptfM, tptib);

							if (link->macTxPackets != okTx) {

								link->macTxTP = tptib;
								link->macTxPackets = okTx;
								link->macUpdated = bmx_time;

							} else if (((TIME_T) (bmx_time - link->macTxTriggered)) >= (TIME_T) linkProbeInterval &&
								((TIME_T) (bmx_time - link->macUpdated)) >= (TIME_T) linkProbeInterval) {

								link->macTxTriggered = bmx_time;

								schedule_tx_task(FRAME_TYPE_TRASH_ADV, link, &link->k.linkDev->key.local->local_id, link->k.linkDev->key.local, link->k.myDev,
									linkProbeSize, &linkProbeSize, sizeof(linkProbeSize));

							}
							break;
						}
					}

					dbg_printf(cn, "\n");

					fclose(fpA);
					if (line)
						free(line);

					break;
				}
			}
		}
		closedir(baseDirDIR);
	}
	return;
}

STATIC_FUNC
void init_ath_capacity_handler(int32_t cb_id, void* devp)
{
        struct dev_node *dev;
        struct avl_node *an;

        for (an = NULL; (dev = avl_iterate_item(&dev_name_tree, &an));) {

		if (dev->active && !dev->upd_link_capacity) {

			struct dirent *baseDirEnt;
			DIR *baseDirDIR;
			char *baseDirName = ATH_RC_STATS_BASE_DIR;
			dbgf_track(DBGT_INFO, "trying opendir=%s\n", baseDirName);

			if ((baseDirDIR = opendir(baseDirName))) {

				while ((baseDirEnt = readdir(baseDirDIR))) {

					dbgf_track(DBGT_INFO, "trying dirent=%s\n", baseDirEnt->d_name);

					if (!strncmp(baseDirEnt->d_name, ATH_RC_STATS_PHY_PREFIX, strlen(ATH_RC_STATS_PHY_PREFIX))) {

						char statsDirName[MAX_PATH_SIZE];
						IFNAME_T phy_name = dev->name_phy_cfg;
						char *dotPtr;

						if ((dotPtr = strchr(phy_name.str, '.')) != NULL)
							*dotPtr = '\0';

						sprintf(statsDirName, "%s/%s/%s%s/", baseDirName, baseDirEnt->d_name, ATH_RC_STATS_DEVS_DIR, phy_name.str);

						if (check_dir(statsDirName, NO, NO, NO) == SUCCESS) {
							dev->upd_link_capacity = upd_ath_capacity;
							dbgf_sys(DBGT_INFO, "found driver statistics directory=%s", statsDirName);
							break;
						}
					}
				}
				closedir(baseDirDIR);
			}
                }
        }
}


STATIC_FUNC
int32_t opt_capacity(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{
        TRACE_FUNCTION_CALL;

	if ( cmd != OPT_APPLY )
		return SUCCESS;

	LinkNode *link;
	struct avl_node *an = NULL;

	while ((link = avl_iterate_item(&link_tree, &an))) {

		if (link->k.myDev->upd_link_capacity)
			(*(link->k.myDev->upd_link_capacity))(link, cn);
		
	}

        return SUCCESS;
}

STATIC_FUNC
int32_t tx_frame_trash_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	uint32_t *trashSize = (uint32_t*) it->ttn->key.data;

	dbgf_track(DBGT_INFO, "size=%d iterations=%d dev=%s myIdx=%d src=%s unicast=%d, dst=%s nbIdx=%d neigh=%s neighId=%s",
		*trashSize, it->ttn->tx_iterations, it->ttn->key.f.p.dev->label_cfg.str, it->ttn->key.f.p.dev->llipKey.devIdx, it->ttn->key.f.p.dev->ip_llocal_str, !!it->ttn->key.f.p.unicast,
		ip6AsStr(it->ttn->key.f.p.unicast ? &it->ttn->key.f.p.unicast->k.linkDev->key.llocal_ip : NULL),
		(it->ttn->key.f.p.unicast ? it->ttn->key.f.p.unicast->k.linkDev->key.devIdx : -1),
		(it->ttn->key.f.p.unicast ? &it->ttn->key.f.p.unicast->k.linkDev->key.local->on->k.hostname: NULL),
		cryptShaAsString(&it->ttn->key.f.groupId));

	cryptRand(tx_iterator_cache_msg_ptr(it), *trashSize);
	return *trashSize;
}


STATIC_FUNC
int32_t rx_frame_trash_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	dbgf_track(DBGT_INFO, "size=%d dev=%s unicast=%d src=%s claimedId=%s",
		it->f_dlen, it->pb->i.iif->label_cfg.str, it->pb->i.unicast, it->pb->i.llip_str, cryptShaAsShortStr(&it->pb->p.hdr.keyHash));

	return it->f_msgs_len;
}

static struct opt_type capacity_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help
	{ODI,0,ARG_LINK_PROBE_IVAL,     0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkProbeInterval,MIN_LINK_PROBE_IVAL,MAX_LINK_PROBE_IVAL,DEF_LINK_PROBE_IVAL,0,0,
			ARG_VALUE_FORM, HLP_LINK_PROBE_IVAL},
	{ODI,0,ARG_LINK_PROBE_SIZE,     0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkProbeSize,MIN_LINK_PROBE_SIZE,MAX_LINK_PROBE_SIZE, DEF_LINK_PROBE_SIZE,0,0,
			ARG_VALUE_FORM, HLP_LINK_PROBE_SIZE},
	{ODI,0,ARG_ATH_STATS,		0,9,2,A_PS0,A_USR,A_DYI,A_ARG,A_ANY,	0,		0, 		0,		0,0, 		opt_capacity,
			0,		"show ath link statistics"},

};


static void capacity_cleanup( void )
{
}



static int32_t capacity_init( void )
{

        struct frame_handl handl;
        memset(&handl, 0, sizeof ( handl));

        handl.name = "TRASH_ADV";
	handl.rx_processUnVerifiedLink = 1;
        handl.min_msg_size = 1;
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = tx_frame_trash_adv;
        handl.rx_frame_handler = rx_frame_trash_adv;
        register_frame_handler(packet_frame_db, FRAME_TYPE_TRASH_ADV, &handl);


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
	capacity_plugin.cb_plugin_handler[PLUGIN_CB_BMX_DEV_EVENT] = init_ath_capacity_handler;

	return &capacity_plugin;
}


