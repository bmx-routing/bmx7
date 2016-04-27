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
#include "bmx7_iwinfo.h"

#include "iwinfo.h"


#define CODE_CATEGORY_NAME "bmx7_iwinfo"


int32_t linkProbeInterval = DEF_LINK_PROBE_IVAL;
int32_t linkProbeSize = DEF_LINK_PROBE_SIZE;

uint16_t iwi_get_channel(struct dev_node *dev)
{
	uint16_t channel = TYP_DEV_CHANNEL_SHARED;

	IFNAME_T ifname;
	strcpy(ifname.str, dev->name_phy_cfg.str);
	char *dot_ptr;
	// if given interface is a vlan then truncate to physical interface name:
	if ((dot_ptr = strchr(ifname.str, '.')) != NULL)
		*dot_ptr = '\0';

	const struct iwinfo_ops *iw;

	if ((iw = iwinfo_backend(ifname.str))) {

		int ch;
		if ((iw->channel(ifname.str, &ch)) == 0 && ch > 0 && ch < TYP_DEV_CHANNEL_SHARED) {
			channel = ch;
		} else {
			dbgf_sys(DBGT_ERR, "Failed accessing channel?=%d for dev=%s", ch, ifname.str);
		}
	}

	iwinfo_finish();

	return channel;
}

STATIC_FUNC
void init_iwinfo_handler(int32_t cb_id, void* devp)
{
	struct dev_node *dev = devp;
//	struct avl_node *an;
//	for (an = NULL; (dev = avl_iterate_item(&dev_name_tree, &an));) {

		if (dev->active) {
			
			if (!dev->upd_link_capacity) {

			}

			if (!dev->get_iw_channel) {

				dev->get_iw_channel = iwi_get_channel;

			}

		} else {

			if (dev->get_iw_channel == iwi_get_channel)
				dev->get_iw_channel = NULL;
		}
//	}
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
	capacity_plugin.cb_plugin_handler[PLUGIN_CB_BMX_DEV_EVENT] = init_iwinfo_handler;

	return &capacity_plugin;
}


