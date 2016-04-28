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
int32_t linkProbeDuration = DEF_LINK_PROBE_DURATION;
int32_t linkProbeTotal = DEF_LINK_PROBE_TOTAL;
int32_t linkAvgRateWeight = DEF_LINK_RATE_AVG_WEIGHT;


void get_link_rate(LinkNode *link, struct ctrl_node *cn)
{
	IFNAME_T ifname;
	strcpy(ifname.str, link->k.myDev->name_phy_cfg.str);
	char *dot_ptr;
	// if given interface is a vlan then truncate to physical interface name:
	if ((dot_ptr = strchr(ifname.str, '.')) != NULL)
		*dot_ptr = '\0';

	const struct iwinfo_ops *iw;

	if ((iw = iwinfo_backend(ifname.str))) {

		int i, len;
		char buf[IWINFO_BUFSIZE];
		struct iwinfo_assoclist_entry *e;

		if ((iw->assoclist(ifname.str, buf, &len))==0 && len > 0 ) {

			MAC_T *mac = ip6Eui64ToMac(&link->k.linkDev->key.llocal_ip, NULL);

			for (i = 0; i < len; i += sizeof(struct iwinfo_assoclist_entry)) {
				e = (struct iwinfo_assoclist_entry *) &buf[i];

				if (memcmp(e->mac, mac, sizeof(MAC_T))==0) {

					dbgf_cn(cn, DBGL_CHANGES, DBGT_INFO,
						"mac=%s signal=%d noise=%d snr=%d age=%d rxRate=%d rxCnt=%d txRate=%d txCount=%d",
						memAsHexStringSep(mac,6,1,":"),
						e->signal, e->noise, (e->signal - e->noise), e->inactive,
						e->rx_rate.rate, e->rx_rate.is_short_gi ,e->rx_packets,
						e->tx_rate.rate, e->tx_packets);

					if (link->linkStats.txPackets != e->tx_packets) {

						link->linkStats.txRate = e->tx_rate.rate * 1000;
						link->linkStats.txRateAvg = link->linkStats.txRateAvg + (link->linkStats.txRate / linkAvgRateWeight) - (link->linkStats.txRateAvg / linkAvgRateWeight);
						link->linkStats.txPackets = e->tx_packets;
						link->linkStats.tx40mhz = e->tx_rate.is_40mhz;
//						link->linkStats.txHt = e->tx_rate.is_ht;
						link->linkStats.txMcs = e->tx_rate.mcs;
//						link->linkStats.txMhz = e->tx_rate.mhz;
//						link->linkStats.txNss = e->tx_rate.nss;
						link->linkStats.txShortGi = e->tx_rate.is_short_gi;
//						link->linkStats.txVht = e->tx_rate.is_vht;

						link->linkStats.rxRate = e->rx_rate.rate * 1000;
						link->linkStats.rxPackets = e->rx_packets;
						link->linkStats.rx40mhz = e->rx_rate.is_40mhz;
//						link->linkStats.rxHt = e->rx_rate.is_ht;
						link->linkStats.rxMcs = e->rx_rate.mcs;
//						link->linkStats.rxMhz = e->rx_rate.mhz;
//						link->linkStats.rxNss = e->rx_rate.nss;
						link->linkStats.rxShortGi = e->rx_rate.is_short_gi;
//						link->linkStats.rxVht = e->rx_rate.is_vht;

						link->linkStats.signal = e->signal;
						link->linkStats.noise = e->noise;


						link->linkStats.updatedTime = bmx_time;

					} else if (((TIME_T) (bmx_time - link->linkStats.txTriggTime)) >= (TIME_T) linkProbeInterval &&
						((TIME_T) (bmx_time - link->linkStats.updatedTime)) >= (TIME_T) linkProbeInterval) {

						link->linkStats.txTriggTime = bmx_time;
						link->linkStats.txTriggCnt++;

						struct tp_test_key tk = {.duration = linkProbeDuration, .endTime = 0, .packetSize = linkProbeSize, .totalSend = 0};

						schedule_tx_task(FRAME_TYPE_TRASH_ADV, link, &link->k.linkDev->key.local->local_id, link->k.linkDev->key.local, link->k.myDev,
							tk.packetSize, &tk, sizeof(tk));

					}

					break;
				}
			}
		}


	}

	iwinfo_finish();
}

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
			
			if (!dev->upd_link_capacity)
				dev->upd_link_capacity = get_link_rate;


			if (!dev->get_iw_channel)
				dev->get_iw_channel = iwi_get_channel;


		} else {

			if (dev->get_iw_channel == iwi_get_channel)
				dev->get_iw_channel = NULL;

			if (dev->upd_link_capacity == get_link_rate)
				dev->upd_link_capacity = NULL;
		}
//	}
}



STATIC_FUNC
int32_t tx_frame_trash_adv(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	LinkNode *link = it->ttn->key.f.p.unicast;
	struct tp_test_key *tk = (struct tp_test_key*) it->ttn->key.data;
	static struct timeval tmp;
	upd_time(&tmp);
	TIME_T now = ( (tmp.tv_sec * 1000) + (tmp.tv_usec / 1000) );

	dbgf_track(DBGT_INFO, "size=%d total=%d duration=%d endTime=%d   iterations=%d dev=%s myIdx=%d src=%s unicast=%d, dst=%s nbIdx=%d neigh=%s neighId=%s",
		tk->packetSize, tk->totalSend, tk->duration, (tk->endTime ? (tk->endTime - now) : 0),
		it->ttn->tx_iterations, it->ttn->key.f.p.dev->label_cfg.str, it->ttn->key.f.p.dev->llipKey.devIdx, it->ttn->key.f.p.dev->ip_llocal_str, !!link,
		ip6AsStr(link ? &link->k.linkDev->key.llocal_ip : NULL),
		(link ? link->k.linkDev->key.devIdx : -1),
		(link ? &link->k.linkDev->key.local->on->k.hostname: NULL),
		cryptShaAsString(&it->ttn->key.f.groupId));

	if (link && tk->duration && ((tk->totalSend + tk->packetSize) <= (uint32_t)linkProbeTotal) && (!tk->endTime || (((TIME_T)(tk->endTime - now)) < tk->duration))) {

		struct tp_test_key TK = *tk;

		if (!TK.endTime)
			TK.endTime = now + TK.duration;

		TK.totalSend += TK.packetSize;

		schedule_tx_task(FRAME_TYPE_TRASH_ADV, link, &link->k.linkDev->key.local->local_id, link->k.linkDev->key.local, link->k.myDev, TK.packetSize, &TK, sizeof(TK) );
	}

	cryptRand(tx_iterator_cache_msg_ptr(it), tk->packetSize);
	return tk->packetSize;
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
	{ODI,0,ARG_LINK_PROBE_DURATION, 0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkProbeDuration,MIN_LINK_PROBE_DURATION,MAX_LINK_PROBE_DURATION, DEF_LINK_PROBE_DURATION,0,0,
			ARG_VALUE_FORM, HLP_LINK_PROBE_DURATION},
	{ODI,0,ARG_LINK_PROBE_TOTAL,    0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkProbeTotal,MIN_LINK_PROBE_TOTAL,MAX_LINK_PROBE_TOTAL, DEF_LINK_PROBE_TOTAL,0,0,
			ARG_VALUE_FORM, HLP_LINK_PROBE_TOTAL},
	{ODI,0,ARG_LINK_RATE_AVG_WEIGHT,0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkAvgRateWeight,MIN_LINK_RATE_AVG_WEIGHT,MAX_LINK_RATE_AVG_WEIGHT, DEF_LINK_RATE_AVG_WEIGHT,0,0,
			ARG_VALUE_FORM, HLP_LINK_RATE_AVG_WEIGHT},


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


