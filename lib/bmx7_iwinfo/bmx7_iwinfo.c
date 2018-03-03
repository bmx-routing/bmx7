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
#include "link.h"
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

static int32_t linkBurstThreshold = DEF_LINK_BURST_THRESHOLD;
static int32_t linkBurstInterval = DEF_LINK_BURST_IVAL;
static int32_t linkBurstPacketSize = DEF_LINK_BURST_PACKETSZ;
static int32_t linkBurstDuration = DEF_LINK_BURST_DURATION;
static int32_t linkBurstBytes = DEF_LINK_BURST_BYTES;

static int32_t linkProbeInterval = DEF_LINK_PROBE_IVAL;
static int32_t linkProbePacketSize = DEF_LINK_PROBE_PACKETSZ;

static int32_t linkAvgRateWeight = DEF_LINK_RATE_AVG_WEIGHT;


void get_link_rate(struct dev_node *tDev)
{
	IDM_T TODO_use_nl_tiny_lib_instead;

	if (tDev->linklayer == TYP_DEV_LL_WIFI  && tDev->active && (
		(linkProbeInterval && (!tDev->upd_link_capacities_time || (((TIME_T) (bmx_time - tDev->upd_link_capacities_time)) >= (TIME_T) linkProbeInterval))) ||
		(linkBurstInterval && (!tDev->upd_link_capacities_time || (((TIME_T) (bmx_time - tDev->upd_link_capacities_time)) >= (TIME_T) linkBurstInterval)))
		)) {
		
		dbgf_track(DBGT_INFO, "dev=%s phy=%s probeInterval=%d burstInterval=%d last=%d",
			tDev->ifname_label.str, tDev->ifname_phy.str, linkProbeInterval, linkBurstInterval, tDev->upd_link_capacities_time);

		struct dev_node *oDev;
		struct avl_node *oDAn;
		for (oDAn = NULL; (oDev = avl_iterate_item(&dev_name_tree, &oDAn));) {
			if (oDev->linklayer == TYP_DEV_LL_WIFI && oDev->active && !strcmp(tDev->ifname_phy.str, oDev->ifname_phy.str))
				oDev->upd_link_capacities_time = bmx_time;
		}

		const struct iwinfo_ops *iw;
		int i, len;
		static char buf[IWINFO_BUFSIZE];
		struct iwinfo_assoclist_entry *e = NULL;
		LinkNode *oLink;
		struct avl_node *oLAn;
		static uint16_t wifiStatsUpdSqn;

		wifiStatsUpdSqn++;

		if ((iw = iwinfo_backend(tDev->ifname_phy.str)) && ((iw->assoclist(tDev->ifname_phy.str, buf, &len)) == 0 && len > 0)) {

			for (i = 0; i < len; i += sizeof(struct iwinfo_assoclist_entry)) {

				e = (struct iwinfo_assoclist_entry *) &buf[i];

				for (oLAn = NULL;(oLink = avl_iterate_item(&link_tree, &oLAn));) {

					MAC_T *oMac = ip6Eui64ToMac(&oLink->k.linkDev->key.llocal_ip, NULL);

					if (min_lq_probe(oLink) && !strcmp(tDev->ifname_phy.str, oLink->k.myDev->ifname_phy.str) && !memcmp(e->mac, oMac, sizeof(MAC_T))) {

						oLink->wifiStats.updSqn = wifiStatsUpdSqn;

						dbgf_track(DBGT_INFO,
							"mac=%s signal=%d noise=%d snr=%d age=%d rxRate=%d sgi=%d rxCnt=%d txRate=%d txCount=%d",
							memAsHexStringSep(oMac, 6, 1, ":"),
							e->signal, e->noise, (e->signal - e->noise), e->inactive,
							e->rx_rate.rate, e->rx_rate.is_short_gi, e->rx_packets,
							e->tx_rate.rate, e->tx_packets);

						if (oLink->wifiStats.txPackets != e->tx_packets) {

							oLink->wifiStats.txRate = e->tx_rate.rate * 1000;
							oLink->wifiStats.txRateAvg = oLink->wifiStats.txRateAvg + (oLink->wifiStats.txRate / linkAvgRateWeight) - (oLink->wifiStats.txRateAvg / linkAvgRateWeight);
							oLink->wifiStats.txRateExpected = e->thr * 1000; 
							oLink->wifiStats.tx40mhz = e->tx_rate.is_40mhz;
							//link->linkStats.txHt = e->tx_rate.is_ht;
							oLink->wifiStats.txMcs = e->tx_rate.mcs;
							//link->linkStats.txMhz = e->tx_rate.mhz;
							//link->linkStats.txNss = e->tx_rate.nss;
							oLink->wifiStats.txShortGi = e->tx_rate.is_short_gi;
							//link->linkStats.txVht = e->tx_rate.is_vht;

							oLink->wifiStats.rxRate = e->rx_rate.rate * 1000;
							oLink->wifiStats.rxPackets = e->rx_packets;
							oLink->wifiStats.rx40mhz = e->rx_rate.is_40mhz;
							//link->linkStats.rxHt = e->rx_rate.is_ht;
							oLink->wifiStats.rxMcs = e->rx_rate.mcs;
							//link->linkStats.rxMhz = e->rx_rate.mhz;
							//link->linkStats.rxNss = e->rx_rate.nss;
							oLink->wifiStats.rxShortGi = e->rx_rate.is_short_gi;
							//link->linkStats.rxVht = e->rx_rate.is_vht;

							oLink->wifiStats.signal = e->signal;
							oLink->wifiStats.noise = e->noise;

							oLink->wifiStats.updatedTime = bmx_time;
							oLink->wifiStats.txTriggTime = bmx_time;

							oLink->wifiStats.txPackets = e->tx_packets;
						}


						if (oLink->wifiStats.txBurstTime == 0) {

							oLink->wifiStats.txBurstPackets = e->tx_packets;
							oLink->wifiStats.txBurstTime = bmx_time - (((TIME_T) linkBurstInterval) - ((TIME_T) (my_ogmInterval / 2)));
							if (!oLink->wifiStats.txBurstTime)
								oLink->wifiStats.txBurstTime = 1;


						} else if (((uint32_t) (e->tx_packets - oLink->wifiStats.txBurstPackets)) >= ((uint32_t) linkBurstThreshold)) {

							oLink->wifiStats.txBurstPackets = e->tx_packets;
							oLink->wifiStats.txBurstTime = bmx_time;
							oLink->wifiStats.txTriggTime = bmx_time;


						} else if (((TIME_T) (bmx_time - oLink->wifiStats.txBurstTime)) >= ((TIME_T) linkBurstInterval) && linkBurstInterval && linkBurstDuration && linkBurstPacketSize) {

							oLink->wifiStats.txBurstPackets = e->tx_packets;
							oLink->wifiStats.txBurstTime = bmx_time;
							oLink->wifiStats.txBurstCnt++;

							struct tp_test_key tk = {.duration = linkBurstDuration, .endTime = 0, .packetSize = linkBurstPacketSize, .totalSend = 0};

							schedule_tx_task(FRAME_TYPE_TRASH_ADV, oLink, &oLink->k.linkDev->key.local->local_id, oLink->k.linkDev->key.local, oLink->k.myDev,
								tk.packetSize, &tk, sizeof(tk));



						} else if (oLink->wifiStats.txPackets == e->tx_packets &&
							(((TIME_T) (bmx_time - oLink->wifiStats.txTriggTime)) >= (TIME_T) linkProbeInterval) && linkProbeInterval && linkProbePacketSize) {

							oLink->wifiStats.txTriggTime = bmx_time;
							oLink->wifiStats.txTriggCnt++;

							struct tp_test_key tk = {.duration = 0, .endTime = 0, .packetSize = linkProbePacketSize, .totalSend = 0};

							schedule_tx_task(FRAME_TYPE_TRASH_ADV, oLink, &oLink->k.linkDev->key.local->local_id, oLink->k.linkDev->key.local, oLink->k.myDev,
								tk.packetSize, &tk, sizeof(tk));

						}

						//break; // if running several vlan-interfaces on same phy this would not find the second
					}
				}
			}
		}

		for (oLAn = NULL;(oLink = avl_iterate_item(&link_tree, &oLAn));) {

			if (!strcmp(tDev->ifname_phy.str, oLink->k.myDev->ifname_phy.str) && oLink->wifiStats.updSqn != wifiStatsUpdSqn) {
				memset(&oLink->wifiStats, 0, sizeof(oLink->wifiStats));
			}
		}

		iwinfo_finish();
	}
}

uint16_t iwi_get_channel(struct dev_node *dev)
{
	uint16_t channel = TYP_DEV_CHANNEL_SHARED;

	const struct iwinfo_ops *iw;

	if ((iw = iwinfo_backend(dev->ifname_phy.str))) {

		int ch;
		if ((iw->channel(dev->ifname_phy.str, &ch)) == 0 && ch > 0 && ch < TYP_DEV_CHANNEL_SHARED) {
			channel = ch;
		} else {
			dbgf_sys(DBGT_ERR, "Failed accessing channel?=%d for dev=%s", ch, dev->ifname_phy.str);
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
			
			if (!dev->upd_link_capacities)
				dev->upd_link_capacities = get_link_rate;


			if (!dev->get_iw_channel)
				dev->get_iw_channel = iwi_get_channel;


		} else {

			if (dev->get_iw_channel == iwi_get_channel)
				dev->get_iw_channel = NULL;

			if (dev->upd_link_capacities == get_link_rate)
				dev->upd_link_capacities = NULL;
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

	// WARNING: Using more verbose debuglevel here distorts link-capacity measurements !!!
	dbgf_all(DBGT_INFO, "size=%d total=%d duration=%d endTime=%d   iterations=%d dev=%s myIdx=%d src=%s unicast=%d, dst=%s nbIdx=%d neigh=%s neighId=%s",
		tk->packetSize, tk->totalSend, tk->duration, (tk->endTime ? (tk->endTime - now) : 0),
		it->ttn->tx_iterations, it->ttn->key.f.p.dev->ifname_label.str, it->ttn->key.f.p.dev->llipKey.devIdx, it->ttn->key.f.p.dev->ip_llocal_str, !!link,
		ip6AsStr(link ? &link->k.linkDev->key.llocal_ip : NULL),
		(link ? link->k.linkDev->key.devIdx : -1),
		(link ? link->k.linkDev->key.local->on->k.hostname : NULL),
		cryptShaAsString(&it->ttn->key.f.groupId));

	if (link && linkBurstInterval && linkBurstDuration && linkBurstPacketSize &&
		((tk->totalSend + tk->packetSize) <= (uint32_t)linkBurstBytes) && (!tk->endTime || (((TIME_T)(tk->endTime - now)) < tk->duration))) {

		struct tp_test_key TK = *tk;

		if (!TK.endTime)
			TK.endTime = now + TK.duration;

		TK.totalSend += TK.packetSize;

		schedule_tx_task(FRAME_TYPE_TRASH_ADV, link, &link->k.linkDev->key.local->local_id, link->k.linkDev->key.local, link->k.myDev, TK.packetSize, &TK, sizeof(TK) );
	}

	link->wifiStats.txBurstPackets++;

	cryptRand(tx_iterator_cache_msg_ptr(it), tk->packetSize);
	return tk->packetSize;
}


STATIC_FUNC
int32_t rx_frame_trash_adv(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	// WARNING: Using more verbose debuglevel here distorts link-capacity measurements !!!
	dbgf_all(DBGT_INFO, "size=%d dev=%s unicast=%d src=%s claimedId=%s",
		it->f_dlen, it->pb->i.iif->ifname_label.str, it->pb->i.unicast, it->pb->i.llip_str, cryptShaAsShortStr(&it->pb->p.hdr.keyHash));

	return it->f_msgs_len;
}

static struct opt_type capacity_options[]= {
//        ord parent long_name          shrt Attributes				*ival		min		max		default		*func,*syntax,*help

	{ODI,0,ARG_LINK_PROBE_IVAL,     0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkProbeInterval,MIN_LINK_PROBE_IVAL,MAX_LINK_PROBE_IVAL,DEF_LINK_PROBE_IVAL,0,0,
			ARG_VALUE_FORM, HLP_LINK_PROBE_IVAL},
	{ODI,0,ARG_LINK_PROBE_PACKETSZ,     0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkProbePacketSize,MIN_LINK_PROBE_PACKETSZ,MAX_LINK_PROBE_PACKETSZ, DEF_LINK_PROBE_PACKETSZ,0,0,
			ARG_VALUE_FORM, HLP_LINK_PROBE_PACKETSZ},

	{ODI,0,ARG_LINK_BURST_IVAL, 0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkBurstInterval,MIN_LINK_BURST_IVAL,MAX_LINK_BURST_IVAL, DEF_LINK_BURST_IVAL,0,0,
			ARG_VALUE_FORM, HLP_LINK_BURST_IVAL},
	{ODI,0,ARG_LINK_BURST_THRESHOLD, 0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkBurstThreshold,MIN_LINK_BURST_THRESHOLD,MAX_LINK_BURST_THRESHOLD, DEF_LINK_BURST_THRESHOLD,0,0,
			ARG_VALUE_FORM, HLP_LINK_BURST_THRESHOLD},
	{ODI,0,ARG_LINK_BURST_PACKETSZ, 0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkBurstPacketSize,MIN_LINK_BURST_PACKETSZ,MAX_LINK_BURST_PACKETSZ, DEF_LINK_BURST_PACKETSZ,0,0,
			ARG_VALUE_FORM, HLP_LINK_BURST_PACKETSZ},
	{ODI,0,ARG_LINK_BURST_DURATION, 0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkBurstDuration,MIN_LINK_BURST_DURATION,MAX_LINK_BURST_DURATION, DEF_LINK_BURST_DURATION,0,0,
			ARG_VALUE_FORM, HLP_LINK_BURST_DURATION},
	{ODI,0,ARG_LINK_BURST_BYTES,    0,9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,&linkBurstBytes,MIN_LINK_BURST_BYTES,MAX_LINK_BURST_BYTES, DEF_LINK_BURST_BYTES,0,0,
			ARG_VALUE_FORM, HLP_LINK_BURST_BYTES},

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


