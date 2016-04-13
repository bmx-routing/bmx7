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

#define ATH_RC_STATS_BASE_DIR "/root/sys/kernel/debug/ieee80211"
#define ATH_RC_STATS_PHY_PREFIX "phy"
#define ATH_RC_STATS_DEVS_DIR "netdev:" // --> "phy0/netdev:wlan0"
#define ATH_RC_STATS_MACS_DIR "stations" // -> "stations/12:34:56:78:9A:BC"
#define ATH_RC_STATS_FILE_CSV "rc_stats_csv"
#define ATH_RC_STATS_FILE_TXT "rc_stats"
#define ATH_RC_STATS_FILE_TXT_LEN 77
#define ATH_RC_STATS_FILE_TXT_POS_P 14
#define ATH_RC_STATS_FILE_TXT_POS_T 22
#define ATH_RC_STATS_FILE_TXT_POS_O 56
#define ATH_RC_STATS_FILE_TXT_POS_OE 65


#define ARG_LINK_PROBE_IVAL "linkProbeInterval"
#define HLP_LINK_PROBE_IVAL "interval for unicast link probing. Needed for accurate link capacity estimation"
#define MIN_LINK_PROBE_IVAL  100
#define MAX_LINK_PROBE_IVAL  10000
#define DEF_LINK_PROBE_IVAL  500

#define ARG_ATH_STATS "athStats"

//// cd /sys/kernel/debug/ieee80211/phy0/netdev:wlan0/stations/14:cf:92:52:13:a6
// while true; do clear; bmx7 -cd8; echo; iwinfo wlan0 assoclist; cat rc_stats; echo; cat rc_stats_csv ; sleep 1; done

struct ath_rc_stats {
	uint32_t airtime;
	uint32_t max_tp;
	uint32_t avg_tp;
	uint32_t tx_count;
	TIME_T probe_time;
	IFNAME_T phyName;
};