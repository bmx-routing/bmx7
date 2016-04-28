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

#define ATH_RC_STATS_BASE_DIR "/sys/kernel/debug/ieee80211"
#define ATH_RC_STATS_PHY_PREFIX "phy"
#define ATH_RC_STATS_DEVS_DIR "netdev:" // --> "phy0/netdev:wlan0"
#define ATH_RC_STATS_MACS_DIR "stations" // -> "stations/12:34:56:78:9A:BC"
#define ATH_RC_STATS_FILE_CSV "rc_stats_csv"
#define ATH_RC_STATS_FILE_TXT "rc_stats"
#define ATH_RC_STATS_FILE_TXT_LEN 77
#define ATH_RC_STATS_FILE_TXT_POS_P 14
#define ATH_RC_STATS_FILE_TXT_POS_T 23
#define ATH_RC_STATS_FILE_TXT_POS_O 57
#define ATH_RC_STATS_FILE_TXT_POS_OE 66

#define ARG_LINK_PROBE_IVAL "linkProbeInterval"
#define HLP_LINK_PROBE_IVAL "set interval in ms for unicast link probing. Needed for accurate link capacity estimation"
#define MIN_LINK_PROBE_IVAL  100
#define MAX_LINK_PROBE_IVAL  10000
#define DEF_LINK_PROBE_IVAL  2000

#define ARG_LINK_PROBE_SIZE "linkProbeSize"
#define HLP_LINK_PROBE_SIZE "set byte size of packets for unicast link probing. Needed for accurate link capacity estimation"
#define MIN_LINK_PROBE_SIZE  0
#define MAX_LINK_PROBE_SIZE  1000
#define DEF_LINK_PROBE_SIZE  100

#define ARG_LINK_PROBE_DURATION "linkProbeDuration"
#define HLP_LINK_PROBE_DURATION "set duration in ms for unicast link probing. Needed for accurate link capacity estimation"
#define MIN_LINK_PROBE_DURATION 0
#define MAX_LINK_PROBE_DURATION 1000
#define DEF_LINK_PROBE_DURATION 0

#define DEF_LINK_PROBE_TOTAL 1000
#define MIN_LINK_PROBE_TOTAL 0
#define MAX_LINK_PROBE_TOTAL 1000000
#define ARG_LINK_PROBE_TOTAL "linkProbeTotal"
#define HLP_LINK_PROBE_TOTAL "maximum total amount of data per link probe burst"



struct tp_test_key {
	uint32_t packetSize;
	uint32_t totalSend;
	TIME_T duration;
	TIME_T endTime;
};
