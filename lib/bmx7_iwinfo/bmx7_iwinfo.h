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


#define ARG_LINK_PROBE_IVAL "linkProbeInterval"
#define HLP_LINK_PROBE_IVAL "set interval in ms for unicast link probing to improve link-capacity estimation"
#define DEF_LINK_PROBE_IVAL 3000
#define MIN_LINK_PROBE_IVAL 0
#define MAX_LINK_PROBE_IVAL 10000000

#define ARG_LINK_PROBE_PACKETSZ "linkProbeSize"
#define HLP_LINK_PROBE_PACKETSZ "set byte size of packets for unicast link probing to improve link-capacity estimation"
#define DEF_LINK_PROBE_PACKETSZ 100
#define MIN_LINK_PROBE_PACKETSZ 0
#define MAX_LINK_PROBE_PACKETSZ PKT_MSGS_SIZE_MAX




#define ARG_LINK_BURST_IVAL "linkBurstInterval"
#define HLP_LINK_BURST_IVAL "set interval in ms for unicast link probing bursts to improve link-capacity estimation"
#define DEF_LINK_BURST_IVAL 0
#define MIN_LINK_BURST_IVAL 0
#define MAX_LINK_BURST_IVAL 10000000

#define ARG_LINK_BURST_THRESHOLD "linkBurstThreshold"
#define HLP_LINK_BURST_THRESHOLD "set number of packets for discarding current linkBurstInterval"
#define DEF_LINK_BURST_THRESHOLD 100
#define MIN_LINK_BURST_THRESHOLD 0
#define MAX_LINK_BURST_THRESHOLD 1000000

#define ARG_LINK_BURST_PACKETSZ "linkBurstSize"
#define HLP_LINK_BURST_PACKETSZ "set byte size of packets for unicast link probing bursts to improve link-capacity estimation"
#define DEF_LINK_BURST_PACKETSZ PKT_MSGS_SIZE_MAX
#define MIN_LINK_BURST_PACKETSZ 0
#define MAX_LINK_BURST_PACKETSZ PKT_MSGS_SIZE_MAX


#define ARG_LINK_BURST_DURATION "linkBurstDuration"
#define HLP_LINK_BURST_DURATION "set duration in ms for unicast link probing bursts to improve link-capacity estimation"
#define DEF_LINK_BURST_DURATION 150
#define MIN_LINK_BURST_DURATION 0
#define MAX_LINK_BURST_DURATION 1000

#define ARG_LINK_BURST_BYTES "linkBurstBytes"
#define HLP_LINK_BURST_BYTES "maximum total amount of data per link probe burst to improve link-capacity estimation"
#define DEF_LINK_BURST_BYTES 1000000
#define MIN_LINK_BURST_BYTES 0
#define MAX_LINK_BURST_BYTES 1000000

#define ARG_LINK_RATE_AVG_WEIGHT "linkAvgWeight"
#define HLP_LINK_RATE_AVG_WEIGHT "inverse weight (1/x) for averaging out old link-rate probes"
#define DEF_LINK_RATE_AVG_WEIGHT 10
#define MIN_LINK_RATE_AVG_WEIGHT 1
#define MAX_LINK_RATE_AVG_WEIGHT 100

struct tp_test_key {
	uint32_t packetSize;
	uint32_t totalSend;
	TIME_T duration;
	TIME_T endTime;
};
