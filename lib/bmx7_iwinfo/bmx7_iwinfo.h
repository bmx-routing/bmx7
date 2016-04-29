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
#define DEF_LINK_PROBE_IVAL  3000
#define MIN_LINK_PROBE_IVAL  100
#define MAX_LINK_PROBE_IVAL  10000000

#define ARG_LINK_PROBE_SIZE "linkProbeSize"
#define HLP_LINK_PROBE_SIZE "set byte size of packets for unicast link probing to improve link-capacity estimation"
#define DEF_LINK_PROBE_SIZE  100
#define MIN_LINK_PROBE_SIZE  0
#define MAX_LINK_PROBE_SIZE  SIGNED_FRAMES_SIZE_MAX

#define ARG_LINK_PROBE_DURATION "linkProbeDuration"
#define HLP_LINK_PROBE_DURATION "set duration in ms for unicast link probing to improve link-capacity estimation"
#define DEF_LINK_PROBE_DURATION 0
#define MIN_LINK_PROBE_DURATION 0
#define MAX_LINK_PROBE_DURATION 1000

#define ARG_LINK_PROBE_TOTAL "linkProbeTotal"
#define HLP_LINK_PROBE_TOTAL "maximum total amount of data per link probe burst to improve link-capacity estimation"
#define DEF_LINK_PROBE_TOTAL 1000
#define MIN_LINK_PROBE_TOTAL 0
#define MAX_LINK_PROBE_TOTAL 1000000

#define ARG_LINK_RATE_AVG_WEIGHT "linkAvgRate"
#define HLP_LINK_RATE_AVG_WEIGHT "weight for averaging out old link-rate probes"
#define DEF_LINK_RATE_AVG_WEIGHT 3
#define MIN_LINK_RATE_AVG_WEIGHT 1
#define MAX_LINK_RATE_AVG_WEIGHT 100


struct tp_test_key {
	uint32_t packetSize;
	uint32_t totalSend;
	TIME_T duration;
	TIME_T endTime;
};
