/*
 * Copyright (c) 2010  Axel Neumann
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


#define ARG_TOPOLOGY "topology"
#define ARG_TOPOLOGY_HYSTERESIS "topologyUpdateHysteresis"
#define MIN_TOPOLOGY_HYSTERESIS 1
#define MAX_TOPOLOGY_HYSTERESIS 10000
#define DEF_TOPOLOGY_HYSTERESIS 33

#define ARG_TOPOLOGY_PERIOD "topologyUpdatePeriod"
#define MIN_TOPOLOGY_PERIOD 10000
#define MAX_TOPOLOGY_PERIOD 36000000
#define DEF_TOPOLOGY_PERIOD 60000

#define TLV_OP_CUSTOM_TOPOLOGY (TLV_OP_CUSTOM_MIN + 1)


struct description_msg_topology {
	GLOBAL_ID_T neighId;
	DEVIDX_T neighIdx;
	DEVIDX_T myIdx;


	FMETRIC_U8_T txBw;
	FMETRIC_U8_T rxBw;
	uint8_t txRate;
	uint8_t rxRate;

} __attribute__((packed));

struct description_hdr_topology {
	uint8_t type;
	uint8_t reserved;
	struct description_msg_topology msg[];
} __attribute__((packed));


#define DESCRIPTION_MSG_TOPOLOGY_FORMAT { \
{FIELD_TYPE_UINT,             -1, (8*sizeof(uint8_t)),     1, FIELD_RELEVANCE_HIGH, "txBw"}, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(uint8_t)),     1, FIELD_RELEVANCE_HIGH, "rxBw"}, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(uint8_t)),     1, FIELD_RELEVANCE_HIGH, "txRate"}, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(uint8_t)),     1, FIELD_RELEVANCE_HIGH, "rxRate"}, \
{FIELD_TYPE_GLOBAL_ID,        -1, (8*sizeof(GLOBAL_ID_T)), 1, FIELD_RELEVANCE_HIGH, "neighId"},  \
FIELD_FORMAT_END }

struct local_topology_node {
	GLOBAL_ID_T pkid;
	UMETRIC_T txBw;
	UMETRIC_T rxBw;
	uint8_t txRate;
	uint8_t rxRate;
	uint8_t updated;
};