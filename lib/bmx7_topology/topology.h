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
#define MIN_TOPOLOGY_PERIOD 0
#define MAX_TOPOLOGY_PERIOD 360000
#define DEF_TOPOLOGY_PERIOD 3600

#define TLV_OP_CUSTOM_TOPOLOGY (TLV_OP_CUSTOM_MIN + 1)


struct description_msg_topology {
	GLOBAL_ID_T nbId;
	DESC_SQN_T nbDescSqn;
	DEVIDX_T nbIdx;
	DEVIDX_T idx;

	FMETRIC_U8_T txBw;
	FMETRIC_U8_T rxBw;
	LQ_T tq;
	LQ_T rq;
	int8_t signal;
	int8_t noise;
	uint8_t channel;
	uint8_t reserved1;
	uint16_t reserved2;

} __attribute__((packed));

struct description_hdr_topology {
	uint8_t type;
	uint8_t reserved;
	struct description_msg_topology msg[];
} __attribute__((packed));


#define DESCRIPTION_MSG_TOPOLOGY_FORMAT { \
{FIELD_TYPE_GLOBAL_ID,        -1, (8*sizeof(GLOBAL_ID_T)), 0, FIELD_RELEVANCE_HIGH, "nbId"},  \
{FIELD_TYPE_UINT,             -1, (8*sizeof(DESC_SQN_T)),  0, FIELD_RELEVANCE_HIGH, "nbDescSqn"}, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(DEVIDX_T)),    0, FIELD_RELEVANCE_HIGH, "nbIdx"}, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(DEVIDX_T)),    0, FIELD_RELEVANCE_HIGH, "myIdx"}, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(FMETRIC_U8_T)),0, FIELD_RELEVANCE_HIGH, "txBw"}, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(FMETRIC_U8_T)),0, FIELD_RELEVANCE_HIGH, "rxBw"}, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(uint8_t)),     0, FIELD_RELEVANCE_HIGH, "tq"}, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(uint8_t)),     0, FIELD_RELEVANCE_HIGH, "rq"}, \
{FIELD_TYPE_INT,              -1, (8*sizeof(int8_t)),      0, FIELD_RELEVANCE_HIGH, "signal"}, \
{FIELD_TYPE_INT,              -1, (8*sizeof(int8_t)),      0, FIELD_RELEVANCE_HIGH, "noise"}, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(uint8_t)),     0, FIELD_RELEVANCE_HIGH, "channel"}, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(uint8_t)),     0, FIELD_RELEVANCE_HIGH, "reserved1"}, \
{FIELD_TYPE_UINT,             -1, (8*sizeof(uint16_t)),    0, FIELD_RELEVANCE_HIGH, "reserved2"}, \
FIELD_FORMAT_END }

struct local_topology_key {
	GLOBAL_ID_T nbId;
	DEVIDX_T nbIdx;
	DEVIDX_T myIdx;
} __attribute__((packed));

struct local_topology_node {
	struct local_topology_key k;
	uint8_t sqn;
	UMETRIC_T txBw;
	UMETRIC_T rxBw;
	LQ_T tq;
	LQ_T rq;
	int8_t signal;
	int8_t noise;
	uint8_t channel;
	uint8_t updated;
};

struct topology_status {
	GLOBAL_ID_T *id;
	char* name;
	IPX_T *primaryIp;
	DEVIDX_T idx;

	GLOBAL_ID_T *neighId;
	DESC_SQN_T neighDescSqnDiff;
	char* neighName;
	IPX_T *neighIp;
	DEVIDX_T neighIdx;

	uint32_t lastDesc;
	int8_t signal;
	int8_t noise;
	int8_t snr;
	uint8_t channel;
	uint8_t rq;
	uint8_t tq;
	UMETRIC_T rxRate;
	UMETRIC_T txRate;
};
