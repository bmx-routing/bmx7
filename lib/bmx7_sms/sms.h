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


#define DEF_SMS_SUBDIR "sms"
#define DEF_SMS_RX_SUBDIR "rcvdSms"
#define DEF_SMS_TX_SUBDIR "sendSms"

#define ARG_SMS "syncSms"

#define MAX_SMS_NAME_LEN 32
#define MAX_SMS_DATA_LEN 300
#define MAX_SMS_DATA_LEN_REF MAX_VRT_FRAME_DATA_SIZE

#define SMS_POLLING_INTERVAL 5000

#define ARG_SMS_FZIP "zipSms"
#define DEF_SMS_FZIP TYP_FZIP_DO

#define ARG_SMS_FREF "refSms"
#define DEF_SMS_FREF TYP_FREF_DO2

struct sms_node {
	char name[MAX_SMS_NAME_LEN];
	uint16_t stale;
	uint32_t dataLen;
	char data[];
};

struct description_msg_sms {
	char name[MAX_SMS_NAME_LEN];
	uint32_t dataLen;
	char data[];
} __attribute__((packed));

#define DESCRIPTION_MSG_SMS_FORMAT { \
{FIELD_TYPE_STRING_CHAR,   -1, (8*MAX_SMS_NAME_LEN), 1, FIELD_RELEVANCE_HIGH, "name"}, \
{FIELD_TYPE_STRING_SIZE,   -1, 32,                        0, FIELD_RELEVANCE_LOW,  "len"},  \
{FIELD_TYPE_STRING_BINARY, -1, 0,                         1, FIELD_RELEVANCE_LOW,  "data" },  \
FIELD_FORMAT_END }
