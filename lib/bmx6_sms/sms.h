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
#define MAX_JSON_SMS_NAME_LEN 16
#define MAX_JSON_SMS_DATA_LEN 240

struct json_sms {
	char name[MAX_JSON_SMS_NAME_LEN];
        uint16_t stale;
	uint16_t text_len;
        char text[];
};

struct description_msg_sms {
	char name[MAX_JSON_SMS_NAME_LEN];
	uint16_t text_len;
        char text[];
} __attribute__((packed));

#define DESCRIPTION_MSG_SMS_FORMAT { \
{FIELD_TYPE_STRING_CHAR,   -1, (8*MAX_JSON_SMS_NAME_LEN), 1, FIELD_RELEVANCE_HIGH, "name"}, \
{FIELD_TYPE_STRING_SIZE,   -1, 16,                        0, FIELD_RELEVANCE_LOW,  "len"},  \
{FIELD_TYPE_STRING_BINARY, -1, 0,                         1, FIELD_RELEVANCE_LOW,  "data" },  \
FIELD_FORMAT_END }


