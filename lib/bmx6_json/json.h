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


#define DEF_JSON_SUBDIR "json"
#define JSON_OPTIONS_FILE "options"
#define JSON_PARAMETERS_FILE "parameters"
#define DEF_JSON_DESC_SUBDIR "descriptions"
#define DEF_JSON_ORIG_SUBDIR "originators"
#define DEF_JSON_SMS_RX_SUBDIR "smsRcvd"
#define DEF_JSON_SMS_TX_SUBDIR "smsSend"


#define ARG_JSON_STATUS         "json_status"
#define ARG_JSON_INTERFACES     "json_interfaces"
#define ARG_JSON_LINKS          "json_links"
#define ARG_JSON_ORIGINATORS    "json_originators"



#define ARG_JSON_SUBDIR "jsonSubdir"


#define ARG_JSON_UPDATE "jsonUpdateInterval"
#define DEF_JSON_UPDATE 10000
#define MIN_JSON_UPDATE 0
#define MAX_JSON_UPDATE REGISTER_TASK_TIMEOUT_MAX

#define ARG_JSON_SMS "jsonSms"
#define MAX_JSON_SMS_NAME_LEN 16
#define MAX_JSON_SMS_DATA_LEN 240
#define TLV_OP_CUSTOM_JSON_SMS  (TLV_OP_CUSTOM_MIN + 0)

struct json_sms {
	char name[MAX_JSON_SMS_NAME_LEN];
        uint16_t stale;
	uint16_t text_len;
        char text[];
};

struct description_msg_json_sms {
	char name[MAX_JSON_SMS_NAME_LEN];
	uint16_t text_len;
        char text[];
} __attribute__((packed));

#define DESCRIPTION_MSG_JSON_SMS_FORMAT { \
{FIELD_TYPE_STRING_CHAR,   -1, (8*MAX_JSON_SMS_NAME_LEN), 1, FIELD_RELEVANCE_HIGH, "name"}, \
{FIELD_TYPE_STRING_SIZE,   -1, 16,                        0, FIELD_RELEVANCE_LOW,  "len"},  \
{FIELD_TYPE_STRING_BINARY, -1, 0,                         1, FIELD_RELEVANCE_LOW,  "data" },  \
FIELD_FORMAT_END }


