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



#define DUMP_ERROR_STR "DUMP_ERROR"
#define DUMP_MAX_STR_SIZE (MAX_DBG_STR_SIZE - strlen(DUMP_ERROR_STR))
#define DUMP_MAX_MSG_SIZE 200


#define DEF_DUMP_PERIOD 1000
#define MIN_DUMP_PERIOD 100
#define MAX_DUMP_PERIOD 1000000
#define ARG_DUMP_PERIOD "trafficCapturePeriod"

#define ARG_DUMP  "traffic"
#define ARG_DUMP_ALL     "all"
#define ARG_DUMP_DEV     "devs"
#define ARG_DUMP_SUMMARY "summary"

