/*
 * Copyright (c) 2012-2013  Axel Neumann
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

#define ARG_REDIST_DELAY  "redistTableOutDelay"
#define HLP_REDIST_DELAY  "delay announcement of changed table routes in ms to aggregate shortly following changes"
#define MIN_REDIST_DELAY  100
#define MAX_REDIST_DELAY  3600000
#define DEF_REDIST_DELAY  2000

#define ARG_FILTER_DELAY  "redistTableInDelay"
#define DEF_FILTER_DELAY  1000
#define HLP_FILTER_DELAY  "delay processing of changed table routes in ms to filter shortly following changes"


#define ARG_REDIST        "redistTable"
#define HLP_REDIST        "arbitrary but unique name for redistributed table network(s) depending on sub criterias"



