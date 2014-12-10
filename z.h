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

#define Z_CHUNK_SIZE 16384


int32_t z_compress( uint8_t *src, int32_t slen, uint8_t **dst, uint32_t dpos, uint8_t *darr, int32_t darr_max_size);
int32_t z_decompress( uint8_t *src, uint32_t len, uint8_t **dst, uint32_t dst_pos);