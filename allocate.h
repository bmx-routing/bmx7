/*
 * Copyright (C) 2006 B.A.T.M.A.N. contributors:
 * Thomas Lopatic, Corinna 'Elektra' Aichele, Axel Neumann, Marek Lindner
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
 *
 */


#ifndef _ALLOCATE_H
#define _ALLOCATE_H 1

#include <stdint.h>

extern uint32_t debugMalloc_bytes;
extern uint32_t debugMalloc_objects;

uint64_t getProcMemory(void);

#ifdef DEBUG_MALLOC

// currently used memory tags: -300000, -300001 .. -300839
#define debugMalloc( length,tag )  _debugMalloc( (length), (tag), 0 )
#define debugMallocReset( length,tag )  _debugMalloc( (length), (tag), 1 )
#define debugRealloc( mem,length,tag ) _debugRealloc( (mem), (length), (tag) )

#define debugFree( mem,tag ) _debugFree( (mem), (tag) )
#define debugFreeReset( mempp, resetSize, tag ) _debugFreeReset( ((void**)(mempp)), (resetSize), (tag) )

void *_debugMalloc(size_t length, int32_t tag, uint8_t reset);
void *_debugRealloc(void *memory, size_t length, int32_t tag);
void _debugFree(void *memoryParameter, int32_t tag);
void _debugFreeReset(void **memoryParameter, size_t resetSize, int32_t tag);

void checkIntegrity(void);
void checkLeak(void);
void debugMemory( struct ctrl_node *cn );

#else

#define debugMalloc( length,tag )  _malloc( (length) )
#define debugMallocReset( length,tag )  _calloc( (length) )
#define debugRealloc( mem,length,tag ) _realloc( (mem), (length) )
#define debugFree( mem,tag ) _free( (mem) )
#define debugFreeReset( mempp, resetSize, tag ) _freeReset( ((void**)(mempp)), (resetSize) )

#define checkIntegrity()
#define checkLeak()
#define debugMemory( c )

void * _malloc( size_t length );
void * _calloc( size_t length );
void * _realloc( void *mem, size_t length );
void _free(void *mem);
void _freeReset(void **mem, size_t resetLength);

#endif

#endif
