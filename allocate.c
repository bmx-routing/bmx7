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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "list.h"
#include "control.h"
#include "bmx.h"
#include "allocate.h"

uint32_t debugMalloc_bytes = 0;
uint32_t debugMalloc_objects = 0;

typedef struct {
    long size,resident,share,text,lib,data,dt;
} statm_t;

uint64_t getProcMemory(void) {
	static statm_t s;
	FILE *f = fopen("/proc/self/statm", "r");
	if (!f)
		return 0;

	if (fscanf(f, "%ld %ld %ld %ld %ld %ld %ld", &s.size, &s.resident, &s.share, &s.text, &s.lib, &s.data, &s.dt) != 7) {
		fclose(f);
		return 0;
	}

	fclose(f);

	return (s.size * getpagesize());
}


#ifdef DEBUG_MALLOC

#define MAGIC_NUMBER_HEADER 0xB2B2B2B2
#define MAGIC_NUMBER_TRAILOR 0xB2


struct chunkHeader *chunkList = NULL;

struct chunkHeader
{
	struct chunkHeader *next;
	uint32_t length;
	int32_t tag;
        uint32_t magicNumberHeader;
};

typedef unsigned char MAGIC_TRAILER_T;


#ifdef MEMORY_USAGE

struct memoryUsage *memoryList = NULL;


struct memoryUsage
{
	struct memoryUsage *next;
	uint32_t length;
	uint32_t counter;
	int32_t tag;
};

void addMemory(uint32_t length, int32_t tag)
{

	struct memoryUsage *walker;

	for ( walker = memoryList; walker != NULL; walker = walker->next ) {

		if ( walker->tag == tag ) {

			walker->counter++;
			break;
		}
	}

	if ( walker == NULL ) {

		walker = malloc( sizeof(struct memoryUsage) );

		walker->length = length;
		walker->tag = tag;
		walker->counter = 1;

		walker->next = memoryList;
		memoryList = walker;
	}

}

void removeMemory(int32_t tag, int32_t freetag)
{

	struct memoryUsage *walker;

	for ( walker = memoryList; walker != NULL; walker = walker->next ) {

		if ( walker->tag == tag ) {

			if ( walker->counter == 0 ) {

                                dbg_sys(DBGT_ERR, "Freeing more memory than was allocated: malloc tag = %d, free tag = %d",
				     tag, freetag );
				cleanup_all( -500069 );

			}

			walker->counter--;
			break;

		}

	}

	if ( walker == NULL ) {

                dbg_sys(DBGT_ERR, "Freeing memory that was never allocated: malloc tag = %d, free tag = %d",
		     tag, freetag );
		cleanup_all( -500070 );
	}
}

void debugMemory(struct ctrl_node *cn)
{

	struct memoryUsage *memoryWalker;

	dbg_printf( cn, "\nMemory usage information:\n" );

	for ( memoryWalker = memoryList; memoryWalker != NULL; memoryWalker = memoryWalker->next ) {

		if ( memoryWalker->counter != 0 )
			dbg_printf( cn, "   tag: %4i, num malloc: %4i, bytes per malloc: %4i, total: %6i\n",
			         memoryWalker->tag, memoryWalker->counter, memoryWalker->length,
			         memoryWalker->counter * memoryWalker->length );

	}
	dbg_printf( cn, "\n" );

}

#endif //#ifdef MEMORY_USAGE


void checkIntegrity(void)
{
	struct chunkHeader *walker;
	MAGIC_TRAILER_T *chunkTrailer;
	unsigned char *memory;

//        dbgf_all(DBGT_INFO, " ");

	for (walker = chunkList; walker != NULL; walker = walker->next)
	{
		if (walker->magicNumberHeader != MAGIC_NUMBER_HEADER)
{
                        dbgf_sys(DBGT_ERR, "invalid magic number in header: %08x, malloc tag = %d",
			     walker->magicNumberHeader, walker->tag );
			cleanup_all( -500073 );
		}

		memory = (unsigned char *)walker;

		chunkTrailer = (MAGIC_TRAILER_T*)(memory + sizeof(struct chunkHeader) + walker->length);

		if (*chunkTrailer != MAGIC_NUMBER_TRAILOR)
{
                        dbgf_sys(DBGT_ERR, "invalid magic number in trailer: %08x, malloc tag = %d",
			     *chunkTrailer, walker->tag );
			cleanup_all( -500075 );
		}
	}

}

void checkLeak(void)
{
	struct chunkHeader *walker;

        if (chunkList != NULL) {

                openlog( "bmx7", LOG_PID, LOG_DAEMON );

                for (walker = chunkList; walker != NULL; walker = walker->next) {
			syslog( LOG_ERR, "Memory leak detected, malloc tag = %d\n", walker->tag );

			fprintf( stderr, "Memory leak detected, malloc tag = %d \n", walker->tag );

		}

		closelog();
	}

}

void *_debugMalloc(size_t length, int32_t tag, uint8_t reset)
{

	unsigned char *memory;
	struct chunkHeader *chunkHeader;
	MAGIC_TRAILER_T *chunkTrailer;
	unsigned char *chunk;

	debugMalloc_bytes += (length + sizeof(struct chunkHeader) + sizeof(MAGIC_TRAILER_T));
	debugMalloc_objects += 1;

        if (!length)
                return NULL;

	if (reset) {
		memory = malloc(length + sizeof(struct chunkHeader) + sizeof(MAGIC_TRAILER_T));
		memset(memory, 0, length + sizeof(struct chunkHeader) + sizeof(MAGIC_TRAILER_T));
	} else {
		memory = malloc(length + sizeof(struct chunkHeader) + sizeof(MAGIC_TRAILER_T));
	}

	if (memory == NULL)
	{
		dbg_sys(DBGT_ERR, "Cannot allocate %u bytes, malloc tag = %d",
		     (unsigned int)(length + sizeof(struct chunkHeader) + sizeof(MAGIC_TRAILER_T)), tag );
		cleanup_all( -500076 );
	}

	chunkHeader = (struct chunkHeader *)memory;
	chunk = memory + sizeof(struct chunkHeader);
	chunkTrailer = (MAGIC_TRAILER_T*)(memory + sizeof(struct chunkHeader) + length);

	chunkHeader->length = length;
	chunkHeader->tag = tag;
	chunkHeader->magicNumberHeader = MAGIC_NUMBER_HEADER;

	*chunkTrailer = MAGIC_NUMBER_TRAILOR;

	chunkHeader->next = chunkList;
	chunkList = chunkHeader;

#ifdef MEMORY_USAGE

	addMemory( length, tag );

#endif //#ifdef MEMORY_USAGE

	return chunk;
}

void *_debugRealloc(void *memoryParameter, size_t length, int32_t tag)
{

        unsigned char *result = _debugMalloc(length, tag, 0);
        uint32_t copyLength = 0;

	if (memoryParameter) { /* if memoryParameter==NULL, realloc() should work like malloc() !! */

                struct chunkHeader *chunkHeader =
                        (struct chunkHeader *) (((unsigned char *) memoryParameter) - sizeof (struct chunkHeader));

                MAGIC_TRAILER_T * chunkTrailer =
                        (MAGIC_TRAILER_T *) (((unsigned char *) memoryParameter) + chunkHeader->length);

		if (chunkHeader->magicNumberHeader != MAGIC_NUMBER_HEADER) {
                        dbgf_sys(DBGT_ERR, "invalid magic number in header: %08x, malloc tag = %d",
			     chunkHeader->magicNumberHeader, chunkHeader->tag );
			cleanup_all( -500078 );
                }

                if (*chunkTrailer != MAGIC_NUMBER_TRAILOR) {
                        dbgf_sys(DBGT_ERR, "invalid magic number in trailer: %08x, malloc tag = %d",
			     *chunkTrailer, chunkHeader->tag );
			cleanup_all( -500079 );
		}

                copyLength = (length < chunkHeader->length) ? length : chunkHeader->length;

                if (copyLength)
                        memcpy(result, memoryParameter, copyLength);

		debugFree(memoryParameter, -300280);
	}

	return result;
}


void _debugFree(void *memoryParameter, int tag)
{
	MAGIC_TRAILER_T *chunkTrailer;
	struct chunkHeader *walker;
	struct chunkHeader *previous;
	struct chunkHeader *chunkHeader =
		(struct chunkHeader *) (((unsigned char *) memoryParameter) - sizeof (struct chunkHeader));

        if (chunkHeader->magicNumberHeader != MAGIC_NUMBER_HEADER)
	{
		dbgf_sys(DBGT_ERR,
		     "invalid magic number in header: %08x, malloc tag = %d, free tag = %d, malloc size = %d",
                        chunkHeader->magicNumberHeader, chunkHeader->tag, tag, chunkHeader->length);
		cleanup_all( -500080 );
	}

	previous = NULL;

	for (walker = chunkList; walker != NULL; walker = walker->next)
	{
		if (walker == chunkHeader)
			break;

		previous = walker;
	}

	if (walker == NULL)
	{
		dbg_sys(DBGT_ERR, "Double free detected, malloc tag = %d, free tag = %d malloc size = %d",
		     chunkHeader->tag, tag, chunkHeader->length );
		cleanup_all( -500081 );
	}

	if (previous == NULL)
		chunkList = walker->next;

	else
		previous->next = walker->next;


        chunkTrailer = (MAGIC_TRAILER_T *) (((unsigned char *) memoryParameter) + chunkHeader->length);

	if (*chunkTrailer != MAGIC_NUMBER_TRAILOR) {
                dbgf_sys(DBGT_ERR, "invalid magic number in trailer: %08x, malloc tag = %d, free tag = %d, malloc size = %d",
                        *chunkTrailer, chunkHeader->tag, tag, chunkHeader->length);
		cleanup_all( -500082 );
	}

	debugMalloc_bytes -= (chunkHeader->length + sizeof(struct chunkHeader) + sizeof(MAGIC_TRAILER_T));
	debugMalloc_objects -= 1;

#ifdef MEMORY_USAGE

	removeMemory( chunkHeader->tag, tag );

#endif //#ifdef MEMORY_USAGE

	if (!terminating)
		free(chunkHeader);

}

void _debugFreeReset(void **mem, size_t resetSize, int tag)
{
	if (mem) {
		if (resetSize)
			memset(*mem, 0, resetSize);

		debugFree( *mem, tag );

		*mem = NULL;
	}
}

#else

void * _malloc( size_t length ) {
	debugMalloc_objects += 1;
	return malloc( length );
}

void * _calloc( size_t length ) {
	debugMalloc_objects += 1;
	void *mem = malloc( length );
	memset( mem, 0, length);
	return mem;
}

void * _realloc( void *mem, size_t length ) {
	return realloc( mem, length );
}

void _free( void *mem ) {
	debugMalloc_objects -= 1;
	if (!terminating)
		free( mem );
}

void _freeReset( void **mem, size_t resetSize ) {

	if (mem) {
		debugMalloc_objects -= 1;

		if (resetSize)
			memset(*mem, 0, resetSize);

		if (!terminating)
			free( *mem );

		*mem = NULL;
	}
}

#endif
