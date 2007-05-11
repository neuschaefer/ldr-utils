/*
 * File: ldr.h
 *
 * Copyright 2006-2007 Analog Devices Inc.
 * Licensed under the GPL-2, see the file COPYING in this dir
 *
 * Description:
 * View LDR contents; based on the "Visual DSP++ 4.0 Loader Manual"
 * and misc Blackfin HRMs
 */

#ifndef __LDR_H__
#define __LDR_H__

#include "headers.h"

/* See page 2-23 / 2-24 of Loader doc */
#define LDR_FLAG_ZEROFILL 0x0001
#define LDR_FLAG_INIT     0x0008
#define LDR_FLAG_IGNORE   0x0010
#define LDR_FLAG_FINAL    0x8000

/* BF537 flags; See page 19-14 of BF537 HRM */
#define LDR_FLAG_RESVECT     0x0002
#define LDR_FLAG_PPORT_MASK  0x0600
#define LDR_FLAG_PPORT_NONE  0x0000
#define LDR_FLAG_PPORT_PORTF 0x0200
#define LDR_FLAG_PPORT_PORTG 0x0400
#define LDR_FLAG_PPORT_PORTH 0x0600
#define LDR_FLAG_PFLAG_MASK  0x01E0
#define LDR_FLAG_PFLAG_SHIFT 5

#define LDR_BLOCK_HEADER_LEN (sizeof(uint32_t) + sizeof(uint32_t) + sizeof(uint16_t))
typedef struct {
	size_t offset;                            /* file offset */
	uint32_t target_address;                  /* blackfin memory address to load block */
	uint32_t byte_count;                      /* number of bytes in block */
	uint16_t flags;                           /* flags to control behavior */
	uint8_t header[LDR_BLOCK_HEADER_LEN];     /* buffer for previous three members */
	uint8_t *data;                            /* buffer for block data */
} BLOCK;

typedef struct {
	BLOCK *blocks;
	size_t num_blocks;
} DXE;

typedef struct {
	DXE *dxes;
	size_t num_dxes;
} LDR;

struct ldr_create_options {
	int cpu;                                  /* CPU # (some have slightly diff LDR formats) */
	int resvec;
	char port;                                /* PORT on CPU for HWAIT signals */
	int gpio;                                 /* GPIO on CPU for HWAIT signals */
	uint32_t block_size;                      /* block size to break the DXE up into */
	uint32_t load_addr;                       /* address at which to load DXE */
};

struct ldr_load_options {
	size_t baud;
	int force;
};

int str2bfcpu(const char *cpu);

LDR *ldr_read(const char *);
void ldr_free(LDR *);
int ldr_print(LDR *);
int ldr_dump(const char *, LDR *);
int ldr_send(LDR *, const char *, const struct ldr_load_options *);
int ldr_create(char **, const struct ldr_create_options *);

#endif
