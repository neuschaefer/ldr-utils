/*
 * File:         blackfin_defines.h
 * Author:       Mike Frysinger <michael.frysinger@analog.com>
 *
 * Description:  Misc defines ripped out of Blackfin headers.
 *
 * Rev:          $Id$
 *
 * Modified:     Copyright 2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
 *
 * Licensed under the GPL-2, see the file COPYING in this dir
 */

#ifndef __BLACKFIN_DEFINES__
#define __BLACKFIN_DEFINES__

/* common stuff */
#define LO(x) ((x) & 0xFFFF)
#define HI(x) (((x) >> 16) & 0xFFFF)

#define GET_1ST_NIBBLE(x) ((x & 0x000000FF) >> 0)
#define GET_2ND_NIBBLE(x) ((x & 0x0000FF00) >> 8)
#define GET_3RD_NIBBLE(x) ((x & 0x00FF0000) >> 16)
#define GET_4TH_NIBBLE(x) ((x & 0xFF000000) >> 24)

#define FILL_ADDR_16(var, val, idx1, idx2) \
	do { \
		var[idx1] = GET_1ST_NIBBLE(val); \
		var[idx2] = GET_2ND_NIBBLE(val); \
	} while (0)
#define FILL_ADDR_32(var, val, idx1, idx2, idx3, idx4) \
	do { \
		var[idx1] = GET_1ST_NIBBLE(val); \
		var[idx2] = GET_2ND_NIBBLE(val); \
		var[idx3] = GET_3RD_NIBBLE(val); \
		var[idx4] = GET_4TH_NIBBLE(val); \
	} while (0)

/* sdram defines */
#define EBIU_SDSTAT 0xFFC00A1C
#define SDRS 0x8
#define SDRS_BITPOS 3

#define EBIU_SDRRC 0xFFC00A18
#define CONFIG_CLKIN_HZ 25000000
#define CONFIG_VCO_MULT 20
#define CONFIG_VCO_HZ ( CONFIG_CLKIN_HZ * CONFIG_VCO_MULT )
#define CONFIG_SCLK_DIV 5
#define CONFIG_SCLK_HZ ( CONFIG_VCO_HZ / CONFIG_SCLK_DIV )
#define SDRAM_Tref 64
#define SDRAM_NRA 8192
#define SDRAM_tRAS_num 5
#define SDRAM_tRP_num 2
#define mem_SDRRC ((( CONFIG_SCLK_HZ / 1000) * SDRAM_Tref) / SDRAM_NRA) - (SDRAM_tRAS_num + SDRAM_tRP_num)

#define EBIU_SDBCTL 0xFFC00A14
#define EBE 0x1
#define EBCAW_10 0x0020
#define SDRAM_WIDTH EBCAW_10
#define EBSZ_64 0x0004
#define SDRAM_SIZE EBSZ_64
#define mem_SDBCTL  (SDRAM_WIDTH | SDRAM_SIZE | EBE)

#define EBIU_SDGCTL 0xFFC00A10
#define SCTLE 0x00000001
#define CL_3 0x0000000C
#define SDRAM_CL CL_3
#define TRAS_5 0x00000140
#define SDRAM_tRAS TRAS_5
#define TRP_2 0x00001000
#define SDRAM_tRP TRP_2
#define TRCD_2 0x00010000
#define SDRAM_tRCD TRCD_2
#define TWR_2 0x00100000
#define SDRAM_tWR TWR_2
#define PSS 0x00800000
#define mem_SDGCTL (SCTLE | SDRAM_CL | SDRAM_tRAS | SDRAM_tRP | SDRAM_tRCD | SDRAM_tWR | PSS)

#endif
