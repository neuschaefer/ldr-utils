/*
 * File: lfd_bf609.c
 *
 * Copyright 2006-2012 Analog Devices Inc.
 * Licensed under the GPL-2, see the file COPYING in this dir
 *
 * Description:
 * Format handlers for LDR files on the BF60[6789].
 */

#define __LFD_INTERNAL
#include "ldr.h"

static const char * const bf609_aliases[] = { "BF606", "BF607", "BF608", "BF609", NULL };
static const struct lfd_target bf609_lfd_target = {
	.name = "BF609",
	.description = "Blackfin LDR handler for BF606/BF607/BF608/BF609",
	.aliases = bf609_aliases,
	.uart_boot = true,
	.iovec = {
		.read_block_header = bf54x_lfd_read_block_header,
		.display_dxe = bf54x_lfd_display_dxe,
		.write_block = bf54x_lfd_write_block,
		.dump_block = bf54x_lfd_dump_block,
	},
};

__attribute__((constructor))
static void bf609_lfd_target_register(void)
{
	lfd_target_register(&bf609_lfd_target);
}
