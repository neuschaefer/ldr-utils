/*
 * File: lfd_bf527.c
 *
 * Copyright 2006-2007 Analog Devices Inc.
 * Licensed under the GPL-2, see the file COPYING in this dir
 *
 * Description:
 * Format handlers for LDR files on the BF52[257].
 */

#define __LFD_INTERNAL
#include "ldr.h"

static const char *bf527_aliases[] = { "BF522", "BF525", "BF527", NULL };
static struct lfd_target bf527_lfd_target = {
	.name = "BF527",
	.description = "Blackfin LDR handler for BF522/BF525/BF527",
	.aliases = bf527_aliases,
	.uart_boot = true,
	.iovec = {
		.read_block_header = bf54x_lfd_read_block_header,
		.display_dxe = bf54x_lfd_display_dxe,
		.write_block = bf54x_lfd_write_block,
		.dump_block = bf54x_lfd_dump_block,
	},
};

__attribute__((constructor))
static void bf527_lfd_target_register(void)
{
	lfd_target_register(&bf527_lfd_target);
}
