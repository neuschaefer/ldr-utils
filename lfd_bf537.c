/*
 * File: lfd_bf537.c
 *
 * Copyright 2006-2007 Analog Devices Inc.
 * Licensed under the GPL-2, see the file COPYING in this dir
 *
 * Description:
 * Format handlers for LDR files on the BF53[467].
 */

#define __LFD_INTERNAL
#include "ldr.h"

/* 10-byte block header; See page 19-13 of BF537 HRM */
#define LDR_BLOCK_HEADER_LEN (10)
typedef struct {
	uint8_t raw[LDR_BLOCK_HEADER_LEN];        /* buffer for following members ... needs to be first */
	uint32_t target_address;                  /* blackfin memory address to load block */
	uint32_t byte_count;                      /* number of bytes in block */
	uint16_t flags;                           /* flags to control behavior */
} BLOCK_HEADER;

/* block flags; See page 19-14 of BF537 HRM */
#define LDR_FLAG_ZEROFILL    0x0001
#define LDR_FLAG_RESVECT     0x0002
#define LDR_FLAG_INIT        0x0008
#define LDR_FLAG_IGNORE      0x0010
#define LDR_FLAG_PPORT_MASK  0x0600
#define LDR_FLAG_PPORT_NONE  0x0000
#define LDR_FLAG_PPORT_PORTF 0x0200
#define LDR_FLAG_PPORT_PORTG 0x0400
#define LDR_FLAG_PPORT_PORTH 0x0600
#define LDR_FLAG_PFLAG_MASK  0x01E0
#define LDR_FLAG_PFLAG_SHIFT 5
#define LDR_FLAG_COMPRESSED  0x2000
#define LDR_FLAG_FINAL       0x8000

static struct lfd_flag bf537_lfd_flags[] = {
	{ LDR_FLAG_ZEROFILL,    "zerofill"  },
	{ LDR_FLAG_RESVECT,     "resvect"   },
	{ LDR_FLAG_INIT,        "init"      },
	{ LDR_FLAG_IGNORE,      "ignore"    },
	{ LDR_FLAG_PPORT_NONE,  "port_none" },
	{ LDR_FLAG_PPORT_PORTF, "portf"     },
	{ LDR_FLAG_PPORT_PORTG, "portg"     },
	{ LDR_FLAG_PPORT_PORTH, "porth"     },
	{ LDR_FLAG_COMPRESSED,  "compressed"},
	{ LDR_FLAG_FINAL,       "final"     },
	{ 0, 0 }
};

/**
 *	bf53x_lfd_read_block_header - read in the BF53x block header
 *
 * The format of each block header:
 * [4 bytes for address]
 * [4 bytes for byte count]
 * [2 bytes for flags]
 */
void *bf53x_lfd_read_block_header(LFD *alfd, bool *ignore, bool *fill, bool *final, size_t *header_len, size_t *data_len)
{
	FILE *fp = alfd->fp;
	BLOCK_HEADER *header = xmalloc(sizeof(*header));
	fread(header->raw, 1, LDR_BLOCK_HEADER_LEN, fp);
	memcpy(&(header->target_address), header->raw, sizeof(header->target_address));
	memcpy(&(header->byte_count), header->raw+4, sizeof(header->byte_count));
	memcpy(&(header->flags), header->raw+8, sizeof(header->flags));
	ldr_make_little_endian_32(header->target_address);
	ldr_make_little_endian_32(header->byte_count);
	ldr_make_little_endian_16(header->flags);
	*ignore = !!(header->flags & LDR_FLAG_IGNORE);
	*fill = !!(header->flags & LDR_FLAG_ZEROFILL);
	*final = !!(header->flags & LDR_FLAG_FINAL);
	*header_len = LDR_BLOCK_HEADER_LEN;
	*data_len = header->byte_count;
	return header;
}

bool bf53x_lfd_display_dxe(LFD *alfd, size_t d)
{
	LDR *ldr = alfd->private_data;
	size_t i, b;
	uint16_t hflags, flags, ignore_flags;

	/* since we let the BF533/BF561 LFDs jump here, let's mask some
	 * flags that aren't used for those targets ...
	 */
	ignore_flags = (family_is(alfd, "BF537") ? 0 : LDR_FLAG_PPORT_MASK | LDR_FLAG_PFLAG_MASK);

	if (quiet)
		printf("              Offset      Address     Bytes    Flags\n");
	for (b = 0; b < ldr->dxes[d].num_blocks; ++b) {
		BLOCK *block = &(ldr->dxes[d].blocks[b]);
		BLOCK_HEADER *header = block->header;
		if (quiet)
			printf("    Block %2zu 0x%08zX: ", b+1, block->offset);
		else
			printf("    Block %2zu at 0x%08zX\n", b+1, block->offset);

		if (quiet) {
			printf("0x%08X 0x%08X 0x%04X ( ", header->target_address, header->byte_count, header->flags);
		} else if (verbose) {
			printf("\t\tTarget Address: 0x%08X ( %s )\n", header->target_address,
				(header->target_address > 0xFF000000 ? "L1" : "SDRAM"));
			printf("\t\t    Byte Count: 0x%08X ( %u bytes )\n", header->byte_count, header->byte_count);
			printf("\t\t         Flags: 0x%04X     ( ", header->flags);
		} else {
			printf("         Addr: 0x%08X Bytes: 0x%08X Flags: 0x%04X ( ",
				header->target_address, header->byte_count, header->flags);
		}

		hflags = header->flags & ~ignore_flags;

		flags = hflags & LDR_FLAG_PPORT_MASK;
		if (flags)
			for (i = 0; bf537_lfd_flags[i].desc; ++i)
				if (flags == bf537_lfd_flags[i].flag)
					printf("%s ", bf537_lfd_flags[i].desc);
		flags = (hflags & LDR_FLAG_PFLAG_MASK) >> LDR_FLAG_PFLAG_SHIFT;
		if (flags)
			printf("gpio%i ", flags);

		flags = hflags & ~LDR_FLAG_PPORT_MASK;
		for (i = 0; bf537_lfd_flags[i].desc; ++i)
			if (flags & bf537_lfd_flags[i].flag)
				printf("%s ", bf537_lfd_flags[i].desc);

		printf(")\n");
	}

	return true;
}

/*
 * ldr_create()
 */
bool bf53x_lfd_write_block(struct lfd *alfd, uint8_t dxe_flags,
                           const void *void_opts, uint32_t addr,
                           uint32_t count, void *src)
{
	const struct ldr_create_options *opts = void_opts;
	FILE *fp = alfd->fp;
	uint16_t flags;
	size_t out_count = count;

	flags = 0;
	if (!target_is(alfd, "BF531") &&
	    !target_is(alfd, "BF532") &&
	    !target_is(alfd, "BF538"))
		flags = LDR_FLAG_RESVECT;
	if (family_is(alfd, "BF537")) {
		flags |= (opts->gpio << LDR_FLAG_PFLAG_SHIFT) & LDR_FLAG_PFLAG_MASK;
		switch (toupper(opts->port)) {
			case 'F': flags |= LDR_FLAG_PPORT_PORTF; break;
			case 'G': flags |= LDR_FLAG_PPORT_PORTG; break;
			case 'H': flags |= LDR_FLAG_PPORT_PORTH; break;
			default:  flags |= LDR_FLAG_PPORT_NONE; break;
		}
	}

	/* we dont need a special first ignore block */
	if (dxe_flags & DXE_BLOCK_FIRST)
		return true;
	if (dxe_flags & DXE_BLOCK_INIT) {
		flags |= LDR_FLAG_INIT;
		addr = (flags & LDR_FLAG_RESVECT ? 0xFFA00000 : 0xFFA08000);
	}
	if (dxe_flags & DXE_BLOCK_JUMP)
		addr = (flags & LDR_FLAG_RESVECT ? 0xFFA00000 : 0xFFA08000);
	if (dxe_flags & DXE_BLOCK_FILL)
		flags |= LDR_FLAG_ZEROFILL;
	if (dxe_flags & DXE_BLOCK_FINAL)
		flags |= LDR_FLAG_FINAL;

	ldr_make_little_endian_32(addr);
	ldr_make_little_endian_32(count);
	ldr_make_little_endian_16(flags);
	fwrite(&addr, sizeof(addr), 1, fp);
	fwrite(&count, sizeof(count), 1, fp);
	fwrite(&flags, sizeof(flags), 1, fp);

	if (src)
		return (fwrite(src, 1, out_count, fp) == out_count ? true : false);
	else
		return true;
}

uint32_t bf53x_lfd_dump_block(BLOCK *block, FILE *fp, bool dump_fill)
{
	BLOCK_HEADER *header = block->header;

	if (!(header->flags & LDR_FLAG_ZEROFILL))
		fwrite(block->data, 1, header->byte_count, fp);
	else if (dump_fill) {
		void *filler = xmalloc(header->byte_count);
		memset(filler, 0x00, header->byte_count);
		fwrite(filler, 1, header->byte_count, fp);
		free(filler);
	}

	return header->target_address;
}


static const char *bf537_aliases[] = { "BF534", "BF536", "BF537", NULL };
static struct lfd_target bf537_lfd_target = {
	.name  = "BF537",
	.description = "Blackfin LDR handler for BF534/BF536/BF537",
	.aliases = bf537_aliases,
	.uart_boot = true,
	.iovec = {
		.read_block_header = bf53x_lfd_read_block_header,
		.display_dxe = bf53x_lfd_display_dxe,
		.write_block = bf53x_lfd_write_block,
		.dump_block = bf53x_lfd_dump_block,
	},
};

__attribute__((constructor))
static void bf537_lfd_target_register(void)
{
	lfd_target_register(&bf537_lfd_target);
}