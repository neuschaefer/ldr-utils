/*
 * File: lfd_bf548.c
 *
 * Copyright 2006-2007 Analog Devices Inc.
 * Licensed under the GPL-2, see the file COPYING in this dir
 *
 * Description:
 * Format handlers for LDR files on the BF54[2489].
 */

#define __LFD_INTERNAL
#include "ldr.h"

/* 16-byte block header; See page 19-13 of BF548 HRM */
#define LDR_BLOCK_HEADER_LEN (16)
typedef struct {
	uint8_t raw[LDR_BLOCK_HEADER_LEN];        /* buffer for following members ... needs to be first */
	uint32_t block_code;                      /* flags to control behavior */
	uint32_t target_address;                  /* blackfin memory address to load block */
	uint32_t byte_count;                      /* number of bytes in block */
	uint32_t argument;                        /* misc extraneous data (like CRC) */
} BLOCK_HEADER;

/* block flags */
#define BFLAG_DMACODE_MASK      0x0000000F
#define BFLAG_DMACODE_SHIFT     0
#define BFLAG_SAFE              0x00000010
#define BFLAG_AUX               0x00000020
#define BFLAG_FILL              0x00000100
#define BFLAG_QUICKBOOT         0x00000200
#define BFLAG_CALLBACK          0x00000400
#define BFLAG_INIT              0x00000800
#define BFLAG_IGNORE            0x00001000
#define BFLAG_INDIRECT          0x00002000
#define BFLAG_FIRST             0x00004000
#define BFLAG_FINAL             0x00008000
#define BFLAG_HDRSIGN_MASK      0xFF000000
#define BFLAG_HDRSIGN_SHIFT     24
#define BFLAG_HDRSIGN_MAGIC     0xAD
#define BFLAG_HDRCHK_MASK       0x00FF0000
#define BFLAG_HDRCHK_SHIFT      16

static struct lfd_flag bf548_lfd_flags[] = {
	{ BFLAG_SAFE,        "safe"      },
	{ BFLAG_AUX,         "aux"       },
	{ BFLAG_FILL,        "fill"      },
	{ BFLAG_QUICKBOOT,   "quickboot" },
	{ BFLAG_CALLBACK,    "callback"  },
	{ BFLAG_INIT,        "init"      },
	{ BFLAG_IGNORE,      "ignore"    },
	{ BFLAG_INDIRECT,    "indirect"  },
	{ BFLAG_FIRST,       "first"     },
	{ BFLAG_FINAL,       "final"     },
	{ 0, 0 }
};

/**
 *	bf548_lfd_read_block_header - read in the BF54x block header
 *
 * The format of each block header:
 * [4 bytes for block codes]
 * [4 bytes for address]
 * [4 bytes for byte count]
 * [4 bytes for arguments]
 */
static void *bf548_lfd_read_block_header(LFD *alfd, bool *ignore, bool *fill, bool *final, size_t *header_len, size_t *data_len)
{
	FILE *fp = alfd->fp;
	BLOCK_HEADER *header = xmalloc(sizeof(*header));
	fread(header->raw, 1, LDR_BLOCK_HEADER_LEN, fp);
	memcpy(header->raw, header->raw, LDR_BLOCK_HEADER_LEN);
	memcpy(&(header->block_code), header->raw, sizeof(header->block_code));
	memcpy(&(header->target_address), header->raw+4, sizeof(header->target_address));
	memcpy(&(header->byte_count), header->raw+8, sizeof(header->byte_count));
	memcpy(&(header->argument), header->raw+12, sizeof(header->argument));
	ldr_make_little_endian_32(header->block_code);
	ldr_make_little_endian_32(header->target_address);
	ldr_make_little_endian_32(header->byte_count);
	ldr_make_little_endian_32(header->argument);
	*ignore = !!(header->block_code & BFLAG_IGNORE);
	*fill = !!(header->block_code & BFLAG_FILL);
	*final = !!(header->block_code & BFLAG_FINAL);
	*header_len = LDR_BLOCK_HEADER_LEN;
	*data_len = header->byte_count;
	return header;
}

static bool bf548_lfd_display_dxe(LFD *alfd, size_t d)
{
	LDR *ldr = alfd->private_data;
	size_t i, b;
	uint32_t block_code, tmp;

	if (quiet)
		printf("              Offset      BlockCode  Address    Bytes      Argument\n");
	for (b = 0; b < ldr->dxes[d].num_blocks; ++b) {
		BLOCK *block = &(ldr->dxes[d].blocks[b]);
		BLOCK_HEADER *header = block->header;
		if (quiet)
			printf("    Block %2zu 0x%08zX: ", b+1, block->offset);
		else
			printf("    Block %2zu at 0x%08zX\n", b+1, block->offset);

		if (quiet) {
			printf("0x%08X 0x%08X 0x%08X 0x%08X ( ", header->block_code, header->target_address, header->byte_count, header->argument);
		} else if (verbose) {
			printf("\t\tTarget Address: 0x%08X ( %s )\n", header->target_address,
				(header->target_address > 0xFF000000 ? "L1" : "SDRAM"));
			printf("\t\t    Block Code: 0x%08X\n", header->block_code);
			printf("\t\t    Byte Count: 0x%08X ( %u bytes )\n", header->byte_count, header->byte_count);
			printf("\t\t      Argument: 0x%08X ( ", header->argument);
		} else {
			printf("         Addr: 0x%08X BCode: 0x%08X Bytes: 0x%08X Args: 0x%08X ( ",
				header->target_address, header->block_code, header->byte_count, header->argument);
		}

		block_code = header->block_code;

		/* address and byte count need to be 4 byte aligned */
		if (header->target_address % 4)
			printf("!!addralgn!! ");
		if (header->byte_count % 4)
			printf("!!cntalgn!! ");

		/* hdrsign should always be set to 0xAD */
		tmp = (header->block_code & BFLAG_HDRSIGN_MASK) >> BFLAG_HDRSIGN_SHIFT;
		if (tmp != BFLAG_HDRSIGN_MAGIC)
			printf("!!hdrsign!! ");

		/* hdrchk is a simple XOR of the block header.
		 * Since the XOR value exists inside of the block header, the XOR
		 * checksum of the actual block should always come out to be 0x00.
		 * This is because the XOR byte is 0x00 when first computed, but
		 * when added to the actual data, the result cancels out the input.
		 */
		tmp = (header->block_code & BFLAG_HDRCHK_MASK) >> BFLAG_HDRCHK_SHIFT;
		if (compute_hdrchk(header->raw, LDR_BLOCK_HEADER_LEN))
			printf("!!hdrchk!! ");

		tmp = (block_code & BFLAG_DMACODE_MASK) >> BFLAG_DMACODE_SHIFT;
		switch (tmp) {
			case  0: printf("dma-reserved "); break;
			case  1: printf("8bit-dma-from-8bit "); break;
			case  2: printf("8bit-dma-from-16bit "); break;
			case  3: printf("8bit-dma-from-32bit "); break;
			case  4: printf("8bit-dma-from-64bit "); break;
			case  5: printf("8bit-dma-from-128bit "); break;
			case  6: printf("16bit-dma-from-16bit "); break;
			case  7: printf("16bit-dma-from-32bit "); break;
			case  8: printf("16bit-dma-from-64bit "); break;
			case  9: printf("16bit-dma-from-128bit "); break;
			case 10: printf("32bit-dma-from-32bit "); break;
			case 11: printf("32bit-dma-from-64bit "); break;
			case 12: printf("32bit-dma-from-128bit "); break;
			case 13: printf("64bit-dma-from-64bit "); break;
			case 14: printf("64bit-dma-from-128bit "); break;
			case 15: printf("128bit-dma-from-128bit "); break;
		}

		for (i = 0; bf548_lfd_flags[i].desc; ++i)
			if (block_code & bf548_lfd_flags[i].flag)
				printf("%s ", bf548_lfd_flags[i].desc);

		printf(")\n");
	}

	return true;
}

/*
 * ldr_create()
 *
 * XXX: no way for user to set "argument" or block_code fields ...
 */
#define LDR_ADDR_INIT 0xFFA00000
static bool _bf548_lfd_write_header(FILE *fp, uint32_t block_code, uint32_t addr,
                                    uint32_t count, uint32_t argument, void *header)
{
	ldr_make_little_endian_32(block_code);
	ldr_make_little_endian_32(addr);
	ldr_make_little_endian_32(count);
	ldr_make_little_endian_32(argument);
	memcpy(header+ 0, &block_code, sizeof(block_code));
	memcpy(header+ 4, &addr, sizeof(addr));
	memcpy(header+ 8, &count, sizeof(count));
	memcpy(header+12, &argument, sizeof(argument));
	ldr_make_little_endian_32(block_code);
	block_code |= (compute_hdrchk(header, LDR_BLOCK_HEADER_LEN) << BFLAG_HDRCHK_SHIFT);
	ldr_make_little_endian_32(block_code);
	memcpy(header+ 0, &block_code, sizeof(block_code));
	return (fwrite(header, sizeof(uint8_t), LDR_BLOCK_HEADER_LEN, fp) == LDR_BLOCK_HEADER_LEN ? true : false);
}
static uint32_t last_dxe_pos = 0;
static bool bf548_lfd_write_block(struct lfd *alfd, uint8_t dxe_flags,
                                  const void *void_opts, uint32_t addr,
                                  uint32_t count, void *src)
{
	const struct ldr_create_options *opts = void_opts;
	FILE *fp = alfd->fp;
	uint32_t block_code_base, block_code, argument;
	uint8_t header[LDR_BLOCK_HEADER_LEN];
	bool ret = true;
	uint8_t pad_size = 0, pad = 0;

	argument = 0xDEADBEEF;
	block_code_base = \
		(BFLAG_HDRSIGN_MAGIC << BFLAG_HDRSIGN_SHIFT) | \
		(opts->dma << BFLAG_DMACODE_SHIFT);

	block_code = block_code_base;

	if (dxe_flags & DXE_BLOCK_FIRST)
		block_code |= BFLAG_IGNORE | BFLAG_FIRST;
	if (dxe_flags & DXE_BLOCK_INIT) {
		block_code |= BFLAG_INIT;
		addr = LDR_ADDR_INIT;
	}
	if (dxe_flags & DXE_BLOCK_JUMP)
		return true;
	if (dxe_flags & DXE_BLOCK_FILL) {
		block_code |= BFLAG_FILL;
		argument = 0;
	}

	if (addr % 4)
		warn("address is not 4 byte aligned (0x%X %% 4 = %i)", addr, addr % 4);
	pad_size = count % 4;
	if (pad_size) {
		warn("count is not 4 byte aligned (0x%X %% 4 = %i)", count, pad_size);
		warn("going to pad the end with zeros, but you should fix this");
	}

	ret &= _bf548_lfd_write_header(fp, block_code, addr, count+pad_size, argument, header);

	if (src)
		ret &= (fwrite(src, 1, count, fp) == count ? true : false);

	if (pad_size)
		fwrite(&pad, sizeof(pad), pad_size, fp);

	if (dxe_flags & DXE_BLOCK_FINAL) {
		uint32_t curr_pos;

		block_code = block_code_base | BFLAG_FINAL;
		addr = LDR_ADDR_INIT;
		count = 0;
		argument = 0;
		ret &= _bf548_lfd_write_header(fp, block_code, addr, count, argument, header);

		/* we need to set the argument in the first block header to point here */
		curr_pos = ftell(fp);
		argument = curr_pos - last_dxe_pos - LDR_BLOCK_HEADER_LEN;
		last_dxe_pos = curr_pos;
		fseek(fp, 4, SEEK_SET);
		fread(&addr, sizeof(addr), 1, fp);
		ldr_make_little_endian_32(addr);
		rewind(fp);
		block_code = block_code_base | BFLAG_IGNORE | BFLAG_FIRST;
		ret &= _bf548_lfd_write_header(fp, block_code, addr, count, argument, header);
		fseek(fp, 0, SEEK_END);
	}

	return ret;
}

static uint32_t bf548_lfd_dump_block(BLOCK *block, FILE *fp, bool dump_fill)
{
	BLOCK_HEADER *header = block->header;

	if (!(header->block_code & BFLAG_FILL))
		fwrite(block->data, 1, header->byte_count, fp);
	else if (dump_fill) {
		/* cant use memset() here as it's a 32bit fill, not 8bit */
		void *filler;
		uint32_t *p = filler = xmalloc(header->byte_count);
		while ((void*)p < (void*)(filler + header->byte_count))
			*p++ = header->argument;
		fwrite(filler, 1, header->byte_count, fp);
		free(filler);
	}

	return header->target_address;
}

static const char *bf548_aliases[] = { "BF542", "BF544", "BF548", "BF549", NULL };
static struct lfd_target bf548_lfd_target = {
	.name  = "BF548",
	.description = "Blackfin LDR handler for BF542/BF544/BF548/BF549",
	.aliases = bf548_aliases,
	.uart_boot = true,
	.iovec = {
		.read_block_header = bf548_lfd_read_block_header,
		.display_dxe = bf548_lfd_display_dxe,
		.write_block = bf548_lfd_write_block,
		.dump_block = bf548_lfd_dump_block,
	},
};

__attribute__((constructor))
static void bf548_lfd_target_register(void)
{
	lfd_target_register(&bf548_lfd_target);
}
