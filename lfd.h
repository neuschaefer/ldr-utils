/*
 * File: lfd.h
 *
 * Copyright 2006-2007 Analog Devices Inc.
 * Licensed under the GPL-2, see the file COPYING in this dir
 *
 * Description:
 * [L]DR File Descriptor Abstraction layer for handling different LDR formats.
 */

#ifndef __LDR_FORMAT_H__
#define __LDR_FORMAT_H__

#ifdef __LFD_INTERNAL

#include "dxes.h"
#include "ldr_elf.h"

struct lfd;
struct lfd_iovec;
struct lfd_target;

struct lfd_flag {
	uint16_t flag;
	const char *desc;
};

struct lfd_iovec {
	bool     (*open)              (struct lfd *alfd, const char *filename);
	void*    (*read_ldr_header)   (struct lfd *alfd);
	void*    (*read_block_header) (struct lfd *alfd, bool *ignore, bool *fill, bool *final, size_t *header_len, size_t *data_len);
	bool     (*display_ldr)       (struct lfd *alfd);
	bool     (*display_dxe)       (struct lfd *alfd, const size_t dxe_idx);
	bool     (*write_ldr)         (struct lfd *alfd);
	bool     (*write_block)       (struct lfd *alfd, uint8_t dxe_flags, const void *opts, uint32_t addr, uint32_t count, void *src);
	uint32_t (*dump_block)        (BLOCK *block, FILE *fp, bool dump_fill);
	bool     (*close)             (struct lfd *alfd);
};

struct lfd_target {
	const char *name;        /* unique short name */
	const char *description; /* description of target */
	const char **aliases;
	const bool uart_boot;

	struct lfd_iovec iovec;
};

typedef struct lfd {
	struct lfd_target *target;

	const char *filename;
	const char *selected_target;
	FILE *fp;
	bool is_open;
	void *private_data;
} LFD;

enum {
	DXE_BLOCK_FIRST = 0x01,
	DXE_BLOCK_INIT  = 0x02,
	DXE_BLOCK_JUMP  = 0x04,
	DXE_BLOCK_DATA  = 0x08,
	DXE_BLOCK_FILL  = 0x10,
	DXE_BLOCK_FINAL = 0x20,
};

void lfd_target_register(struct lfd_target *target);
struct lfd_target *lfd_target_find(const char *target);

#define target_is(alfd, target) (!strcmp(alfd->selected_target, target))

static inline bool family_is(LFD *alfd, const char *family)
{
	size_t i;
	struct lfd_target *target = lfd_target_find(family);
	if (target == NULL)
		err("family '%s' is not supported", family);
	for (i = 0; target->aliases[i]; ++i)
		if (target_is(alfd, target->aliases[i]))
			return true;
	return false;
}

/**
 *	compute_hdrchk - compute 8bit XOR checksum of input
 */
static inline uint8_t compute_hdrchk(uint8_t *data, size_t len)
{
	size_t i;
	uint8_t ret = 0;
	for (i = 0; i < len; ++i)
		ret ^= data[i];
	return ret;
}

/* let the BF53x family share funcs for now */
void *bf53x_lfd_read_block_header(struct lfd *alfd, bool *ignore, bool *fill, bool *final, size_t *header_len, size_t *data_len);
bool bf53x_lfd_display_dxe(struct lfd *alfd, size_t d);
bool bf53x_lfd_write_block(struct lfd *alfd, uint8_t dxe_flags,
                           const void *void_opts, uint32_t addr,
                           uint32_t count, void *src);
uint32_t bf53x_lfd_dump_block(BLOCK *block, FILE *fp, bool dump_fill);

#else

typedef struct lfd LFD;

#endif

void lfd_target_list(void);

LFD *lfd_malloc(const char *target);
bool lfd_free(LFD *alfd);

bool lfd_open(LFD *alfd, const char *filename);
bool lfd_read(LFD *alfd);
bool lfd_display(LFD *alfd);
bool lfd_create(LFD *alfd, const void *opts);
bool lfd_dump(LFD *alfd, const void *opts);
bool lfd_load_uart(LFD *alfd, const void *opts);
bool lfd_close(LFD *alfd);

#endif