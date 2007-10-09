/*
 * File: lfd_common.c
 *
 * Copyright 2006-2007 Analog Devices Inc.
 * Licensed under the GPL-2, see the file COPYING in this dir
 *
 * Description:
 * Common functions for LDR target framework.
 */

#define __LFD_INTERNAL
#include "ldr.h"

struct list_item {
	struct list_item *next;
	struct lfd_target *target;
};

static struct list_item *target_list = NULL;

void lfd_target_register(struct lfd_target *target)
{
	struct list_item *new_node = xmalloc(sizeof(*new_node));
	if (!target->name || !target->description || !target->aliases)
		err("lfd_target's must fill out name/desc/aliases");
	new_node->target = target;
	new_node->next = target_list;
	target_list = new_node;
}

struct lfd_target *lfd_target_find(const char *name)
{
	const char *p = strchr(name, '-');
	size_t i, checklen;
	struct list_item *curr = target_list;
	checklen = (p ? (size_t)(p - name) : strlen(name));
	while (curr) {
		if (!strncasecmp(name, curr->target->name, checklen))
			return curr->target;
		if (curr->target->aliases)
			for (i = 0; curr->target->aliases[i]; ++i)
				if (!strncasecmp(name, curr->target->aliases[i], checklen))
					return curr->target;
		curr = curr->next;
	}
	return NULL;
}

void lfd_target_list(void)
{
	struct list_item *curr = target_list;
	while (curr) {
		printf(" %s: %s\n", curr->target->name, curr->target->description);
		curr = curr->next;
	}
}

LFD *lfd_malloc(const char *target)
{
	LFD *alfd = xmalloc(sizeof(*alfd));
	memset(alfd, 0x00, sizeof(*alfd));
	if (target) {
		char *p;
		alfd->dupped_mem = xstrdup(target);
		alfd->selected_target = alfd->dupped_mem;
		p = strchr(alfd->selected_target, '-');
		if (p) {
			alfd->selected_sirev = p + 1;
			*p = '\0';
		}
		alfd->target = lfd_target_find(target);
		if (!alfd->target)
			err("unable to handle specified target: %s", target);
	}
	return alfd;
}

bool lfd_free(LFD *alfd)
{
	free(alfd->dupped_mem);
	free(alfd);
	return true;
}

bool lfd_open(LFD *alfd, const char *filename)
{
	if (alfd->is_open) {
		errno = -EBUSY;
		return false;
	}

	/* Do autodetection here if need be by looking at the 4th byte.
	 *  - BF53x -> "0xFF"
	 *  - BF561 -> "0xA0"
	 *  - BF54x -> "0xAD"
	 */
	if (!alfd->target && !filename) {
		err("please select a target with -T <target>");
	} else if (!alfd->target) {
		uint8_t bytes[4];
		FILE *fp = fopen(filename, "r");
		if (!fp)
			return false;
		if (fread(bytes, sizeof(bytes[0]), ARRAY_SIZE(bytes), fp) != sizeof(bytes)) {
			fclose(fp);
			return false;
		}
		fclose(fp);
		switch (bytes[3]) {
			case 0xFF: alfd->selected_target = "BF537"; break;
			case 0xA0: alfd->selected_target = "BF561"; break;
			case 0xAD: alfd->selected_target = "BF548"; break;
			default: {
				warn("unable to auto-detect target type of LDR: %s", filename);
				err("please select a target with -T <target>");
			}
		}
		alfd->target = lfd_target_find(alfd->selected_target);
		if (!alfd->target)
			return false;
		else if (!quiet)
			printf("auto detected LDR as '%s'\n", alfd->selected_target);
	}

	if (filename && alfd->target->iovec.open) {
		return alfd->target->iovec.open(alfd, filename);
	} else {
		alfd->filename = filename;
		if (filename) {
			alfd->fp = fopen(alfd->filename, "r");
			alfd->is_open = (alfd->fp == NULL ? false : true);
		} else
			alfd->is_open = true;
		return alfd->is_open;
	}
}

/**
 *	lfd_read - translate the ADI visual dsp ldr binary format into our ldr structure
 *
 * The LDR format as seen in three different ways:
 *  - [LDR]
 *  - [[DXE][DXE][...]]
 *  - [[[BLOCK][BLOCK][...]][[BLOCK][BLOCK][BLOCK][...]][...]]
 * So one LDR contains an arbitrary number of DXEs and one DXE contains
 * an arbitrary number of blocks.  The end of the LDR is signified by
 * a block with the final flag set.  The start of a DXE is signified
 * by the ignore flag being set.
 *
 * The format of each block:
 * [Processor-specific header]
 * [data]
 * If the fill flag is set, there is no actual data section, otherwise
 * the data block will be [byte count] bytes long.
 */
bool lfd_read(LFD *alfd)
{
	if (!alfd->is_open) {
		errno = -EBADF;
		return false;
	}
	if (!alfd->target->iovec.read_block_header) {
		warn("target '%s' does not support reading LDRs", alfd->target->name);
		return false;
	}

	FILE *fp = alfd->fp;
	LDR *ldr;
	DXE *dxe;
	BLOCK *block;
	size_t pos = 0, d;
	void *tmp_header;
	bool ignore, fill, final;
	size_t header_len, data_len;

	ldr = xmalloc(sizeof(LDR));
	ldr->dxes = NULL;
	ldr->num_dxes = 0;
	d = 0;

	if (!alfd->target->iovec.read_ldr_header) {
		ldr->header = NULL;
		ldr->header_size = 0;
	} else
		ldr->header = alfd->target->iovec.read_ldr_header(alfd, &ldr->header_size);

	do {
		tmp_header = alfd->target->iovec.read_block_header(alfd, &ignore, &fill, &final, &header_len, &data_len);
		if (feof(fp))
			break;

		if (ldr->dxes == NULL) {
			ldr->dxes = xrealloc(ldr->dxes, (++ldr->num_dxes) * sizeof(DXE));
			dxe = &ldr->dxes[d++];
			dxe->num_blocks = 0;
			dxe->blocks = NULL;
		}

		++dxe->num_blocks;
		dxe->blocks = xrealloc(dxe->blocks, dxe->num_blocks * sizeof(BLOCK));
		block = &dxe->blocks[dxe->num_blocks - 1];
		block->header_size = header_len;
		block->offset = pos;
		block->header = tmp_header;
		block->data_size = data_len;

		if (fill)
			block->data = NULL;
		else if (block->data_size) {
			block->data = xmalloc(block->data_size);
			fread(block->data, 1, block->data_size, fp);
			pos += block->data_size;
		} else
			block->data = NULL;
		pos += header_len;

		if (final)
			break;
	} while (1);

	alfd->private_data = ldr;

	return true;
}

bool lfd_display(LFD *alfd)
{
	if (!alfd->is_open) {
		errno = -EBADF;
		return false;
	}
	if (!alfd->target->iovec.display_dxe) {
		warn("target '%s' does not support displaying LDRs", alfd->target->name);
		return false;
	}

	LDR *ldr = alfd->private_data;
	bool ret = true;
	size_t d;

	if (alfd->target->iovec.display_ldr)
		ret &= alfd->target->iovec.display_ldr(alfd);

	for (d = 0; d < ldr->num_dxes; ++d) {
		printf("  DXE %zu at 0x%08zX:\n", d+1, ldr->dxes[d].blocks[0].offset);
		ret &= alfd->target->iovec.display_dxe(alfd, d);
	}

	return ret;
}

/**
 *	lfd_blockify - break up large sections
 */
static bool lfd_blockify(LFD *alfd, const struct ldr_create_options *opts, uint8_t final,
                         uint32_t dst_addr, size_t byte_count, void *src_addr)
{
	bool ret = true;
	size_t bytes_to_write, bytes_written;

	bytes_written = 0;
	do {
		if (byte_count - bytes_written < opts->block_size)
			bytes_to_write = byte_count - bytes_written;
		else
			bytes_to_write = opts->block_size;

		ret &= alfd->target->iovec.write_block(alfd, DXE_BLOCK_DATA | final, opts,
			dst_addr + bytes_written, bytes_to_write, src_addr + bytes_written);

		bytes_written += bytes_to_write;
	} while (bytes_written < byte_count);

	return ret;
}

/**
 *	lfd_create - produce an LDR from ELFS
 *
 *	This will create one DXE per input ELF file.
 */
bool lfd_create(LFD *alfd, const void *void_opts)
{
	if (!alfd->is_open) {
		errno = -EBADF;
		return false;
	}

	if (!alfd->target->iovec.write_block) {
		warn("target '%s' does not support creating LDRs", alfd->target->name);
		return false;
	}

	const struct ldr_create_options *opts = void_opts;
	char **filelist = opts->filelist;
	bool ret = true;
	uint8_t *dxe_init_start, *dxe_init_end;
	const char *outfile = filelist[0];
	elfobj *elf;
	size_t i = 0;
	int fd;

	fd = open(outfile, O_RDWR|O_CREAT|O_TRUNC| (force?0:O_EXCL), 00666); /* we just want +rw ... let umask sort out the rest */
	if (fd == -1)
		return false;

	alfd->fp = fdopen(fd, "w+");
	if (alfd->fp == NULL) {
		close(fd);
		return false;
	}

	setbuf(stdout, NULL);

	if (alfd->target->iovec.write_ldr)
		alfd->target->iovec.write_ldr(alfd, opts);

	/* write out one DXE per ELF given to us */
	while (filelist[++i]) {
		if (!quiet)
			printf(" Adding DXE '%s' ... ", filelist[i]);

		/* lets get this ELF rolling */
		elf = elf_open(filelist[i]);
		if (elf == NULL) {
			warn("'%s' is not a Blackfin ELF!", filelist[i]);
			ret &= false;
			continue;
		}

		Elf32_Ehdr *ehdr = elf->ehdr;
		Elf32_Phdr *phdr = elf->phdr;

		/* spit out a special first block if the target needs it */
		alfd->target->iovec.write_block(alfd, DXE_BLOCK_FIRST, opts, EGET(ehdr->e_entry), 0, NULL);

		/* if the user gave us some init code, let's pull the code out */
		if (opts->init_code) {
			elfobj *init = elf_open(opts->init_code);
			if (init == NULL) {
				warn("'%s' is not a Blackfin ELF!", opts->init_code);
				ret &= false;
			} else {
				Elf32_Shdr *shdr = elf_lookup_section(init, ".text");

				if (!EGET(shdr->sh_size)) {
					warn("'%s' is missing .text to extract", opts->init_code);
				} else {
					if (!quiet)
						printf("[initcode %zi] ", EGET(shdr->sh_size));

					alfd->target->iovec.write_block(alfd, DXE_BLOCK_INIT, opts, 0, EGET(shdr->sh_size), init->data + EGET(shdr->sh_offset));
				}

				elf_close(init);
			}
		}

		/* if the ELF has ldr init markers, let's pull the code out */
		dxe_init_start = elf_lookup_symbol(elf, "dxe_init_start");
		dxe_init_end = elf_lookup_symbol(elf, "dxe_init_end");
		if (dxe_init_start != dxe_init_end) {
			if (!quiet)
				printf("[init block %zi] ", (size_t)(dxe_init_end - dxe_init_start));
			alfd->target->iovec.write_block(alfd, DXE_BLOCK_INIT, opts, 0, (dxe_init_end-dxe_init_start), dxe_init_start);
		}

		size_t final_load, p;
		bool elf_ok = true;

		/* figure out the index of the last PT_LOAD program header
		 * and validate there arent any crappy program headers
		 */
		final_load = EGET(ehdr->e_phnum);
		for (p = 0; p < EGET(ehdr->e_phnum); ++p)
			switch (EGET(phdr[p].p_type)) {
				case PT_LOAD:
					final_load = p;
					break;

				case PT_INTERP:
				case PT_DYNAMIC:
					warn("'%s' is not a static ELF!", filelist[i]);
					elf_ok &= false;
					p = EGET(ehdr->e_phnum);
					break;
			}
		/* if program headers are OK, then check for undefined symbols */
		if (elf_ok && elf->shdr) {
			Elf32_Shdr *shdr = elf->shdr;
			size_t shi;

			/* since one ELF can have multiple SYMTAB's, need to check them all */
			for (shi = 0; shi < EGET(ehdr->e_shnum); ++shi) {
				if (EGET(shdr[shi].sh_type) != SHT_SYMTAB)
					continue;

				Elf32_Sym *sym = SYM32(elf->data + EGET(shdr[shi].sh_offset));
				const char *symname;
				size_t symi = 0;

				/* skip first "notype" undefined sym */
				symname = elf->data + EGET(shdr[EGET(shdr[shi].sh_link)].sh_offset) + EGET(sym[symi].st_name);
				if (!strcmp(symname, ""))
					++symi;

				/* now check all of the SYMs in this SYMTAB section */
				for (; symi < EGET(shdr[shi].sh_size) / EGET(shdr[shi].sh_entsize); ++symi) {
					if (EGET(sym[symi].st_shndx) != SHN_UNDEF)
						continue;

					/* VDSP labels "FILE" types as SHN_UNDEF */
					if (ELF32_ST_TYPE(EGET(sym[symi].st_info)) == STT_FILE)
						continue;

					const char *symname = elf->data + EGET(shdr[EGET(shdr[shi].sh_link)].sh_offset) + EGET(sym[symi].st_name);
					warn("Undefined symbol '%s' in ELF!", symname);
					if (!force) {
						elf_ok &= false;
						break;
					}
				}
				if (!elf_ok)
					break;
			}
		}
		if (!elf_ok) {
			elf_close(elf);
			ret &= false;
			continue;
		}

		/* now create a jump block to the ELF entry ... we can
		 * only omit this block if the ELF entry is the same as
		 * what the bootrom defaults to, but this differs depending
		 * on the target, so we have to let the target figure out
		 * if it can ommit the jump.
		 */
		if (!quiet)
			printf("[jump block] ");
		alfd->target->iovec.write_block(alfd, DXE_BLOCK_JUMP, opts, EGET(ehdr->e_entry), DXE_JUMP_CODE_SIZE, dxe_jump_code(EGET(ehdr->e_entry)));

		/* extract each PT_LOAD program header */
		for (p = 0; p < EGET(ehdr->e_phnum); ++p) {
			if (EGET(phdr->p_type) == PT_LOAD) {
				uint32_t final;
				size_t paddr = EGET(phdr->p_paddr);
				size_t filesz = EGET(phdr->p_filesz);
				size_t memsz = EGET(phdr->p_memsz);

				if (!quiet)
					printf("[ELF block: %zi @ 0x%08zX] ", memsz, paddr);

				if (filesz) {
					final = (p == final_load && memsz == filesz ? DXE_BLOCK_FINAL : 0);
					lfd_blockify(alfd, opts, final, paddr, filesz, elf->data + EGET(phdr->p_offset));
				}

				if (memsz > filesz) {
					final = (p == final_load ? DXE_BLOCK_FINAL : 0);
					alfd->target->iovec.write_block(alfd, DXE_BLOCK_FILL | final, opts, paddr + filesz, memsz - filesz, NULL);
				}
			}
			++phdr;
		}

		/*
		 * XXX: VDSP does not fully enumerate the program header table, so
		 *      no DXE blocks are made for bss sections ... do we care ?
		 *      we'd walk the section table here for NOBITS ...
		 */

		elf_close(elf);

		if (!quiet)
			printf("OK!\n");
	}

	fclose(alfd->fp);
	close(fd);
	alfd->fp = NULL;

	return ret;
}

bool lfd_dump(LFD *alfd, const void *void_opts)
{
	if (!alfd->is_open) {
		errno = -EBADF;
		return false;
	}

	if (!alfd->target->iovec.dump_block) {
		warn("target '%s' does not support dumping LDRs", alfd->target->name);
		return false;
	}

	const struct ldr_dump_options *opts = void_opts;
	LDR *ldr = alfd->private_data;
	const char *base = opts->filename;
	char file_dxe[1024], file_block[1024];
	FILE *fp_dxe, *fp_block;
	size_t d, b;
	uint32_t next_block_addr;
	bool ret = true;

	for (d = 0; d < ldr->num_dxes; ++d) {
		snprintf(file_dxe, sizeof(file_dxe), "%s-%zi.dxe", base, d);
		if (!quiet)
			printf("  Dumping DXE %zi to %s\n", d, file_dxe);
		fp_dxe = fopen(file_dxe, "w");
		if (fp_dxe == NULL) {
			warnp("Unable to open DXE output '%s'", file_dxe);
			ret = false;
			break;
		}

		next_block_addr = 0;
		fp_block = NULL;
		for (b = 0; b < ldr->dxes[d].num_blocks; ++b) {
			BLOCK *block;
			uint32_t target_address;

			block = &(ldr->dxes[d].blocks[b]);
			target_address = alfd->target->iovec.dump_block(block, fp_dxe, opts->dump_fill);

			if (fp_block != NULL && next_block_addr != target_address) {
				fclose(fp_block);
				fp_block = NULL;
			}
			if (fp_block == NULL) {
				snprintf(file_block, sizeof(file_block), "%s-%zi.dxe-%zi.block", base, d, b+1);
				if (!quiet)
					printf("    Dumping block %zi to %s\n", b+1, file_block);
				fp_block = fopen(file_block, "w");
				if (fp_block == NULL)
					perror("Unable to open block output");
			}
			if (fp_block != NULL) {
				alfd->target->iovec.dump_block(block, fp_block, opts->dump_fill);
				next_block_addr = target_address + block->data_size;
			}
		}
		fclose(fp_dxe);
	}

	return true;
}

/*
 * ldr_send()
 * Transmit the specified ldr over the serial line to a BF537.  Used when
 * you want to boot over the UART.
 *
 * The way this works is:
 *  - reboot board
 *  - write @ so the board autodetects the baudrate
 *  - read 4 bytes from the board (0xBF UART_DLL UART_DLH 0x00)
 *  - start writing the blocks
 *  - if data is being sent too fast, the board will assert CTS until
 *    it is ready for more ... we let the kernel worry about this crap
 *    in the call to write()
 */
static void ldr_send_timeout(int sig)
{
	warn("received signal %i: timeout while sending; aborting", sig);
	exit(2);
}
static void ldr_send_erase_output(size_t count)
{
	while (count--)
		printf("\b \b");
}
static char ldr_send_prompt(const char *msg)
{
	int outret, inret;
	char dummy;
	alarm(0);
	outret = printf("\n%s: ", msg);
	fflush(stdout);
	while ((inret = read(0, &dummy, 1)) == -1)
		if (errno != EAGAIN)
			break;
	return (inret <= 0 ? EOF : dummy);
}
static void *ldr_read_board(void *arg)
{
	int fd = *(int *)arg;
	char buf[1024];

	while (1) {
		ssize_t ret = read(fd, buf, sizeof(buf)-1);
		if (ret > 0) {
			buf[ret] = '\0';
			printf("[board said: %s]\n", buf);
		}
	}

	return NULL;
}
static struct termios stdin_orig_attrs;
void ldr_restore_stdin_attrs(void)
{
	tcsetattr(0, TCSANOW, &stdin_orig_attrs);
}
static bool ldr_load_uart(LFD *alfd, const void *void_opts)
{
	const struct ldr_load_options *opts = void_opts;
	LDR *ldr = alfd->private_data;
	const char *tty = opts->tty;
	unsigned char autobaud[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
	int fd = -1;
	bool ok = false, prompt = opts->prompt;
	ssize_t ret;
	size_t d, b, baud, sclock;
	void (*old_alarm)(int);
	pthread_t reader;
	struct termios stdin_attrs;

	if (tty_lock(tty)) {
		if (!force) {
			warn("tty '%s' is locked", tty);
			return false;
		} else
			warn("ignoring lock for tty '%s'", tty);
	}

	setbuf(stdout, NULL);

	tcgetattr(0, &stdin_orig_attrs);
	atexit(ldr_restore_stdin_attrs);
	stdin_attrs = stdin_orig_attrs;
	stdin_attrs.c_lflag &= ~(ECHO | ICANON);
	tcsetattr(0, TCSADRAIN, &stdin_attrs);
	setbuf(stdin, NULL);

	old_alarm = signal(SIGALRM, ldr_send_timeout);

	alarm(10);
	printf("Opening %s ... ", tty);
	if (tty[0] != '#') {
		fd = open(tty, O_RDWR);
		if (fd == -1)
			goto out;
	} else
		fd = atoi(tty+1);
	printf("OK!\n");

	printf("Configuring terminal I/O ... ");
	if (!tty_init(fd, opts->baud)) {
		if (!force) {
			perror("Failed");
			goto out;
		} else
			perror("Skipping");
	} else
		printf("OK!\n");

	if (prompt)
		ldr_send_prompt("Press any key to send autobaud");

	alarm(10);
	printf("Trying to send autobaud ... ");
	ret = write(fd, "@", 1);
	if (ret != 1)
		goto out;
	tcdrain(fd);
	printf("OK!\n");

	if (prompt)
		ldr_send_prompt("Press any key to read autobaud");

	alarm(10);
	printf("Trying to read autobaud ... ");
	ret = read_retry(fd, autobaud, 4);
	if (ret != 4)
		goto out;
	printf("OK!\n");

	printf("Checking autobaud ... ");
	if (autobaud[0] != 0xBF || autobaud[3] != 0x00) {
		printf("Failed: wanted {0xBF,..,..,0x00} but got {0x%02X,[0x%02X],[0x%02X],0x%02X}\n",
			autobaud[0], autobaud[1], autobaud[2], autobaud[3]);
		goto out;
	}
	printf("OK!\n");

	pthread_create(&reader, NULL, ldr_read_board, &fd);

	/* bitrate = SCLK / (16 * Divisor) */
	baud = tty_get_baud(fd);
	sclock = baud * 16 * (autobaud[1] + (autobaud[2] << 8));
	printf("Autobaud result: %zibps %zi.%zimhz (header:0x%02X DLL:0x%02X DLH:0x%02X fin:0x%02X)\n",
	       baud, sclock / 1000000, sclock / 1000 - sclock / 1000000 * 1000,
	       autobaud[0], autobaud[1], autobaud[2], autobaud[3]);

	if (ldr->header) {
		if (prompt)
			if (ldr_send_prompt("Press any key to send global LDR header") == 'c')
				prompt = false;

		alarm(10);
		printf("Sending global LDR header ... ");
		ret = write(fd, ldr->header, ldr->header_size);
		if (ret != (ssize_t)ldr->header_size)
			goto pout;
		tcdrain(fd);
		printf("OK!\n");
	}

	for (d = 0; d < ldr->num_dxes; ++d) {
		printf("Sending blocks of DXE %zi ... ", d+1);
		for (b = 0; b < ldr->dxes[d].num_blocks; ++b) {
			BLOCK *block = &(ldr->dxes[d].blocks[b]);
			int del;

			if (prompt)
				if (ldr_send_prompt("Press any key to send block header") == 'c')
					prompt = false;

			alarm(60);

			if (verbose)
				printf("[%zi:%zi bytes] ", block->header_size, block->data_size);

			del = printf("[%zi/", b+1);
			ret = write(fd, block->header, block->header_size);
			if (ret != (ssize_t)block->header_size)
				goto pout;
			tcdrain(fd);

			if (prompt && block->data != NULL)
				if (ldr_send_prompt("Press any key to send block data") == 'c')
				prompt = false;

			del += printf("%zi] (%2.0f%%)", ldr->dxes[d].num_blocks,
			              ((float)(b+1) / (float)ldr->dxes[d].num_blocks) * 100);
			if (block->data != NULL) {
				ret = write(fd, block->data, block->data_size);
				if (ret != (ssize_t)block->data_size)
					goto pout;
				tcdrain(fd);
			}

			if (!prompt)
				ldr_send_erase_output(del);
		}
		printf("OK!\n");
	}

	if (!quiet)
		printf("You may want to run minicom or kermit now\n"
		       "Quick tip: run 'ldr <ldr> <tty> && minicom'\n");

	ok = true;
 pout:
	pthread_cancel(reader);
 out:
	if (!ok)
		perror("Failed");
	if (fd != -1)
		close(fd);
	alarm(0);
	signal(SIGALRM, old_alarm);
	ok &= tty_unlock(tty);
	return ok;
}
bool lfd_load_uart(LFD *alfd, const void *opts)
{
	if (!alfd->is_open) {
		errno = -EBADF;
		return false;
	}

	if (!alfd->target->uart_boot) {
		warn("target '%s' does not support booting via UART", alfd->selected_target);
		return false;
	} else
		return ldr_load_uart(alfd, opts);
}

/**
 *	lfd_close
 */
bool lfd_close(LFD *alfd)
{
	if (!alfd->is_open) {
		errno = -EBADF;
		return false;
	}

	if (alfd->target->iovec.close) {
		if (!alfd->target->iovec.close(alfd))
			return false;
	} else if (alfd->private_data) {
		LDR *ldr = alfd->private_data;
		size_t d, b;

		for (d = 0; d < ldr->num_dxes; ++d) {
			for (b = 0; b < ldr->dxes[d].num_blocks; ++b) {
				free(ldr->dxes[d].blocks[b].header);
				free(ldr->dxes[d].blocks[b].data);
			}
			free(ldr->dxes[d].blocks);
		}
		free(ldr->dxes);
		free(ldr->header);
		free(ldr);

		alfd->private_data = NULL;
	}

	if (fclose(alfd->fp))
		return false;

	alfd->target = NULL;
	alfd->filename = NULL;
	alfd->fp = NULL;
	alfd->is_open = false;

	return true;
}
