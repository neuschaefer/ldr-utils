/*
 * File: ldr.c
 *
 * Copyright 2006-2007 Analog Devices Inc.
 * Licensed under the GPL-2, see the file COPYING in this dir
 *
 * Description:
 * View LDR contents; based on the "Visual DSP++ 4.0 Loader Manual"
 * and misc Blackfin HRMs
 */

#include "headers.h"
#include "helpers.h"
#include "ldr.h"
#include "dxes.h"
#include "elf.h"

struct ldr_flag {
	uint16_t flag;
	const char *desc;
};

struct ldr_flag ldr_common_flag_list[] = {
	{ LDR_FLAG_ZEROFILL, "zerofill" },
	{ LDR_FLAG_RESVECT,  "resvect"  },
	{ LDR_FLAG_INIT,     "init"     },
	{ LDR_FLAG_IGNORE,   "ignore"   },
	{ LDR_FLAG_FINAL,    "final"    },
	{ 0, 0 }
};
struct ldr_flag ldr_bf537_flag_list[] = {
	{ LDR_FLAG_PPORT_NONE,  "port_none" },
	{ LDR_FLAG_PPORT_PORTF, "portf"     },
	{ LDR_FLAG_PPORT_PORTG, "portg"     },
	{ LDR_FLAG_PPORT_PORTH, "porth"     },
	{ 0, 0 }
};

/*
 * Parse a string like 'BF###' or just '###' into an acceptable cpu integer
 */
int str2bfcpu(const char *cpu)
{
	int cpunum;
	char tmp;

	if (strlen(cpu) >= 2 && (cpu[0] == 'B' || cpu[0] == 'b') && (cpu[1] == 'F' || cpu[1] == 'f'))
		cpu += 2;
	if (sscanf(cpu, "%i%c", &cpunum, &tmp) == 2)
		return -1;
	if (sscanf(cpu, "%i", &cpunum) != 1)
		return -2;

	switch (cpunum) {
		case 531:
		case 532:
		case 533:
		case 534:
		case 535:
		case 536:
		case 537:
		case 561:
			return cpunum;
	}

	return -cpunum;
}


/*
 * _ldr_read_bin()
 * Translate the ADI visual dsp ldr binary format into our ldr structure.
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
 * [4 bytes for address]
 * [4 bytes for byte count]
 * [2 bytes for flags]
 * [data]
 * If the zero flag is set, there is no actual data section, otherwise
 * the data block will be [byte count] bytes long.
 *
 * TODO: The BF561 has a 4 byte global header prefixed to the LDR
 *       which we do not handle here.
 */
static LDR *_ldr_read_bin(FILE *fp)
{
	LDR *ldr;
	DXE *dxe;
	BLOCK *block;
	size_t pos = 0, d;
	uint8_t header[LDR_BLOCK_HEADER_LEN];
	uint16_t flags;

	ldr = xmalloc(sizeof(LDR));
	ldr->dxes = NULL;
	ldr->num_dxes = 0;
	d = 0;

	do {
		fread(header, LDR_BLOCK_HEADER_LEN, 1, fp);
		if (feof(fp))
			break;
		memcpy(&flags, header+8, sizeof(flags));
		ldr_make_little_endian_16(flags);
		if (flags & LDR_FLAG_IGNORE) {
			ldr->dxes = xrealloc(ldr->dxes, (++ldr->num_dxes) * sizeof(DXE));
			dxe = &ldr->dxes[d++];
			dxe->num_blocks = 0;
			dxe->blocks = NULL;
		} else if (ldr->dxes == NULL) {
			printf("Invalid block header in LDR!\n");
			free(ldr);
			return NULL;
		}

		++dxe->num_blocks;
		dxe->blocks = xrealloc(dxe->blocks, dxe->num_blocks * sizeof(BLOCK));
		block = &dxe->blocks[dxe->num_blocks-1];
		block->offset = pos;
		memcpy(block->header, header, sizeof(header));
		memcpy(&(block->target_address), block->header, sizeof(block->target_address));
		memcpy(&(block->byte_count), block->header+4, sizeof(block->byte_count));
		memcpy(&(block->flags), block->header+8, sizeof(block->flags));
		ldr_make_little_endian_32(block->target_address);
		ldr_make_little_endian_32(block->byte_count);
		ldr_make_little_endian_16(block->flags);
		if (block->flags & LDR_FLAG_ZEROFILL)
			block->data = NULL;
		else {
			block->data = xmalloc(block->byte_count);
			fread(block->data, block->byte_count, 1, fp);
		}

		if (block->flags & LDR_FLAG_FINAL)
			break;

		pos += block->byte_count + sizeof(block->header);
	} while (1);

	return ldr;
}

/*
 * _ldr_read_ihex()
 * Translate the Intel HEX32 format into our ldr structure.
 *
 * TODO: implement it
 * Documentation: http://en.wikipedia.org/wiki/Intel_hex
 */
static LDR *_ldr_read_ihex(FILE *fp)
{
	warn("Sorry, but parsing of Intel HEX32 files not supported yet");
	warn("Please convert to binary format:");
	warn(" $ objcopy -I ihex -O binary <infile> <outfile>");
	return NULL;
}

/*
 * _ldr_read_srec()
 * Translate the Motorola SREC format into our ldr structure.
 *
 * TODO: get some documentation on the actual file format and implement it
 */
static LDR *_ldr_read_srec(FILE *fp)
{
	warn("Sorry, but parsing of Motorola SREC files not supported yet");
	warn("Please convert to binary format:");
	warn(" $ objcopy -I srec -O binary <infile> <outfile>");
	return NULL;
}

/*
 * ldr_read()
 * Open the specified file, figure out what format it is, and
 * then call the function to translate the format into our own
 * ldr memory structure.
 */
LDR *ldr_read(const char *filename)
{
	FILE *fp;
	LDR *ret;
	char byte_header[2];

	fp = fopen(filename, "r");
	if (fp == NULL)
		return NULL;

	fread(byte_header, 1, 2, fp);
	rewind(fp);

	/* this of course assumes the address itself doesnt happen to translate
	 * into the corresponding ASCII value ... but this is a pretty safe bet
	 * anyways, so lets do it ...
	 */
	switch (byte_header[0]) {
		case ':': ret = _ldr_read_ihex(fp); break;
		case 'S': ret = _ldr_read_srec(fp); break;
		default:  ret = _ldr_read_bin(fp); break;
	}

	fclose(fp);

	return ret;
}

/*
 * ldr_free()
 * Free all the memory taken up by our ldr structure.
 */
void ldr_free(LDR *ldr)
{
	size_t d, b;
	for (d = 0; d < ldr->num_dxes; ++d) {
		for (b = 0; b < ldr->dxes[d].num_blocks; ++b)
			free(ldr->dxes[d].blocks[b].data);
		free(ldr->dxes[d].blocks);
	}
	free(ldr->dxes);
	free(ldr);
}

/*
 * ldr_print()
 * Translate our ldr structure into something human readable.
 */
int ldr_print(LDR *ldr)
{
	size_t i, d, b;
	uint16_t pport;

	if (ldr == NULL)
		return -1;

	for (d = 0; d < ldr->num_dxes; ++d) {
		printf("  DXE %zu at 0x%08zX:\n", d+1, ldr->dxes[d].blocks[0].offset);
		if (quiet)
			printf("              Offset      Address     Bytes    Flags\n");
		for (b = 0; b < ldr->dxes[d].num_blocks; ++b) {
			BLOCK *block = &(ldr->dxes[d].blocks[b]);
			if (quiet)
				printf("    Block %zu 0x%08zX: ", b+1, block->offset);
			else
				printf("    Block %zu at 0x%08zX\n", b+1, block->offset);

			if (quiet) {
				printf("0x%08X 0x%08X 0x%04X ( ", block->target_address, block->byte_count, block->flags);
			} else if (verbose) {
				printf("\t\tTarget Address: 0x%08X ( %s )\n", block->target_address,
					(block->target_address > 0xFF000000 ? "L1" : "SDRAM"));
				printf("\t\t    Byte Count: 0x%08X ( %u bytes )\n", block->byte_count, block->byte_count);
				printf("\t\t         Flags: 0x%04X     ( ", block->flags);
			} else {
				printf("         Addr: 0x%08X Bytes: 0x%08X Flags: 0x%04X ( ",
					block->target_address, block->byte_count, block->flags);
			}

			for (i = 0; ldr_common_flag_list[i].desc; ++i)
				if (block->flags & ldr_common_flag_list[i].flag)
					printf("%s ", ldr_common_flag_list[i].desc);

			pport = block->flags & LDR_FLAG_PPORT_MASK;
			if (pport)
				for (i = 0; ldr_bf537_flag_list[i].desc; ++i)
					if (pport == ldr_bf537_flag_list[i].flag)
						printf("%s ", ldr_bf537_flag_list[i].desc);
			pport = (block->flags & LDR_FLAG_PFLAG_MASK) >> LDR_FLAG_PFLAG_SHIFT;
			if (pport)
				printf("gpio%i ", pport);

			printf(")\n");
		}
	}

	return 0;
}

/*
 * ldr_dump()
 * Dump the individual DXEs into separate files.
 */
int ldr_dump(const char *base, LDR *ldr)
{
	char file_dxe[1024], file_block[1024];
	FILE *fp_dxe, *fp_block;
	size_t d, b;
	uint32_t next_block_addr;

	if (ldr == NULL)
		return -1;

	for (d = 0; d < ldr->num_dxes; ++d) {
		snprintf(file_dxe, sizeof(file_dxe), "%s-%zi.dxe", base, d);
		if (!quiet)
			printf("  Dumping DXE %zi to %s\n", d, file_dxe);
		fp_dxe = fopen(file_dxe, "w");
		if (fp_dxe == NULL) {
			perror("Unable to open DXE output");
			return -1;
		}

		next_block_addr = 0;
		fp_block = NULL;
		for (b = 0; b < ldr->dxes[d].num_blocks; ++b) {
			BLOCK *block = &(ldr->dxes[d].blocks[b]);
			fwrite(block->data, 1, block->byte_count, fp_dxe);

			if (fp_block != NULL && next_block_addr != block->target_address) {
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
				fwrite(block->data, 1, block->byte_count, fp_block);
				next_block_addr = block->target_address + block->byte_count;
			}
		}
		fclose(fp_dxe);
	}

	return 0;
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
void ldr_send_timeout(int sig)
{
	warn("received signal %i: timeout while sending; aborting", sig);
	exit(2);
}
int ldr_send(LDR *ldr, const char *tty)
{
	unsigned char autobaud[4] = { 0xFF, 0xFF, 0xFF, 0xFF };
	int fd, error = 1;
	ssize_t ret;
	size_t d, b, baud, sclock;
	void (*old_alarm)(int);

	if (tty_lock(tty)) {
		warn("tty '%s' is locked", tty);
		return 3;
	}

	setbuf(stdout, NULL);

	/* give ourselves like ten seconds to do autobaud */
	old_alarm = signal(SIGALRM, ldr_send_timeout);
	alarm(10);

	printf("Opening %s ... ", tty);
	fd = open(tty, O_RDWR);
	if (fd == -1)
		goto out;
	printf("OK!\n");

	printf("Configuring terminal I/O ... ");
	if (tty_init(fd))
		perror("skipping");
	else
		printf("OK!\n");

	printf("Trying to send autobaud ... ");
	ret = write(fd, "@", 1);
	if (ret != 1)
		goto out;
	printf("OK!\n");

	printf("Trying to read autobaud ... ");
	ret = read_retry(fd, autobaud, 4);
	if (ret != 4)
		goto out;
	printf("OK!\n");

	printf("Checking autobaud ... ");
	if (autobaud[0] != 0xBF || autobaud[3] != 0x00) {
		printf("Failed: wanted {0xBF,..,..,0x00} but got {0x%02X,[0x%02X],[0x%02X],0x%02X}\n",
			autobaud[0], autobaud[1], autobaud[2], autobaud[3]);
		error = 2;
		goto out;
	}
	printf("OK!\n");

	/* bitrate = SCLK / (16 * Divisor) */
	baud = tty_get_baud(fd);
	sclock = baud * 16 * (autobaud[1] + (autobaud[2] << 8));
	printf("Autobaud result: %zibps %zi.%zimhz (header:0x%02X DLL:0x%02X DLH:0x%02X fin:0x%02X)\n",
	       baud, sclock / 1000000, sclock / 1000 - sclock / 1000000 * 1000,
	       autobaud[0], autobaud[1], autobaud[2], autobaud[3]);

	for (d = 0; d < ldr->num_dxes; ++d) {
		printf("Sending blocks of DXE %zi ... ", d+1);
		for (b = 0; b < ldr->dxes[d].num_blocks; ++b) {
			BLOCK *block = &(ldr->dxes[d].blocks[b]);

			alarm(60);

			printf("[%zi/", b+1);
			ret = write(fd, block->header, sizeof(block->header));
			if (ret != sizeof(block->header))
				goto out;

			printf("%zi] ", ldr->dxes[d].num_blocks);
			if (block->data != NULL) {
				ret = write(fd, block->data, block->byte_count);
				if (ret != (ssize_t)block->byte_count)
					goto out;
			}
		}
		printf("OK!\n");
	}

	close(fd);

	if (!quiet)
		printf("You may want to run minicom or kermit now\n"
		       "Quick tip: run 'ldrviewer <ldr> <tty> && minicom'\n");

	error = 0;
out:
	if (error == -1)
		perror("Failed");
	alarm(0);
	signal(SIGALRM, old_alarm);
	error |= tty_unlock(tty);
	return error;
}

/*
 * ldr_create()
 */
#define LDR_ADDR_IGNORE  0xFF800040
#define LDR_ADDR_INIT    0xFFA00000
#define LDR_ADDR_SDRAM   0x1000 /* TODO: should make this configurable */
#define LDR_BLOCK_SIZE   0x8000 /* TODO: should make this configurable */
static void _ldr_write_block(const int fd, BLOCK b)
{
	ldr_make_little_endian_32(b.target_address);
	ldr_make_little_endian_32(b.byte_count);
	ldr_make_little_endian_16(b.flags);
	write(fd, &b.target_address, sizeof(b.target_address));
	write(fd, &b.byte_count, sizeof(b.byte_count));
	write(fd, &b.flags, sizeof(b.flags));
	if (b.data) {
		ssize_t ret = write(fd, b.data, b.byte_count);
		if (ret < 0)
			printf("[write() failed: %s] ", strerror(errno));
	}
}
#define _ldr_quick_write_block(fd, _target_address, _byte_count, _flags, _data) \
	do { \
		BLOCK b; \
		b.target_address = _target_address; \
		b.byte_count = _byte_count; \
		b.flags = _flags; \
		b.data = _data; \
		_ldr_write_block(fd, b); \
	} while (0)
static int _ldr_copy_file_to_block(int out_fd, const char *file, uint32_t addr, uint16_t flags)
{
	FILE *in_fp;
	char *data;
	size_t bytes_written, cnt, cnt_left;
	struct stat st;
	uint32_t filesize;
	uint16_t out_flags = (flags & ~LDR_FLAG_FINAL);

	in_fp = fopen(file, "r");
	if (in_fp == NULL)
		return -1;

	data = xmalloc(LDR_BLOCK_SIZE);

	fstat(fileno(in_fp), &st);
	filesize = st.st_size;
	bytes_written = 0;
	cnt_left = 0;

	while (bytes_written < filesize) {
		if (cnt_left == 0) {
			if (filesize < LDR_BLOCK_SIZE)
				cnt_left = filesize;
			else if (filesize - bytes_written < LDR_BLOCK_SIZE)
				cnt_left = filesize - bytes_written;
			else
				cnt_left = LDR_BLOCK_SIZE;
			if ((flags & LDR_FLAG_FINAL) && (bytes_written + LDR_BLOCK_SIZE >= filesize))
				out_flags = flags;
			_ldr_quick_write_block(out_fd, addr, cnt_left, out_flags, NULL);
			cnt_left = LDR_BLOCK_SIZE;
			addr += LDR_BLOCK_SIZE;
		}

		cnt = fread(data, 1, cnt_left, in_fp);
		if (cnt) {
			bytes_written += cnt;
			cnt_left -= cnt;
			write(out_fd, data, cnt);
		}
	} while (!feof(in_fp));

	free(data);

	return 0;
}
int ldr_create(char **filelist, struct ldr_create_options *opts)
{
	uint16_t base_flags;
	uint8_t *jump_bin = dxe_jump_code(LDR_ADDR_SDRAM);
	elfobj *elf;
	uint8_t *dxe_init_start, *dxe_init_end;
	const char *outfile = filelist[0];
	char *tmpfile;
	size_t i = 0;
	int fd;

	fd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC| (force?0:O_EXCL), 00660);
	if (fd == -1)
		return -1;

	setbuf(stdout, NULL);

	base_flags = (opts->resvec ? LDR_FLAG_RESVECT : 0);
	base_flags |= (opts->gpio << LDR_FLAG_PFLAG_SHIFT) & LDR_FLAG_PFLAG_MASK;
	switch (toupper(opts->port)) {
		case 'F': base_flags |= LDR_FLAG_PPORT_PORTF; break;
		case 'G': base_flags |= LDR_FLAG_PPORT_PORTG; break;
		case 'H': base_flags |= LDR_FLAG_PPORT_PORTH; break;
		default:  base_flags |= LDR_FLAG_PPORT_NONE; break;
	}
	if (!quiet)
		printf(" Base flags: 0x%X\n", base_flags);

	if (opts->cpu == 561) {
		/* BF561 requires a 4 byte 'global' header for external memory */
		/* TODO: allow users to control this */
		uint8_t bf561_global_block[4] = { 0xDF, 0x00, 0x00, 0xA0 };
		if (write(fd, bf561_global_block, 4) != 4)
			errp("Could not write 4 byte global header for BF561");
	}

	/* write out one DXE per ELF given to us */
	while (filelist[++i]) {
		if (!quiet)
			printf(" Adding DXE '%s' ... ", filelist[i]);

		/* TODO: for the BF561, we need to output a 32bit byte count DXE block */
		if (opts->cpu == 561) {
			/*
			_ldr_quick_write_block(fd, LDR_ADDR_IGNORE, 0x4, base_flags|LDR_FLAG_IGNORE, buf);
			*/
			printf("[Skipping 32bit byte count DXE block] ");
		}

		/* if the ELF has ldr init markers, let's pull the code out */
		elf = elf_open(filelist[i]);
		if (elf == NULL) {
			printf(" '%s' is not an ELF!\n", filelist[i]);
			continue;
		}
		dxe_init_start = elf_lookup_symbol(elf, "dxe_init_start");
		dxe_init_end = elf_lookup_symbol(elf, "dxe_init_end");
		if (dxe_init_start != dxe_init_end) {
			if (!quiet)
				printf("[init block %zi] ", (size_t)(dxe_init_end - dxe_init_start));
			_ldr_quick_write_block(fd, LDR_ADDR_IGNORE, 0x4, base_flags|LDR_FLAG_IGNORE, (uint8_t*)"\0\0\0\0");
			_ldr_quick_write_block(fd, LDR_ADDR_INIT, (dxe_init_end-dxe_init_start), base_flags|LDR_FLAG_INIT, dxe_init_start);
		}
		elf_close(elf);

		/* convert the ELF to a binary */
		tmpfile = xmalloc(strlen(filelist[i])+sizeof(".tmp..bin"));
		{
			char *base_ret, *base_tmp = xstrdup(filelist[i]);
			base_ret = basename(base_tmp);
			sprintf(tmpfile, ".tmp.%s.bin", base_ret);
			free(base_tmp);
		}
		if (fork()) {
			int status;
			wait(&status);
			if (status) {
				printf("[objcopy exit (%i)] ", status);
				free(tmpfile);
				return -1;
			}
		} else {
			execlp("bfin-uclinux-objcopy", "bfin-uclinux-objcopy", "-O", "binary", filelist[i], tmpfile, NULL);
			printf("[objcopy failed (%s)] ", strerror(errno));
			exit(1);
		}

		/* write out two blocks: ignore followed by jump code */
		if (!quiet)
			printf("[jump block] ");
		_ldr_quick_write_block(fd, LDR_ADDR_IGNORE, 4, base_flags|LDR_FLAG_IGNORE, (uint8_t*)"\0\0\0\0");
		_ldr_quick_write_block(fd, LDR_ADDR_INIT, DXE_JUMP_CODE_SIZE, base_flags, jump_bin);

		/* write out third (and last block) for the actual file */
		if (!quiet)
			printf("[file blocks] ");
		if (_ldr_copy_file_to_block(fd, tmpfile, LDR_ADDR_SDRAM, base_flags|(filelist[i+1] == NULL ? LDR_FLAG_FINAL : 0)) == -1) {
			printf("Unable to copy '%s' to output\n", filelist[i]);
			unlink(tmpfile);
			free(tmpfile);
			return -1;
		}

		unlink(tmpfile);
		free(tmpfile);

		if (!quiet)
			printf("OK!\n");
	}

	close(fd);

	return (i > 1 ? 0 : 1);
}
