/*
 * File: ldrviewer.c
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


static const char *rcsid = "$Id$";
const char *argv0;
int force = 0, verbose = 0, quiet = 0;


struct option_help {
	const char *desc, *opts;
};

#define PARSE_FLAGS "sdlcfvqhV"
#define a_argument required_argument
static struct option const long_opts[] = {
	{"show",     no_argument, NULL, 's'},
	{"dump",     no_argument, NULL, 'd'},
	{"load",     no_argument, NULL, 'l'},
	{"create",   no_argument, NULL, 'c'},
	{"force",    no_argument, NULL, 'f'},
	{"verbose",  no_argument, NULL, 'v'},
	{"quiet",    no_argument, NULL, 'q'},
	{"help",     no_argument, NULL, 'h'},
	{"version",  no_argument, NULL, 'V'},
	{NULL,       no_argument, NULL, 0x0}
};
static struct option_help const opts_help[] = {
	{"Show details of a LDR",         "<ldrs>"},
	{"Break DXEs out of LDR",         "<ldrs>"},
	{"Load LDR over UART to a BF537", "<ldr> <tty>"},
	{"Create LDR from binaries\n",    "<ldr> <elfs>"},
	{"Ignore errors",                 NULL},
	{"Make a lot of noise",           NULL},
	{"Only show errors",              NULL},
	{"Print this help and exit",      NULL},
	{"Print version and exit",        NULL},
	{NULL,NULL}
};
#define show_usage(status) show_some_usage(long_opts, opts_help, PARSE_FLAGS, status)

#define CREATE_PARSE_FLAGS "rp:g:hC:b:l:"
static struct option const create_long_opts[] = {
	{"cpu",       a_argument, NULL, 'C'},
	{"resvec",   no_argument, NULL, 'r'},
	{"port",      a_argument, NULL, 'p'},
	{"gpio",      a_argument, NULL, 'g'},
	{"blocksize", a_argument, NULL, 'b'},
	{"loadaddr",  a_argument, NULL, 'l'},
	{"help",     no_argument, NULL, 'h'},
	{NULL,       no_argument, NULL, 0x0}
};
static struct option_help const create_opts_help[] = {
	{"Select target CPU type",        "<BFXXX>"},
	{"Enable resvec bit",             NULL},
	{"Select PORT for HWAIT signal",  "<F|G|H>"},
	{"Select GPIO for HWAIT signal",  "<#>"},
	{"Block size of DXE (0x8000)",    "<size>"},
	{"Load address of DXE (0x1000)",  "<addr>"},
	{"Print this help and exit",      NULL},
	{NULL,NULL}
};
#define show_create_usage(status) show_some_usage(create_long_opts, create_opts_help, CREATE_PARSE_FLAGS, status)

#define LOAD_PARSE_FLAGS "b:fh"
static struct option const load_long_opts[] = {
	{"baud",      a_argument, NULL, 'b'},
	{"force",    no_argument, NULL, 'f'},
	{"help",     no_argument, NULL, 'h'},
	{NULL,       no_argument, NULL, 0x0}
};
static struct option_help const load_opts_help[] = {
	{"Set baud rate (default 115200)", "<baud>"},
	{"Try to force loading",           NULL},
	{"Print this help and exit",       NULL},
	{NULL,NULL}
};
#define show_load_usage(status) show_some_usage(load_long_opts, load_opts_help, LOAD_PARSE_FLAGS, status)

#define CASE_common_errors \
	case ':': err("Option '%c' is missing parameter", optopt); \
	case '?': err("Unknown option '%c' or argument missing", optopt); \
	default:  err("Unhandled option '%c'; please report this", i);

static void show_some_usage(struct option const opts[], struct option_help const help[], const char *flags, int exit_status)
{
	unsigned long i;

	printf("Usage: ldr [options] <-s|-d|-l|-c> [subcommand options] <arguments>\n\n");
	printf("Options: -[%s]\n", flags);
	for (i=0; opts[i].name; ++i) {
		if (!help[i].desc)
			err("someone forgot to update the help text");
		printf("  -%c, --%-10s %-10s * %s\n",
		       opts[i].val, opts[i].name,
		       (help[i].opts != NULL ? help[i].opts :
		          (opts[i].has_arg == no_argument ? "" : "<arg>")),
		       help[i].desc);
	}
	if (opts == long_opts)
		printf(
			"\n"
			"Most subcommands take their own arguments, so type:\n"
			"\tldr <subcommand> --help\n"
			"for help on a specific command.\n"
		);

	exit(exit_status);
}


static int show_ldr(const char *filename)
{
	int ret;
	LDR *ldr;
	printf("Showing LDR %s ...\n", filename);
	ldr = ldr_read(filename);
	if (ldr == NULL) {
		printf("Unable to read specified LDR\n");
		return -1;
	}
	ret = ldr_print(ldr);
	ldr_free(ldr);
	return ret;
}

static int dump_ldr(const char *filename)
{
	int ret;
	LDR *ldr;
	printf("Dumping LDR %s ...\n", filename);
	ldr = ldr_read(filename);
	if (ldr == NULL) {
		perror("Unable to read specified LDR");
		return -1;
	}
	ret = ldr_dump(filename, ldr);
	ldr_free(ldr);
	return ret;
}

static int load_ldr(const int argc, char *argv[])
{
	const char *filename, *tty;
	int ret, i;
	LDR *ldr;
	struct ldr_load_options opts = {
		.baud = 115200,
		.force = 0,
	};

	while ((i=getopt_long(argc, argv, LOAD_PARSE_FLAGS, load_long_opts, NULL)) != -1) {
		switch (i) {
			case 'b': opts.baud = atoi(optarg); break;
			case 'f': opts.force = 1; break;
			case 'h': show_load_usage(0);
			CASE_common_errors
		}
	}

	if (optind + 2 != argc)
		err("Load requires two arguments: <ldr> <tty>");

	filename = argv[optind];
	tty = argv[optind+1];

	printf("Loading LDR %s ... ", filename);
	ldr = ldr_read(filename);
	if (ldr == NULL) {
		perror("Unable to read specified LDR");
		return -1;
	}
	printf("OK!\n");
	ret = ldr_send(ldr, tty, &opts);
	ldr_free(ldr);
	return ret;
}

static int create_ldr(const int argc, char *argv[])
{
	int ret, i;
	struct ldr_create_options opts = {
		.cpu = 0,
		.resvec = 0,
		.port = '?',
		.gpio = 0,
		.block_size = 0x8000,
		.load_addr = 0x1000,
	};

	while ((i=getopt_long(argc, argv, CREATE_PARSE_FLAGS, create_long_opts, NULL)) != -1) {
		switch (i) {
			case 'C': opts.cpu = str2bfcpu(optarg); break;
			case 'r': opts.resvec = 1; break;
			case 'p': opts.port = toupper(optarg[0]); break;
			case 'g': opts.gpio = atoi(optarg); break;
			case 'b':
				/* support reading in hex values since it's much more
				 * common for people to set size in terms of hex ...
				 */
				opts.block_size = atoi(optarg);
				if (opts.block_size == 0)
					sscanf(optarg, "%X", &opts.block_size);
				break;
			case 'l':
				/* support reading in hex values since it's much more
				 * common for people to set address in terms of hex ...
				 */
				opts.load_addr = atoi(optarg);
				if (opts.load_addr == 0)
					sscanf(optarg, "%X", &opts.load_addr);
				break;
			case 'h': show_create_usage(0);
			CASE_common_errors
		}
	}
	if (argc < optind + 2)
		err("Create requires at least two arguments: <ldr> <elfs>");
	if (opts.cpu < 0)
		err("Invalid CPU selection '%i'.", opts.cpu);
	if (strchr("?FGH", opts.port) == NULL)
		err("Invalid PORT '%c'.  Valid PORT values are 'F', 'G', and 'H'.", opts.port);
	if (opts.gpio < 0 || opts.gpio > 16)
		err("Invalid GPIO '%i'.  Valid GPIO values are 0 - 16.", opts.gpio);
	if (opts.block_size == 0)
		err("Invalid block size '%i'.  Valid block sizes are 1 <= size < 2^32.", opts.block_size);

	printf("Creating LDR %s ...\n", *(argv+optind));
	ret = ldr_create(argv+optind, &opts);
	if (ret)
		perror("Failed to create LDR");
	else
		printf("Done!\n");
	return ret;
}


static void show_version(void)
{
	printf("ldr-utils-%s: %s compiled %s\n%s\n",
	       VERSION, __FILE__, __DATE__, rcsid);
	exit(EXIT_SUCCESS);
}

#define set_action(action) \
	do { \
		if (a != NONE) \
			err("Cannot specify more than one action at a time"); \
		a = action; \
	} while (0)
#define reload_sub_args(new_argv0) \
	do { \
		--optind; \
		argc -= optind; \
		argv += optind; \
		optind = 0; \
		argv[0] = new_argv0; \
	} while (0)

int main(int argc, char *argv[])
{
	typedef enum { SHOW, DUMP, LOAD, CREATE, NONE } actions;
	actions a = NONE;
	int i, ret;

	argv0 = strchr(argv[0], '/');
	argv0 = (argv0 == NULL ? argv[0] : argv0+1);

	while ((i=getopt_long(argc, argv, PARSE_FLAGS, long_opts, NULL)) != -1) {
		switch (i) {
			case 's': set_action(SHOW); goto parse_action;
			case 'd': set_action(DUMP); goto parse_action;
			case 'l': set_action(LOAD); goto parse_action;
			case 'c': set_action(CREATE); goto parse_action;
			case 'f': ++force; break;
			case 'v': ++verbose; break;
			case 'q': ++quiet; break;
			case 'h': show_usage(0);
			case 'V': show_version();
			CASE_common_errors
		}
	}
	if (optind == argc)
		show_usage(EXIT_FAILURE);

	ret = 0;
parse_action:
	switch (a) {
		case SHOW:
			/*reload_sub_args("show");*/
			for (i = optind; i < argc; ++i)
				ret |= show_ldr(argv[i]);
			break;
		case DUMP:
			/*reload_sub_args("dump");*/
			for (i = optind; i < argc; ++i)
				ret |= dump_ldr(argv[i]);
			break;
		case LOAD:
			reload_sub_args("load");
			ret |= load_ldr(argc, argv);
			break;
		case CREATE:
			reload_sub_args("create");
			ret |= create_ldr(argc, argv);
			break;
		case NONE:
			/* guess at requested action based upon context
			 *  - one argument: show ldr
			 *  - two arguments, second is a char device: load ldr
			 */
			if (argc - optind == 1)
				a = SHOW;
			else if (argc - optind == 2) {
				struct stat st;
				if (stat(argv[optind+1], &st) == 0) {
					if (S_ISCHR(st.st_mode))
						a = LOAD;
				}
			}
			if (a != NONE)
				goto parse_action;
			show_usage(EXIT_FAILURE);
	}

	return ret;
}
