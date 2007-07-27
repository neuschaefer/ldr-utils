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

#include "ldr.h"

static const char *rcsid = "$Id$";
const char *argv0;
int force = 0, verbose = 0, quiet = 0;


struct option_help {
	const char *desc, *opts;
};

#define COMMON_FLAGS "fvqhV"
#define COMMON_LONG_OPTS \
	{"force",    no_argument, NULL, 'f'}, \
	{"verbose",  no_argument, NULL, 'v'}, \
	{"quiet",    no_argument, NULL, 'q'}, \
	{"help",     no_argument, NULL, 'h'}, \
	{"version",  no_argument, NULL, 'V'}, \
	{NULL,       no_argument, NULL, 0x0}
#define COMMON_HELP_OPTS \
	{"Ignore problems",          NULL}, \
	{"Make a lot of noise",      NULL}, \
	{"Only show errors",         NULL}, \
	{"Print this help and exit", NULL}, \
	{"Print version and exit",   NULL}, \
	{NULL,NULL}
#define CASE_common_errors \
	case 'f': ++force; break; \
	case 'v': ++verbose; break; \
	case 'q': ++quiet; break; \
	case 'V': show_version(); \
	case ':': err("Option '%c' is missing parameter", optopt); \
	case '?': err("Unknown option '%c' or argument missing", (optopt ? : '?')); \
	default:  err("Unhandled option '%c'; please report this", i);

#define PARSE_FLAGS COMMON_FLAGS "sdlcT:f"
#define a_argument required_argument
static struct option const long_opts[] = {
	{"show",     no_argument, NULL, 's'},
	{"dump",     no_argument, NULL, 'd'},
	{"load",     no_argument, NULL, 'l'},
	{"create",   no_argument, NULL, 'c'},
	{"target",    a_argument, NULL, 'T'},
	COMMON_LONG_OPTS
};
static struct option_help const opts_help[] = {
	{"Show details of a LDR",               "<ldrs>"},
	{"Break DXEs out of LDR",               "<ldrs>"},
	{"Load LDR over UART",                  "<ldr> <tty>"},
	{"Create LDR from binaries\n",          "<ldr> <elfs>"},
	{"Select LDR target",                   "<target>"},
	COMMON_HELP_OPTS
};
#define show_usage(status) show_some_usage(NULL, long_opts, opts_help, PARSE_FLAGS, status)

#define SHOW_PARSE_FLAGS COMMON_FLAGS ""
static struct option const show_long_opts[] = {
	COMMON_LONG_OPTS
};
static struct option_help const show_opts_help[] = {
	COMMON_HELP_OPTS
};
#define show_show_usage(status) show_some_usage("show", show_long_opts, show_opts_help, SHOW_PARSE_FLAGS, status)

#define DUMP_PARSE_FLAGS COMMON_FLAGS "F"
static struct option const dump_long_opts[] = {
	{"fill",     no_argument, NULL, 'F'},
	COMMON_LONG_OPTS
};
static struct option_help const dump_opts_help[] = {
	{"Dump fill sections as well",    NULL},
	COMMON_HELP_OPTS
};
#define show_dump_usage(status) show_some_usage("dump", dump_long_opts, dump_opts_help, DUMP_PARSE_FLAGS, status)

#define CREATE_PARSE_FLAGS COMMON_FLAGS "p:g:d:B:w:H:s:b:i:"
static struct option const create_long_opts[] = {
	{"port",      a_argument, NULL, 'p'},
	{"gpio",      a_argument, NULL, 'g'},
	{"dma",       a_argument, NULL, 'd'},
	{"bits",      a_argument, NULL, 'B'},
	{"waitstate", a_argument, NULL, 'w'},
	{"holdtimes", a_argument, NULL, 'H'},
	{"spibaud",   a_argument, NULL, 's'},
	{"blocksize", a_argument, NULL, 'b'},
	{"initcode",  a_argument, NULL, 'i'},
	COMMON_LONG_OPTS
};
static struct option_help const create_opts_help[] = {
	{"(BF53x) PORT for HWAIT signal",       "<F|G|H>"},
	{"(BF53x) GPIO for HWAIT signal",       "<#>"},
	{"(BF54x) DMA flag",                    "<#>"},
	{"(BF56x) Flash bits (8bit)",           "<bits>"},
	{"(BF56x) Wait states (15)",            "<num>"},
	{"(BF56x) Flash Hold time cycles (3)",  "<num>"},
	{"(BF56x) SPI boot baud rate (500k)",   "<baud>"},
	{"Block size of DXE (0x8000)",          "<size>"},
	{"Init code",                           "<file>"},
	COMMON_HELP_OPTS
};
#define show_create_usage(status) show_some_usage("create", create_long_opts, create_opts_help, CREATE_PARSE_FLAGS, status)

#define LOAD_PARSE_FLAGS COMMON_FLAGS "b:p"
static struct option const load_long_opts[] = {
	{"baud",      a_argument, NULL, 'b'},
	{"prompt",   no_argument, NULL, 'p'},
	COMMON_LONG_OPTS
};
static struct option_help const load_opts_help[] = {
	{"Set baud rate (default 115200)",           "<baud>"},
	{"Prompt for data flow",                     NULL},
	COMMON_HELP_OPTS
};
#define show_load_usage(status) show_some_usage("load", load_long_opts, load_opts_help, LOAD_PARSE_FLAGS, status)

static void show_version(void)
{
	printf("ldr-utils-%s: %s compiled %s\n%s\n",
	       VERSION, __FILE__, __DATE__, rcsid);
	exit(EXIT_SUCCESS);
}

static void show_some_usage(const char *subcommand, struct option const opts[],
                            struct option_help const help[], const char *flags,
                            int exit_status)
{
	size_t i;

	if (subcommand)
		printf("Usage: ldr %s [options] <arguments>\n\n", subcommand);
	else
		printf("Usage: ldr [options] <-s|-d|-l|-c> [subcommand options] <arguments>\n\n");
	printf("Options: -[%s]\n", flags);
	for (i = 0; opts[i].name; ++i) {
		if (!help[i].desc)
			err("someone forgot to update the help text");
		printf("  -%c, --%-10s %-15s * %s\n",
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

	printf("\nSupported LDR targets:\n");
	lfd_target_list();

	exit(exit_status);
}


static bool show_ldr(const int argc, char *argv[], const char *target)
{
	LFD *alfd = lfd_malloc(target);
	bool ret = true;
	int i;
	const char *filename;

	while ((i=getopt_long(argc, argv, SHOW_PARSE_FLAGS, show_long_opts, NULL)) != -1) {
		switch (i) {
			case 'h': show_show_usage(0);
			CASE_common_errors
		}
	}
	if (optind == argc)
		err("need at least one file to show");

	for (i = optind; i < argc; ++i) {
		filename = argv[i];
		if (!quiet)
			printf("Showing LDR %s ...\n", filename);
		if (!lfd_open(alfd, filename)) {
			warnp("unable to open LDR");
			ret &= false;
			continue;
		}
		if (!lfd_read(alfd)) {
			warnp("unable to read LDR");
			ret &= false;
		} else
			ret &= lfd_display(alfd);
		lfd_close(alfd);
	}
	return ret;
}

static bool dump_ldr(const int argc, char *argv[], const char *target)
{
	LFD *alfd = lfd_malloc(target);
	bool ret = true;
	int i;

	struct ldr_dump_options opts = {
		.dump_fill = false,
	};

	while ((i=getopt_long(argc, argv, DUMP_PARSE_FLAGS, dump_long_opts, NULL)) != -1) {
		switch (i) {
			case 'F': opts.dump_fill = true; break;
			case 'h': show_dump_usage(0);
			CASE_common_errors
		}
	}
	if (optind == argc)
		err("need at least one LDR to dump");

	for (i = optind; i < argc; ++i) {
		opts.filename = argv[i];
		if (!quiet)
			printf("Dumping LDR %s ...\n", opts.filename);
		if (!lfd_open(alfd, opts.filename)) {
			warnp("unable to open LDR");
			ret &= false;
			continue;
		}
		if (!lfd_read(alfd)) {
			warnp("unable to read LDR");
			ret &= false;
		} else
			ret &= lfd_dump(alfd, &opts);
		lfd_close(alfd);
	}
	return ret;
}

static bool load_ldr(const int argc, char *argv[], const char *target)
{
	LFD *alfd = lfd_malloc(target);
	bool ret = true;
	int i;
	const char *filename;

	struct ldr_load_options opts = {
		.tty = NULL,
		.baud = 115200,
		.prompt = false,
	};

	while ((i=getopt_long(argc, argv, LOAD_PARSE_FLAGS, load_long_opts, NULL)) != -1) {
		switch (i) {
			case 'b': opts.baud = atoi(optarg); break;
			case 'p': opts.prompt = true; break;
			case 'h': show_load_usage(0);
			CASE_common_errors
		}
	}
	if (optind + 2 != argc)
		err("Load requires two arguments: <ldr> <tty>");

	filename = argv[optind];
	opts.tty = argv[optind+1];

	if (!quiet)
		printf("Loading LDR %s ... ", filename);
	if (!lfd_open(alfd, filename)) {
		warnp("unable to open LDR");
		ret &= false;
	} else {
		if (!lfd_read(alfd)) {
			warnp("unable to read LDR");
			ret &= false;
		} else {
			if (!quiet)
				printf("OK!\n");
			ret &= lfd_load_uart(alfd, &opts);
		}
		lfd_close(alfd);
	}
	return ret;
}

static bool create_ldr(const int argc, char **argv, const char *target)
{
	LFD *alfd = lfd_malloc(target);
	bool ret = true;
	int i;

	struct ldr_create_options opts = {
		.port = '?',
		.gpio = 0,
		.dma = 1,
		.flash_bits = 8,
		.wait_states = 15,
		.flash_holdtimes = 3,
		.spi_baud = 500,
		.block_size = 0x8000,
		.init_code = NULL,
		.filelist = NULL,
	};

	while ((i=getopt_long(argc, argv, CREATE_PARSE_FLAGS, create_long_opts, NULL)) != -1) {
		switch (i) {
			case 'p': opts.port = toupper(optarg[0]); break;
			case 'g': opts.gpio = atoi(optarg); break;
			case 'd': opts.dma = atoi(optarg); break;
			case 'B': opts.flash_bits = atoi(optarg); break;
			case 'w': opts.wait_states = atoi(optarg); break;
			case 'H': opts.flash_holdtimes = atoi(optarg); break;
			case 's': opts.spi_baud = atoi(optarg); break;
			case 'b':
				/* support reading in hex values since it's much more
				 * common for people to set size in terms of hex ...
				 */
				opts.block_size = atoi(optarg);
				if (opts.block_size == 0)
					sscanf(optarg, "%X", &opts.block_size);
				break;
			case 'i': opts.init_code = optarg; break;
			case 'h': show_create_usage(0);
			CASE_common_errors
		}
	}
	if (argc < optind + 2)
		err("Create requires at least two arguments: <ldr> <elfs>");
	if (strchr("?FGH", opts.port) == NULL)
		err("Invalid PORT '%c'.  Valid PORT values are 'F', 'G', and 'H'.", opts.port);
	if (opts.gpio > 16)
		err("Invalid GPIO '%i'.  Valid GPIO values are 0 - 16.", opts.gpio);
	if (opts.dma < 1 || opts.dma > 15)
		err("Invalid DMA '%i'.  Valid DMA values are 1 - 15.", opts.dma);
	if (opts.block_size == 0)
		err("Invalid block size '%i'.  Valid block sizes are 1 <= size < 2^32.", opts.block_size);
	if (opts.flash_bits != 8 && opts.flash_bits != 16)
		err("Invalid flash bits '%i'.  Valid bits are '8' and '16'.", opts.flash_bits);
	if (opts.wait_states > 15)
		err("Invalid number of wait states '%i'.  Valid values are 0 - 15.", opts.wait_states);
	if (opts.flash_holdtimes > 3)
		err("Invalid number of flash hold time cycles '%i'.  Valid values are 0 - 3.", opts.flash_holdtimes);
	if (opts.spi_baud != 500 && opts.spi_baud != 1000 && opts.spi_baud != 2000)
		err("Invalid SPI baud '%i'.  Valid values are 500 (500k), 1000 (1M), or 2000 (2M).", opts.spi_baud);
	if (opts.init_code && access(opts.init_code, R_OK))
		errp("Unable to read initcode '%s'", opts.init_code);

	opts.filelist = argv + optind;

	if (!quiet)
		printf("Creating LDR %s ...\n", *(argv+optind));
	if (!lfd_open(alfd, NULL)) {
		warnp("Unable to init lfd");
		ret &= false;
	} else if (!lfd_create(alfd, &opts)) {
		perror("Failed to create LDR");
		ret &= false;
	} else if (!quiet)
		printf("Done!\n");
	return ret;
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
	const char *lfd_target = NULL;
	bool ret = true;
	int i;

	argv0 = strrchr(argv[0], '/');
	argv0 = (argv0 == NULL ? argv[0] : argv0+1);

	while ((i=getopt_long(argc, argv, PARSE_FLAGS, long_opts, NULL)) != -1) {
		switch (i) {
			case 's': set_action(SHOW); goto parse_action;
			case 'd': set_action(DUMP); goto parse_action;
			case 'l': set_action(LOAD); goto parse_action;
			case 'c': set_action(CREATE); goto parse_action;
			case 'T': lfd_target = optarg; break;
			case 'h': show_usage(0);
			CASE_common_errors
		}
	}
	if (optind == argc)
		show_usage(EXIT_FAILURE);

 parse_action:

	switch (a) {
		case SHOW:
			reload_sub_args("show");
			ret &= show_ldr(argc, argv, lfd_target);
			break;
		case DUMP:
			reload_sub_args("dump");
			ret &= dump_ldr(argc, argv, lfd_target);
			break;
		case LOAD:
			reload_sub_args("load");
			ret &= load_ldr(argc, argv, lfd_target);
			break;
		case CREATE:
			reload_sub_args("create");
			ret &= create_ldr(argc, argv, lfd_target);
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

	return (ret ? EXIT_SUCCESS : EXIT_FAILURE);
}
