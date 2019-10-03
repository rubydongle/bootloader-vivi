/*
 * Network Interface 
 * based on ARMBOOT
 * Author : SW.LEE <hitchcar@sec.samsung.com>
 *
 */

#include <config.h>
#include <printk.h>
#include <heap.h>
#include <time.h>
#include <command.h>
#include <types.h>
#include <io.h>
#include <sizes.h>
#include <vivi_string.h>
#include <errno.h>
#include <string.h>

#undef NETDEV_DEBUG
#ifdef NETDEV_DEBUG
#define DPRINTK(args...)        printk(##args)
#else
#define DPRINTK(args...)
#endif



void command_tftpboot(int argc, const char**argv);
static user_subcommand_t net_cmds[] = {
	{
		"tftpboot",
		netboot_common,
		"net tftpboot <dest_addr> <filename>\t\t-- tftp file transfer"
	}
};


void command_net(int argc, const char **argv)
{
	switch (argc) {
		case 1:
			invalid_cmd("net", net_cmds);
			break;
		case 2:
			if (strncmp("help", argv[1], 4) == 0) {
				print_usage("", net_cmds);
				break;
			}
		default:
			execsubcmd(net_cmds, argc-1, argv+1);
	}
}

user_command_t net_cmd = {
	"net",
	command_net,
	NULL,
	"net [{cmds}]\t\t\t-- Manage Network functions"
};

