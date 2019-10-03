/*
 * vivi/arch/s3c2440/smdk.c:
 *
 *  This code is GPL.
 *
 * Author: Janghoon Lyu <nandy@mizi.com>
 * Date  : $Date: 2007/01/27 18:33:49 $
 *
 * $Revision: 1.1.1.1 $
 * 
 */

#include "config.h"
#include "machine.h"
#include "vivi.h"
#include "priv_data.h"
#include "mtd/map.h"
#include "boot_kernel.h"
#include "command.h"
#include "time.h"

#ifdef CONFIG_S3C2440_NAND_BOOT
mtd_partition_t default_mtd_partitions[] = {	/*struct mtd_partition_t was defined at include/priv_data.h*/
	{
		name:		"vivi",
		offset:		0,
		size:		0x00020000,
		flag:		0
	}, {    /* add by thisway.diy, 2006.06.20 */
		name:		"eboot",
		offset:		0x00020000,
		size:		0x00020000,
		flag:		0
	},	{
		name:		"param",
		offset:		0x00040000,
		size:		0x00010000,
		flag:		0
	}, 
#ifdef CONFIG_BOOT_LOGO
	{
		name:		"logo",
		offset:		0x00050000,
		size:		0x00180000,
		flag:		0
	},	{
		name:		"kernel",
		offset:		0x001D0000,
		size:		0x00200000,
		flag:		0
	}, {
		name:		"root",
		offset:		0x003D0000,
		size:		0x03C2C000,
		flag:		0
	}
#else
	{
		name:		"kernel",
		offset:		0x00050000,
		size:		0x00200000,
		flag:		0
	}, {
		name:		"root",
		offset:		0x00250000,
		size:		0x03DAC000,
		flag:		0
	}
#endif		
};
#endif
#ifdef CONFIG_S3C2440_AMD_BOOT
mtd_partition_t default_mtd_partitions[] = {
	{
		name:		"vivi",
		offset:		0,
		size:		0x00020000,
		flag:		0
	}, {
		name:		"param",
		offset:		0x00020000,
		size:		0x00010000,
		flag:		0
	}, {
		name:		"kernel",
		offset:		0x00030000,
		size:		0x000C0000,
		flag:		0
	}, {
		name:		"root",
		offset:		0x00100000,
		size:		0x00140000,
		flag:		MF_BONFS
	}
};
#endif
int default_nb_part = ARRAY_SIZE(default_mtd_partitions);

#ifdef CONFIG_S3C2440_NAND_BOOT
#define MT_S3C2440	MT_SMC_S3C2410
#endif
#ifdef CONFIG_S3C2440_AMD_BOOT
#define MT_S3C2440	MT_NOR_FLASH
#endif
vivi_parameter_t default_vivi_parameters[] = {
	{ "mach_type",			MACH_TYPE,	NULL },
	{ "media_type",			MT_S3C2440,	NULL },
	{ "boot_mem_base",		0x30000000,	NULL },
	{ "baudrate",			UART_BAUD_RATE,	NULL },
	{ "xmodem",			1,		NULL },
	{ "xmodem_one_nak",		0,		NULL },
	{ "xmodem_initial_timeout",	300000,		NULL },
	{ "xmodem_timeout",		1000000,	NULL },
	{ "boot_delay",			0x1000000,	NULL }
};
int default_nb_params = ARRAY_SIZE(default_vivi_parameters);

char linux_cmd[] = "noinitrd root=/dev/mtdblock2 init=/linuxrc console=ttySAC0";

void set_vpp(struct map_info *map, int vpp)
{
}

void set_gpios(void)
{
	GPACON  = vGPACON;
	GPBCON  = vGPBCON;
	GPBUP   = vGPBUP; 
	GPCCON  = vGPCCON;
	GPCUP   = vGPCUP; 
	GPDCON  = vGPDCON;
	GPDUP   = vGPDUP; 
	GPECON  = vGPECON;
	GPEUP   = vGPEUP; 
	GPFCON  = vGPFCON;
	GPFUP   = vGPFUP; 
	GPGCON  = vGPGCON;
	GPGUP   = vGPGUP; 
	GPHCON  = vGPHCON;
	GPHUP   = vGPHUP; 
	EXTINT0 = vEXTINT0;
	EXTINT1 = vEXTINT1;
	EXTINT2 = vEXTINT2;
}

/* S3C2440 CPU Testing Function  SW.LEE */
static void ajust_smdk()
{
	BANKSIZE = 0x82;
	DSC1	 = 0x3C000000;
}

int board_init(void)
{
	init_time();
	set_gpios();
//	ajust_smdk();
	return 0;
}

extern user_command_t cpu_cmd;
int misc(void)
{
	add_command(&cpu_cmd);
	return 0;
}
