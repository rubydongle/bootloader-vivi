/*
 * Copyright (C) Samsung Electronics 
 *  SW.LEE <hitchcar@sec.samsung.com>
 *  based on ARMBOOT
 *
 */

#ifndef __NET_PARAM_H__
#define __NET_PARAM_H__

#include <types.h>

#define CFG_ENV_SIZE                            0x200                   /* FIXME How big when embedded?? */
`
typedef struct environment_s {
	        ulong   crc;                    /* CRC32 over data bytes        */
		        uchar   data[CFG_ENV_SIZE - sizeof(ulong)];
} env_t;

typedef struct bd_info {
	int                 bi_baudrate;    /* serial console baudrate */
	unsigned long       bi_ip_addr;     /* IP Address */
	unsigned char       bi_enetaddr[6]; /* Ethernet adress */
	env_t              *bi_env;
	ulong               bi_arch_number; /* unique id for this board */
	ulong               bi_boot_params; /* where this board expects params */
	struct                              /* RAM configuration */
	{
		ulong start;
		ulong size;
	}                   bi_dram[CONFIG_NR_DRAM_BANKS];
	struct bd_info_ext  bi_ext;         /* board specific extension */
} bd_t;






#endif	/* _NET_PARAM_H */


