/* 
 * vivi/include/sa1100_gen_memmapB.h: generic memory map for SA1100
 *
 * Copyright (C) 2002 MIZI Research, Inc.
 *
 * Author: Janghoon Lyu <nandy@mizi.com>
 * Date  : $Date: 2004/02/04 06:22:25 $
 *
 * $Revision: 1.1.1.1 $
 *
 *
 *
 */

#include "sizes.h"

#define ROM_BASE0		0x00000000      /* base address of rom bank 0 */
#define ROM_BASE1		0x02000000      /* base address of rom bank 1 */
#define DRAM_BASE0		0xC0000000      /* base address of dram bank 0 */
#define DRAM_BASE1		0xC8000000	/* base address of dram bank 1 */

/* Global definitions */
#define FLASH_BASE		ROM_BASE0
#define FLASH_SIZE		SZ_32M
#define FLASH_UNCACHED_BASE	0x04000000	/* to mapping flash memory */
#define FLASH_BUSWIDTH		4

#define DRAM_BASE		DRAM_BASE0
#define DRAM_SIZE		SZ_32M

#define MTD_PART_SIZE		SZ_16K
#define MTD_PART_OFFSET		0x00000000
#define PARAMETER_TLB_SIZE	SZ_16K
#define PARAMETER_TLB_OFFSET	0x00004000
#define LINUX_CMD_SIZE		SZ_16K
#define LINUX_CMD_OFFSET	0x00008000
#define VIVI_PRIV_SIZE		(MTD_PART_SIZE + PARAMETER_TLB_SIZE + LINUX_CMD_SIZE)

/* ROM */
#define VIVI_ROM_BASE		0x00000000
#define VIVI_PRIV_ROM_BASE	0x01FC0000

/* RAM */
#define VIVI_RAM_ABS_POS	SZ_4M		/* absolute position for vivi */
#define VIVI_RAM_SIZE		SZ_1M
#define VIVI_RAM_BASE		(DRAM_BASE + VIVI_RAM_ABS_POS - VIVI_RAM_SIZE)
#define HEAP_SIZE		SZ_1M
#define HEAP_BASE		(VIVI_RAM_BASE - HEAP_SIZE)
#define MMU_TABLE_SIZE		SZ_16K
#define MMU_TABLE_BASE		(HEAP_BASE - MMU_TABLE_SIZE)
#define VIVI_PRIV_RAM_BASE	(MMU_TABLE_BASE - VIVI_PRIV_SIZE)
#define STACK_SIZE		SZ_32K
#define STACK_BASE		(VIVI_PRIV_RAM_BASE - STACK_SIZE)
#define RAM_SIZE		(DRAM_SIZE - VIVI_RAM_ABS_POS)
#define RAM_BASE		(DRAM_BASE + VIVI_RAM_ABS_POS)
