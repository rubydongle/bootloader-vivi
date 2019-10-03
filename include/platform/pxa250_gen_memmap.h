/*
 * pxa250_gen_memmap.h
 *
 * pxa250 general memory map (as example)
 *
 * Author: Yong-iL Joh <tolkien@mizi.com>
 * Date  : $Date: 2004/02/04 06:22:25 $ 
 *
 * $Revision: 1.1.1.1 $
 *
   Mon Jul 22 2002 Yong-iL Joh <tolkien@mizi.com>
   - initial

   Mon Jul 22 2002 Janghoon Lyu <nandy@mizi.com>

 */

#ifndef _PXA250_GEN_MEMMAP_H_
#define _PXA250_GEN_MEMMAP_H_

#include "sizes.h"

#define ROM_BASE0		0x00000000
#define DRAM_BASE0		0xA0000000

#define FLASH_BASE		ROM_BASE0
#define FLASH_SIZE		SZ_32M
#define FLASH_UNCACHED_BASE	0x50000000
#define FLASH_BUSWIDTH		4

#define DRAM_BASE		DRAM_BASE0
#define DRAM_SIZE		SZ_64M

/* VIVI Private Data */
#define MTD_PART_SIZE		SZ_16K
#define MTD_PART_OFFSET		0x00000000
#define PARAMETER_TLB_SIZE	SZ_16K
#define PARAMETER_TLB_OFFSET	0x00004000
#define LINUX_CMD_SIZE		SZ_16K
#define LINUX_CMD_OFFSET	0x00008000
#define VIVI_PRIV_SIZE		(MTD_PART_SIZE + PARAMETER_TLB_SIZE + LINUX_CMD_SIZE)

/* ROM */
#define VIVI_ROM_BASE		0x00000000
#define VIVI_PRIV_ROM_BASE	(FLASH_BASE + FLASH_SIZE - VIVI_PRIV_SIZE)

/* RAM */
#define VIVI_RAM_SIZE		SZ_1M
#define VIVI_RAM_BASE		(DRAM_BASE + DRAM_SIZE - VIVI_RAM_SIZE)
#define HEAP_SIZE		SZ_1M
#define HEAP_BASE		(VIVI_RAM_BASE - HEAP_SIZE)
#define MMU_TABLE_SIZE		SZ_16K
#define MMU_TABLE_BASE		(HEAP_BASE - MMU_TABLE_SIZE)
#define VIVI_PRIV_RAM_BASE	(MMU_TABLE_BASE - VIVI_PRIV_SIZE)
#define STACK_SIZE		SZ_32K
#define STACK_BASE		(VIVI_PRIV_RAM_BASE - STACK_SIZE)
#define RAM_SIZE		(STACK_BASE - DRAM_BASE)
#define RAM_BASE		DRAM_BASE

#endif	/* _PXA250_GEN_MEMMAP_H_ */
/*
 | $Id: pxa250_gen_memmap.h,v 1.1.1.1 2004/02/04 06:22:25 laputa Exp $
 |
 | Local Variables:
 | mode: c
 | mode: font-lock
 | version-control: t
 | delete-old-versions: t
 | End:
 |
 | -*- End-Of-File -*-
 */
