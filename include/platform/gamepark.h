#include "config.h"
#include "s3c2400.h"

/*
 * Memory Map
 */
#include "sizes.h"

#define ROM_BASE0		0x00000000
#define ROM_BASE1		0x02000000
#define ROM_BASE2		0x04000000
#define ROM_BASE3		0x06000000
#define ROM_BASE4		0x08000000
#define ROM_BASE5		0x0A000000
#define DRAM_BASE0		0x0C000000
#define DRAM_BASE1		0x0E000000

/* Intel Strata Flash Memory */
#define FLASH_BASE              ROM_BASE0
#define FLASH_SIZE              SZ_16M
#define FLASH_UNCACHED_BASE	ROM_BASE2
#define FLASH_BUSWIDTH		2		/* 16-bit wide */

/* DRAM */
#define DRAM_BASE               DRAM_BASE0
#define DRAM_SIZE		SZ_32M

/* VIVI Private Data */
#define MTD_PART_SIZE		SZ_16K
#define MTD_PART_OFFSET		0x00000000
#define PARAMETER_TLB_SIZE	SZ_16K
#define PARAMETER_TLB_OFFSET	0x00004000
#define LINUX_CMD_SIZE		SZ_16K
#define LINUX_CMD_OFFSET	0x00008000
#define VIVI_PRIV_SIZE		(MTD_PART_SIZE + PARAMETER_TLB_SIZE + LINUX_CMD_SIZE)

/* ROM */
#ifdef CONFIG_S3C2400_GAMEPARK_OSSWITCH
#define VIVI_ROM_BASE           0x00100000
#elif defined(CONFIG_S3C2400_GAMEPARK_ON_RAM)
#define VIVI_ROM_BASE		0x0C000000
#else
#define VIVI_ROM_BASE           0x00000000
#endif
#define VIVI_PRIV_ROM_BASE	0x00FC0000

/* RAM */
#define GP_RAM_TWEAK		SZ_8M
#define VIVI_RAM_SIZE		SZ_1M
#define VIVI_RAM_BASE		(DRAM_BASE + GP_RAM_TWEAK - VIVI_RAM_SIZE)
#define HEAP_SIZE		SZ_1M
#define HEAP_BASE		((VIVI_RAM_BASE) - HEAP_SIZE)
#define MMU_TABLE_SIZE		SZ_16K
#define MMU_TABLE_BASE		(HEAP_BASE - MMU_TABLE_SIZE)
#define VIVI_PRIV_RAM_BASE	(MMU_TABLE_BASE - VIVI_PRIV_SIZE)
#define STACK_SIZE		SZ_32K
#define STACK_BASE		(VIVI_PRIV_RAM_BASE - STACK_SIZE)
#define RAM_SIZE		(DRAM_SIZE - GP_RAM_TWEAK)
#define RAM_BASE		(DRAM_BASE + GP_RAM_TWEAK)

/*
 * Architectuer magic, machine type
 */
#include "architecture.h"
#define MACH_TYPE		146
#define ARCHITECTURE_MAGIC	((ARM_PLATFORM << 24) | (ARM_S3C2400_CPU << 16) | \
				  MACH_TYPE)

/*
 */
#define UART_BAUD_RATE		115200

/* 
 */
#define FIN	 		12000000
/* CPU clcok */
/* FCLK = PCLK = HCLK = 50 Mhz */
#define MPLL_MDIV	0x5c
#define MPLL_PDIV	0xa
#define MPLL_SDIV	0x1

/* initial values for DRAM */
#define BWSCON_CFG	0x11111110
#define BANKCON0_CFG	0x00000600
#define BANKCON1_CFG	0x00000f00
#define BANKCON2_CFG	0x00000700
#define BANKCON3_CFG	0x00000700
#define BANKCON4_CFG	0x00000700
#define BANKCON5_CFG	0x00000700
#define BANKCON6_CFG	0x00018001
#define BANKCON7_CFG	0x00018001
#define REFRESH_CFG	0x00ab03ee
#define BANKSIZE_CFG	0x10	/* 32M/32M */
#define MRSRB6_CFG		0x20
#define MRSRB7_CFG		0x20

#define LOCKTIME_VAL	0x00ffffff	/* It's a default value */
#define MPLLCON_CFG	((MPLL_MDIV << 12) | (MPLL_PDIV << 4) | (MPLL_SDIV)) 
#define UPLLCON_CFG	0x0	/* not used currently */
#define CLKCON_CFG	0x0000fff8	/* It's a default value */
#define CLKSLOW_CFG	0x00000004	/* It's a default value */
#define CLKDIVN_CFG	0x00000000	/* FCLK : HCLK : PCLK = 1 : 1 : 1 */	

/* initial values for serial */
#define UART1_ULCON	0x3	/* UART, no parity, one stop bit, 8 bits */
#define UART1_UCON	0x245
#define UART1_UFCON	0x0
#define UART1_UMCON	0x0
#define UART2_ULCON	0x3
#define UART2_UCON	0x45
#define UART2_UFCON	0xf6
#define UART2_UMCON	0x0

/* inital values for GPIOs */
#define PACON_CFG	0x7ff
#define PBCON_CFG	0x5555
#define PBUP_CFG	0x00ff
#define PCCON_CFG	0xaaaaaaaa
#define PCUP_CFG	0xffff
#define PDCON_CFG	0x1141aa
#define PDDAT_CFG	0x0
#define PDUP_CFG	0xffff
#define PECON_CFG	0x55a555
#define PEUP_CFG	0xf3f
#define PFCON_CFG	0x0aaa
#define PFUP_CFG	0x3f
#define PGCON_CFG	0xa67d5
#define PGUP_CFG	0x1ff
#define OPENCR_CFG	0x0
#define EXTINT_CFG	0x22222222
