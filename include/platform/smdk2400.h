#include "config.h"
#include "s3c2400.h"

#define DRAM_SZ_3232 		1
#undef DRAM_SZ_1616

/* CPU clcok */
/* FCLK = PCLK = HCLK = 50 Mhz */
#define MPLL_MDIV		0x5c
#define MPLL_PDIV		0xa
#define MPLL_SDIV		0x1

/* initial values for DRAM */
//#define BWSCON_CFG		0x22111122
#define BWSCON_CFG		0x22111114
#define BANKCON0_CFG		0x00000700
#define BANKCON1_CFG		0x00000700
#define BANKCON2_CFG		0x00000700
#define BANKCON3_CFG		0x00000700
#define BANKCON4_CFG		0x00000700
#define BANKCON5_CFG		0x00000700
#define BANKCON6_CFG		0x00018005
#define BANKCON7_CFG		0x00018005
#define REFRESH_CFG		0x008e0459
#ifdef DRAM_SZ_3232
#define BANKSIZE_CFG		0x10	/* 32M/32M */
#define MRSRB6_CFG		0x30	/* 32M */
#define MRSRB7_CFG		0x30	/* 32M */
#endif
#ifdef DRAM_SZ_1616
#define BANKSIZE_CFG		0x17	/* 16M/16M */
#define MRSRB6_CFG		0x20	/* 16M */
#define MRSRB7_CFG		0x20	/* 16M */
#endif

#define LOCKTIME_VAL		0x00ffffff	/* It's a default value */
#define MPLLCON_CFG		((MPLL_MDIV << 12) | (MPLL_PDIV << 4) | (MPLL_SDIV)) 
#define UPLLCON_CFG		0x0	/* not used currently */
#define CLKCON_CFG		0x0000fff8	/* It's a default value */
#define CLKSLOW_CFG		0x00000004	/* It's a default value */
#define CLKDIVN_CFG		0x00000000	/* FCLK : HCLK : PCLK = 1 : 1 : 1 */	

/* initial values for serial */
#define UART1_ULCON		0x3	/* UART, no parity, one stop bit, 8 bits */
#define UART1_UCON		0x245
#define UART1_UFCON		0x0
#define UART1_UMCON		0x0
#define UART2_ULCON		0x3
#define UART2_UCON		0x45
#define UART2_UFCON		0xf6
#define UART2_UMCON		0x0

/* inital values for GPIOs */
#define PACON_CFG		0x3ffff
#define PBCON_CFG		0xaaaaaaaa
#define PBUP_CFG		0xffff
#define PCCON_CFG		0x55000000
#define PCUP_CFG		0x0
#define PDCON_CFG		0x40000
#define PDDAT_CFG		0x0
#define PDUP_CFG		0x200
#define PECON_CFG		0x0
#define PEUP_CFG		0x0
#define PFCON_CFG		0x22
#define PFUP_CFG		0x5
#define PGCON_CFG		0x0
#define PGUP_CFG		0x0
#define OPENCR_CFG		0x0
#define EXTINT_CFG		0x22222222
