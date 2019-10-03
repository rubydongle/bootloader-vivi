/*
 * premium.h
 *
 * machine specified definitions
 *
 * Author: Yong-iL Joh <tolkien@mizi.com>
 * Date  : $Date: 2004/02/04 06:22:25 $ 
 *
 * $Revision: 1.1.1.1 $
 *
   Mon Jul 22 2002 Yong-iL Joh <tolkien@mizi.com>
   - initial

 */

#ifndef _PREMIUM_H_
#define _PREMIUM_H_

#include "config.h"
#include "pxa250.h"

/*
 * Memory map
 */
#include "pxa250_gen_memmap.h"

/*
 * Architectuer magic, machine type
 */
#include "architecture.h"
#define MACH_TYPE		194
#define ARCHITECTURE_MAGIC	((ARM_PLATFORM << 24) | \
				 (ARM_PXA250_CPU << 16) | MACH_TYPE)
/*
 */
#define UART_BASE	BTUART_BASE
#define UART_BAUD_RATE	115200
#define CONFIG_GPIO_LED
#define GPIO_LED	(1 << 16)	/* PDA STATUS LED */
#define GPDR_LED	GPDR1_OFFSET
#define GPSR_LED	GPSR1_OFFSET
#define GPCR_LED	GPCR1_OFFSET

/*
 */
#define GPSR0_VAL	0x00228004
#define GPSR1_VAL	0xfe0a322b
#define GPSR2_VAL	0x0001f7ff

#define GPCR0_VAL	0x00584000
#define GPCR1_VAL	0x00950050
#define GPCR2_VAL	0x0

#define GPDR0_VAL	0xc3fbc004
#define GPDR1_VAL	0xffdfbafb
#define GPDR2_VAL	0x0001f7ff

#define GAFR0L_VAL	0x80000000
#define GAFR0U_VAL	0xa55a8012
#define GAFR1L_VAL	0x60908010
#define GAFR1U_VAL	0xaaa01000
#define GAFR2L_VAL	0xaa0aaaaa
#define GAFR2U_VAL	0x2

#define PSSR_VAL	0x30

/* Static */
#define MSC0_VAL	0x232423f2
#define MSC1_VAL	0x3ff1a449
#define MSC2_VAL	0x7ff123f2

/* SDRAM */
#define MDCNFG_VAL	0x00001ac9
	/* DE0, 32bits, 9col, 13row, 4 internal bank,
	   tRP=3clk,CL=3,tRCD=3clk,tRAS(min)=7clk,tRC=10clk,
	   DLATCH0, DSA1111_2 */
#define MDREFR_VAL	0x000bc018
	/* K0DB2, K1DB2, K2DB2, K1RUN, ,E1PIN, DRI=0x018 */
#define MDMRS_VAL	0x0

/* PCMCIA */
#define MECR_VAL	0x0
#define MCMEM0_VAL	0x00010504
#define MCMEM1_VAL	0x00010504
#define MCATT0_VAL	0x00010504
#define MCATT1_VAL	0x00010504
#define MCIO0_VAL	0x00004715
#define MCIO1_VAL	0x00004715

#define CCCR_VAL	0x241
	/* N:100 - Multiplier=2, M:10 - Multiplier=2, L:Multiplier=27 */
#define CKEN_VAL	0x017def
	/* all clock enable */

/* GPIO definition */
#define GPIO14_VPP_EN	(1 << 14)

#endif	/* _PREMIUM_H_ */
/*
 | $Id: premium.h,v 1.1.1.1 2004/02/04 06:22:25 laputa Exp $
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
