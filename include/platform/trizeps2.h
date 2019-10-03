/*
 * trizeps2.h
 *
 * machine specified definitions
 *
 * Author: Yong-iL Joh <tolkien@mizi.com>
 * Date  : $Date: 2004/02/04 06:22:25 $ 
 *
 * $Revision: 1.1.1.1 $
 *
   Thu Aug 29 2002 Yong-iL Joh <tolkien@mizi.com>
   - initial

 */

#ifndef _TRIZEPS2_H_
#define _TRIZEPS2_H_

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
#define MACH_TYPE		74
#define ARCHITECTURE_MAGIC      ((ARM_PLATFORM << 24) | \
				 (ARM_PXA250_CPU << 16) | MACH_TYPE)
/*
 */
#define UART_BASE	FFUART_BASE
#define UART_BAUD_RATE	115200
#undef CONFIG_GPIO_LED
#define GPIO_LED	(1 << 27)	/* for debugging */
#define GPDR_LED	GPDR0_OFFSET
#define GPSR_LED	GPSR0_OFFSET
#define GPCR_LED	GPCR0_OFFSET

/*
 */
#define GPSR0_VAL	(GPIO15_nCS1)
#define GPSR1_VAL	(GPIO33_nCS5|GPIO39_FFTXD|\
			GPIO48_nPOE|GPIO49_nPWE|GPIO50_nPIOR|GPIO51_nPIOW|\
			GPIO52_nPCE1|GPIO53_nPCE2|GPIO54_nPSKTSEL|GPIO55_nPREG)
#define GPSR2_VAL	(GPIO78_nCS2|GPIO79_nCS3|GPIO80_nCS4)

#define GPCR0_VAL	(GPIO11_3P6MHz|GPIO13_MBGNT|GPIO23_SCLK|GPIO24_SFRM)
#define GPCR1_VAL	(GPIO39_FFTXD|GPIO40_FFDTR|GPIO41_FFRTS)
#define GPCR2_VAL	0x0

#define GPDR0_VAL	(GPIO11_3P6MHz|GPIO13_MBGNT|GPIO15_nCS1|\
			GPIO23_SCLK|GPIO24_SFRM)
#define GPDR1_VAL	(GPIO33_nCS5|GPIO39_FFTXD|\
			GPIO48_nPOE|GPIO49_nPWE|GPIO50_nPIOR|GPIO51_nPIOW|\
			GPIO52_nPCE1|GPIO53_nPCE2|GPIO54_nPSKTSEL|GPIO55_nPREG)
#define GPDR2_VAL	(GPIO78_nCS2|GPIO79_nCS3|GPIO80_nCS4)

#define GAFR0L_VAL	(GP11_3P6MHz|GP13_MBGNT|GP14_MBREQ|GP15_nCS1)
#define GAFR0U_VAL	(GP18_RDY|GP19_DREQ1|GP20_DREQ0|GP21_DVAL0|GP22_DVAL1)
#define GAFR1L_VAL	(GP33_nCS5|GP34_FFRXD|GP39_FFTXD)
#define GAFR1U_VAL	(GP48_nPOE|GP49_nPWE|GP50_nPIOR|GP51_nPIOW|GP52_nPCE1|\
		GP53_nPCE2|GP54_nPSKTSEL|GP55_nPREG|GP56_nPWAIT|GP57_nIOIS16)
#define GAFR2L_VAL	(GP78_nCS2|GP79_nCS3)
#define GAFR2U_VAL	(GP80_nCS4)

#define PSSR_VAL	0x30

/* Static */
#define MSC0_VAL	0x2BD04df8
#define MSC1_VAL	0x7ff87ff8
#define MSC2_VAL	0x44646cD4

/* SDRAM */
#define MDCNFG_VAL	0x1AA91AC9
	/* DE0, 32bits, 9col, 13row, 4 internal bank,
	   tRP=3clk,CL=3,tRCD=3clk,tRAS(min)=7clk,tRC=10clk,
	   DLATCH0, DSA1111_2 */
#define MDCNFG_VAL_100	0x009DC01D	/* SDCLK=memory clock */
#define MDREFR_VAL	0x000bc018
	/* K0DB2, K1DB2, K2DB2, K1RUN, ,E1PIN, DRI=0x018 */
#define MDMRS_VAL	0x0

/* PCMCIA */
#define MECR_VAL	0x00000001
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

#endif	/* _TRIZEPS2_H_ */
/*
 | $Id: trizeps2.h,v 1.1.1.1 2004/02/04 06:22:25 laputa Exp $
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
