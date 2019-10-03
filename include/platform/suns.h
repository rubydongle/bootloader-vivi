#include "config.h"
#include "sa1100.h"

/*
 * Memory map
 */
#include "sa1100_gen_memmapB.h"		/* include 'Type B' map */

/*
 * Architectuer magic, machine type
 */
#include "architecture.h"
#define MACH_TYPE		157
#define ARCHITECTURE_MAGIC      ((ARM_PLATFORM << 24) | (ARM_SA1100_CPU << 16) | \
	                          MACH_TYPE)

/*
 * related to reset handling
 */
#define PWBT_PRESS_LEVEL	1	/* High voltage, 1 = HIGH, 0 = LOW */
#define PWBT_GPIO_NUM		0	/* GPIO number */
#define PWBT_REG		GPLR	/* where pin status */
#define USER_RAM_BASE		(DRAM_BASE + VIVI_RAM_ABS_POS)
#define USER_RAM_SIZE		(DRAM_SIZE - VIVI_RAM_ABS_POS)

/*
 */
#define UART_BAUD_RATE          115200

/*
 */
#define DRAM_MDCNFG_ENABLE	MDCNFG_BANK0_ENABLE
#define DRAM_MDCNFG_32MB	(MDCNFG_BANK0_ENABLE | MDCNFG_DTIM0_SDRAM | \
				MDCNFG_DWID0_32B | MDCNFG_DRAC0(5) | \
				MDCNFG_TRP0(2) | MDCNFG_TDL0(3) | MDCNFG_TWR0(3))
#define DRAM_MDCNFG		DRAM_MDCNFG_32MB
#define DRAM_CAS0_WAVEFORM0	0xAAAAAA9f
#define DRAM_CAS0_WAVEFORM1	0xAAAAAAAA
#define DRAM_CAS0_WAVEFORM2	0xAAAAAAAA
#define DRAM_MDREFR		(MDREFR_TRASR(1) | MDREFR_DRI(512) | \
				MDREFR_E1PIN | MDREFR_K1RUN | \
				MDREFR_EAPD | MDREFR_KAPD)
#define MSC0_CONFIG		(MSC_RT_BURST8 | MSC_RBW32 | \
				MSC_RDF(14) | MSC_RDN(3) | MSC_RRR(4))
#define MSC1_CONFIG		0x494dfff8
//#define MSC2_CONFIG		0xFFF8FFF8
#define MSC2_CONFIG		0x64790025
#define MECR_CONFIG		0x994A994A
