#include "config.h"
#include "sa1100.h"

/*
 * Memory map
 */
#include "sizes.h"

#define ROM_BASE0		0x00000000      /* base address of rom bank 0 */
#define ROM_BASE1		0x02000000      /* base address of rom bank 1 */
#define DRAM_BASE0		0xC0000000      /* base address of dram bank 0 */
#define DRAM_BASE1		0xC8000000	/* base address of dram bank 1 */

/* Global definitions */
#define FLASH_BASE		ROM_BASE0
#define FLASH_SIZE		SZ_16M
#define FLASH_UNCACHED_BASE	0x04000000	/* to mapping flash memory */
#define FLASH_BUSWIDTH		4

#define DRAM_BASE		DRAM_BASE0
#define DRAM_SIZE		SZ_16M

#define MTD_PART_SIZE		SZ_16K
#define MTD_PART_OFFSET		0x00000000
#define PARAMETER_TLB_SIZE	SZ_16K
#define PARAMETER_TLB_OFFSET	0x00004000
#define LINUX_CMD_SIZE		SZ_16K
#define LINUX_CMD_OFFSET	0x00008000
#define VIVI_PRIV_SIZE		(MTD_PART_SIZE + PARAMETER_TLB_SIZE + LINUX_CMD_SIZE)

/* ROM */
#define VIVI_ROM_BASE		0x00000000
#define VIVI_PRIV_ROM_BASE	0x00FC0000

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

/*
 * Architectuer magic, machine type
 */
#include "architecture.h"
#define MACH_TYPE		84
#define ARCHITECTURE_MAGIC	((ARM_PLATFORM << 24) | (ARM_SA1100_CPU << 16) | \
				MACH_TYPE)

/*
 * 
 */
#define UART_BAUD_RATE		115200

/*
 * CPU register
 */
#define HALF_MEM_CLK

#ifdef HALF_MEM_CLK
#define DRAM_MDCNFG_ENABLE	MDCNFG_BANK0_ENABLE
#define DRAM_MDCNFG_32MB	(MDCNFG_BANK0_ENABLE | MDCNFG_DTIM0_SDRAM | \
				MDCNFG_DWID0_32B | MDCNFG_DRAC0(5) | MDCNFG_TRP0(2) | \
			       	MDCNFG_TDL0(3) | MDCNFG_TWR0(3))
#define DRAM_CAS0_WAVEFORM0	0x55555557
#define DRAM_CAS0_WAVEFORM1	0x55555555
#define DRAM_CAS0_WAVEFORM2	0x55555555
#define DRAM_MDREFR		(MDREFR_TRASR(1) | MDREFR_DRI(2048) | \
				MDREFR_E1PIN | MDREFR_K1RUN | MDREFR_K1DB2 | \
				MDREFR_EAPD | MDREFR_KAPD)
#define MSC0_CONFIG		(MSC_RT_BURST8 | MSC_RBW32 | \
				MSC_RDF(31) | MSC_RDN(31) | MSC_RRR(31))
#define MSC1_CONFIG		0xFFF8FFF8
#define MSC2_CONFIG		0xFFF8FFF8
#define MECR_CONFIG		0x994A994A

#else
#define DRAM_MDCNFG_ENABLE	MDCNFG_BANK0_ENABLE
#define DRAM_MDCNFG_32MB	(MDCNFG_BANK0_ENABLE | MDCNFG_DTIM0_SDRAM | \
				MDCNFG_DWID0_32B | MDCNFG_DRAC0(5) | MDCNFG_TRP0(2) | \
			       	MDCNFG_TDL0(3) | MDCNFG_TWR0(3))
#define DRAM_MDCNFG_16MB	(MDCNFG_BANK0_ENABLE | MDCNFG_DTIM0_SDRAM | \
       				MDCNFG_DWID0_32B | MDCNFG_DRAC0(4) | MDCNFG_TRP0(3) | \
				MDCNFG_TDL0(3) | MDCNFG_TWR0(3))
#define DRAM_CAS0_WAVEFORM0	0xAAAAAA9f
#define DRAM_CAS0_WAVEFORM1	0xAAAAAAAA
#define DRAM_CAS0_WAVEFORM2	0xAAAAAAAA
#define DRAM_MDREFR		(MDREFR_TRASR(1) | MDREFR_DRI(512) | \
				MDREFR_E1PIN | MDREFR_K1RUN | \
				MDREFR_EAPD | MDREFR_KAPD)
#define MSC0_CONFIG		(MSC_RT_BURST8 | MSC_RBW32 | \
				MSC_RDF(14) | MSC_RDN(3) | MSC_RRR(4))
#define MSC1_CONFIG		0xFFF8FFF8
#define MSC2_CONFIG		0xFFF8FFF8
#define MECR_CONFIG		0x994A994A
#endif /* HALF_MEM_CLK */

/*
 * GPIO definitions
 */
#define nPOWER_ONOFF	(1 << 0)    /* I, GPIO 0 */
#define MICOM_IRQ	(1 << 1)    /* I, GPIO 1 */    
#define MENU		(1 << 10)   /* I, GPIO 10 */
#define CPU_IRQ		(1 << 11)   /* I, GPIO 11 */
#define nMICOM_RESET	(1 << 12)	/* GPIO 12 */
#define CRADLE		(1 << 15)	/* GPIO 15 */
#define JACK_SENSE	(1 << 16)	/* GPIO 16 */
#define nFLASH_BUSY0	(1 << 18)	/* GPIO 18 */
#define BIT_REQ		(1 << 19)	/* GPIO 19 */
#define nBAT_LOW_RDY	(1 << 20)	/* GPIO 20 */
#define nSA_CF_IRQ	(1 << 21)	/* GPIO 21 */
#define nCF_INSERTED	(1 << 22)	/* GPIO 22 */
#define nCF_PW_FALUT	(1 << 23)	/* GPIO 23 */
#define CF_BVD1		(1 << 24)	/* GPIO 24 */
#define CF_BVD2		(1 << 25)	/* GPIO 25 */
#define USB_INSERTED	(1 << 26)	/* GPIO 26 */

#define MING_EGPIO0     0x40000000

#define EGPIO_MING_CF_3P3V_ON	(1 << 0)    /* W */
#define EGPIO_MING_SA_CF_RESET	(1 << 1)    /* W */
#define EGPIO_MING_CF_5V_ON	(1 << 2)    /* W */
#define EGPIO_MING_CF_VCC_CTL0	(1 << 3)    /* W */
#define EGPIO_MING_CF_VCC_CTL1	(1 << 4)    /* W */
#define EGPIO_MING_ICP_SHDN	(1 << 5)    /* W */
#define EGPIO_MING_ICP_MODE	(1 << 6)    /* W */
#define EGPIO_MING_RS232_ON	(1 << 7)    /* W */
#define EGPIO_MING_AMP_VOL0	(1 << 8)    /* W */
#define EGPIO_MING_AMP_VOL1	(1 << 9)    /* W */
#define EGPIO_MING_AMP_VOL2	(1 << 10)   /* W */
#define EGPIO_MING_AMP_PW_ON	(1 << 11)   /* W */
#define EGPIO_MING_ANALOG_PW_ON	(1 << 12)   /* W */
#define EGPIO_MING_RADIO_OUT_EN	(1 << 13)   /* W */
#define EGPIO_MING_MP3_OUT_EN	(1 << 14)   /* W */
#define EGPIO_MING_EARPHONE_EN	(1 << 15)   /* W */
#define EGPIO_MING_UART_DTR	(1 << 16)   /* W */
#define EGPIO_MING_UART_RTS	(1 << 17)   /* W */
#define EGPIO_MING_LCD_DRIVER_ON	(1 << 18)   /* W */
#define EGPIO_MING_nLCD_BIAS_ON	(1 << 19)   /* W */
#define EGPIO_MING_nLCD_RESET	(1 << 20)   /* W */
#define EGPIO_MING_INVERTER_PW_ON	(1 << 21)   /* W */
#define EGPIO_MING_FLASH_WR_EN	(1 << 22)   /* W */
#define EGPIO_MING_nFLASH_LOCK	(1 << 23)   /* W */
#define EGPIO_MING_RS232_OK	(1 << 24)   /* R */
#define EGPIO_MING_UART_DCD	(1 << 25)   /* R */
#define EGPIO_MING_UART_CTS	(1 << 26)   /* R */
#define EGPIO_MING_UART_DSR	(1 << 27)   /* R */
#define EGPIO_MING_CF_VSENSE1	(1 << 28)   /* R */
#define EGPIO_MING_CF_VSENSE2	(1 << 29)   /* R */

#define MING_EGPIO1     0x48000000

#define EGPIO_MING_nMP3_CS	(1 << 0)    /* W */
#define EGPIO_MING_MP3_PGM_DN	(1 << 1)    /* W */
#define EGPIO_MING_MP3_CKBYPASS	(1 << 2)    /* W */
#define EGPIO_MING_nMP3_RESET	(1 << 3)    /* W */
#define EGPIO_MING_OSC_12M_EN	(1 << 4)    /* W */
#define EGPIO_MING_nFMWE	(1 << 8)    /* W */
#define EGPIO_MING_nFMRD	(1 << 9)    /* W */
#define EGPIO_MING_CLE		(1 << 10)   /* W */
#define EGPIO_MING_ALE		(1 << 11)   /* W */
#define EGPIO_MING_nNAND_CS	(1 << 12)   /* W */
#define EGPIO_MING_nNAND_WP	(1 << 13)   /* W */
