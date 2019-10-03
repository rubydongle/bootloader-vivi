/*
 * include/platform/gill.h
 *
 * This file contains the hardware specific definitions for Gill
 *
 * Author: Chan Gyun Jeong <cgjeong@mizi.com>
 * $Id: gill.h,v 1.1.1.1 2004/02/04 06:22:25 laputa Exp $
 *
 *
 * History
 *
 * 2002-07-30: Janghoo Lyu <nandy@mizi.com>
 */

#include "config.h"
#include "sa1100.h"

/*
 * Memory map
 */
#include "sa1100_gen_memmap.h"

/*
 * Architecture magic and machine type
 */
#include "architecture.h"
#define MACH_TYPE		198
#define ARCHITECTURE_MAGIC	((ARM_PLATFORM << 24) | (ARM_SA1100_CPU << 16) | \
				  MACH_TYPE)

/*
 */
#define DRAM_MDCNFG_ENABLE	MDCNFG_BANK0_ENABLE
#define DRAM_MDCNFG_32MB	(DRAM_MDCNFG_ENABLE | MDCNFG_DTIM0_SDRAM | \
				MDCNFG_DWID0_32B | MDCNFG_DRAC0(5) | \
				MDCNFG_TRP0(2) | MDCNFG_TDL0(3) | MDCNFG_TWR0(1))
#define DRAM_MDCNFG		DRAM_MDCNFG_32MB
#define DRAM_CAS0_WAVEFORM0	0xAAAAAA7f
#define DRAM_CAS0_WAVEFORM1	0xAAAAAAAA
#define DRAM_CAS0_WAVEFORM2	0xAAAAAAAA
#define DRAM_MDREFR		(MDREFR_TRASR(1) | MDREFR_DRI(512) | \
				 MDREFR_E1PIN | MDREFR_K1RUN)
#define MSC0_CONFIG	\
                ( ((MSC_RT_ROMFLASH | MSC_RBW32 | MSC_RDF(14) | \
                    MSC_RDN(3) | MSC_RRR(2)) << 0 ) /* Bank 0 150ns flash */ | \
                  ((MSC_RT_ROMFLASH | MSC_RBW32 | MSC_RDF(7) | MSC_RDN(11) | \
                    MSC_RRR(2)) << 16 )  /* Bank 1 150ns flash */ \
                )
#define MSC1_CONFIG \
                ( ((MSC_RT_SRAM_012 | MSC_RBW32 | MSC_RDF(3) | MSC_RDN(4) | \
                    MSC_RRR(1)) << 0 )  /* Bank 2 system registers */ | \
                  ((MSC_RT_VARLAT_345 | MSC_RBW32 | MSC_RDF(4) | MSC_RDN(2) | \
                    MSC_RRR(1)) << 16 )  /* Bank 3 ethernet */ \
                )
#define MSC2_CONFIG \
                ( ((MSC_RT_VARLAT_345 | MSC_RBW32 | MSC_RDF(13) | MSC_RDN(6) | \
                    MSC_RRR(3)) << 0 )  /* Bank 4 SA-1111 */ | \
                  ((MSC_RT_VARLAT_345 | MSC_RBW32 | MSC_RDF(3) | MSC_RDN(2) | \
                    MSC_RRR(2)) << 16 )  /* Bank 5 graphics */ \
                )
#define MECR_CONFIG	0x994a994a



#define UART_BAUD_RATE		115200



#define GILL_BCR_BASE    0x10000000

#define GILL_BCR	__REG(GILL_BCR_BASE)

#define GILL_BCR_DB1110	(0x00A07410) /* from the hardhat kernel patches of GILL */
#define GILL_BCR_DB1111	(0x00A074E2) 

/* Write only external IO */
#define GILL_BCR_IRDA_FSEL   (1<<0)  /* IrDA Frequency select (0 = SIR, 1 = FIR) */
#define GILL_BCR_IRDA_MD0    (1<<1)	 /* IrDA control signal */
#define GILL_BCR_IRDA_MD1    (1<<2)	 /* IrDA control signal */
#define GILL_BCR_LED_ON      (1<<3)  /* Turn LED on (active low) */
#define GILL_BCR_GSM_BOOT    (1<<4)  /* Boot up GSM module */
#define GILL_BCR_GSM_RESET   (1<<5)  /* Reset GSM module (active low) */
#define GILL_BCR_GSM_CTS     (1<<6)  /* GSM module clear to send (active low) */
#define GILL_BCR_GSM_ON      (1<<7)  /* Turn GSM module on */
#define GILL_BCR_AUDIO_ON    (1<<8)	 /* Switch on audio amplifier */
#define GILL_BCR_LIGHT_ON    (1<<9)	 /* Switch on LCD light */
#define GILL_BCR_CHARGE_PULSE (1<<10) /* Pulse generator for battery charger */
#define GILL_BCR_LCD_ON	     (1<<11) /* LCD power on */
#define GILL_BCR_RS232_ON    (1<<12) /* RS232 enable */
#define GILL_BCR_COM_RTS     (1<<13) /* RS232 request to send (active low) */
#define GILL_BCR_M_RTS       (1<<14) /* Hardware modem request to send (active low) */
#define GILL_BCR_NF_CS       (1<<15) /* NAND Flash chip select (active low) */
#define GILL_BCR_BAT_LVL1    (1<<16) /* Battery level 1 test pin (active low) */
#define GILL_BCR_BAT_LVL2    (1<<17) /* Battery level 2 test pin (active low) */
/* 18 ~ 20 write signal reserved */
#define GILL_BCR_L3_MODE     (1<<21) /* CODEC control enable (active low) */
#define GILL_BCR_L3_SCL      (1<<22) /* CODEC control clock */
#define GILL_BCR_L3_SDA      (1<<23) /* CODEC control data  */
#define GILL_BCR_LIN1_ON     (1<<24) /* Switch on audio line input amplifier */
#define GILL_BCR_LIN2_ON     (1<<25) /* Switch on audio microphone input amplifier */
#define GILL_BCR_BT_RTS      (1<<26) /* Bluetooth request to send (active low) */
#define GILL_BCR_BT_ON       (1<<27) /* Bluetooth on */
#define GILL_BCR_BT_RESET    (1<<28) /* Bluetooth reset (active low) */
#define GILL_BCR_CF_RESET    (1<<29) /* Compact flash card reset */
#define GILL_BCR_CODEC_ON    (1<<30) /* CODEC enable */
#define GILL_BCR_CODEC_RST   (1<<31) /* CODEC reset (active low) */


#define GILL_BSR_BASE    GILL_BCR_BASE
#define GILL_BSR	__REG(GILL_BSR_BASE)

/* Read only external IO */
#define GILL_BSR_IRDA_FSEL   (1<<0)  /* IrDA Frequency select (0 = SIR, 1 = FIR) */
#define GILL_BSR_ADC_BSY     (1<<1)  /* A/D Converter busy */
#define GILL_BSR_NF_BSY      (1<<2)  /* NAND Flash Busy/Ready (active low) */
#define GILL_BSR_BT_CTS      (1<<3)  /* Bluetooth clear to send (active low) */
#define GILL_BSR_GSM_BOOT    (1<<4)  /* Boot up GSM module */
#define GILL_BSR_GSM_RESET   (1<<5)  /* Reset GSM module (active low) */
#define GILL_BSR_GSM_CTS     (1<<6)  /* GSM module clear to send (active low) */
#define GILL_BSR_GSM_ON      (1<<7)  /* Turn GSM module on */
#define GILL_BSR_AUDIO_ON    (1<<8)  /* Switch on audio amplifier */
#define GILL_BSR_DC_JACK_ON  (1<<9)  /* DC jack inserted */
#define GILL_BSR_CHARGE_PULSE (1<<10) /* Pulse generator for battery charger */
#define GILL_BSR_LCD_ON      (1<<11) /* Switch on LCD power */
#define GILL_BSR_RS232_ON    (1<<12) /* RS232 enable */
#define GILL_BSR_COM_RTS     (1<<13) /* RS232 request to send (active low) */
#define GILL_BSR_MMC_CD      (1<<14) /* MMC/SD card detect (active low) */
#define GILL_BSR_MMC_WP      (1<<15) /* MMC/SD card write protect */
#define GILL_BSR_PAGEDN_BT   (1<<16) /* Switch button 3 pressed */
#define GILL_BSR_ENTER_BT    (1<<17) /* Switch button 4 pressed */
#define GILL_BSR_PAGEUP_BT   (1<<18) /* Switch button 5 pressed */
#define GILL_BSR_UP_BT       (1<<19) /* Switch button 6 pressed */
#define GILL_BSR_LEFT_BT     (1<<20) /* Switch button 7 pressed */
#define GILL_BSR_DOWN_BT     (1<<21) /* Switch button 8 pressed */
#define GILL_BSR_RIGHT_BT    (1<<22) /* Switch button 9 pressed */
#define GILL_BSR_ESCAPE_BT   (1<<23) /* Switch button 10 pressed */
#define GILL_BSR_HS_ON       (1<<24) /* Telephone handset on */
#define GILL_BSR_GSM_ANSBUT  (1<<25) /* Telephone answer button pushed */
#define GILL_BSR_GSM_RTS     (1<<26) /* GSM module request to send (active low) */
#define GILL_BSR_GSM_INTR    (1<<27) /* GSM module interrupt triggered (active low) */
#define GILL_BSR_M_CTS       (1<<28) /* Hardware modem clear to send (active low) */
#define GILL_BSR_COM_CTS     (1<<29) /* RS232 clear to send (active low) */
#define GILL_BSR_CF_BSY      (1<<30) /* Compact flash card busy (active low) */
#define GILL_BSR_CF_VS       (1<<31) /* ? (active low) */

/* GPIOs */
#define GPIO_GPIO(Nb)		(0x00000001 << (Nb))

#define GILL_GPIO_POWER_BT   GPIO_GPIO (0)  /* I, Power on/off button interrupt */
#define GILL_GPIO_DC_JACK_ON GPIO_GPIO (1)  /* I, DC Jack on (?) */
#define GILL_GPIO_ADC_TXD    GPIO_GPIO (10) /* O, A/D Convertor serial data output */
#define GILL_GPIO_ADC_RXD    GPIO_GPIO (11) /* I, A/D Convertor serial data input */
#define GILL_GPIO_ADC_CLK    GPIO_GPIO (12) /* O, A/D Convertor clock */
#define GILL_GPIO_ADC_FRM    GPIO_GPIO (13) /* O, A/D Convertor frame */
#define GILL_GPIO_BAT_LOW    GPIO_GPIO (14) /* I, Battery low level detected (active low) */
#define GILL_GPIO_SDC_D0     GPIO_GPIO (15) /* I/O, MMC/SD card data 0 */
#define GILL_GPIO_SDC_SCL    GPIO_GPIO (16) /* O, MMC/SD card clock */
#define GILL_GPIO_SDC_SDA    GPIO_GPIO (17) /* I/O, MMC/SD card I2C data */
#define GILL_GPIO_SDC_CS     GPIO_GPIO (18) /* O, MMC/SD card chip select (active low) */
#define GILL_GPIO_FS64       GPIO_GPIO (19) /* I, FS64 clock for CODEC */
#define GILL_GPIO_KEY_IRQ    GPIO_GPIO (20) /* I, Key(SW3-SW10) interrupt */
#define GILL_GPIO_PEN_IRQ    GPIO_GPIO (21) /* I, Touch panel interrupt (active low) */
#define GILL_GPIO_SDC_D1     GPIO_GPIO (22) /* I/O, MMC/SD card data 1 */
#define GILL_GPIO_CF_CD      GPIO_GPIO (23) /* I, CF card detect (active low) */
#define GILL_GPIO_CF_IRQ     GPIO_GPIO (24) /* I, CF card interrupt (active low) */
#define GILL_GPIO_CF_BVD     GPIO_GPIO (25) /* I, CF card battery detect */
#define GILL_GPIO_SDC_D2     GPIO_GPIO (26) /* I/O, MMC/SD card data 2 */
#define GILL_GPIO_RECORD_BT  GPIO_GPIO (27) /* I, Voice Record button interrupt */
