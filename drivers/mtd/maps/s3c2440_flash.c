/*
 * vivi/drivers/mtd/maps/s3c2440-flash.c: 
 *   Flash memory access on SA11x0 based devices
 *
 * Copyright (C) 2002 MIZI Research, Inc.
 * 
 * Based on linux/drivers/mtd/maps/s3c2440-flash.c
 *
 * This code is GPL.
 * 
 * Author: Janghoon Lyu <nandy@mizi.com>
 * Date  : $Date: 2004/02/04 06:22:25 $
 *
 * $Revision: 1.1.1.1 $
 * $Id: s3c2440_flash.c,v 1.1.1.1 2004/02/04 06:22:25 laputa Exp $
 *
 *
 * History
 *
 * 2002-06-26: Janghoon Lyu <nandy@mizi.com>
 *    - Created this code
 *
 */

#include "config.h"
#include "machine.h"
#include "mtd/mtd.h"
#include "mtd/map.h"
#include "io.h"
#include "printk.h"
#include "time.h"
#ifdef CONFIG_MTD_SMC
#include "mtd/nand.h"
#include "heap.h"
#endif
#include <types.h>
#include <errno.h>

#ifndef CONFIG_ARCH_S3C2440
#error This is for S3C2440 architecture only
#endif

extern struct mtd_info *mymtd;

#ifdef CONFIG_MTD_CFI

#define WINDOW_ADDR	FLASH_UNCACHED_BASE

static __u8 s3c2440_read8(struct map_info *map, unsigned long ofs)
{
	return readb(map->map_priv_1 + ofs);
}

static __u16 s3c2440_read16(struct map_info *map, unsigned long ofs)
{
	return readw(map->map_priv_1 + ofs);
}

static __u32 s3c2440_read32(struct map_info *map, unsigned long ofs)
{
	return readl(map->map_priv_1 + ofs);
}

static void s3c2440_copy_from(struct map_info *map, void *to, unsigned long from, ssize_t len)
{
	memcpy(to, (void *)(map->map_priv_1 + from), len);
}

static void s3c2440_write8(struct map_info *map, __u8 d, unsigned long adr)
{
	writeb(d, map->map_priv_1 + adr);
}

static void s3c2440_write16(struct map_info *map, __u16 d, unsigned long adr)
{
	writew(d, map->map_priv_1 + adr);
}

static void s3c2440_write32(struct map_info *map, __u32 d, unsigned long adr)
{
	writel(d, map->map_priv_1 + adr);
}

static void s3c2440_copy_to(struct map_info *map, unsigned long to, const void *from, ssize_t len)
{
	memcpy((void *)(map->map_priv_1 + to), from, len);
}

static struct map_info s3c2440_map = {
	name:		"S3C2440 flash",
	read8:		s3c2440_read8,
	read16:		s3c2440_read16,
	read32:		s3c2440_read32,
	copy_from:	s3c2440_copy_from,
	write8:		s3c2440_write8,
	write16:	s3c2440_write16,
	write32:	s3c2440_write32,
	copy_to:	s3c2440_copy_to,

	map_priv_1:	WINDOW_ADDR,
	map_priv_2:	-1,
};


extern void set_vpp(struct map_info *map, int vpp);

static int 
cfi_init(void)
{
	/* Default flash buswidth */
	s3c2440_map.buswidth = FLASH_BUSWIDTH;
	/* Default flash size */
	s3c2440_map.size = FLASH_SIZE;

	s3c2440_map.set_vpp = set_vpp;

	/*
	 * Now let's probe for the actual flash.  Do it here since
	 * specific machine settings might have been set above.
	 */
	printk("S3C2440 flash: probing %d-bit flash bus\n", s3c2440_map.buswidth*8);
	mymtd = do_map_probe("cfi_probe", &s3c2440_map);
	if (!mymtd) return -ENXIO;

	return 0;
}
#endif /* CONFIG_MTD_CFI */

#ifdef CONFIG_S3C2440_AMD_BOOT

static __u8 s3c2440_read8(struct map_info *map, unsigned long ofs)
{
	return readb(map->map_priv_1 + ofs);
}

static __u16 s3c2440_read16(struct map_info *map, unsigned long ofs)
{
	return readw(map->map_priv_1 + ofs);
}

static __u32 s3c2440_read32(struct map_info *map, unsigned long ofs)
{
	return readl(map->map_priv_1 + ofs);
}

static void s3c2440_copy_from(struct map_info *map, void *to, unsigned long from, ssize_t len)
{
	memcpy(to, (void *)(map->map_priv_1 + from), len);
}

static void s3c2440_write8(struct map_info *map, __u8 d, unsigned long adr)
{
	writeb(d, map->map_priv_1 + adr);
}

static void s3c2440_write16(struct map_info *map, __u16 d, unsigned long adr)
{
	writew(d, map->map_priv_1 + adr);
}

static void s3c2440_write32(struct map_info *map, __u32 d, unsigned long adr)
{
	writel(d, map->map_priv_1 + adr);
}

static void s3c2440_copy_to(struct map_info *map, unsigned long to, const void *from, ssize_t len)
{
	memcpy((void *)(map->map_priv_1 + to), from, len);
}

static struct map_info s3c2440_map = {
	name:		"S3C2440 amd flash",
	read8:		s3c2440_read8,
	read16:		s3c2440_read16,
	read32:		s3c2440_read32,
	copy_from:	s3c2440_copy_from,
	write8:		s3c2440_write8,
	write16:	s3c2440_write16,
	write32:	s3c2440_write32,
	copy_to:	s3c2440_copy_to,

	map_priv_1:	FLASH_UNCACHED_BASE,
	//map_priv_1:	FLASH_BASE,
	map_priv_2:	-1,
};


extern void set_vpp(struct map_info *map, int vpp);

static int 
amd_init(void)
{
	/* Default flash buswidth */
	s3c2440_map.buswidth = FLASH_BUSWIDTH;
	/* Default flash size */
	s3c2440_map.size = FLASH_SIZE;

	s3c2440_map.set_vpp = set_vpp;

	/*
	 * Now let's probe for the actual flash.  Do it here since
	 * specific machine settings might have been set above.
	 */
	printk("S3C2440 flash: probing %d-bit flash bus\n", s3c2440_map.buswidth*8);
	mymtd = do_map_probe("amd_flash", &s3c2440_map);
	if (!mymtd) return -ENXIO;

	return 0;
}
#endif /* CONFIG_MTD_CFI */




#ifdef CONFIG_MTD_SMC

static void smc_hwcontrol(int cmd) {
	switch (cmd) {
	case NAND_CTL_SETNCE:		
					NFCONT &= ~NFCONT_nFCE_HIGH; 
					break;
	case NAND_CTL_CLRNCE:		NFCONT |= NFCONT_nFCE_HIGH; break;
	case NAND_CTL_SETCLE:		break;
	case NAND_CTL_CLRCLE:		break;
	case NAND_CTL_SETALE:		break;
	case NAND_CTL_CLRALE:		break;
	case NAND_CTL_DAT_IN:		break;
	case NAND_CTL_DAT_OUT:		break;
	case NAND_CTL_CLRRnB:
					NFSTAT |= NFSTAT_RnB;
					break;
	}
}

static void
write_cmd(u_char val) 
{
	NFCMD = (u_char)val;
}

static void
write_addr(u_char val) 
{
	NFADDR = (u_char)val;
}

static u_char
read_data(void) 
{
	return (u_char)NFDATA;
}

static void
write_data(u_char val) 
{
	NFDATA = (u_char)val;
}

static void
wait_for_ready(void) 
{
	while (!(NFSTAT & NFSTAT_RnB)) {
		/* Busy */
	}
}

inline int
smc_insert(struct nand_chip *this) {
	/* Scan to find existance of the device */
    if (smc_scan(mymtd)) {
		return -ENXIO;
    }
    /* Allocate memory for internal data buffer */
    this->data_buf = mmalloc(sizeof(u_char) *
			     (mymtd->oobblock + mymtd->oobsize));

    if (!this->data_buf) {
		printk("Unable to allocate NAND data buffer for S3C2440.\n");
		this->data_buf = NULL;
		return -ENOMEM;
    }

    return 0;
}

static int
smc_init(void)
{
	struct nand_chip *this;
	//u_int16_t nfconf;
	u_int16_t nfcont;

	/* Allocate memory for MTD device structure and private data */
	mymtd = mmalloc(sizeof(struct mtd_info) + sizeof(struct nand_chip));

	if (!mymtd) {
		printk("Unable to allocate S3C2440 NAND MTD device structure.\n");
		return -ENOMEM;
	}

	/* Get pointer to private data */
	this = (struct nand_chip *)(&mymtd[1]);

	/* Initialize structures */
	memset((char *)mymtd, 0, sizeof(struct mtd_info));
	memset((char *)this, 0, sizeof(struct nand_chip));

	/* Link the private data with the MTD structure */
	mymtd->priv = this;

	/* set NAND Flash  controller */
	nfcont = NFCONT;
	/* NAND Flash controller enable */
	nfcont |= NFCONT_FCTRL_EN;
	nfcont |= NFCONT_ECC_INIT;
	nfcont |= NFCONT_MAINECC_LOCK;
	NFCONT = nfcont;
		

	/* Set flash memory timing */
//	nfconf &= ~NFCONF_TWRPH1;
//	nfconf |=  NFCONF_TWRPH1_7;
	
//	nfconf &= ~NFCONF_TWRPH0;
//	nfconf |=  NFCONF_TWRPH0_7;

//	nfconf &= ~NFCONF_TACLS;
//	nfconf &= ~NFCONF_TACLS_7;	

//	NFCONF = nfconf;

	/* Set address of NAND IO lines */
	this->hwcontrol = smc_hwcontrol;
	this->write_cmd = write_cmd;
	this->write_addr = write_addr;
	this->read_data = read_data;
	this->write_data = write_data;
	this->wait_for_ready = wait_for_ready;

	/* Chip Enable -> RESET -> Wait for Ready -> Chip Disable */
	//this->hwcontrol(NAND_CTL_SETNCE);
//	this->write_cmd(NAND_CMD_RESET);
//	this->wait_for_ready();
//	this->hwcontrol(NAND_CTL_CLRNCE);
	smc_insert(this);
	return 0;
}

#endif /* CONFIG_MTD_SMC */

int mtd_init(void)
{
	int ret;

#ifdef CONFIG_MTD_CFI
	ret = cfi_init();
#endif
#ifdef CONFIG_MTD_SMC
	ret = smc_init();
#endif
#ifdef CONFIG_S3C2440_AMD_BOOT
	ret = amd_init();
#endif

	if (ret) {
		mymtd = NULL;
		return ret;
	}
	return 0;
}
