#
# linux/drivers/nand/Makefile
#
# $Id: Makefile,v 1.1.1.1 2004/02/04 06:22:25 laputa Exp $

O_TARGET	:= nandlink.o


obj-y			:=
obj-$(CONFIG_MTD_NAND_ECC)	+= nand_ecc.o
ifeq ($(CONFIG_ARCH_S3C2440),y)
obj-$(CONFIG_MTD_SMC)		+= smc_core_2440.o bon.o
else
obj-$(CONFIG_MTD_SMC)		+= smc_core.o bon.o
endif
obj-$(CONFIG_MTD_BONFS)		+= bon.o

include $(TOPDIR)/Rules.make
