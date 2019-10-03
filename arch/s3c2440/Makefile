O_TARGET	:= s3c2440.o

obj-y :=

ifeq ($(CONFIG_S3C2440_NAND_BOOT),y)
obj-y += nand_read.o
endif
obj-y += mmu.o proc.o
obj-$(CONFIG_S3C2440_SMDK) += smdk.o
ifeq ($(CONFIG_S3C2440_SMDK),y)
obj-$(CONFIG_TEST) += smdk2440_test.o
endif

include $(TOPDIR)/Rules.make
