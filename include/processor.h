/*
 * vivi/include/processor.h:
 *
 *
 */
#ifndef _VIVI_PROC_H_
#define _VIVI_PROC_H_

#include "config.h"

#ifdef CONFIG_ARCH_SA1100
#include "proc/proc_sa1100.h"
#elif defined(CONFIG_ARCH_S3C2400)
#include "proc/proc_s3c2400.h"
#elif defined(CONFIG_ARCH_S3C2410)
#include "proc/proc_s3c2410.h"
#elif defined(CONFIG_ARCH_S3C2440)
#include "proc/proc_s3c2440.h"
#elif defined(CONFIG_ARCH_PXA250)
#include "proc/proc_pxa250.h"
#else
#error no defined processor
#endif

#define PROC_SERIAL_PUTC(c)	\
	({ while (!SERIAL_WRITE_READY()); \
	   SERIAL_WRITE_CHAR(c); })

#endif /* _VIVI_PROC_H_ */
