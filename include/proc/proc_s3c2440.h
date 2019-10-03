/*
 * vivi/include/proc/proc_s3c2440.h: 
 *
 * Copyright (C) 2002 MIZI Research, Inc.
 *
 * Author: Janghoon Lyu <nandy@mizi.com>
 * Date  : $Date: 2004/02/04 06:22:25 $ 
 *
 * $Revision: 1.1.1.1 $
 * $Id: proc_s3c2440.h,v 1.1.1.1 2004/02/04 06:22:25 laputa Exp $
 *
 *
 * History
 *
 * 2002-07-08: Janghoon Lyu <nandy@mizi.com>
 *
 */

#ifndef _PROC_S3C2440_H_
#define _PROC_S3C2440_H_

#include "s3c2440.h"

/*
 * UART
 *
 * You may be define six functions.
 *  SERIAL_READ_READY(), SERIAL_READ_CHAR(), SERIAL_READ_STATUS(),
 *  SERIAL_WRITE_READY(), SERIAL_WRITE_CHAR(), SERIAL_WRITE_STATUS()
 */


#ifdef CONFIG_SERIAL_UART0
#define SERIAL_CHAR_READY()     (UTRSTAT0 & UTRSTAT_RX_READY)
#define SERIAL_READ_CHAR()      URXH0
#define SERIAL_READ_STATUS()    (UERSTAT0 & UART_ERR_MASK) 
#elif defined(CONFIG_SERIAL_UART1)
#define SERIAL_CHAR_READY()     (UTRSTAT1 & UTRSTAT_RX_READY)
#define SERIAL_READ_CHAR()      URXH1
#define SERIAL_READ_STATUS()    (UERSTAT1 & UART_ERR_MASK) 
#elif defined(CONFIG_SERIAL_UART2)
#define SERIAL_CHAR_READY()     (UTRSTAT2 & UTRSTAT_RX_READY)
#define SERIAL_READ_CHAR()      URXH2
#define SERIAL_READ_STATUS()    (UERSTAT2 & UART_ERR_MASK) 
#else
#error not support this serial port
#endif


#ifdef CONFIG_SERIAL_UART0
#define SERIAL_WRITE_STATUS()	(UTRSTAT0)
#define SERIAL_WRITE_READY()	((UTRSTAT0) & UTRSTAT_TX_EMPTY)
#define SERIAL_WRITE_CHAR(c)	((UTXH0) = (c))
#elif defined(CONFIG_SERIAL_UART1)
#define SERIAL_WRITE_STATUS()	(UTRSTAT1)
#define SERIAL_WRITE_READY()	((UTRSTAT1) & UTRSTAT_TX_EMPTY)
#define SERIAL_WRITE_CHAR(c)	((UTXH1) = (c))
#elif defined(CONFIG_SERIAL_UART2)
#define SERIAL_WRITE_STATUS()	(UTRSTAT2)
#define SERIAL_WRITE_READY()	((UTRSTAT2) & UTRSTAT_TX_EMPTY)
#define SERIAL_WRITE_CHAR(c)	((UTXH2) = (c))
#else
#error not support this serial port
#endif

#endif /* _PROC_S3C2440_H_ */
