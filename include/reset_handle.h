/*
 * vivi/include/memory.h
 *
 * Copyright (C) 2001,2002 MIZI Research, Inc.
 *
 * $Id: reset_handle.h,v 1.1.1.1 2004/02/04 06:22:25 laputa Exp $
 */

#ifndef __VIVI_RESET_H__
#define __VIVI_RESET_H__

#include <config.h>

#ifdef CONFIG_RESET_HANDLING
void reset_handler(void);
#else
#define reset_handler()	(void)(0)
#endif

#endif /* __VIVI_RESET_H__ */
