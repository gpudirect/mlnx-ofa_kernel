#ifndef _COMPAT_LINUX_MM_H
#define _COMPAT_LINUX_MM_H 1

#include "../../compat/config.h"
#include_next <linux/mm.h>

#ifdef HAVE_GET_USER_PAGES_6_PARAMS
#define get_user_pages(p1, p2, p3, p4, p5, p6, p7, p8) \
	get_user_pages(p3, p4, p5, p6, p7, p8)
#endif


#endif	/* _COMPAT_LINUX_MM_H */
