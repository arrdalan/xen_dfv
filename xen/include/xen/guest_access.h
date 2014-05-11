/******************************************************************************
 * guest_access.h
 * 
 * Copyright (x) 2006, K A Fraser
 */

#ifndef __XEN_GUEST_ACCESS_H__
#define __XEN_GUEST_ACCESS_H__

#include <asm/guest_access.h>

#define copy_to_guest(hnd, ptr, nr)                     \
    copy_to_guest_offset(hnd, 0, ptr, nr)

#define copy_from_guest(ptr, hnd, nr)                   \
    copy_from_guest_offset(ptr, hnd, 0, nr)

#define clear_guest(hnd, nr)                            \
    clear_guest_offset(hnd, 0, nr)

#define __copy_to_guest(hnd, ptr, nr)                   \
    __copy_to_guest_offset(hnd, 0, ptr, nr)

#define __copy_from_guest(ptr, hnd, nr)                 \
    __copy_from_guest_offset(ptr, hnd, 0, nr)

#define __clear_guest(hnd, nr)                          \
    __clear_guest_offset(hnd, 0, nr)
    
#define copy_between_guests(dst_dom, src_dom, dst, src, len, flags, grant)  \
    __copy_between_guests(dst_dom, src_dom, dst, src, len, flags, grant)
    
#define map_page_to_domain_user(dom, gfn, addr, flags, grant)               \
    __map_page_to_domain_user(dom, gfn, addr, flags, grant)
    
#define unmap_page_from_domain_user(dom, gfn, grant)                        \
    __unmap_page_from_domain_user(dom, gfn, grant)

#endif /* __XEN_GUEST_ACCESS_H__ */
