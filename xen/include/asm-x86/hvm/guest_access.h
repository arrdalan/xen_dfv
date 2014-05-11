#ifndef __ASM_X86_HVM_GUEST_ACCESS_H__
#define __ASM_X86_HVM_GUEST_ACCESS_H__

unsigned long copy_to_user_hvm(void *to, const void *from, unsigned len);
unsigned long clear_user_hvm(void *to, unsigned int len);
unsigned long copy_from_user_hvm(void *to, const void *from, unsigned len);
unsigned long copy_between_guests_hvm(struct domain *dst_domain,
    struct domain *src_domain, const void *dst_addr, const void *src_addr, 
    int len, unsigned int flags, unsigned long grant);
unsigned long __hvm_map_page_to_domain_user(struct domain *domain,
		unsigned long gfn, unsigned long vaddr, unsigned long flags,
		unsigned long grant);
unsigned long __hvm_unmap_page_from_domain_user(struct domain *domain,
		unsigned long gfn, unsigned long grant);

#endif /* __ASM_X86_HVM_GUEST_ACCESS_H__ */
