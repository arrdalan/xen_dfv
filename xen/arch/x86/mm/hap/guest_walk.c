/*
 * arch/x86/mm/hap/guest_walk.c
 *
 * Guest page table walker
 * Copyright (c) 2007, AMD Corporation (Wei Huang)
 * Copyright (c) 2007, XenSource Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 59 Temple
 * Place - Suite 330, Boston, MA 02111-1307 USA.
 */


#include <xen/domain_page.h>
#include <xen/paging.h>
#include <xen/config.h>
#include <xen/sched.h>
#include <xen/grant_table.h>
#include "private.h" /* for hap_gva_to_gfn_* */

#define _hap_gva_to_gfn(levels) hap_gva_to_gfn_##levels##_levels
#define hap_gva_to_gfn(levels) _hap_gva_to_gfn(levels)

#define _hap_p2m_ga_to_gfn(levels) hap_p2m_ga_to_gfn_##levels##_levels
#define hap_p2m_ga_to_gfn(levels) _hap_p2m_ga_to_gfn(levels)

#define _hap_map_page_to_domain_user(levels) 		\
			hap_map_page_to_domain_user_##levels##_levels
#define hap_map_page_to_domain_user(levels)		\
			_hap_map_page_to_domain_user(levels)

#define _hap_unmap_page_from_domain_user(levels)	\
			hap_unmap_page_from_domain_user_##levels##_levels
#define hap_unmap_page_from_domain_user(levels)		\
			_hap_unmap_page_from_domain_user(levels)
			
struct map_entry {
    unsigned long mfn;
    unsigned long gfn;
    unsigned long vaddr;
    int p2mt;
    int p2ma;
    int is_mmio;
    struct list_head list;
};

#if GUEST_PAGING_LEVELS > CONFIG_PAGING_LEVELS
#error GUEST_PAGING_LEVELS must not exceed CONFIG_PAGING_LEVELS
#endif

#include <asm/guest_pt.h>
#include <asm/p2m.h>

unsigned long hap_gva_to_gfn(GUEST_PAGING_LEVELS)(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long gva, uint32_t *pfec)
{
    unsigned long cr3 = v->arch.hvm_vcpu.guest_cr[3];
    return hap_p2m_ga_to_gfn(GUEST_PAGING_LEVELS)(v, p2m, cr3, gva, pfec, NULL);
}

unsigned long hap_p2m_ga_to_gfn(GUEST_PAGING_LEVELS)(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long cr3,
    paddr_t ga, uint32_t *pfec, unsigned int *page_order)
{
    uint32_t missing;
    mfn_t top_mfn;
    void *top_map;
    p2m_type_t p2mt;
    walk_t gw;
    unsigned long top_gfn;
    struct page_info *top_page;

    /* Get the top-level table's MFN */
    top_gfn = cr3 >> PAGE_SHIFT;
    top_page = get_page_from_gfn_p2m(p2m->domain, p2m, top_gfn,
                                     &p2mt, NULL, P2M_ALLOC | P2M_UNSHARE);
    if ( p2m_is_paging(p2mt) )
    {
        ASSERT(!p2m_is_nestedp2m(p2m));
        pfec[0] = PFEC_page_paged;
        if ( top_page )
            put_page(top_page);
        p2m_mem_paging_populate(p2m->domain, cr3 >> PAGE_SHIFT);
        return INVALID_GFN;
    }
    if ( p2m_is_shared(p2mt) )
    {
        pfec[0] = PFEC_page_shared;
        if ( top_page )
            put_page(top_page);
        return INVALID_GFN;
    }
    if ( !top_page )
    {
        pfec[0] &= ~PFEC_page_present;
        return INVALID_GFN;
    }
    top_mfn = _mfn(page_to_mfn(top_page));

    /* Map the top-level table and call the tree-walker */
    ASSERT(mfn_valid(mfn_x(top_mfn)));
    top_map = map_domain_page(mfn_x(top_mfn));
#if GUEST_PAGING_LEVELS == 3
    top_map += (cr3 & ~(PAGE_MASK | 31));
#endif
    missing = guest_walk_tables(v, p2m, ga, &gw, pfec[0], top_mfn, top_map);
    unmap_domain_page(top_map);
    put_page(top_page);

    /* Interpret the answer */
    if ( missing == 0 )
    {
        gfn_t gfn = guest_l1e_get_gfn(gw.l1e);
        struct page_info *page;
        page = get_page_from_gfn_p2m(p2m->domain, p2m, gfn_x(gfn), &p2mt,
                                     NULL, P2M_ALLOC | P2M_UNSHARE);
        if ( page )
            put_page(page);
        if ( p2m_is_paging(p2mt) )
        {
            ASSERT(!p2m_is_nestedp2m(p2m));
            pfec[0] = PFEC_page_paged;
            p2m_mem_paging_populate(p2m->domain, gfn_x(gfn));
            return INVALID_GFN;
        }
        if ( p2m_is_shared(p2mt) )
        {
            pfec[0] = PFEC_page_shared;
            return INVALID_GFN;
        }

        if ( page_order )
            *page_order = guest_walk_to_page_order(&gw);

        return gfn_x(gfn);
    }

    if ( missing & _PAGE_PRESENT )
        pfec[0] &= ~PFEC_page_present;

    if ( missing & _PAGE_INVALID_BITS ) 
        pfec[0] |= PFEC_reserved_bit;

    if ( missing & _PAGE_PAGED )
        pfec[0] = PFEC_page_paged;

    if ( missing & _PAGE_SHARED )
        pfec[0] = PFEC_page_shared;

    return INVALID_GFN;
}

static unsigned long get_free_gfn(struct domain *domain, struct p2m_domain *p2m)
{
    unsigned long gfn;
    p2m_type_t p2mt;
    mfn_t mfn;
    p2m_access_t a;
    
    gfn = domain->last_mapped_pfn;
    
    if ( gfn == 0 )
    {    	
        /*
         * FIXME: We need s gfn not used in the domain here. Currently,
         * we use this hack that we start from 0xeeeee and go down and test
         * to see whether the gfn is already used or not. This approach has
         * one important problem: the domain is not aware of this and hence if 
         * the domain's memory is increased and overlaps with the addresses
         * we've used, it can cause problems. The solution is to allocate a
         * range of unused gfn's in the domain for this purpose.
         */
	gfn = 0xeeeee;    	    
    }
        
    for( ; ; )
    {
        gfn_lock(p2m, gfn, 0);
        mfn = p2m->get_entry(p2m, gfn, &p2mt, &a, 0, NULL);

        if ( (INVALID_MFN == mfn_x(mfn)) )
        {
            gfn_unlock(p2m, gfn, 0);
            break;
        }
        gfn_unlock(p2m, gfn, 0);
        gfn--;
    }    
    
    domain->last_mapped_pfn = gfn - 1;    
    
    return gfn;
}

static struct map_entry *get_map_entry(struct domain *domain, unsigned long mfn)
{
    struct map_entry *entry, *e_tmp;
	    
    list_for_each_entry_safe( entry, e_tmp, &domain->map_list, list )
    {		
        if ( entry->mfn != mfn )
	    continue;
    
        return entry;
    }
    
    return NULL;	
}
static int save_mapped_page_info(struct domain *domain, unsigned long mfn,
				unsigned long gfn, unsigned long vaddr,
				int p2mt, int p2ma, int is_mmio)
{
    struct map_entry *entry;
    
    entry = xmalloc(struct map_entry);
    if (!entry) {
    	PRINTK_ERR("Error: entry allocation failed.\n");
	return -ENOMEM;
    }
	
    entry->mfn = mfn;
    entry->gfn = gfn;
    entry->vaddr = vaddr;
    entry->p2mt = p2mt;
    entry->p2ma = p2ma;
    entry->is_mmio = is_mmio;
    
    INIT_LIST_HEAD(&entry->list);
    list_add(&entry->list, &domain->map_list);
    
    return 0;
}

unsigned long hap_map_page_to_domain_user(GUEST_PAGING_LEVELS)(
    struct vcpu *v, struct domain *domain, unsigned long gfn,
    unsigned long vaddr, unsigned long flags, unsigned long grant)
{    
    walk_t gw;
    mfn_t top_mfn;
    p2m_type_t p2mt, p2mt2, p2mt4;
    p2m_access_t p2ma, p2ma2;
    void *top_map;
    unsigned long top_gfn;
    struct page_info *top_page;
    uint32_t pfec = 0, missing;
    struct page_info *src_page;
    unsigned long dst_gfn, src_mfn;
    int is_mmio;
    unsigned long cr3 = grant;
    unsigned long mfn;
    l1_pgentry_t l1e;
    guest_l1e_t l1_pte;
    uint32_t pte_flags;
    void *entry_ma;
    struct p2m_domain *p2m = domain->arch.p2m;
        
    top_gfn = cr3 >> PAGE_SHIFT;
    top_page = get_page_from_gfn_p2m(domain, p2m, top_gfn,
                                     &p2mt, NULL, P2M_ALLOC | P2M_UNSHARE);
    
    if ( p2m_is_paging(p2mt) )
    {
        if ( top_page )
            put_page(top_page);        
        
        return 0;        
    }
    if ( p2m_is_shared(p2mt) )
    {        
        if ( top_page )
            put_page(top_page);
            
        return 0;
    }
    if ( !top_page )
    {
    	PRINTK_ERR("Error: top_page does not exist.\n");        
        return 0;
    }

    top_mfn = _mfn(page_to_mfn(top_page));

    ASSERT(mfn_valid(mfn_x(top_mfn)));
        
    top_map = map_domain_page(mfn_x(top_mfn));
#if GUEST_PAGING_LEVELS == 3
    top_map += (cr3 & ~(PAGE_MASK | 31));
#endif
    missing = guest_walk_tables(v, p2m, vaddr, &gw, pfec, top_mfn, top_map);
    unmap_domain_page(top_map);
    put_page(top_page);
    
    if ( missing == 0 )
    {
    	PRINTK_ERR("Error: page is already mapped.\n");        
        return 0;
    }
    if ( !(missing & _PAGE_PRESENT) )
    {
        PRINTK_ERR("Error: _PAGE_PRESENT is set.\n");        
        return 0;
    }
        
#if GUEST_PAGING_LEVELS >= 3 /* PAE or 64... */
    if ( gw.l3e.l3 == 0 )
    {
        PRINTK_ERR("Error: fixing the l3e is not supported.\n");
        return 0;
    }
#endif
    
    if (gw.l2e.l2 == 0)
    {
    	PRINTK_ERR("Error: fixing the l2e is not supported.\n");
        return 0;    
    }	    
    
    dst_gfn = get_free_gfn(domain, p2m);
        
    src_page = get_page_from_gfn_p2m(current->domain, current->domain->arch.p2m,
    	    			gfn, &p2mt2, &p2ma2, P2M_UNSHARE);
    
    if ( p2m_is_paging(p2mt2) )
    {
        if (src_page)
        	    put_page(src_page);
            
        return 0;
    }
    if ( p2m_is_shared(p2mt2) )
    {
        if (src_page)
        	    put_page(src_page);
            
        return 0;    
    }
    
    if ( !src_page )
    {
        src_mfn = get_mmio_p2m_entry(current->domain, gfn);
                
        if (!src_mfn) {
            PRINTK_ERR("Error: get_mmio_p2m_entry from gfn failed.\n");    	        
            return 0;        
        }
        
        if ( !set_mmio_p2m_entry(domain, dst_gfn, src_mfn) )
        {
            PRINTK_ERR("Error: set_mmio_p2m_entry for dst_gfn failed.\n");    	        
            return 0;        
        }
        
        is_mmio = 1;
        
    }
    else
    {
        src_mfn = _mfn(page_to_mfn(src_page));
        
        if ( flags & _PAGE_RW )
        {
            p2mt4 = p2m_grant_map_rw;
            p2ma = p2m_access_rw;
        }
        else
        {
            p2mt4 = p2m_grant_map_ro;
            p2ma = p2m_access_r;
        }
       
        if (!set_p2m_entry(p2m, dst_gfn, src_mfn, PAGE_ORDER_4K, p2m_ram_rw,
    	    					p2m->default_access))
        {
            PRINTK_ERR("Error: set_p2m_entry for dst_gfn failed.\n");
    	    put_page(src_page);    
            return 0;        
        }
                        
        put_page(src_page);
        
        is_mmio = 0;
    }
    
    if ( save_mapped_page_info(domain, src_mfn, gfn, vaddr, (int) p2mt2,
						(int) p2ma2, is_mmio) )
    {
        PRINTK_ERR("Error: save_unmapped_page failed.\n");
        return 0;
    }
    
            
    pte_flags = (uint32_t) flags;
        
    l1e = l1e_from_pfn(dst_gfn, pte_flags);
            
    l1_pte.l1 = (guest_intpte_t) l1e.l1;    
      
    mfn = gw.l1mfn;
        
    entry_ma = map_domain_page(mfn_x(mfn));
    
    ((guest_l1e_t *) entry_ma)[guest_l1_table_offset(vaddr)] = l1_pte;
    
    unmap_domain_page(entry_ma);
    /* Double-check that the map was successful. */
    /*
    missing = guest_walk_tables(v, p2m, vaddr, &gw, pfec, top_mfn, top_map);
        
    
    print_gw2(&gw);
 
    if (missing & _PAGE_PRESENT) {
        PRINTK_ERR("Error: page was not mapped successfully.\n");
    }
    */
    
    return dst_gfn;
}

unsigned long hap_unmap_page_from_domain_user(GUEST_PAGING_LEVELS)(
    struct vcpu *v, struct domain *domain, unsigned long gfn,
    unsigned long grant)
{       
    unsigned long src_mfn, unused_cr3;
    int ret;
    struct map_entry *entry;
    struct p2m_domain *p2m = domain->arch.p2m;
    
    src_mfn = get_p2m_entry(domain, gfn);
    
    entry = get_map_entry(domain, src_mfn);
    if (entry == NULL) {
    	PRINTK_ERR("Error: get_map_entry failed.\n");
    	return INVALID_GFN;
    }    
    
    /* First, we validate the unmap operation. */
    ret = validate_dfv_grant(current->domain, domain, grant, &unused_cr3, 
    	    entry->vaddr, PAGE_SIZE, 3);
    if (ret) {
        PRINTK_ERR("Error: grant could not be validated for munmap, "
    	    	    					"error = %d.\n", ret);
        return INVALID_GFN;
    }
    
    /* Then, we unmap. */
    if (!set_p2m_entry(p2m, gfn, _mfn(INVALID_MFN), PAGE_ORDER_4K,
    	    				p2m_invalid, p2m->default_access))
    {
    	PRINTK_ERR("Error: clearing p2m entry failed.\n");
    	return INVALID_GFN;
    }
    
    /* Is this the best algorithm? */
    if (gfn > domain->last_mapped_pfn) {
    	    domain->last_mapped_pfn = gfn;
    }
    return 0;    	    
}


/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
