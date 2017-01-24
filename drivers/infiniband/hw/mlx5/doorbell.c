/*
 * Copyright (c) 2013-2015, Mellanox Technologies. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/kref.h>
#include <linux/slab.h>
#include <rdma/ib_umem.h>

#include "mlx5_ib.h"

struct mlx5_ib_user_db_page {
	struct list_head	list;
	struct ib_umem	       *umem;
	unsigned long		user_virt;
	int			refcnt;

	atomic_t                invalidated;
	struct completion       invalidation_comp;
};

static void mlx5_db_invalidate_umem(void *invalidation_cookie,
                                    struct ib_umem *umem,
                                    unsigned long addr, size_t size)
{

	struct mlx5_ib_user_db_page *page = (struct mlx5_ib_user_db_page *)invalidation_cookie;

	printk(KERN_INFO "%s page=%p umem=%p\n", __FUNCTION__, page, umem);

	/* This function is called under client peer lock so its resources are race protected */
	if (atomic_inc_return(&page->invalidated) > 1) {
		printk(KERN_ERR "%s invalidation is already in-flight\n", __FUNCTION__);
		umem->invalidation_ctx->inflight_invalidation = 1;
		return;
	}

        if (umem != page->umem) {
                printk(KERN_ERR "%s error unexpected cq->uem=%p != umem=%p\n", __FUNCTION__, page->umem, umem);
        } else {
                page->umem = NULL;
        }

	umem->invalidation_ctx->peer_callback = 1;
	// TODO:
	// - free MTTs related, etc..
	// - make it ODP friendly ?
	printk(KERN_ERR "releasing umem=%p\n", umem);
	ib_umem_release(umem);
	complete(&page->invalidation_comp);
}

int mlx5_ib_db_map_user(struct mlx5_ib_ucontext *context, unsigned long virt,
			struct mlx5_db *db)
{
	struct mlx5_ib_user_db_page *page;
	int err = 0;

	printk(KERN_INFO "%s %d\n", __FUNCTION__, __LINE__);

	mutex_lock(&context->db_page_mutex);

	list_for_each_entry(page, &context->db_page_list, list)
		if (page->user_virt == (virt & PAGE_MASK)) {
                        if (!page->umem)
                                printk(KERN_INFO "INFO %s skipping page=%p as umem==NULL\n", __FUNCTION__, page);
                        else
                                goto found;
                }

	page = kmalloc(sizeof(*page), GFP_KERNEL);
	if (!page) {
		err = -ENOMEM;
		goto out;
	}

	page->user_virt = (virt & PAGE_MASK);
	page->refcnt    = 0;
	//page->umem      = ib_umem_get(&context->ibucontext, virt & PAGE_MASK,
	//			      PAGE_SIZE, 0, 0);
	page->umem      = ib_umem_get_ex(&context->ibucontext, virt & PAGE_MASK,
                                         PAGE_SIZE, 0, 0, 1);
	if (IS_ERR(page->umem)) {
		err = PTR_ERR(page->umem);
                printk(KERN_ERR "ERR %s error %d in ib_umem_get_ex virt=%lx\n", __FUNCTION__, err, page->user_virt);
		kfree(page);
		goto out;
	}

	list_add(&page->list, &context->db_page_list);

	atomic_set(&page->invalidated, 0);
	if (page->umem && page->umem->ib_peer_mem) {
                printk(KERN_INFO "%s got peer_mem, umem=%p\n", __FUNCTION__, page->umem);
		init_completion(&page->invalidation_comp);
		ib_umem_activate_invalidation_notifier(page->umem, mlx5_db_invalidate_umem, page);
	}

found:
	db->dma = sg_dma_address(page->umem->sg_head.sgl) + (virt & ~PAGE_MASK);
	db->u.user_page = page;
	++page->refcnt;

	printk(KERN_INFO "%s %d dma=%lx\n", __FUNCTION__, __LINE__, (unsigned long)db->dma);
out:
	mutex_unlock(&context->db_page_mutex);

	return err;
}

void mlx5_ib_db_unmap_user(struct mlx5_ib_ucontext *context, struct mlx5_db *db)
{
	mutex_lock(&context->db_page_mutex);

	if (!--db->u.user_page->refcnt) {
		list_del(&db->u.user_page->list);
                if (db->u.user_page->umem)
                    ib_umem_release(db->u.user_page->umem);
                else
                    printk(KERN_INFO "%s %d umem already released\n", __FUNCTION__, __LINE__);
		kfree(db->u.user_page);
	}

	mutex_unlock(&context->db_page_mutex);
}
