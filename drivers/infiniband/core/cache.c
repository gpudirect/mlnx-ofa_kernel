/*
 * Copyright (c) 2004 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Intel Corporation. All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2005 Voltaire, Inc. All rights reserved.
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

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/workqueue.h>

#include <rdma/ib_cache.h>

#include "core_priv.h"

#define __IB_ONLY

struct ib_pkey_cache {
	int             table_len;
	u16             table[0];
};

struct ib_gid_cache {
	int             table_len;
	union ib_gid    table[0];
};

struct ib_update_work {
	struct work_struct work;
	struct ib_device  *device;
	u8                 port_num;
};

static int __IB_ONLY __ib_get_cached_gid(struct ib_device *device,
					 u8                port_num,
					 int               index,
					 union ib_gid     *gid)
{
	struct ib_gid_cache *cache;
	unsigned long flags;
	int ret = -ENOENT;

	if (port_num < rdma_start_port(device) || port_num > rdma_end_port(device))
		return -EINVAL;
	if (!device->cache.gid_cache)
		return -ENOENT;

	read_lock_irqsave(&device->cache.lock, flags);

	cache = device->cache.gid_cache[port_num - rdma_start_port(device)];
	if (cache && index >= 0 && index < cache->table_len) {
		*gid = cache->table[index];
		ret = 0;
	}

	read_unlock_irqrestore(&device->cache.lock, flags);
	return ret;
}

int ib_cache_use_roce_gid_cache(struct ib_device *device, u8 port_num)
{
	if (rdma_port_get_link_layer(device, port_num) ==
	    IB_LINK_LAYER_ETHERNET) {
		if (device->cache.roce_gid_cache)
			return 0;
		else
			return -EAGAIN;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(ib_cache_use_roce_gid_cache);

int ib_get_cached_gid(struct ib_device *device,
		      u8                port_num,
		      int               index,
		      union ib_gid     *gid,
		      struct ib_gid_attr *attr)
{
	int ret;

	if (port_num < rdma_start_port(device) || port_num > rdma_end_port(device))
		return -EINVAL;

	ret = ib_cache_use_roce_gid_cache(device, port_num);
	if (!ret)
		return roce_gid_cache_get_gid(device, port_num, index, gid,
					      attr);

	if (ret == -EAGAIN)
		return ret;

	ret = __ib_get_cached_gid(device, port_num, index, gid);

	if (!ret && attr) {
		memset(attr, 0, sizeof(*attr));
		attr->gid_type = IB_GID_TYPE_IB;
	}

	return ret;
}
EXPORT_SYMBOL(ib_get_cached_gid);

static int __IB_ONLY ___ib_find_cached_gid_by_port(struct ib_device *device,
						   u8               port_num,
						   const union ib_gid *gid,
						   u16              *index)
{
	struct ib_gid_cache *cache;
	u8 p = port_num - rdma_start_port(device);
	int i;

	if (port_num < rdma_start_port(device) || port_num > rdma_end_port(device))
		return -EINVAL;
	if (!ib_cache_use_roce_gid_cache(device, port_num))
		return -ENOSYS;
	if (!device->cache.gid_cache)
		return -ENOENT;

	cache = device->cache.gid_cache[p];
	if (!cache)
		return -ENOENT;

	for (i = 0; i < cache->table_len; ++i) {
		if (!memcmp(gid, &cache->table[i], sizeof(*gid))) {
			if (index)
				*index = i;
			return 0;
		}
	}

	return -ENOENT;
}

static int __IB_ONLY __ib_find_cached_gid_by_port(struct ib_device *device,
						  u8		    port_num,
						  union ib_gid     *gid,
						  u16              *index)
{
	unsigned long flags;
	u16 found_index;
	int ret;

	if (index)
		*index = -1;

	read_lock_irqsave(&device->cache.lock, flags);

	ret = ___ib_find_cached_gid_by_port(device, port_num, gid,
					    &found_index);

	read_unlock_irqrestore(&device->cache.lock, flags);

	if (!ret && index)
		*index = found_index;

	return ret;
}

static int __IB_ONLY __ib_find_cached_gid(struct ib_device *device,
					  union ib_gid     *gid,
					  u8               *port_num,
					  u16              *index)
{
	unsigned long flags;
	u16 found_index;
	int p;
	int ret = -ENOENT;

	if (port_num)
		*port_num = -1;
	if (index)
		*index = -1;

	read_lock_irqsave(&device->cache.lock, flags);

	for (p = rdma_start_port(device); p <= rdma_end_port(device); ++p) {
		if (!___ib_find_cached_gid_by_port(device, p, gid,
						   &found_index)) {
			if (port_num)
				*port_num = p;
			ret = 0;
			break;
		}
	}

	read_unlock_irqrestore(&device->cache.lock, flags);

	if (!ret && index)
		*index = found_index;

	return ret;
}

int ib_find_cached_gid(struct ib_device *device,
		       union ib_gid	*gid,
		       enum ib_gid_type gid_type,
		       struct net	*net,
		       int		if_index,
		       u8               *port_num,
		       u16              *index)
{
	int ret = -ENOENT;

	/* Look for a RoCE device with the specified GID. */
	if (device->cache.roce_gid_cache)
		ret = roce_gid_cache_find_gid(device, gid, gid_type, net,
					      if_index, port_num, index);

	/* If no RoCE devices with the specified GID, look for IB device. */
	if (ret && gid_type == IB_GID_TYPE_IB)
		ret =  __ib_find_cached_gid(device, gid, port_num, index);

	return ret;
}
EXPORT_SYMBOL(ib_find_cached_gid);

int ib_find_cached_gid_by_port(struct ib_device *device,
			       union ib_gid	*gid,
			       enum ib_gid_type gid_type,
			       u8               port_num,
			       struct net	*net,
			       int		if_index,
			       u16              *index)
{
	int ret = -ENOENT;

	/* Look for a RoCE device with the specified GID. */
	if (!ib_cache_use_roce_gid_cache(device, port_num))
		return roce_gid_cache_find_gid_by_port(device, gid, gid_type,
						       port_num, net, if_index,
						       index);

	/* If no RoCE devices with the specified GID, look for IB device. */
	if (gid_type == IB_GID_TYPE_IB)
		ret = __ib_find_cached_gid_by_port(device, port_num,
						   gid, index);

	return ret;
}
EXPORT_SYMBOL(ib_find_cached_gid_by_port);

int ib_find_gid_by_filter(struct ib_device *device,
			  union ib_gid *gid,
			  u8 port_num,
			  bool (*filter)(const union ib_gid *gid,
					 const struct ib_gid_attr *,
					 void *),
			  void *context, u16 *index)
{
	/* Look for a RoCE device with the specified GID. */
	if (!ib_cache_use_roce_gid_cache(device, port_num))
		return roce_gid_cache_find_gid_by_filter(device, gid,
							 port_num, filter,
							 context, index);

	/* Only RoCE GID cache supports filter function */
	if (filter)
		return -ENOSYS;

	/* If no RoCE devices with the specified GID, look for IB device. */
	return __ib_find_cached_gid_by_port(device, port_num,
					    gid, index);
}
EXPORT_SYMBOL(ib_find_gid_by_filter);

int ib_get_cached_pkey(struct ib_device *device,
		       u8                port_num,
		       int               index,
		       u16              *pkey)
{
	struct ib_pkey_cache *cache;
	unsigned long flags;
	int ret = -ENOENT;

	if (port_num < rdma_start_port(device) || port_num > rdma_end_port(device))
		return -EINVAL;

	if (!device->cache.pkey_cache)
		return -ENOENT;

	read_lock_irqsave(&device->cache.lock, flags);

	cache = device->cache.pkey_cache[port_num - rdma_start_port(device)];
	if (cache && index >= 0 && index < cache->table_len) {
		*pkey = cache->table[index];
		ret = 0;
	}

	read_unlock_irqrestore(&device->cache.lock, flags);
	return ret;
}
EXPORT_SYMBOL(ib_get_cached_pkey);

int ib_find_cached_pkey(struct ib_device *device,
			u8                port_num,
			u16               pkey,
			u16              *index)
{
	struct ib_pkey_cache *cache;
	unsigned long flags;
	int i;
	int ret = -ENOENT;
	int partial_ix = -1;

	if (port_num < rdma_start_port(device) || port_num > rdma_end_port(device))
		return -EINVAL;

	if (!device->cache.pkey_cache)
		return -ENOENT;

	read_lock_irqsave(&device->cache.lock, flags);

	cache = device->cache.pkey_cache[port_num - rdma_start_port(device)];
	if (!cache)
		goto out;

	*index = -1;

	for (i = 0; i < cache->table_len; ++i)
		if ((cache->table[i] & 0x7fff) == (pkey & 0x7fff)) {
			if (cache->table[i] & 0x8000) {
				*index = i;
				ret = 0;
				break;
			} else
				partial_ix = i;
		}

	if (ret && partial_ix >= 0) {
		*index = partial_ix;
		ret = 0;
	}

out:
	read_unlock_irqrestore(&device->cache.lock, flags);
	return ret;
}
EXPORT_SYMBOL(ib_find_cached_pkey);

int ib_find_exact_cached_pkey(struct ib_device *device,
			      u8                port_num,
			      u16               pkey,
			      u16              *index)
{
	struct ib_pkey_cache *cache;
	unsigned long flags;
	int i;
	int ret = -ENOENT;

	if (port_num < rdma_start_port(device) || port_num > rdma_end_port(device))
		return -EINVAL;

	if (!device->cache.pkey_cache)
		return -ENOENT;

	read_lock_irqsave(&device->cache.lock, flags);

	cache = device->cache.pkey_cache[port_num - rdma_start_port(device)];
	if (!cache)
		goto out;

	*index = -1;

	for (i = 0; i < cache->table_len; ++i)
		if (cache->table[i] == pkey) {
			*index = i;
			ret = 0;
			break;
		}
out:
	read_unlock_irqrestore(&device->cache.lock, flags);
	return ret;
}
EXPORT_SYMBOL(ib_find_exact_cached_pkey);

int ib_get_cached_lmc(struct ib_device *device,
		      u8                port_num,
		      u8                *lmc)
{
	unsigned long flags;
	int ret = -ENOENT;

	if (port_num < rdma_start_port(device) || port_num > rdma_end_port(device))
		return -EINVAL;

	read_lock_irqsave(&device->cache.lock, flags);
	if (device->cache.lmc_cache) {
		*lmc = device->cache.lmc_cache[port_num - rdma_start_port(device)];
		ret = 0;
	}
	read_unlock_irqrestore(&device->cache.lock, flags);

	return ret;
}
EXPORT_SYMBOL(ib_get_cached_lmc);

static void ib_cache_update(struct ib_device *device,
			    u8                port)
{
	struct ib_port_attr       *tprops = NULL;
	struct ib_pkey_cache      *pkey_cache = NULL, *old_pkey_cache;
	struct ib_gid_cache       *gid_cache = NULL, *old_gid_cache = NULL;
	int                        i;
	int                        ret;
	bool			   use_roce_gid_cache =
					!ib_cache_use_roce_gid_cache(device,
								     port);

	if (port < rdma_start_port(device) || port > rdma_end_port(device))
		return;

	if (!(device->cache.pkey_cache && device->cache.gid_cache &&
	      device->cache.lmc_cache))
		return;

	tprops = kmalloc(sizeof *tprops, GFP_KERNEL);
	if (!tprops)
		return;

	ret = ib_query_port(device, port, tprops);
	if (ret) {
		printk(KERN_WARNING "ib_query_port failed (%d) for %s\n",
		       ret, device->name);
		goto err;
	}

	pkey_cache = kmalloc(sizeof *pkey_cache + tprops->pkey_tbl_len *
			     sizeof *pkey_cache->table, GFP_KERNEL);
	if (!pkey_cache)
		goto err;

	pkey_cache->table_len = tprops->pkey_tbl_len;

	if (!use_roce_gid_cache) {
		gid_cache = kmalloc(sizeof(*gid_cache) + tprops->gid_tbl_len *
			    sizeof(*gid_cache->table), GFP_KERNEL);
		if (!gid_cache)
			goto err;

		gid_cache->table_len = tprops->gid_tbl_len;
	}

	for (i = 0; i < pkey_cache->table_len; ++i) {
		ret = ib_query_pkey(device, port, i, pkey_cache->table + i);
		if (ret) {
			printk(KERN_WARNING "ib_query_pkey failed (%d) for %s (index %d)\n",
			       ret, device->name, i);
			goto err;
		}
	}

	if (!use_roce_gid_cache) {
		for (i = 0;  i < gid_cache->table_len; ++i) {
			ret = ib_query_gid(device, port, i,
					   gid_cache->table + i, NULL);
			if (ret) {
				printk(KERN_WARNING "ib_query_gid failed (%d) for %s (index %d)\n",
				       ret, device->name, i);
				goto err;
			}
		}
	}

	write_lock_irq(&device->cache.lock);

	old_pkey_cache = device->cache.pkey_cache[port - rdma_start_port(device)];
	if (!use_roce_gid_cache)
		old_gid_cache  =
			device->cache.gid_cache[port - rdma_start_port(device)];

	device->cache.pkey_cache[port - rdma_start_port(device)] = pkey_cache;
	if (!use_roce_gid_cache)
		device->cache.gid_cache[port - rdma_start_port(device)] = gid_cache;

	device->cache.lmc_cache[port - rdma_start_port(device)] = tprops->lmc;

	write_unlock_irq(&device->cache.lock);

	kfree(old_pkey_cache);
	kfree(old_gid_cache);
	kfree(tprops);
	return;

err:
	kfree(pkey_cache);
	kfree(gid_cache);
	kfree(tprops);
}

static void ib_cache_task(struct work_struct *_work)
{
	struct ib_update_work *work =
		container_of(_work, struct ib_update_work, work);

	ib_cache_update(work->device, work->port_num);
	kfree(work);
}

static void ib_cache_event(struct ib_event_handler *handler,
			   struct ib_event *event)
{
	struct ib_update_work *work;

	if (event->event == IB_EVENT_PORT_ERR    ||
	    event->event == IB_EVENT_PORT_ACTIVE ||
	    event->event == IB_EVENT_LID_CHANGE  ||
	    event->event == IB_EVENT_PKEY_CHANGE ||
	    event->event == IB_EVENT_SM_CHANGE   ||
	    event->event == IB_EVENT_CLIENT_REREGISTER ||
	    event->event == IB_EVENT_GID_CHANGE) {
		work = kmalloc(sizeof *work, GFP_ATOMIC);
		if (work) {
			INIT_WORK(&work->work, ib_cache_task);
			work->device   = event->device;
			work->port_num = event->element.port_num;
			queue_work(ib_wq, &work->work);
		}
	}
}

static void ib_cache_setup_one(struct ib_device *device)
{
	int p;

	rwlock_init(&device->cache.lock);

	device->cache.pkey_cache =
		kmalloc(sizeof *device->cache.pkey_cache *
			(rdma_end_port(device) - rdma_start_port(device) + 1),
			GFP_KERNEL);
	device->cache.gid_cache =
		kmalloc(sizeof *device->cache.gid_cache *
			(rdma_end_port(device) - rdma_start_port(device) + 1),
			GFP_KERNEL);

	device->cache.lmc_cache = kmalloc(sizeof *device->cache.lmc_cache *
					  (rdma_end_port(device) -
					   rdma_start_port(device) + 1),
					  GFP_KERNEL);

	if (!device->cache.pkey_cache || !device->cache.gid_cache ||
	    !device->cache.lmc_cache) {
		printk(KERN_WARNING "Couldn't allocate cache "
		       "for %s\n", device->name);
		goto err;
	}

	for (p = 0; p <= rdma_end_port(device) - rdma_start_port(device); ++p) {
		device->cache.pkey_cache[p] = NULL;
		device->cache.gid_cache [p] = NULL;
		ib_cache_update(device, p + rdma_start_port(device));
	}

	INIT_IB_EVENT_HANDLER(&device->cache.event_handler,
			      device, ib_cache_event);
	if (ib_register_event_handler(&device->cache.event_handler))
		goto err_cache;

	return;

err_cache:
	for (p = 0; p <= rdma_end_port(device) - rdma_start_port(device); ++p) {
		kfree(device->cache.pkey_cache[p]);
		kfree(device->cache.gid_cache[p]);
	}

err:
	kfree(device->cache.pkey_cache);
	kfree(device->cache.gid_cache);
	kfree(device->cache.lmc_cache);
	device->cache.pkey_cache = NULL;
	device->cache.gid_cache = NULL;
	device->cache.lmc_cache = NULL;
}

static void ib_cache_cleanup_one(struct ib_device *device)
{
	int p;

	if (!(device->cache.pkey_cache && device->cache.gid_cache &&
	      device->cache.lmc_cache))
		return;

	ib_unregister_event_handler(&device->cache.event_handler);
	flush_workqueue(ib_wq);

	for (p = 0; p <= rdma_end_port(device) - rdma_start_port(device); ++p) {
		kfree(device->cache.pkey_cache[p]);
		kfree(device->cache.gid_cache[p]);
	}

	kfree(device->cache.pkey_cache);
	kfree(device->cache.gid_cache);
	kfree(device->cache.lmc_cache);
}

static struct ib_client cache_client = {
	.name   = "cache",
	.add    = ib_cache_setup_one,
	.remove = ib_cache_cleanup_one
};

int __init ib_cache_setup(void)
{
	return ib_register_client(&cache_client);
}

void __exit ib_cache_cleanup(void)
{
	ib_unregister_client(&cache_client);
}
