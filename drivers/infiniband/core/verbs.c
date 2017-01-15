/*
 * Copyright (c) 2004 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2004 Infinicon Corporation.  All rights reserved.
 * Copyright (c) 2004 Intel Corporation.  All rights reserved.
 * Copyright (c) 2004 Topspin Corporation.  All rights reserved.
 * Copyright (c) 2004 Voltaire Corporation.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2005, 2006 Cisco Systems.  All rights reserved.
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

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/export.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/addrconf.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_cache.h>
#include <rdma/ib_addr.h>

#include "core_priv.h"

__attribute_const__ int ib_rate_to_mult(enum ib_rate rate)
{
	switch (rate) {
	case IB_RATE_2_5_GBPS: return  1;
	case IB_RATE_5_GBPS:   return  2;
	case IB_RATE_10_GBPS:  return  4;
	case IB_RATE_20_GBPS:  return  8;
	case IB_RATE_30_GBPS:  return 12;
	case IB_RATE_40_GBPS:  return 16;
	case IB_RATE_60_GBPS:  return 24;
	case IB_RATE_80_GBPS:  return 32;
	case IB_RATE_120_GBPS: return 48;
	default:	       return -1;
	}
}
EXPORT_SYMBOL(ib_rate_to_mult);

__attribute_const__ enum ib_rate mult_to_ib_rate(int mult)
{
	switch (mult) {
	case 1:  return IB_RATE_2_5_GBPS;
	case 2:  return IB_RATE_5_GBPS;
	case 4:  return IB_RATE_10_GBPS;
	case 8:  return IB_RATE_20_GBPS;
	case 12: return IB_RATE_30_GBPS;
	case 16: return IB_RATE_40_GBPS;
	case 24: return IB_RATE_60_GBPS;
	case 32: return IB_RATE_80_GBPS;
	case 48: return IB_RATE_120_GBPS;
	default: return IB_RATE_PORT_CURRENT;
	}
}
EXPORT_SYMBOL(mult_to_ib_rate);

__attribute_const__ int ib_rate_to_mbps(enum ib_rate rate)
{
	switch (rate) {
	case IB_RATE_2_5_GBPS: return 2500;
	case IB_RATE_5_GBPS:   return 5000;
	case IB_RATE_10_GBPS:  return 10000;
	case IB_RATE_20_GBPS:  return 20000;
	case IB_RATE_30_GBPS:  return 30000;
	case IB_RATE_40_GBPS:  return 40000;
	case IB_RATE_60_GBPS:  return 60000;
	case IB_RATE_80_GBPS:  return 80000;
	case IB_RATE_120_GBPS: return 120000;
	case IB_RATE_14_GBPS:  return 14062;
	case IB_RATE_56_GBPS:  return 56250;
	case IB_RATE_112_GBPS: return 112500;
	case IB_RATE_168_GBPS: return 168750;
	case IB_RATE_25_GBPS:  return 25781;
	case IB_RATE_100_GBPS: return 103125;
	case IB_RATE_200_GBPS: return 206250;
	case IB_RATE_300_GBPS: return 309375;
	default:	       return -1;
	}
}
EXPORT_SYMBOL(ib_rate_to_mbps);

__attribute_const__ enum rdma_transport_type
rdma_node_get_transport(enum rdma_node_type node_type)
{
	switch (node_type) {
	case RDMA_NODE_IB_CA:
	case RDMA_NODE_IB_SWITCH:
	case RDMA_NODE_IB_ROUTER:
		return RDMA_TRANSPORT_IB;
	case RDMA_NODE_RNIC:
		return RDMA_TRANSPORT_IWARP;
	case RDMA_NODE_USNIC:
		return RDMA_TRANSPORT_USNIC;
	case RDMA_NODE_USNIC_UDP:
		return RDMA_TRANSPORT_USNIC_UDP;
	case RDMA_EXP_NODE_MIC:
		return RDMA_EXP_TRANSPORT_SCIF;
	default:
		BUG();
		return 0;
	}
}
EXPORT_SYMBOL(rdma_node_get_transport);

enum rdma_link_layer rdma_port_get_link_layer(struct ib_device *device, u8 port_num)
{
	if (device->get_link_layer)
		return device->get_link_layer(device, port_num);

	switch (rdma_node_get_transport(device->node_type)) {
	case RDMA_TRANSPORT_IB:
		return IB_LINK_LAYER_INFINIBAND;
	case RDMA_TRANSPORT_IWARP:
	case RDMA_TRANSPORT_USNIC:
	case RDMA_TRANSPORT_USNIC_UDP:
		return IB_LINK_LAYER_ETHERNET;
	case RDMA_EXP_TRANSPORT_SCIF:
		return IB_EXP_LINK_LAYER_SCIF;
	default:
		return IB_LINK_LAYER_UNSPECIFIED;
	}
}
EXPORT_SYMBOL(rdma_port_get_link_layer);

/* Protection domains */

struct ib_pd *ib_alloc_pd(struct ib_device *device)
{
	struct ib_pd *pd;

	pd = device->alloc_pd(device, NULL, NULL);

	if (!IS_ERR(pd)) {
		pd->device  = device;
		pd->uobject = NULL;
		atomic_set(&pd->usecnt, 0);
	}

	return pd;
}
EXPORT_SYMBOL(ib_alloc_pd);

int ib_dealloc_pd(struct ib_pd *pd)
{
	if (atomic_read(&pd->usecnt))
		return -EBUSY;

	return pd->device->dealloc_pd(pd);
}
EXPORT_SYMBOL(ib_dealloc_pd);

/* Address handles */

struct ib_ah *ib_create_ah(struct ib_pd *pd, struct ib_ah_attr *ah_attr)
{
	struct ib_ah *ah;

	ah = pd->device->create_ah(pd, ah_attr);

	if (!IS_ERR(ah)) {
		ah->device  = pd->device;
		ah->pd      = pd;
		ah->uobject = NULL;
		atomic_inc(&pd->usecnt);
	}

	return ah;
}
EXPORT_SYMBOL(ib_create_ah);

int ib_get_grh_header_version(const void *h)
{
	const struct iphdr *ip4h = (struct iphdr *)(h + 20);
	struct iphdr ip4h_checked;
	const struct ipv6hdr *ip6h = (struct ipv6hdr *)h;

	if (ip6h->version != 6)
		return (ip4h->version == 4) ? 4 : 0;
	/* version may be 6 or 4 */
	if (ip4h->ihl != 5) /* IPv4 header length must be 5 for RR */
		return 6;
	/* Verify checksum.
	   We can't write on scattered buffers so we need to copy to
	   temp buffer.
	 */
	memcpy(&ip4h_checked, ip4h, sizeof(ip4h_checked));
	ip4h_checked.check = 0;
	ip4h_checked.check = ip_fast_csum((u8 *)&ip4h_checked, 5);
	/* if IPv4 header checksum is OK, bellive it */
	if (ip4h->check == ip4h_checked.check)
		return 4;
	return 6;
}
EXPORT_SYMBOL(ib_get_grh_header_version);

static enum rdma_network_type ib_get_net_type_by_grh(struct ib_device *device,
						     u8 port_num,
						     const struct ib_grh *grh)
{
	int grh_version;

	if (rdma_port_get_link_layer(device, port_num) == IB_LINK_LAYER_INFINIBAND)
		return RDMA_NETWORK_IB;

	grh_version = ib_get_grh_header_version(grh);

	if (grh_version == 4)
		return RDMA_NETWORK_IPV4;

	if (grh->next_hdr == IPPROTO_UDP || grh->next_hdr == 0xfe)
		return RDMA_NETWORK_IPV6;

	return RDMA_NETWORK_IB;
}

struct find_gid_index_context {
	u16 vlan_id;
	enum ib_gid_type gid_type;
};

static bool find_gid_index(const union ib_gid *gid,
			   const struct ib_gid_attr *gid_attr,
			   void *context)
{
	struct find_gid_index_context *ctx =
		(struct find_gid_index_context *)context;

	if (ctx->gid_type != gid_attr->gid_type)
		return false;

	if ((!!(ctx->vlan_id != 0xffff) == !is_vlan_dev(gid_attr->ndev)) ||
	    (is_vlan_dev(gid_attr->ndev) &&
	     vlan_dev_vlan_id(gid_attr->ndev) != ctx->vlan_id))
		return false;

	return true;
}

static int get_sgid_index_from_eth(struct ib_device *device, u8 port_num,
				   u16 vlan_id, union ib_gid *sgid,
				   enum ib_gid_type gid_type,
				   u16 *gid_index)
{
	struct find_gid_index_context context = {.vlan_id = vlan_id,
						 .gid_type = gid_type};

	return ib_find_gid_by_filter(device, sgid, port_num, find_gid_index,
				     &context, gid_index);
}

int ib_get_gids_from_grh(struct ib_grh *grh, enum rdma_network_type net_type,
			 union ib_gid *sgid, union ib_gid *dgid)
{
	union rdma_network_hdr *l3grh;
	struct sockaddr_in  src_in;
	struct sockaddr_in  dst_in;
	__be32 src_saddr, dst_saddr;

	if (!sgid || !dgid)
		return -EINVAL;

	if (net_type == RDMA_NETWORK_IPV4) {
		l3grh = (union rdma_network_hdr *)
			((u8 *)grh + 20);
		memcpy(&src_in.sin_addr.s_addr,
		       &l3grh->roce4grh.saddr, 4);
		memcpy(&dst_in.sin_addr.s_addr,
		       &l3grh->roce4grh.daddr, 4);
		src_saddr = src_in.sin_addr.s_addr;
		dst_saddr = dst_in.sin_addr.s_addr;
		ipv6_addr_set_v4mapped(src_saddr,
				       (struct in6_addr *)sgid);
		ipv6_addr_set_v4mapped(dst_saddr,
				       (struct in6_addr *)dgid);
		return 0;
	} else if (net_type == RDMA_NETWORK_IPV6 ||
		   net_type == RDMA_NETWORK_IB) {
		*dgid = grh->dgid;
		*sgid = grh->sgid;
		return 0;
	} else
		return -EINVAL;
}
EXPORT_SYMBOL(ib_get_gids_from_grh);

int ib_init_ah_from_wc(struct ib_device *device, u8 port_num, struct ib_wc *wc,
		       struct ib_grh *grh, struct ib_ah_attr *ah_attr)
{
	u32 flow_class;
	u16 gid_index;
	int ret;
	int is_eth = (rdma_port_get_link_layer(device, port_num) ==
			IB_LINK_LAYER_ETHERNET);
	enum rdma_network_type net_type = RDMA_NETWORK_IB;
	enum ib_gid_type gid_type = IB_GID_TYPE_IB;
	union ib_gid dgid;
	union ib_gid sgid;

	memset(ah_attr, 0, sizeof *ah_attr);
	if (is_eth) {
		if (wc->wc_flags & IB_WC_WITH_NETWORK_HDR_TYPE)
			net_type = wc->network_hdr_type;
		else
			net_type = ib_get_net_type_by_grh(device, port_num, grh);
		gid_type = ib_network_to_gid_type(net_type, grh);
	}
	ret = ib_get_gids_from_grh(grh, net_type, &sgid, &dgid);
	if (ret)
		return ret;

	if (is_eth) {
		u16 vlan_id = wc->wc_flags & IB_WC_WITH_VLAN ?
				wc->vlan_id : 0xffff;

		if (!(wc->wc_flags & IB_WC_GRH))
			return -EPROTOTYPE;

		if (!(wc->wc_flags & IB_WC_WITH_SMAC) ||
		    !(wc->wc_flags & IB_WC_WITH_VLAN)) {
			ret = rdma_addr_find_dmac_by_grh(&dgid, &sgid,
							 ah_attr->dmac,
							 wc->wc_flags & IB_WC_WITH_VLAN ?
							 NULL : &vlan_id,
							 0);
			if (ret)
				return ret;
		}

		ret = get_sgid_index_from_eth(device, port_num, vlan_id,
					      &dgid, gid_type, &gid_index);
		if (ret)
			return ret;

		if (wc->wc_flags & IB_WC_WITH_SMAC)
			memcpy(ah_attr->dmac, wc->smac, ETH_ALEN);
	}

	ah_attr->dlid = wc->slid;
	ah_attr->sl = wc->sl;
	ah_attr->src_path_bits = wc->dlid_path_bits;
	ah_attr->port_num = port_num;

	if (wc->wc_flags & IB_WC_GRH) {
		ah_attr->ah_flags = IB_AH_GRH;
		ah_attr->grh.dgid = sgid;

		if (!is_eth) {
			if (dgid.global.interface_id != cpu_to_be64(IB_SA_WELL_KNOWN_GUID)) {
				ret = ib_find_cached_gid_by_port(device, &dgid,
								 IB_GID_TYPE_IB,
								 port_num, NULL, 0,
								 &gid_index);
				if (ret)
					return ret;
			} else {
				gid_index = 0;
			}
		}

		ah_attr->grh.sgid_index = (u8) gid_index;
		flow_class = be32_to_cpu(grh->version_tclass_flow);
		ah_attr->grh.flow_label = flow_class & 0xFFFFF;
		ah_attr->grh.hop_limit = 0xFF;
		ah_attr->grh.traffic_class = (flow_class >> 20) & 0xFF;
	}
	return 0;
}
EXPORT_SYMBOL(ib_init_ah_from_wc);

struct ib_ah *ib_create_ah_from_wc(struct ib_pd *pd, struct ib_wc *wc,
				   struct ib_grh *grh, u8 port_num)
{
	struct ib_ah_attr ah_attr;
	int ret;

	ret = ib_init_ah_from_wc(pd->device, port_num, wc, grh, &ah_attr);
	if (ret)
		return ERR_PTR(ret);

	return ib_create_ah(pd, &ah_attr);
}
EXPORT_SYMBOL(ib_create_ah_from_wc);

int ib_modify_ah(struct ib_ah *ah, struct ib_ah_attr *ah_attr)
{
	return ah->device->modify_ah ?
		ah->device->modify_ah(ah, ah_attr) :
		-ENOSYS;
}
EXPORT_SYMBOL(ib_modify_ah);

int ib_query_ah(struct ib_ah *ah, struct ib_ah_attr *ah_attr)
{
	return ah->device->query_ah ?
		ah->device->query_ah(ah, ah_attr) :
		-ENOSYS;
}
EXPORT_SYMBOL(ib_query_ah);

int ib_query_values(struct ib_device *device,
		    int q_values, struct ib_device_values *values)
{
	return device->query_values ?
		device->query_values(device, q_values, values) :
		-ENOSYS;
}
EXPORT_SYMBOL(ib_query_values);

int ib_destroy_ah(struct ib_ah *ah)
{
	struct ib_pd *pd;
	int ret;

	pd = ah->pd;
	ret = ah->device->destroy_ah(ah);
	if (!ret)
		atomic_dec(&pd->usecnt);

	return ret;
}
EXPORT_SYMBOL(ib_destroy_ah);

/* Shared receive queues */

struct ib_srq *ib_create_srq(struct ib_pd *pd,
			     struct ib_srq_init_attr *srq_init_attr)
{
	struct ib_srq *srq;

	if (!pd->device->create_srq)
		return ERR_PTR(-ENOSYS);

	srq = pd->device->create_srq(pd, srq_init_attr, NULL);

	if (!IS_ERR(srq)) {
		srq->device    	   = pd->device;
		srq->pd        	   = pd;
		srq->uobject       = NULL;
		srq->event_handler = srq_init_attr->event_handler;
		srq->srq_context   = srq_init_attr->srq_context;
		srq->srq_type      = srq_init_attr->srq_type;
		if (srq->srq_type == IB_SRQT_XRC) {
			srq->ext.xrc.xrcd = srq_init_attr->ext.xrc.xrcd;
			srq->ext.xrc.cq   = srq_init_attr->ext.xrc.cq;
			atomic_inc(&srq->ext.xrc.xrcd->usecnt);
			atomic_inc(&srq->ext.xrc.cq->usecnt);
		}
		atomic_inc(&pd->usecnt);
		atomic_set(&srq->usecnt, 0);
	}

	return srq;
}
EXPORT_SYMBOL(ib_create_srq);

int ib_modify_srq(struct ib_srq *srq,
		  struct ib_srq_attr *srq_attr,
		  enum ib_srq_attr_mask srq_attr_mask)
{
	return srq->device->modify_srq ?
		srq->device->modify_srq(srq, srq_attr, srq_attr_mask, NULL) :
		-ENOSYS;
}
EXPORT_SYMBOL(ib_modify_srq);

int ib_query_srq(struct ib_srq *srq,
		 struct ib_srq_attr *srq_attr)
{
	return srq->device->query_srq ?
		srq->device->query_srq(srq, srq_attr) : -ENOSYS;
}
EXPORT_SYMBOL(ib_query_srq);

int ib_destroy_srq(struct ib_srq *srq)
{
	struct ib_pd *pd;
	enum ib_srq_type srq_type;
	struct ib_xrcd *uninitialized_var(xrcd);
	struct ib_cq *uninitialized_var(cq);
	int ret;

	if (atomic_read(&srq->usecnt))
		return -EBUSY;

	pd = srq->pd;
	srq_type = srq->srq_type;
	if (srq_type == IB_SRQT_XRC) {
		xrcd = srq->ext.xrc.xrcd;
		cq = srq->ext.xrc.cq;
	}

	ret = srq->device->destroy_srq(srq);
	if (!ret) {
		atomic_dec(&pd->usecnt);
		if (srq_type == IB_SRQT_XRC) {
			atomic_dec(&xrcd->usecnt);
			atomic_dec(&cq->usecnt);
		}
	}

	return ret;
}
EXPORT_SYMBOL(ib_destroy_srq);

/* Queue pairs */

static void __ib_shared_qp_event_handler(struct ib_event *event, void *context)
{
	struct ib_qp *qp = context;
	unsigned long flags;

	spin_lock_irqsave(&qp->device->event_handler_lock, flags);
	list_for_each_entry(event->element.qp, &qp->open_list, open_list)
		if (event->element.qp->event_handler)
			event->element.qp->event_handler(event, event->element.qp->qp_context);
	spin_unlock_irqrestore(&qp->device->event_handler_lock, flags);
}

static void __ib_insert_xrcd_qp(struct ib_xrcd *xrcd, struct ib_qp *qp)
{
	mutex_lock(&xrcd->tgt_qp_mutex);
	list_add(&qp->xrcd_list, &xrcd->tgt_qp_list);
	mutex_unlock(&xrcd->tgt_qp_mutex);
}

static struct ib_qp *__ib_open_qp(struct ib_qp *real_qp,
				  void (*event_handler)(struct ib_event *, void *),
				  void *qp_context)
{
	struct ib_qp *qp;
	unsigned long flags;

	qp = kzalloc(sizeof *qp, GFP_KERNEL);
	if (!qp)
		return ERR_PTR(-ENOMEM);

	qp->real_qp = real_qp;
	atomic_inc(&real_qp->usecnt);
	qp->device = real_qp->device;
	qp->event_handler = event_handler;
	qp->qp_context = qp_context;
	qp->qp_num = real_qp->qp_num;
	qp->qp_type = real_qp->qp_type;

	spin_lock_irqsave(&real_qp->device->event_handler_lock, flags);
	list_add(&qp->open_list, &real_qp->open_list);
	spin_unlock_irqrestore(&real_qp->device->event_handler_lock, flags);

	return qp;
}

struct ib_qp *ib_open_qp(struct ib_xrcd *xrcd,
			 struct ib_qp_open_attr *qp_open_attr)
{
	struct ib_qp *qp, *real_qp;

	if (qp_open_attr->qp_type != IB_QPT_XRC_TGT)
		return ERR_PTR(-EINVAL);

	qp = ERR_PTR(-EINVAL);
	mutex_lock(&xrcd->tgt_qp_mutex);
	list_for_each_entry(real_qp, &xrcd->tgt_qp_list, xrcd_list) {
		if (real_qp->qp_num == qp_open_attr->qp_num) {
			qp = __ib_open_qp(real_qp, qp_open_attr->event_handler,
					  qp_open_attr->qp_context);
			break;
		}
	}
	mutex_unlock(&xrcd->tgt_qp_mutex);
	return qp;
}
EXPORT_SYMBOL(ib_open_qp);

static int ib_qpg_verify(struct ib_qp_init_attr *qp_init_attr)
{
	/* RSS/TSS QP group basic validation */
	struct ib_qp *parent;
	struct ib_qpg_init_attrib *attr;
	struct ib_qpg_attr *pattr;

	switch (qp_init_attr->qpg_type) {
	case IB_QPG_PARENT:
		attr = &qp_init_attr->parent_attrib;
		if (attr->tss_child_count == 1)
			return -EINVAL; /* doesn't make sense */
		if (attr->rss_child_count == 1)
			return -EINVAL; /* doesn't make sense */
		if ((attr->tss_child_count == 0) &&
		    (attr->rss_child_count == 0))
			/* should be called with IP_QPG_NONE */
			return -EINVAL;
		break;
	case IB_QPG_CHILD_RX:
		parent = qp_init_attr->qpg_parent;
		if (!parent || parent->qpg_type != IB_QPG_PARENT)
			return -EINVAL;
		pattr = &parent->qpg_attr.parent_attr;
		if (!pattr->rss_child_count)
			return -EINVAL;
		if (atomic_read(&pattr->rsscnt) >= pattr->rss_child_count)
			return -EINVAL;
		break;
	case IB_QPG_CHILD_TX:
		parent = qp_init_attr->qpg_parent;
		if (!parent || parent->qpg_type != IB_QPG_PARENT)
			return -EINVAL;
		pattr = &parent->qpg_attr.parent_attr;
		if (!pattr->tss_child_count)
			return -EINVAL;
		if (atomic_read(&pattr->tsscnt) >= pattr->tss_child_count)
			return -EINVAL;
		break;
	default:
		break;
	}

	return 0;
}

static void ib_init_qpg(struct ib_qp_init_attr *qp_init_attr, struct ib_qp *qp)
{
	struct ib_qp *parent;
	struct ib_qpg_init_attrib *attr;
	struct ib_qpg_attr *pattr;

	qp->qpg_type = qp_init_attr->qpg_type;

	/* qp was created without an error parmaters are O.K. */
	switch (qp_init_attr->qpg_type) {
	case IB_QPG_PARENT:
		attr = &qp_init_attr->parent_attrib;
		pattr = &qp->qpg_attr.parent_attr;
		pattr->rss_child_count = attr->rss_child_count;
		pattr->tss_child_count = attr->tss_child_count;
		atomic_set(&pattr->rsscnt, 0);
		atomic_set(&pattr->tsscnt, 0);
		break;
	case IB_QPG_CHILD_RX:
		parent = qp_init_attr->qpg_parent;
		qp->qpg_attr.parent = parent;
		/* update parent's counter */
		pattr = &parent->qpg_attr.parent_attr;
		atomic_inc(&pattr->rsscnt);
		break;
	case IB_QPG_CHILD_TX:
		parent = qp_init_attr->qpg_parent;
		qp->qpg_attr.parent = parent;
		/* update parent's counter */
		pattr = &parent->qpg_attr.parent_attr;
		atomic_inc(&pattr->tsscnt);
		break;
	default:
		break;
	}
}

struct ib_qp *ib_create_qp(struct ib_pd *pd,
			   struct ib_qp_init_attr *qp_init_attr)
{
	struct ib_qp *qp, *real_qp;
	struct ib_device *device;

	if (ib_qpg_verify(qp_init_attr))
		return ERR_PTR(-EINVAL);

	device = pd ? pd->device : qp_init_attr->xrcd->device;
	qp = device->create_qp(pd, qp_init_attr, NULL);

	if (!IS_ERR(qp)) {
		qp->device     = device;
		qp->real_qp    = qp;
		qp->uobject    = NULL;
		qp->qp_type    = qp_init_attr->qp_type;

		atomic_set(&qp->usecnt, 0);
		if (qp_init_attr->qp_type == IB_QPT_XRC_TGT) {
			qp->event_handler = __ib_shared_qp_event_handler;
			qp->qp_context = qp;
			qp->pd = NULL;
			qp->send_cq = qp->recv_cq = NULL;
			qp->srq = NULL;
			qp->xrcd = qp_init_attr->xrcd;
			atomic_inc(&qp_init_attr->xrcd->usecnt);
			INIT_LIST_HEAD(&qp->open_list);

			real_qp = qp;
			qp = __ib_open_qp(real_qp, qp_init_attr->event_handler,
					  qp_init_attr->qp_context);
			if (!IS_ERR(qp))
				__ib_insert_xrcd_qp(qp_init_attr->xrcd, real_qp);
			else
				real_qp->device->destroy_qp(real_qp);
		} else {
			qp->event_handler = qp_init_attr->event_handler;
			qp->qp_context = qp_init_attr->qp_context;
			if (qp_init_attr->qp_type == IB_QPT_XRC_INI) {
				qp->recv_cq = NULL;
				qp->srq = NULL;
			} else {
				qp->recv_cq = qp_init_attr->recv_cq;
				atomic_inc(&qp_init_attr->recv_cq->usecnt);
				qp->srq = qp_init_attr->srq;
				if (qp->srq)
					atomic_inc(&qp_init_attr->srq->usecnt);
			}

			qp->pd	    = pd;
			qp->send_cq = qp_init_attr->send_cq;
			qp->xrcd    = NULL;

			atomic_inc(&pd->usecnt);
			atomic_inc(&qp_init_attr->send_cq->usecnt);
		}

		ib_init_qpg(qp_init_attr, qp);
	}

	return qp;
}
EXPORT_SYMBOL(ib_create_qp);

static const struct {
	int			valid;
	enum ib_qp_attr_mask	req_param[IB_QPT_MAX];
	enum ib_qp_attr_mask	opt_param[IB_QPT_MAX];
} qp_state_table[IB_QPS_ERR + 1][IB_QPS_ERR + 1] = {
	[IB_QPS_RESET] = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_INIT]  = {
			.valid = 1,
			.req_param = {
				[IB_QPT_UD]  = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_QKEY),
				[IB_QPT_RAW_PACKET] = IB_QP_PORT,
				[IB_QPT_UC]  = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_RC]  = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_ACCESS_FLAGS),
				[IB_EXP_QPT_DC_INI]  = (IB_QP_PKEY_INDEX	|
							IB_QP_PORT		|
							IB_QP_DC_KEY),
				[IB_QPT_XRC_INI] = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_XRC_TGT] = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_SMI] = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
			},
			.opt_param = {
				[IB_QPT_UD]  = (IB_QP_GROUP_RSS			|
						IB_QP_FLOW_ENTROPY),
				[IB_QPT_RAW_PACKET] = IB_QP_GROUP_RSS,
				[IB_QPT_RC]  = IB_QP_FLOW_ENTROPY,
				[IB_QPT_UC]  = IB_QP_FLOW_ENTROPY,
				[IB_QPT_XRC_INI]  = IB_QP_FLOW_ENTROPY,
				[IB_QPT_XRC_TGT]  = IB_QP_FLOW_ENTROPY,
			}
		},
	},
	[IB_QPS_INIT]  = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 },
		[IB_QPS_INIT]  = {
			.valid = 1,
			.opt_param = {
				[IB_QPT_UD]  = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_QKEY),
				[IB_QPT_UC]  = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_RC]  = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_ACCESS_FLAGS),
				[IB_EXP_QPT_DC_INI]  = (IB_QP_PKEY_INDEX	|
							IB_QP_PORT		|
							IB_QP_DC_KEY),
				[IB_QPT_XRC_INI] = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_XRC_TGT] = (IB_QP_PKEY_INDEX		|
						IB_QP_PORT			|
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_SMI] = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
			}
		},
		[IB_QPS_RTR]   = {
			.valid = 1,
			.req_param = {
				[IB_QPT_UC]  = (IB_QP_AV			|
						IB_QP_PATH_MTU			|
						IB_QP_DEST_QPN			|
						IB_QP_RQ_PSN),
				[IB_QPT_RC]  = (IB_QP_AV			|
						IB_QP_PATH_MTU			|
						IB_QP_DEST_QPN			|
						IB_QP_RQ_PSN			|
						IB_QP_MAX_DEST_RD_ATOMIC	|
						IB_QP_MIN_RNR_TIMER),
				[IB_EXP_QPT_DC_INI]  = (IB_QP_AV		|
							IB_QP_PATH_MTU),
				[IB_QPT_XRC_INI] = (IB_QP_AV			|
						IB_QP_PATH_MTU			|
						IB_QP_DEST_QPN			|
						IB_QP_RQ_PSN),
				[IB_QPT_XRC_TGT] = (IB_QP_AV			|
						IB_QP_PATH_MTU			|
						IB_QP_DEST_QPN			|
						IB_QP_RQ_PSN			|
						IB_QP_MAX_DEST_RD_ATOMIC	|
						IB_QP_MIN_RNR_TIMER),
			},
			.opt_param = {
				 [IB_QPT_UD]  = (IB_QP_PKEY_INDEX		|
						 IB_QP_QKEY),
				 [IB_QPT_UC]  = (IB_QP_ALT_PATH			|
						 IB_QP_ACCESS_FLAGS		|
						 IB_QP_PKEY_INDEX),
				 [IB_QPT_RC]  = (IB_QP_ALT_PATH			|
						 IB_QP_ACCESS_FLAGS		|
						 IB_QP_PKEY_INDEX),
				 [IB_EXP_QPT_DC_INI]  = (IB_QP_PKEY_INDEX	|
							 IB_QP_DC_KEY),
				 [IB_QPT_XRC_INI] = (IB_QP_ALT_PATH		|
						 IB_QP_ACCESS_FLAGS		|
						 IB_QP_PKEY_INDEX),
				 [IB_QPT_XRC_TGT] = (IB_QP_ALT_PATH		|
						 IB_QP_ACCESS_FLAGS		|
						 IB_QP_PKEY_INDEX),
				 [IB_QPT_SMI] = (IB_QP_PKEY_INDEX		|
						 IB_QP_QKEY),
				 [IB_QPT_GSI] = (IB_QP_PKEY_INDEX		|
						 IB_QP_QKEY),
			 },
		},
	},
	[IB_QPS_RTR]   = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 },
		[IB_QPS_RTS]   = {
			.valid = 1,
			.req_param = {
				[IB_QPT_UD]  = IB_QP_SQ_PSN,
				[IB_QPT_UC]  = IB_QP_SQ_PSN,
				[IB_QPT_RC]  = (IB_QP_TIMEOUT			|
						IB_QP_RETRY_CNT			|
						IB_QP_RNR_RETRY			|
						IB_QP_SQ_PSN			|
						IB_QP_MAX_QP_RD_ATOMIC),
				[IB_EXP_QPT_DC_INI]  = (IB_QP_TIMEOUT		|
							IB_QP_RETRY_CNT		|
							IB_QP_RNR_RETRY		|
							IB_QP_MAX_QP_RD_ATOMIC),
				[IB_QPT_XRC_INI] = (IB_QP_TIMEOUT		|
						IB_QP_RETRY_CNT			|
						IB_QP_RNR_RETRY			|
						IB_QP_SQ_PSN			|
						IB_QP_MAX_QP_RD_ATOMIC),
				[IB_QPT_XRC_TGT] = (IB_QP_TIMEOUT		|
						IB_QP_SQ_PSN),
				[IB_QPT_SMI] = IB_QP_SQ_PSN,
				[IB_QPT_GSI] = IB_QP_SQ_PSN,
			},
			.opt_param = {
				 [IB_QPT_UD]  = (IB_QP_CUR_STATE		|
						 IB_QP_QKEY),
				 [IB_QPT_UC]  = (IB_QP_CUR_STATE		|
						 IB_QP_ALT_PATH			|
						 IB_QP_ACCESS_FLAGS		|
						 IB_QP_PATH_MIG_STATE),
				 [IB_QPT_RC]  = (IB_QP_CUR_STATE		|
						 IB_QP_ALT_PATH			|
						 IB_QP_ACCESS_FLAGS		|
						 IB_QP_MIN_RNR_TIMER		|
						 IB_QP_PATH_MIG_STATE),
				 [IB_EXP_QPT_DC_INI] = (IB_QP_CUR_STATE		|
							IB_QP_ALT_PATH		|
							IB_QP_MIN_RNR_TIMER	|
							IB_QP_PATH_MIG_STATE),
				 [IB_QPT_XRC_INI] = (IB_QP_CUR_STATE		|
						 IB_QP_ALT_PATH			|
						 IB_QP_ACCESS_FLAGS		|
						 IB_QP_PATH_MIG_STATE),
				 [IB_QPT_XRC_TGT] = (IB_QP_CUR_STATE		|
						 IB_QP_ALT_PATH			|
						 IB_QP_ACCESS_FLAGS		|
						 IB_QP_MIN_RNR_TIMER		|
						 IB_QP_PATH_MIG_STATE),
				 [IB_QPT_SMI] = (IB_QP_CUR_STATE		|
						 IB_QP_QKEY),
				 [IB_QPT_GSI] = (IB_QP_CUR_STATE		|
						 IB_QP_QKEY),
				 [IB_QPT_RAW_PACKET] = IB_QP_RATE_LIMIT,
			 }
		}
	},
	[IB_QPS_RTS]   = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 },
		[IB_QPS_RTS]   = {
			.valid = 1,
			.opt_param = {
				[IB_QPT_UD]  = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_UC]  = (IB_QP_CUR_STATE			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_ALT_PATH			|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_RC]  = (IB_QP_CUR_STATE			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_ALT_PATH			|
						IB_QP_PATH_MIG_STATE		|
						IB_QP_MIN_RNR_TIMER),
				[IB_EXP_QPT_DC_INI]  = (IB_QP_CUR_STATE		|
							IB_QP_ALT_PATH		|
							IB_QP_PATH_MIG_STATE	|
							IB_QP_MIN_RNR_TIMER),
				[IB_QPT_XRC_INI] = (IB_QP_CUR_STATE		|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_ALT_PATH			|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_XRC_TGT] = (IB_QP_CUR_STATE		|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_ALT_PATH			|
						IB_QP_PATH_MIG_STATE		|
						IB_QP_MIN_RNR_TIMER),
				[IB_QPT_SMI] = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_RAW_PACKET] = IB_QP_RATE_LIMIT,
			}
		},
		[IB_QPS_SQD]   = {
			.valid = 1,
			.opt_param = {
				[IB_QPT_UD]  = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_UC]  = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_RC]  = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_XRC_INI] = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_XRC_TGT] = IB_QP_EN_SQD_ASYNC_NOTIFY, /* ??? */
				[IB_QPT_SMI] = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_GSI] = IB_QP_EN_SQD_ASYNC_NOTIFY
			}
		},
	},
	[IB_QPS_SQD]   = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 },
		[IB_QPS_RTS]   = {
			.valid = 1,
			.opt_param = {
				[IB_QPT_UD]  = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_UC]  = (IB_QP_CUR_STATE			|
						IB_QP_ALT_PATH			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_RC]  = (IB_QP_CUR_STATE			|
						IB_QP_ALT_PATH			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_MIN_RNR_TIMER		|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_XRC_INI] = (IB_QP_CUR_STATE		|
						IB_QP_ALT_PATH			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_XRC_TGT] = (IB_QP_CUR_STATE		|
						IB_QP_ALT_PATH			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_MIN_RNR_TIMER		|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_SMI] = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
			}
		},
		[IB_QPS_SQD]   = {
			.valid = 1,
			.opt_param = {
				[IB_QPT_UD]  = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
				[IB_QPT_UC]  = (IB_QP_AV			|
						IB_QP_ALT_PATH			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_PKEY_INDEX		|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_RC]  = (IB_QP_PORT			|
						IB_QP_AV			|
						IB_QP_TIMEOUT			|
						IB_QP_RETRY_CNT			|
						IB_QP_RNR_RETRY			|
						IB_QP_MAX_QP_RD_ATOMIC		|
						IB_QP_MAX_DEST_RD_ATOMIC	|
						IB_QP_ALT_PATH			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_PKEY_INDEX		|
						IB_QP_MIN_RNR_TIMER		|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_XRC_INI] = (IB_QP_PORT			|
						IB_QP_AV			|
						IB_QP_TIMEOUT			|
						IB_QP_RETRY_CNT			|
						IB_QP_RNR_RETRY			|
						IB_QP_MAX_QP_RD_ATOMIC		|
						IB_QP_ALT_PATH			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_PKEY_INDEX		|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_XRC_TGT] = (IB_QP_PORT			|
						IB_QP_AV			|
						IB_QP_TIMEOUT			|
						IB_QP_MAX_DEST_RD_ATOMIC	|
						IB_QP_ALT_PATH			|
						IB_QP_ACCESS_FLAGS		|
						IB_QP_PKEY_INDEX		|
						IB_QP_MIN_RNR_TIMER		|
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_SMI] = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_PKEY_INDEX		|
						IB_QP_QKEY),
			}
		}
	},
	[IB_QPS_SQE]   = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 },
		[IB_QPS_RTS]   = {
			.valid = 1,
			.opt_param = {
				[IB_QPT_UD]  = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_UC]  = (IB_QP_CUR_STATE			|
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_SMI] = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_CUR_STATE			|
						IB_QP_QKEY),
			}
		}
	},
	[IB_QPS_ERR] = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 }
	}
};

int ib_modify_qp_is_ok(enum ib_qp_state cur_state, enum ib_qp_state next_state,
		       enum ib_qp_type type, enum ib_qp_attr_mask mask,
		       enum rdma_link_layer ll)
{
	enum ib_qp_attr_mask req_param, opt_param;

	if (cur_state  < 0 || cur_state  > IB_QPS_ERR ||
	    next_state < 0 || next_state > IB_QPS_ERR)
		return 0;

	if (mask & IB_QP_CUR_STATE  &&
	    cur_state != IB_QPS_RTR && cur_state != IB_QPS_RTS &&
	    cur_state != IB_QPS_SQD && cur_state != IB_QPS_SQE)
		return 0;

	if (!qp_state_table[cur_state][next_state].valid)
		return 0;

	req_param = qp_state_table[cur_state][next_state].req_param[type];
	opt_param = qp_state_table[cur_state][next_state].opt_param[type];

	if ((mask & req_param) != req_param)
		return 0;

	if (mask & ~(req_param | opt_param | IB_QP_STATE))
		return 0;

	return 1;
}
EXPORT_SYMBOL(ib_modify_qp_is_ok);

int ib_resolve_eth_dmac(struct ib_qp *qp,
			struct ib_qp_attr *qp_attr, int *qp_attr_mask)
{
	int           ret = 0;
	u8            start_port = qp->device->node_type == RDMA_NODE_IB_SWITCH ? 0 : 1;

	if ((*qp_attr_mask & IB_QP_AV)  &&
	    (qp_attr->ah_attr.port_num >= start_port) &&
	    (qp_attr->ah_attr.port_num < start_port + qp->device->phys_port_cnt) &&
	    (rdma_port_get_link_layer(qp->device, qp_attr->ah_attr.port_num) ==
	     IB_LINK_LAYER_ETHERNET)) {
		if (rdma_link_local_addr((struct in6_addr *)qp_attr->ah_attr.grh.dgid.raw)) {
			rdma_get_ll_mac((struct in6_addr *)qp_attr->ah_attr.grh.dgid.raw,
					qp_attr->ah_attr.dmac);
		} else {
			union ib_gid		sgid;
			struct ib_gid_attr	sgid_attr;
			int			ifindex;

			rcu_read_lock();
			ret = ib_query_gid(qp->device,
					   qp_attr->ah_attr.port_num,
					   qp_attr->ah_attr.grh.sgid_index,
					   &sgid, &sgid_attr);

			if (ret || !sgid_attr.ndev) {
				if (!ret)
					ret = -ENXIO;
				rcu_read_unlock();
				goto out;
			}
			if (sgid_attr.gid_type == IB_GID_TYPE_ROCE_V2 ||
			    sgid_attr.gid_type == IB_GID_TYPE_ROCE_V1_5)
				qp_attr->ah_attr.grh.hop_limit =
							IPV6_DEFAULT_HOPLIMIT;

			dev_hold(sgid_attr.ndev);
			ifindex = sgid_attr.ndev->ifindex;

			rcu_read_unlock();

			ret = rdma_addr_find_dmac_by_grh(&sgid,
							 &qp_attr->ah_attr.grh.dgid,
							 qp_attr->ah_attr.dmac,
							 NULL, ifindex);

			dev_put(sgid_attr.ndev);
		}
	}
out:
	return ret;
}
EXPORT_SYMBOL(ib_resolve_eth_dmac);


int ib_modify_qp(struct ib_qp *qp,
		 struct ib_qp_attr *qp_attr,
		 int qp_attr_mask)
{
	int ret;

	if (qp->qpg_type == IB_QPG_PARENT) {
		struct ib_qpg_attr *pattr = &qp->qpg_attr.parent_attr;
		if (atomic_read(&pattr->rsscnt) < pattr->rss_child_count)
			return -EINVAL;
		if (atomic_read(&pattr->tsscnt) < pattr->tss_child_count)
			return -EINVAL;
	}

	ret = ib_resolve_eth_dmac(qp, qp_attr, &qp_attr_mask);

	if (ret)
		return ret;

	return qp->device->modify_qp(qp->real_qp, qp_attr, qp_attr_mask, NULL);
}
EXPORT_SYMBOL(ib_modify_qp);

int ib_query_qp(struct ib_qp *qp,
		struct ib_qp_attr *qp_attr,
		int qp_attr_mask,
		struct ib_qp_init_attr *qp_init_attr)
{
	return qp->device->query_qp ?
		qp->device->query_qp(qp->real_qp, qp_attr, qp_attr_mask, qp_init_attr) :
		-ENOSYS;
}
EXPORT_SYMBOL(ib_query_qp);

int ib_close_qp(struct ib_qp *qp)
{
	struct ib_qp *real_qp;
	unsigned long flags;

	real_qp = qp->real_qp;
	if (real_qp == qp)
		return -EINVAL;

	spin_lock_irqsave(&real_qp->device->event_handler_lock, flags);
	list_del(&qp->open_list);
	spin_unlock_irqrestore(&real_qp->device->event_handler_lock, flags);

	atomic_dec(&real_qp->usecnt);
	kfree(qp);

	return 0;
}
EXPORT_SYMBOL(ib_close_qp);

static int __ib_destroy_shared_qp(struct ib_qp *qp)
{
	struct ib_xrcd *xrcd;
	struct ib_qp *real_qp;
	int ret;

	real_qp = qp->real_qp;
	xrcd = real_qp->xrcd;

	mutex_lock(&xrcd->tgt_qp_mutex);
	ib_close_qp(qp);
	if (atomic_read(&real_qp->usecnt) == 0)
		list_del(&real_qp->xrcd_list);
	else
		real_qp = NULL;
	mutex_unlock(&xrcd->tgt_qp_mutex);

	if (real_qp) {
		ret = ib_destroy_qp(real_qp);
		if (!ret)
			atomic_dec(&xrcd->usecnt);
		else
			__ib_insert_xrcd_qp(xrcd, real_qp);
	}

	return 0;
}

int ib_destroy_qp(struct ib_qp *qp)
{
	struct ib_pd *pd;
	struct ib_cq *scq, *rcq;
	struct ib_srq *srq;
	struct ib_rwq_ind_table *ind_tbl;
	struct ib_qpg_attr *pattr = NULL;
	enum ib_qpg_type qpg_type;
	int ret;

	if (atomic_read(&qp->usecnt))
		return -EBUSY;

	if (qp->qpg_type == IB_QPG_PARENT) {
		/* All children should have been deleted by now */
		pattr = &qp->qpg_attr.parent_attr;
		if (atomic_read(&pattr->rsscnt))
			return -EINVAL;
		if (atomic_read(&pattr->tsscnt))
			return -EINVAL;
	}

	if (qp->real_qp != qp)
		return __ib_destroy_shared_qp(qp);

	pd   = qp->pd;
	scq  = qp->send_cq;
	rcq  = qp->recv_cq;
	srq  = qp->srq;
	ind_tbl = qp->rwq_ind_tbl;
	qpg_type = qp->qpg_type;
	if (qpg_type == IB_QPG_CHILD_RX ||
	    qpg_type == IB_QPG_CHILD_TX) {
		struct ib_qp *pqp = qp->qpg_attr.parent;

		pattr = &pqp->qpg_attr.parent_attr;
	}

	ret = qp->device->destroy_qp(qp);
	if (!ret) {
		if (pd)
			atomic_dec(&pd->usecnt);
		if (scq)
			atomic_dec(&scq->usecnt);
		if (rcq)
			atomic_dec(&rcq->usecnt);
		if (srq)
			atomic_dec(&srq->usecnt);
		if (ind_tbl)
			atomic_dec(&ind_tbl->usecnt);

		/* decrement parent's counters */
		if (qpg_type == IB_QPG_CHILD_RX)
			atomic_dec(&pattr->rsscnt);
		else if (qpg_type == IB_QPG_CHILD_TX)
			atomic_dec(&pattr->tsscnt);
	}

	return ret;
}
EXPORT_SYMBOL(ib_destroy_qp);

/* Completion queues */

struct ib_cq *ib_create_cq(struct ib_device *device,
			   ib_comp_handler comp_handler,
			   void (*event_handler)(struct ib_event *, void *),
			   void *cq_context, int cqe, int comp_vector)
{
	struct ib_cq *cq;
	struct ib_cq_init_attr attr = {
		.cqe		= cqe,
		.comp_vector	= comp_vector,
		.flags		= 0,
	};

	cq = device->create_cq(device, &attr, NULL, NULL);

	if (!IS_ERR(cq)) {
		cq->device        = device;
		cq->uobject       = NULL;
		cq->comp_handler  = comp_handler;
		cq->event_handler = event_handler;
		cq->cq_context    = cq_context;
		atomic_set(&cq->usecnt, 0);
	}

	return cq;
}
EXPORT_SYMBOL(ib_create_cq);

int ib_modify_cq(struct ib_cq *cq,
		 struct ib_cq_attr *cq_attr,
		 int cq_attr_mask)
{
	return cq->device->modify_cq ?
		cq->device->modify_cq(cq, cq_attr, cq_attr_mask) : -ENOSYS;
}
EXPORT_SYMBOL(ib_modify_cq);

int ib_destroy_cq(struct ib_cq *cq)
{
	if (atomic_read(&cq->usecnt))
		return -EBUSY;

	return cq->device->destroy_cq(cq);
}
EXPORT_SYMBOL(ib_destroy_cq);

int ib_resize_cq(struct ib_cq *cq, int cqe)
{
	return cq->device->resize_cq ?
		cq->device->resize_cq(cq, cqe, NULL) : -ENOSYS;
}
EXPORT_SYMBOL(ib_resize_cq);

/* Memory regions */

struct ib_mr *ib_get_dma_mr(struct ib_pd *pd, int mr_access_flags)
{
	struct ib_mr *mr;
	int err;

	err = ib_check_mr_access(mr_access_flags);
	if (err)
		return ERR_PTR(err);

	mr = pd->device->get_dma_mr(pd, mr_access_flags);

	if (!IS_ERR(mr)) {
		mr->device  = pd->device;
		mr->pd      = pd;
		mr->uobject = NULL;
		atomic_inc(&pd->usecnt);
		atomic_set(&mr->usecnt, 0);
	}

	return mr;
}
EXPORT_SYMBOL(ib_get_dma_mr);

struct ib_mr *ib_reg_phys_mr(struct ib_pd *pd,
			     struct ib_phys_buf *phys_buf_array,
			     int num_phys_buf,
			     int mr_access_flags,
			     u64 *iova_start)
{
	struct ib_mr *mr;
	int err;

	err = ib_check_mr_access(mr_access_flags);
	if (err)
		return ERR_PTR(err);

	if (!pd->device->reg_phys_mr)
		return ERR_PTR(-ENOSYS);

	mr = pd->device->reg_phys_mr(pd, phys_buf_array, num_phys_buf,
				     mr_access_flags, iova_start);

	if (!IS_ERR(mr)) {
		mr->device  = pd->device;
		mr->pd      = pd;
		mr->uobject = NULL;
		atomic_inc(&pd->usecnt);
		atomic_set(&mr->usecnt, 0);
	}

	return mr;
}
EXPORT_SYMBOL(ib_reg_phys_mr);

int ib_rereg_phys_mr(struct ib_mr *mr,
		     int mr_rereg_mask,
		     struct ib_pd *pd,
		     struct ib_phys_buf *phys_buf_array,
		     int num_phys_buf,
		     int mr_access_flags,
		     u64 *iova_start)
{
	struct ib_pd *old_pd;
	int ret;

	ret = ib_check_mr_access(mr_access_flags);
	if (ret)
		return ret;

	if (!mr->device->rereg_phys_mr)
		return -ENOSYS;

	if (atomic_read(&mr->usecnt))
		return -EBUSY;

	old_pd = mr->pd;

	ret = mr->device->rereg_phys_mr(mr, mr_rereg_mask, pd,
					phys_buf_array, num_phys_buf,
					mr_access_flags, iova_start);

	if (!ret && (mr_rereg_mask & IB_MR_REREG_PD)) {
		atomic_dec(&old_pd->usecnt);
		atomic_inc(&pd->usecnt);
	}

	return ret;
}
EXPORT_SYMBOL(ib_rereg_phys_mr);

int ib_query_mr(struct ib_mr *mr, struct ib_mr_attr *mr_attr)
{
	return mr->device->query_mr ?
		mr->device->query_mr(mr, mr_attr) : -ENOSYS;
}
EXPORT_SYMBOL(ib_query_mr);

int ib_dereg_mr(struct ib_mr *mr)
{
	struct ib_pd *pd;
	int ret;

	if (atomic_read(&mr->usecnt))
		return -EBUSY;

	pd = mr->pd;
	ret = mr->device->dereg_mr(mr);
	if (!ret)
		atomic_dec(&pd->usecnt);

	return ret;
}
EXPORT_SYMBOL(ib_dereg_mr);

struct ib_mr *ib_create_mr(struct ib_pd *pd,
			   struct ib_mr_init_attr *mr_init_attr)
{
	struct ib_mr *mr;

	if (!pd->device->create_mr)
		return ERR_PTR(-ENOSYS);

	mr = pd->device->create_mr(pd, mr_init_attr);

	if (!IS_ERR(mr)) {
		mr->device  = pd->device;
		mr->pd      = pd;
		mr->uobject = NULL;
		atomic_inc(&pd->usecnt);
		atomic_set(&mr->usecnt, 0);
	}

	return mr;
}
EXPORT_SYMBOL(ib_create_mr);

int ib_destroy_mr(struct ib_mr *mr)
{
	struct ib_pd *pd;
	int ret;

	if (atomic_read(&mr->usecnt))
		return -EBUSY;

	pd = mr->pd;
	ret = mr->device->destroy_mr(mr);
	if (!ret)
		atomic_dec(&pd->usecnt);

	return ret;
}
EXPORT_SYMBOL(ib_destroy_mr);

struct ib_mr *ib_alloc_fast_reg_mr(struct ib_pd *pd, int max_page_list_len)
{
	struct ib_mr *mr;

	if (!pd->device->alloc_fast_reg_mr)
		return ERR_PTR(-ENOSYS);

	mr = pd->device->alloc_fast_reg_mr(pd, max_page_list_len);

	if (!IS_ERR(mr)) {
		mr->device  = pd->device;
		mr->pd      = pd;
		mr->uobject = NULL;
		atomic_inc(&pd->usecnt);
		atomic_set(&mr->usecnt, 0);
	}

	return mr;
}
EXPORT_SYMBOL(ib_alloc_fast_reg_mr);

struct ib_fast_reg_page_list *ib_alloc_fast_reg_page_list(struct ib_device *device,
							  int max_page_list_len)
{
	struct ib_fast_reg_page_list *page_list;

	if (!device->alloc_fast_reg_page_list)
		return ERR_PTR(-ENOSYS);

	page_list = device->alloc_fast_reg_page_list(device, max_page_list_len);

	if (!IS_ERR(page_list)) {
		page_list->device = device;
		page_list->max_page_list_len = max_page_list_len;
	}

	return page_list;
}
EXPORT_SYMBOL(ib_alloc_fast_reg_page_list);

void ib_free_fast_reg_page_list(struct ib_fast_reg_page_list *page_list)
{
	page_list->device->free_fast_reg_page_list(page_list);
}
EXPORT_SYMBOL(ib_free_fast_reg_page_list);

/* Memory windows */

struct ib_mw *ib_alloc_mw(struct ib_pd *pd, enum ib_mw_type type)
{
	struct ib_mw *mw;

	if (!pd->device->alloc_mw)
		return ERR_PTR(-ENOSYS);

	mw = pd->device->alloc_mw(pd, type);
	if (!IS_ERR(mw)) {
		mw->device  = pd->device;
		mw->pd      = pd;
		mw->uobject = NULL;
		mw->type    = type;
		atomic_inc(&pd->usecnt);
	}

	return mw;
}
EXPORT_SYMBOL(ib_alloc_mw);

int ib_dealloc_mw(struct ib_mw *mw)
{
	struct ib_pd *pd;
	int ret;

	pd = mw->pd;
	ret = mw->device->dealloc_mw(mw);
	if (!ret)
		atomic_dec(&pd->usecnt);

	return ret;
}
EXPORT_SYMBOL(ib_dealloc_mw);

/* "Fast" memory regions */

struct ib_fmr *ib_alloc_fmr(struct ib_pd *pd,
			    int mr_access_flags,
			    struct ib_fmr_attr *fmr_attr)
{
	struct ib_fmr *fmr;

	if (!pd->device->alloc_fmr)
		return ERR_PTR(-ENOSYS);

	fmr = pd->device->alloc_fmr(pd, mr_access_flags, fmr_attr);
	if (!IS_ERR(fmr)) {
		fmr->device = pd->device;
		fmr->pd     = pd;
		atomic_inc(&pd->usecnt);
	}

	return fmr;
}
EXPORT_SYMBOL(ib_alloc_fmr);

int ib_unmap_fmr(struct list_head *fmr_list)
{
	struct ib_fmr *fmr;

	if (list_empty(fmr_list))
		return 0;

	fmr = list_entry(fmr_list->next, struct ib_fmr, list);
	return fmr->device->unmap_fmr(fmr_list);
}
EXPORT_SYMBOL(ib_unmap_fmr);

int ib_dealloc_fmr(struct ib_fmr *fmr)
{
	struct ib_pd *pd;
	int ret;

	pd = fmr->pd;
	ret = fmr->device->dealloc_fmr(fmr);
	if (!ret)
		atomic_dec(&pd->usecnt);

	return ret;
}
EXPORT_SYMBOL(ib_dealloc_fmr);

/* Multicast groups */

int ib_attach_mcast(struct ib_qp *qp, union ib_gid *gid, u16 lid)
{
	int ret;

	if (!qp->device->attach_mcast)
		return -ENOSYS;
	if ((gid->raw[0] != 0xff || qp->qp_type != IB_QPT_UD) &&
	    qp->qp_type != IB_QPT_RAW_PACKET)
		return -EINVAL;

	if (rdma_node_get_transport(qp->device->node_type) ==
	    RDMA_EXP_TRANSPORT_SCIF && (qp->qp_type != IB_QPT_RAW_PACKET))
		return -EINVAL;

	ret = qp->device->attach_mcast(qp, gid, lid);
	if (!ret)
		atomic_inc(&qp->usecnt);
	return ret;
}
EXPORT_SYMBOL(ib_attach_mcast);

int ib_detach_mcast(struct ib_qp *qp, union ib_gid *gid, u16 lid)
{
	int ret;

	if (!qp->device->detach_mcast)
		return -ENOSYS;
	if ((gid->raw[0] != 0xff || qp->qp_type != IB_QPT_UD) &&
	    qp->qp_type != IB_QPT_RAW_PACKET)
		return -EINVAL;

	if (rdma_node_get_transport(qp->device->node_type) ==
	    RDMA_EXP_TRANSPORT_SCIF && (qp->qp_type != IB_QPT_RAW_PACKET))
		return -EINVAL;

	ret = qp->device->detach_mcast(qp, gid, lid);
	if (!ret)
		atomic_dec(&qp->usecnt);
	return ret;
}
EXPORT_SYMBOL(ib_detach_mcast);

struct ib_xrcd *ib_alloc_xrcd(struct ib_device *device)
{
	struct ib_xrcd *xrcd;

	if (!device->alloc_xrcd)
		return ERR_PTR(-ENOSYS);

	xrcd = device->alloc_xrcd(device, NULL, NULL);
	if (!IS_ERR(xrcd)) {
		xrcd->device = device;
		xrcd->inode = NULL;
		atomic_set(&xrcd->usecnt, 0);
		mutex_init(&xrcd->tgt_qp_mutex);
		INIT_LIST_HEAD(&xrcd->tgt_qp_list);
	}

	return xrcd;
}
EXPORT_SYMBOL(ib_alloc_xrcd);

int ib_dealloc_xrcd(struct ib_xrcd *xrcd)
{
	struct ib_qp *qp;
	int ret;

	if (atomic_read(&xrcd->usecnt))
		return -EBUSY;

	while (!list_empty(&xrcd->tgt_qp_list)) {
		qp = list_entry(xrcd->tgt_qp_list.next, struct ib_qp, xrcd_list);
		ret = ib_destroy_qp(qp);
		if (ret)
			return ret;
	}

	return xrcd->device->dealloc_xrcd(xrcd);
}
EXPORT_SYMBOL(ib_dealloc_xrcd);

struct ib_wq *ib_create_wq(struct ib_pd *pd,
			   struct ib_wq_init_attr *wq_attr)
{
	struct ib_wq *wq;

	if (!pd->device->create_wq)
		return ERR_PTR(-ENOSYS);

	wq = pd->device->create_wq(pd, wq_attr, NULL);
	if (!IS_ERR(wq)) {
		wq->event_handler = wq_attr->event_handler;
		wq->wq_context = wq_attr->wq_context;
		wq->wq_type = wq_attr->wq_type;
		wq->cq = wq_attr->cq;
		wq->device = pd->device;
		wq->pd = pd;
		wq->uobject = NULL;
		atomic_inc(&pd->usecnt);
		atomic_inc(&wq_attr->cq->usecnt);
		if (wq_attr->srq) {
			wq->srq = wq_attr->srq;
			atomic_inc(&wq_attr->srq->usecnt);
		}
		atomic_set(&wq->usecnt, 0);
	}
	return wq;
}
EXPORT_SYMBOL(ib_create_wq);

int ib_destroy_wq(struct ib_wq *wq)
{
	int err;
	struct ib_cq *cq = wq->cq;
	struct ib_pd *pd = wq->pd;
	struct ib_srq *srq = wq->srq;

	if (!wq->device->destroy_wq)
		return -ENOSYS;

	if (atomic_read(&wq->usecnt))
		return -EBUSY;

	err = wq->device->destroy_wq(wq);
	if (!err) {
		atomic_dec(&pd->usecnt);
		atomic_dec(&cq->usecnt);
		if (srq)
			atomic_dec(&srq->usecnt);
	}
	return err;
}
EXPORT_SYMBOL(ib_destroy_wq);

int ib_modify_wq(struct ib_wq *wq, struct ib_wq_attr *wq_attr,
		 enum ib_wq_attr_mask attr_mask)
{
	int err;

	if (!wq->device->modify_wq)
		return -ENOSYS;

	err = wq->device->modify_wq(wq, wq_attr, attr_mask, NULL);
	return err;
}
EXPORT_SYMBOL(ib_modify_wq);

struct ib_rwq_ind_table *ib_create_rwq_ind_table(struct ib_device *device,
						 struct ib_rwq_ind_table_init_attr*
						 init_attr)
{
	struct ib_rwq_ind_table *rwq_ind_table;
	int i;
	u32 table_size;

	if (!device->create_rwq_ind_table)
		return ERR_PTR(-ENOSYS);

	table_size = (1 << init_attr->log_ind_tbl_size);
	rwq_ind_table = device->create_rwq_ind_table(device,
				init_attr, NULL);
	if (IS_ERR(rwq_ind_table))
		return rwq_ind_table;

	rwq_ind_table->ind_tbl = init_attr->ind_tbl;
	rwq_ind_table->log_ind_tbl_size = init_attr->log_ind_tbl_size;
	rwq_ind_table->device = device;
	rwq_ind_table->pd = init_attr->pd;
	rwq_ind_table->uobject = NULL;
	atomic_set(&rwq_ind_table->usecnt, 0);

	for (i = 0; i < table_size; i++)
		atomic_inc(&rwq_ind_table->ind_tbl[i]->usecnt);

	return rwq_ind_table;
}
EXPORT_SYMBOL(ib_create_rwq_ind_table);

int ib_destroy_rwq_ind_table(struct ib_rwq_ind_table *rwq_ind_table)
{
	int err, i;
	u32 table_size = (1 << rwq_ind_table->log_ind_tbl_size);
	struct ib_wq **ind_tbl = rwq_ind_table->ind_tbl;

	if (atomic_read(&rwq_ind_table->usecnt))
		return -EBUSY;

	if (!rwq_ind_table->device->destroy_rwq_ind_table)
		return -ENOSYS;

	err = rwq_ind_table->device->destroy_rwq_ind_table(rwq_ind_table);
	if (!err) {
		for (i = 0; i < table_size; i++)
			atomic_dec(&ind_tbl[i]->usecnt);
	}

	return err;
}
EXPORT_SYMBOL(ib_destroy_rwq_ind_table);

struct ib_flow *ib_create_flow(struct ib_qp *qp,
			       struct ib_flow_attr *flow_attr,
			       int domain)
{
	struct ib_flow *flow_id;
	if (!qp->device->create_flow)
		return ERR_PTR(-ENOSYS);

	flow_id = qp->device->create_flow(qp, flow_attr, domain);
	if (!IS_ERR(flow_id)) {
		atomic_inc(&qp->usecnt);
		flow_id->qp = qp;
		flow_id->uobject = NULL;
	}
	return flow_id;
}
EXPORT_SYMBOL(ib_create_flow);

int ib_destroy_flow(struct ib_flow *flow_id)
{
	int err;
	struct ib_qp *qp = flow_id->qp;

	err = qp->device->destroy_flow(flow_id);
	if (!err)
		atomic_dec(&qp->usecnt);
	return err;
}
EXPORT_SYMBOL(ib_destroy_flow);

struct ib_dct *ib_create_dct(struct ib_pd *pd, struct ib_dct_init_attr *attr,
			     struct ib_udata *udata)
{
	struct ib_dct *dct;

	if (!pd->device->exp_create_dct)
		return ERR_PTR(-ENOSYS);

	dct = pd->device->exp_create_dct(pd, attr, udata);
	if (!IS_ERR(dct)) {
		dct->pd = pd;
		dct->srq = attr->srq;
		dct->cq = attr->cq;
		atomic_inc(&dct->srq->usecnt);
		atomic_inc(&dct->cq->usecnt);
		atomic_inc(&dct->pd->usecnt);
	}

	return dct;
}
EXPORT_SYMBOL(ib_create_dct);

int ib_destroy_dct(struct ib_dct *dct)
{
	struct ib_srq *srq;
	struct ib_cq *cq;
	struct ib_pd *pd;
	int err;

	if (!dct->device->exp_destroy_dct)
		return -ENOSYS;

	srq = dct->srq;
	cq = dct->cq;
	pd = dct->pd;
	err = dct->device->exp_destroy_dct(dct);
	if (!err) {
		atomic_dec(&srq->usecnt);
		atomic_dec(&cq->usecnt);
		atomic_dec(&pd->usecnt);
	}

	return err;
}
EXPORT_SYMBOL(ib_destroy_dct);

int ib_query_dct(struct ib_dct *dct, struct ib_dct_attr *attr)
{
	if (!dct->device->exp_query_dct)
		return -ENOSYS;

	return dct->device->exp_query_dct(dct, attr);
}
EXPORT_SYMBOL(ib_query_dct);

int ib_arm_dct(struct ib_dct *dct)
{
	if (!dct->device->exp_arm_dct)
		return -ENOSYS;

	return dct->device->exp_arm_dct(dct, NULL);
}
EXPORT_SYMBOL(ib_arm_dct);
int ib_check_mr_status(struct ib_mr *mr, u32 check_mask,
		       struct ib_mr_status *mr_status)
{
	return mr->device->check_mr_status ?
		mr->device->check_mr_status(mr, check_mask, mr_status) : -ENOSYS;
}
EXPORT_SYMBOL(ib_check_mr_status);

int ib_query_mkey(struct ib_mr *mr, u64 mkey_attr_mask,
		  struct ib_mkey_attr *mkey_attr)
{
	return mr->device->exp_query_mkey ?
		mr->device->exp_query_mkey(mr, mkey_attr_mask, mkey_attr) : -ENOSYS;
}
EXPORT_SYMBOL(ib_query_mkey);
int ib_roce_mode_is_over_ip(struct ib_device *ibdev, int port_num)
{
	struct ib_device_attr attr;
	if ((rdma_port_get_link_layer(ibdev, port_num) == IB_LINK_LAYER_ETHERNET) &&
	    !ib_query_device(ibdev, &attr) &&
	    (attr.device_cap_flags & (IB_DEVICE_ROCE_MODE_1_5 | IB_DEVICE_ROCE_MODE_2)))
		return 1;
	return 0;
}
EXPORT_SYMBOL(ib_roce_mode_is_over_ip);

struct ib_indir_reg_list *
ib_alloc_indir_reg_list(struct ib_device *device,
			unsigned int max_indir_list_len)
{
	struct ib_indir_reg_list *indir_list;

	if (!device->alloc_indir_reg_list)
		return ERR_PTR(-ENOSYS);

	indir_list = device->alloc_indir_reg_list(device,
						  max_indir_list_len);
	if (!IS_ERR(indir_list)) {
		indir_list->device = device;
		indir_list->max_indir_list_len = max_indir_list_len;
	}

	return indir_list;
}
EXPORT_SYMBOL(ib_alloc_indir_reg_list);

void
ib_free_indir_reg_list(struct ib_indir_reg_list *indir_list)
{
	if (indir_list->device->free_indir_reg_list)
		indir_list->device->free_indir_reg_list(indir_list);
}
EXPORT_SYMBOL(ib_free_indir_reg_list);

int ib_get_vf_stats(struct ib_device *device, int vf,
		    struct ib_vf_stats *stats)
{
	if (device->get_vf_stats)
		return device->get_vf_stats(device, vf, stats);

	return -ENOSYS;
}
EXPORT_SYMBOL(ib_get_vf_stats);

struct ib_drain_cqe {
	struct ib_cqe cqe;
	struct completion done;
};

static void ib_drain_qp_done(struct ib_cq *cq, struct ib_wc *wc)
{
	struct ib_drain_cqe *cqe = container_of(wc->wr_cqe, struct ib_drain_cqe,
						cqe);

	complete(&cqe->done);
}

/*
 * Post a WR and block until its completion is reaped for the SQ.
 */
static void __ib_drain_sq(struct ib_qp *qp)
{
	struct ib_qp_attr attr = { .qp_state = IB_QPS_ERR };
	struct ib_drain_cqe sdrain;
	struct ib_send_wr swr = {}, *bad_swr;
	int ret;

	if (qp->send_cq->poll_ctx == IB_POLL_DIRECT) {
		WARN_ONCE(qp->send_cq->poll_ctx == IB_POLL_DIRECT,
			  "IB_POLL_DIRECT poll_ctx not supported for drain\n");
		return;
	}

	swr.wr_cqe = &sdrain.cqe;
	sdrain.cqe.done = ib_drain_qp_done;
	init_completion(&sdrain.done);

	ret = ib_modify_qp(qp, &attr, IB_QP_STATE);
	if (ret) {
		WARN_ONCE(ret, "failed to drain send queue: %d\n", ret);
		return;
	}

	ret = ib_post_send(qp, &swr, &bad_swr);
	if (ret) {
		WARN_ONCE(ret, "failed to drain send queue: %d\n", ret);
		return;
	}

	wait_for_completion(&sdrain.done);
}

/*
 * Post a WR and block until its completion is reaped for the RQ.
 */
static void __ib_drain_rq(struct ib_qp *qp)
{
	struct ib_qp_attr attr = { .qp_state = IB_QPS_ERR };
	struct ib_drain_cqe rdrain;
	struct ib_recv_wr rwr = {}, *bad_rwr;
	int ret;

	if (qp->recv_cq->poll_ctx == IB_POLL_DIRECT) {
		WARN_ONCE(qp->recv_cq->poll_ctx == IB_POLL_DIRECT,
			  "IB_POLL_DIRECT poll_ctx not supported for drain\n");
		return;
	}

	rwr.wr_cqe = &rdrain.cqe;
	rdrain.cqe.done = ib_drain_qp_done;
	init_completion(&rdrain.done);

	ret = ib_modify_qp(qp, &attr, IB_QP_STATE);
	if (ret) {
		WARN_ONCE(ret, "failed to drain recv queue: %d\n", ret);
		return;
	}

	ret = ib_post_recv(qp, &rwr, &bad_rwr);
	if (ret) {
		WARN_ONCE(ret, "failed to drain recv queue: %d\n", ret);
		return;
	}

	wait_for_completion(&rdrain.done);
}

/**
 * ib_drain_sq() - Block until all SQ CQEs have been consumed by the
 *		   application.
 * @qp:            queue pair to drain
 *
 * If the device has a provider-specific drain function, then
 * call that.  Otherwise call the generic drain function
 * __ib_drain_sq().
 *
 * The caller must:
 *
 * ensure there is room in the CQ and SQ for the drain work request and
 * completion.
 *
 * allocate the CQ using ib_alloc_cq() and the CQ poll context cannot be
 * IB_POLL_DIRECT.
 *
 * ensure that there are no other contexts that are posting WRs concurrently.
 * Otherwise the drain is not guaranteed.
 */
void ib_drain_sq(struct ib_qp *qp)
{
	if (qp->device->drain_sq)
		qp->device->drain_sq(qp);
	else
		__ib_drain_sq(qp);
}
EXPORT_SYMBOL(ib_drain_sq);

/**
 * ib_drain_rq() - Block until all RQ CQEs have been consumed by the
 *		   application.
 * @qp:            queue pair to drain
 *
 * If the device has a provider-specific drain function, then
 * call that.  Otherwise call the generic drain function
 * __ib_drain_rq().
 *
 * The caller must:
 *
 * ensure there is room in the CQ and RQ for the drain work request and
 * completion.
 *
 * allocate the CQ using ib_alloc_cq() and the CQ poll context cannot be
 * IB_POLL_DIRECT.
 *
 * ensure that there are no other contexts that are posting WRs concurrently.
 * Otherwise the drain is not guaranteed.
 */
void ib_drain_rq(struct ib_qp *qp)
{
	if (qp->device->drain_rq)
		qp->device->drain_rq(qp);
	else
		__ib_drain_rq(qp);
}
EXPORT_SYMBOL(ib_drain_rq);

/**
 * ib_drain_qp() - Block until all CQEs have been consumed by the
 *		   application on both the RQ and SQ.
 * @qp:            queue pair to drain
 *
 * The caller must:
 *
 * ensure there is room in the CQ(s), SQ, and RQ for drain work requests
 * and completions.
 *
 * allocate the CQs using ib_alloc_cq() and the CQ poll context cannot be
 * IB_POLL_DIRECT.
 *
 * ensure that there are no other contexts that are posting WRs concurrently.
 * Otherwise the drain is not guaranteed.
 */
void ib_drain_qp(struct ib_qp *qp)
{
	ib_drain_sq(qp);
	ib_drain_rq(qp);
}
EXPORT_SYMBOL(ib_drain_qp);
