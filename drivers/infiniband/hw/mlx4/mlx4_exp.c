/*
 * Copyright (c) 2006, 2007 Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2007, 2008 Mellanox Technologies. All rights reserved.
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

#include "mlx4_ib.h"
#include "mlx4_exp.h"
#include <linux/mlx4/qp.h>

int mlx4_ib_exp_query_device(struct ib_device *ibdev,
			     struct ib_exp_device_attr *props)
{
	struct ib_device_attr *base = &props->base;
	struct mlx4_ib_dev *dev = to_mdev(ibdev);
	int ret = mlx4_ib_query_device(ibdev, &props->base);
	struct ib_exp_masked_atomic_caps *atom_caps =
		&props->masked_atomic_caps;

	props->exp_comp_mask = IB_EXP_DEVICE_ATTR_INLINE_RECV_SZ;
	props->inline_recv_sz = dev->dev->caps.max_rq_sg * sizeof(struct mlx4_wqe_data_seg);
	props->device_cap_flags2 = 0;

	/* move RSS device cap from device_cap to device_cap_flags2 */
	if (base->device_cap_flags & IB_DEVICE_QPG) {
		props->device_cap_flags2 |= IB_EXP_DEVICE_QPG;
		if (base->device_cap_flags & IB_DEVICE_UD_RSS)
			props->device_cap_flags2 |= IB_EXP_DEVICE_UD_RSS;
	}
	base->device_cap_flags &= ~(IB_DEVICE_QPG |
				    IB_DEVICE_UD_RSS |
				    IB_DEVICE_UD_TSS);

	if (base->device_cap_flags & IB_DEVICE_ROCE_MODE_1_5)
		props->device_cap_flags2 |= IB_EXP_DEVICE_ROCE_MODE_1_5;
	if (base->device_cap_flags & IB_DEVICE_ROCE_MODE_2)
		props->device_cap_flags2 |= IB_EXP_DEVICE_ROCE_MODE_2;

	if (dev->dev->caps.tunnel_offload_mode != MLX4_TUNNEL_OFFLOAD_MODE_NONE)
		props->device_cap_flags2 |= IB_EXP_DEVICE_VXLAN_SUPPORT;

	/* Only ConnectX3 pro reports csum for now. can add ConnextX-3 later */
	if (dev->dev->caps.rx_checksum_flags_port[1] &
	    MLX4_RX_CSUM_MODE_IP_OK_IP_NON_TCP_UDP)
		props->device_cap_flags2 |= (IB_EXP_DEVICE_RX_CSUM_IP_PKT |
					     IB_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT);
	if (dev->dev->caps.rx_checksum_flags_port[2] &
	    MLX4_RX_CSUM_MODE_IP_OK_IP_NON_TCP_UDP)
		props->device_cap_flags2 |= (IB_EXP_DEVICE_RX_CSUM_IP_PKT |
					     IB_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT);

	if (base->max_rss_tbl_sz > 0) {
		props->max_rss_tbl_sz = base->max_rss_tbl_sz;
		props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_RSS_TBL_SZ;
	} else {
		props->max_rss_tbl_sz = 0;
		props->exp_comp_mask &= ~IB_EXP_DEVICE_ATTR_RSS_TBL_SZ;
	}

	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_CAP_FLAGS2;

	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_EXT_ATOMIC_ARGS;
	/* Legacy extended atomic fields */
	props->atomic_arg_sizes = 1 << 3;
	props->max_fa_bit_boudary = 64;
	props->log_max_atomic_inline_arg = 3;
	props->device_cap_flags2 |= IB_EXP_DEVICE_EXT_ATOMICS;

	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_MAX_CTX_RES_DOMAIN;
	props->max_ctx_res_domain = MLX4_IB_MAX_CTX_UARS * dev->dev->caps.bf_regs_per_page;

	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_MAX_DEVICE_CTX;

	/*mlx4_core uses 1 UAR*/
	props->max_device_ctx = dev->dev->caps.num_uars - dev->dev->caps.reserved_uars - 1;

	/* Report masked atomic properties - new API */
	atom_caps->masked_log_atomic_arg_sizes = props->atomic_arg_sizes;
	/* Requestor's response in ConnectX-3 is in host endianness. */
	if (!mlx4_host_is_le())
		atom_caps->masked_log_atomic_arg_sizes_network_endianness =
			props->atomic_arg_sizes;
	else
		atom_caps->masked_log_atomic_arg_sizes_network_endianness = 0;

	atom_caps->max_fa_bit_boudary = props->max_fa_bit_boudary;
	atom_caps->log_max_atomic_inline_arg = props->log_max_atomic_inline_arg;

	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_EXT_MASKED_ATOMICS;

	return ret;
}

/*
 * Experimental functions
 */
struct ib_qp *mlx4_ib_exp_create_qp(struct ib_pd *pd,
				    struct ib_exp_qp_init_attr *init_attr,
				    struct ib_udata *udata)
{
	int rwqe_size;
	struct ib_qp *qp;
	struct mlx4_ib_qp *mqp;
	int use_inlr;
	struct mlx4_ib_dev *dev;

	if ((init_attr->create_flags & IB_QP_CREATE_ATOMIC_BE_REPLY) &&
	    mlx4_is_little_endian())
		return ERR_PTR(-EINVAL);

	if (init_attr->max_inl_recv && !udata)
		return ERR_PTR(-EINVAL);

	use_inlr = mlx4_ib_qp_has_rq((struct ib_qp_init_attr *)init_attr) &&
		   init_attr->max_inl_recv && pd;
	if (use_inlr) {
		rwqe_size = roundup_pow_of_two(max(1U, init_attr->cap.max_recv_sge)) *
					       sizeof(struct mlx4_wqe_data_seg);
		if (rwqe_size < init_attr->max_inl_recv) {
			dev = to_mdev(pd->device);
			init_attr->max_inl_recv = min(init_attr->max_inl_recv,
						      (u32)(dev->dev->caps.max_rq_sg *
						      sizeof(struct mlx4_wqe_data_seg)));
			init_attr->cap.max_recv_sge = roundup_pow_of_two(init_attr->max_inl_recv) /
						      sizeof(struct mlx4_wqe_data_seg);
		}
	} else {
		init_attr->max_inl_recv = 0;
	}
	qp = mlx4_ib_create_qp(pd, (struct ib_qp_init_attr *)init_attr, udata);
	if (IS_ERR(qp))
		return qp;

	if (use_inlr) {
		mqp = to_mqp(qp);
		mqp->max_inlr_data = 1 << mqp->rq.wqe_shift;
		init_attr->max_inl_recv = mqp->max_inlr_data;
	}

	return qp;
}
