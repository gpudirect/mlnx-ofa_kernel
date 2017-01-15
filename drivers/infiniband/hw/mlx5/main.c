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

#include <linux/module.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/io-mapping.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/spinlock.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_user_verbs_exp.h>
#include <rdma/ib_verbs_exp.h>
#include <rdma/ib_smi.h>
#include <rdma/ib_umem.h>
#include "user.h"
#include "mlx5_ib.h"
#include "linux/mlx5/vport.h"
#include "linux/mlx5/fs.h"

#define DRIVER_NAME "mlx5_ib"
#define DRIVER_VERSION	"3.4-1.0.0"
#define DRIVER_RELDATE	"25 Sep 2016"

MODULE_AUTHOR("Eli Cohen <eli@mellanox.com>");
MODULE_DESCRIPTION("Mellanox Connect-IB HCA IB driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(DRIVER_VERSION);

static int deprecated_prof_sel = 2;
module_param_named(prof_sel, deprecated_prof_sel, int, 0444);
MODULE_PARM_DESC(prof_sel, "profile selector. Deprecated here. Moved to module mlx5_core");

enum {
	MLX5_STANDARD_ATOMIC_SIZE = 0x8,
};

struct workqueue_struct *mlx5_ib_wq;

static char mlx5_version[] =
	DRIVER_NAME ": Mellanox Connect-IB Infiniband driver v"
	DRIVER_VERSION " (" DRIVER_RELDATE ")\n";

static void ext_atomic_caps(struct mlx5_ib_dev *dev,
			    struct ib_exp_device_attr *props)
{
	int tmp;
	unsigned long last;
	unsigned long arg;
	struct ib_exp_masked_atomic_caps *atom_caps =
		&props->masked_atomic_caps;

	/* Legacy extended atomic fields */
	props->max_fa_bit_boudary = 0;
	props->log_max_atomic_inline_arg = 0;
	/* New extended atomic fields */
	atom_caps->max_fa_bit_boudary = 0;
	atom_caps->log_max_atomic_inline_arg = 0;
	atom_caps->masked_log_atomic_arg_sizes = 0;
	atom_caps->masked_log_atomic_arg_sizes_network_endianness = 0;

	tmp = MLX5_ATOMIC_OPS_CMP_SWAP		|
	      MLX5_ATOMIC_OPS_FETCH_ADD		|
	      MLX5_ATOMIC_OPS_MASKED_CMP_SWAP	|
	      MLX5_ATOMIC_OPS_MASKED_FETCH_ADD;

	if (MLX5_CAP_ATOMIC(dev->mdev, atomic_operations) != tmp)
		return;

	props->atomic_arg_sizes = MLX5_CAP_ATOMIC(dev->mdev, atomic_size_qp) &
				  MLX5_CAP_ATOMIC(dev->mdev, atomic_size_dc);
	props->max_fa_bit_boudary = 64;
	arg = (unsigned long)props->atomic_arg_sizes;
	last = find_last_bit(&arg, BITS_PER_LONG);
	if (last < 6)
		props->log_max_atomic_inline_arg = last;
	else
		props->log_max_atomic_inline_arg = 6;

	atom_caps->masked_log_atomic_arg_sizes = props->atomic_arg_sizes;
	if (!mlx5_host_is_le() ||
	    props->base.atomic_cap == IB_ATOMIC_HCA_REPLY_BE)
		atom_caps->masked_log_atomic_arg_sizes_network_endianness =
			props->atomic_arg_sizes;
	else if (props->base.atomic_cap == IB_ATOMIC_HCA)
		atom_caps->masked_log_atomic_arg_sizes_network_endianness =
			atom_caps->masked_log_atomic_arg_sizes &
			~MLX5_STANDARD_ATOMIC_SIZE;

	if (props->base.atomic_cap == IB_ATOMIC_HCA && mlx5_host_is_le())
		props->atomic_arg_sizes &= MLX5_STANDARD_ATOMIC_SIZE;
	atom_caps->max_fa_bit_boudary = props->max_fa_bit_boudary;
	atom_caps->log_max_atomic_inline_arg = props->log_max_atomic_inline_arg;

	props->device_cap_flags2 |= IB_EXP_DEVICE_EXT_ATOMICS |
				    IB_EXP_DEVICE_EXT_MASKED_ATOMICS;
}

static void get_atomic_caps(struct mlx5_ib_dev *dev,
			    struct ib_device_attr *props,
			    int exp)
{
	int tmp;
	u8 atomic_operations;
	u8 atomic_size_qp;
	u8 atomic_req_endianess;

	atomic_operations = MLX5_CAP_ATOMIC(dev->mdev, atomic_operations);
	atomic_size_qp = MLX5_CAP_ATOMIC(dev->mdev, atomic_size_qp);
	atomic_req_endianess = MLX5_CAP_ATOMIC(dev->mdev,
					       atomic_req_8B_endianess_mode) ||
			       !mlx5_host_is_le();

	tmp = MLX5_ATOMIC_OPS_CMP_SWAP | MLX5_ATOMIC_OPS_FETCH_ADD;
	if (((atomic_operations & tmp) == tmp)
	    && (atomic_size_qp & 8)) {
		if (atomic_req_endianess) {
			props->atomic_cap = IB_ATOMIC_HCA;
		 } else {
			if (exp)
				props->atomic_cap = IB_ATOMIC_HCA_REPLY_BE;
			else
				props->atomic_cap = IB_ATOMIC_NONE;
		}
	} else {
		props->atomic_cap = IB_ATOMIC_NONE;
	}

	tmp = MLX5_ATOMIC_OPS_MASKED_CMP_SWAP | MLX5_ATOMIC_OPS_MASKED_FETCH_ADD;
	if (((atomic_operations & tmp) == tmp)
	    &&(atomic_size_qp & 8)) {
		if (atomic_req_endianess)
			props->masked_atomic_cap = IB_ATOMIC_HCA;
		else {
			if (exp)
				props->masked_atomic_cap = IB_ATOMIC_HCA_REPLY_BE;
			else
				props->masked_atomic_cap = IB_ATOMIC_NONE;
		}
	} else {
		props->masked_atomic_cap = IB_ATOMIC_NONE;
	}
}

static enum rdma_link_layer
mlx5_ib_port_link_layer(struct ib_device *device, u8 port_num)
{
	struct mlx5_ib_dev *dev = to_mdev(device);

	switch (MLX5_CAP_GEN(dev->mdev, port_type)) {
	case MLX5_CAP_PORT_TYPE_IB:
		return IB_LINK_LAYER_INFINIBAND;
	case MLX5_CAP_PORT_TYPE_ETH:
		return IB_LINK_LAYER_ETHERNET;
	default:
		return IB_LINK_LAYER_UNSPECIFIED;
	}
}

static int mlx5_use_mad_ifc(struct mlx5_ib_dev *dev)
{
	if (MLX5_CAP_GEN(dev->mdev, port_type) == MLX5_CAP_PORT_TYPE_IB)
		return !MLX5_CAP_GEN(dev->mdev, ib_virt);
	return 0;
}

enum {
	MLX5_VPORT_ACCESS_METHOD_MAD,
	MLX5_VPORT_ACCESS_METHOD_HCA,
	MLX5_VPORT_ACCESS_METHOD_NIC,
};

static int mlx5_get_vport_access_method(struct ib_device *ibdev)
{
	if (MLX5_CAP_GEN(to_mdev(ibdev)->mdev, port_type) ==
	     MLX5_CAP_PORT_TYPE_ETH)
		return MLX5_VPORT_ACCESS_METHOD_NIC;

	if (mlx5_use_mad_ifc(to_mdev(ibdev)))
		return MLX5_VPORT_ACCESS_METHOD_MAD;

	return MLX5_VPORT_ACCESS_METHOD_HCA;
}

static int mlx5_query_system_image_guid(struct ib_device *ibdev,
					__be64 *sys_image_guid)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_hca_vport_context *rep;
	u64 tmp;
	int err;

	switch (mlx5_get_vport_access_method(ibdev)) {
	case MLX5_VPORT_ACCESS_METHOD_MAD:
		return mlx5_query_system_image_guid_mad_ifc(ibdev,
							    sys_image_guid);

	case MLX5_VPORT_ACCESS_METHOD_HCA:
		rep = kzalloc(sizeof(*rep), GFP_KERNEL);
			if (!rep)
				return -ENOMEM;
		err = mlx5_core_query_hca_vport_context(mdev, 0, 1, 0, rep);
		if (!err)
			*sys_image_guid = cpu_to_be64(rep->sys_image_guid);
		kfree(rep);
		return err;

	case MLX5_VPORT_ACCESS_METHOD_NIC:
		if (!MLX5_CAP_GEN(dev->mdev, roce)) {
			mlx5_ib_warn(dev, "Trying to query system image GUID "
				     "but RoCE is not supported\n");
			return -ENOTSUPP;
		}
		err = mlx5_query_nic_vport_system_image_guid(mdev, &tmp);
		if (!err)
			*sys_image_guid = cpu_to_be64(tmp);
		return err;

	default:
		return -EINVAL;
	}
}

static int mlx5_query_max_pkeys(struct ib_device *ibdev,
				u16 *max_pkeys)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct mlx5_core_dev *mdev = dev->mdev;

	switch (mlx5_get_vport_access_method(ibdev)) {
	case MLX5_VPORT_ACCESS_METHOD_MAD:
		return mlx5_query_max_pkeys_mad_ifc(ibdev, max_pkeys);

	case MLX5_VPORT_ACCESS_METHOD_HCA:
	case MLX5_VPORT_ACCESS_METHOD_NIC:
		*max_pkeys = mlx5_to_sw_pkey_sz(MLX5_CAP_GEN(mdev,
						pkey_table_size));
		return 0;

	default:
		return -EINVAL;
	}
}

static int mlx5_query_vendor_id(struct ib_device *ibdev,
				u32 *vendor_id)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);

	switch (mlx5_get_vport_access_method(ibdev)) {
	case MLX5_VPORT_ACCESS_METHOD_MAD:
		return mlx5_query_vendor_id_mad_ifc(ibdev, vendor_id);

	case MLX5_VPORT_ACCESS_METHOD_HCA:
	case MLX5_VPORT_ACCESS_METHOD_NIC:
		return mlx5_core_query_vendor_id(dev->mdev, vendor_id);

	default:
		return -EINVAL;
	}
}

static int mlx5_query_node_guid(struct mlx5_ib_dev *dev,
				__be64 *node_guid)
{
	struct mlx5_hca_vport_context *rep;
	u64 tmp;
	int err;

	switch (mlx5_get_vport_access_method(&dev->ib_dev)) {
	case MLX5_VPORT_ACCESS_METHOD_MAD:
		return mlx5_query_node_guid_mad_ifc(dev, node_guid);

	case MLX5_VPORT_ACCESS_METHOD_HCA:
		rep = kzalloc(sizeof(*rep), GFP_KERNEL);
			if (!rep)
				return -ENOMEM;
		err = mlx5_core_query_hca_vport_context(dev->mdev, 0, 1, 0,
							rep);
		if (!err)
			*node_guid = cpu_to_be64(rep->node_guid);
		kfree(rep);
		return err;

	case MLX5_VPORT_ACCESS_METHOD_NIC:
		if (!MLX5_CAP_GEN(dev->mdev, roce)) {
			mlx5_ib_warn(dev, "Trying to query node GUID but RoCE "
				     "is not supported\n");
			return -ENOTSUPP;
		}
		err = mlx5_query_nic_vport_node_guid(dev->mdev, 0, &tmp);
		if (!err)
			*node_guid = cpu_to_be64(tmp);

		return err;

	default:
		return -EINVAL;
	}
}

struct mlx5_reg_node_desc {
	u8	desc[64];
};

static int mlx5_query_node_desc(struct mlx5_ib_dev *dev, char *node_desc)
{
	struct mlx5_reg_node_desc in;

	if (mlx5_use_mad_ifc(dev))
		return mlx5_query_node_desc_mad_ifc(dev, node_desc);

	memset(&in, 0, sizeof(in));

	return mlx5_core_access_reg(dev->mdev, &in, sizeof(in), node_desc,
				    sizeof(struct mlx5_reg_node_desc),
				    MLX5_REG_NODE_DESC, 0, 0);
}

static int query_device(struct ib_device *ibdev,
			struct ib_device_attr *props,
			int exp)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct mlx5_core_dev *mdev = dev->mdev;
	int max_sq_desc;
	int max_rq_sg;
	int max_sq_sg;
	int err;


	memset(props, 0, sizeof(*props));

	err = mlx5_query_system_image_guid(ibdev,
					   &props->sys_image_guid);
	if (err)
		return err;

	err = mlx5_query_max_pkeys(ibdev, &props->max_pkeys);
	if (err)
		return err;

	err = mlx5_query_vendor_id(ibdev, &props->vendor_id);
	if (err)
		return err;

	props->fw_ver = ((u64)fw_rev_maj(dev->mdev) << 32) |
		(fw_rev_min(dev->mdev) << 16) |
		fw_rev_sub(dev->mdev);
	props->device_cap_flags    = IB_DEVICE_CHANGE_PHY_PORT |
		IB_DEVICE_PORT_ACTIVE_EVENT		|
		IB_DEVICE_SYS_IMAGE_GUID		|
		IB_DEVICE_RC_RNR_NAK_GEN;

	if ((MLX5_CAP_GEN(mdev, port_type) == MLX5_CAP_PORT_TYPE_ETH) &&
		mlx5_get_flow_namespace(dev->mdev, MLX5_FLOW_NAMESPACE_BYPASS))
		props->device_cap_flags |= IB_DEVICE_MANAGED_FLOW_STEERING;

	if (MLX5_CAP_GEN(mdev, pkv))
		props->device_cap_flags |= IB_DEVICE_BAD_PKEY_CNTR;
	if (MLX5_CAP_GEN(mdev, qkv))
		props->device_cap_flags |= IB_DEVICE_BAD_QKEY_CNTR;
	if (MLX5_CAP_GEN(mdev, apm))
		props->device_cap_flags |= IB_DEVICE_AUTO_PATH_MIG;
	props->device_cap_flags |= IB_DEVICE_LOCAL_DMA_LKEY;
	if (MLX5_CAP_GEN(mdev, xrc))
		props->device_cap_flags |= IB_DEVICE_XRC;
	props->device_cap_flags |= IB_DEVICE_MEM_MGT_EXTENSIONS;
	props->device_cap_flags |= IB_DEVICE_INDIR_REGISTRATION;
	if (MLX5_CAP_GEN(mdev, cq_oi) &&
	    MLX5_CAP_GEN(mdev, cd))
		props->device_cap_flags |= IB_DEVICE_CROSS_CHANNEL;
	if (MLX5_CAP_GEN(mdev, sho)) {
		props->device_cap_flags |= IB_DEVICE_SIGNATURE_HANDOVER;
		/* At this stage no support for signature handover */
		props->sig_prot_cap = IB_PROT_T10DIF_TYPE_1 |
				      IB_PROT_T10DIF_TYPE_2 |
				      IB_PROT_T10DIF_TYPE_3;
		props->sig_guard_cap = IB_GUARD_T10DIF_CRC |
				       IB_GUARD_T10DIF_CSUM;
	}
	if (MLX5_CAP_GEN(mdev, drain_sigerr))
		props->device_cap_flags |= IB_DEVICE_SIGNATURE_RESP_PIPE;

	if (MLX5_CAP_GEN(mdev, block_lb_mc))
		props->device_cap_flags |= IB_DEVICE_BLOCK_MULTICAST_LOOPBACK;

	if (MLX5_CAP_GEN(mdev, ipoib_basic_offloads)) {
		props->device_cap_flags |= IB_DEVICE_UD_IP_CSUM;
		props->device_cap_flags |= IB_DEVICE_UD_TSO;
	}

	props->vendor_part_id	   = mdev->pdev->device;
	props->hw_ver		   = mdev->pdev->revision;

	props->max_mr_size	   = ~0ull;
	props->page_size_cap	   = ~(u32)((1ull << MLX5_CAP_GEN(mdev, log_pg_sz)) -1);
	props->max_qp		   = 1 << MLX5_CAP_GEN(mdev, log_max_qp);
	props->max_qp_wr	   = 1 << MLX5_CAP_GEN(mdev, log_max_qp_sz);
	max_rq_sg =  MLX5_CAP_GEN(mdev, max_wqe_sz_rq) /
		     sizeof(struct mlx5_wqe_data_seg);
	max_sq_desc = min((int)MLX5_CAP_GEN(mdev, max_wqe_sz_sq), 512);
	max_sq_sg = (max_sq_desc -
		     sizeof(struct mlx5_wqe_ctrl_seg) -
		     sizeof(struct mlx5_wqe_raddr_seg)) / sizeof(struct mlx5_wqe_data_seg);
	props->max_sge = min(max_rq_sg, max_sq_sg);
	props->max_sge_rd	   = MLX5_MAX_SGE_RD;
	props->max_cq		   = 1 << MLX5_CAP_GEN(mdev, log_max_cq);
	props->max_cqe = (1 << MLX5_CAP_GEN(mdev, log_max_cq_sz)) - 1;
	props->max_mr		   = 1 << MLX5_CAP_GEN(mdev, log_max_mkey);
	props->max_pd		   = 1 << MLX5_CAP_GEN(mdev, log_max_pd);
	props->max_qp_rd_atom	   = 1 << MLX5_CAP_GEN(mdev, log_max_ra_req_qp);
	props->max_qp_init_rd_atom = 1 << MLX5_CAP_GEN(mdev, log_max_ra_res_qp);
	props->max_srq		   = 1 << MLX5_CAP_GEN(mdev, log_max_srq);
	props->max_srq_wr = (1 << MLX5_CAP_GEN(mdev, log_max_srq_sz)) - 1;
	props->local_ca_ack_delay  = MLX5_CAP_GEN(mdev, local_ca_ack_delay);
	props->max_res_rd_atom	   = props->max_qp_rd_atom * props->max_qp;
	props->max_srq_sge	   = max_rq_sg - 1;
	props->max_fast_reg_page_list_len = (unsigned int)-1;
	props->max_indir_reg_mr_list_len = 1 << MLX5_CAP_GEN(mdev, log_max_klm_list_size);
	get_atomic_caps(dev, props, exp);
	props->max_mcast_grp	   = 1 << MLX5_CAP_GEN(mdev, log_max_mcg);
	props->max_mcast_qp_attach = MLX5_CAP_GEN(mdev, max_qp_mcg);
	props->max_total_mcast_qp_attach = props->max_mcast_qp_attach *
					   props->max_mcast_grp;
	props->max_map_per_fmr = INT_MAX; /* no limit in ConnectIB */
	props->max_ah		= INT_MAX;
	props->hca_core_clock = MLX5_CAP_GEN(mdev, device_frequency_khz);
	props->timestamp_mask = 0xFFFFFFFFFFFFFFFFULL;
	props->comp_mask |= IB_DEVICE_ATTR_WITH_TIMESTAMP_MASK |
		IB_DEVICE_ATTR_WITH_HCA_CORE_CLOCK;

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	if (MLX5_CAP_GEN(mdev, pg))
		props->device_cap_flags |= IB_DEVICE_ON_DEMAND_PAGING;
	props->odp_caps = dev->odp_caps;
#endif

	return 0;
}

static int mlx5_ib_query_device(struct ib_device *ibdev,
				struct ib_device_attr *props)
{
	return query_device(ibdev, props, 0);
}

enum mlx5_ib_width {
	MLX5_IB_WIDTH_1X	= 1 << 0,
	MLX5_IB_WIDTH_2X	= 1 << 1,
	MLX5_IB_WIDTH_4X	= 1 << 2,
	MLX5_IB_WIDTH_8X	= 1 << 3,
	MLX5_IB_WIDTH_12X	= 1 << 4
};

static int translate_active_width(struct ib_device *ibdev, u8 active_width,
				  u8 *ib_width)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	int err = 0;

	if (active_width & MLX5_IB_WIDTH_1X) {
		*ib_width = IB_WIDTH_1X;
	} else if (active_width & MLX5_IB_WIDTH_2X) {
		mlx5_ib_warn(dev, "active_width %d is not supported by IB spec\n",
			     (int)active_width);
		err = -EINVAL;
	} else if (active_width & MLX5_IB_WIDTH_4X) {
		*ib_width = IB_WIDTH_4X;
	} else if (active_width & MLX5_IB_WIDTH_8X) {
		*ib_width = IB_WIDTH_8X;
	} else if (active_width & MLX5_IB_WIDTH_12X) {
		*ib_width = IB_WIDTH_12X;
	} else {
		mlx5_ib_dbg(dev, "Invalid active_width %d\n",
			    (int)active_width);
		err = -EINVAL;
	}

	return err;
}

/*
 * TODO: Move to IB core
 */
enum ib_max_vl_num {
	__IB_MAX_VL_0		= 1,
	__IB_MAX_VL_0_1		= 2,
	__IB_MAX_VL_0_3		= 3,
	__IB_MAX_VL_0_7		= 4,
	__IB_MAX_VL_0_14	= 5,
};

enum mlx5_vl_hw_cap {
	MLX5_VL_HW_0	= 1,
	MLX5_VL_HW_0_1	= 2,
	MLX5_VL_HW_0_2	= 3,
	MLX5_VL_HW_0_3	= 4,
	MLX5_VL_HW_0_4	= 5,
	MLX5_VL_HW_0_5	= 6,
	MLX5_VL_HW_0_6	= 7,
	MLX5_VL_HW_0_7	= 8,
	MLX5_VL_HW_0_14	= 15
};

static int translate_max_vl_num(struct ib_device *ibdev, u8 vl_hw_cap,
				u8 *max_vl_num)
{
	switch (vl_hw_cap) {
	case MLX5_VL_HW_0:
		*max_vl_num = __IB_MAX_VL_0;
		break;
	case MLX5_VL_HW_0_1:
		*max_vl_num = __IB_MAX_VL_0_1;
		break;
	case MLX5_VL_HW_0_3:
		*max_vl_num = __IB_MAX_VL_0_3;
		break;
	case MLX5_VL_HW_0_7:
		*max_vl_num = __IB_MAX_VL_0_7;
		break;
	case MLX5_VL_HW_0_14:
		*max_vl_num = __IB_MAX_VL_0_14;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static int mlx5_query_port_ib(struct ib_device *ibdev, u8 port,
			      struct ib_port_attr *props)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_hca_vport_context *rep;
	struct mlx5_ptys_reg *ptys;
	struct mlx5_pmtu_reg *pmtu;
	struct mlx5_pvlc_reg pvlc;
	int err;

	rep = kzalloc(sizeof(*rep), GFP_KERNEL);
	ptys = kzalloc(sizeof(*ptys), GFP_KERNEL);
	pmtu = kzalloc(sizeof(*pmtu), GFP_KERNEL);
	if (!rep || !ptys || !pmtu) {
		err = -ENOMEM;
		goto out;
	}

	memset(props, 0, sizeof(*props));

	/* what if I am pf with dual port */
	err = mlx5_core_query_hca_vport_context(mdev, 0, port, 0, rep);
	if (err)
		goto out;

	props->lid		= rep->lid;
	props->lmc		= rep->lmc;
	props->sm_lid		= rep->sm_lid;
	props->sm_sl		= rep->sm_sl;
	props->state		= rep->vport_state;
	props->phys_state	= rep->port_physical_state;
	props->port_cap_flags	= rep->cap_mask1;
	props->gid_tbl_len	= mlx5_get_gid_table_len(MLX5_CAP_GEN(mdev, gid_table_size));
	props->max_msg_sz	= 1 << MLX5_CAP_GEN(mdev, log_max_msg);
	props->pkey_tbl_len	= mlx5_to_sw_pkey_sz(MLX5_CAP_GEN(mdev, pkey_table_size));
	props->bad_pkey_cntr	= rep->pkey_violation_counter;
	props->qkey_viol_cntr	= rep->qkey_violation_counter;
	props->subnet_timeout	= rep->subnet_timeout;
	props->init_type_reply	= rep->init_type_reply;
	props->grh_required	= rep->grh_required;

	ptys->proto_mask |= MLX5_PTYS_IB;
	ptys->local_port = port;
	err = mlx5_core_access_ptys(mdev, ptys, 0);
	if (err)
		goto out;

	err = translate_active_width(ibdev, ptys->ib_link_width_oper,
				     &props->active_width);
	if (err)
		goto out;

	props->active_speed	= ptys->ib_proto_oper;

	pmtu->local_port = port;
	err = mlx5_core_access_pmtu(mdev, pmtu, 0);
	if (err)
		goto out;

	props->max_mtu		= pmtu->max_mtu;
	props->active_mtu	= pmtu->oper_mtu;

	memset(&pvlc, 0, sizeof(pvlc));
	pvlc.local_port = port;
	err = mlx5_core_access_pvlc(mdev, &pvlc, 0);
	if (err)
		goto out;

	err = translate_max_vl_num(ibdev, pvlc.vl_hw_cap,
				   &props->max_vl_num);
out:
	kfree(rep);
	kfree(ptys);
	kfree(pmtu);
	return err;
}

int mlx5_ib_query_port(struct ib_device *ibdev, u8 port,
		       struct ib_port_attr *props)
{
	switch (mlx5_get_vport_access_method(ibdev)) {
	case MLX5_VPORT_ACCESS_METHOD_MAD:
		return mlx5_query_port_mad_ifc(ibdev, port, props);

	case MLX5_VPORT_ACCESS_METHOD_HCA:
		return mlx5_query_port_ib(ibdev, port, props);

	case MLX5_VPORT_ACCESS_METHOD_NIC:
		return mlx5_query_port_roce(ibdev, port, props);

	default:
		return -EINVAL;
	}

}

static int mlx5_ib_query_gid(struct ib_device *ibdev, u8 port, int index,
			     union ib_gid *gid)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct mlx5_core_dev *mdev = dev->mdev;

	switch (mlx5_get_vport_access_method(ibdev)) {
	case MLX5_VPORT_ACCESS_METHOD_MAD:
		return mlx5_query_gids_mad_ifc(ibdev, port, index, gid);

	case MLX5_VPORT_ACCESS_METHOD_HCA:
		return mlx5_core_query_gids(mdev, 0, port, 0, index,
					    gid);

	case MLX5_VPORT_ACCESS_METHOD_NIC:
		return -ENOSYS;

	default:
		return -EINVAL;
	}

}

static int mlx5_ib_modify_gid(struct ib_device *ibdev, u8 port,
			      unsigned int index, const union ib_gid *gid,
			      const struct ib_gid_attr *attr,
			      __always_unused void **context)
{
	enum rdma_link_layer ll = mlx5_ib_port_link_layer(ibdev, port);

	if (ll != IB_LINK_LAYER_ETHERNET)
		return -EINVAL;

	return modify_gid_roce(ibdev, port, index, gid, attr);
}

static int mlx5_ib_query_pkey(struct ib_device *ibdev, u8 port, u16 index,
			      u16 *pkey)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct mlx5_core_dev *mdev = dev->mdev;

	switch (mlx5_get_vport_access_method(ibdev)) {
	case MLX5_VPORT_ACCESS_METHOD_MAD:
		return mlx5_query_pkey_mad_ifc(ibdev, port, index, pkey);

	case MLX5_VPORT_ACCESS_METHOD_HCA:
	case MLX5_VPORT_ACCESS_METHOD_NIC:
		return mlx5_core_query_pkeys(mdev, 0, port,  0, index,
					     pkey);
	default:
		return -EINVAL;
	}
}

static int mlx5_ib_modify_device(struct ib_device *ibdev, int mask,
				 struct ib_device_modify *props)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct mlx5_reg_node_desc in;
	struct mlx5_reg_node_desc out;
	int err;

	if (mask & ~IB_DEVICE_MODIFY_NODE_DESC)
		return -EOPNOTSUPP;

	if (!(mask & IB_DEVICE_MODIFY_NODE_DESC))
		return 0;

	/*
	 * If possible, pass node desc to FW, so it can generate
	 * a 144 trap.  If cmd fails, just ignore.
	 */
	memcpy(&in, props->node_desc, 64);
	err = mlx5_core_access_reg(dev->mdev, &in, sizeof(in), &out,
				   sizeof(out), MLX5_REG_NODE_DESC, 0, 1);
	if (err)
		return err;

	memcpy(ibdev->node_desc, props->node_desc, 64);

	return err;
}

static int mlx5_ib_modify_port(struct ib_device *ibdev, u8 port, int mask,
			       struct ib_port_modify *props)
{
	u8 is_eth = (mlx5_ib_port_link_layer(ibdev, port) ==
		     IB_LINK_LAYER_ETHERNET);
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct ib_port_attr attr;
	int err;

	/* return OK if this is RoCE. CM calls ib_modify_port() regardless
	 * of whether port link layer is ETH or IB. For ETH ports, qkey
	 * violations and port capabilities are not valid.
	 */
	if (is_eth)
		return 0;

	mutex_lock(&dev->cap_mask_mutex);

	err = mlx5_ib_query_port(ibdev, port, &attr);
	if (err)
		goto out;

	err = mlx5_set_port_caps(dev->mdev, port, props->set_port_cap_mask,
				 props->clr_port_cap_mask, attr.port_cap_flags);

out:
	mutex_unlock(&dev->cap_mask_mutex);
	return err;
}

enum mlx5_cap_flags {
	MLX5_CAP_COMPACT_AV = 1 << 0,
};

static void set_mlx5_flags(u32 *flags, struct mlx5_core_dev *dev)
{
	*flags |= MLX5_CAP_GEN(dev, compact_address_vector) ?
		  MLX5_CAP_COMPACT_AV : 0;
}

static struct ib_ucontext *mlx5_ib_alloc_ucontext(struct ib_device *ibdev,
						  struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct mlx5_ib_alloc_ucontext_req_v2 req;
	struct mlx5_exp_ib_alloc_ucontext_resp resp;
	struct mlx5_ib_ucontext *context;
	struct mlx5_uuar_info *uuari;
	struct mlx5_uar *uars;
	int gross_uuars;
	int num_uars;
	int ver;
	int uuarn;
	int err;
	int i;
	size_t reqlen;

	if (!dev->ib_active)
		return ERR_PTR(-EAGAIN);

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	reqlen = udata->inlen - sizeof(struct ib_uverbs_cmd_hdr);
	if (reqlen == sizeof(struct mlx5_ib_alloc_ucontext_req))
		ver = 0;
	else if (reqlen == sizeof(struct mlx5_ib_alloc_ucontext_req_v2))
		ver = 2;
	else {
		mlx5_ib_err(dev, "request malformed, reqlen: %ld\n", reqlen);
		return ERR_PTR(-EINVAL);
	}

	err = ib_copy_from_udata(&req, udata, reqlen);
	if (err) {
		mlx5_ib_err(dev, "copy failed\n");
		return ERR_PTR(err);
	}

	if (req.reserved) {
		mlx5_ib_err(dev, "request corrupted\n");
		return ERR_PTR(-EINVAL);
	}

	if (req.total_num_uuars == 0 || req.total_num_uuars > MLX5_MAX_UUARS) {
		mlx5_ib_warn(dev, "wrong num_uuars: %d\n", req.total_num_uuars);
		return ERR_PTR(-ENOMEM);
	}

	req.total_num_uuars = ALIGN(req.total_num_uuars,
				    MLX5_NON_FP_BF_REGS_PER_PAGE);
	if (req.num_low_latency_uuars > req.total_num_uuars - 1) {
		mlx5_ib_warn(dev, "wrong num_low_latency_uuars: %d ( > %d)\n",
			     req.total_num_uuars, req.total_num_uuars);
		return ERR_PTR(-EINVAL);
	}

	num_uars = req.total_num_uuars / MLX5_NON_FP_BF_REGS_PER_PAGE;
	gross_uuars = num_uars * MLX5_BF_REGS_PER_PAGE;
	resp.qp_tab_size = 1 << MLX5_CAP_GEN(dev->mdev, log_max_qp);
	if (mlx5_core_is_pf(dev->mdev) && MLX5_CAP_GEN(dev->mdev, bf))
		resp.bf_reg_size = 1 << MLX5_CAP_GEN(dev->mdev, log_bf_reg_size);
	resp.cache_line_size = cache_line_size();
	resp.max_sq_desc_sz = MLX5_CAP_GEN(dev->mdev, max_wqe_sz_sq);
	resp.max_rq_desc_sz = MLX5_CAP_GEN(dev->mdev, max_wqe_sz_rq);
	resp.max_send_wqebb = 1 << MLX5_CAP_GEN(dev->mdev, log_max_qp_sz);
	resp.max_recv_wr = 1 << MLX5_CAP_GEN(dev->mdev, log_max_qp_sz);
	resp.max_srq_recv_wr = 1 << MLX5_CAP_GEN(dev->mdev, log_max_srq_sz);
	set_mlx5_flags(&resp.flags, dev->mdev);

	if (offsetof(struct mlx5_ib_alloc_ucontext_resp, max_desc_sz_sq_dc) < udata->outlen)
		resp.max_desc_sz_sq_dc = MLX5_CAP_GEN(dev->mdev, max_wqe_sz_sq_dc);

	if (offsetof(struct mlx5_ib_alloc_ucontext_resp, atomic_arg_sizes_dc) < udata->outlen)
		resp.atomic_arg_sizes_dc = MLX5_CAP_ATOMIC(dev->mdev, atomic_size_dc);

	resp.exp_data.comp_mask = MLX5_EXP_ALLOC_CTX_RESP_MASK_CQE_VERSION |
				  MLX5_EXP_ALLOC_CTX_RESP_MASK_CQE_COMP_MAX_NUM;
	if (PAGE_SIZE <= 4096)
		resp.exp_data.comp_mask |=  MLX5_EXP_ALLOC_CTX_RESP_MASK_HCA_CORE_CLOCK_OFFSET;

	resp.exp_data.cqe_version = MLX5_CAP_GEN(dev->mdev, cqe_version);
	resp.exp_data.cqe_comp_max_num = MLX5_CAP_GEN(dev->mdev,
						      cqe_compression_max_num);
	resp.exp_data.hca_core_clock_offset =
		offsetof(struct mlx5_init_seg, internal_timer_h) % PAGE_SIZE;

	if (MLX5_CAP_GEN(dev->mdev, roce)) {
		resp.exp_data.comp_mask |= MLX5_EXP_ALLOC_CTX_RESP_MASK_RROCE_UDP_SPORT_MIN |
					   MLX5_EXP_ALLOC_CTX_RESP_MASK_RROCE_UDP_SPORT_MAX;
		resp.exp_data.rroce_udp_sport_min = MLX5_CAP_ROCE(dev->mdev,
								  r_roce_min_src_udp_port);
		resp.exp_data.rroce_udp_sport_max = MLX5_CAP_ROCE(dev->mdev,
								  r_roce_max_src_udp_port);
	}

	context = kzalloc(sizeof(*context), GFP_KERNEL);
	if (!context)
		return ERR_PTR(-ENOMEM);

	uuari = &context->uuari;
	mutex_init(&uuari->lock);
	uars = kcalloc(num_uars, sizeof(*uars), GFP_KERNEL);
	if (!uars) {
		err = -ENOMEM;
		goto out_ctx;
	}

	uuari->bitmap = kcalloc(BITS_TO_LONGS(gross_uuars),
				sizeof(*uuari->bitmap),
				GFP_KERNEL);
	if (!uuari->bitmap) {
		err = -ENOMEM;
		goto out_uar_ctx;
	}
	/*
	 * clear all fast path uuars
	 */
	for (i = 0; i < gross_uuars; i++) {
		uuarn = i & 3;
		if (uuarn == 2 || uuarn == 3)
			set_bit(i, uuari->bitmap);
	}

	uuari->count = kcalloc(gross_uuars, sizeof(*uuari->count), GFP_KERNEL);
	if (!uuari->count) {
		err = -ENOMEM;
		goto out_bitmap;
	}

	for (i = 0; i < num_uars; i++) {
		err = mlx5_cmd_alloc_uar(dev->mdev, &uars[i].index);
		if (err) {
			mlx5_ib_err(dev, "uar alloc failed at %d\n", i);
			goto out_uars;
		}
	}
	for (i = 0; i < MLX5_IB_MAX_CTX_DYNAMIC_UARS; i++)
		context->dynamic_wc_uar_index[i] = MLX5_IB_INVALID_UAR_INDEX;

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	context->ibucontext.invalidate_range = &mlx5_ib_invalidate_range;
#endif

	INIT_LIST_HEAD(&context->vma_private_list);
	INIT_LIST_HEAD(&context->db_page_list);
	spin_lock_init(&context->vma_private_lock);
	mutex_init(&context->db_page_mutex);

	resp.tot_uuars = req.total_num_uuars;
	resp.num_ports = MLX5_CAP_GEN(dev->mdev, num_ports);
	err = ib_copy_to_udata(udata, &resp,
			       min_t(size_t, udata->outlen, sizeof(resp)));
	if (err)
		goto out_uars;

	uuari->ver = ver;
	uuari->num_low_latency_uuars = req.num_low_latency_uuars;
	uuari->uars = uars;
	uuari->num_uars = num_uars;

	if (mlx5_ib_port_link_layer(&dev->ib_dev, 1) ==
	    IB_LINK_LAYER_ETHERNET) {
		err = mlx5_alloc_transport_domain(dev->mdev, &context->tdn);
		if (err)
			goto out_uars;
	}

	return &context->ibucontext;

out_uars:
	for (i--; i >= 0; i--)
		mlx5_cmd_free_uar(dev->mdev, uars[i].index);
	kfree(uuari->count);

out_bitmap:
	kfree(uuari->bitmap);

out_uar_ctx:
	kfree(uars);

out_ctx:
	kfree(context);
	return ERR_PTR(err);
}

static int mlx5_ib_dealloc_ucontext(struct ib_ucontext *ibcontext)
{
	struct mlx5_ib_ucontext *context = to_mucontext(ibcontext);
	struct mlx5_ib_dev *dev = to_mdev(ibcontext->device);
	struct mlx5_uuar_info *uuari = &context->uuari;
	int i;

	if (mlx5_ib_port_link_layer(&dev->ib_dev, 1) ==
	    IB_LINK_LAYER_ETHERNET)
		mlx5_dealloc_transport_domain(dev->mdev, context->tdn);

	for (i = 0; i < uuari->num_uars; i++) {
		if (mlx5_cmd_free_uar(dev->mdev, uuari->uars[i].index))
			mlx5_ib_warn(dev, "failed to free UAR 0x%x\n", uuari->uars[i].index);
	}
	for (i = 0; i < MLX5_IB_MAX_CTX_DYNAMIC_UARS; i++) {
		if (context->dynamic_wc_uar_index[i] != MLX5_IB_INVALID_UAR_INDEX)
			mlx5_cmd_free_uar(dev->mdev, context->dynamic_wc_uar_index[i]);
	}

	kfree(uuari->count);
	kfree(uuari->bitmap);
	kfree(uuari->uars);
	kfree(context);

	return 0;
}

static phys_addr_t uar_index2pfn(struct mlx5_ib_dev *dev, int index)
{
	return (pci_resource_start(dev->mdev->pdev, 0) >> PAGE_SHIFT) + index;
}

static int get_command(unsigned long offset)
{
	return (offset >> MLX5_IB_MMAP_CMD_SHIFT) & MLX5_IB_MMAP_CMD_MASK;
}

static int get_arg(unsigned long offset)
{
	return offset & ((1 << MLX5_IB_MMAP_CMD_SHIFT) - 1);
}

static int get_index(unsigned long offset)
{
	return get_arg(offset);
}

static int get_pg_order(unsigned long offset)
{
	return get_arg(offset);
}

static void  mlx5_ib_vma_open(struct vm_area_struct *area)
{
	/* vma_open is called when a new VMA is created on top of our VMA.
	 * This is done through either mremap flow or split_vma (usually due to mlock,
	 * madvise, munmap, etc.)
	 * We do not support a clone of the vma, as this VMA is strongly hardware related.
	 * Therefore we set the vm_ops of the newly created/cloned VMA to NULL, to
	 * prevent it from calling us again and trying to do incorrect actions.
	 * We assume that the original vma size is exactly a single page, and therefore all
	 * "splitting" operation will not happen to it.
	 */
	area->vm_ops = NULL;
}

static void  mlx5_ib_vma_close(struct vm_area_struct *area)
{
	struct mlx5_ib_vma_private_data *mlx5_ib_vma_priv_data;

	/* It's guaranteed that all VMAs opened on a FD are closed before the file itself is closed, therefor no
	  * sync is needed with the regular closing flow. (e.g. mlx5 ib_dealloc_ucontext)
	  * However need a sync with accessing the vma as part of mlx5_ib_disassociate_ucontext.
	  * The close operation is usually called under mm->mmap_sem except when process is exiting.
	  * The exiting case is handled explicitly as part of mlx5_ib_disassociate_ucontext.
	*/
	mlx5_ib_vma_priv_data = (struct mlx5_ib_vma_private_data *)area->vm_private_data;

	/* setting the vma context pointer to null in the mlx5_ib driver's private data,
	 * to protect a race condition in mlx5_ib_dissassociate_ucontext().
	 */
	mlx5_ib_vma_priv_data->vma = NULL;
	list_del(&mlx5_ib_vma_priv_data->list);
	kfree(mlx5_ib_vma_priv_data);
}

static const struct vm_operations_struct mlx5_ib_vm_ops = {
	.open = mlx5_ib_vma_open,
	.close = mlx5_ib_vma_close
};

static void mlx5_ib_disassociate_ucontext(struct ib_ucontext *ibcontext)
{
	int ret;
	struct vm_area_struct *vma;
	struct mlx5_ib_vma_private_data *vma_private, *n;
	struct mlx5_ib_ucontext *context = to_mucontext(ibcontext);
	struct task_struct *owning_process  = NULL;
	struct mm_struct   *owning_mm       = NULL;

	owning_process = get_pid_task(ibcontext->tgid, PIDTYPE_PID);
	if (!owning_process)
		return;

	owning_mm = get_task_mm(owning_process);
	if (!owning_mm) {
		pr_info("no mm, disassociate ucontext is pending task termination\n");
		while (1) {
			put_task_struct(owning_process);
			msleep(1);
			owning_process = get_pid_task(ibcontext->tgid, PIDTYPE_PID);
			if (!owning_process || owning_process->state == TASK_DEAD) {
				pr_info("disassociate ucontext done, task was terminated\n");
				/* in case task was dead need to release the task struct */
				if (owning_process)
					put_task_struct(owning_process);
				return;
			}
		}
	}

	/* need to protect from a race on closing the vma as part of mlx5_ib_vma_close */
	down_read(&owning_mm->mmap_sem);
	list_for_each_entry_safe(vma_private, n, &context->vma_private_list, list) {
		vma = vma_private->vma;
		ret = zap_vma_ptes(vma, vma->vm_start,
				   PAGE_SIZE);

		BUG_ON(ret);
		/* need to turn off that flag to prevent double untracking VMA on RH 6.2 and some
		  * other kernels.
		*/
		vma->vm_flags &= ~VM_PFNMAP;

		/* context going to be destroyed, should not access ops any more */
		vma->vm_ops = NULL;
		list_del(&vma_private->list);
		kfree(vma_private);
	}
	up_read(&owning_mm->mmap_sem);
	mmput(owning_mm);
	put_task_struct(owning_process);
	return;
}

static void mlx5_ib_set_vma_data(struct vm_area_struct *vma,
				 struct mlx5_ib_ucontext *ctx,
				 struct mlx5_ib_vma_private_data *vma_prv)
{
	struct list_head *vma_head = &ctx->vma_private_list;

	vma_prv->vma = vma;
	vma->vm_private_data = vma_prv;
	vma->vm_ops =  &mlx5_ib_vm_ops;

	list_add(&vma_prv->list, vma_head);
}

static inline bool mlx5_writecombine_available(void)
{
	pgprot_t prot = __pgprot(0);

	if (pgprot_val(pgprot_writecombine(prot)) == pgprot_val(pgprot_noncached(prot)))
		return false;

	return true;
}

static int uar_mmap(struct vm_area_struct *vma, pgprot_t prot, bool is_wc,
		    struct mlx5_uuar_info *uuari, struct mlx5_ib_dev *dev,
		    struct mlx5_ib_ucontext *context)
{
	unsigned long idx;
	phys_addr_t pfn;
	struct mlx5_ib_vma_private_data *vma_prv;

	if (vma->vm_end - vma->vm_start != PAGE_SIZE) {
		mlx5_ib_warn(dev, "wrong size, expected PAGE_SIZE(%ld) got %ld\n",
			     PAGE_SIZE, vma->vm_end - vma->vm_start);
		return -EINVAL;
	}

	idx = get_index(vma->vm_pgoff);
	if (idx >= uuari->num_uars) {
		mlx5_ib_warn(dev, "wrong offset, idx:%ld num_uars:%d\n",
			     idx, uuari->num_uars);
		return -EINVAL;
	}

	pfn = uar_index2pfn(dev, uuari->uars[idx].index);
	mlx5_ib_dbg(dev, "uar idx 0x%lx, pfn 0x%llx\n", idx,
		    (unsigned long long)pfn);

	vma_prv = kzalloc(sizeof(struct mlx5_ib_vma_private_data), GFP_KERNEL);
	if (!vma_prv)
		return -ENOMEM;

	vma->vm_page_prot = prot;
	if (io_remap_pfn_range(vma, vma->vm_start, pfn,
			       PAGE_SIZE, vma->vm_page_prot)) {
		mlx5_ib_err(dev, "io remap failed\n");
		kfree(vma_prv);
		return -EAGAIN;
	}

	mlx5_ib_set_vma_data(vma, context, vma_prv);

	mlx5_ib_dbg(dev, "mapped %s at 0x%lx, PA 0x%llx\n", is_wc ? "WC" : "NC",
		    vma->vm_start, (unsigned long long)pfn << PAGE_SHIFT);

	return 0;
}

static int alloc_and_map_wc(struct mlx5_ib_dev *dev,
			    struct mlx5_ib_ucontext *context, u32 indx,
			    struct vm_area_struct *vma)
{
	phys_addr_t pfn;
	u32 uar_index;
	struct mlx5_ib_vma_private_data *vma_prv;
	int err;

	if (!mlx5_writecombine_available()) {
		mlx5_ib_warn(dev, "write combine not available\n");
		return -EPERM;
	}

	if (vma->vm_end - vma->vm_start != PAGE_SIZE) {
		mlx5_ib_warn(dev, "wrong size, expected PAGE_SIZE(%ld) got %ld\n",
			     PAGE_SIZE, vma->vm_end - vma->vm_start);
		return -EINVAL;
	}

	if (indx >= MLX5_IB_MAX_CTX_DYNAMIC_UARS) {
		mlx5_ib_warn(dev, "wrong offset, idx:%d max:%d\n",
			     indx, MLX5_IB_MAX_CTX_DYNAMIC_UARS);
		return -EINVAL;
	}

	/* Fail if uar already allocated */
	if (context->dynamic_wc_uar_index[indx] != MLX5_IB_INVALID_UAR_INDEX) {
		mlx5_ib_warn(dev, "wrong offset, idx %d is busy\n", indx);
		return -EINVAL;
	}

	err = mlx5_cmd_alloc_uar(dev->mdev, &uar_index);
	if (err) {
		mlx5_ib_warn(dev, "UAR alloc failed\n");
		return err;
	}

	vma_prv = kzalloc(sizeof(struct mlx5_ib_vma_private_data), GFP_KERNEL);
	if (!vma_prv) {
		mlx5_cmd_free_uar(dev->mdev, uar_index);
		return -ENOMEM;
	}

	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	pfn = uar_index2pfn(dev, uar_index);
	if (io_remap_pfn_range(vma, vma->vm_start, pfn,
			       PAGE_SIZE, vma->vm_page_prot)) {
		mlx5_ib_err(dev, "io remap failed\n");
		mlx5_cmd_free_uar(dev->mdev, uar_index);
		kfree(vma_prv);
		return -EAGAIN;
	}
	context->dynamic_wc_uar_index[indx] = uar_index;

	mlx5_ib_set_vma_data(vma, context, vma_prv);

	return 0;
}

static int mlx5_ib_mmap(struct ib_ucontext *ibcontext, struct vm_area_struct *vma)
{
	struct mlx5_ib_ucontext *context = to_mucontext(ibcontext);
	struct mlx5_ib_dev *dev = to_mdev(ibcontext->device);
	struct mlx5_uuar_info *uuari = &context->uuari;
	struct mlx5_dc_tracer *dct;
	unsigned long command;
	int err;
	unsigned long total_size;
	unsigned long order;
	struct ib_cmem *ib_cmem;
	int numa_node;
	phys_addr_t pfn;

	command = get_command(vma->vm_pgoff);
	switch (command) {
	case MLX5_IB_MMAP_MAP_DC_INFO_PAGE:
		if ((MLX5_CAP_GEN(dev->mdev, port_type) !=
		    MLX5_CAP_PORT_TYPE_IB) ||
		    (!mlx5_core_is_pf(dev->mdev)) ||
		    (!MLX5_CAP_GEN(dev->mdev, dc_cnak_trace)))
			return -ENOTSUPP;

		dct = &dev->dctr;
		if (!dct->pg) {
			mlx5_ib_err(dev, "mlx5_ib_mmap DC no page\n");
			return -ENOMEM;
		}

		pfn = page_to_pfn(dct->pg);
		err = remap_pfn_range(vma, vma->vm_start, pfn, dct->size, vma->vm_page_prot);
		if (err) {
			mlx5_ib_err(dev, "mlx5_ib_mmap DC remap_pfn_range failed\n");
			return err;
		}
		break;

	case MLX5_IB_MMAP_REGULAR_PAGE:
		return uar_mmap(vma, pgprot_writecombine(vma->vm_page_prot),
				mlx5_writecombine_available(),
				uuari, dev, context);

		break;

	case MLX5_IB_EXP_MMAP_GET_CONTIGUOUS_PAGES_CPU_NUMA:
	case MLX5_IB_EXP_MMAP_GET_CONTIGUOUS_PAGES_DEV_NUMA:
	case MLX5_IB_MMAP_GET_CONTIGUOUS_PAGES:
		if (command == MLX5_IB_EXP_MMAP_GET_CONTIGUOUS_PAGES_CPU_NUMA)
			numa_node = numa_node_id();
		else if (command == MLX5_IB_EXP_MMAP_GET_CONTIGUOUS_PAGES_DEV_NUMA)
			numa_node = dev_to_node(&dev->mdev->pdev->dev);
		else
			numa_node = -1;
		total_size = vma->vm_end - vma->vm_start;
		order = get_pg_order(vma->vm_pgoff);

		ib_cmem = ib_cmem_alloc_contiguous_pages(ibcontext, total_size,
							 order, numa_node);
		if (IS_ERR(ib_cmem)) {
			mlx5_ib_dbg(dev, "contig allocation failed\n");
			return PTR_ERR(ib_cmem);
		}

		err = ib_cmem_map_contiguous_pages_to_vma(ib_cmem, vma);
		if (err) {
			mlx5_ib_err(dev, "contig map failed\n");
			ib_cmem_release_contiguous_pages(ib_cmem);
			return err;
		}
		break;

	case MLX5_IB_MMAP_WC_PAGE:
		if (!mlx5_writecombine_available()) {
			mlx5_ib_dbg(dev, "write combine not available\n");
			return -EPERM;
		}

		return uar_mmap(vma, pgprot_writecombine(vma->vm_page_prot),
				true, uuari, dev, context);
		break;

	case MLX5_IB_MMAP_NC_PAGE:
		return uar_mmap(vma, pgprot_noncached(vma->vm_page_prot),
				false, uuari, dev, context);
		break;

	case MLX5_IB_EXP_ALLOC_N_MMAP_WC:
		return alloc_and_map_wc(dev, context, get_index(vma->vm_pgoff),
					vma);
		break;

	case MLX5_IB_EXP_MMAP_CORE_CLOCK:
	{
		phys_addr_t pfn;
		struct mlx5_ib_vma_private_data *vma_prv;

		if (vma->vm_end - vma->vm_start != PAGE_SIZE) {
			mlx5_ib_warn(dev, "wrong size, expected PAGE_SIZE(%ld) got %ld\n",
				     PAGE_SIZE, vma->vm_end - vma->vm_start);
			return -EINVAL;
		}

		if (vma->vm_flags & VM_WRITE) {
			mlx5_ib_warn(dev, "wrong access\n");
			return -EINVAL;
		}

		/* Don't expose to user-space information it shouldn't have */
		if (PAGE_SIZE > 4096)
			return -EINVAL;

		vma_prv = kzalloc(sizeof(*vma_prv), GFP_KERNEL);
		if (!vma_prv)
			return -ENOMEM;

		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		pfn = (dev->mdev->iseg_base +
		       offsetof(struct mlx5_init_seg, internal_timer_h)) >>
			PAGE_SHIFT;
		if (io_remap_pfn_range(vma, vma->vm_start, pfn,
				       PAGE_SIZE, vma->vm_page_prot)) {
			mlx5_ib_err(dev, "io remap failed\n");
			kfree(vma_prv);
			return -EAGAIN;
		}

		mlx5_ib_set_vma_data(vma, context, vma_prv);

		mlx5_ib_dbg(dev, "mapped internal timer at 0x%lx, PA 0x%llx\n",
			    vma->vm_start,
			    (unsigned long long)pfn << PAGE_SHIFT);
		break;
	}

	default:
		return -EINVAL;
	}

	return 0;
}

static unsigned long mlx5_ib_get_unmapped_area(struct file *file,
					       unsigned long addr,
					       unsigned long len,
					       unsigned long pgoff,
					       unsigned long flags)
{
	struct mm_struct *mm;
	struct vm_area_struct *vma;
	unsigned long start_addr;
	unsigned long order;
	unsigned long command;

	mm = current->mm;
	if (addr)
		return current->mm->get_unmapped_area(file, addr, len,
						      pgoff, flags);
	command = get_command(pgoff);
	if (command == MLX5_IB_MMAP_REGULAR_PAGE ||
	    command == MLX5_IB_MMAP_WC_PAGE ||
	    command == MLX5_IB_MMAP_NC_PAGE ||
	    command == MLX5_IB_MMAP_MAP_DC_INFO_PAGE ||
	    command == MLX5_IB_EXP_ALLOC_N_MMAP_WC ||
	    command == MLX5_IB_EXP_MMAP_CORE_CLOCK)
		return current->mm->get_unmapped_area(file, addr, len,
						      pgoff, flags);

	if (command != MLX5_IB_MMAP_GET_CONTIGUOUS_PAGES &&
	    command != MLX5_IB_EXP_MMAP_GET_CONTIGUOUS_PAGES_DEV_NUMA &&
	    command != MLX5_IB_EXP_MMAP_GET_CONTIGUOUS_PAGES_CPU_NUMA) {
		pr_warn("get_unmapped_area unsupported command %ld\n", command);
		return -EINVAL;
	}

	order = get_pg_order(pgoff);

	/*
	 * code is based on the huge-pages get_unmapped_area code
	 */
	start_addr = mm->free_area_cache;
	if (len <= mm->cached_hole_size)
		start_addr = TASK_UNMAPPED_BASE;
full_search:
	addr = ALIGN(start_addr, 1 << order);

	for (vma = find_vma(mm, addr); ; vma = vma->vm_next) {
		if (addr > TASK_SIZE - len) {
			if (start_addr != TASK_UNMAPPED_BASE) {
				start_addr = TASK_UNMAPPED_BASE;
				goto full_search;
			}
			return -ENOMEM;
		}

		if (!vma || addr + len <= vma->vm_start)
			return addr;
		addr = ALIGN(vma->vm_end, 1 << order);
	}
}

static int alloc_pa_mkey(struct mlx5_ib_dev *dev, u32 *key, u32 pdn)
{
	struct mlx5_create_mkey_mbox_in *in;
	struct mlx5_mkey_seg *seg;
	struct mlx5_core_mr mr;
	int err;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	seg = &in->seg;
	seg->flags = MLX5_PERM_LOCAL_READ | MLX5_ACCESS_MODE_PA;
	seg->flags_pd = cpu_to_be32(pdn | MLX5_MKEY_LEN64);
	seg->qpn_mkey7_0 = cpu_to_be32(0xffffff << 8);
	seg->start_addr = 0;

	err = mlx5_core_create_mkey(dev->mdev, &mr, in, sizeof(*in),
				    NULL, NULL, NULL);
	if (err) {
		mlx5_ib_warn(dev, "failed to create mkey, %d\n", err);
		goto err_in;
	}

	kfree(in);
	*key = mr.key;

	return 0;

err_in:
	kfree(in);

	return err;
}

static void free_pa_mkey(struct mlx5_ib_dev *dev, u32 key)
{
	struct mlx5_core_mr mr;
	int err;

	memset(&mr, 0, sizeof(mr));
	mr.key = key;
	err = mlx5_core_destroy_mkey(dev->mdev, &mr);
	if (err)
		mlx5_ib_warn(dev, "failed to destroy mkey 0x%x\n", key);
}

static struct ib_pd *mlx5_ib_alloc_pd(struct ib_device *ibdev,
				      struct ib_ucontext *context,
				      struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct mlx5_ib_alloc_pd_resp resp;
	struct mlx5_ib_pd *pd;
	int err;

	pd = kmalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return ERR_PTR(-ENOMEM);

	err = mlx5_core_alloc_pd(to_mdev(ibdev)->mdev, &pd->pdn);
	if (err) {
		mlx5_ib_warn(dev, "pd alloc failed\n");
		kfree(pd);
		return ERR_PTR(err);
	}

	if (context) {
		resp.pdn = pd->pdn;
		if (ib_copy_to_udata(udata, &resp, sizeof(resp))) {
			mlx5_ib_err(dev, "copy failed\n");
			mlx5_core_dealloc_pd(to_mdev(ibdev)->mdev, pd->pdn);
			kfree(pd);
			return ERR_PTR(-EFAULT);
		}
	} else {
		err = alloc_pa_mkey(to_mdev(ibdev), &pd->pa_lkey, pd->pdn);
		if (err) {
			mlx5_ib_err(dev, "alloc mkey failed\n");
			mlx5_core_dealloc_pd(to_mdev(ibdev)->mdev, pd->pdn);
			kfree(pd);
			return ERR_PTR(err);
		}
	}

	return &pd->ibpd;
}

static int mlx5_ib_dealloc_pd(struct ib_pd *pd)
{
	struct mlx5_ib_dev *mdev = to_mdev(pd->device);
	struct mlx5_ib_pd *mpd = to_mpd(pd);

	if (!pd->uobject)
		free_pa_mkey(mdev, mpd->pa_lkey);

	mlx5_core_dealloc_pd(mdev->mdev, mpd->pdn);
	kfree(mpd);

	return 0;
}

static struct mlx5_ib_fs_mc_flow  *get_mc_flow(struct mlx5_ib_qp *mqp,
					       union ib_gid *gid)
{
	struct mlx5_ib_fs_mc_flow *iter;

	list_for_each_entry(iter, &mqp->mc_flows_list.flows_list, list) {
		if (!memcmp(iter->gid.raw, gid->raw, 16))
			return iter;
	}

	return NULL;
}

static int attach_mcg_fs(struct mlx5_ib_dev *dev, struct ib_qp *ibqp,
			 union ib_gid *gid)
{
	struct ib_flow_attr *flow_attr;
	struct ib_flow_spec_eth *eth_flow;
	unsigned int size = sizeof(*flow_attr) + sizeof(*eth_flow);
	struct ib_flow *ib_flow;
	struct mlx5_ib_qp *mqp = to_mqp(ibqp);
	struct mlx5_ib_fs_mc_flow *mc_flow = NULL;
	int err = 0;
	static const char mac_mask[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	WARN_ON_ONCE(MLX5_CAP_GEN(dev->mdev, num_ports) != 1);

	mutex_lock(&mqp->mc_flows_list.lock);
	mc_flow = get_mc_flow(mqp, gid);
	if (mc_flow) {
		mc_flow->refcount++;
		goto unlock;
	}

	flow_attr = kzalloc(size, GFP_KERNEL);
	if (!flow_attr) {
		err = -ENOMEM;
		goto unlock;
	}

	flow_attr->size = size;
	flow_attr->priority = 0;
	flow_attr->num_of_specs = 1;
	flow_attr->port = 1;
	flow_attr->type = IB_FLOW_ATTR_NORMAL;

	eth_flow = (void *)(flow_attr + 1);
	eth_flow->type = IB_FLOW_SPEC_ETH;
	eth_flow->size =  sizeof(*eth_flow);
	memcpy(eth_flow->mask.dst_mac, mac_mask, ETH_ALEN);
	memcpy(eth_flow->val.dst_mac, &gid->raw[10], ETH_ALEN);
	mc_flow = kzalloc(sizeof(*mc_flow), GFP_KERNEL);
	if (!mc_flow) {
		err = -ENOMEM;
		goto free;
	}

	ib_flow  = ib_create_flow(ibqp,
				  flow_attr,
				  IB_FLOW_DOMAIN_USER);
	if (IS_ERR(ib_flow)) {
		err = PTR_ERR(ib_flow);
		goto free;
	}

	mc_flow->ib_flow = ib_flow;
	mc_flow->refcount = 1;
	memcpy(&mc_flow->gid, gid, sizeof(*gid));
	list_add_tail(&mc_flow->list,  &mqp->mc_flows_list.flows_list);

	mutex_unlock(&mqp->mc_flows_list.lock);
	kfree(flow_attr);
	return 0;
free:
	kfree(flow_attr);
	kfree(mc_flow);
unlock:
	mutex_unlock(&mqp->mc_flows_list.lock);
	return err;
}

static int mlx5_ib_mcg_attach(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	struct mlx5_ib_dev *dev = to_mdev(ibqp->device);
	int err;

	if (ibqp->qp_type == IB_QPT_RAW_PACKET)
		err = attach_mcg_fs(dev, ibqp, gid);
	else
		err = mlx5_core_attach_mcg(dev->mdev, gid, ibqp->qp_num);
	if (err)
		mlx5_ib_warn(dev, "failed attaching QPN 0x%x, MGID %pI6\n",
			     ibqp->qp_num, gid->raw);

	return err;
}

static int detach_mcg_fs(struct ib_qp *ibqp, union ib_gid *gid)
{
	struct mlx5_ib_qp *mqp = to_mqp(ibqp);
	struct mlx5_ib_fs_mc_flow *mc_flow;
	int err = 0;

	mutex_lock(&mqp->mc_flows_list.lock);
	mc_flow = get_mc_flow(mqp, gid);
	if (!mc_flow) {
		err = -EINVAL;
		goto unlock;
	}
	if (!--mc_flow->refcount)
		err = ib_destroy_flow(mc_flow->ib_flow);
	list_del(&mc_flow->list);
	kfree(mc_flow);
unlock:
	mutex_unlock(&mqp->mc_flows_list.lock);
	return err;
}

static int mlx5_ib_mcg_detach(struct ib_qp *ibqp, union ib_gid *gid, u16 lid)
{
	struct mlx5_ib_dev *dev = to_mdev(ibqp->device);
	int err;

	if (ibqp->qp_type == IB_QPT_RAW_PACKET)
		err = detach_mcg_fs(ibqp, gid);
	else
		err = mlx5_core_detach_mcg(dev->mdev, gid, ibqp->qp_num);
	if (err)
		mlx5_ib_warn(dev, "failed detaching QPN 0x%x, MGID %pI6\n",
			     ibqp->qp_num, gid->raw);

	return err;
}

static void put_ft(struct mlx5_ib_dev *dev,
		   struct mlx5_ib_fs_prio *prio, bool ft_added)
{
	prio->refcount -= !!ft_added;
	if (!prio->refcount) {
		mlx5_destroy_flow_table(prio->ft);
		prio->ft = NULL;
	}
}

int mlx5_ib_destroy_flow(struct ib_flow *flow_id)
{
	struct mlx5_ib_dev *dev = to_mdev(flow_id->qp->device);
	struct mlx5_ib_fs_handler *handler = container_of(flow_id,
							  struct mlx5_ib_fs_handler,
							  ibflow);
	struct mlx5_ib_fs_handler *iter, *tmp;

	mutex_lock(&dev->fs.lock);

	mlx5_del_flow_rule(handler->rule);

	list_for_each_entry_safe(iter, tmp, &handler->list, list) {
		mlx5_del_flow_rule(iter->rule);
		list_del(&iter->list);
		kfree(iter);
	}

	put_ft(dev, &dev->fs.prios[handler->prio], true);

	mutex_unlock(&dev->fs.lock);

	kfree(handler);

	return 0;
}

static inline bool addr_is_zero(char *addr, ssize_t size)
{
	return (size == 0 || (addr[0] == 0 &&
			      !memcmp(addr, addr + 1, size -1)));
}

static void set_proto(void *outer_c, void *outer_v, u8 mask, u8 val)
{
	MLX5_SET(fte_match_set_lyr_2_4, outer_c, ip_protocol, mask);
	MLX5_SET(fte_match_set_lyr_2_4, outer_v, ip_protocol, val);
}

static void set_tos(void *outer_c, void *outer_v, u8 mask, u8 val)
{
	MLX5_SET(fte_match_set_lyr_2_4, outer_c, ip_ecn, mask);
	MLX5_SET(fte_match_set_lyr_2_4, outer_v, ip_ecn, val);
	MLX5_SET(fte_match_set_lyr_2_4, outer_c, ip_dscp, mask >> 2);
	MLX5_SET(fte_match_set_lyr_2_4, outer_v, ip_dscp, val >> 2);
}

static void set_flow_label(void *misc_c, void *misc_v, u8 mask, u8 val, bool
			   inner)
{
	if (inner) {
		MLX5_SET(fte_match_set_misc, misc_c, inner_ipv6_flow_label, mask);
		MLX5_SET(fte_match_set_misc, misc_v, inner_ipv6_flow_label, val);
	} else {
		MLX5_SET(fte_match_set_misc, misc_c, outer_ipv6_flow_label, mask);
		MLX5_SET(fte_match_set_misc, misc_v, outer_ipv6_flow_label, val);
	}
}

#define LAST_ETH_FIELD vlan_tag
#define LAST_IB_FIELD dst_gid
#define LAST_IPV4_FIELD tos
#define LAST_IPV6_FIELD traffic_class
#define LAST_TCP_UDP_FIELD src_port
#define LAST_TUNNEL_FIELD tunnel_id
#define LAST_FLOW_TAG_FIELD tag_id

/* Field is the last supported field */
#define FIELDS_NOT_SUPPORTED(filter, field)\
	!(addr_is_zero((void *)&filter.field  +\
		       sizeof(filter.field),\
		       sizeof(filter) -\
		       offsetof(typeof(filter), field) -\
		       sizeof(filter.field)))

static int parse_flow_attr(u32 *match_c, u32 *match_v,
			   union ib_flow_spec *ib_spec, u32 *tag_id)
{
	void *misc_params_c = MLX5_ADDR_OF(fte_match_param, match_c,
					   misc_parameters);
	void *misc_params_v = MLX5_ADDR_OF(fte_match_param, match_v,
					   misc_parameters);
	void *headers_c;
	void *headers_v;

	if (ib_spec->type & IB_FLOW_SPEC_INNER) {
		headers_c = MLX5_ADDR_OF(fte_match_param, match_c,
					 inner_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, match_v,
					 inner_headers);
	} else {
		headers_c = MLX5_ADDR_OF(fte_match_param, match_c,
					 outer_headers);
		headers_v = MLX5_ADDR_OF(fte_match_param, match_v,
					 outer_headers);
	}

	switch (ib_spec->type) {
	case IB_FLOW_SPEC_ETH:
	case IB_FLOW_SPEC_ETH | IB_FLOW_SPEC_INNER:
		if (FIELDS_NOT_SUPPORTED(ib_spec->eth.mask, LAST_ETH_FIELD))
			return -ENOTSUPP;

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dmac_47_16),
		       ib_spec->eth.mask.dst_mac, ETH_ALEN);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dmac_47_16),
		       ib_spec->eth.val.dst_mac, ETH_ALEN);

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    smac_47_16),
		       ib_spec->eth.mask.src_mac, ETH_ALEN);
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    smac_47_16),
		       ib_spec->eth.val.src_mac, ETH_ALEN);

		if (ib_spec->eth.mask.vlan_tag) {
			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 cvlan_tag, 1);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 cvlan_tag, 1);

			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 first_vid, ntohs(ib_spec->eth.mask.vlan_tag));
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 first_vid, ntohs(ib_spec->eth.val.vlan_tag));

			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 first_cfi,
				 ntohs(ib_spec->eth.mask.vlan_tag) >> 12);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 first_cfi,
				 ntohs(ib_spec->eth.val.vlan_tag) >> 12);

			MLX5_SET(fte_match_set_lyr_2_4, headers_c,
				 first_prio,
				 ntohs(ib_spec->eth.mask.vlan_tag) >> 13);
			MLX5_SET(fte_match_set_lyr_2_4, headers_v,
				 first_prio,
				 ntohs(ib_spec->eth.val.vlan_tag) >> 13);
		}
		break;
	case IB_FLOW_SPEC_IPV4:
	case IB_FLOW_SPEC_IPV4 | IB_FLOW_SPEC_INNER:
		if (FIELDS_NOT_SUPPORTED(ib_spec->ipv4.mask, LAST_IPV4_FIELD))
			return -ENOTSUPP;

		MLX5_SET(fte_match_set_lyr_2_4, headers_c,
			 ethertype, 0xffff);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 ethertype, 0x0800);

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    src_ip.ipv4.ip),
		       &ib_spec->ipv4.mask.src_ip,
		       sizeof(ib_spec->ipv4.mask.src_ip));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    src_ip.ipv4.ip),
		       &ib_spec->ipv4.val.src_ip,
		       sizeof(ib_spec->ipv4.val.src_ip));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_c,
				    dst_ip.ipv4.ip),
		       &ib_spec->ipv4.mask.dst_ip,
		       sizeof(ib_spec->ipv4.mask.dst_ip));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, headers_v,
				    dst_ip.ipv4.ip),
		       &ib_spec->ipv4.val.dst_ip,
		       sizeof(ib_spec->ipv4.val.dst_ip));

		set_tos(headers_c, headers_v,
			ib_spec->ipv4.mask.tos, ib_spec->ipv4.val.tos);

		set_proto(headers_c, headers_v,
			  ib_spec->ipv4.mask.proto, ib_spec->ipv4.val.proto);
		break;
	case IB_FLOW_SPEC_IPV6:
	case IB_FLOW_SPEC_IPV6 | IB_FLOW_SPEC_INNER:
		if (FIELDS_NOT_SUPPORTED(ib_spec->ipv6.mask, LAST_IPV6_FIELD))
			return -ENOTSUPP;

		MLX5_SET(fte_match_set_lyr_2_4, headers_c,
			 ethertype, 0xffff);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v,
			 ethertype, ETH_P_IPV6);

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4,
				    headers_c, src_ip.ipv6),
		       &ib_spec->ipv6.mask.src_ip,
		       sizeof(ib_spec->ipv6.mask.src_ip));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4,
				    headers_v, src_ip.ipv6),
		       &ib_spec->ipv6.val.src_ip,
		       sizeof(ib_spec->ipv6.val.src_ip));

		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4,
				    headers_c, dst_ip.ipv6),
		       &ib_spec->ipv6.mask.dst_ip,
		       sizeof(ib_spec->ipv6.mask.dst_ip));
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4,
				    headers_v, dst_ip.ipv6),
		       &ib_spec->ipv6.val.dst_ip,
		       sizeof(ib_spec->ipv6.val.dst_ip));

		set_tos(headers_c, headers_v,
			ib_spec->ipv6.mask.traffic_class,
			ib_spec->ipv6.val.traffic_class);

		set_proto(headers_c, headers_v,
			  ib_spec->ipv6.mask.next_hdr,
			  ib_spec->ipv6.val.next_hdr);

		set_flow_label(misc_params_c, misc_params_v,
			       ntohl(ib_spec->ipv6.mask.flow_label),
			       ntohl(ib_spec->ipv6.val.flow_label),
			       ib_spec->type & IB_FLOW_SPEC_INNER);
		break;
	case IB_FLOW_SPEC_TCP:
	case IB_FLOW_SPEC_TCP | IB_FLOW_SPEC_INNER:
		if (FIELDS_NOT_SUPPORTED(ib_spec->tcp_udp.mask,
					 LAST_TCP_UDP_FIELD))
			return -ENOTSUPP;

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_protocol,
			 0xff);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol,
			 IPPROTO_TCP);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, tcp_sport,
			 ntohs(ib_spec->tcp_udp.mask.src_port));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_sport,
			 ntohs(ib_spec->tcp_udp.val.src_port));

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, tcp_dport,
			 ntohs(ib_spec->tcp_udp.mask.dst_port));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, tcp_dport,
			 ntohs(ib_spec->tcp_udp.val.dst_port));
		break;

	case IB_FLOW_SPEC_UDP:
	case IB_FLOW_SPEC_UDP | IB_FLOW_SPEC_INNER:
		if (FIELDS_NOT_SUPPORTED(ib_spec->tcp_udp.mask,
					 LAST_TCP_UDP_FIELD))
			return -ENOTSUPP;

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, ip_protocol,
			 0xff);
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, ip_protocol,
			 IPPROTO_UDP);

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, udp_sport,
			 ntohs(ib_spec->tcp_udp.mask.src_port));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_sport,
			 ntohs(ib_spec->tcp_udp.val.src_port));

		MLX5_SET(fte_match_set_lyr_2_4, headers_c, udp_dport,
			 ntohs(ib_spec->tcp_udp.mask.dst_port));
		MLX5_SET(fte_match_set_lyr_2_4, headers_v, udp_dport,
			 ntohs(ib_spec->tcp_udp.val.dst_port));
		break;
	case IB_FLOW_SPEC_VXLAN_TUNNEL:
		if (FIELDS_NOT_SUPPORTED(ib_spec->tunnel.mask,
					 LAST_TUNNEL_FIELD))
			return -ENOTSUPP;

		MLX5_SET(fte_match_set_misc, misc_params_c, vxlan_vni,
			 ntohl(ib_spec->tunnel.mask.tunnel_id));
		MLX5_SET(fte_match_set_misc, misc_params_v, vxlan_vni,
			 ntohl(ib_spec->tunnel.val.tunnel_id));
		break;
	case IB_FLOW_SPEC_ACTION_TAG:
		if (FIELDS_NOT_SUPPORTED(ib_spec->flow_tag,
					 LAST_FLOW_TAG_FIELD))
			return -ENOTSUPP;
		if (ib_spec->flow_tag.tag_id >= BIT(24))
			return -EINVAL;

		*tag_id = ib_spec->flow_tag.tag_id;
		break;

	default:
		return -EINVAL;
	}

	return 0;
}

static bool flow_is_multicast(struct ib_flow_attr *ib_attr)
{
	struct ib_flow_spec_eth *eth_spec;

	if (ib_attr->type != IB_FLOW_ATTR_NORMAL ||
	    ib_attr->size < sizeof(struct ib_flow_attr) +
	    sizeof(struct ib_flow_spec_eth) ||
	    ib_attr->num_of_specs < 1)
		return false;

	eth_spec = (struct ib_flow_spec_eth *)(ib_attr + 1);
	if (eth_spec->type != IB_FLOW_SPEC_ETH ||
	    eth_spec->size != sizeof(*eth_spec))
		return false;

	return	is_multicast_ether_addr(eth_spec->mask.dst_mac) &&
		is_multicast_ether_addr(eth_spec->val.dst_mac);
}

#define MLX5_BYPASS_LEVEL 0
static struct mlx5_ib_fs_prio *get_ft(struct mlx5_ib_dev *dev,
				      struct ib_flow_attr *flow_attr)
{
	struct mlx5_flow_namespace *ns = NULL;
	unsigned int priority;
	char	     name[FT_NAME_STR_SZ];
	int n_ent, n_grp;
	struct mlx5_ib_fs_prio *prio;
	struct mlx5_flow_table *ft;

	if (flow_attr->type == IB_FLOW_ATTR_NORMAL) {
		if (flow_is_multicast(flow_attr)) {
			priority = MLX5_IB_FS_MCAST_PRIO;
			snprintf(name, sizeof(name), "bypass_mcast");
		} else {
			priority = flow_attr->priority;
			snprintf(name, sizeof(name), "bypass%u", priority + 1);
		}
		ns = mlx5_get_flow_namespace(dev->mdev, MLX5_FLOW_NAMESPACE_BYPASS);
		n_ent = FS_MAX_ENTRIES;
		n_grp = FS_MAX_TYPES;
		prio = &dev->fs.prios[priority];
	} else if (flow_attr->type == IB_FLOW_ATTR_ALL_DEFAULT ||
		   flow_attr->type == IB_FLOW_ATTR_MC_DEFAULT) {
		ns = mlx5_get_flow_namespace(dev->mdev, MLX5_FLOW_NAMESPACE_LEFTOVERS);
		build_leftovers_ft_param(name, &priority, &n_ent, &n_grp);
		prio = &dev->fs.prios[MLX5_IB_FS_LEFTOVERS_PRIO];
	}

	if (!ns)
		return ERR_PTR(-ENOTSUPP);

	ft = prio->ft;
	if (!ft) {
		ft = mlx5_create_auto_grouped_flow_table(ns, priority, name,
							 n_ent, n_grp,
							 MLX5_BYPASS_LEVEL,
							 MLX5_FS_AUTOGROUP_SAVE_SPARE_SPACE);

		if (!IS_ERR(ft)) {
			prio->refcount = 0;
			prio->ft = ft;
		}
	}

	return IS_ERR(ft) ? (void *)ft : prio;
}

static struct mlx5_ib_fs_handler *create_user_normal_rule(struct mlx5_ib_dev *dev,
							  struct mlx5_ib_fs_prio *ft_prio,
							  struct ib_flow_attr *flow_attr,
							  struct mlx5_flow_destination *dst)
{
	struct mlx5_ib_fs_handler *handler;
	struct mlx5_flow_table	*ft = ft_prio->ft;
	u8 match_criteria_enable = 0;
	u32 *match_c;
	u32 *match_v;
	unsigned int spec_index;
	void *ib_flow = flow_attr + 1;
	int err = 0;
	u32 tag_id = MLX5_FS_DEFAULT_FLOW_TAG;

	match_c	= kzalloc(MLX5_ST_SZ_BYTES(fte_match_param), GFP_KERNEL);
	match_v	= kzalloc(MLX5_ST_SZ_BYTES(fte_match_param), GFP_KERNEL);
	handler = kzalloc(sizeof(*handler), GFP_KERNEL);
	if (!handler || !match_c || !match_v) {
		err = -ENOMEM;
		goto free;
	}

	INIT_LIST_HEAD(&handler->list);

	for (spec_index = 0; spec_index < flow_attr->num_of_specs; spec_index++) {
		err = parse_flow_attr(match_c, match_v, ib_flow, &tag_id);
		if (err < 0)
			goto free;

		ib_flow += ((union ib_flow_spec *)ib_flow)->size;
	}

	match_criteria_enable = get_match_criteria_enable(match_c);
	handler->rule = mlx5_add_flow_rule(ft, match_criteria_enable,
					   match_c, match_v,
					   MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
					   tag_id,
					   dst);

	if (IS_ERR(handler->rule)) {
		err = PTR_ERR(handler->rule);
		goto free;
	}

	handler->prio = ft_prio - dev->fs.prios;

	ft_prio->ft = ft;
	ft_prio->refcount++;

	kfree(match_c);
	kfree(match_v);

	return handler;

free:
	kfree(handler);
	kfree(match_c);
	kfree(match_v);

	return ERR_PTR(err);
}
static struct mlx5_ib_fs_handler *create_leftovers_rule(struct mlx5_ib_dev *dev,
							struct mlx5_ib_fs_prio *ft_prio,
							struct ib_flow_attr *flow_attr,
							struct mlx5_flow_destination *dst)
{
	struct mlx5_ib_fs_handler *handler_mcast;
	struct mlx5_ib_fs_handler *handler_ucast = NULL;
	struct mlx5_flow_table	*ft = ft_prio->ft;
	u8 match_criteria_enable = 0;
	u32 *match_c;
	u32 *match_v;
	void *outer_headers_c;
	void *outer_headers_v;
	static const char mcast_mac[ETH_ALEN] = {0x1};
	static const char empty_mac[ETH_ALEN] = {};
	int err = 0;

	match_c	= kzalloc(MLX5_ST_SZ_BYTES(fte_match_param), GFP_KERNEL);
	match_v	= kzalloc(MLX5_ST_SZ_BYTES(fte_match_param), GFP_KERNEL);
	handler_mcast = kzalloc(sizeof(*handler_mcast), GFP_KERNEL);
	if (flow_attr->type == IB_FLOW_ATTR_ALL_DEFAULT)
		handler_ucast = kzalloc(sizeof(*handler_ucast), GFP_KERNEL);

	if (!handler_mcast || !match_c || !match_v ||
	    ((flow_attr->type == IB_FLOW_ATTR_ALL_DEFAULT) && !handler_ucast)) {
		err = -ENOMEM;
		goto free;
	}

	INIT_LIST_HEAD(&handler_mcast->list);
	if (flow_attr->type == IB_FLOW_ATTR_ALL_DEFAULT) {
		INIT_LIST_HEAD(&handler_ucast->list);
		list_add(&handler_ucast->list, &handler_mcast->list);
	}

	outer_headers_c = MLX5_ADDR_OF(fte_match_param, match_c, outer_headers);
	outer_headers_v = MLX5_ADDR_OF(fte_match_param, match_v, outer_headers);
	memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_c, dmac_47_16), mcast_mac, ETH_ALEN);
	memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_v, dmac_47_16), mcast_mac, ETH_ALEN);

	match_criteria_enable = get_match_criteria_enable(match_c);
	handler_mcast->rule = mlx5_add_flow_rule(ft, match_criteria_enable,
						 match_c, match_v,
						 MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
						 MLX5_FS_DEFAULT_FLOW_TAG,
						 dst);

	if (IS_ERR(handler_mcast->rule)) {
		err = PTR_ERR(handler_mcast->rule);
		goto free;
	}

	handler_mcast->prio = ft_prio - dev->fs.prios;

	if (flow_attr->type == IB_FLOW_ATTR_ALL_DEFAULT) {
		memcpy(MLX5_ADDR_OF(fte_match_set_lyr_2_4, outer_headers_v, dmac_47_16), empty_mac, ETH_ALEN);

		match_criteria_enable = get_match_criteria_enable(match_c);
		handler_ucast->rule = mlx5_add_flow_rule(ft, match_criteria_enable,
							 match_c, match_v,
							 MLX5_FLOW_CONTEXT_ACTION_FWD_DEST,
							 MLX5_FS_DEFAULT_FLOW_TAG,
							 dst);

		if (IS_ERR(handler_ucast->rule)) {
			err = PTR_ERR(handler_ucast->rule);
			goto destroy_mcast;
		}

		handler_ucast->prio = ft_prio - dev->fs.prios;
	}

	ft_prio->ft = ft;
	ft_prio->refcount++;

	kfree(match_c);
	kfree(match_v);

	return handler_mcast;

destroy_mcast:
	mlx5_del_flow_rule(handler_mcast->rule);
free:
	kfree(match_c);
	kfree(match_v);
	kfree(handler_mcast);
	kfree(handler_ucast);
	return ERR_PTR(err);
}

static struct ib_flow *mlx5_ib_create_flow(struct ib_qp *qp,
					   struct ib_flow_attr *flow_attr,
					   int domain)
{
	struct mlx5_ib_dev *dev = to_mdev(qp->device);
	int err;
	struct mlx5_flow_destination *dst = NULL;
	struct mlx5_ib_fs_handler *handler = NULL;
	struct mlx5_ib_fs_prio	    *ft_prio;
	struct mlx5_flow_table	    *ft;

	if (flow_attr->priority > MLX5_IB_FS_LAST_PRIO) {
		mlx5_ib_warn(dev, "wrong priority %d\n", flow_attr->priority);
		return ERR_PTR(-ENOSPC);
	}

	if (domain != IB_FLOW_DOMAIN_USER ||
	    flow_attr->port > MLX5_CAP_GEN(dev->mdev, num_ports) ||
	    flow_attr->flags) {
		mlx5_ib_warn(dev, "wrong params\n");
		return ERR_PTR(-EINVAL);
	}

	dst = kzalloc(sizeof(*dst), GFP_KERNEL);
	if (!dst)
		return ERR_PTR(-ENOMEM);

	mutex_lock(&dev->fs.lock);

	ft_prio = get_ft(dev, flow_attr);
	if (IS_ERR(ft_prio)) {
		mlx5_ib_warn(dev, "failed to get priority\n");
		err = PTR_ERR(ft_prio);
		goto unlock;
	}

	ft = ft_prio->ft;

	dst->type = MLX5_FLOW_DESTINATION_TYPE_TIR;
	dst->tir_num = to_mqp(qp)->tirn;

	if (flow_attr->type == IB_FLOW_ATTR_NORMAL) {
		handler = create_user_normal_rule(dev, ft_prio, flow_attr,
						  dst);
	} else if (flow_attr->type == IB_FLOW_ATTR_ALL_DEFAULT ||
		   flow_attr->type == IB_FLOW_ATTR_MC_DEFAULT) {
		handler = create_leftovers_rule(dev, ft_prio, flow_attr,
						dst);
	} else {
		mlx5_ib_warn(dev, "wrong attr type %d\n", flow_attr->type);
		err = -EINVAL;
		goto destroy_ft;
	}

	if (IS_ERR(handler)) {
		mlx5_ib_warn(dev, "failed to create rule\n");
		err = PTR_ERR(handler);
		handler = NULL;
		goto destroy_ft;
	}

	mutex_unlock(&dev->fs.lock);
	kfree(dst);

	return &handler->ibflow;

destroy_ft:
	put_ft(dev, ft_prio, false);
unlock:
	mutex_unlock(&dev->fs.lock);
	kfree(dst);
	kfree(handler);
	return ERR_PTR(err);
}

static int init_node_data(struct mlx5_ib_dev *dev)
{
	int err;

	err = mlx5_query_node_desc(dev, dev->ib_dev.node_desc);
	if (err)
		return err;

	dev->mdev->rev_id = dev->mdev->pdev->revision;

	return mlx5_query_node_guid(dev, &dev->ib_dev.node_guid);
}

static ssize_t show_fw_pages(struct device *device, struct device_attribute *attr,
			     char *buf)
{
	struct mlx5_ib_dev *dev =
		container_of(device, struct mlx5_ib_dev, ib_dev.dev);

	return sprintf(buf, "%d\n", dev->mdev->priv.fw_pages);
}

static ssize_t show_reg_pages(struct device *device,
			      struct device_attribute *attr, char *buf)
{
	struct mlx5_ib_dev *dev =
		container_of(device, struct mlx5_ib_dev, ib_dev.dev);

	return sprintf(buf, "%d\n", atomic_read(&dev->mdev->priv.reg_pages));
}

static ssize_t show_hca(struct device *device, struct device_attribute *attr,
			char *buf)
{
	struct mlx5_ib_dev *dev =
		container_of(device, struct mlx5_ib_dev, ib_dev.dev);
	return sprintf(buf, "MT%d\n", dev->mdev->pdev->device);
}

static ssize_t show_fw_ver(struct device *device, struct device_attribute *attr,
			   char *buf)
{
	struct mlx5_ib_dev *dev =
		container_of(device, struct mlx5_ib_dev, ib_dev.dev);
	return sprintf(buf, "%d.%d.%04d\n", fw_rev_maj(dev->mdev),
		       fw_rev_min(dev->mdev), fw_rev_sub(dev->mdev));
}

static ssize_t show_rev(struct device *device, struct device_attribute *attr,
			char *buf)
{
	struct mlx5_ib_dev *dev =
		container_of(device, struct mlx5_ib_dev, ib_dev.dev);
	return sprintf(buf, "%x\n", dev->mdev->rev_id);
}

static ssize_t show_board(struct device *device, struct device_attribute *attr,
			  char *buf)
{
	struct mlx5_ib_dev *dev =
		container_of(device, struct mlx5_ib_dev, ib_dev.dev);
	return sprintf(buf, "%.*s\n", MLX5_BOARD_ID_LEN,
		       dev->mdev->board_id);
}

static DEVICE_ATTR(hw_rev,   S_IRUGO, show_rev,    NULL);
static DEVICE_ATTR(fw_ver,   S_IRUGO, show_fw_ver, NULL);
static DEVICE_ATTR(hca_type, S_IRUGO, show_hca,    NULL);
static DEVICE_ATTR(board_id, S_IRUGO, show_board,  NULL);
static DEVICE_ATTR(fw_pages, S_IRUGO, show_fw_pages, NULL);
static DEVICE_ATTR(reg_pages, S_IRUGO, show_reg_pages, NULL);

static struct device_attribute *mlx5_class_attributes[] = {
	&dev_attr_hw_rev,
	&dev_attr_fw_ver,
	&dev_attr_hca_type,
	&dev_attr_board_id,
	&dev_attr_fw_pages,
	&dev_attr_reg_pages,
};

static void mlx5_ib_handle_internal_error(struct mlx5_ib_dev *ibdev)
{
	struct mlx5_ib_qp *mqp;
	struct mlx5_ib_cq *send_mcq, *recv_mcq;
	struct mlx5_core_cq *mcq;
	struct list_head cq_armed_list;
	unsigned long flags_qp;
	unsigned long flags_cq;
	unsigned long flags;

	mlx5_ib_warn(ibdev, " started\n");
	INIT_LIST_HEAD(&cq_armed_list);

	/* Go over qp list reside on that ibdev, sync with create/destroy qp.*/
	spin_lock_irqsave(&ibdev->reset_flow_resource_lock, flags);
	list_for_each_entry(mqp, &ibdev->qp_list, qps_list) {
		spin_lock_irqsave(&mqp->sq.lock, flags_qp);
		if (mqp->sq.tail != mqp->sq.head) {
			send_mcq = to_mcq(mqp->ibqp.send_cq);
			spin_lock_irqsave(&send_mcq->lock, flags_cq);
			if (send_mcq->mcq.comp &&
			    mqp->ibqp.send_cq->comp_handler) {
				if (!send_mcq->mcq.reset_notify_added) {
					send_mcq->mcq.reset_notify_added = 1;
					list_add_tail(&send_mcq->mcq.reset_notify,
						      &cq_armed_list);
				}
			}
			spin_unlock_irqrestore(&send_mcq->lock, flags_cq);
		}
		spin_unlock_irqrestore(&mqp->sq.lock, flags_qp);
		spin_lock_irqsave(&mqp->rq.lock, flags_qp);
		/* no handling is needed for SRQ */
		if (!mqp->ibqp.srq) {
			if (mqp->rq.tail != mqp->rq.head) {
				recv_mcq = to_mcq(mqp->ibqp.recv_cq);
				spin_lock_irqsave(&recv_mcq->lock, flags_cq);
				if (recv_mcq->mcq.comp &&
				    mqp->ibqp.recv_cq->comp_handler) {
					if (!recv_mcq->mcq.reset_notify_added) {
						recv_mcq->mcq.reset_notify_added = 1;
						list_add_tail(&recv_mcq->mcq.reset_notify,
							      &cq_armed_list);
					}
				}
				spin_unlock_irqrestore(&recv_mcq->lock,
						       flags_cq);
			}
		}
		spin_unlock_irqrestore(&mqp->rq.lock, flags_qp);
	}
	/*At that point all inflight post send were put to be executed as of we
	 * lock/unlock above locks Now need to arm all involved CQs.
	 */
	list_for_each_entry(mcq, &cq_armed_list, reset_notify) {
		mcq->comp(mcq);
	}
	spin_unlock_irqrestore(&ibdev->reset_flow_resource_lock, flags);
	mlx5_ib_warn(ibdev, " ended\n");
	return;
}

static void mlx5_ib_event(struct mlx5_core_dev *dev, void *context,
			  enum mlx5_dev_event event, unsigned long param)
{
	struct mlx5_ib_dev *ibdev = (struct mlx5_ib_dev *)context;
	struct ib_event ibev;
	int fatal = 0;
	u8 port = 0;

	switch (event) {
	case MLX5_DEV_EVENT_SYS_ERROR:
		ibev.event = IB_EVENT_DEVICE_FATAL;
		mlx5_ib_handle_internal_error(ibdev);
		fatal = 1;
		break;

	case MLX5_DEV_EVENT_PORT_UP:
		ibev.event = IB_EVENT_PORT_ACTIVE;
		port = (u8)param;
		break;

	case MLX5_DEV_EVENT_PORT_DOWN:
	case MLX5_DEV_EVENT_PORT_INITIALIZED:
		ibev.event = IB_EVENT_PORT_ERR;
		port = (u8)param;
		break;

	case MLX5_DEV_EVENT_LID_CHANGE:
		ibev.event = IB_EVENT_LID_CHANGE;
		port = (u8)param;
		break;

	case MLX5_DEV_EVENT_PKEY_CHANGE:
		ibev.event = IB_EVENT_PKEY_CHANGE;
		port = (u8)param;
		break;

	case MLX5_DEV_EVENT_GUID_CHANGE:
		ibev.event = IB_EVENT_GID_CHANGE;
		port = (u8)param;
		break;

	case MLX5_DEV_EVENT_CLIENT_REREG:
		ibev.event = IB_EVENT_CLIENT_REREGISTER;
		port = (u8)param;
		break;
	}

	ibev.device	      = &ibdev->ib_dev;
	ibev.element.port_num = port;

	if ((event != MLX5_DEV_EVENT_SYS_ERROR) &&
	    (port < 1 || port > ibdev->num_ports)) {
		mlx5_ib_warn(ibdev, "warning: event on port %d\n", port);
		return;
	}

	if (ibdev->ib_active)
		ib_dispatch_event(&ibev);

	if (fatal)
		ibdev->ib_active = false;
}

static void get_ext_port_caps(struct mlx5_ib_dev *dev)
{
	int port;

	for (port = 1; port <= MLX5_CAP_GEN(dev->mdev, num_ports); port++)
		mlx5_query_ext_port_caps(dev, port);
}

static void config_atomic_responder(struct mlx5_ib_dev *dev,
				    struct ib_exp_device_attr *props)
{
	enum ib_atomic_cap cap = props->base.atomic_cap;

	if (cap == IB_ATOMIC_HCA ||
	    cap == IB_ATOMIC_GLOB ||
	    cap == IB_ATOMIC_HCA_REPLY_BE)
		dev->enable_atomic_resp = 1;

	dev->atomic_cap = cap;
}

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
static void copy_odp_exp_caps(struct ib_exp_odp_caps *exp_caps,
			      struct ib_odp_caps *caps)
{
	exp_caps->general_odp_caps = caps->general_caps;
	exp_caps->per_transport_caps.rc_odp_caps = caps->per_transport_caps.rc_odp_caps;
	exp_caps->per_transport_caps.uc_odp_caps = caps->per_transport_caps.uc_odp_caps;
	exp_caps->per_transport_caps.ud_odp_caps = caps->per_transport_caps.ud_odp_caps;
}
#endif

enum mlx5_addr_align {
	MLX5_ADDR_ALIGN_0	= 0,
	MLX5_ADDR_ALIGN_64	= 64,
	MLX5_ADDR_ALIGN_128	= 128,
};

int mlx5_ib_exp_query_device(struct ib_device *ibdev,
			     struct ib_exp_device_attr *props)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	int err;
	u32 max_tso;

	err = query_device(ibdev, &props->base, 1);
	if (err)
		return err;

	props->exp_comp_mask = IB_EXP_DEVICE_ATTR_CAP_FLAGS2;
	props->device_cap_flags2 = 0;
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_DC_REQ_RD;
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_DC_RES_RD;
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_MAX_DCT;
	if (MLX5_CAP_GEN(dev->mdev, dct)) {
		props->device_cap_flags2 |= IB_EXP_DEVICE_DC_TRANSPORT;
		props->dc_rd_req = 1 << MLX5_CAP_GEN(dev->mdev, log_max_ra_req_dc);
		props->dc_rd_res = 1 << MLX5_CAP_GEN(dev->mdev, log_max_ra_res_dc);
		props->max_dct = props->base.max_qp;
	} else {
		props->dc_rd_req = 0;
		props->dc_rd_res = 0;
		props->max_dct = 0;
	}

	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_INLINE_RECV_SZ;
	if (MLX5_CAP_GEN(dev->mdev, sctr_data_cqe))
		props->inline_recv_sz = MLX5_MAX_INLINE_RECEIVE_SIZE;
	else
		props->inline_recv_sz = 0;

	props->vlan_offloads = 0;
	if (MLX5_CAP_GEN(dev->mdev, eth_net_offloads)) {
		if (MLX5_CAP_ETH(dev->mdev, csum_cap))
			props->device_cap_flags2 |=
				IB_EXP_DEVICE_RX_CSUM_IP_PKT |
				IB_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT |
				IB_EXP_DEVICE_RX_TCP_UDP_PKT_TYPE;
		if (MLX5_CAP_ETH(dev->mdev, scatter_fcs))
			props->device_cap_flags2 |=
				IB_EXP_DEVICE_SCATTER_FCS;
		if (MLX5_CAP_ETH(dev->mdev, vlan_cap)) {
			props->exp_comp_mask |=
				IB_EXP_DEVICE_ATTR_VLAN_OFFLOADS;
			props->vlan_offloads |= IB_WQ_CVLAN_STRIPPING |
						IB_WQ_CVLAN_INSERTION;
		}

		max_tso = MLX5_CAP_ETH(dev->mdev, max_lso_cap);
		if (max_tso) {
			props->tso_caps.max_tso = 1 << max_tso;
			props->tso_caps.supported_qpts |=
				1 << IB_QPT_RAW_PACKET;
			props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_TSO_CAPS;
		}
	}

	ext_atomic_caps(dev, props);
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_EXT_ATOMIC_ARGS |
				IB_EXP_DEVICE_ATTR_EXT_MASKED_ATOMICS;

	props->device_cap_flags2 |= IB_EXP_DEVICE_NOP;

	props->device_cap_flags2 |= IB_EXP_DEVICE_UMR;
	props->umr_caps.max_reg_descriptors = 1 << MLX5_CAP_GEN(dev->mdev, log_max_klm_list_size);
	props->umr_caps.max_send_wqe_inline_klms = 20;
	props->umr_caps.max_umr_recursion_depth = MLX5_CAP_GEN(dev->mdev, max_indirection);
	props->umr_caps.max_umr_stride_dimenson = 1;
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_UMR;
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_MAX_CTX_RES_DOMAIN;
	props->max_ctx_res_domain = MLX5_IB_MAX_CTX_DYNAMIC_UARS * MLX5_NON_FP_BF_REGS_PER_PAGE;
#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_ODP;
	props->device_cap_flags2 |= IB_EXP_DEVICE_ODP;
	copy_odp_exp_caps(&props->odp_caps, &dev->odp_caps);
#endif

	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_RX_HASH;
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_MAX_WQ_TYPE_RQ;
	if (MLX5_CAP_GEN(dev->mdev, port_type) == MLX5_CAP_PORT_TYPE_ETH) {
		props->rx_hash_caps.max_rwq_indirection_tables = 1 << MLX5_CAP_GEN(dev->mdev, log_max_rqt);
		props->rx_hash_caps.max_rwq_indirection_table_size = 1 << MLX5_CAP_GEN(dev->mdev, log_max_rqt_size);
		props->rx_hash_caps.supported_hash_functions = IB_EX_RX_HASH_FUNC_TOEPLITZ;
		props->rx_hash_caps.supported_packet_fields = IB_RX_HASH_SRC_IPV4 |
									      IB_RX_HASH_DST_IPV4 |
									      IB_RX_HASH_SRC_IPV6 |
									      IB_RX_HASH_DST_IPV6 |
									      IB_RX_HASH_SRC_PORT_TCP |
									      IB_RX_HASH_DST_PORT_TCP |
									      IB_RX_HASH_SRC_PORT_UDP |
									      IB_RX_HASH_DST_PORT_UDP;
		props->rx_hash_caps.supported_qps = IB_EXP_QPT_RAW_PACKET;
		props->max_wq_type_rq = 1 << MLX5_CAP_GEN(dev->mdev, log_max_rq);
	} else {
		memset(&props->rx_hash_caps, 0, sizeof(props->rx_hash_caps));
		props->max_wq_type_rq = 0;
	}

	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_MAX_DEVICE_CTX;
	/*mlx5_core uses NUM_DRIVER_UARS uar pages*/
	/*For simplicity, assume one to one releation ship between uar pages and context*/
	props->max_device_ctx =
		(1 << (MLX5_CAP_GEN(dev->mdev, uar_sz) + 20 - PAGE_SHIFT))
		/ (MLX5_DEF_TOT_UUARS / MLX5_NUM_UUARS_PER_PAGE)
		- NUM_DRIVER_UARS;

	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_MP_RQ;
	if (MLX5_CAP_GEN(dev->mdev, striding_rq)) {
		props->mp_rq_caps.allowed_shifts =  IB_MP_RQ_2BYTES_SHIFT;
		props->mp_rq_caps.supported_qps =  IB_EXP_QPT_RAW_PACKET;
		props->mp_rq_caps.max_single_stride_log_num_of_bytes =  MLX5_MAX_SINGLE_STRIDE_LOG_NUM_BYTES;
		props->mp_rq_caps.min_single_stride_log_num_of_bytes =  MLX5_MIN_SINGLE_STRIDE_LOG_NUM_BYTES;
		props->mp_rq_caps.max_single_wqe_log_num_of_strides =  MLX5_MAX_SINGLE_WQE_LOG_NUM_STRIDES;
		props->mp_rq_caps.min_single_wqe_log_num_of_strides =  MLX5_MIN_SINGLE_WQE_LOG_NUM_STRIDES;
	} else {
		props->mp_rq_caps.supported_qps = 0;
	}

	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_EC_CAPS;
	if (MLX5_CAP_GEN(dev->mdev, vector_calc)) {
		if (MLX5_CAP_VECTOR_CALC(dev->mdev, calc_matrix)  &&
		    MLX5_CAP_VECTOR_CALC(dev->mdev, calc0.op_xor) &&
		    MLX5_CAP_VECTOR_CALC(dev->mdev, calc1.op_xor) &&
		    MLX5_CAP_VECTOR_CALC(dev->mdev, calc2.op_xor) &&
		    MLX5_CAP_VECTOR_CALC(dev->mdev, calc3.op_xor)) {
			props->device_cap_flags2 |= IB_EXP_DEVICE_EC_OFFLOAD;
			props->ec_caps.max_ec_data_vector_count =
				MLX5_CAP_VECTOR_CALC(dev->mdev, max_vec_count);
			/* XXX: Should be MAX_SQ_SIZE / (11 * WQE_BB) */
			props->ec_caps.max_ec_calc_inflight_calcs = 1024;
		}
	}

	props->rx_pad_end_addr_align = MLX5_ADDR_ALIGN_0;
	if (MLX5_CAP_GEN(dev->mdev, end_pad)) {
		if (MLX5_CAP_GEN(dev->mdev, cache_line_128byte) &&
		    (cache_line_size() == 128))
			props->rx_pad_end_addr_align = MLX5_ADDR_ALIGN_128;
		else
			props->rx_pad_end_addr_align = MLX5_ADDR_ALIGN_64;
	}
	props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_RX_PAD_END_ALIGN;

	if (MLX5_CAP_QOS(dev->mdev, packet_pacing) &&
	    MLX5_CAP_GEN(dev->mdev, qos)) {
		props->packet_pacing_caps.qp_rate_limit_max =
			MLX5_CAP_QOS(dev->mdev, packet_pacing_max_rate);
		props->packet_pacing_caps.qp_rate_limit_min =
			MLX5_CAP_QOS(dev->mdev, packet_pacing_min_rate);
		props->packet_pacing_caps.supported_qpts |=
			1 << IB_QPT_RAW_PACKET;
		props->exp_comp_mask |= IB_EXP_DEVICE_ATTR_PACKET_PACING_CAPS;
	}

	return err;
}

static int get_port_caps(struct mlx5_ib_dev *dev)
{
	struct ib_exp_device_attr *dprops = NULL;
	struct ib_port_attr *pprops = NULL;
	int err = -ENOMEM;
	int port;

	pprops = kmalloc(sizeof(*pprops), GFP_KERNEL);
	if (!pprops)
		goto out;

	dprops = kmalloc(sizeof(*dprops), GFP_KERNEL);
	if (!dprops)
		goto out;

	err = mlx5_ib_exp_query_device(&dev->ib_dev, dprops);
	if (err) {
		mlx5_ib_warn(dev, "query_device failed %d\n", err);
		goto out;
	}

	config_atomic_responder(dev, dprops);

	for (port = 1; port <= MLX5_CAP_GEN(dev->mdev, num_ports); port++) {
		err = mlx5_ib_query_port(&dev->ib_dev, port, pprops);
		if (err) {
			mlx5_ib_warn(dev, "query_port %d failed %d\n",
				     port, err);
			break;
		}
		dev->mdev->port_caps[port - 1].pkey_table_len = dprops->base.max_pkeys;
		dev->mdev->port_caps[port - 1].gid_table_len = pprops->gid_tbl_len;
		mlx5_ib_dbg(dev, "pkey_table_len %d, gid_table_len %d\n",
			    dprops->base.max_pkeys, pprops->gid_tbl_len);
	}

out:
	kfree(pprops);
	kfree(dprops);

	return err;
}

static void destroy_umrc_res(struct mlx5_ib_dev *dev)
{
	int err;

	err = mlx5_mr_cache_cleanup(dev);
	if (err)
		mlx5_ib_warn(dev, "mr cache cleanup failed\n");

	mlx5_ib_destroy_qp(dev->umrc.qp);
	ib_destroy_cq(dev->umrc.cq);
	ib_dereg_mr(dev->umrc.mr);
	ib_dealloc_pd(dev->umrc.pd);
}

enum {
	MAX_UMR_WR = 128,
};

static int create_umr_res(struct mlx5_ib_dev *dev)
{
	struct ib_qp_init_attr *init_attr = NULL;
	struct ib_qp_attr *attr = NULL;
	struct ib_pd *pd;
	struct ib_cq *cq;
	struct ib_qp *qp;
	struct ib_mr *mr;
	int ret;

	attr = kzalloc(sizeof(*attr), GFP_KERNEL);
	init_attr = kzalloc(sizeof(*init_attr), GFP_KERNEL);
	if (!attr || !init_attr) {
		ret = -ENOMEM;
		goto error_0;
	}

	pd = ib_alloc_pd(&dev->ib_dev);
	if (IS_ERR(pd)) {
		mlx5_ib_dbg(dev, "Couldn't create PD for sync UMR QP\n");
		ret = PTR_ERR(pd);
		goto error_0;
	}

	mr = ib_get_dma_mr(pd,  IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(mr)) {
		mlx5_ib_dbg(dev, "Couldn't create DMA MR for sync UMR QP\n");
		ret = PTR_ERR(mr);
		goto error_1;
	}

	cq = ib_create_cq(&dev->ib_dev, mlx5_umr_cq_handler, NULL, NULL, 128,
			  0);
	if (IS_ERR(cq)) {
		mlx5_ib_dbg(dev, "Couldn't create CQ for sync UMR QP\n");
		ret = PTR_ERR(cq);
		goto error_2;
	}
	ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);

	init_attr->send_cq = cq;
	init_attr->recv_cq = cq;
	init_attr->sq_sig_type = IB_SIGNAL_ALL_WR;
	init_attr->cap.max_send_wr = MAX_UMR_WR;
	init_attr->cap.max_send_sge = 1;
	init_attr->qp_type = MLX5_IB_QPT_REG_UMR;
	init_attr->port_num = 1;
	qp = mlx5_ib_create_qp(pd, init_attr, NULL);
	if (IS_ERR(qp)) {
		mlx5_ib_dbg(dev, "Couldn't create sync UMR QP\n");
		ret = PTR_ERR(qp);
		goto error_3;
	}
	qp->device     = &dev->ib_dev;
	qp->real_qp    = qp;
	qp->uobject    = NULL;
	qp->qp_type    = MLX5_IB_QPT_REG_UMR;

	attr->qp_state = IB_QPS_INIT;
	attr->port_num = 1;
	ret = mlx5_ib_modify_qp(qp, attr, IB_QP_STATE | IB_QP_PKEY_INDEX |
				IB_QP_PORT, NULL);
	if (ret) {
		mlx5_ib_dbg(dev, "Couldn't modify UMR QP\n");
		goto error_4;
	}

	memset(attr, 0, sizeof(*attr));
	attr->qp_state = IB_QPS_RTR;
	attr->path_mtu = IB_MTU_256;

	ret = mlx5_ib_modify_qp(qp, attr, IB_QP_STATE, NULL);
	if (ret) {
		mlx5_ib_dbg(dev, "Couldn't modify umr QP to rtr\n");
		goto error_4;
	}

	memset(attr, 0, sizeof(*attr));
	attr->qp_state = IB_QPS_RTS;
	ret = mlx5_ib_modify_qp(qp, attr, IB_QP_STATE, NULL);
	if (ret) {
		mlx5_ib_dbg(dev, "Couldn't modify umr QP to rts\n");
		goto error_4;
	}

	dev->umrc.qp = qp;
	dev->umrc.cq = cq;
	dev->umrc.mr = mr;
	dev->umrc.pd = pd;

	sema_init(&dev->umrc.sem, MAX_UMR_WR);
	ret = mlx5_mr_cache_init(dev);
	if (ret) {
		mlx5_ib_warn(dev, "mr cache init failed %d\n", ret);
		goto error_4;
	}

	kfree(attr);
	kfree(init_attr);

	return 0;

error_4:
	mlx5_ib_destroy_qp(qp);

error_3:
	ib_destroy_cq(cq);

error_2:
	ib_dereg_mr(mr);

error_1:
	ib_dealloc_pd(pd);

error_0:
	kfree(attr);
	kfree(init_attr);
	return ret;
}

static int create_dev_resources(struct mlx5_ib_resources *devr)
{
	struct ib_srq_init_attr attr;
	struct mlx5_ib_dev *dev;
	struct ib_cq_init_attr cq_attr;
	int ret = 0;

	dev = container_of(devr, struct mlx5_ib_dev, devr);

	devr->p0 = mlx5_ib_alloc_pd(&dev->ib_dev, NULL, NULL);
	if (IS_ERR(devr->p0)) {
		ret = PTR_ERR(devr->p0);
		goto error0;
	}
	devr->p0->device  = &dev->ib_dev;
	devr->p0->uobject = NULL;
	atomic_set(&devr->p0->usecnt, 0);

	memset(&cq_attr, 0, sizeof(cq_attr));
	cq_attr.cqe = 1;
	devr->c0 = mlx5_ib_create_cq(&dev->ib_dev, &cq_attr, NULL, NULL);
	if (IS_ERR(devr->c0)) {
		ret = PTR_ERR(devr->c0);
		goto error1;
	}
	devr->c0->device        = &dev->ib_dev;
	devr->c0->uobject       = NULL;
	devr->c0->comp_handler  = NULL;
	devr->c0->event_handler = NULL;
	devr->c0->cq_context    = NULL;
	atomic_set(&devr->c0->usecnt, 0);

	devr->x0 = mlx5_ib_alloc_xrcd(&dev->ib_dev, NULL, NULL);
	if (IS_ERR(devr->x0)) {
		ret = PTR_ERR(devr->x0);
		goto error2;
	}
	devr->x0->device = &dev->ib_dev;
	devr->x0->inode = NULL;
	atomic_set(&devr->x0->usecnt, 0);
	mutex_init(&devr->x0->tgt_qp_mutex);
	INIT_LIST_HEAD(&devr->x0->tgt_qp_list);

	devr->x1 = mlx5_ib_alloc_xrcd(&dev->ib_dev, NULL, NULL);
	if (IS_ERR(devr->x1)) {
		ret = PTR_ERR(devr->x1);
		goto error3;
	}
	devr->x1->device = &dev->ib_dev;
	devr->x1->inode = NULL;
	atomic_set(&devr->x1->usecnt, 0);
	mutex_init(&devr->x1->tgt_qp_mutex);
	INIT_LIST_HEAD(&devr->x1->tgt_qp_list);

	memset(&attr, 0, sizeof(attr));
	attr.attr.max_sge = 1;
	attr.attr.max_wr = 1;
	attr.srq_type = IB_SRQT_XRC;
	attr.ext.xrc.cq = devr->c0;
	attr.ext.xrc.xrcd = devr->x0;

	devr->s0 = mlx5_ib_create_srq(devr->p0, &attr, NULL);
	if (IS_ERR(devr->s0)) {
		ret = PTR_ERR(devr->s0);
		goto error4;
	}

	devr->s0->device	= &dev->ib_dev;
	devr->s0->pd		= devr->p0;
	devr->s0->uobject       = NULL;
	devr->s0->event_handler = NULL;
	devr->s0->srq_context   = NULL;
	devr->s0->srq_type      = IB_SRQT_XRC;
	devr->s0->ext.xrc.xrcd	= devr->x0;
	devr->s0->ext.xrc.cq	= devr->c0;
	atomic_inc(&devr->s0->ext.xrc.xrcd->usecnt);
	atomic_inc(&devr->s0->ext.xrc.cq->usecnt);
	atomic_inc(&devr->p0->usecnt);
	atomic_set(&devr->s0->usecnt, 0);

	memset(&attr, 0, sizeof(attr));
	attr.attr.max_sge = 1;
	attr.attr.max_wr = 1;
	attr.srq_type = IB_SRQT_BASIC;
	devr->s1 = mlx5_ib_create_srq(devr->p0, &attr, NULL);
	if (IS_ERR(devr->s1)) {
		ret = PTR_ERR(devr->s0);
		goto error5;
	}
	devr->s1->device	= &dev->ib_dev;
	devr->s1->pd		= devr->p0;
	devr->s1->uobject       = NULL;
	devr->s1->event_handler = NULL;
	devr->s1->srq_context   = NULL;
	devr->s1->srq_type      = IB_SRQT_BASIC;
	devr->s1->ext.xrc.cq	= devr->c0;
	atomic_inc(&devr->p0->usecnt);
	atomic_set(&devr->s0->usecnt, 0);
	return 0;
error5:
	mlx5_ib_destroy_srq(devr->s1);
error4:
	mlx5_ib_dealloc_xrcd(devr->x1);
error3:
	mlx5_ib_dealloc_xrcd(devr->x0);
error2:
	mlx5_ib_destroy_cq(devr->c0);
error1:
	mlx5_ib_dealloc_pd(devr->p0);
error0:
	return ret;
}

static void destroy_dev_resources(struct mlx5_ib_resources *devr)
{
	mlx5_ib_destroy_srq(devr->s1);
	mlx5_ib_destroy_srq(devr->s0);
	mlx5_ib_dealloc_xrcd(devr->x0);
	mlx5_ib_dealloc_xrcd(devr->x1);
	mlx5_ib_destroy_cq(devr->c0);
	mlx5_ib_dealloc_pd(devr->p0);
}

static int mlx5_ib_set_vf_port_guid(struct ib_device *device, u8 port_num,
				    u64 guid)
{
	struct mlx5_ib_dev *dev = to_mdev(device);
	struct mlx5_hca_vport_context *in;
	int err;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	in->field_select = MLX5_HCA_VPORT_SEL_PORT_GUID;
	in->port_guid = guid;
	err = mlx5_core_modify_hca_vport_context(dev->mdev, 0, port_num,
						 port_num - 1, in);

	kfree(in);
	return err;
}

static int mlx5_ib_set_vf_node_guid(struct ib_device *device, u16 vf, u64 guid)
{
	struct mlx5_ib_dev *dev = to_mdev(device);
	struct mlx5_hca_vport_context *in;
	int err;

	switch (mlx5_get_vport_access_method(device)) {
	case MLX5_VPORT_ACCESS_METHOD_MAD:
		return -ENOTSUPP;

	case MLX5_VPORT_ACCESS_METHOD_HCA:
		in = kzalloc(sizeof(*in), GFP_KERNEL);
		if (!in)
			return -ENOMEM;

		in->field_select = MLX5_HCA_VPORT_SEL_NODE_GUID;
		in->node_guid = guid;
		err = mlx5_core_modify_hca_vport_context(dev->mdev, 0, 1, vf, in);

		kfree(in);
		return err;

	case MLX5_VPORT_ACCESS_METHOD_NIC:
		return mlx5_modify_nic_vport_node_guid(dev->mdev, vf + 1, guid);

	default:
		return -EINVAL;
	}
}

static int mlx5_ib_get_vf_stats(struct ib_device *device, u16 vf,
				struct ib_vf_stats *stats)
{
	struct mlx5_ib_dev *dev = to_mdev(device);
	struct mlx5_vport_counters *vc;
	int err;

	vc = kzalloc(sizeof(*vc), GFP_KERNEL);
	if (!vc)
		return -ENOMEM;

	err = mlx5_core_query_vport_counter(dev->mdev, 0, 1,  vf, vc);
	if (err)
		goto ex;

	stats->rx_frames = vc->received_ib_unicast.packets;
	stats->tx_frames = vc->transmitted_ib_unicast.packets;
	stats->rx_bytes = vc->received_ib_unicast.octets;
	stats->tx_bytes = vc->transmitted_ib_unicast.octets;
	stats->rx_errors = vc->received_errors.packets;
	stats->tx_errors = vc->transmit_errors.packets;
	stats->rx_dropped = vc->received_errors.packets;
	stats->tx_dropped = vc->transmit_errors.packets;
	stats->rx_mcast = vc->received_ib_multicast.packets;

ex:
	kfree(vc);
	return err;
}

static void enable_dc_tracer(struct mlx5_ib_dev *dev)
{
	struct device *device = dev->ib_dev.dma_device;
	struct mlx5_dc_tracer *dct = &dev->dctr;
	int order;
	void *tmp;
	int size;
	int err;

	size = MLX5_CAP_GEN(dev->mdev, num_ports) * 4096;
	if (size <= PAGE_SIZE)
		order = 0;
	else
		order = 1;

	dct->pg = alloc_pages(GFP_KERNEL, order);
	if (!dct->pg) {
		mlx5_ib_err(dev, "failed to allocate %d pages\n", order);
		return;
	}

	tmp = kmap(dct->pg);
	if (!tmp) {
		mlx5_ib_err(dev, "failed to kmap one page\n");
		err = -ENOMEM;
		goto map_err;
	}

	memset(tmp, 0xff, size);
	kunmap(dct->pg);

	dct->size = size;
	dct->order = order;
	dct->dma = dma_map_page(device, dct->pg, 0, size, DMA_FROM_DEVICE);
	if (dma_mapping_error(device, dct->dma)) {
		mlx5_ib_err(dev, "dma mapping error\n");
		goto map_err;
	}

	err = mlx5_core_set_dc_cnak_trace(dev->mdev, 1, dct->dma);
	if (err) {
		mlx5_ib_warn(dev, "failed to enable DC tracer\n");
		goto cmd_err;
	}

	return;

cmd_err:
	dma_unmap_page(device, dct->dma, size, DMA_FROM_DEVICE);
map_err:
	__free_pages(dct->pg, dct->order);
	dct->pg = NULL;
}

static void disable_dc_tracer(struct mlx5_ib_dev *dev)
{
	struct device *device = dev->ib_dev.dma_device;
	struct mlx5_dc_tracer *dct = &dev->dctr;
	int err;

	if (!dct->pg)
		return;

	err = mlx5_core_set_dc_cnak_trace(dev->mdev, 0, dct->dma);
	if (err) {
		mlx5_ib_warn(dev, "failed to disable DC tracer\n");
		return;
	}

	dma_unmap_page(device, dct->dma, dct->size, DMA_FROM_DEVICE);
	__free_pages(dct->pg, dct->order);
	dct->pg = NULL;
}

enum {
	MLX5_DC_CNAK_SIZE		= 128,
	MLX5_NUM_BUF_IN_PAGE		= PAGE_SIZE / MLX5_DC_CNAK_SIZE,
	MLX5_CNAK_TX_CQ_SIGNAL_FACTOR	= 128,
	MLX5_DC_CNAK_SL			= 0,
	MLX5_DC_CNAK_VL			= 0,
};

static void dump_buf(void *buf, int size)
{
	__be32 *p = buf;
	int offset;
	int i;

	for (i = 0, offset = 0; i < size; i += 16) {
		pr_info("%03x: %08x %08x %08x %08x\n", offset, be32_to_cpu(p[0]),
			be32_to_cpu(p[1]), be32_to_cpu(p[2]), be32_to_cpu(p[3]));
		p += 4;
		offset += 16;
	}
	pr_info("\n");
}

enum {
	CNAK_LENGTH_WITHOUT_GRH	= 32,
	CNAK_LENGTH_WITH_GRH	= 72,
};

static struct mlx5_dc_desc *get_desc_from_index(struct mlx5_dc_desc *desc, u64 index, unsigned *offset)
{
	struct mlx5_dc_desc *d;

	int i;
	int j;

	i = index / MLX5_NUM_BUF_IN_PAGE;
	j = index % MLX5_NUM_BUF_IN_PAGE;
	d = desc + i;
	*offset = j * MLX5_DC_CNAK_SIZE;
	return d;
}

static void build_cnak_msg(void *rbuf, void *sbuf, u32 *length, u16 *dlid)
{
	void *rdceth, *sdceth;
	void *rlrh, *slrh;
	void *rgrh, *sgrh;
	void *rbth, *sbth;
	int is_global;
	void *saeth;

	memset(sbuf, 0, MLX5_DC_CNAK_SIZE);
	rlrh = rbuf;
	is_global = MLX5_GET(lrh, rlrh, lnh) == 0x3;
	rgrh = is_global ? rlrh + MLX5_ST_SZ_BYTES(lrh) : NULL;
	rbth = rgrh ? rgrh + MLX5_ST_SZ_BYTES(grh) : rlrh + MLX5_ST_SZ_BYTES(lrh);
	rdceth = rbth + MLX5_ST_SZ_BYTES(bth);

	slrh = sbuf;
	sgrh = is_global ? slrh + MLX5_ST_SZ_BYTES(lrh) : NULL;
	sbth = sgrh ? sgrh + MLX5_ST_SZ_BYTES(grh) : slrh + MLX5_ST_SZ_BYTES(lrh);
	sdceth = sbth + MLX5_ST_SZ_BYTES(bth);
	saeth = sdceth + MLX5_ST_SZ_BYTES(dceth);

	*dlid = MLX5_GET(lrh, rlrh, slid);
	MLX5_SET(lrh, slrh, vl, MLX5_DC_CNAK_VL);
	MLX5_SET(lrh, slrh, lver, MLX5_GET(lrh, rlrh, lver));
	MLX5_SET(lrh, slrh, sl, MLX5_DC_CNAK_SL);
	MLX5_SET(lrh, slrh, lnh, MLX5_GET(lrh, rlrh, lnh));
	MLX5_SET(lrh, slrh, dlid, MLX5_GET(lrh, rlrh, slid));
	MLX5_SET(lrh, slrh, pkt_len, 0x9 + ((is_global ? MLX5_ST_SZ_BYTES(grh) : 0) >> 2));
	MLX5_SET(lrh, slrh, slid, MLX5_GET(lrh, rlrh, dlid));

	if (is_global) {
		void *rdgid, *rsgid;
		void *ssgid, *sdgid;

		MLX5_SET(grh, sgrh, ip_version, MLX5_GET(grh, rgrh, ip_version));
		MLX5_SET(grh, sgrh, traffic_class, MLX5_GET(grh, rgrh, traffic_class));
		MLX5_SET(grh, sgrh, flow_label, MLX5_GET(grh, rgrh, flow_label));
		MLX5_SET(grh, sgrh, payload_length, 0x1c);
		MLX5_SET(grh, sgrh, next_header, 0x1b);
		MLX5_SET(grh, sgrh, hop_limit, MLX5_GET(grh, rgrh, hop_limit));

		rdgid = MLX5_ADDR_OF(grh, rgrh, dgid);
		rsgid = MLX5_ADDR_OF(grh, rgrh, sgid);
		ssgid = MLX5_ADDR_OF(grh, sgrh, sgid);
		sdgid = MLX5_ADDR_OF(grh, sgrh, dgid);
		memcpy(ssgid, rdgid, 16);
		memcpy(sdgid, rsgid, 16);
		*length = CNAK_LENGTH_WITH_GRH;
	} else {
		*length = CNAK_LENGTH_WITHOUT_GRH;
	}

	MLX5_SET(bth, sbth, opcode, 0x51);
	MLX5_SET(bth, sbth, migreq, 0x1);
	MLX5_SET(bth, sbth, p_key, MLX5_GET(bth, rbth, p_key));
	MLX5_SET(bth, sbth, dest_qp, MLX5_GET(dceth, rdceth, dci_dct));
	MLX5_SET(bth, sbth, psn, MLX5_GET(bth, rbth, psn));

	MLX5_SET(dceth, sdceth, dci_dct, MLX5_GET(bth, rbth, dest_qp));

	MLX5_SET(aeth, saeth, syndrome, 0x64);

	if (0) {
		pr_info("===dump packet ====\n");
		dump_buf(sbuf, *length);
	}
}

static int reduce_tx_pending(struct mlx5_dc_data *dcd, int num)
{
	struct mlx5_ib_dev *dev = dcd->dev;
	struct ib_cq *cq = dcd->scq;
	unsigned int send_completed;
	unsigned int polled;
	struct ib_wc wc;
	int n;

	while (num > 0) {
		n = ib_poll_cq(cq, 1, &wc);
		if (unlikely(n < 0)) {
			mlx5_ib_warn(dev, "error polling cnak send cq\n");
			return n;
		}
		if (unlikely(!n))
			return -EAGAIN;

		if (unlikely(wc.status != IB_WC_SUCCESS)) {
			mlx5_ib_warn(dev, "cnak send completed with error, status %d vendor_err %d\n",
				     wc.status, wc.vendor_err);
			dcd->last_send_completed++;
			dcd->tx_pending--;
			num--;
		} else {
			send_completed = wc.wr_id;
			polled = send_completed - dcd->last_send_completed;
			dcd->tx_pending = (unsigned int)(dcd->cur_send - send_completed);
			num -= polled;
			dcd->cnaks += polled;
			dcd->last_send_completed = send_completed;
		}
	}

	return 0;
}

static int send_cnak(struct mlx5_dc_data *dcd, struct mlx5_send_wr *mlx_wr,
		     u64 rcv_buff_id)
{
	struct ib_send_wr *wr = &mlx_wr->wr;
	struct mlx5_ib_dev *dev = dcd->dev;
	struct ib_send_wr *bad_wr;
	struct mlx5_dc_desc *rxd;
	struct mlx5_dc_desc *txd;
	unsigned int offset;
	unsigned int cur;
	__be32 *sbuf;
	void *rbuf;
	int err;

	if (unlikely(dcd->tx_pending > dcd->max_wqes)) {
		mlx5_ib_warn(dev, "SW error in cnak send: tx_pending(%d) > max_wqes(%d)\n",
			     dcd->tx_pending, dcd->max_wqes);
		return -EFAULT;
	}

	if (unlikely(dcd->tx_pending == dcd->max_wqes)) {
		err = reduce_tx_pending(dcd, 1);
		if (err)
			return err;
		if (dcd->tx_pending == dcd->max_wqes)
			return -EAGAIN;
	}

	cur = dcd->cur_send;
	txd = get_desc_from_index(dcd->txdesc, cur % dcd->max_wqes, &offset);
	sbuf = txd->buf + offset;

	wr->sg_list[0].addr = txd->dma + offset;
	wr->sg_list[0].lkey = dcd->mr->lkey;
	wr->opcode = IB_WR_SEND;
	wr->num_sge = 1;
	wr->wr_id = cur;
	if (cur % MLX5_CNAK_TX_CQ_SIGNAL_FACTOR)
		wr->send_flags &= ~IB_SEND_SIGNALED;
	else
		wr->send_flags |= IB_SEND_SIGNALED;

	rxd = get_desc_from_index(dcd->rxdesc, rcv_buff_id, &offset);
	rbuf = rxd->buf + offset;
	build_cnak_msg(rbuf, sbuf, &wr->sg_list[0].length, &mlx_wr->sel.mlx.dlid);

	mlx_wr->sel.mlx.sl = MLX5_DC_CNAK_SL;
	mlx_wr->sel.mlx.icrc = 1;

	err = ib_post_send(dcd->dcqp, wr, &bad_wr);
	if (likely(!err)) {
		dcd->tx_pending++;
		dcd->cur_send++;
	}

	return err;
}

static int mlx5_post_one_rxdc(struct mlx5_dc_data *dcd, int index)
{
	struct ib_recv_wr *bad_wr;
	struct ib_recv_wr wr;
	struct ib_sge sge;
	u64 addr;
	int err;
	int i;
	int j;

	i = index / (PAGE_SIZE / MLX5_DC_CNAK_SIZE);
	j = index % (PAGE_SIZE / MLX5_DC_CNAK_SIZE);
	addr = dcd->rxdesc[i].dma + j * MLX5_DC_CNAK_SIZE;

	memset(&wr, 0, sizeof(wr));
	wr.num_sge = 1;
	sge.addr = addr;
	sge.length = MLX5_DC_CNAK_SIZE;
	sge.lkey = dcd->mr->lkey;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr_id = index;
	err = ib_post_recv(dcd->dcqp, &wr, &bad_wr);
	if (unlikely(err))
		mlx5_ib_warn(dcd->dev, "failed to post dc rx buf at index %d\n", index);

	return err;
}

static void dc_cnack_rcv_comp_handler(struct ib_cq *cq, void *cq_context)
{
	struct mlx5_dc_data *dcd = cq_context;
	struct mlx5_ib_dev *dev = dcd->dev;
	struct mlx5_send_wr mlx_wr;
	struct ib_send_wr *wr = &mlx_wr.wr;
	struct ib_wc *wc = dcd->wc_tbl;
	struct ib_sge sge;
	int err;
	int n;
	int i;

	memset(&mlx_wr, 0, sizeof(mlx_wr));
	wr->sg_list = &sge;

	n = ib_poll_cq(cq, MLX5_CNAK_RX_POLL_CQ_QUOTA, wc);
	if (unlikely(n < 0)) {
		/* mlx5 never returns negative values but leave a message just in case */
		mlx5_ib_warn(dev, "failed to poll cq (%d), aborting\n", n);
		return;
	}
	if (likely(n > 0)) {
		for (i = 0; i < n; i++) {
			if (dev->mdev->state == MLX5_DEVICE_STATE_INTERNAL_ERROR)
				return;

			if (unlikely(wc[i].status != IB_WC_SUCCESS)) {
				mlx5_ib_warn(dev, "DC cnak: completed with error, status = %d vendor_err = %d\n",
					     wc[i].status, wc[i].vendor_err);
			} else {
				dcd->connects++;
				if (unlikely(send_cnak(dcd, &mlx_wr, wc[i].wr_id)))
					mlx5_ib_warn(dev, "DC cnak: failed to allocate send buf - dropped\n");
			}

			if (unlikely(mlx5_post_one_rxdc(dcd, wc[i].wr_id))) {
				dcd->discards++;
				mlx5_ib_warn(dev, "DC cnak: repost rx failed, will leak rx queue\n");
			}
		}
	}

	err = ib_req_notify_cq(cq, IB_CQ_NEXT_COMP);
	if (unlikely(err))
		mlx5_ib_warn(dev, "DC cnak: failed to re-arm receive cq (%d)\n", err);
}

static int alloc_dc_buf(struct mlx5_dc_data *dcd, int rx)
{
	struct mlx5_ib_dev *dev = dcd->dev;
	struct mlx5_dc_desc **desc;
	struct mlx5_dc_desc *d;
	struct device *ddev;
	int max_wqes;
	int err = 0;
	int npages;
	int totsz;
	int i;

	ddev = &dev->mdev->pdev->dev;
	max_wqes = dcd->max_wqes;
	totsz = max_wqes * MLX5_DC_CNAK_SIZE;
	npages = DIV_ROUND_UP(totsz, PAGE_SIZE);
	desc = rx ? &dcd->rxdesc : &dcd->txdesc;
	*desc = kcalloc(npages, sizeof(*dcd->rxdesc), GFP_KERNEL);
	if (!*desc) {
		err = -ENOMEM;
		goto out;
	}

	for (i = 0; i < npages; i++) {
		d = *desc + i;
		d->buf = dma_alloc_coherent(ddev, PAGE_SIZE, &d->dma, GFP_KERNEL);
		if (!d->buf) {
			mlx5_ib_err(dev, "dma alloc failed at %d\n", i);
			goto out_free;
		}
	}
	if (rx)
		dcd->rx_npages = npages;
	else
		dcd->tx_npages = npages;

	return 0;

out_free:
	for (i--; i >= 0; i--) {
		d = *desc + i;
		dma_free_coherent(ddev, PAGE_SIZE, d->buf, d->dma);
	}
	kfree(*desc);
out:
	return err;
}

static int alloc_dc_rx_buf(struct mlx5_dc_data *dcd)
{
	return alloc_dc_buf(dcd, 1);
}

static int alloc_dc_tx_buf(struct mlx5_dc_data *dcd)
{
	return alloc_dc_buf(dcd, 0);
}

static void free_dc_buf(struct mlx5_dc_data *dcd, int rx)
{
	struct mlx5_ib_dev *dev = dcd->dev;
	struct mlx5_dc_desc *desc;
	struct mlx5_dc_desc *d;
	struct device *ddev;
	int npages;
	int i;

	ddev = &dev->mdev->pdev->dev;
	npages = rx ? dcd->rx_npages : dcd->tx_npages;
	desc = rx ? dcd->rxdesc : dcd->txdesc;
	for (i = 0; i < npages; i++) {
		d = desc + i;
		dma_free_coherent(ddev, PAGE_SIZE, d->buf, d->dma);
	}
	kfree(desc);
}

static void free_dc_rx_buf(struct mlx5_dc_data *dcd)
{
	free_dc_buf(dcd, 1);
}

static void free_dc_tx_buf(struct mlx5_dc_data *dcd)
{
	free_dc_buf(dcd, 0);
}

struct dc_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx5_dc_data *, struct dc_attribute *, char *buf);
	ssize_t (*store)(struct mlx5_dc_data *, struct dc_attribute *,
			 const char *buf, size_t count);
};

#define DC_ATTR(_name, _mode, _show, _store) \
struct dc_attribute dc_attr_##_name = __ATTR(_name, _mode, _show, _store)

static ssize_t rx_connect_show(struct mlx5_dc_data *dcd,
			       struct dc_attribute *unused,
			       char *buf)
{
	unsigned long num;

	num = dcd->connects;

	return sprintf(buf, "%lu\n", num);
}

static ssize_t tx_cnak_show(struct mlx5_dc_data *dcd,
			    struct dc_attribute *unused,
			    char *buf)
{
	unsigned long num;

	num = dcd->cnaks;

	return sprintf(buf, "%lu\n", num);
}

static ssize_t tx_discard_show(struct mlx5_dc_data *dcd,
			       struct dc_attribute *unused,
			       char *buf)
{
	unsigned long num;

	num = dcd->discards;

	return sprintf(buf, "%lu\n", num);
}

#define DC_ATTR_RO(_name) \
struct dc_attribute dc_attr_##_name = __ATTR_RO(_name)

static DC_ATTR_RO(rx_connect);
static DC_ATTR_RO(tx_cnak);
static DC_ATTR_RO(tx_discard);

static struct attribute *dc_attrs[] = {
	&dc_attr_rx_connect.attr,
	&dc_attr_tx_cnak.attr,
	&dc_attr_tx_discard.attr,
	NULL
};

static ssize_t dc_attr_show(struct kobject *kobj,
			    struct attribute *attr, char *buf)
{
	struct dc_attribute *dc_attr = container_of(attr, struct dc_attribute, attr);
	struct mlx5_dc_data *d = container_of(kobj, struct mlx5_dc_data, kobj);

	if (!dc_attr->show)
		return -EIO;

	return dc_attr->show(d, dc_attr, buf);
}

static const struct sysfs_ops dc_sysfs_ops = {
	.show = dc_attr_show
};

static struct kobj_type dc_type = {
	.sysfs_ops     = &dc_sysfs_ops,
	.default_attrs = dc_attrs
};

static int init_sysfs(struct mlx5_ib_dev *dev)
{
	struct device *device = &dev->ib_dev.dev;

	dev->dc_kobj = kobject_create_and_add("dct", &device->kobj);
	if (!dev->dc_kobj) {
		mlx5_ib_err(dev, "failed to register DCT sysfs object\n");
		return -ENOMEM;
	}

	return 0;
}

static void cleanup_sysfs(struct mlx5_ib_dev *dev)
{
	if (dev->dc_kobj) {
		kobject_put(dev->dc_kobj);
		dev->dc_kobj = NULL;
	}
}

static int init_port_sysfs(struct mlx5_dc_data *dcd)
{
	return kobject_init_and_add(&dcd->kobj, &dc_type, dcd->dev->dc_kobj,
				    "%d", dcd->port);
}

static void cleanup_port_sysfs(struct mlx5_dc_data *dcd)
{
	kobject_put(&dcd->kobj);
}

static int init_driver_cnak(struct mlx5_ib_dev *dev, int port)
{
	int ncqe = 1 << MLX5_CAP_GEN(dev->mdev, log_max_qp_sz);
	struct mlx5_dc_data *dcd = &dev->dcd[port - 1];
	struct mlx5_ib_resources *devr = &dev->devr;
	struct ib_qp_init_attr init_attr;
	struct ib_pd *pd = devr->p0;
	struct ib_qp_attr attr;
	int err;
	int i;

	dcd->dev = dev;
	dcd->port = port;
	dcd->mr = ib_get_dma_mr(pd,  IB_ACCESS_LOCAL_WRITE);
	if (IS_ERR(dcd->mr)) {
		mlx5_ib_warn(dev, "failed to create dc DMA MR\n");
		err = PTR_ERR(dcd->mr);
		goto error1;
	}

	dcd->rcq = ib_create_cq(&dev->ib_dev, dc_cnack_rcv_comp_handler, NULL,
				dcd, ncqe, 0);
	if (IS_ERR(dcd->rcq)) {
		err = PTR_ERR(dcd->rcq);
		mlx5_ib_warn(dev, "failed to create dc cnack rx cq (%d)\n", err);
		goto error2;
	}

	err = ib_req_notify_cq(dcd->rcq, IB_CQ_NEXT_COMP);
	if (err) {
		mlx5_ib_warn(dev, "failed to setup dc cnack rx cq (%d)\n", err);
		goto error3;
	}

	dcd->scq = ib_create_cq(&dev->ib_dev, NULL, NULL,
				dcd, ncqe, 0);
	if (IS_ERR(dcd->scq)) {
		err = PTR_ERR(dcd->scq);
		mlx5_ib_warn(dev, "failed to create dc cnack tx cq (%d)\n", err);
		goto error3;
	}

	memset(&init_attr, 0, sizeof(init_attr));
	init_attr.qp_type = MLX5_IB_QPT_SW_CNAK;
	init_attr.cap.max_recv_wr = ncqe;
	init_attr.cap.max_recv_sge = 1;
	init_attr.cap.max_send_wr = ncqe;
	init_attr.cap.max_send_sge = 1;
	init_attr.sq_sig_type = IB_SIGNAL_REQ_WR;
	init_attr.recv_cq = dcd->rcq;
	init_attr.send_cq = dcd->scq;
	dcd->dcqp = ib_create_qp(pd, &init_attr);
	if (IS_ERR(dcd->dcqp)) {
		mlx5_ib_warn(dev, "failed to create qp (%d)\n", err);
		err = PTR_ERR(dcd->dcqp);
		goto error4;
	}

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IB_QPS_INIT;
	attr.port_num = port;
	err = ib_modify_qp(dcd->dcqp, &attr,
			   IB_QP_STATE | IB_QP_PKEY_INDEX | IB_QP_PORT);
	if (err) {
		mlx5_ib_warn(dev, "failed to modify qp to init\n");
		goto error5;
	}

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IB_QPS_RTR;
	attr.path_mtu = IB_MTU_4096;
	err = ib_modify_qp(dcd->dcqp, &attr, IB_QP_STATE);
	if (err) {
		mlx5_ib_warn(dev, "failed to modify qp to rtr\n");
		goto error5;
	}

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IB_QPS_RTS;
	err = ib_modify_qp(dcd->dcqp, &attr, IB_QP_STATE);
	if (err) {
		mlx5_ib_warn(dev, "failed to modify qp to rts\n");
		goto error5;
	}

	dcd->max_wqes = ncqe;
	err = alloc_dc_rx_buf(dcd);
	if (err) {
		mlx5_ib_warn(dev, "failed to allocate rx buf\n");
		goto error5;
	}

	err = alloc_dc_tx_buf(dcd);
	if (err) {
		mlx5_ib_warn(dev, "failed to allocate tx buf\n");
		goto error6;
	}

	for (i = 0; i < ncqe; i++) {
		err = mlx5_post_one_rxdc(dcd, i);
		if (err)
			goto error7;
	}

	err = init_port_sysfs(dcd);
	if (err) {
		mlx5_ib_warn(dev, "failed to initialize DC cnak sysfs\n");
		goto error7;
	}

	dcd->initialized = 1;
	return 0;

error7:
	free_dc_tx_buf(dcd);
error6:
	free_dc_rx_buf(dcd);
error5:
	if (ib_destroy_qp(dcd->dcqp))
		mlx5_ib_warn(dev, "failed to destroy dc qp\n");
error4:
	if (ib_destroy_cq(dcd->scq))
		mlx5_ib_warn(dev, "failed to destroy dc scq\n");
error3:
	if (ib_destroy_cq(dcd->rcq))
		mlx5_ib_warn(dev, "failed to destroy dc rcq\n");
error2:
	ib_dereg_mr(dcd->mr);
error1:
	return err;
}

static void cleanup_driver_cnak(struct mlx5_ib_dev *dev, int port)
{
	struct mlx5_dc_data *dcd = &dev->dcd[port - 1];

	if (!dcd->initialized)
		return;

	cleanup_port_sysfs(dcd);

	if (ib_destroy_qp(dcd->dcqp))
		mlx5_ib_warn(dev, "destroy qp failed\n");

	if (ib_destroy_cq(dcd->scq))
		mlx5_ib_warn(dev, "destroy scq failed\n");

	if (ib_destroy_cq(dcd->rcq))
		mlx5_ib_warn(dev, "destroy rcq failed\n");

	ib_dereg_mr(dcd->mr);
	free_dc_tx_buf(dcd);
	free_dc_rx_buf(dcd);
	dcd->initialized = 0;
}

static int init_dc_improvements(struct mlx5_ib_dev *dev)
{
	int port;
	int err;

	if (!mlx5_core_is_pf(dev->mdev))
		return 0;

	if (!(MLX5_CAP_GEN(dev->mdev, dc_cnak_trace)))
		return 0;

	enable_dc_tracer(dev);

	err = init_sysfs(dev);
	if (err)
		return err;

	if (!MLX5_CAP_GEN(dev->mdev, dc_connect_qp))
		return 0;

	for (port = 1; port <= MLX5_CAP_GEN(dev->mdev, num_ports); port++) {
		err = init_driver_cnak(dev, port);
		if (err)
			goto out;
	}

	return 0;

out:
	for (port--; port >= 1; port--)
		cleanup_driver_cnak(dev, port);

	cleanup_sysfs(dev);

	return err;
}

static void cleanup_dc_improvements(struct mlx5_ib_dev *dev)
{
	int port;

	for (port = 1; port <= MLX5_CAP_GEN(dev->mdev, num_ports); port++)
		cleanup_driver_cnak(dev, port);
	cleanup_sysfs(dev);

	disable_dc_tracer(dev);
}

static void mlx5_ib_dealloc_q_port_counter(struct mlx5_ib_dev *dev, u8 port_num)
{
	mlx5_vport_dealloc_q_counter(dev->mdev,
				     MLX5_INTERFACE_PROTOCOL_IB,
				     dev->port[port_num].q_cnt_id);
	dev->port[port_num].q_cnt_id = 0;
}

static void mlx5_ib_dealloc_q_counters(struct mlx5_ib_dev *dev)
{
	unsigned int i;

	for (i = 0; i < dev->num_ports; i++)
		mlx5_ib_dealloc_q_port_counter(dev, i);
}

static int mlx5_ib_alloc_q_counters(struct mlx5_ib_dev *dev)
{
	int i;
	int ret;

	for (i = 0; i < dev->num_ports; i++) {
		ret = mlx5_vport_alloc_q_counter(dev->mdev,
						 MLX5_INTERFACE_PROTOCOL_IB,
						 &dev->port[i].q_cnt_id);
		if (ret) {
			mlx5_ib_warn(dev,
				     "couldn't allocate queue counter for port %d\n",
				     i + 1);
			goto dealloc_counters;
		}
	}

	return 0;

dealloc_counters:
	while (--i >= 0)
		mlx5_ib_dealloc_q_port_counter(dev, i);

	return ret;
}

struct port_attribute {
	struct attribute attr;
	ssize_t (*show)(struct mlx5_ib_port *,
			struct port_attribute *, char *buf);
	ssize_t (*store)(struct mlx5_ib_port *,
			 struct port_attribute *,
			 const char *buf, size_t count);
};

struct port_counter_attribute {
	struct port_attribute	attr;
	size_t			offset;
};

static ssize_t port_attr_show(struct kobject *kobj,
			      struct attribute *attr, char *buf)
{
	struct port_attribute *port_attr =
		container_of(attr, struct port_attribute, attr);
	struct mlx5_ib_port_sysfs_group *p =
		container_of(kobj, struct mlx5_ib_port_sysfs_group,
			     kobj);
	struct mlx5_ib_port *mibport = container_of(p, struct mlx5_ib_port,
						    group);

	if (!port_attr->show)
		return -EIO;

	return port_attr->show(mibport, port_attr, buf);
}

static ssize_t show_port_counter(struct mlx5_ib_port *p,
				 struct port_attribute *port_attr,
				 char *buf)
{
	int outlen = MLX5_ST_SZ_BYTES(query_q_counter_out);
	struct port_counter_attribute *counter_attr =
		container_of(port_attr, struct port_counter_attribute, attr);
	void *out;
	int ret;

	out = mlx5_vzalloc(outlen);
	if (!out)
		return -ENOMEM;

	ret = mlx5_vport_query_q_counter(p->dev->mdev,
					 p->q_cnt_id, 0,
					 out, outlen);
	if (ret)
		goto free;

	ret = sprintf(buf, "%u\n",
		      be32_to_cpu(*(__be32 *)(out + counter_attr->offset)));

free:
	kfree(out);
	return ret;
}

#define PORT_COUNTER_ATTR(_name)					\
struct port_counter_attribute port_counter_attr_##_name = {		\
	.attr  = __ATTR(_name, S_IRUGO, show_port_counter, NULL),	\
	.offset = MLX5_BYTE_OFF(query_q_counter_out, _name)		\
}

static PORT_COUNTER_ATTR(rx_write_requests);
static PORT_COUNTER_ATTR(rx_read_requests);
static PORT_COUNTER_ATTR(rx_atomic_requests);
static PORT_COUNTER_ATTR(rx_dct_connect);
static PORT_COUNTER_ATTR(out_of_buffer);
static PORT_COUNTER_ATTR(out_of_sequence);
static PORT_COUNTER_ATTR(duplicate_request);
static PORT_COUNTER_ATTR(rnr_nak_retry_err);
static PORT_COUNTER_ATTR(packet_seq_err);
static PORT_COUNTER_ATTR(implied_nak_seq_err);
static PORT_COUNTER_ATTR(local_ack_timeout_err);

static struct attribute *counter_attrs[] = {
	&port_counter_attr_rx_write_requests.attr.attr,
	&port_counter_attr_rx_read_requests.attr.attr,
	&port_counter_attr_rx_atomic_requests.attr.attr,
	&port_counter_attr_rx_dct_connect.attr.attr,
	&port_counter_attr_out_of_buffer.attr.attr,
	&port_counter_attr_out_of_sequence.attr.attr,
	&port_counter_attr_duplicate_request.attr.attr,
	&port_counter_attr_rnr_nak_retry_err.attr.attr,
	&port_counter_attr_packet_seq_err.attr.attr,
	&port_counter_attr_implied_nak_seq_err.attr.attr,
	&port_counter_attr_local_ack_timeout_err.attr.attr,
	NULL
};

static struct attribute_group port_counters_group = {
	.name  = "counters",
	.attrs  = counter_attrs
};

static const struct sysfs_ops port_sysfs_ops = {
	.show = port_attr_show
};

static struct kobj_type port_type = {
	.sysfs_ops     = &port_sysfs_ops,
};

static int add_port_attrs(struct mlx5_ib_dev *dev,
			  struct kobject *parent,
			  struct mlx5_ib_port_sysfs_group *port,
			  u8 port_num)
{
	int ret;

	ret = kobject_init_and_add(&port->kobj, &port_type,
				   parent,
				   "%d", port_num);
	if (ret)
		return ret;

	if (MLX5_CAP_GEN(dev->mdev, out_of_seq_cnt) &&
	    MLX5_CAP_GEN(dev->mdev, retransmission_q_counters)) {
		ret = sysfs_create_group(&port->kobj, &port_counters_group);
		if (ret)
			goto put_kobj;
	}

	port->enabled = true;
	return ret;

put_kobj:
	kobject_put(&port->kobj);
	return ret;
}

static void destroy_ports_attrs(struct mlx5_ib_dev *dev,
				unsigned int num_ports)
{
	unsigned int i;

	for (i = 0; i < num_ports; i++) {
		struct mlx5_ib_port_sysfs_group *port =
			&dev->port[i].group;

		if (!port->enabled)
			continue;

		if (MLX5_CAP_GEN(dev->mdev, out_of_seq_cnt) &&
		    MLX5_CAP_GEN(dev->mdev, retransmission_q_counters))
			sysfs_remove_group(&port->kobj,
					   &port_counters_group);
		kobject_put(&port->kobj);
		port->enabled = false;
	}

	if (dev->ports_parent) {
		kobject_put(dev->ports_parent);
		dev->ports_parent = NULL;
	}
}

static int create_port_attrs(struct mlx5_ib_dev *dev)
{
	int ret = 0;
	unsigned int i = 0;
	struct device *device = &dev->ib_dev.dev;

	dev->ports_parent = kobject_create_and_add("mlx5_ports",
						   &device->kobj);
	if (!dev->ports_parent)
		return -ENOMEM;

	for (i = 0; i < dev->num_ports; i++) {
		ret = add_port_attrs(dev,
				     dev->ports_parent,
				     &dev->port[i].group,
				     i + 1);

		if (ret)
			goto _destroy_ports_attrs;
	}

	return 0;

_destroy_ports_attrs:
	destroy_ports_attrs(dev, i);
	return ret;
}

static void *mlx5_ib_add(struct mlx5_core_dev *mdev)
{
	struct mlx5_ib_dev *dev;
	int err;
	int i;

	printk_once(KERN_INFO "%s", mlx5_version);

	dev = (struct mlx5_ib_dev *)ib_alloc_device(sizeof(*dev));
	if (!dev)
		return NULL;

	dev->mdev = mdev;

	dev->port = kcalloc(MLX5_CAP_GEN(mdev, num_ports), sizeof(*dev->port),
			     GFP_KERNEL);
	if (!dev->port)
		goto err_dealloc;

	for (i = 0; i < MLX5_CAP_GEN(mdev, num_ports); i++) {
		dev->port[i].dev = dev;
		dev->port[i].port_num = i;
	}

	err = get_port_caps(dev);
	if (err)
		goto err_free_port;

	for (i = 0; i < MLX5_CAP_GEN(dev->mdev, num_ports); i++)
		if (mlx5_ib_port_link_layer(&dev->ib_dev, i + 1) ==
			IB_LINK_LAYER_INFINIBAND)
			mlx5_set_port_status(dev->mdev, MLX5_PORT_UP, i + 1);

	if (mlx5_use_mad_ifc(dev))
		get_ext_port_caps(dev);
	if (mlx5_ib_port_link_layer(&dev->ib_dev, 1) ==
	    IB_LINK_LAYER_ETHERNET) {
		if (MLX5_CAP_GEN(mdev, roce)) {
			err = mlx5_nic_vport_enable_roce(mdev);
			if (err)
				goto err_free_port;
		} else {
			goto err_free_port;
		}
	}

	MLX5_INIT_DOORBELL_LOCK(&dev->uar_lock);

	strlcpy(dev->ib_dev.name, "mlx5_%d", IB_DEVICE_NAME_MAX);
	dev->ib_dev.owner		= THIS_MODULE;
	dev->ib_dev.node_type		= RDMA_NODE_IB_CA;
	dev->ib_dev.local_dma_lkey	= mdev->special_contexts.resd_lkey;
	dev->num_ports		= MLX5_CAP_GEN(mdev, num_ports);
	dev->ib_dev.phys_port_cnt     = dev->num_ports;
	dev->ib_dev.num_comp_vectors    =
		dev->mdev->priv.eq_table.num_comp_vectors;
	dev->ib_dev.dma_device	= &mdev->pdev->dev;

	dev->ib_dev.uverbs_abi_ver	= MLX5_IB_UVERBS_ABI_VERSION;
	dev->ib_dev.uverbs_cmd_mask	=
		(1ull << IB_USER_VERBS_CMD_GET_CONTEXT)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_DEVICE)	|
		(1ull << IB_USER_VERBS_CMD_QUERY_PORT)		|
		(1ull << IB_USER_VERBS_CMD_ALLOC_PD)		|
		(1ull << IB_USER_VERBS_CMD_DEALLOC_PD)		|
		(1ull << IB_USER_VERBS_CMD_REG_MR)		|
		(1ull << IB_USER_VERBS_CMD_DEREG_MR)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL)	|
		(1ull << IB_USER_VERBS_CMD_CREATE_CQ)		|
		(1ull << IB_USER_VERBS_CMD_RESIZE_CQ)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_CQ)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_QP)		|
		(1ull << IB_USER_VERBS_CMD_MODIFY_QP)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_QP)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_QP)		|
		(1ull << IB_USER_VERBS_CMD_ATTACH_MCAST)	|
		(1ull << IB_USER_VERBS_CMD_DETACH_MCAST)	|
		(1ull << IB_USER_VERBS_CMD_CREATE_SRQ)		|
		(1ull << IB_USER_VERBS_CMD_MODIFY_SRQ)		|
		(1ull << IB_USER_VERBS_CMD_QUERY_SRQ)		|
		(1ull << IB_USER_VERBS_CMD_DESTROY_SRQ)		|
		(1ull << IB_USER_VERBS_CMD_CREATE_XSRQ)		|
		(1ull << IB_USER_VERBS_CMD_OPEN_QP);
	dev->ib_dev.uverbs_ex_cmd_mask =
		(1ull << IB_USER_VERBS_EX_CMD_QUERY_DEVICE)	|
		(1ull << IB_USER_VERBS_EX_CMD_CREATE_FLOW)	|
		(1ull << IB_USER_VERBS_EX_CMD_DESTROY_FLOW);
	dev->ib_dev.uverbs_exp_cmd_mask	=
		(1ull << IB_USER_VERBS_EXP_CMD_REG_MR_EX)       |
#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
		(1ull << IB_USER_VERBS_EXP_CMD_PREFETCH_MR)	|
#endif
		(1ull << IB_USER_VERBS_EXP_CMD_MODIFY_QP)	|
		(1ull << IB_USER_VERBS_EXP_CMD_CREATE_CQ)	|
		(1ull << IB_USER_VERBS_EXP_CMD_MODIFY_CQ);

	dev->ib_dev.query_device	= mlx5_ib_query_device;
	dev->ib_dev.query_port		= mlx5_ib_query_port;
	dev->ib_dev.get_link_layer	= mlx5_ib_port_link_layer;
	dev->ib_dev.get_netdev		= mlx5_ib_get_netdev;
	dev->ib_dev.query_gid		= mlx5_ib_query_gid;
	dev->ib_dev.modify_gid		= mlx5_ib_modify_gid;
	dev->ib_dev.query_pkey		= mlx5_ib_query_pkey;
	dev->ib_dev.modify_device	= mlx5_ib_modify_device;
	dev->ib_dev.modify_port		= mlx5_ib_modify_port;
	dev->ib_dev.alloc_ucontext	= mlx5_ib_alloc_ucontext;
	dev->ib_dev.dealloc_ucontext	= mlx5_ib_dealloc_ucontext;
	dev->ib_dev.mmap		= mlx5_ib_mmap;
	dev->ib_dev.get_unmapped_area	= mlx5_ib_get_unmapped_area;
	dev->ib_dev.alloc_pd		= mlx5_ib_alloc_pd;
	dev->ib_dev.dealloc_pd		= mlx5_ib_dealloc_pd;
	dev->ib_dev.create_ah		= mlx5_ib_create_ah;
	dev->ib_dev.query_ah		= mlx5_ib_query_ah;
	dev->ib_dev.destroy_ah		= mlx5_ib_destroy_ah;
	dev->ib_dev.create_srq		= mlx5_ib_create_srq;
	dev->ib_dev.modify_srq		= mlx5_ib_modify_srq;
	dev->ib_dev.query_srq		= mlx5_ib_query_srq;
	dev->ib_dev.destroy_srq		= mlx5_ib_destroy_srq;
	dev->ib_dev.post_srq_recv	= mlx5_ib_post_srq_recv;
	dev->ib_dev.create_qp		= mlx5_ib_create_qp;
	dev->ib_dev.modify_qp		= mlx5_ib_modify_qp;
	dev->ib_dev.query_qp		= mlx5_ib_query_qp;
	dev->ib_dev.destroy_qp		= mlx5_ib_destroy_qp;
	dev->ib_dev.post_send		= mlx5_ib_post_send;
	dev->ib_dev.post_recv		= mlx5_ib_post_recv;
	dev->ib_dev.create_cq		= mlx5_ib_create_cq;
	dev->ib_dev.modify_cq		= mlx5_ib_modify_cq;
	dev->ib_dev.resize_cq		= mlx5_ib_resize_cq;
	dev->ib_dev.destroy_cq		= mlx5_ib_destroy_cq;
	dev->ib_dev.poll_cq		= mlx5_ib_poll_cq;
	dev->ib_dev.req_notify_cq	= mlx5_ib_arm_cq;
	dev->ib_dev.get_dma_mr		= mlx5_ib_get_dma_mr;
	dev->ib_dev.reg_user_mr		= mlx5_ib_reg_user_mr;
	dev->ib_dev.dereg_mr		= mlx5_ib_dereg_mr;
	dev->ib_dev.destroy_mr		= mlx5_ib_destroy_mr;
	dev->ib_dev.attach_mcast	= mlx5_ib_mcg_attach;
	dev->ib_dev.detach_mcast	= mlx5_ib_mcg_detach;
	dev->ib_dev.create_flow		= mlx5_ib_create_flow;
	dev->ib_dev.destroy_flow	= mlx5_ib_destroy_flow;
	dev->ib_dev.process_mad		= mlx5_ib_process_mad;
	dev->ib_dev.create_mr		= mlx5_ib_create_mr;
	dev->ib_dev.alloc_fast_reg_mr	= mlx5_ib_alloc_fast_reg_mr;
	dev->ib_dev.alloc_fast_reg_page_list = mlx5_ib_alloc_fast_reg_page_list;
	dev->ib_dev.free_fast_reg_page_list  = mlx5_ib_free_fast_reg_page_list;
	dev->ib_dev.check_mr_status	= mlx5_ib_check_mr_status;
	dev->ib_dev.alloc_indir_reg_list = mlx5_ib_alloc_indir_reg_list;
	dev->ib_dev.free_indir_reg_list  = mlx5_ib_free_indir_reg_list;
	dev->ib_dev.disassociate_ucontext = mlx5_ib_disassociate_ucontext;

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	dev->ib_dev.exp_prefetch_mr	= mlx5_ib_prefetch_mr;
#endif

	mlx5_ib_internal_fill_odp_caps(dev);

	if (MLX5_CAP_GEN(mdev, xrc)) {
		dev->ib_dev.alloc_xrcd = mlx5_ib_alloc_xrcd;
		dev->ib_dev.dealloc_xrcd = mlx5_ib_dealloc_xrcd;
		dev->ib_dev.uverbs_cmd_mask |=
			(1ull << IB_USER_VERBS_CMD_OPEN_XRCD) |
			(1ull << IB_USER_VERBS_CMD_CLOSE_XRCD);
	}
	dev->ib_dev.set_vf_port_guid = mlx5_ib_set_vf_port_guid;
	dev->ib_dev.set_vf_node_guid = mlx5_ib_set_vf_node_guid;
	dev->ib_dev.get_vf_stats = mlx5_ib_get_vf_stats;

	if (MLX5_CAP_GEN(mdev, dct)) {
		dev->ib_dev.exp_create_dct = mlx5_ib_create_dct;
		dev->ib_dev.exp_destroy_dct = mlx5_ib_destroy_dct;
		dev->ib_dev.exp_query_dct = mlx5_ib_query_dct;
		dev->ib_dev.exp_arm_dct = mlx5_ib_arm_dct;
		dev->ib_dev.uverbs_exp_cmd_mask |=
			(1ull << IB_USER_VERBS_EXP_CMD_CREATE_DCT)	|
			(1ull << IB_USER_VERBS_EXP_CMD_DESTROY_DCT)	|
			(1ull << IB_USER_VERBS_EXP_CMD_QUERY_DCT)	|
			(1ull << IB_USER_VERBS_EXP_CMD_ARM_DCT);
	}
	dev->ib_dev.uverbs_exp_cmd_mask |= (1ull << IB_USER_VERBS_EXP_CMD_CREATE_MR);

	dev->ib_dev.exp_create_qp = mlx5_ib_exp_create_qp;
	dev->ib_dev.uverbs_exp_cmd_mask |= (1ull << IB_USER_VERBS_EXP_CMD_CREATE_QP);

	dev->ib_dev.exp_query_device = mlx5_ib_exp_query_device;
	dev->ib_dev.uverbs_exp_cmd_mask	|= (1 << IB_USER_VERBS_EXP_CMD_QUERY_DEVICE);
	dev->ib_dev.exp_query_mkey	= mlx5_ib_exp_query_mkey;
	dev->ib_dev.uverbs_exp_cmd_mask	|= (1 << IB_USER_VERBS_EXP_CMD_QUERY_MKEY);

	if (MLX5_CAP_GEN(mdev, port_type) == MLX5_CAP_PORT_TYPE_ETH) {
		dev->ib_dev.create_wq		= mlx5_ib_create_wq;
		dev->ib_dev.modify_wq		= mlx5_ib_modify_wq;
		dev->ib_dev.destroy_wq		= mlx5_ib_destroy_wq;
		dev->ib_dev.uverbs_exp_cmd_mask |=
				(1ull << IB_USER_VERBS_EXP_CMD_CREATE_WQ) |
				(1ull << IB_USER_VERBS_EXP_CMD_MODIFY_WQ) |
				(1ull << IB_USER_VERBS_EXP_CMD_DESTROY_WQ) |
				(1ull << IB_USER_VERBS_EXP_CMD_CREATE_RWQ_IND_TBL) |
				(1ull << IB_USER_VERBS_EXP_CMD_DESTROY_RWQ_IND_TBL) |
				(1ull << IB_USER_VERBS_EXP_CMD_CREATE_FLOW);
		dev->ib_dev.create_rwq_ind_table = mlx5_ib_create_rwq_ind_table;
		dev->ib_dev.destroy_rwq_ind_table = mlx5_ib_destroy_rwq_ind_table;
	}
	err = init_node_data(dev);
	if (err)
		goto err_disable_roce;

	mutex_init(&dev->fs.lock);
	mutex_init(&dev->cap_mask_mutex);
	INIT_LIST_HEAD(&dev->qp_list);
	spin_lock_init(&dev->reset_flow_resource_lock);

	err = create_dev_resources(&dev->devr);
	if (err)
		goto err_disable_roce;

	err = mlx5_ib_odp_init_one(dev);
	if (err)
		goto err_rsrc;

	err = mlx5_ib_alloc_q_counters(dev);
	if (err)
		goto err_odp;

	err = ib_register_device(&dev->ib_dev, NULL);
	if (err)
		goto err_q_cnt;

	err = create_umr_res(dev);
	if (err)
		goto err_dev;

	if (MLX5_CAP_GEN(dev->mdev, port_type) ==
	    MLX5_CAP_PORT_TYPE_IB) {
		if (init_dc_improvements(dev))
			mlx5_ib_dbg(dev, "init_dc_improvements - continuing\n");
	}

	err = create_port_attrs(dev);
	if (err)
		goto err_dc;

	for (i = 0; i < ARRAY_SIZE(mlx5_class_attributes); i++) {
		err = device_create_file(&dev->ib_dev.dev,
					 mlx5_class_attributes[i]);
		if (err)
			goto err_port_attrs;
	}

	dev->ib_active = true;

	return dev;

err_port_attrs:
	destroy_ports_attrs(dev, dev->num_ports);

err_dc:
	if (MLX5_CAP_GEN(dev->mdev, port_type) ==
	    MLX5_CAP_PORT_TYPE_IB)
		cleanup_dc_improvements(dev);
	destroy_umrc_res(dev);

err_dev:
	ib_unregister_device(&dev->ib_dev);

err_q_cnt:
	mlx5_ib_dealloc_q_counters(dev);

err_odp:
	mlx5_ib_odp_remove_one(dev);

err_rsrc:
	destroy_dev_resources(&dev->devr);

err_disable_roce:
	if (mlx5_ib_port_link_layer(&dev->ib_dev, 1) ==
	    IB_LINK_LAYER_ETHERNET && MLX5_CAP_GEN(mdev, roce))
		mlx5_nic_vport_disable_roce(mdev);
err_free_port:
	kfree(dev->port);

	for (i = 0; i < MLX5_CAP_GEN(mdev, num_ports); i++)
		if (mlx5_ib_port_link_layer(&dev->ib_dev, i + 1) ==
			IB_LINK_LAYER_INFINIBAND)
			mlx5_set_port_status(mdev, MLX5_PORT_DOWN, i + 1);

err_dealloc:
	ib_dealloc_device((struct ib_device *)dev);

	return NULL;
}

static void mlx5_ib_remove(struct mlx5_core_dev *mdev, void *context)
{
	struct mlx5_ib_dev *dev = context;
	int i;

	destroy_ports_attrs(dev, dev->num_ports);
	if (MLX5_CAP_GEN(dev->mdev, port_type) ==
	    MLX5_CAP_PORT_TYPE_IB)
		cleanup_dc_improvements(dev);
	mlx5_ib_dealloc_q_counters(dev);
	ib_unregister_device(&dev->ib_dev);
	destroy_umrc_res(dev);
	mlx5_ib_odp_remove_one(dev);
	destroy_dev_resources(&dev->devr);

	if (mlx5_ib_port_link_layer(&dev->ib_dev, 1) ==
	    IB_LINK_LAYER_ETHERNET && MLX5_CAP_GEN(mdev, roce))
		mlx5_nic_vport_disable_roce(mdev);

	for (i = 0; i < MLX5_CAP_GEN(mdev, num_ports); i++)
		if (mlx5_ib_port_link_layer(&dev->ib_dev, i + 1) ==
			IB_LINK_LAYER_INFINIBAND)
			mlx5_set_port_status(mdev, MLX5_PORT_DOWN, i + 1);

	kfree(dev->port);
	ib_dealloc_device(&dev->ib_dev);
}

static struct mlx5_interface mlx5_ib_interface = {
	.add            = mlx5_ib_add,
	.remove         = mlx5_ib_remove,
	.event          = mlx5_ib_event,
	.protocol	= MLX5_INTERFACE_PROTOCOL_IB,
};

static int __init mlx5_ib_init(void)
{
	int err;

	if (deprecated_prof_sel != 2)
		pr_warn("prof_sel is deprecated for mlx5_ib, set it for mlx5_core\n");

	err = mlx5_ib_odp_init();
	if (err)
		return err;

	err = mlx5_register_interface(&mlx5_ib_interface);
	if (err)
		goto clean_odp;

	mlx5_ib_wq = create_singlethread_workqueue("mlx5_ib_wq");
	if (!mlx5_ib_wq) {
		pr_err("%s: failed to create mlx5_ib_wq\n", __func__);
		goto err_unreg;
	}

	return err;

err_unreg:
	mlx5_unregister_interface(&mlx5_ib_interface);
clean_odp:
	mlx5_ib_odp_cleanup();
	return err;
}

static void __exit mlx5_ib_cleanup(void)
{
	destroy_workqueue(mlx5_ib_wq);
	mlx5_unregister_interface(&mlx5_ib_interface);
	mlx5_ib_odp_cleanup();
}

module_init(mlx5_ib_init);
module_exit(mlx5_ib_cleanup);
