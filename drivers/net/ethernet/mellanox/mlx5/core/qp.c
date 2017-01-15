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


#include <linux/gfp.h>
#include <linux/export.h>
#include <linux/mlx5/cmd.h>
#include <linux/mlx5/qp.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/mlx5_ifc.h>
#include <linux/mlx5/transobj.h>

#include "mlx5_core.h"

static struct mlx5_core_rsc_common *mlx5_get_rsc(struct mlx5_core_dev *dev,
						 u32 rsn)
{
	struct mlx5_qp_table *table = &dev->priv.qp_table;
	struct mlx5_core_rsc_common *common;

	spin_lock(&table->lock);

	common = radix_tree_lookup(&table->tree, rsn);
	if (common)
		atomic_inc(&common->refcount);

	spin_unlock(&table->lock);

	if (!common) {
		mlx5_core_warn(dev, "Async event for bogus resource 0x%x\n",
			       rsn);
		return NULL;
	}
	return common;
}

void mlx5_core_put_rsc(struct mlx5_core_rsc_common *common)
{
	if (atomic_dec_and_test(&common->refcount))
		complete(&common->free);
}

int mlx5_rsc_event(struct mlx5_core_dev *dev, u32 rsn, int event_type)
{
	struct mlx5_core_rsc_common *common = mlx5_get_rsc(dev, rsn);
	struct mlx5_core_dct *dct;
	struct mlx5_core_qp *qp;

	if (!common)
		return -1;

	switch (common->res) {
	case MLX5_RES_QP:
	case MLX5_RES_RQ:
	case MLX5_RES_SQ:
		qp = (struct mlx5_core_qp *)common;
		qp->event(qp, event_type);
		break;

	case MLX5_RES_DCT:
		dct = (struct mlx5_core_dct *)common;
		if (event_type == MLX5_EVENT_TYPE_DCT_DRAINED)
			complete(&dct->drained);
		else
			dct->event(dct, event_type);
		break;

	default:
		mlx5_core_warn(dev, "invalid resource type for 0x%x\n", rsn);
	}

	mlx5_core_put_rsc(common);
	return 0;
}

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
void mlx5_eq_pagefault(struct mlx5_core_dev *dev, struct mlx5_eqe *eqe)
{
	struct mlx5_eqe_page_fault *pf_eqe = &eqe->data.page_fault;
	int qpn = be32_to_cpu(pf_eqe->flags_qpn) & MLX5_QPN_MASK;
	struct mlx5_core_rsc_common *common = mlx5_get_rsc(dev, qpn);
	struct mlx5_core_qp *qp =
		container_of(common, struct mlx5_core_qp, common);
	struct mlx5_pagefault pfault;

	if (!qp) {
		mlx5_core_warn(dev, "ODP event for non-existent QP %06x\n",
			       qpn);
		return;
	}

	pfault.event_subtype = eqe->sub_type;
	pfault.flags = (be32_to_cpu(pf_eqe->flags_qpn) >> MLX5_QPN_BITS) &
		(MLX5_PFAULT_REQUESTOR | MLX5_PFAULT_WRITE | MLX5_PFAULT_RDMA);
	pfault.bytes_committed = be32_to_cpu(
		pf_eqe->bytes_committed);

	mlx5_core_dbg(dev,
		      "PAGE_FAULT: subtype: 0x%02x, flags: 0x%02x,\n",
		      eqe->sub_type, pfault.flags);

	switch (eqe->sub_type) {
	case MLX5_PFAULT_SUBTYPE_RDMA:
		/* RDMA based event */
		pfault.rdma.r_key =
			be32_to_cpu(pf_eqe->rdma.r_key);
		pfault.rdma.packet_size =
			be16_to_cpu(pf_eqe->rdma.packet_length);
		pfault.rdma.rdma_op_len =
			be32_to_cpu(pf_eqe->rdma.rdma_op_len);
		pfault.rdma.rdma_va =
			be64_to_cpu(pf_eqe->rdma.rdma_va);
		mlx5_core_dbg(dev,
			      "PAGE_FAULT: qpn: 0x%06x, r_key: 0x%08x,\n",
			      qpn, pfault.rdma.r_key);
		mlx5_core_dbg(dev,
			      "PAGE_FAULT: rdma_op_len: 0x%08x,\n",
			      pfault.rdma.rdma_op_len);
		mlx5_core_dbg(dev,
			      "PAGE_FAULT: rdma_va: 0x%016llx,\n",
			      pfault.rdma.rdma_va);
		mlx5_core_dbg(dev,
			      "PAGE_FAULT: bytes_committed: 0x%06x\n",
			      pfault.bytes_committed);
		break;

	case MLX5_PFAULT_SUBTYPE_WQE:
		/* WQE based event */
		pfault.wqe.wqe_index =
			be16_to_cpu(pf_eqe->wqe.wqe_index);
		pfault.wqe.packet_size =
			be16_to_cpu(pf_eqe->wqe.packet_length);
		mlx5_core_dbg(dev,
			      "PAGE_FAULT: qpn: 0x%06x, wqe_index: 0x%04x,\n",
			      qpn, pfault.wqe.wqe_index);
		mlx5_core_dbg(dev,
			      "PAGE_FAULT: bytes_committed: 0x%06x\n",
			      pfault.bytes_committed);
		break;

	default:
		mlx5_core_warn(dev,
			       "Unsupported page fault event sub-type: 0x%02hhx, QP %06x\n",
			       eqe->sub_type, qpn);
		/* Unsupported page faults should still be resolved by the
		 * page fault handler
		 */
	}

	if (qp->pfault_handler) {
		qp->pfault_handler(qp, &pfault);
	} else {
		mlx5_core_err(dev,
			      "ODP event for QP %08x, without a fault handler in QP\n",
			      qpn);
		/* Page fault will remain unresolved. QP will hang until it is
		 * destroyed
		 */
	}

	mlx5_core_put_rsc(common);
}
#endif

static int create_qprqsq_common(struct mlx5_core_dev *dev,
				struct mlx5_core_qp *qp, int rsc_type)
{
	struct mlx5_qp_table *table = &dev->priv.qp_table;
	int err;

	qp->common.res = rsc_type;
	spin_lock_irq(&table->lock);
	err = radix_tree_insert(&table->tree, qp->qpn | (rsc_type << 24), qp);
	spin_unlock_irq(&table->lock);
	if (err)
		return err;

	atomic_set(&qp->common.refcount, 1);
	init_completion(&qp->common.free);
	qp->pid = current->pid;

	return 0;

}

static void destroy_qprqsq_common(struct mlx5_core_dev *dev,
				  struct mlx5_core_qp *qp, int rsc_type)
{
	struct mlx5_qp_table *table = &dev->priv.qp_table;
	unsigned long flags;

	spin_lock_irqsave(&table->lock, flags);
	radix_tree_delete(&table->tree, qp->qpn | (rsc_type << 24));
	spin_unlock_irqrestore(&table->lock, flags);

	mlx5_core_put_rsc((struct mlx5_core_rsc_common *)qp);
	wait_for_completion(&qp->common.free);
}

int mlx5_core_create_qp(struct mlx5_core_dev *dev,
			struct mlx5_core_qp *qp,
			struct mlx5_create_qp_mbox_in *in,
			int inlen)
{
	struct mlx5_create_qp_mbox_out out;
	struct mlx5_destroy_qp_mbox_in din;
	struct mlx5_destroy_qp_mbox_out dout;
	int err;

	memset(&out, 0, sizeof(out));
	in->hdr.opcode = cpu_to_be16(MLX5_CMD_OP_CREATE_QP);

	err = mlx5_cmd_exec(dev, in, inlen, &out, sizeof(out));
	if (err) {
		mlx5_core_warn(dev, "ret %d\n", err);
		return err;
	}

	if (out.hdr.status) {
		mlx5_core_warn(dev, "current num of QPs 0x%x\n",
			       atomic_read(&dev->num_qps));
		return mlx5_cmd_status_to_err(dev, &out.hdr);
	}

	qp->qpn = be32_to_cpu(out.qpn) & 0xffffff;
	mlx5_core_dbg(dev, "qpn = 0x%x\n", qp->qpn);

	err = create_qprqsq_common(dev, qp, MLX5_RES_QP);
	if (err)
		goto err_cmd;

	err = mlx5_debug_qp_add(dev, qp);
	if (err)
		mlx5_core_dbg(dev, "failed adding QP 0x%x to debug file system\n",
			      qp->qpn);

	atomic_inc(&dev->num_qps);

	return 0;

err_cmd:
	memset(&din, 0, sizeof(din));
	memset(&dout, 0, sizeof(dout));
	din.hdr.opcode = cpu_to_be16(MLX5_CMD_OP_DESTROY_QP);
	din.qpn = cpu_to_be32(qp->qpn);
	mlx5_cmd_exec(dev, &din, sizeof(din), &out, sizeof(dout));

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_create_qp);

int mlx5_core_destroy_qp(struct mlx5_core_dev *dev,
			 struct mlx5_core_qp *qp)
{
	struct mlx5_destroy_qp_mbox_in in;
	struct mlx5_destroy_qp_mbox_out out;
	int err;

	mlx5_debug_qp_remove(dev, qp);

	destroy_qprqsq_common(dev, qp, MLX5_RES_QP);

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(MLX5_CMD_OP_DESTROY_QP);
	in.qpn = cpu_to_be32(qp->qpn);

	err = mlx5_cmd_exec_check_status(dev, (void *)&in, sizeof(in),
					 (void *)&out, sizeof(out));
	if (!err)
		atomic_dec(&dev->num_qps);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_destroy_qp);

int mlx5_core_qp_modify(struct mlx5_core_dev *dev, u16 operation,
			struct mlx5_modify_qp_mbox_in *in, int sqd_event,
			struct mlx5_core_qp *qp)
{
	struct mlx5_modify_qp_mbox_out out;

	memset(&out, 0, sizeof(out));
	in->hdr.opcode = cpu_to_be16(operation);
	in->qpn = cpu_to_be32(qp->qpn);

	return mlx5_cmd_exec(dev, (void *)in, sizeof(*in), (void *)&out,
			     sizeof(out));
}
EXPORT_SYMBOL_GPL(mlx5_core_qp_modify);

void mlx5_init_qp_table(struct mlx5_core_dev *dev)
{
	struct mlx5_qp_table *table = &dev->priv.qp_table;

	memset(table, 0, sizeof(*table));
	spin_lock_init(&table->lock);
	INIT_RADIX_TREE(&table->tree, GFP_ATOMIC);
	mlx5_qp_debugfs_init(dev);
}

void mlx5_cleanup_qp_table(struct mlx5_core_dev *dev)
{
	mlx5_qp_debugfs_cleanup(dev);
}

void mlx5_init_dct_table(struct mlx5_core_dev *dev)
{
	mlx5_dct_debugfs_init(dev);
}

void mlx5_cleanup_dct_table(struct mlx5_core_dev *dev)
{
	mlx5_dct_debugfs_cleanup(dev);
}

int mlx5_core_qp_query(struct mlx5_core_dev *dev, struct mlx5_core_qp *qp,
		       struct mlx5_query_qp_mbox_out *out, int outlen)
{
	struct mlx5_query_qp_mbox_in in;

	memset(&in, 0, sizeof(in));
	memset(out, 0, outlen);
	in.hdr.opcode = cpu_to_be16(MLX5_CMD_OP_QUERY_QP);
	in.qpn = cpu_to_be32(qp->qpn);

	return mlx5_cmd_exec_check_status(dev, (void *)&in, sizeof(in),
					  (void *)out, outlen);
}
EXPORT_SYMBOL_GPL(mlx5_core_qp_query);

int mlx5_core_xrcd_alloc(struct mlx5_core_dev *dev, u32 *xrcdn)
{
	struct mlx5_alloc_xrcd_mbox_in in;
	struct mlx5_alloc_xrcd_mbox_out out;
	int err;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(MLX5_CMD_OP_ALLOC_XRCD);
	err = mlx5_cmd_exec_check_status(dev, (void *)&in, sizeof(in),
					 (void *)&out, sizeof(out));
	if (!err)
		*xrcdn = be32_to_cpu(out.xrcdn) & 0xffffff;

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_xrcd_alloc);

int mlx5_core_xrcd_dealloc(struct mlx5_core_dev *dev, u32 xrcdn)
{
	struct mlx5_dealloc_xrcd_mbox_in in;
	struct mlx5_dealloc_xrcd_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(MLX5_CMD_OP_DEALLOC_XRCD);
	in.xrcdn = cpu_to_be32(xrcdn);

	return mlx5_cmd_exec_check_status(dev, (void *)&in, sizeof(in),
					  (void *)&out, sizeof(out));
}
EXPORT_SYMBOL_GPL(mlx5_core_xrcd_dealloc);

int mlx5_core_create_dct(struct mlx5_core_dev *dev,
			 struct mlx5_core_dct *dct,
			 struct mlx5_create_dct_mbox_in *in)
{
	struct mlx5_qp_table *table = &dev->priv.qp_table;
	struct mlx5_create_dct_mbox_out out;
	struct mlx5_destroy_dct_mbox_in din;
	struct mlx5_destroy_dct_mbox_out dout;
	int err;

	init_completion(&dct->drained);
	memset(&out, 0, sizeof(out));
	in->hdr.opcode = cpu_to_be16(MLX5_CMD_OP_CREATE_DCT);

	err = mlx5_cmd_exec(dev, in, sizeof(*in), &out, sizeof(out));
	if (err) {
		mlx5_core_warn(dev, "create DCT failed, ret %d", err);
		return err;
	}

	if (out.hdr.status)
		return mlx5_cmd_status_to_err(dev, &out.hdr);

	dct->dctn = be32_to_cpu(out.dctn) & 0xffffff;

	dct->common.res = MLX5_RES_DCT;
	spin_lock_irq(&table->lock);
	err = radix_tree_insert(&table->tree, dct->dctn, dct);
	spin_unlock_irq(&table->lock);
	if (err) {
		mlx5_core_warn(dev, "err %d", err);
		goto err_cmd;
	}

	err = mlx5_debug_dct_add(dev, dct);
	if (err)
		mlx5_core_dbg(dev, "failed adding DCT 0x%x to debug file system\n",
			      dct->dctn);

	dct->pid = current->pid;
	atomic_set(&dct->common.refcount, 1);
	init_completion(&dct->common.free);

	return 0;

err_cmd:
	memset(&din, 0, sizeof(din));
	memset(&dout, 0, sizeof(dout));
	din.hdr.opcode = cpu_to_be16(MLX5_CMD_OP_DESTROY_DCT);
	din.dctn = cpu_to_be32(dct->dctn);
	mlx5_cmd_exec(dev, &din, sizeof(din), &out, sizeof(dout));

	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_create_dct);

static int mlx5_core_drain_dct(struct mlx5_core_dev *dev,
			       struct mlx5_core_dct *dct)
{
	struct mlx5_drain_dct_mbox_out out;
	struct mlx5_drain_dct_mbox_in in;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(MLX5_CMD_OP_DRAIN_DCT);
	in.dctn = cpu_to_be32(dct->dctn);
	return mlx5_cmd_exec_check_status(dev, (void *)&in, sizeof(in),
			    (void *)&out, sizeof(out));
}

int mlx5_core_destroy_dct(struct mlx5_core_dev *dev,
			  struct mlx5_core_dct *dct)
{
	struct mlx5_qp_table *table = &dev->priv.qp_table;
	struct mlx5_destroy_dct_mbox_out out;
	struct mlx5_destroy_dct_mbox_in in;
	unsigned long flags;
	int err;

	err = mlx5_core_drain_dct(dev, dct);
	if (err) {
		mlx5_core_warn(dev, "failed drain DCT 0x%x\n", dct->dctn);
		return err;
	}

	wait_for_completion(&dct->drained);

	mlx5_debug_dct_remove(dev, dct);

	spin_lock_irqsave(&table->lock, flags);
	if (radix_tree_delete(&table->tree, dct->dctn) != dct)
		mlx5_core_warn(dev, "dct delete differs\n");
	spin_unlock_irqrestore(&table->lock, flags);

	if (atomic_dec_and_test(&dct->common.refcount))
		complete(&dct->common.free);
	wait_for_completion(&dct->common.free);

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(MLX5_CMD_OP_DESTROY_DCT);
	in.dctn = cpu_to_be32(dct->dctn);
	return mlx5_cmd_exec_check_status(dev, (void *)&in, sizeof(in),
					  (void *)&out, sizeof(out));
}
EXPORT_SYMBOL_GPL(mlx5_core_destroy_dct);

int mlx5_core_dct_query(struct mlx5_core_dev *dev, struct mlx5_core_dct *dct,
			struct mlx5_query_dct_mbox_out *out)
{
	struct mlx5_query_dct_mbox_in in;

	memset(&in, 0, sizeof(in));
	memset(out, 0, sizeof(*out));
	in.hdr.opcode = cpu_to_be16(MLX5_CMD_OP_QUERY_DCT);
	in.dctn = cpu_to_be32(dct->dctn);
	return mlx5_cmd_exec_check_status(dev, (void *)&in, sizeof(in),
					 (void *)out, sizeof(*out));
}
EXPORT_SYMBOL_GPL(mlx5_core_dct_query);

int mlx5_core_arm_dct(struct mlx5_core_dev *dev, struct mlx5_core_dct *dct)
{
	struct mlx5_arm_dct_mbox_out out;
	struct mlx5_arm_dct_mbox_in in;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));

	in.hdr.opcode = cpu_to_be16(MLX5_CMD_OP_ARM_DCT_FOR_KEY_VIOLATION);
	in.dctn = cpu_to_be32(dct->dctn);
	return mlx5_cmd_exec_check_status(dev, (void *)&in, sizeof(in),
					 (void *)&out, sizeof(out));
}
EXPORT_SYMBOL_GPL(mlx5_core_arm_dct);
#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
int mlx5_core_page_fault_resume(struct mlx5_core_dev *dev, u32 qpn,
				u8 flags, int error)
{
	struct mlx5_page_fault_resume_mbox_in in;
	struct mlx5_page_fault_resume_mbox_out out;

	memset(&in, 0, sizeof(in));
	memset(&out, 0, sizeof(out));
	in.hdr.opcode = cpu_to_be16(MLX5_CMD_OP_PAGE_FAULT_RESUME);
	in.hdr.opmod = 0;
	flags &= (MLX5_PAGE_FAULT_RESUME_REQUESTOR |
		  MLX5_PAGE_FAULT_RESUME_WRITE	   |
		  MLX5_PAGE_FAULT_RESUME_RDMA);
	flags |= (error ? MLX5_PAGE_FAULT_RESUME_ERROR : 0);
	in.flags_qpn = cpu_to_be32((qpn & MLX5_QPN_MASK) |
				   (flags << MLX5_QPN_BITS));

	return mlx5_cmd_exec_check_status(dev, (void *)&in, sizeof(in),
					  (void *)&out, sizeof(out));

}
EXPORT_SYMBOL_GPL(mlx5_core_page_fault_resume);
#endif

int mlx5_core_create_rq_tracked(struct mlx5_core_dev *dev, u32 *in, int inlen,
				struct mlx5_core_qp *rq)
{
	int err;

	err = mlx5_core_create_rq(dev, in, inlen, &rq->qpn);
	if (err)
		return err;

	err = create_qprqsq_common(dev, rq, MLX5_RES_RQ);
	if (err)
		mlx5_core_destroy_rq(dev, rq->qpn);

	return err;
}
EXPORT_SYMBOL(mlx5_core_create_rq_tracked);

void mlx5_core_destroy_rq_tracked(struct mlx5_core_dev *dev,
				  struct mlx5_core_qp *rq)
{
	destroy_qprqsq_common(dev, rq, MLX5_RES_RQ);
	mlx5_core_destroy_rq(dev, rq->qpn);
}
EXPORT_SYMBOL(mlx5_core_destroy_rq_tracked);

int mlx5_core_create_sq_tracked(struct mlx5_core_dev *dev, u32 *in, int inlen,
				struct mlx5_core_qp *sq)
{
	int err;

	err = mlx5_core_create_sq(dev, in, inlen, &sq->qpn);
	if (err)
		return err;

	err = create_qprqsq_common(dev, sq, MLX5_RES_SQ);
	if (err)
		mlx5_core_destroy_sq(dev, sq->qpn);

	return err;
}
EXPORT_SYMBOL(mlx5_core_create_sq_tracked);

void mlx5_core_destroy_sq_tracked(struct mlx5_core_dev *dev,
				  struct mlx5_core_qp *sq)
{
	destroy_qprqsq_common(dev, sq, MLX5_RES_SQ);
	mlx5_core_destroy_sq(dev, sq->qpn);
}
EXPORT_SYMBOL(mlx5_core_destroy_sq_tracked);
