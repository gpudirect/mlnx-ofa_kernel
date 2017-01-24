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
#include <rdma/ib_umem.h>
#include <linux/mlx5/mlx5_ifc.h>
#include <rdma/ib_verbs_exp.h>
#include <rdma/ib_cache.h>
#include <linux/mlx5/transobj.h>
#include <rdma/ib_user_verbs.h>
#include <linux/errno.h>
#include "mlx5_ib.h"
#include "user.h"

static int __mlx5_ib_modify_qp(struct ib_qp *ibqp,
			       const struct ib_qp_attr *attr, int attr_mask,
			       enum ib_qp_state cur_state, enum ib_qp_state new_state);

/* not supported currently */
static int wq_signature;

enum {
	MLX5_IB_ACK_REQ_FREQ	= 8,
};

enum {
	MLX5_IB_DEFAULT_SCHED_QUEUE	= 0x83,
	MLX5_IB_DEFAULT_QP0_SCHED_QUEUE	= 0x3f,
	MLX5_IB_LINK_TYPE_IB		= 0,
	MLX5_IB_LINK_TYPE_ETH		= 1
};

enum {
	MLX5_IB_SQ_STRIDE	= 6,
};

enum {
	MLX5_RQ_NUM_STATE	= MLX5_RQC_STATE_ERR + 1,
	MLX5_SQ_NUM_STATE	= MLX5_SQC_STATE_ERR + 1,
	MLX5_QP_STATE		= MLX5_QP_NUM_STATE + 1,
	MLX5_QP_STATE_BAD	= MLX5_QP_STATE + 1,
};

static const u32 mlx5_ib_opcode[] = {
	[IB_WR_SEND]				= MLX5_OPCODE_SEND,
	[IB_WR_LSO]				= MLX5_OPCODE_LSO,
	[IB_WR_SEND_WITH_IMM]			= MLX5_OPCODE_SEND_IMM,
	[IB_WR_RDMA_WRITE]			= MLX5_OPCODE_RDMA_WRITE,
	[IB_WR_RDMA_WRITE_WITH_IMM]		= MLX5_OPCODE_RDMA_WRITE_IMM,
	[IB_WR_RDMA_READ]			= MLX5_OPCODE_RDMA_READ,
	[IB_WR_ATOMIC_CMP_AND_SWP]		= MLX5_OPCODE_ATOMIC_CS,
	[IB_WR_ATOMIC_FETCH_AND_ADD]		= MLX5_OPCODE_ATOMIC_FA,
	[IB_WR_SEND_WITH_INV]			= MLX5_OPCODE_SEND_INVAL,
	[IB_WR_LOCAL_INV]			= MLX5_OPCODE_UMR,
	[IB_WR_FAST_REG_MR]			= MLX5_OPCODE_UMR,
	[IB_WR_REG_INDIR_MR]			= MLX5_OPCODE_UMR,
	[IB_WR_MASKED_ATOMIC_CMP_AND_SWP]	= MLX5_OPCODE_ATOMIC_MASKED_CS,
	[IB_WR_MASKED_ATOMIC_FETCH_AND_ADD]	= MLX5_OPCODE_ATOMIC_MASKED_FA,
	[MLX5_IB_WR_UMR]			= MLX5_OPCODE_UMR,
};

struct mlx5_wqe_eth_pad {
	u8 rsvd0[16];
};

enum raw_qp_set_mask_map {
	MLX5_RAW_QP_MOD_SET_RQ_Q_CTR_ID		= 1UL << 0,
	MLX5_RAW_QP_RATE_LIMIT			= 1UL << 1,
};

struct mlx5_modify_raw_qp_param {
	u16 operation;

	u32 set_mask; /* raw_qp_set_mask_map */
	u8 rq_q_ctr_id;
	u32 rate_limit;
};

static int is_qp0(enum ib_qp_type qp_type)
{
	return qp_type == IB_QPT_SMI;
}

static int is_qp1(enum ib_qp_type qp_type)
{
	return qp_type == IB_QPT_GSI;
}

static int is_sqp(enum ib_qp_type qp_type)
{
	return is_qp0(qp_type) || is_qp1(qp_type);
}

static void *get_wqe(struct mlx5_ib_qp *qp, int offset)
{
	return mlx5_buf_offset(&qp->buf, offset);
}

static void *get_recv_wqe(struct mlx5_ib_qp *qp, int n)
{
	return get_wqe(qp, qp->rq.offset + (n << qp->rq.wqe_shift));
}

void *mlx5_get_send_wqe(struct mlx5_ib_qp *qp, int n)
{
	return get_wqe(qp, qp->sq.offset + (n << MLX5_IB_SQ_STRIDE));
}

/**
 * mlx5_ib_read_user_wqe() - Copy a user-space WQE to kernel space.
 *
 * @qp: QP to copy from.
 * @send: copy from the send queue when non-zero, use the receive queue
 *	  otherwise.
 * @wqe_index:  index to start copying from. For send work queues, the
 *		wqe_index is in units of MLX5_SEND_WQE_BB.
 *		For receive work queue, it is the number of work queue
 *		element in the queue.
 * @buffer: destination buffer.
 * @length: maximum number of bytes to copy.
 *
 * Copies at least a single WQE, but may copy more data.
 *
 * Return: the number of bytes copied, or an error code.
 */
int mlx5_ib_read_user_wqe(struct mlx5_ib_qp *qp, int send, int wqe_index,
			  void *buffer, u32 length)
{
	struct ib_device *ibdev = qp->ibqp.device;
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct mlx5_ib_wq *wq = send ? &qp->sq : &qp->rq;
	size_t offset;
	size_t wq_end;
	struct ib_umem *umem = qp->umem;
	u32 first_copy_length;
	int wqe_length;
	int ret;

	if (wq->wqe_cnt == 0) {
		mlx5_ib_warn(dev, "mlx5_ib_read_user_wqe for a QP with wqe_cnt == 0. qp_type: 0x%x\n",
			     qp->ibqp.qp_type);
		return -EINVAL;
	}

	offset = wq->offset + ((wqe_index % wq->wqe_cnt) << wq->wqe_shift);
	wq_end = wq->offset + (wq->wqe_cnt << wq->wqe_shift);

	if (send && length < sizeof(struct mlx5_wqe_ctrl_seg))
		return -EINVAL;

	if (offset > umem->length ||
	    (send && offset + sizeof(struct mlx5_wqe_ctrl_seg) > umem->length))
		return -EINVAL;

	first_copy_length = min_t(u32, offset + length, wq_end) - offset;
	ret = ib_umem_copy_from(buffer, umem, offset, first_copy_length);
	if (ret)
		return ret;

	if (send) {
		struct mlx5_wqe_ctrl_seg *ctrl = buffer;
		int ds = be32_to_cpu(ctrl->qpn_ds) & MLX5_WQE_CTRL_DS_MASK;

		wqe_length = ds * MLX5_WQE_DS_UNITS;
	} else {
		wqe_length = 1 << wq->wqe_shift;
	}

	if (wqe_length <= first_copy_length)
		return first_copy_length;

	ret = ib_umem_copy_from(buffer + first_copy_length, umem, wq->offset,
				wqe_length - first_copy_length);
	if (ret)
		return ret;

	return wqe_length;
}

static int
query_wqe_idx(struct mlx5_ib_qp *qp)
{
	struct mlx5_ib_dev *dev = to_mdev(qp->ibqp.device);
	struct mlx5_query_qp_mbox_out *outb;
	struct mlx5_qp_context *context;
	int ret;

	outb = kzalloc(sizeof(*outb), GFP_KERNEL);
	if (!outb)
		return -ENOMEM;

	context = &outb->ctx;

	mutex_lock(&qp->mutex);
	ret = mlx5_core_qp_query(dev->mdev, &qp->mqp, outb, sizeof(*outb));
	if (ret)
		goto out_free;

	ret = be16_to_cpu(context->hw_sq_wqe_counter) & (qp->sq.wqe_cnt - 1);

out_free:
	mutex_unlock(&qp->mutex);
	kfree(outb);

	return ret;
}

static int mlx5_handle_sig_pipelining(struct mlx5_ib_qp *qp)
{
	int wqe_idx;

	wqe_idx = query_wqe_idx(qp);
	if (wqe_idx < 0) {
		pr_err("Failed to query QP 0x%x wqe index\n", qp->mqp.qpn);
		return wqe_idx;
	}

	if (qp->sq.swr_ctx[wqe_idx].sig_piped) {
		struct mlx5_ib_dev *dev = to_mdev(qp->ibqp.device);
		struct mlx5_wqe_ctrl_seg *cwqe;

		cwqe = mlx5_get_send_wqe(qp, wqe_idx);
		cwqe->opmod_idx_opcode = cpu_to_be32(be32_to_cpu(cwqe->opmod_idx_opcode) & 0xffffff00);
		qp->sq.swr_ctx[wqe_idx].w_list.opcode |= MLX5_OPCODE_SIGNATURE_CANCELED;
		mlx5_ib_dbg(dev, "Cancel QP 0x%x wqe_index 0x%x\n",
			    qp->mqp.qpn, wqe_idx);
	}

	return 0;
}

static void mlx5_ib_sqd_work(struct work_struct *work)
{
	struct mlx5_ib_sqd *sqd;
	struct mlx5_ib_qp *qp;
	struct ib_qp_attr qp_attr;

	sqd = container_of(work, struct mlx5_ib_sqd, work);
	qp = sqd->qp;

	if (mlx5_handle_sig_pipelining(qp))
		goto out;

	mutex_lock(&qp->mutex);
	if (__mlx5_ib_modify_qp(&qp->ibqp, &qp_attr, 0, IB_QPS_SQD, IB_QPS_RTS))
		pr_err("Failed to resume QP 0x%x\n", qp->mqp.qpn);
	mutex_unlock(&qp->mutex);
out:
	kfree(sqd);
}

static void mlx5_ib_sigerr_sqd_event(struct mlx5_ib_qp *qp)
{
	struct mlx5_ib_sqd *sqd;

	sqd = kzalloc(sizeof(*sqd), GFP_ATOMIC);
	if (!sqd)
		return;

	sqd->qp = qp;
	INIT_WORK(&sqd->work, mlx5_ib_sqd_work);
	queue_work(mlx5_ib_wq, &sqd->work);
}

static void mlx5_ib_qp_event(struct mlx5_core_qp *qp, int type)
{
	struct ib_qp *ibqp = &to_mibqp(qp)->ibqp;
	struct ib_event event;

	if (type == MLX5_EVENT_TYPE_SQ_DRAINED &&
	    to_mibqp(qp)->state != IB_QPS_SQD) {
		mlx5_ib_sigerr_sqd_event(to_mibqp(qp));
		return;
	}

	if (type == MLX5_EVENT_TYPE_PATH_MIG)
		to_mibqp(qp)->port = to_mibqp(qp)->alt_port;

	if (ibqp->event_handler) {
		event.device     = ibqp->device;
		event.element.qp = ibqp;
		switch (type) {
		case MLX5_EVENT_TYPE_PATH_MIG:
			event.event = IB_EVENT_PATH_MIG;
			break;
		case MLX5_EVENT_TYPE_COMM_EST:
			event.event = IB_EVENT_COMM_EST;
			break;
		case MLX5_EVENT_TYPE_SQ_DRAINED:
			event.event = IB_EVENT_SQ_DRAINED;
			break;
		case MLX5_EVENT_TYPE_SRQ_LAST_WQE:
			event.event = IB_EVENT_QP_LAST_WQE_REACHED;
			break;
		case MLX5_EVENT_TYPE_WQ_CATAS_ERROR:
			event.event = IB_EVENT_QP_FATAL;
			break;
		case MLX5_EVENT_TYPE_PATH_MIG_FAILED:
			event.event = IB_EVENT_PATH_MIG_ERR;
			break;
		case MLX5_EVENT_TYPE_WQ_INVAL_REQ_ERROR:
			event.event = IB_EVENT_QP_REQ_ERR;
			break;
		case MLX5_EVENT_TYPE_WQ_ACCESS_ERROR:
			event.event = IB_EVENT_QP_ACCESS_ERR;
			break;
		default:
			pr_warn("mlx5_ib: Unexpected event type %d on QP %06x\n", type, qp->qpn);
			return;
		}

		ibqp->event_handler(&event, ibqp->qp_context);
	}
}

static int set_rq_size(struct mlx5_ib_dev *dev, struct ib_qp_cap *cap,
		       int has_rq, struct mlx5_ib_qp *qp, struct mlx5_ib_create_qp *ucmd)
{
	int wqe_size;
	int wq_size;

	/* Sanity check RQ size before proceeding */
	if (cap->max_recv_wr > (1 << MLX5_CAP_GEN(dev->mdev, log_max_qp_sz)))
		return -EINVAL;

	if (!has_rq) {
		qp->rq.max_gs = 0;
		qp->rq.wqe_cnt = 0;
		qp->rq.wqe_shift = 0;
		cap->max_recv_wr = 0;
		cap->max_recv_sge = 0;
	} else {
		if (ucmd) {
			qp->rq.wqe_cnt = ucmd->rq_wqe_count;
			qp->rq.wqe_shift = ucmd->rq_wqe_shift;
			qp->rq.max_gs = (1 << qp->rq.wqe_shift) / sizeof(struct mlx5_wqe_data_seg) - qp->wq_sig;
			qp->rq.max_post = qp->rq.wqe_cnt;
		} else {
			wqe_size = qp->wq_sig ? sizeof(struct mlx5_wqe_signature_seg) : 0;
			wqe_size += cap->max_recv_sge * sizeof(struct mlx5_wqe_data_seg);
			wqe_size = roundup_pow_of_two(wqe_size);
			wq_size = roundup_pow_of_two(cap->max_recv_wr) * wqe_size;
			wq_size = max_t(int, wq_size, MLX5_SEND_WQE_BB);
			qp->rq.wqe_cnt = wq_size / wqe_size;
			if (wqe_size > MLX5_CAP_GEN(dev->mdev, max_wqe_sz_rq)) {
				mlx5_ib_warn(dev, "wqe_size %d, max %d\n",
					     wqe_size,
					     MLX5_CAP_GEN(dev->mdev,
							  max_wqe_sz_rq));
				return -EINVAL;
			}
			qp->rq.wqe_shift = ilog2(wqe_size);
			qp->rq.max_gs = (1 << qp->rq.wqe_shift) / sizeof(struct mlx5_wqe_data_seg) - qp->wq_sig;
			qp->rq.max_post = qp->rq.wqe_cnt;
		}
	}

	return 0;
}

static int sq_overhead(struct ib_exp_qp_init_attr *attr)
{
	int size = 0;

	switch (attr->qp_type) {
	case IB_QPT_XRC_INI:
		size += sizeof(struct mlx5_wqe_xrc_seg);
		/* fall through */
	case IB_QPT_RC:
		size += sizeof(struct mlx5_wqe_ctrl_seg) +
			sizeof(struct mlx5_wqe_atomic_seg) +
			sizeof(struct mlx5_wqe_raddr_seg) +
			sizeof(struct mlx5_wqe_umr_ctrl_seg) +
			sizeof(struct mlx5_mkey_seg);
		break;

	case IB_QPT_XRC_TGT:
		return 0;

	case IB_QPT_UC:
		size += sizeof(struct mlx5_wqe_ctrl_seg) +
			sizeof(struct mlx5_wqe_raddr_seg) +
			sizeof(struct mlx5_wqe_umr_ctrl_seg) +
			sizeof(struct mlx5_mkey_seg);
		break;

	case IB_QPT_UD:
		if (attr->create_flags & IB_QP_CREATE_IPOIB_UD_LSO)
			size += sizeof(struct mlx5_wqe_eth_pad) +
				sizeof(struct mlx5_wqe_eth_seg);
		/* fall through */
	case IB_QPT_SMI:
	case IB_QPT_GSI:
		size += sizeof(struct mlx5_wqe_ctrl_seg) +
			sizeof(struct mlx5_wqe_datagram_seg);
		break;

	case MLX5_IB_QPT_REG_UMR:
		size += sizeof(struct mlx5_wqe_ctrl_seg) +
			sizeof(struct mlx5_wqe_umr_ctrl_seg) +
			sizeof(struct mlx5_mkey_seg);
		break;

	case MLX5_IB_QPT_SW_CNAK:
		size += sizeof(struct mlx5_wqe_ctrl_seg) +
			sizeof(struct mlx5_mlx_seg);
		break;

	default:
		return -EINVAL;
	}

	return size;
}

static int calc_send_wqe(struct ib_exp_qp_init_attr *attr)
{
	int inl_size = 0;
	int size;

	size = sq_overhead(attr);
	if (size < 0)
		return size;

	if (attr->cap.max_inline_data) {
		inl_size = size + sizeof(struct mlx5_wqe_inline_seg) +
			attr->cap.max_inline_data;
	}

	size += attr->cap.max_send_sge * sizeof(struct mlx5_wqe_data_seg);
	if (attr->create_flags & IB_QP_CREATE_SIGNATURE_EN &&
	    ALIGN(max_t(int, inl_size, size), MLX5_SEND_WQE_BB) < MLX5_SIG_WQE_SIZE)
			return MLX5_SIG_WQE_SIZE;
	else
		return ALIGN(max_t(int, inl_size, size), MLX5_SEND_WQE_BB);
}

static int get_send_sge(struct ib_exp_qp_init_attr *attr, int wqe_size)
{
	int max_sge;

	if (attr->qp_type == IB_QPT_RC)
		max_sge = (min_t(int, wqe_size, 512) -
			   sizeof(struct mlx5_wqe_ctrl_seg) -
			   sizeof(struct mlx5_wqe_raddr_seg)) /
			sizeof(struct mlx5_wqe_data_seg);
	else if (attr->qp_type == IB_EXP_QPT_DC_INI)
		max_sge = (min_t(int, wqe_size, 512) -
			   sizeof(struct mlx5_wqe_ctrl_seg) -
			   sizeof(struct mlx5_wqe_datagram_seg) -
			   sizeof(struct mlx5_wqe_raddr_seg)) /
			sizeof(struct mlx5_wqe_data_seg);
	else if (attr->qp_type == IB_QPT_XRC_INI)
		max_sge = (min_t(int, wqe_size, 512) -
			   sizeof(struct mlx5_wqe_ctrl_seg) -
			   sizeof(struct mlx5_wqe_xrc_seg) -
			   sizeof(struct mlx5_wqe_raddr_seg)) /
			sizeof(struct mlx5_wqe_data_seg);
	else
		max_sge = (wqe_size - sq_overhead(attr)) /
			sizeof(struct mlx5_wqe_data_seg);

	return min_t(int, max_sge, wqe_size - sq_overhead(attr) /
		     sizeof(struct mlx5_wqe_data_seg));
}

static int calc_sq_size(struct mlx5_ib_dev *dev, struct ib_exp_qp_init_attr *attr,
			struct mlx5_ib_qp *qp)
{
	int wqe_size;
	int wq_size;

	if (!attr->cap.max_send_wr)
		return 0;

	wqe_size = calc_send_wqe(attr);
	mlx5_ib_dbg(dev, "wqe_size %d\n", wqe_size);
	if (wqe_size < 0)
		return wqe_size;

	if (wqe_size > MLX5_CAP_GEN(dev->mdev, max_wqe_sz_sq)) {
		mlx5_ib_warn(dev, "wqe_size(%d) > max_sq_desc_sz(%d)\n",
			     wqe_size, MLX5_CAP_GEN(dev->mdev, max_wqe_sz_sq));
		return -EINVAL;
	}

	qp->max_inline_data = wqe_size - sq_overhead(attr) -
			      sizeof(struct mlx5_wqe_inline_seg);
	attr->cap.max_inline_data = qp->max_inline_data;

	if (attr->create_flags & IB_QP_CREATE_SIGNATURE_EN)
		qp->signature_en = true;

	wq_size = roundup_pow_of_two(attr->cap.max_send_wr * wqe_size);
	qp->sq.wqe_cnt = wq_size / MLX5_SEND_WQE_BB;
	if (qp->sq.wqe_cnt > (1 << MLX5_CAP_GEN(dev->mdev, log_max_qp_sz))) {
		mlx5_ib_warn(dev, "wqe count(%d) exceeds limits(%d)\n",
			     qp->sq.wqe_cnt,
			     1 << MLX5_CAP_GEN(dev->mdev, log_max_qp_sz));
		return -ENOMEM;
	}
	qp->sq.wqe_shift = ilog2(MLX5_SEND_WQE_BB);
	qp->sq.max_gs = get_send_sge(attr, wqe_size);
	if (qp->sq.max_gs < attr->cap.max_send_sge) {
		mlx5_ib_warn(dev, "max sge(%d) exceeds limits(%d)\n",
			     qp->sq.max_gs, attr->cap.max_send_sge);
		return -ENOMEM;
	}

	attr->cap.max_send_sge = qp->sq.max_gs;
	qp->sq.max_post = wq_size / wqe_size;
	attr->cap.max_send_wr = qp->sq.max_post;

	return wq_size;
}

static int set_user_buf_size(struct mlx5_ib_dev *dev,
			    struct mlx5_ib_qp *qp,
			    struct mlx5_ib_create_qp *ucmd,
			    struct ib_exp_qp_init_attr *attr)
{
	int desc_sz = 1 << qp->sq.wqe_shift;

	if (desc_sz > MLX5_CAP_GEN(dev->mdev, max_wqe_sz_sq)) {
		mlx5_ib_warn(dev, "desc_sz %d, max_sq_desc_sz %d\n",
			     desc_sz, MLX5_CAP_GEN(dev->mdev, max_wqe_sz_sq));
		return -EINVAL;
	}

	if (ucmd->sq_wqe_count && ((1 << ilog2(ucmd->sq_wqe_count)) != ucmd->sq_wqe_count)) {
		mlx5_ib_warn(dev, "sq_wqe_count %d, sq_wqe_count %d\n",
			     ucmd->sq_wqe_count, ucmd->sq_wqe_count);
		return -EINVAL;
	}

	qp->sq.wqe_cnt = ucmd->sq_wqe_count;

	if (qp->sq.wqe_cnt > (1 << MLX5_CAP_GEN(dev->mdev, log_max_qp_sz))) {
		mlx5_ib_warn(dev, "wqe_cnt %d, max_wqes %d\n",
			     qp->sq.wqe_cnt,
			     1 << MLX5_CAP_GEN(dev->mdev, log_max_qp_sz));
		return -EINVAL;
	}


	if (attr->qp_type == IB_QPT_RAW_PACKET) {
		qp->buf_size = qp->rq.wqe_cnt << qp->rq.wqe_shift;
		qp->sq_buf_size = qp->sq.wqe_cnt << 6;
	} else {
		qp->buf_size = (qp->rq.wqe_cnt << qp->rq.wqe_shift) +
			       (qp->sq.wqe_cnt << 6);
		qp->sq_buf_size = 0;
	}

	return 0;
}

static int qp_has_rq(struct ib_exp_qp_init_attr *attr)
{
	if (attr->qp_type == IB_QPT_XRC_INI ||
	    attr->qp_type == IB_QPT_XRC_TGT || attr->srq ||
	    attr->qp_type == MLX5_IB_QPT_REG_UMR ||
	    !attr->cap.max_recv_wr)
		return 0;

	return 1;
}

static int first_med_uuar(void)
{
	return 1;
}

static int next_uuar(int n)
{
	n++;

	while (((n % 4) & 2))
		n++;

	return n;
}

static int num_med_uuar(struct mlx5_uuar_info *uuari)
{
	int n;

	n = uuari->num_uars * MLX5_NON_FP_BF_REGS_PER_PAGE -
		uuari->num_low_latency_uuars - 1;

	return n >= 0 ? n : 0;
}

static int max_uuari(struct mlx5_uuar_info *uuari)
{
	return uuari->num_uars * 4;
}

static int first_hi_uuar(struct mlx5_uuar_info *uuari)
{
	int med;
	int i;
	int t;

	med = num_med_uuar(uuari);
	for (t = 0, i = first_med_uuar();; i = next_uuar(i)) {
		t++;
		if (t == med)
			return next_uuar(i);
	}

	return 0;
}

static int alloc_high_class_uuar(struct mlx5_uuar_info *uuari)
{
	int i;

	for (i = first_hi_uuar(uuari); i < max_uuari(uuari); i = next_uuar(i)) {
		if (!test_bit(i, uuari->bitmap)) {
			set_bit(i, uuari->bitmap);
			uuari->count[i]++;
			return i;
		}
	}

	return -ENOMEM;
}

static int alloc_med_class_uuar(struct mlx5_uuar_info *uuari)
{
	int minidx = first_med_uuar();
	int i;

	for (i = first_med_uuar(); i < first_hi_uuar(uuari); i = next_uuar(i)) {
		if (uuari->count[i] < uuari->count[minidx])
			minidx = i;
	}

	uuari->count[minidx]++;

	return minidx;
}

static int alloc_uuar(struct mlx5_uuar_info *uuari,
		      enum mlx5_ib_latency_class lat)
{
	int uuarn = -EINVAL;

	mutex_lock(&uuari->lock);
	switch (lat) {
	case MLX5_IB_LATENCY_CLASS_LOW:
		uuarn = 0;
		uuari->count[uuarn]++;
		break;

	case MLX5_IB_LATENCY_CLASS_MEDIUM:
		if (uuari->ver < 2)
			uuarn = -ENOMEM;
		else
			uuarn = alloc_med_class_uuar(uuari);
		break;

	case MLX5_IB_LATENCY_CLASS_HIGH:
		if (uuari->ver < 2)
			uuarn = -ENOMEM;
		else
			uuarn = alloc_high_class_uuar(uuari);
		break;

	case MLX5_IB_LATENCY_CLASS_FAST_PATH:
		uuarn = 2;
		break;
	}
	mutex_unlock(&uuari->lock);

	return uuarn;
}

static void free_med_class_uuar(struct mlx5_uuar_info *uuari, int uuarn)
{
	clear_bit(uuarn, uuari->bitmap);
	--uuari->count[uuarn];
}

static void free_high_class_uuar(struct mlx5_uuar_info *uuari, int uuarn)
{
	clear_bit(uuarn, uuari->bitmap);
	--uuari->count[uuarn];
}

static void free_uuar(struct mlx5_uuar_info *uuari, int uuarn)
{
	int nuuars = uuari->num_uars * MLX5_BF_REGS_PER_PAGE;
	int high_uuar = nuuars - uuari->num_low_latency_uuars;

	mutex_lock(&uuari->lock);
	if (uuarn == 0) {
		--uuari->count[uuarn];
		goto out;
	}

	if (uuarn < high_uuar) {
		free_med_class_uuar(uuari, uuarn);
		goto out;
	}

	free_high_class_uuar(uuari, uuarn);

out:
	mutex_unlock(&uuari->lock);
}

static enum mlx5_qp_state to_mlx5_state(enum ib_qp_state state)
{
	switch (state) {
	case IB_QPS_RESET:	return MLX5_QP_STATE_RST;
	case IB_QPS_INIT:	return MLX5_QP_STATE_INIT;
	case IB_QPS_RTR:	return MLX5_QP_STATE_RTR;
	case IB_QPS_RTS:	return MLX5_QP_STATE_RTS;
	case IB_QPS_SQD:	return MLX5_QP_STATE_SQD;
	case IB_QPS_SQE:	return MLX5_QP_STATE_SQER;
	case IB_QPS_ERR:	return MLX5_QP_STATE_ERR;
	default:		return -1;
	}
}

static int to_mlx5_st(enum ib_qp_type type)
{
	switch (type) {
	case IB_QPT_RC:			return MLX5_QP_ST_RC;
	case IB_QPT_UC:			return MLX5_QP_ST_UC;
	case IB_QPT_UD:			return MLX5_QP_ST_UD;
	case MLX5_IB_QPT_REG_UMR:	return MLX5_QP_ST_REG_UMR;
	case MLX5_IB_QPT_SW_CNAK:	return MLX5_QP_ST_SW_CNAK;
	case IB_QPT_XRC_INI:
	case IB_QPT_XRC_TGT:		return MLX5_QP_ST_XRC;
	case IB_QPT_SMI:		return MLX5_QP_ST_QP0;
	case IB_QPT_GSI:		return MLX5_QP_ST_QP1;
	case IB_QPT_RAW_IPV6:		return MLX5_QP_ST_RAW_IPV6;
	case IB_QPT_RAW_PACKET:
	case IB_QPT_RAW_ETHERTYPE:	return MLX5_QP_ST_RAW_ETHERTYPE;
	case IB_EXP_QPT_DC_INI:		return MLX5_QP_ST_DC;
	case IB_QPT_MAX:
	default:		return -EINVAL;
	}
}

static void mlx5_ib_lock_cqs(struct mlx5_ib_cq *send_cq,
			     struct mlx5_ib_cq *recv_cq);
static void mlx5_ib_unlock_cqs(struct mlx5_ib_cq *send_cq,
			       struct mlx5_ib_cq *recv_cq);

static int uuarn_to_uar_index(struct mlx5_uuar_info *uuari, int uuarn)
{
	return uuari->uars[uuarn / MLX5_BF_REGS_PER_PAGE].index;
}

static void destroy_user_rq(struct ib_pd *pd, struct mlx5_ib_rwq *rwq)
{
	struct mlx5_ib_ucontext *context;

	context = to_mucontext(pd->uobject->context);
	mlx5_ib_db_unmap_user(context, &rwq->db);
	if (rwq->umem)
		ib_umem_release(rwq->umem);
}

static int create_user_rq(struct mlx5_ib_dev *dev, struct ib_pd *pd,
			  struct mlx5_ib_rwq *rwq,
			  struct mlx5_ib_create_wq *ucmd)
{
	struct mlx5_ib_ucontext *context;
	int page_shift = 0;
	int npages;
	u32 offset = 0;
	int ncont = 0;
	int err;

	if (!ucmd->buf_addr || rwq->buf_size <= 0)
		return -EINVAL;

	context = to_mucontext(pd->uobject->context);
	rwq->umem = ib_umem_get(pd->uobject->context, ucmd->buf_addr,
			       rwq->buf_size, 0, 0);
	if (IS_ERR(rwq->umem)) {
		mlx5_ib_warn(dev, "umem_get failed\n");
		err = PTR_ERR(rwq->umem);
		return err;
	}

	mlx5_ib_cont_pages(rwq->umem, ucmd->buf_addr, 0, &npages, &page_shift,
			   &ncont, NULL);
	err = mlx5_ib_get_buf_offset(ucmd->buf_addr, page_shift,
				     &rwq->rq_page_offset);
	if (err) {
		mlx5_ib_warn(dev, "bad offset\n");
		goto err_umem;
	}

	rwq->rq_num_pas = ncont;
	rwq->page_shift = page_shift;
	rwq->log_page_size =  page_shift - MLX5_ADAPTER_PAGE_SHIFT;
	rwq->wq_sig = !!(ucmd->flags & MLX5_WQ_FLAG_SIGNATURE);

	mlx5_ib_dbg(dev, "addr 0x%llx, size %d, npages %d, page_shift %d, ncont %d, offset %d\n",
		    (unsigned long long)ucmd->buf_addr, rwq->buf_size,
		    npages, page_shift, ncont, offset);

	err = mlx5_ib_db_map_user(context, ucmd->db_addr, &rwq->db);
	if (err) {
		mlx5_ib_warn(dev, "map failed\n");
		goto err_umem;
	}

	rwq->create_type = MLX5_WQ_USER;
	return 0;

err_umem:
	ib_umem_release(rwq->umem);
	return err;
}

static void mlx5_qp_invalidate_umem(void *invalidation_cookie,
                                    struct ib_umem *umem,
                                    unsigned long addr, size_t size)
{
	struct mlx5_ib_qp *qp = (struct mlx5_ib_qp *)invalidation_cookie;

	printk(KERN_ERR "WARN  mlx5_qp_invalidate_umem qp=%p umem=%p\n", qp, umem);

	/* This function is called under client peer lock so its resources are race protected */
	if (atomic_inc_return(&qp->invalidated) > 1) {
		printk(KERN_ERR "invalidation is already in-flight\n");
		umem->invalidation_ctx->inflight_invalidation = 1;
		return;
	}

        if (umem != qp->umem) {
            printk(KERN_ERR "ERR unexpected qp->umem=%p != umem=%p\n", qp->umem, umem);
        } else {
            qp->umem = NULL;
        }

	umem->invalidation_ctx->peer_callback = 1;
	// TODO:
	// - free MTTs related, etc..
	// - make it ODP friendly ?
	printk(KERN_ERR "releasing umem=%p\n", umem);
	ib_umem_release(umem);
	complete(&qp->invalidation_comp);
}

static int create_user_qp(struct mlx5_ib_dev *dev, struct ib_pd *pd,
			  struct mlx5_ib_qp *qp, struct ib_udata *udata,
			  struct ib_exp_qp_init_attr *attr,
			  struct mlx5_create_qp_mbox_in **in,
			  int *inlen,
			  struct mlx5_exp_ib_create_qp *ucmd)
{
	struct mlx5_exp_ib_create_qp_resp resp;
	struct mlx5_ib_ucontext *context;
	int page_shift = 0;
	int uar_index;
	int npages;
	u32 offset = 0;
	int uuarn;
	int ncont = 0;
	int err;

	context = to_mucontext(pd->uobject->context);
	memset(&resp, 0, sizeof(resp));
	resp.size_of_prefix = offsetof(struct mlx5_exp_ib_create_qp_resp, prefix_reserved);
	/*
	 * TBD: should come from the verbs when we have the API
	 */
	if (ucmd->exp.comp_mask & MLX5_EXP_CREATE_QP_MASK_WC_UAR_IDX) {
		/* In CROSS_CHANNEL CQ and QP must use the same UAR */
		if (attr->create_flags & IB_QP_CREATE_CROSS_CHANNEL)
			return -EINVAL;

		if (ucmd->exp.wc_uar_index == MLX5_EXP_CREATE_QP_DB_ONLY_UUAR) {
			/* Assign LATENCY_CLASS_LOW (DB only UUAR) to this QP */
			uuarn = alloc_uuar(&context->uuari, MLX5_IB_LATENCY_CLASS_LOW);
			if (uuarn < 0) {
				mlx5_ib_warn(dev, "DB only uuar allocation failed\n");
				return uuarn;
			}
			uar_index = uuarn_to_uar_index(&context->uuari, uuarn);
		} else if (ucmd->exp.wc_uar_index >= MLX5_IB_MAX_CTX_DYNAMIC_UARS ||
			   context->dynamic_wc_uar_index[ucmd->exp.wc_uar_index] ==
			   MLX5_IB_INVALID_UAR_INDEX) {
			mlx5_ib_warn(dev, "dynamic uuar allocation failed\n");
			return -EINVAL;
		} else {
			uar_index = context->dynamic_wc_uar_index[ucmd->exp.wc_uar_index];
			uuarn = MLX5_EXP_INVALID_UUAR;
		}
	} else if (attr->create_flags & IB_QP_CREATE_CROSS_CHANNEL) {
		uuarn = MLX5_CROSS_CHANNEL_UUAR;
		uar_index = uuarn_to_uar_index(&context->uuari, uuarn);
	} else {
		uuarn = alloc_uuar(&context->uuari, MLX5_IB_LATENCY_CLASS_HIGH);
		if (uuarn < 0) {
			mlx5_ib_dbg(dev, "failed to allocate low latency UUAR\n");
			mlx5_ib_dbg(dev, "reverting to medium latency\n");
			uuarn = alloc_uuar(&context->uuari, MLX5_IB_LATENCY_CLASS_MEDIUM);
			if (uuarn < 0) {
				mlx5_ib_dbg(dev, "failed to allocate medium latency UUAR\n");
				mlx5_ib_dbg(dev, "reverting to high latency\n");
				uuarn = alloc_uuar(&context->uuari, MLX5_IB_LATENCY_CLASS_LOW);
				if (uuarn < 0) {
					mlx5_ib_warn(dev, "uuar allocation failed\n");
					return uuarn;
				}
			}
		}
		uar_index = uuarn_to_uar_index(&context->uuari, uuarn);
	}
	mlx5_ib_dbg(dev, "uuarn 0x%x, uar_index 0x%x\n", uuarn, uar_index);

	qp->rq.offset = 0;
	qp->sq.wqe_shift = ilog2(MLX5_SEND_WQE_BB);
	qp->sq.offset = qp->rq.wqe_cnt << qp->rq.wqe_shift;

	err = set_user_buf_size(dev, qp, (struct mlx5_ib_create_qp *)ucmd, attr);
	if (err)
		goto err_uuar;

	if (ucmd->buf_addr && qp->buf_size) {
		//qp->umem = ib_umem_get(pd->uobject->context, ucmd->buf_addr,
		//		       qp->buf_size, 0, 0);
                qp->umem = ib_umem_get_ex(pd->uobject->context, ucmd->buf_addr,
                                          qp->buf_size, 0, 0, 1);
		if (IS_ERR(qp->umem)) {
			mlx5_ib_warn(dev, "umem_get failed\n");
			err = PTR_ERR(qp->umem);
			goto err_uuar;
		}
                if (qp->umem->ib_peer_mem)
                        printk(KERN_ERR "INFO create_user_qp got peer_mem, qp=%p umem=%p\n", qp, qp->umem);
	} else {
		qp->umem = NULL;
	}

	if (qp->umem) {
		mlx5_ib_cont_pages(qp->umem, ucmd->buf_addr, 0, &npages,
				   &page_shift, &ncont, NULL);
		err = mlx5_ib_get_buf_offset(ucmd->buf_addr, page_shift, &offset);
		if (err) {
			mlx5_ib_warn(dev, "bad offset\n");
			goto err_umem;
		}
		mlx5_ib_dbg(dev, "addr 0x%llx, size %d, npages %d, page_shift %d, ncont %d, offset %d\n",
			    ucmd->buf_addr, qp->buf_size, npages, page_shift, ncont, offset);
	}

	*inlen = sizeof(**in) + sizeof(*(*in)->pas) * ncont;
	*in = mlx5_vzalloc(*inlen);
	if (!*in) {
		err = -ENOMEM;
		goto err_umem;
	}
	if (qp->umem)
		mlx5_ib_populate_pas(dev, qp->umem, page_shift, (*in)->pas, 0);
	(*in)->ctx.log_pg_sz_remote_qpn =
		cpu_to_be32((page_shift - MLX5_ADAPTER_PAGE_SHIFT) << 24);
	(*in)->ctx.params2 = cpu_to_be32(offset << 6);

	(*in)->ctx.params2 |= (qp->flags & MLX5_IB_QP_CAP_CROSS_CHANNEL ?
		cpu_to_be32(MLX5_QP_BIT_COLL_MASTER) : 0);
	(*in)->ctx.params2 |= (qp->flags & MLX5_IB_QP_CAP_MANAGED_SEND ?
		cpu_to_be32(MLX5_QP_BIT_COLL_SYNC_SQ) : 0);
	(*in)->ctx.params2 |= (qp->flags & MLX5_IB_QP_CAP_MANAGED_RECV ?
		cpu_to_be32(MLX5_QP_BIT_COLL_SYNC_RQ) : 0);

	(*in)->ctx.qp_counter_set_usr_page = cpu_to_be32(uar_index);
	resp.uuar_index = uuarn;
	qp->uuarn = uuarn;

	err = mlx5_ib_db_map_user(context, ucmd->db_addr, &qp->db);
	if (err) {
		mlx5_ib_warn(dev, "map failed\n");
		goto err_free;
	}

	if (udata->src == IB_UDATA_EXP_CMD &&
	    attr->qp_type == IB_QPT_RAW_PACKET && qp->sq.wqe_cnt &&
	    (ucmd->exp.comp_mask & MLX5_EXP_CREATE_QP_MASK_FLAGS_IDX) &&
	    (ucmd->exp.flags & MLX5_EXP_CREATE_QP_MULTI_PACKET_WQE_REQ_FLAG)) {
		/*
		 * Enable Multi-Packet WQE only if:
		 * - user process is privilege
		 * - SRIOV is not supported
		 * - Multi-Packet is supported
		 */
		if (capable(CAP_SYS_ADMIN) &&
		    MLX5_CAP_ETH(dev->mdev, multi_pkt_send_wqe) == 1) {
			qp->allow_mp_wqe = 1;
			resp.exp.comp_mask |= MLX5_EXP_CREATE_QP_RESP_MASK_FLAGS_IDX;
			resp.exp.flags |= MLX5_EXP_CREATE_QP_RESP_MULTI_PACKET_WQE_FLAG;
		}
	}
	if (udata->src == IB_UDATA_EXP_CMD)
		err = ib_copy_to_udata(udata, &resp, min(udata->outlen, sizeof(resp)));
	else
		err = ib_copy_to_udata(udata, &resp, sizeof(struct mlx5_ib_create_qp_resp));

	if (err) {
		mlx5_ib_err(dev, "copy failed\n");
		goto err_unmap;
	}
	qp->create_type = MLX5_QP_USER;

	atomic_set(&qp->invalidated, 0);
	if (qp->umem && qp->umem->ib_peer_mem) {
		init_completion(&qp->invalidation_comp);
		ib_umem_activate_invalidation_notifier(qp->umem, mlx5_qp_invalidate_umem, qp);
	}

	return 0;

err_unmap:
	mlx5_ib_db_unmap_user(context, &qp->db);

err_free:
	kvfree(*in);

err_umem:
	if (qp->umem)
		ib_umem_release(qp->umem);

err_uuar:
	free_uuar(&context->uuari, uuarn);
	return err;
}

static void destroy_qp_user(struct ib_pd *pd, struct mlx5_ib_qp *qp)
{
	struct mlx5_ib_ucontext *context;

	context = to_mucontext(pd->uobject->context);
	mlx5_ib_db_unmap_user(context, &qp->db);
	if (qp->umem)
		ib_umem_release(qp->umem);
	if (qp->sq_umem)
		ib_umem_release(qp->sq_umem);
	/*
	 * Free only the UUARs handled by the kernel.
	 * UUARs of UARs allocated dynamically are handled by user.
	 */
	if (qp->uuarn != MLX5_EXP_INVALID_UUAR)
		free_uuar(&context->uuari, qp->uuarn);
}

static bool verify_flags(struct mlx5_ib_dev *dev,
			 struct ib_exp_qp_init_attr *init_attr)
{
	struct mlx5_core_dev *mdev = dev->mdev;

	if ((init_attr->create_flags & ~(IB_QP_CREATE_SIGNATURE_EN |
					IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK |
					IB_QP_CREATE_IPOIB_UD_LSO)) ||
	    ((init_attr->qp_type == IB_QPT_UD) &&
	     (init_attr->create_flags & IB_QP_CREATE_IPOIB_UD_LSO) &&
	     !MLX5_CAP_GEN(mdev, ipoib_basic_offloads)))
		return false;

	return true;
}

static int create_kernel_qp(struct mlx5_ib_dev *dev,
			    struct ib_exp_qp_init_attr *init_attr,
			    struct mlx5_ib_qp *qp,
			    struct mlx5_create_qp_mbox_in **in, int *inlen)
{
	enum mlx5_ib_latency_class lc = MLX5_IB_LATENCY_CLASS_LOW;
	struct mlx5_uuar_info *uuari;
	int uar_index;
	int uuarn;
	int err;

	uuari = &dev->mdev->priv.uuari;
	if (!verify_flags(dev, init_attr))
		return -EINVAL;

	if (init_attr->qp_type == MLX5_IB_QPT_REG_UMR)
		lc = MLX5_IB_LATENCY_CLASS_FAST_PATH;

	uuarn = alloc_uuar(uuari, lc);
	if (uuarn < 0) {
		mlx5_ib_warn(dev, "\n");
		return -ENOMEM;
	}

	qp->bf = &uuari->bfs[uuarn];
	uar_index = qp->bf->uar->index;

	err = calc_sq_size(dev, init_attr, qp);
	if (err < 0) {
		mlx5_ib_warn(dev, "err %d\n", err);
		goto err_uuar;
	}

	qp->rq.offset = 0;
	qp->sq.offset = qp->rq.wqe_cnt << qp->rq.wqe_shift;
	qp->buf_size = err + (qp->rq.wqe_cnt << qp->rq.wqe_shift);

	err = mlx5_buf_alloc(dev->mdev, qp->buf_size, PAGE_SIZE * 2, &qp->buf);
	if (err) {
		mlx5_ib_warn(dev, "err %d\n", err);
		goto err_uuar;
	}

	qp->sq.qend = mlx5_get_send_wqe(qp, qp->sq.wqe_cnt);
	*inlen = sizeof(**in) + sizeof(*(*in)->pas) * qp->buf.npages;
	*in = mlx5_vzalloc(*inlen);
	if (!*in) {
		err = -ENOMEM;
		goto err_buf;
	}
	(*in)->ctx.qp_counter_set_usr_page = cpu_to_be32(uar_index);
	(*in)->ctx.log_pg_sz_remote_qpn =
		cpu_to_be32((qp->buf.page_shift - MLX5_ADAPTER_PAGE_SHIFT) << 24);
	/* Set "fast registration enabled" for all kernel QPs */
	(*in)->ctx.params1 |= cpu_to_be32(1 << 11);
	(*in)->ctx.sq_crq_size |= cpu_to_be16(1 << 4);

	mlx5_fill_page_array(&qp->buf, (*in)->pas);

	err = mlx5_db_alloc(dev->mdev, &qp->db);
	if (err) {
		mlx5_ib_warn(dev, "err %d\n", err);
		goto err_free;
	}

	qp->sq.swr_ctx = kcalloc(qp->sq.wqe_cnt, sizeof(*qp->sq.swr_ctx),
				 GFP_KERNEL);
	qp->rq.rwr_ctx = kcalloc(qp->rq.wqe_cnt, sizeof(*qp->rq.rwr_ctx),
				 GFP_KERNEL);
	if (!qp->sq.swr_ctx || !qp->rq.rwr_ctx) {
		err = -ENOMEM;
		goto err_wrid;
	}
	qp->create_type = MLX5_QP_KERNEL;

	return 0;

err_wrid:
	mlx5_db_free(dev->mdev, &qp->db);
	kfree(qp->sq.swr_ctx);
	kfree(qp->rq.rwr_ctx);

err_free:
	kvfree(*in);

err_buf:
	mlx5_buf_free(dev->mdev, &qp->buf);

err_uuar:
	free_uuar(&dev->mdev->priv.uuari, uuarn);
	return err;
}

static void destroy_qp_kernel(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp)
{
	mlx5_db_free(dev->mdev, &qp->db);
	kfree(qp->sq.swr_ctx);
	kfree(qp->rq.rwr_ctx);
	mlx5_buf_free(dev->mdev, &qp->buf);
	free_uuar(&dev->mdev->priv.uuari, qp->bf->uuarn);
}

static __be32 get_rx_type(struct mlx5_ib_qp *qp, struct ib_exp_qp_init_attr *attr)
{
	enum ib_qp_type qt = attr->qp_type;

	if (attr->srq || (qt == IB_QPT_XRC_TGT) || (qt == IB_QPT_XRC_INI) ||
	    (qt == IB_EXP_QPT_DC_INI))
		return cpu_to_be32(MLX5_SRQ_RQ);
	else if (!qp->has_rq)
		return cpu_to_be32(MLX5_ZERO_LEN_RQ);
	else
		return cpu_to_be32(MLX5_NON_ZERO_RQ);
}

static int is_connected(enum ib_qp_type qp_type)
{
	if (qp_type == IB_QPT_RC || qp_type == IB_QPT_UC)
		return 1;

	return 0;
}

static void get_cqs(enum ib_qp_type qp_type,
		    struct ib_cq *ib_send_cq, struct ib_cq *ib_recv_cq,
		    struct mlx5_ib_cq **send_cq, struct mlx5_ib_cq **recv_cq)
{
	switch (qp_type) {
	case IB_QPT_XRC_TGT:
		*send_cq = NULL;
		*recv_cq = NULL;
		break;
	case MLX5_IB_QPT_REG_UMR:
	case IB_QPT_XRC_INI:
		*send_cq = ib_send_cq ? to_mcq(ib_send_cq) : NULL;
		*recv_cq = NULL;
		break;

	case IB_QPT_SMI:
	case IB_QPT_GSI:
	case IB_QPT_RC:
	case IB_QPT_UC:
	case IB_QPT_UD:
	case IB_QPT_RAW_IPV6:
	case IB_QPT_RAW_ETHERTYPE:
	case MLX5_IB_QPT_SW_CNAK:
	case IB_QPT_RAW_PACKET:
		*send_cq = ib_send_cq ? to_mcq(ib_send_cq) : NULL;
		*recv_cq = ib_recv_cq ? to_mcq(ib_recv_cq) : NULL;
		break;

	case IB_QPT_MAX:
	default:
		*send_cq = NULL;
		*recv_cq = NULL;
		break;
	}
}

static void destroy_rss_raw_qp_tir(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp)
{
	mlx5_core_destroy_tir(dev->mdev, qp->tirn);
}

static int create_rss_raw_qp_tir(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp,
				 struct ib_pd *pd,
				 struct ib_exp_qp_init_attr *init_attr)
{
	struct ib_uobject *uobj = pd->uobject;
	struct ib_ucontext *ucontext = uobj->context;
	struct mlx5_ib_ucontext *mucontext = to_mucontext(ucontext);
	int inlen;
	int err;
	u32 *in;
	void *tirc;
	void *hfso;
	u32 selected_fields = 0;
	u32 tdn = mucontext->tdn;

	inlen = MLX5_ST_SZ_BYTES(create_tir_in);
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);
	MLX5_SET(tirc, tirc, disp_type,
		 MLX5_TIRC_DISP_TYPE_INDIRECT);
	MLX5_SET(tirc, tirc, indirect_table,
		 init_attr->rx_hash_conf->rwq_ind_tbl->ind_tbl_num);
	MLX5_SET(tirc, tirc, transport_domain, tdn);

	hfso = MLX5_ADDR_OF(tirc, tirc, rx_hash_field_selector_outer);
	switch (init_attr->rx_hash_conf->rx_hash_function) {
	case IB_EX_RX_HASH_FUNC_XOR:
		err = -ENOSYS;
		goto err;

	case IB_EX_RX_HASH_FUNC_TOEPLITZ:
	{
		void *rss_key = MLX5_ADDR_OF(tirc, tirc, rx_hash_toeplitz_key);
		size_t len = MLX5_FLD_SZ_BYTES(tirc, rx_hash_toeplitz_key);

		if (len != init_attr->rx_hash_conf->rx_key_len) {
			err = -EINVAL;
			goto err;
		}

		MLX5_SET(tirc, tirc, rx_hash_fn, MLX5_TIRC_RX_HASH_FN_HASH_TOEPLITZ);
		MLX5_SET(tirc, tirc, rx_hash_symmetric, 1);
		memcpy(rss_key, init_attr->rx_hash_conf->rx_hash_key, len);
		break;
	}
	default:
		err = -EINVAL;
		goto err;
	}

	if (!init_attr->rx_hash_conf->rx_hash_fields_mask) {
		/* special case when this TIR serves as steering entry without hashing */
		if (!init_attr->rx_hash_conf->rwq_ind_tbl->log_ind_tbl_size)
			goto create_tir;
		err = -EINVAL;
		goto err;
	}

	if (((init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_SRC_IPV4) ||
	     (init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_DST_IPV4)) &&
	     ((init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_SRC_IPV6) ||
	     (init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_DST_IPV6))) {
		err = -EINVAL;
		goto err;
	}

	/* If none of IPV4 & IPV6 SRC/DST was set - this bit field is ignored */
	if ((init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_SRC_IPV4) ||
	    (init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_DST_IPV4))
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV4);
	else if ((init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_SRC_IPV6) ||
		 (init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_DST_IPV6))
		MLX5_SET(rx_hash_field_select, hfso, l3_prot_type,
			 MLX5_L3_PROT_TYPE_IPV6);

	if (((init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_SRC_PORT_TCP) ||
	     (init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_DST_PORT_TCP)) &&
	     ((init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_SRC_PORT_UDP) ||
	     (init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_DST_PORT_UDP))) {
		err = -EINVAL;
		goto err;
	}

	/* If none of TCP & UDP SRC/DST was set - this bit field is ignored */
	if ((init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_SRC_PORT_TCP) ||
	    (init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_DST_PORT_TCP))
		MLX5_SET(rx_hash_field_select, hfso, l4_prot_type,
			 MLX5_L4_PROT_TYPE_TCP);
	else if ((init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_SRC_PORT_UDP) ||
		 (init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_DST_PORT_UDP))
		MLX5_SET(rx_hash_field_select, hfso, l4_prot_type,
			 MLX5_L4_PROT_TYPE_UDP);

	if ((init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_SRC_IPV4) ||
	    (init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_SRC_IPV6))
		selected_fields |= MLX5_HASH_FIELD_SEL_SRC_IP;

	if ((init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_DST_IPV4) ||
	    (init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_DST_IPV6))
			selected_fields |= MLX5_HASH_FIELD_SEL_DST_IP;

	if ((init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_SRC_PORT_TCP) ||
	    (init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_SRC_PORT_UDP))
			selected_fields |= MLX5_HASH_FIELD_SEL_L4_SPORT;

	if ((init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_DST_PORT_TCP) ||
	    (init_attr->rx_hash_conf->rx_hash_fields_mask & IB_RX_HASH_DST_PORT_UDP))
			selected_fields |= MLX5_HASH_FIELD_SEL_L4_DPORT;

	MLX5_SET(rx_hash_field_select, hfso, selected_fields, selected_fields);

create_tir:
	err = mlx5_core_create_tir(dev->mdev, in, inlen, &qp->tirn);

	if (err)
		goto err;

	kvfree(in);
	/* qpn is reserved for that QP */
	qp->mqp.qpn = 0;
	return 0;

err:
	kvfree(in);
	return err;
}

static int create_raw_qp_tis(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp,
			     u32 tdn)
{
	u32 in[MLX5_ST_SZ_DW(create_tis_in)];
	void *tisc = MLX5_ADDR_OF(create_tis_in, in, ctx);

	memset(in, 0, sizeof(in));

	MLX5_SET(tisc, tisc, transport_domain, tdn);

	return mlx5_core_create_tis(dev->mdev, in, sizeof(in), &qp->tisn);
}

static void destroy_raw_qp_tis(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp)
{
	mlx5_core_destroy_tis(dev->mdev, qp->tisn);
}

static void mlx5_ib_sq_event(struct mlx5_core_qp *sq, int type)
{
	struct ib_qp *ibqp = &sq_to_mibqp(sq)->ibqp;
	struct ib_event event;

	if (ibqp->event_handler) {
		event.device     = ibqp->device;
		event.element.qp = ibqp;
		switch (type) {
		case MLX5_EVENT_TYPE_WQ_CATAS_ERROR:
			event.event = IB_EVENT_QP_FATAL;
			break;
		default:
			pr_warn("mlx5_ib: Unexpected event type %d on SQ %06x\n",
				type, sq->qpn);
			return;
		}

		ibqp->event_handler(&event, ibqp->qp_context);
	}
}

static void mlx5_ib_rq_event(struct mlx5_core_qp *rq, int type)
{
	struct ib_qp *ibqp = &rq_to_mibqp(rq)->ibqp;
	struct ib_event event;

	if (ibqp->event_handler) {
		event.device     = ibqp->device;
		event.element.qp = ibqp;
		switch (type) {
		case MLX5_EVENT_TYPE_SRQ_LAST_WQE:
			event.event = IB_EVENT_QP_LAST_WQE_REACHED;
			break;
		case MLX5_EVENT_TYPE_WQ_CATAS_ERROR:
			event.event = IB_EVENT_QP_FATAL;
			break;
		default:
			pr_warn("mlx5_ib: Unexpected event type %d on RQ %06x\n",
				type, rq->qpn);
			return;
		}

		ibqp->event_handler(&event, ibqp->qp_context);
	}
}

static int create_raw_qp_sq(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp,
			    void *qpin, struct ib_pd *pd)
{
	__be64 *pas;
	void *in;
	void *sqc;
	void *qpc = MLX5_ADDR_OF(create_qp_in, qpin, qpc);
	void *wq;
	int inlen;
	int err;
	int page_shift = 0;
	int npages;
	int ncont = 0;
	u32 offset = 0;

	qp->sq_umem = ib_umem_get(pd->uobject->context, qp->sq_buf_addr,
				  qp->sq_buf_size, 0, 0);
	if (IS_ERR(qp->sq_umem)) {
		mlx5_ib_warn(dev, "umem_get failed\n");
		qp->sq_umem = NULL;
		return -ENOMEM;
	}

	mlx5_ib_cont_pages(qp->sq_umem, qp->sq_buf_addr, 0, &npages,
			   &page_shift, &ncont, NULL);
	err = mlx5_ib_get_buf_offset(qp->sq_buf_addr, page_shift, &offset);
	if (err) {
		mlx5_ib_warn(dev, "SQ bad offset\n");
		err = -EINVAL;
		goto err_umem;
	}

	mlx5_ib_dbg(dev, "addr 0x%llx, size %d, npages %d, page_shift %d, ncont %d, offset %d\n",
		    qp->sq_buf_addr, qp->sq_buf_size, npages, page_shift, ncont, offset);

	inlen = MLX5_ST_SZ_BYTES(create_sq_in) + sizeof(u64) * ncont;
	in = mlx5_vzalloc(inlen);
	if (!in) {
		mlx5_ib_err(dev, "allocation failed\n");
		err = -ENOMEM;
		goto err_umem;
	}

	sqc = MLX5_ADDR_OF(create_sq_in, in, ctx);
	MLX5_SET(sqc, sqc, flush_in_error_en, 1);
	MLX5_SET(sqc, sqc, allow_multi_pkt_send_wqe, qp->allow_mp_wqe);
	MLX5_SET(sqc, sqc, state, MLX5_SQC_STATE_RST);
	MLX5_SET(sqc, sqc, user_index, MLX5_GET(qpc, qpc, user_index));
	MLX5_SET(sqc, sqc, cqn, MLX5_GET(qpc, qpc, cqn_snd));
	MLX5_SET(sqc, sqc, tis_lst_sz, 1);
	MLX5_SET(sqc, sqc, tis_num_0, qp->tisn);

	wq = MLX5_ADDR_OF(sqc, sqc, wq);
	MLX5_SET(wq, wq, wq_type, MLX5_WQ_TYPE_CYCLIC);
	MLX5_SET(wq, wq, pd, MLX5_GET(qpc, qpc, pd));
	MLX5_SET(wq, wq, uar_page, MLX5_GET(qpc, qpc, uar_page));
	MLX5_SET64(wq, wq, dbr_addr, MLX5_GET64(qpc, qpc, dbr_addr));
	MLX5_SET(wq, wq, log_wq_stride, ilog2(MLX5_SEND_WQE_BB));
	MLX5_SET(wq, wq, log_wq_sz, MLX5_GET(qpc, qpc, log_sq_size));
	MLX5_SET(wq, wq, log_wq_pg_sz,  page_shift - MLX5_ADAPTER_PAGE_SHIFT);
	MLX5_SET(wq, wq, page_offset, offset);


	pas = (__be64 *)MLX5_ADDR_OF(wq, wq, pas);
	mlx5_ib_populate_pas(dev, qp->sq_umem, page_shift, pas, 0);

	err = mlx5_core_create_sq_tracked(dev->mdev, in, inlen, &qp->msq);
	kvfree(in);
	if (err)
		goto err_umem;

	return 0;

err_umem:
	ib_umem_release(qp->sq_umem);
	qp->sq_umem = NULL;

	return err;
}

static void destroy_raw_qp_sq(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp)
{
	mlx5_core_destroy_sq_tracked(dev->mdev, &qp->msq);
}

static int get_rq_pas_size(void *qpc)
{
	u32 log_page_size = MLX5_GET(qpc, qpc, log_page_size) + 12;
	u32 log_rq_stride = MLX5_GET(qpc, qpc, log_rq_stride);
	u32 log_rq_size   = MLX5_GET(qpc, qpc, log_rq_size);
	u32 page_offset   = MLX5_GET(qpc, qpc, page_offset);
	u32 po_quanta	  = 1 << (log_page_size - 6);
	u32 rq_sz	  = 1 << (log_rq_size + 4 + log_rq_stride);
	u32 page_size	  = 1 << log_page_size;
	u32 rq_sz_po      = rq_sz + (page_offset * po_quanta);
	u32 rq_num_pas	  = (rq_sz_po + page_size - 1) / page_size;

	return rq_num_pas * sizeof(u64);
}

static int create_raw_qp_rq(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp,
			    void *qpin)
{
	__be64 *pas;
	__be64 *qp_pas;
	void *in;
	void *rqc;
	void *wq;
	void *qpc = MLX5_ADDR_OF(create_qp_in, qpin, qpc);
	int inlen;
	int err;
	u32 rq_pas_size = get_rq_pas_size(qpc);

	inlen = MLX5_ST_SZ_BYTES(create_rq_in) + rq_pas_size;
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	rqc = MLX5_ADDR_OF(create_rq_in, in, ctx);
	MLX5_SET(rqc, rqc, vsd, 1);
	MLX5_SET(rqc, rqc, mem_rq_type, MLX5_RQC_MEM_RQ_TYPE_MEMORY_RQ_INLINE);
	MLX5_SET(rqc, rqc, state, MLX5_RQC_STATE_RST);
	MLX5_SET(rqc, rqc, flush_in_error_en, 1);
	MLX5_SET(rqc, rqc, user_index, MLX5_GET(qpc, qpc, user_index));
	MLX5_SET(rqc, rqc, cqn, MLX5_GET(qpc, qpc, cqn_rcv));

	if (qp->flags & MLX5_IB_QP_CAP_SCATTER_FCS)
		MLX5_SET(rqc, rqc, scatter_fcs, 1);

	wq = MLX5_ADDR_OF(rqc, rqc, wq);
	MLX5_SET(wq, wq, wq_type, MLX5_WQ_TYPE_CYCLIC);
	MLX5_SET(wq, wq, end_padding_mode, MLX5_GET(qpc, qpc, end_padding_mode));
	MLX5_SET(wq, wq, page_offset, MLX5_GET(qpc, qpc, page_offset));
	MLX5_SET(wq, wq, pd, MLX5_GET(qpc, qpc, pd));
	MLX5_SET64(wq, wq, dbr_addr, MLX5_GET64(qpc, qpc, dbr_addr));
	MLX5_SET(wq, wq, log_wq_stride, MLX5_GET(qpc, qpc, log_rq_stride) + 4);
	MLX5_SET(wq, wq, log_wq_pg_sz, MLX5_GET(qpc, qpc, log_page_size));
	MLX5_SET(wq, wq, log_wq_sz, MLX5_GET(qpc, qpc, log_rq_size));

	pas = (__be64 *)MLX5_ADDR_OF(wq, wq, pas);
	qp_pas = (__be64 *)MLX5_ADDR_OF(create_qp_in, qpin, pas);
	memcpy(pas, qp_pas, rq_pas_size);

	err = mlx5_core_create_rq_tracked(dev->mdev, in, inlen, &qp->mrq);
	kvfree(in);

	return err;
}

static void destroy_raw_qp_rq(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp)
{
	mlx5_core_destroy_rq_tracked(dev->mdev, &qp->mrq);
}

static int create_raw_qp_tir(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp,
			     u32 tdn)
{
	u32 *in;
	void *tirc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(create_tir_in);
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	tirc = MLX5_ADDR_OF(create_tir_in, in, ctx);
	MLX5_SET(tirc, tirc, disp_type, MLX5_TIRC_DISP_TYPE_DIRECT);
	MLX5_SET(tirc, tirc, inline_rqn, qp->mrq.qpn);
	MLX5_SET(tirc, tirc, transport_domain, tdn);

	err = mlx5_core_create_tir(dev->mdev, in, inlen, &qp->tirn);

	kvfree(in);

	return err;
}

static void destroy_raw_qp_tir(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp)
{
	mlx5_core_destroy_tir(dev->mdev, qp->tirn);
}

static int create_raw_qp(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp,
			 struct mlx5_create_qp_mbox_in *in, struct ib_pd *pd)
{
	struct ib_uobject *uobj = pd->uobject;
	struct ib_ucontext *ucontext = uobj->context;
	struct mlx5_ib_ucontext *mucontext = to_mucontext(ucontext);
	int err;
	u32 tdn = mucontext->tdn;


	if (!qp->sq.wqe_cnt && !qp->rq.wqe_cnt)
		return -EINVAL;

	if (qp->sq.wqe_cnt) {
		err = create_raw_qp_tis(dev, qp, tdn);
		if (err)
			return err;

		err = create_raw_qp_sq(dev, qp, in, pd);
		if (err)
			goto err_tis;

		qp->sq_state = MLX5_SQC_STATE_RST;
		qp->msq.event = mlx5_ib_sq_event;
	}

	if (qp->rq.wqe_cnt) {
		err = create_raw_qp_rq(dev, qp, in);
		if (err)
			goto err_sq;


		err = create_raw_qp_tir(dev, qp, tdn);
		if (err)
			goto err_rq;

		qp->rq_state = MLX5_RQC_STATE_RST;
		qp->mrq.event = mlx5_ib_rq_event;
	}

	/* If we allocated SQ, then the QP number should be the SQ number,
	 * otherwise the RQ number.
	 */
	qp->mqp.qpn = qp->sq.wqe_cnt ? qp->msq.qpn : qp->mrq.qpn;

	INIT_LIST_HEAD(&qp->mc_flows_list.flows_list);
	mutex_init(&qp->mc_flows_list.lock);

	return 0;

err_rq:
	destroy_raw_qp_rq(dev, qp);
err_sq:
	if (qp->sq.wqe_cnt)
		destroy_raw_qp_sq(dev, qp);
err_tis:
	if (qp->sq.wqe_cnt)
		destroy_raw_qp_tis(dev, qp);

	return err;
}

enum {
	MLX5_QP_END_PAD_MODE_ALIGN	= MLX5_WQ_END_PAD_MODE_ALIGN,
	MLX5_QP_END_PAD_MODE_NONE	= MLX5_WQ_END_PAD_MODE_NONE,
};

static int create_qp_common(struct mlx5_ib_dev *dev, struct ib_pd *pd,
			    struct ib_exp_qp_init_attr *init_attr,
			    struct ib_udata *udata, struct mlx5_ib_qp *qp)
{
	struct mlx5_ib_resources *devr = &dev->devr;
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_create_qp_mbox_in *in;
	struct mlx5_exp_ib_create_qp ucmd;
	struct mlx5_ib_create_qp *pucmd = NULL;
	struct mlx5_ib_cq *send_cq;
	struct mlx5_ib_cq *recv_cq;
	unsigned long flags;
	int inlen = sizeof(*in);
	size_t ucmd_size;
	int err;
	int st;
	u32 uidx;
	void *qpc;

	if (udata && (init_attr->qp_type == MLX5_IB_QPT_REG_UMR ||
		      init_attr->qp_type == MLX5_IB_QPT_SW_CNAK)) {
		mlx5_ib_warn(dev, "required QP type is supported only for kernel consumers\n");
		return -ENOSYS;
	}

	mlx5_ib_odp_create_qp(qp);

	mutex_init(&qp->mutex);
	spin_lock_init(&qp->sq.lock);
	spin_lock_init(&qp->rq.lock);

	if (init_attr->rx_hash_conf) {
		if (!udata) {
			mlx5_ib_err(dev, "internal error\n");
			return -ENOSYS;
		}

		err = create_rss_raw_qp_tir(dev, qp, pd, init_attr);
		return err;
	}

	if (init_attr->create_flags & IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK) {
		if (!MLX5_CAP_GEN(mdev, block_lb_mc)) {
			mlx5_ib_warn(dev, "block multicast loopback isn't supported\n");
			return -EINVAL;
		} else {
			qp->flags |= MLX5_IB_QP_BLOCK_MULTICAST_LOOPBACK;
		}
	}

	if ((init_attr->create_flags & IB_QP_CREATE_ATOMIC_BE_REPLY) &&
	    (dev->atomic_cap != IB_ATOMIC_HCA_REPLY_BE) &&
	     mlx5_host_is_le()) {
		mlx5_ib_dbg(dev, "Create QP with atomic BE REPLY is not supported on this type HCA device\n");
		return -EINVAL;
	}
	if ((init_attr->create_flags & IB_QP_CREATE_RX_END_PADDING) &&
	    MLX5_CAP_GEN(mdev, end_pad))
		qp->flags |= MLX5_IB_QP_CAP_RX_END_PADDING;

	if (init_attr->create_flags & IB_QP_CREATE_SCATTER_FCS) {
		if (!MLX5_CAP_GEN(dev->mdev, eth_net_offloads) ||
		    !MLX5_CAP_ETH(dev->mdev, scatter_fcs)) {
			mlx5_ib_dbg(dev, "Scatter FCS is not supported by the HCA\n");
			return -EOPNOTSUPP;
		} else {
			qp->flags |= MLX5_IB_QP_CAP_SCATTER_FCS;
		}
	}

	if (init_attr->sq_sig_type == IB_SIGNAL_ALL_WR)
		qp->sq_signal_bits = MLX5_WQE_CTRL_CQ_UPDATE;

	if (init_attr->max_inl_recv)
		qp->scat_cqe = 1;

	if (pd && pd->uobject) {
		memset(&ucmd, 0, sizeof(ucmd));
		if (udata->src == IB_UDATA_EXP_CMD) {
			ucmd_size = sizeof(ucmd);
		} else {
			ucmd_size = sizeof(struct mlx5_ib_create_qp);
			if (ucmd_size > offsetof(struct mlx5_exp_ib_create_qp, size_of_prefix)) {
				mlx5_ib_warn(dev, "mlx5_ib_create_qp is too big to fit as prefix of mlx5_exp_ib_create_qp\n");
				return -EINVAL;
			}
		}
		err = ib_copy_from_udata(&ucmd, udata, min(udata->inlen, ucmd_size));
		if (err) {
			mlx5_ib_err(dev, "copy failed\n");
			return err;
		}
		if ((udata->src == IB_UDATA_EXP_CMD) &&
		    ((ucmd.size_of_prefix > sizeof(struct mlx5_ib_create_qp)) ||
		     (ucmd.exp.comp_mask >= MLX5_EXP_CREATE_QP_MASK_RESERVED))) {
			mlx5_ib_warn(dev, "Unrecognized driver data\n");
			return -EINVAL;
		}
		pucmd = (struct mlx5_ib_create_qp *)&ucmd;
		if (ucmd.exp.comp_mask & MLX5_EXP_CREATE_QP_MASK_UIDX)
			uidx = ucmd.exp.uidx;
		else
			uidx = 0xffffff;

		qp->wq_sig = !!(ucmd.flags & MLX5_QP_FLAG_SIGNATURE);
	} else {
		qp->wq_sig = !!wq_signature;
		uidx = 0xffffff;
	}

	qp->has_rq = qp_has_rq(init_attr);
	err = set_rq_size(dev, &init_attr->cap, qp->has_rq,
			  qp, (pd && pd->uobject) ? pucmd : NULL);
	if (err) {
		mlx5_ib_warn(dev, "err %d\n", err);
		return err;
	}

	if (pd) {
		if (pd->uobject) {
			__u32 max_wqes =
				1 << MLX5_CAP_GEN(mdev, log_max_qp_sz);
			mlx5_ib_dbg(dev, "requested sq_wqe_count (%d)\n", ucmd.sq_wqe_count);
			if (ucmd.rq_wqe_shift != qp->rq.wqe_shift ||
			    ucmd.rq_wqe_count != qp->rq.wqe_cnt) {
				mlx5_ib_warn(dev, "invalid rq params\n");
				return -EINVAL;
			}
			if (ucmd.sq_wqe_count > max_wqes) {
				mlx5_ib_warn(dev, "requested sq_wqe_count (%d) > max allowed (%d)\n",
					     ucmd.sq_wqe_count, max_wqes);
				return -EINVAL;
			}
			if ((init_attr->create_flags &
				(IB_QP_CREATE_CROSS_CHANNEL |
				 IB_QP_CREATE_MANAGED_SEND |
				 IB_QP_CREATE_MANAGED_RECV)) &&
			     !MLX5_CAP_GEN(dev->mdev, cd)) {
				mlx5_ib_warn(dev, "%s does not support cross-channel operations\n",
					     dev->ib_dev.name);
				return -EINVAL;
			}

			if (init_attr->create_flags & IB_QP_CREATE_CROSS_CHANNEL)
				qp->flags |= MLX5_IB_QP_CAP_CROSS_CHANNEL;

			if (init_attr->create_flags & IB_QP_CREATE_MANAGED_SEND)
				qp->flags |= MLX5_IB_QP_CAP_MANAGED_SEND;

			if (init_attr->create_flags & IB_QP_CREATE_MANAGED_RECV)
				qp->flags |= MLX5_IB_QP_CAP_MANAGED_RECV;

			err = create_user_qp(dev, pd, qp, udata, init_attr, &in,
					     &inlen, &ucmd);
			if (err)
				mlx5_ib_warn(dev, "err %d\n", err);
		} else {
			if (init_attr->qp_type == IB_QPT_RAW_PACKET) {
				mlx5_ib_warn(dev, "Raw Eth QP is disabled for Kernel consumers\n");
				return -EINVAL;
			}
			err = create_kernel_qp(dev, init_attr, qp, &in, &inlen);
			if (err)
				mlx5_ib_warn(dev, "err %d\n", err);
			else
				qp->pa_lkey = to_mpd(pd)->pa_lkey;
		}

		if (err)
			return err;
	} else {
		in = mlx5_vzalloc(sizeof(*in));
		if (!in)
			return -ENOMEM;

		qp->create_type = MLX5_QP_EMPTY;
	}

	if (is_sqp(init_attr->qp_type))
		qp->port = init_attr->port_num;

	st = to_mlx5_st(init_attr->qp_type);
	if (st < 0) {
		mlx5_ib_warn(dev, "invalid service type\n");
		err = st;
		goto err_create;
	}
	in->ctx.flags |= cpu_to_be32(st << 16 | MLX5_QP_PM_MIGRATED << 11);

	if (init_attr->qp_type != MLX5_IB_QPT_REG_UMR)
		in->ctx.flags_pd = cpu_to_be32(to_mpd(pd ? pd : devr->p0)->pdn);
	else
		in->ctx.flags_pd = cpu_to_be32(MLX5_QP_LAT_SENSITIVE);

	if (qp->wq_sig)
		in->ctx.flags_pd |= cpu_to_be32(MLX5_QP_ENABLE_SIG);

	if (qp->flags & MLX5_IB_QP_BLOCK_MULTICAST_LOOPBACK)
		in->ctx.flags_pd |= cpu_to_be32(MLX5_QP_BLOCK_MCAST);

	if (qp->flags &  MLX5_IB_QP_CAP_RX_END_PADDING)
		in->ctx.flags |= cpu_to_be32(MLX5_QP_END_PAD_MODE_ALIGN << 2);
	else
		in->ctx.flags |= cpu_to_be32(MLX5_QP_END_PAD_MODE_NONE << 2);

	if (init_attr->create_flags & IB_QP_CREATE_SIGNATURE_PIPELINE)
		in->ctx.flags_pd |= cpu_to_be32(MLX5_QP_DRAIN_SIGERR);

	if (qp->scat_cqe && is_connected(init_attr->qp_type)) {
		int rcqe_sz;
		int scqe_sz;

		rcqe_sz = mlx5_ib_get_cqe_size(dev, init_attr->recv_cq);
		scqe_sz = mlx5_ib_get_cqe_size(dev, init_attr->send_cq);

		if (rcqe_sz == 128) {
			in->ctx.cs_res = MLX5_RES_SCAT_DATA64_CQE;
			init_attr->max_inl_recv = 64;
		} else {
			in->ctx.cs_res = MLX5_RES_SCAT_DATA32_CQE;
			init_attr->max_inl_recv = 32;
		}

		if (init_attr->sq_sig_type != IB_SIGNAL_ALL_WR) {
			in->ctx.cs_req = 0;
		} else {
			if (scqe_sz == 128)
				in->ctx.cs_req = MLX5_REQ_SCAT_DATA64_CQE;
			else
				in->ctx.cs_req = MLX5_REQ_SCAT_DATA32_CQE;
		}
	} else {
		init_attr->max_inl_recv = 0;
	}

	if (qp->rq.wqe_cnt) {
		in->ctx.rq_size_stride = (qp->rq.wqe_shift - 4);
		in->ctx.rq_size_stride |= ilog2(qp->rq.wqe_cnt) << 3;
	}

	in->ctx.rq_type_srqn = get_rx_type(qp, init_attr);

	if (qp->sq.wqe_cnt)
		in->ctx.sq_crq_size |= cpu_to_be16(ilog2(qp->sq.wqe_cnt) << 11);
	else
		in->ctx.sq_crq_size |= cpu_to_be16(0x8000);

	/* Set default resources */
	switch (init_attr->qp_type) {
	case IB_QPT_XRC_TGT:
		in->ctx.cqn_recv = cpu_to_be32(to_mcq(devr->c0)->mcq.cqn);
		in->ctx.cqn_send = cpu_to_be32(to_mcq(devr->c0)->mcq.cqn);
		in->ctx.rq_type_srqn |= cpu_to_be32(to_msrq(devr->s0)->msrq.srqn);
		in->ctx.xrcd = cpu_to_be32(to_mxrcd(init_attr->xrcd)->xrcdn);
		break;
	case IB_QPT_XRC_INI:
		in->ctx.cqn_recv = cpu_to_be32(to_mcq(devr->c0)->mcq.cqn);
		in->ctx.xrcd = cpu_to_be32(to_mxrcd(devr->x1)->xrcdn);
		in->ctx.rq_type_srqn |= cpu_to_be32(to_msrq(devr->s0)->msrq.srqn);
		break;
	default:
		if (init_attr->srq) {
			in->ctx.xrcd = cpu_to_be32(to_mxrcd(devr->x0)->xrcdn);
			in->ctx.rq_type_srqn |= cpu_to_be32(to_msrq(init_attr->srq)->msrq.srqn);
		} else {
			in->ctx.xrcd = cpu_to_be32(to_mxrcd(devr->x1)->xrcdn);
			in->ctx.rq_type_srqn |= cpu_to_be32(to_msrq(devr->s1)->msrq.srqn);
		}
	}

	if (init_attr->send_cq)
		in->ctx.cqn_send = cpu_to_be32(to_mcq(init_attr->send_cq)->mcq.cqn);

	if (init_attr->recv_cq)
		in->ctx.cqn_recv = cpu_to_be32(to_mcq(init_attr->recv_cq)->mcq.cqn);

	in->ctx.db_rec_addr = cpu_to_be64(qp->db.dma);

	if (MLX5_CAP_GEN(mdev, cqe_version)) {
		qpc = MLX5_ADDR_OF(create_qp_in, in, qpc);
		/* 0xffffff means we ask to work with cqe version 0 */
		MLX5_SET(qpc, qpc, user_index, uidx);
	}
	/* we use IB_QP_CREATE_IPOIB_UD_LSO to indicates ipoib qp */
	if (init_attr->qp_type == IB_QPT_UD &&
	    (init_attr->create_flags & IB_QP_CREATE_IPOIB_UD_LSO) &&
	     MLX5_CAP_GEN(mdev, ipoib_basic_offloads)) {
		qpc = MLX5_ADDR_OF(create_qp_in, in, qpc);
		MLX5_SET(qpc, qpc, ulp_stateless_offload_mode, 1);
		qp->flags |= MLX5_IB_QP_LSO;
	}

	if (init_attr->qp_type == IB_QPT_RAW_PACKET) {
		if (MLX5_CAP_GEN(dev->mdev, port_type) != MLX5_CAP_PORT_TYPE_ETH) {
			mlx5_ib_warn(dev, "Raw Ethernet QP is allowed only for Ethernet link layer\n");
			return -ENOSYS;
		}
		if (ucmd.exp.comp_mask & MLX5_EXP_CREATE_QP_MASK_SQ_BUFF_ADD) {
			qp->sq_buf_addr = ucmd.exp.sq_buf_addr;
		} else {
			mlx5_ib_warn(dev, "Raw Ethernet QP needs SQ buff address\n");
			return -EINVAL;
		}
		err = create_raw_qp(dev, qp, in, pd);
	} else {
		err = mlx5_core_create_qp(dev->mdev, &qp->mqp, in, inlen);
		qp->mqp.event = mlx5_ib_qp_event;
	}

	if (err) {
		mlx5_ib_warn(dev, "create qp failed\n");
		goto err_create;
	}

	kvfree(in);
	/* Hardware wants QPN written in big-endian order (after
	 * shifting) for send doorbell.  Precompute this value to save
	 * a little bit when posting sends.
	 */
	qp->doorbell_qpn = swab32(qp->mqp.qpn << 8);


	get_cqs(init_attr->qp_type, init_attr->send_cq, init_attr->recv_cq,
		&send_cq, &recv_cq);
	spin_lock_irqsave(&dev->reset_flow_resource_lock, flags);
	mlx5_ib_lock_cqs(send_cq, recv_cq);
	/* Maintain device to QPs access, needed for further handling via reset
	 * flow
	 */
	list_add_tail(&qp->qps_list, &dev->qp_list);
	/* Maintain CQ to QPs access, needed for further handling via reset flow
	 */
	if (send_cq)
		list_add_tail(&qp->cq_send_list, &send_cq->list_send_qp);
	if (recv_cq)
		list_add_tail(&qp->cq_recv_list, &recv_cq->list_recv_qp);
	mlx5_ib_unlock_cqs(send_cq, recv_cq);
	spin_unlock_irqrestore(&dev->reset_flow_resource_lock, flags);

	return 0;

err_create:
	if (qp->create_type == MLX5_QP_USER)
		destroy_qp_user(pd, qp);
	else if (qp->create_type == MLX5_QP_KERNEL)
		destroy_qp_kernel(dev, qp);

	kvfree(in);
	return err;
}

static void mlx5_ib_lock_cqs(struct mlx5_ib_cq *send_cq, struct mlx5_ib_cq *recv_cq)
	__acquires(&send_cq->lock) __acquires(&recv_cq->lock)
{
	if (send_cq) {
		if (recv_cq) {
			if (send_cq->mcq.cqn < recv_cq->mcq.cqn)  {
				spin_lock(&send_cq->lock);
				spin_lock_nested(&recv_cq->lock,
						 SINGLE_DEPTH_NESTING);
			} else if (send_cq->mcq.cqn == recv_cq->mcq.cqn) {
				spin_lock(&send_cq->lock);
				__acquire(&recv_cq->lock);
			} else {
				spin_lock(&recv_cq->lock);
				spin_lock_nested(&send_cq->lock,
						 SINGLE_DEPTH_NESTING);
			}
		} else {
			spin_lock(&send_cq->lock);
			__acquire(&recv_cq->lock);
		}
	} else if (recv_cq) {
		spin_lock(&recv_cq->lock);
		__acquire(&send_cq->lock);
	} else {
		__acquire(&send_cq->lock);
		__acquire(&recv_cq->lock);
	}
}

static void mlx5_ib_unlock_cqs(struct mlx5_ib_cq *send_cq, struct mlx5_ib_cq *recv_cq)
	__releases(&send_cq->lock) __releases(&recv_cq->lock)
{
	if (send_cq) {
		if (recv_cq) {
			if (send_cq->mcq.cqn < recv_cq->mcq.cqn)  {
				spin_unlock(&recv_cq->lock);
				spin_unlock(&send_cq->lock);
			} else if (send_cq->mcq.cqn == recv_cq->mcq.cqn) {
				__release(&recv_cq->lock);
				spin_unlock(&send_cq->lock);
			} else {
				spin_unlock(&send_cq->lock);
				spin_unlock(&recv_cq->lock);
			}
		} else {
			__release(&recv_cq->lock);
			spin_unlock(&send_cq->lock);
		}
	} else if (recv_cq) {
		__release(&send_cq->lock);
		spin_unlock(&recv_cq->lock);
	} else {
		__release(&recv_cq->lock);
		__release(&send_cq->lock);
	}
}

static struct mlx5_ib_pd *get_pd(struct mlx5_ib_qp *qp)
{
	return to_mpd(qp->ibqp.pd);
}

static void destroy_raw_qp_rules(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp)
{
	struct mlx5_ib_fs_mc_flow *flow_iter;
	struct mlx5_ib_fs_mc_flow *temp_iter;

	mutex_lock(&qp->mc_flows_list.lock);
	list_for_each_entry_safe(flow_iter, temp_iter,
				 &qp->mc_flows_list.flows_list,
				 list) {
		if (mlx5_ib_destroy_flow(flow_iter->ib_flow))
			mlx5_ib_warn(dev, "Fail to destroy ib_flow, qp num=0x%x\n",
				     qp->mqp.qpn);
		list_del(&flow_iter->list);
		kfree(flow_iter);
	}
	mutex_unlock(&qp->mc_flows_list.lock);
}

static void destroy_raw_qp(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp)
{
	destroy_raw_qp_rules(dev, qp);

	if (qp->rq.wqe_cnt) {
		destroy_raw_qp_tir(dev, qp);
		destroy_raw_qp_rq(dev, qp);
	}

	if (qp->sq.wqe_cnt) {
		destroy_raw_qp_sq(dev, qp);
		destroy_raw_qp_tis(dev, qp);
	}
}

static int modify_raw_qp(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp,
			 const struct mlx5_modify_raw_qp_param *raw_qp_param);

static void destroy_qp_common(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp)
{
	struct mlx5_ib_cq *send_cq, *recv_cq;
	struct mlx5_modify_qp_mbox_in *in;
	unsigned long flags;
	int err;

	if (qp->ibqp.rwq_ind_tbl) {
		destroy_rss_raw_qp_tir(dev, qp);
		return;
	}

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return;

	if (qp->state != IB_QPS_RESET) {
		if (qp->ibqp.qp_type != IB_QPT_RAW_PACKET) {
			mlx5_ib_qp_disable_pagefaults(qp);
			if (mlx5_core_qp_modify(dev->mdev, MLX5_CMD_OP_2RST_QP, in, 0,
						&qp->mqp))
				mlx5_ib_warn(dev, "mlx5_ib: modify QP %06x to RESET failed\n",
					     qp->mqp.qpn);
		} else {
			struct mlx5_modify_raw_qp_param raw_qp_param = {
				.operation = MLX5_CMD_OP_2RST_QP
			};

			if (modify_raw_qp(dev, qp, &raw_qp_param))
				mlx5_ib_warn(dev, "mlx5_ib: modify QP %06x to RESET failed\n",
					     qp->mqp.qpn);
		}
	}

	get_cqs(qp->ibqp.qp_type, qp->ibqp.send_cq, qp->ibqp.recv_cq,
		&send_cq, &recv_cq);

	spin_lock_irqsave(&dev->reset_flow_resource_lock, flags);
	mlx5_ib_lock_cqs(send_cq, recv_cq);
	/* del from lists under both locks above to protect reset flow paths */
	list_del(&qp->qps_list);
	if (send_cq)
		list_del(&qp->cq_send_list);

	if (recv_cq)
		list_del(&qp->cq_recv_list);

	if (qp->create_type == MLX5_QP_KERNEL) {
		__mlx5_ib_cq_clean(recv_cq, qp->mqp.qpn,
				   qp->ibqp.srq ? to_msrq(qp->ibqp.srq) : NULL);
		if (send_cq != recv_cq)
			__mlx5_ib_cq_clean(send_cq, qp->mqp.qpn, NULL);
	}
	mlx5_ib_unlock_cqs(send_cq, recv_cq);
	spin_unlock_irqrestore(&dev->reset_flow_resource_lock, flags);

	if (qp->ibqp.qp_type == IB_QPT_RAW_PACKET) {
		destroy_raw_qp(dev, qp);
	} else {
		err = mlx5_core_destroy_qp(dev->mdev, &qp->mqp);
		if (err)
			mlx5_ib_warn(dev, "failed to destroy QP 0x%x\n",
				     qp->mqp.qpn);
	}

	kfree(in);

	if (qp->create_type == MLX5_QP_KERNEL)
		destroy_qp_kernel(dev, qp);
	else if (qp->create_type == MLX5_QP_USER)
		destroy_qp_user(&get_pd(qp)->ibpd, qp);
}

static const char *ib_qp_type_str(enum ib_qp_type type)
{
	switch (type) {
	case IB_QPT_SMI:
		return "IB_QPT_SMI";
	case IB_QPT_GSI:
		return "IB_QPT_GSI";
	case IB_QPT_RC:
		return "IB_QPT_RC";
	case IB_QPT_UC:
		return "IB_QPT_UC";
	case IB_QPT_UD:
		return "IB_QPT_UD";
	case IB_QPT_RAW_IPV6:
		return "IB_QPT_RAW_IPV6";
	case IB_QPT_RAW_ETHERTYPE:
		return "IB_QPT_RAW_ETHERTYPE";
	case IB_QPT_XRC_INI:
		return "IB_QPT_XRC_INI";
	case IB_QPT_XRC_TGT:
		return "IB_QPT_XRC_TGT";
	case IB_QPT_RAW_PACKET:
		return "IB_QPT_RAW_PACKET";
	case MLX5_IB_QPT_REG_UMR:
		return "MLX5_IB_QPT_REG_UMR";
	case MLX5_IB_QPT_SW_CNAK:
		return "MLX5_QP_ST_SW_CNAK";
	case IB_QPT_MAX:
	default:
		return "Invalid QP type";
	}
}

static struct ib_qp *__create_qp(struct ib_pd *pd,
				 struct ib_exp_qp_init_attr *init_attr,
				 struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev;
	struct mlx5_ib_qp *qp;
	u16 xrcdn = 0;
	int err;
	u32 rcqn;
	u32 scqn;

	if (pd) {
		dev = to_mdev(pd->device);
	} else {
		/* being cautious here */
		if (init_attr->qp_type != IB_QPT_XRC_TGT &&
		    init_attr->qp_type != MLX5_IB_QPT_REG_UMR) {
			pr_warn("%s: no PD for transport %s\n", __func__,
				ib_qp_type_str(init_attr->qp_type));
			return ERR_PTR(-EINVAL);
		}
		dev = to_mdev(to_mxrcd(init_attr->xrcd)->ibxrcd.device);
	}

	switch (init_attr->qp_type) {
	case IB_QPT_XRC_TGT:
	case IB_QPT_XRC_INI:
		if (!MLX5_CAP_GEN(dev->mdev, xrc)) {
			mlx5_ib_warn(dev, "XRC not supported\n");
			return ERR_PTR(-ENOSYS);
		}
		init_attr->recv_cq = NULL;
		if (init_attr->qp_type == IB_QPT_XRC_TGT) {
			xrcdn = to_mxrcd(init_attr->xrcd)->xrcdn;
			init_attr->send_cq = NULL;
		}

		/* fall through */
	case IB_QPT_RC:
	case IB_QPT_UC:
	case IB_QPT_UD:
	case IB_QPT_SMI:
	case IB_QPT_GSI:
	case IB_EXP_QPT_DC_INI:
	case MLX5_IB_QPT_REG_UMR:
	case MLX5_IB_QPT_SW_CNAK:
	case IB_QPT_RAW_ETHERTYPE:
	case IB_QPT_RAW_PACKET:
		qp = kzalloc(sizeof(*qp), GFP_KERNEL);
		if (!qp)
			return ERR_PTR(-ENOMEM);

		err = create_qp_common(dev, pd, init_attr, udata, qp);
		if (err) {
			mlx5_ib_warn(dev, "create_qp_common failed\n");
			kfree(qp);
			return ERR_PTR(err);
		}

		if (is_qp0(init_attr->qp_type))
			qp->ibqp.qp_num = 0;
		else if (is_qp1(init_attr->qp_type))
			qp->ibqp.qp_num = 1;
		else
			qp->ibqp.qp_num = qp->mqp.qpn;

		rcqn = init_attr->recv_cq ? to_mcq(init_attr->recv_cq)->mcq.cqn : -1;
		scqn = init_attr->send_cq ? to_mcq(init_attr->send_cq)->mcq.cqn : -1;
		mlx5_ib_dbg(dev, "ib qpnum 0x%x, mlx qpn 0x%x, rcqn 0x%x, scqn 0x%x\n",
			    qp->ibqp.qp_num, qp->mqp.qpn, rcqn, scqn);

		qp->xrcdn = xrcdn;

		break;

	case IB_QPT_RAW_IPV6:
	case IB_QPT_MAX:
	default:
		mlx5_ib_warn(dev, "unsupported qp type %d\n",
			     init_attr->qp_type);
		/* Don't support raw QPs */
		return ERR_PTR(-EINVAL);
	}

	return &qp->ibqp;
}

struct ib_qp *mlx5_ib_create_qp(struct ib_pd *pd,
				struct ib_qp_init_attr *init_attr,
				struct ib_udata *udata)
{
	struct ib_exp_qp_init_attr *attrx;
	struct ib_qp *qp;

	attrx = kzalloc(sizeof(*attrx), GFP_KERNEL);
	if (!attrx)
		return ERR_PTR(-ENOMEM);

	memcpy(attrx, init_attr, sizeof(*init_attr));

	qp = __create_qp(pd, attrx, udata);
	if (!IS_ERR(qp))
		memcpy(init_attr, attrx, sizeof(*init_attr));

	kfree(attrx);
	return qp;
}

struct ib_qp *mlx5_ib_exp_create_qp(struct ib_pd *pd,
				    struct ib_exp_qp_init_attr *init_attr,
				    struct ib_udata *udata)
{
	return __create_qp(pd, init_attr, udata);
}

int mlx5_ib_destroy_qp(struct ib_qp *qp)
{
	struct mlx5_ib_dev *dev = to_mdev(qp->device);
	struct mlx5_ib_qp *mqp = to_mqp(qp);

	destroy_qp_common(dev, mqp);

	kfree(mqp);

	return 0;
}

static u32 atomic_mode_qp(struct mlx5_ib_dev *dev)
{
	unsigned long mask;
	unsigned long tmp;

	mask = MLX5_CAP_ATOMIC(dev->mdev, atomic_size_qp) &
		MLX5_CAP_ATOMIC(dev->mdev, atomic_size_dc);

	tmp = find_last_bit(&mask, BITS_PER_LONG);
	if (tmp < 2)
		return MLX5_ATOMIC_MODE_NONE;

	if (tmp == 2)
		return MLX5_ATOMIC_MODE_CX;

	return tmp << MLX5_ATOMIC_MODE_OFF;
}

static __be32 to_mlx5_access_flags(struct mlx5_ib_qp *qp, const struct ib_qp_attr *attr,
				   int attr_mask)
{
	struct mlx5_ib_dev *dev = to_mdev(qp->ibqp.device);
	u32 hw_access_flags = 0;
	u8 dest_rd_atomic;
	u32 access_flags;

	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		dest_rd_atomic = attr->max_dest_rd_atomic;
	else
		dest_rd_atomic = qp->resp_depth;

	if (attr_mask & IB_QP_ACCESS_FLAGS)
		access_flags = attr->qp_access_flags;
	else
		access_flags = qp->atomic_rd_en;

	if (!dest_rd_atomic)
		access_flags &= IB_ACCESS_REMOTE_WRITE;

	if (access_flags & IB_ACCESS_REMOTE_READ)
		hw_access_flags |= MLX5_QP_BIT_RRE;
	if (access_flags & IB_ACCESS_REMOTE_ATOMIC)
		hw_access_flags |= (MLX5_QP_BIT_RAE |
				    atomic_mode_qp(dev));
	if (access_flags & IB_ACCESS_REMOTE_WRITE)
		hw_access_flags |= MLX5_QP_BIT_RWE;

	return cpu_to_be32(hw_access_flags);
}

enum {
	MLX5_PATH_FLAG_FL	= 1 << 0,
	MLX5_PATH_FLAG_FREE_AR	= 1 << 1,
	MLX5_PATH_FLAG_COUNTER	= 1 << 2,
};

static int ib_rate_to_mlx5(struct mlx5_ib_dev *dev, u8 rate)
{
	if (rate == IB_RATE_PORT_CURRENT) {
		return 0;
	} else if (rate < IB_RATE_2_5_GBPS || rate > IB_RATE_300_GBPS) {
		return -EINVAL;
	} else {
		while (rate != IB_RATE_2_5_GBPS &&
		       !(1 << (rate + MLX5_STAT_RATE_OFFSET) &
			 MLX5_CAP_GEN(dev->mdev, stat_rate_support)))
			--rate;
	}

	return rate + MLX5_STAT_RATE_OFFSET;
}

static int mlx5_set_path(struct mlx5_ib_dev *dev, const struct ib_ah_attr *ah,
			 struct mlx5_qp_path *path, u8 port, int attr_mask,
			 u32 path_flags, const struct ib_qp_attr *attr,
			 int alt)
{
	enum rdma_link_layer ll = dev->ib_dev.get_link_layer(&dev->ib_dev,
							     port);
	int err;
	int gid_type;

	if ((ll == IB_LINK_LAYER_ETHERNET) || (ah->ah_flags & IB_AH_GRH)) {
		int len = dev->ib_dev.gid_tbl_len[port - 1];
		if (ah->grh.sgid_index >= len) {
			pr_err("sgid_index (%u) too large. max is %d\n",
			       ah->grh.sgid_index, len - 1);
			return -EINVAL;
		}
	}

	if (ll == IB_LINK_LAYER_ETHERNET) {
		if (!(ah->ah_flags & IB_AH_GRH))
			return -EINVAL;

		err = mlx5_get_roce_gid_type(dev, port, ah->grh.sgid_index,
					     &gid_type);
		if (err)
			return err;
		memcpy(path->rmac, ah->dmac, sizeof(ah->dmac));
		path->udp_sport = mlx5_get_roce_udp_sport(dev, port,
							  ah->grh.sgid_index);
		path->dci_cfi_prio_sl = (ah->sl & 0xf) << 4;
	} else {
		path->fl_free_ar = (path_flags & MLX5_PATH_FLAG_FL) ? 0x80 : 0;
		path->grh_mlid	= ah->src_path_bits & 0x7f;
		path->rlid	= cpu_to_be16(ah->dlid);
		if (ah->ah_flags & IB_AH_GRH)
			path->grh_mlid	|= 1 << 7;
		if (attr_mask & IB_QP_PKEY_INDEX)
			path->pkey_index = cpu_to_be16(alt ?
						       attr->alt_pkey_index :
						       attr->pkey_index);

		path->dci_cfi_prio_sl = ah->sl & 0xf;
	}

	path->fl_free_ar |= (path_flags & MLX5_PATH_FLAG_FREE_AR) ? 0x40 : 0;

	if (ah->ah_flags & IB_AH_GRH) {
		path->mgid_index = ah->grh.sgid_index;
		if ((ll == IB_LINK_LAYER_ETHERNET) &&
		    (gid_type != IB_GID_TYPE_IB) &&
		    (ah->grh.hop_limit < 2))
			path->hop_limit  = IPV6_DEFAULT_HOPLIMIT;
		else
			path->hop_limit  = ah->grh.hop_limit;
		path->tclass_flowlabel =
			cpu_to_be32((ah->grh.traffic_class << 20) |
				    (ah->grh.flow_label));
		memcpy(path->rgid, ah->grh.dgid.raw, 16);
	}

	err = ib_rate_to_mlx5(dev, ah->static_rate);
	if (err < 0)
		return err;
	path->static_rate = err;
	path->port = port;

	if (attr_mask & IB_QP_TIMEOUT)
		path->ackto_lt = alt ? attr->alt_timeout << 3 : attr->timeout << 3;

	return 0;
}

static enum mlx5_qp_optpar opt_mask[MLX5_QP_NUM_STATE][MLX5_QP_NUM_STATE][MLX5_QP_ST_MAX] = {
	[MLX5_QP_STATE_INIT] = {
		[MLX5_QP_STATE_INIT] = {
			[MLX5_QP_ST_RC] = MLX5_QP_OPTPAR_RRE		|
					  MLX5_QP_OPTPAR_RAE		|
					  MLX5_QP_OPTPAR_RWE		|
					  MLX5_QP_OPTPAR_PKEY_INDEX	|
					  MLX5_QP_OPTPAR_PRI_PORT,
			[MLX5_QP_ST_UC] = MLX5_QP_OPTPAR_RWE		|
					  MLX5_QP_OPTPAR_PKEY_INDEX	|
					  MLX5_QP_OPTPAR_PRI_PORT,
			[MLX5_QP_ST_UD] = MLX5_QP_OPTPAR_PKEY_INDEX	|
					  MLX5_QP_OPTPAR_Q_KEY		|
					  MLX5_QP_OPTPAR_PRI_PORT,
			[MLX5_QP_ST_DC] = MLX5_QP_OPTPAR_PRI_PORT	|
					  MLX5_QP_OPTPAR_DC_KEY		|
					  MLX5_QP_OPTPAR_PKEY_INDEX	|
					  MLX5_QP_OPTPAR_RAE,
		},
		[MLX5_QP_STATE_RTR] = {
			[MLX5_QP_ST_RC] = MLX5_QP_OPTPAR_ALT_ADDR_PATH  |
					  MLX5_QP_OPTPAR_RRE            |
					  MLX5_QP_OPTPAR_RAE            |
					  MLX5_QP_OPTPAR_RWE            |
					  MLX5_QP_OPTPAR_PKEY_INDEX,
			[MLX5_QP_ST_UC] = MLX5_QP_OPTPAR_ALT_ADDR_PATH  |
					  MLX5_QP_OPTPAR_RWE            |
					  MLX5_QP_OPTPAR_PKEY_INDEX,
			[MLX5_QP_ST_UD] = MLX5_QP_OPTPAR_PKEY_INDEX     |
					  MLX5_QP_OPTPAR_Q_KEY,
			[MLX5_QP_ST_MLX] = MLX5_QP_OPTPAR_PKEY_INDEX	|
					   MLX5_QP_OPTPAR_Q_KEY,
			[MLX5_QP_ST_XRC] = MLX5_QP_OPTPAR_ALT_ADDR_PATH |
					  MLX5_QP_OPTPAR_RRE            |
					  MLX5_QP_OPTPAR_RAE            |
					  MLX5_QP_OPTPAR_RWE            |
					  MLX5_QP_OPTPAR_PKEY_INDEX,
			[MLX5_QP_ST_DC] = MLX5_QP_OPTPAR_PKEY_INDEX	|
					  MLX5_QP_OPTPAR_RAE		|
					  MLX5_QP_OPTPAR_DC_KEY,
		},
	},
	[MLX5_QP_STATE_RTR] = {
		[MLX5_QP_STATE_RTS] = {
			[MLX5_QP_ST_RC] = MLX5_QP_OPTPAR_ALT_ADDR_PATH	|
					  MLX5_QP_OPTPAR_RRE		|
					  MLX5_QP_OPTPAR_RAE		|
					  MLX5_QP_OPTPAR_RWE		|
					  MLX5_QP_OPTPAR_PM_STATE	|
					  MLX5_QP_OPTPAR_RNR_TIMEOUT,
			[MLX5_QP_ST_UC] = MLX5_QP_OPTPAR_ALT_ADDR_PATH	|
					  MLX5_QP_OPTPAR_RWE		|
					  MLX5_QP_OPTPAR_PM_STATE,
			[MLX5_QP_ST_UD] = MLX5_QP_OPTPAR_Q_KEY,
			[MLX5_QP_ST_DC] = MLX5_QP_OPTPAR_DC_KEY		|
					  MLX5_QP_OPTPAR_PM_STATE	|
					  MLX5_QP_OPTPAR_RAE,
		},
	},
	[MLX5_QP_STATE_RTS] = {
		[MLX5_QP_STATE_RTS] = {
			[MLX5_QP_ST_RC] = MLX5_QP_OPTPAR_RRE		|
					  MLX5_QP_OPTPAR_RAE		|
					  MLX5_QP_OPTPAR_RWE		|
					  MLX5_QP_OPTPAR_RNR_TIMEOUT	|
					  MLX5_QP_OPTPAR_PM_STATE	|
					  MLX5_QP_OPTPAR_ALT_ADDR_PATH,
			[MLX5_QP_ST_UC] = MLX5_QP_OPTPAR_RWE		|
					  MLX5_QP_OPTPAR_PM_STATE	|
					  MLX5_QP_OPTPAR_ALT_ADDR_PATH,
			[MLX5_QP_ST_UD] = MLX5_QP_OPTPAR_Q_KEY		|
					  MLX5_QP_OPTPAR_SRQN		|
					  MLX5_QP_OPTPAR_CQN_RCV,
			[MLX5_QP_ST_DC] = MLX5_QP_OPTPAR_DC_KEY		|
					  MLX5_QP_OPTPAR_PM_STATE	|
					  MLX5_QP_OPTPAR_RAE,
		},
	},
	[MLX5_QP_STATE_SQER] = {
		[MLX5_QP_STATE_RTS] = {
			[MLX5_QP_ST_UD]	 = MLX5_QP_OPTPAR_Q_KEY,
			[MLX5_QP_ST_MLX] = MLX5_QP_OPTPAR_Q_KEY,
			[MLX5_QP_ST_UC]	 = MLX5_QP_OPTPAR_RWE,
			[MLX5_QP_ST_RC]	 = MLX5_QP_OPTPAR_RNR_TIMEOUT	|
					   MLX5_QP_OPTPAR_RWE		|
					   MLX5_QP_OPTPAR_RAE		|
					   MLX5_QP_OPTPAR_RRE,
			[MLX5_QP_ST_DC]  = MLX5_QP_OPTPAR_DC_KEY	|
					   MLX5_QP_OPTPAR_RAE,

		},
	},
	[MLX5_QP_STATE_SQD] = {
		[MLX5_QP_STATE_RTS] = {
			[MLX5_QP_ST_UD]	 = MLX5_QP_OPTPAR_Q_KEY,
			[MLX5_QP_ST_MLX] = MLX5_QP_OPTPAR_Q_KEY,
			[MLX5_QP_ST_UC]	 = MLX5_QP_OPTPAR_RWE,
			[MLX5_QP_ST_RC]	 = MLX5_QP_OPTPAR_RNR_TIMEOUT	|
					   MLX5_QP_OPTPAR_RWE		|
					   MLX5_QP_OPTPAR_RAE		|
					   MLX5_QP_OPTPAR_RRE,
		},
	},
};

static int ib_nr_to_mlx5_nr(int ib_mask)
{
	switch (ib_mask) {
	case IB_QP_STATE:
		return 0;
	case IB_QP_CUR_STATE:
		return 0;
	case IB_QP_EN_SQD_ASYNC_NOTIFY:
		return 0;
	case IB_QP_ACCESS_FLAGS:
		return MLX5_QP_OPTPAR_RWE | MLX5_QP_OPTPAR_RRE |
			MLX5_QP_OPTPAR_RAE;
	case IB_QP_PKEY_INDEX:
		return MLX5_QP_OPTPAR_PKEY_INDEX;
	case IB_QP_PORT:
		return MLX5_QP_OPTPAR_PRI_PORT;
	case IB_QP_QKEY:
		return MLX5_QP_OPTPAR_Q_KEY;
	case IB_QP_AV:
		return MLX5_QP_OPTPAR_PRIMARY_ADDR_PATH |
			MLX5_QP_OPTPAR_PRI_PORT;
	case IB_QP_PATH_MTU:
		return 0;
	case IB_QP_TIMEOUT:
		return MLX5_QP_OPTPAR_ACK_TIMEOUT;
	case IB_QP_RETRY_CNT:
		return MLX5_QP_OPTPAR_RETRY_COUNT;
	case IB_QP_RNR_RETRY:
		return MLX5_QP_OPTPAR_RNR_RETRY;
	case IB_QP_RQ_PSN:
		return 0;
	case IB_QP_MAX_QP_RD_ATOMIC:
		return MLX5_QP_OPTPAR_SRA_MAX;
	case IB_QP_ALT_PATH:
		return MLX5_QP_OPTPAR_ALT_ADDR_PATH;
	case IB_QP_MIN_RNR_TIMER:
		return MLX5_QP_OPTPAR_RNR_TIMEOUT;
	case IB_QP_SQ_PSN:
		return 0;
	case IB_QP_MAX_DEST_RD_ATOMIC:
		return MLX5_QP_OPTPAR_RRA_MAX | MLX5_QP_OPTPAR_RWE |
			MLX5_QP_OPTPAR_RRE | MLX5_QP_OPTPAR_RAE;
	case IB_QP_PATH_MIG_STATE:
		return MLX5_QP_OPTPAR_PM_STATE;
	case IB_QP_CAP:
		return 0;
	case IB_QP_DEST_QPN:
		return 0;
	}
	return 0;
}

static int ib_mask_to_mlx5_opt(int ib_mask)
{
	int result = 0;
	int i;

	for (i = 0; i < 8 * sizeof(int); i++) {
		if ((1 << i) & ib_mask)
			result |= ib_nr_to_mlx5_nr(1 << i);
	}

	return result;
}

static int modify_raw_qp_rq(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp,
			    const struct mlx5_modify_raw_qp_param *raw_qp_param,
			    int new_state)
{
	void *in;
	void *rqc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(modify_rq_in);
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_rq_in, in, rqn, qp->mrq.qpn);
	MLX5_SET(modify_rq_in, in, rq_state, qp->rq_state);

	rqc = MLX5_ADDR_OF(modify_rq_in, in, ctx);
	MLX5_SET(rqc, rqc, state, new_state);

	if (raw_qp_param->set_mask & MLX5_RAW_QP_MOD_SET_RQ_Q_CTR_ID) {
		if (MLX5_CAP_GEN(dev->mdev, mod_rq_counter_set_id)) {
			MLX5_SET(modify_rq_in, in, bitmask.mod_rq_ctr_set_id, 1);
			MLX5_SET(rqc, rqc, counter_set_id, raw_qp_param->rq_q_ctr_id);
		} else
			pr_info_once("%s: RAW PACKET QP counters are not supported on current FW\n",
				     dev->ib_dev.name);
	}

	err = mlx5_core_modify_rq(dev->mdev, in, inlen);
	if (err)
		goto out;

	qp->rq_state = new_state;

out:
	kvfree(in);
	return err;
}

static int modify_raw_qp_sq(struct mlx5_core_dev *dev, struct mlx5_ib_qp *qp,
			    int new_state,
			    const struct mlx5_modify_raw_qp_param *raw_qp_param)
{
	u32 old_rate = qp->rate_limit;
	u32 new_rate = old_rate;
	u16 rl_index = 0;
	void *in;
	void *sqc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(modify_sq_in);
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	MLX5_SET(modify_sq_in, in, sqn, qp->msq.qpn);
	MLX5_SET(modify_sq_in, in, sq_state, qp->sq_state);

	sqc = MLX5_ADDR_OF(modify_sq_in, in, ctx);
	MLX5_SET(sqc, sqc, state, new_state);

	if (raw_qp_param->set_mask & MLX5_RAW_QP_RATE_LIMIT)
		new_rate = raw_qp_param->rate_limit;

	if (old_rate != new_rate) {
		if (new_rate) {
			err = mlx5_rl_add_rate(dev, new_rate, &rl_index);
			if (err) {
				mlx5_ib_warn(to_mdev(qp->ibqp.device),
					     "Failed configuring rate %u: %d\n",
					     new_rate, err);
				goto out;
			}
		}

		MLX5_SET64(modify_sq_in, in, modify_bitmask, 1);
		MLX5_SET(sqc, sqc, packet_pacing_rate_limit_index, rl_index);
	}

	err = mlx5_core_modify_sq(dev, in, inlen);
	if (err) {
		/* Remove new rate from table if failed */
		if (new_rate &&
		    old_rate != new_rate)
			mlx5_rl_remove_rate(dev, new_rate);
		goto out;
	}

	if ((new_state == MLX5_SQC_STATE_ERR) ||
	    (new_state == MLX5_SQC_STATE_RST))
		new_rate = 0;

	/* Only remove the old rate after new rate was set */
	if (old_rate &&
	    old_rate != new_rate)
		mlx5_rl_remove_rate(dev, old_rate);

	qp->rate_limit = new_rate;
	qp->sq_state = new_state;

out:
	kvfree(in);
	return err;
}

static int modify_raw_qp(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp,
			 const struct mlx5_modify_raw_qp_param *raw_qp_param)
{
	int err;
	int rq_state;
	int sq_state;
	const char *new_state_str;
	int modify_rq = !!qp->rq.wqe_cnt;
	int modify_sq = !!qp->sq.wqe_cnt;

	switch (raw_qp_param->operation) {
	case MLX5_CMD_OP_RST2INIT_QP:
		rq_state = MLX5_RQC_STATE_RDY;
		sq_state = MLX5_SQC_STATE_RDY;
		new_state_str = "READY";
		break;

	case MLX5_CMD_OP_2ERR_QP:
		rq_state = MLX5_RQC_STATE_ERR;
		sq_state = MLX5_SQC_STATE_ERR;
		new_state_str = "ERROR";
		break;

	case MLX5_CMD_OP_2RST_QP:
		rq_state = MLX5_RQC_STATE_RST;
		sq_state = MLX5_SQC_STATE_RST;
		new_state_str = "RESET";
		break;

	case MLX5_CMD_OP_RTR2RTS_QP:
	case MLX5_CMD_OP_RTS2RTS_QP:
		if (raw_qp_param->set_mask ==
		    MLX5_RAW_QP_RATE_LIMIT) {
			modify_rq = 0;
			sq_state = qp->sq_state;
			new_state_str = "READY";
		} else {
			return raw_qp_param->set_mask ? -EINVAL : 0;
		}
		break;

	case MLX5_CMD_OP_INIT2RTR_QP:
		/* TBD: update eth_prio using MODIFY_TIS*/
	case MLX5_CMD_OP_INIT2INIT_QP:
		if (raw_qp_param->set_mask)
			return -EINVAL;
		else
			return 0;

	default:
		return -EINVAL;
	}

	if (modify_rq) {
		err = modify_raw_qp_rq(dev, qp, raw_qp_param, rq_state);
		if (err) {
			mlx5_ib_warn(dev, "Failed to  modify RQ %06x to %s err %d\n",
				     qp->msq.qpn, new_state_str, err);
			return err;
		}
	}
	if (modify_sq) {
		err = modify_raw_qp_sq(dev->mdev, qp, sq_state, raw_qp_param);
		if (err) {
			mlx5_ib_warn(dev, "Failed to  modify SQ %06x to %s err %d\n",
				     qp->msq.qpn, new_state_str, err);
			return err;
		}
	}

	return 0;
}

static int __mlx5_ib_modify_qp(struct ib_qp *ibqp,
			       const struct ib_qp_attr *attr, int attr_mask,
			       enum ib_qp_state cur_state, enum ib_qp_state new_state)
{
	static const u16 optab[MLX5_QP_NUM_STATE][MLX5_QP_NUM_STATE] = {
		[MLX5_QP_STATE_RST] = {
			[MLX5_QP_STATE_RST]	= MLX5_CMD_OP_2RST_QP,
			[MLX5_QP_STATE_ERR]	= MLX5_CMD_OP_2ERR_QP,
			[MLX5_QP_STATE_INIT]	= MLX5_CMD_OP_RST2INIT_QP,
		},
		[MLX5_QP_STATE_INIT]  = {
			[MLX5_QP_STATE_RST]	= MLX5_CMD_OP_2RST_QP,
			[MLX5_QP_STATE_ERR]	= MLX5_CMD_OP_2ERR_QP,
			[MLX5_QP_STATE_INIT]	= MLX5_CMD_OP_INIT2INIT_QP,
			[MLX5_QP_STATE_RTR]	= MLX5_CMD_OP_INIT2RTR_QP,
		},
		[MLX5_QP_STATE_RTR]   = {
			[MLX5_QP_STATE_RST]	= MLX5_CMD_OP_2RST_QP,
			[MLX5_QP_STATE_ERR]	= MLX5_CMD_OP_2ERR_QP,
			[MLX5_QP_STATE_RTS]	= MLX5_CMD_OP_RTR2RTS_QP,
		},
		[MLX5_QP_STATE_RTS]   = {
			[MLX5_QP_STATE_RST]	= MLX5_CMD_OP_2RST_QP,
			[MLX5_QP_STATE_ERR]	= MLX5_CMD_OP_2ERR_QP,
			[MLX5_QP_STATE_RTS]	= MLX5_CMD_OP_RTS2RTS_QP,
		},
		[MLX5_QP_STATE_SQD] = {
			[MLX5_QP_STATE_RST]	= MLX5_CMD_OP_2RST_QP,
			[MLX5_QP_STATE_ERR]	= MLX5_CMD_OP_2ERR_QP,
			[MLX5_QP_STATE_RTS]	= MLX5_CMD_OP_SQD_RTS_QP,
		},
		[MLX5_QP_STATE_SQER] = {
			[MLX5_QP_STATE_RST]	= MLX5_CMD_OP_2RST_QP,
			[MLX5_QP_STATE_ERR]	= MLX5_CMD_OP_2ERR_QP,
			[MLX5_QP_STATE_RTS]	= MLX5_CMD_OP_SQERR2RTS_QP,
		},
		[MLX5_QP_STATE_ERR] = {
			[MLX5_QP_STATE_RST]	= MLX5_CMD_OP_2RST_QP,
			[MLX5_QP_STATE_ERR]	= MLX5_CMD_OP_2ERR_QP,
		}
	};

	struct mlx5_ib_dev *dev = to_mdev(ibqp->device);
	struct mlx5_ib_qp *qp = to_mqp(ibqp);
	struct mlx5_ib_cq *send_cq, *recv_cq;
	struct mlx5_qp_context *context;
	struct mlx5_modify_qp_mbox_in *in;
	struct mlx5_ib_pd *pd;
	struct mlx5_ib_port *mibport;
	enum mlx5_qp_state mlx5_cur, mlx5_new;
	enum mlx5_qp_optpar optpar;
	int sqd_event;
	int mlx5_st;
	int err;
	u16 op;
	u8 port_num;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	context = &in->ctx;
	err = to_mlx5_st(ibqp->qp_type);
	if (err < 0)
		goto out;

	port_num = (attr_mask & IB_QP_PORT ? attr->port_num : qp->port) - 1;
	mibport = &dev->port[port_num];

	context->flags = cpu_to_be32(err << 16);

	if (!(attr_mask & IB_QP_PATH_MIG_STATE)) {
		context->flags |= cpu_to_be32(MLX5_QP_PM_MIGRATED << 11);
	} else {
		switch (attr->path_mig_state) {
		case IB_MIG_MIGRATED:
			context->flags |= cpu_to_be32(MLX5_QP_PM_MIGRATED << 11);
			break;
		case IB_MIG_REARM:
			context->flags |= cpu_to_be32(MLX5_QP_PM_REARM << 11);
			break;
		case IB_MIG_ARMED:
			context->flags |= cpu_to_be32(MLX5_QP_PM_ARMED << 11);
			break;
		}
	}

	if (ibqp->qp_type == IB_QPT_GSI || ibqp->qp_type == IB_QPT_SMI) {
		context->mtu_msgmax = (IB_MTU_256 << 5) | 8;
	} else if (ibqp->qp_type == IB_QPT_UD ||
		   ibqp->qp_type == MLX5_IB_QPT_REG_UMR) {
		context->mtu_msgmax = (IB_MTU_4096 << 5) | 12;
	} else if (attr_mask & IB_QP_PATH_MTU) {
		if (attr->path_mtu < IB_MTU_256 ||
		    attr->path_mtu > IB_MTU_4096) {
			mlx5_ib_warn(dev, "invalid mtu %d\n", attr->path_mtu);
			err = -EINVAL;
			goto out;
		}
		context->mtu_msgmax = (attr->path_mtu << 5) |
				      (u8)MLX5_CAP_GEN(dev->mdev, log_max_msg);
	}

	if (attr_mask & IB_QP_DEST_QPN)
		context->log_pg_sz_remote_qpn = cpu_to_be32(attr->dest_qp_num);

	if (attr_mask & IB_QP_DC_KEY)
		context->dc_access_key = cpu_to_be64(attr->dct_key);

	if (attr_mask & IB_QP_PKEY_INDEX)
		context->pri_path.pkey_index = cpu_to_be16(attr->pkey_index);

	/* todo implement counter_index functionality */

	if (is_sqp(ibqp->qp_type))
		context->pri_path.port = qp->port;

	if (attr_mask & IB_QP_PORT)
		context->pri_path.port = attr->port_num;

	if (attr_mask & IB_QP_AV) {
		err = mlx5_set_path(dev, &attr->ah_attr, &context->pri_path,
				    attr_mask & IB_QP_PORT ? attr->port_num : qp->port,
				    attr_mask, 0, attr, 0);
		if (err)
			goto out;
	}

	if (attr_mask & IB_QP_TIMEOUT)
		context->pri_path.ackto_lt |= attr->timeout << 3;

	if (attr_mask & IB_QP_ALT_PATH) {
		err = mlx5_set_path(dev, &attr->alt_ah_attr, &context->alt_path,
				    attr->alt_port_num,
				    attr_mask  | IB_QP_PKEY_INDEX | IB_QP_TIMEOUT,
				    0, attr, 1);
		if (err)
			goto out;
	}

	pd = get_pd(qp);
	get_cqs(qp->ibqp.qp_type, qp->ibqp.send_cq, qp->ibqp.recv_cq,
		&send_cq, &recv_cq);

	context->flags_pd = cpu_to_be32(pd ? pd->pdn : to_mpd(dev->devr.p0)->pdn);
	context->cqn_send = send_cq ? cpu_to_be32(send_cq->mcq.cqn) : 0;
	context->cqn_recv = recv_cq ? cpu_to_be32(recv_cq->mcq.cqn) : 0;
	context->params1  = cpu_to_be32(MLX5_IB_ACK_REQ_FREQ << 28);

	if (attr_mask & IB_QP_RNR_RETRY)
		context->params1 |= cpu_to_be32(attr->rnr_retry << 13);

	if (attr_mask & IB_QP_RETRY_CNT)
		context->params1 |= cpu_to_be32(attr->retry_cnt << 16);

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC) {
		if (attr->max_rd_atomic)
			context->params1 |=
				cpu_to_be32(fls(attr->max_rd_atomic - 1) << 21);
	}

	if (attr_mask & IB_QP_SQ_PSN)
		context->next_send_psn = cpu_to_be32(attr->sq_psn & 0xffffff);

	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		if (attr->max_dest_rd_atomic)
			context->params2 |=
				cpu_to_be32(fls(attr->max_dest_rd_atomic - 1) << 21);
	}

	if ((attr_mask & IB_QP_ACCESS_FLAGS) &&
	    (attr->qp_access_flags & IB_ACCESS_REMOTE_ATOMIC) &&
	    !dev->enable_atomic_resp) {
		mlx5_ib_warn(dev, "atomic responder is not supported\n");
		err = -EINVAL;
		goto out;
	}

	if (attr_mask & (IB_QP_ACCESS_FLAGS | IB_QP_MAX_DEST_RD_ATOMIC))
		context->params2 |= to_mlx5_access_flags(qp, attr, attr_mask);

	if (attr_mask & IB_QP_MIN_RNR_TIMER)
		context->rnr_nextrecvpsn |= cpu_to_be32(attr->min_rnr_timer << 24);

	if (attr_mask & IB_QP_RQ_PSN)
		context->rnr_nextrecvpsn |= cpu_to_be32(attr->rq_psn & 0xffffff);

	if (attr_mask & IB_QP_QKEY)
		context->qkey = cpu_to_be32(attr->qkey);

	if (qp->rq.wqe_cnt && cur_state == IB_QPS_RESET && new_state == IB_QPS_INIT)
		context->db_rec_addr = cpu_to_be64(qp->db.dma);

	if (cur_state == IB_QPS_RTS && new_state == IB_QPS_SQD	&&
	    attr_mask & IB_QP_EN_SQD_ASYNC_NOTIFY && attr->en_sqd_async_notify)
		sqd_event = 1;
	else
		sqd_event = 0;

	if (!ibqp->uobject && cur_state == IB_QPS_RESET && new_state == IB_QPS_INIT)
		context->sq_crq_size |= cpu_to_be16(1 << 4);

	if (cur_state == IB_QPS_RESET && new_state == IB_QPS_INIT)
		context->qp_counter_set_usr_page |=
			cpu_to_be32(mibport->q_cnt_id << 24);


	mlx5_cur = to_mlx5_state(cur_state);
	mlx5_new = to_mlx5_state(new_state);
	mlx5_st = to_mlx5_st(ibqp->qp_type);
	if (mlx5_st < 0)
		goto out;

	/* If moving to a reset or error state, we must disable page faults on
	 * this QP and flush all current page faults. Otherwise a stale page
	 * fault may attempt to work on this QP after it is reset and moved
	 * again to RTS, and may cause the driver and the device to get out of
	 * sync. */
	if (cur_state != IB_QPS_RESET && cur_state != IB_QPS_ERR &&
	    (new_state == IB_QPS_RESET || new_state == IB_QPS_ERR))
		mlx5_ib_qp_disable_pagefaults(qp);

	if (mlx5_cur >= MLX5_QP_NUM_STATE || mlx5_new >= MLX5_QP_NUM_STATE ||
	    !optab[mlx5_cur][mlx5_new])
		return -EINVAL;

	op = optab[mlx5_cur][mlx5_new];
	optpar = ib_mask_to_mlx5_opt(attr_mask);
	optpar &= opt_mask[mlx5_cur][mlx5_new][mlx5_st];
	in->optparam = cpu_to_be32(optpar);

	if (qp->ibqp.qp_type == IB_QPT_RAW_PACKET) {
		struct mlx5_modify_raw_qp_param raw_qp_param = {};

		raw_qp_param.operation = op;
		if (cur_state == IB_QPS_RESET && new_state == IB_QPS_INIT) {
			raw_qp_param.rq_q_ctr_id = mibport->q_cnt_id;
			raw_qp_param.set_mask |= MLX5_RAW_QP_MOD_SET_RQ_Q_CTR_ID;
		}

		if (attr_mask & IB_QP_RATE_LIMIT) {
			raw_qp_param.rate_limit = attr->rate_limit;
			raw_qp_param.set_mask |= MLX5_RAW_QP_RATE_LIMIT;
		}

		err = modify_raw_qp(dev, qp, &raw_qp_param);
	} else
		err = mlx5_core_qp_modify(dev->mdev, op, in, sqd_event,
					  &qp->mqp);
	if (err)
		goto out;

	if (cur_state == IB_QPS_RESET && new_state == IB_QPS_INIT)
		mlx5_ib_qp_enable_pagefaults(qp);

	qp->state = new_state;

	if (attr_mask & IB_QP_ACCESS_FLAGS)
		qp->atomic_rd_en = attr->qp_access_flags;
	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC)
		qp->resp_depth = attr->max_dest_rd_atomic;
	if (attr_mask & IB_QP_PORT)
		qp->port = attr->port_num;
	if (attr_mask & IB_QP_ALT_PATH)
		qp->alt_port = attr->alt_port_num;

	/*
	 * If we moved a kernel QP to RESET, clean up all old CQ
	 * entries and reinitialize the QP.
	 */
	if (new_state == IB_QPS_RESET && !ibqp->uobject) {
		mlx5_ib_cq_clean(recv_cq, qp->mqp.qpn,
				 ibqp->srq ? to_msrq(ibqp->srq) : NULL);
		if (send_cq != recv_cq)
			mlx5_ib_cq_clean(send_cq, qp->mqp.qpn, NULL);

		qp->rq.head = 0;
		qp->rq.tail = 0;
		qp->sq.head = 0;
		qp->sq.tail = 0;
		qp->sq.cur_post = 0;
		qp->sq.last_poll = 0;
		if (qp->db.db) {
			qp->db.db[MLX5_RCV_DBR] = 0;
			qp->db.db[MLX5_SND_DBR] = 0;
		}
	}

out:
	kfree(in);
	return err;
}

static int ignored_ts_check(enum ib_qp_type qp_type)
{
	if (qp_type == MLX5_IB_QPT_REG_UMR ||
	    qp_type == MLX5_IB_QPT_SW_CNAK)
		return 1;

	return 0;
}

int mlx5_ib_modify_qp(struct ib_qp *ibqp, struct ib_qp_attr *attr,
		      int attr_mask, struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(ibqp->device);
	struct mlx5_ib_qp *qp = to_mqp(ibqp);
	enum ib_qp_state cur_state, new_state;
	int err = -EINVAL;
	int port;
	enum rdma_link_layer ll = IB_LINK_LAYER_UNSPECIFIED;

	mutex_lock(&qp->mutex);

	cur_state = attr_mask & IB_QP_CUR_STATE ? attr->cur_qp_state : qp->state;
	new_state = attr_mask & IB_QP_STATE ? attr->qp_state : cur_state;

	if (!(cur_state == new_state && cur_state == IB_QPS_RESET)) {
		port = attr_mask & IB_QP_PORT ? attr->port_num : qp->port;
		ll = dev->ib_dev.get_link_layer(&dev->ib_dev, port);
	}
	if (!ignored_ts_check(ibqp->qp_type) &&
	    !ib_modify_qp_is_ok(cur_state, new_state, ibqp->qp_type, attr_mask, ll))
		goto out;

	if ((attr_mask & IB_QP_PORT) &&
	    (attr->port_num == 0 ||
	     attr->port_num > MLX5_CAP_GEN(dev->mdev, num_ports)))
		goto out;

	if (attr_mask & IB_QP_PKEY_INDEX) {
		port = attr_mask & IB_QP_PORT ? attr->port_num : qp->port;
		if (attr->pkey_index >=
		    dev->mdev->port_caps[port - 1].pkey_table_len)
			goto out;
	}

	if (attr_mask & IB_QP_MAX_QP_RD_ATOMIC &&
	    attr->max_rd_atomic >
	    (1 << MLX5_CAP_GEN(dev->mdev, log_max_ra_res_qp)))
		goto out;

	if (attr_mask & IB_QP_MAX_DEST_RD_ATOMIC &&
	    attr->max_dest_rd_atomic >
	    (1 << MLX5_CAP_GEN(dev->mdev, log_max_ra_req_qp)))
		goto out;

	if (cur_state == new_state && cur_state == IB_QPS_RESET) {
		err = 0;
		goto out;
	}

	err = __mlx5_ib_modify_qp(ibqp, attr, attr_mask, cur_state, new_state);

out:
	mutex_unlock(&qp->mutex);
	return err;
}

static int mlx5_wq_overflow(struct mlx5_ib_wq *wq, int nreq, struct ib_cq *ib_cq)
{
	struct mlx5_ib_cq *cq;
	unsigned cur;

	cur = wq->head - wq->tail;
	if (likely(cur + nreq < wq->max_post))
		return 0;

	cq = to_mcq(ib_cq);
	spin_lock(&cq->lock);
	cur = wq->head - wq->tail;
	spin_unlock(&cq->lock);

	return cur + nreq >= wq->max_post;
}

static __always_inline void set_raddr_seg(struct mlx5_wqe_raddr_seg *rseg,
					  u64 remote_addr, u32 rkey)
{
	rseg->raddr    = cpu_to_be64(remote_addr);
	rseg->rkey     = cpu_to_be32(rkey);
	rseg->reserved = 0;
}

static void *set_eth_seg(struct mlx5_wqe_eth_seg *eseg,
			 struct ib_send_wr *wr, void *qend,
			 struct mlx5_ib_qp *qp, int *size)
{
	void *seg = eseg;

	memset(eseg, 0, sizeof(struct mlx5_wqe_eth_seg));

	if (wr->send_flags & IB_SEND_IP_CSUM)
		eseg->cs_flags = MLX5_ETH_WQE_L3_CSUM |
				 MLX5_ETH_WQE_L4_CSUM;

	seg += sizeof(struct mlx5_wqe_eth_seg);
	*size += sizeof(struct mlx5_wqe_eth_seg) / 16;

	if (wr->opcode == IB_WR_LSO) {
		int size_of_inl_hdr_start = sizeof(eseg->inline_hdr_start);
		u64 left, leftlen, copysz;
		void *pdata = wr->wr.ud.header;

		left = wr->wr.ud.hlen;
		eseg->mss = cpu_to_be16(wr->wr.ud.mss);
		eseg->inline_hdr_sz = cpu_to_be16(left);

		/*
		 * check if there is space till the end of queue, if yes,
		 * copy all in one shot, otherwise copy till the end of queue,
		 * rollback and than the copy the left
		 */
		leftlen = qend - (void *)eseg->inline_hdr_start;
		copysz = min_t(u64, leftlen, left);

		memcpy(seg - size_of_inl_hdr_start, pdata, copysz);

		if (unlikely(copysz < left)) /* the lase wqe in the queue */
			seg = mlx5_get_send_wqe(qp, 0);
		else if (copysz > size_of_inl_hdr_start)
			seg += ALIGN(copysz - size_of_inl_hdr_start, 16);


		if (likely(copysz > size_of_inl_hdr_start))
			*size += ALIGN(copysz - size_of_inl_hdr_start, 16) / 16;

		left -= copysz;
		pdata += copysz;

		if (unlikely(left)) {
			memcpy(seg, pdata, left);
			seg += ALIGN(left, 16);
			*size += ALIGN(left, 16) / 16;
		}
	}
	return seg;
}

static void set_datagram_seg(struct mlx5_wqe_datagram_seg *dseg,
			     struct ib_send_wr *wr)
{
	memcpy(&dseg->av, &to_mah(wr->wr.ud.ah)->av, sizeof(struct mlx5_av));
	dseg->av.dqp_dct = cpu_to_be32(wr->wr.ud.remote_qpn | MLX5_EXTENDED_UD_AV);
	dseg->av.key.qkey.qkey = cpu_to_be32(wr->wr.ud.remote_qkey);
}

static void set_mlx_seg(struct mlx5_mlx_seg *seg, struct mlx5_mlx_wr *wr)
{
	memset(seg, 0, sizeof(*seg));
	seg->stat_rate_sl = wr->sl & 0xf;
	seg->dlid = cpu_to_be16(wr->dlid);
	seg->flags = wr->icrc ? 8 : 0;
}

static void set_data_ptr_seg(struct mlx5_wqe_data_seg *dseg, struct ib_sge *sg)
{
	dseg->byte_count = cpu_to_be32(sg->length);
	dseg->lkey       = cpu_to_be32(sg->lkey);
	dseg->addr       = cpu_to_be64(sg->addr);
}

static __be16 get_klm_octo(int npages)
{
	return cpu_to_be16(ALIGN(npages, 8) / 2);
}

static __be64 frwr_mkey_mask(void)
{
	u64 result;

	result = MLX5_MKEY_MASK_LEN		|
		MLX5_MKEY_MASK_PAGE_SIZE	|
		MLX5_MKEY_MASK_START_ADDR	|
		MLX5_MKEY_MASK_EN_RINVAL	|
		MLX5_MKEY_MASK_KEY		|
		MLX5_MKEY_MASK_LR		|
		MLX5_MKEY_MASK_LW		|
		MLX5_MKEY_MASK_RR		|
		MLX5_MKEY_MASK_RW		|
		MLX5_MKEY_MASK_A		|
		MLX5_MKEY_MASK_SMALL_FENCE	|
		MLX5_MKEY_MASK_FREE;

	return cpu_to_be64(result);
}

static __be64 sig_mkey_mask(void)
{
	u64 result;

	result = MLX5_MKEY_MASK_LEN		|
		MLX5_MKEY_MASK_PAGE_SIZE	|
		MLX5_MKEY_MASK_START_ADDR	|
		MLX5_MKEY_MASK_EN_SIGERR	|
		MLX5_MKEY_MASK_EN_RINVAL	|
		MLX5_MKEY_MASK_KEY		|
		MLX5_MKEY_MASK_LR		|
		MLX5_MKEY_MASK_LW		|
		MLX5_MKEY_MASK_RR		|
		MLX5_MKEY_MASK_RW		|
		MLX5_MKEY_MASK_SMALL_FENCE	|
		MLX5_MKEY_MASK_FREE		|
		MLX5_MKEY_MASK_BSF_EN;

	return cpu_to_be64(result);
}

static void set_frwr_umr_segment(struct mlx5_wqe_umr_ctrl_seg *umr,
				 struct ib_send_wr *wr, int li)
{
	memset(umr, 0, sizeof(*umr));

	if (li) {
		umr->mkey_mask = cpu_to_be64(MLX5_MKEY_MASK_FREE);
		umr->flags = 1 << 7;
		return;
	}

	umr->flags = (1 << 5); /* fail if not free */
	umr->klm_octowords = get_klm_octo(wr->wr.fast_reg.page_list_len);
	umr->mkey_mask = frwr_mkey_mask();
}


static __be64 get_umr_reg_mr_mask(int atomic)
{
	u64 result;

	result = MLX5_MKEY_MASK_LEN		|
		 MLX5_MKEY_MASK_PAGE_SIZE	|
		 MLX5_MKEY_MASK_START_ADDR	|
		 MLX5_MKEY_MASK_PD		|
		 MLX5_MKEY_MASK_LR		|
		 MLX5_MKEY_MASK_LW		|
		 MLX5_MKEY_MASK_KEY		|
		 MLX5_MKEY_MASK_RR		|
		 MLX5_MKEY_MASK_RW		|
		 MLX5_MKEY_MASK_FREE;

	if (atomic)
		result |= MLX5_MKEY_MASK_A;


	return cpu_to_be64(result);
}

static __be64 get_umr_unreg_mr_mask(void)
{
	u64 result;

	result = MLX5_MKEY_MASK_FREE;

	return cpu_to_be64(result);
}

static __be64 get_umr_update_mtt_mask(void)
{
	u64 result;

	result = MLX5_MKEY_MASK_FREE;

	return cpu_to_be64(result);
}

static void set_reg_umr_segment(struct mlx5_wqe_umr_ctrl_seg *umr,
				struct ib_send_wr *wr, int atomic)
{
	struct mlx5_umr_wr *umrwr = (struct mlx5_umr_wr *)&wr->wr.fast_reg;

	memset(umr, 0, sizeof(*umr));

	if (wr->send_flags & MLX5_IB_SEND_UMR_FAIL_IF_FREE)
		umr->flags = MLX5_UMR_CHECK_FREE; /* fail if free */
	else
		umr->flags = MLX5_UMR_CHECK_NOT_FREE; /* fail if not free */

	if (!(wr->send_flags & MLX5_IB_SEND_UMR_UNREG)) {
		umr->klm_octowords = get_klm_octo(umrwr->npages);
		if (wr->send_flags & MLX5_IB_SEND_UMR_UPDATE_MTT) {
			umr->mkey_mask = get_umr_update_mtt_mask();
			umr->bsf_octowords = get_klm_octo(umrwr->target.offset);
			umr->flags |= MLX5_UMR_TRANSLATION_OFFSET_EN;
		} else {
			umr->mkey_mask = get_umr_reg_mr_mask(atomic);
		}
	} else {
		umr->mkey_mask = get_umr_unreg_mr_mask();
	}

	if (!wr->num_sge)
		umr->flags |= MLX5_UMR_INLINE;
}

static u8 get_umr_flags(int acc)
{
	return (acc & IB_ACCESS_REMOTE_ATOMIC ? MLX5_PERM_ATOMIC       : 0) |
	       (acc & IB_ACCESS_REMOTE_WRITE  ? MLX5_PERM_REMOTE_WRITE : 0) |
	       (acc & IB_ACCESS_REMOTE_READ   ? MLX5_PERM_REMOTE_READ  : 0) |
	       (acc & IB_ACCESS_LOCAL_WRITE   ? MLX5_PERM_LOCAL_WRITE  : 0) |
		MLX5_PERM_LOCAL_READ | MLX5_PERM_UMR_EN;
}

static void set_mkey_segment(struct mlx5_mkey_seg *seg, struct ib_send_wr *wr,
			     int li, int *writ)
{
	memset(seg, 0, sizeof(*seg));
	if (li) {
		seg->status = MLX5_MKEY_STATUS_FREE;
		return;
	}

	seg->flags = get_umr_flags(wr->wr.fast_reg.access_flags) |
		     MLX5_ACCESS_MODE_MTT;
	*writ = seg->flags & (MLX5_PERM_LOCAL_WRITE | IB_ACCESS_REMOTE_WRITE);
	seg->qpn_mkey7_0 = cpu_to_be32((wr->wr.fast_reg.rkey & 0xff) | 0xffffff00);
	seg->flags_pd = cpu_to_be32(MLX5_MKEY_REMOTE_INVAL);
	seg->start_addr = cpu_to_be64(wr->wr.fast_reg.iova_start);
	seg->len = cpu_to_be64(wr->wr.fast_reg.length);
	seg->xlt_oct_size = cpu_to_be32((wr->wr.fast_reg.page_list_len + 1) / 2);
	seg->log2_page_size = wr->wr.fast_reg.page_shift;
}

static void set_reg_mkey_segment(struct mlx5_mkey_seg *seg, struct ib_send_wr *wr)
{
	struct mlx5_umr_wr *umrwr = (struct mlx5_umr_wr *)&wr->wr.fast_reg;

	memset(seg, 0, sizeof(*seg));
	if (wr->send_flags & MLX5_IB_SEND_UMR_UNREG) {
		seg->status = MLX5_MKEY_STATUS_FREE;
		return;
	}

	seg->flags = convert_access(umrwr->access_flags);
	if (!(wr->send_flags & MLX5_IB_SEND_UMR_UPDATE_MTT)) {
		seg->flags_pd = cpu_to_be32(to_mpd(umrwr->pd)->pdn);
		seg->start_addr = cpu_to_be64(umrwr->target.virt_addr);
	}
	seg->len = cpu_to_be64(umrwr->length);
	seg->log2_page_size = umrwr->page_shift;
	seg->qpn_mkey7_0 = cpu_to_be32(0xffffff00 |
				       mlx5_mkey_variant(umrwr->mkey));
}

static void set_frwr_pages(struct mlx5_wqe_data_seg *dseg,
			   struct ib_send_wr *wr,
			   struct mlx5_core_dev *mdev,
			   struct mlx5_ib_pd *pd,
			   int writ)
{
	struct mlx5_ib_fast_reg_page_list *mfrpl = to_mfrpl(wr->wr.fast_reg.page_list);
	u64 *page_list = wr->wr.fast_reg.page_list->page_list;
	u64 perm = MLX5_EN_RD | (writ ? MLX5_EN_WR : 0);
	int i;

	for (i = 0; i < wr->wr.fast_reg.page_list_len; i++)
		mfrpl->mapped_page_list[i] = cpu_to_be64(page_list[i] | perm);
	dseg->addr = cpu_to_be64(mfrpl->map);
	dseg->byte_count = cpu_to_be32(ALIGN(sizeof(u64) * wr->wr.fast_reg.page_list_len, 64));
	dseg->lkey = cpu_to_be32(pd->pa_lkey);
}

static __be32 send_ieth(struct ib_send_wr *wr)
{
	switch (wr->opcode) {
	case IB_WR_SEND_WITH_IMM:
	case IB_WR_RDMA_WRITE_WITH_IMM:
		return wr->ex.imm_data;

	case IB_WR_SEND_WITH_INV:
		return cpu_to_be32(wr->ex.invalidate_rkey);

	default:
		return 0;
	}
}

static u8 calc_sig(void *wqe, int size)
{
	u8 *p = wqe;
	u8 res = 0;
	int i;

	for (i = 0; i < size; i++)
		res ^= p[i];

	return ~res;
}

static u8 wq_sig(void *wqe)
{
	return calc_sig(wqe, (*((u8 *)wqe + 8) & 0x3f) << 4);
}

static int set_data_inl_seg(struct mlx5_ib_qp *qp, struct ib_send_wr *wr,
			    void *wqe, int *sz)
{
	struct mlx5_wqe_inline_seg *seg;
	void *qend = qp->sq.qend;
	void *addr;
	int inl = 0;
	int copy;
	int len;
	int i;

	seg = wqe;
	wqe += sizeof(*seg);
	for (i = 0; i < wr->num_sge; i++) {
		addr = (void *)(unsigned long)(wr->sg_list[i].addr);
		len  = wr->sg_list[i].length;
		inl += len;

		if (unlikely(inl > qp->max_inline_data))
			return -ENOMEM;

		if (unlikely(wqe + len > qend)) {
			copy = qend - wqe;
			memcpy(wqe, addr, copy);
			addr += copy;
			len -= copy;
			wqe = mlx5_get_send_wqe(qp, 0);
		}
		memcpy(wqe, addr, len);
		wqe += len;
	}

	seg->byte_count = cpu_to_be32(inl | MLX5_INLINE_SEG);

	*sz = ALIGN(inl + sizeof(seg->byte_count), 16) / 16;

	return 0;
}

static u16 prot_field_size(enum ib_signature_type type)
{
	switch (type) {
	case IB_SIG_TYPE_T10_DIF:
		return MLX5_DIF_SIZE;
	default:
		return 0;
	}
}

static u8 bs_selector(int block_size)
{
	switch (block_size) {
	case 512:	    return 0x1;
	case 520:	    return 0x2;
	case 4096:	    return 0x3;
	case 4160:	    return 0x4;
	case 1073741824:    return 0x5;
	default:	    return 0;
	}
}

static void mlx5_fill_inl_bsf(struct ib_sig_domain *domain,
			      struct mlx5_bsf_inl *inl)
{
	/* Valid inline section and allow BSF refresh */
	inl->vld_refresh = cpu_to_be16(MLX5_BSF_INL_VALID |
				       MLX5_BSF_REFRESH_DIF);
	inl->dif_apptag = cpu_to_be16(domain->sig.dif.app_tag);
	inl->dif_reftag = cpu_to_be32(domain->sig.dif.ref_tag);
	/* repeating block */
	inl->rp_inv_seed = MLX5_BSF_REPEAT_BLOCK;
	inl->sig_type = domain->sig.dif.bg_type == IB_T10DIF_CRC ?
			MLX5_DIF_CRC : MLX5_DIF_IPCS;

	if (domain->sig.dif.ref_remap)
		inl->dif_inc_ref_guard_check |= MLX5_BSF_INC_REFTAG;

	if (domain->sig.dif.app_escape) {
		if (domain->sig.dif.ref_escape)
			inl->dif_inc_ref_guard_check |= MLX5_BSF_APPREF_ESCAPE;
		else
			inl->dif_inc_ref_guard_check |= MLX5_BSF_APPTAG_ESCAPE;
	}

	inl->dif_app_bitmask_check =
		cpu_to_be16(domain->sig.dif.apptag_check_mask);
}

static int mlx5_set_bsf(struct ib_mr *sig_mr,
			struct ib_sig_attrs *sig_attrs,
			struct mlx5_bsf *bsf, u32 data_size)
{
	struct mlx5_core_sig_ctx *msig = to_mmr(sig_mr)->sig;
	struct mlx5_bsf_basic *basic = &bsf->basic;
	struct ib_sig_domain *mem = &sig_attrs->mem;
	struct ib_sig_domain *wire = &sig_attrs->wire;

	memset(bsf, 0, sizeof(*bsf));

	/* Basic + Extended + Inline */
	basic->bsf_size_sbs = 1 << 7;
	/* Input domain check byte mask */
	basic->check_byte_mask = sig_attrs->check_mask;
	basic->raw_data_size = cpu_to_be32(data_size);

	/* Memory domain */
	switch (sig_attrs->mem.sig_type) {
	case IB_SIG_TYPE_NONE:
		break;
	case IB_SIG_TYPE_T10_DIF:
		basic->mem.bs_selector = bs_selector(mem->sig.dif.pi_interval);
		basic->m_bfs_psv = cpu_to_be32(msig->psv_memory.psv_idx);
		mlx5_fill_inl_bsf(mem, &bsf->m_inl);
		break;
	default:
		return -EINVAL;
	}

	/* Wire domain */
	switch (sig_attrs->wire.sig_type) {
	case IB_SIG_TYPE_NONE:
		break;
	case IB_SIG_TYPE_T10_DIF:
		if (mem->sig.dif.pi_interval == wire->sig.dif.pi_interval &&
		    mem->sig_type == wire->sig_type) {
			/* Same block structure */
			basic->bsf_size_sbs |= 1 << 4;
			if (mem->sig.dif.bg_type == wire->sig.dif.bg_type)
				basic->wire.copy_byte_mask |= MLX5_CPY_GRD_MASK;
			if (mem->sig.dif.app_tag == wire->sig.dif.app_tag)
				basic->wire.copy_byte_mask |= MLX5_CPY_APP_MASK;
			if (mem->sig.dif.ref_tag == wire->sig.dif.ref_tag)
				basic->wire.copy_byte_mask |= MLX5_CPY_REF_MASK;
		} else
			basic->wire.bs_selector = bs_selector(wire->sig.dif.pi_interval);

		basic->w_bfs_psv = cpu_to_be32(msig->psv_wire.psv_idx);
		mlx5_fill_inl_bsf(wire, &bsf->w_inl);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int set_sig_data_segment(struct ib_send_wr *wr, struct mlx5_ib_qp *qp,
				void **seg, int *size)
{
	struct ib_sig_attrs *sig_attrs = wr->wr.sig_handover.sig_attrs;
	struct ib_mr *sig_mr = wr->wr.sig_handover.sig_mr;
	struct mlx5_bsf *bsf;
	u32 data_len = wr->sg_list->length;
	u32 data_key = wr->sg_list->lkey;
	u64 data_va = wr->sg_list->addr;
	int ret;
	int wqe_size;

	if (!wr->wr.sig_handover.prot ||
	    (data_key == wr->wr.sig_handover.prot->lkey &&
	     data_va == wr->wr.sig_handover.prot->addr &&
	     data_len == wr->wr.sig_handover.prot->length)) {
		/**
		 * Source domain doesn't contain signature information
		 * or data and protection are interleaved in memory.
		 * So need construct:
		 *                  ------------------
		 *                 |     data_klm     |
		 *                  ------------------
		 *                 |       BSF        |
		 *                  ------------------
		 **/
		struct mlx5_klm *data_klm = *seg;

		data_klm->bcount = cpu_to_be32(data_len);
		data_klm->key = cpu_to_be32(data_key);
		data_klm->va = cpu_to_be64(data_va);
		wqe_size = ALIGN(sizeof(*data_klm), 64);
	} else {
		/**
		 * Source domain contains signature information
		 * So need construct a strided block format:
		 *               ---------------------------
		 *              |     stride_block_ctrl     |
		 *               ---------------------------
		 *              |          data_klm         |
		 *               ---------------------------
		 *              |          prot_klm         |
		 *               ---------------------------
		 *              |             BSF           |
		 *               ---------------------------
		 **/
		struct mlx5_stride_block_ctrl_seg *sblock_ctrl;
		struct mlx5_stride_block_entry *data_sentry;
		struct mlx5_stride_block_entry *prot_sentry;
		u32 prot_key = wr->wr.sig_handover.prot->lkey;
		u64 prot_va = wr->wr.sig_handover.prot->addr;
		u16 block_size = sig_attrs->mem.sig.dif.pi_interval;
		int prot_size;

		sblock_ctrl = *seg;
		data_sentry = (void *)sblock_ctrl + sizeof(*sblock_ctrl);
		prot_sentry = (void *)data_sentry + sizeof(*data_sentry);

		prot_size = prot_field_size(sig_attrs->mem.sig_type);
		if (!prot_size) {
			pr_err("Bad block size given: %u\n", block_size);
			return -EINVAL;
		}
		sblock_ctrl->bcount_per_cycle = cpu_to_be32(block_size +
							    prot_size);
		sblock_ctrl->op = cpu_to_be32(MLX5_STRIDE_BLOCK_OP);
		sblock_ctrl->repeat_count = cpu_to_be32(data_len / block_size);
		sblock_ctrl->num_entries = cpu_to_be16(2);

		data_sentry->bcount = cpu_to_be16(block_size);
		data_sentry->key = cpu_to_be32(data_key);
		data_sentry->va = cpu_to_be64(data_va);
		data_sentry->stride = cpu_to_be16(block_size);

		prot_sentry->bcount = cpu_to_be16(prot_size);
		prot_sentry->key = cpu_to_be32(prot_key);
		prot_sentry->va = cpu_to_be64(prot_va);
		prot_sentry->stride = cpu_to_be16(prot_size);

		wqe_size = ALIGN(sizeof(*sblock_ctrl) + sizeof(*data_sentry) +
				 sizeof(*prot_sentry), 64);
	}

	*seg += wqe_size;
	*size += wqe_size / 16;
	if (unlikely((*seg == qp->sq.qend)))
		*seg = mlx5_get_send_wqe(qp, 0);

	bsf = *seg;
	ret = mlx5_set_bsf(sig_mr, sig_attrs, bsf, data_len);
	if (ret)
		return -EINVAL;

	*seg += sizeof(*bsf);
	*size += sizeof(*bsf) / 16;
	if (unlikely((*seg == qp->sq.qend)))
		*seg = mlx5_get_send_wqe(qp, 0);

	return 0;
}

static void set_sig_mkey_segment(struct mlx5_mkey_seg *seg,
				 struct ib_send_wr *wr, u32 nelements,
				 u32 length, u32 pdn)
{
	struct ib_mr *sig_mr = wr->wr.sig_handover.sig_mr;
	u32 sig_key = sig_mr->rkey;
	u8 sigerr = to_mmr(sig_mr)->sig->sigerr_count & 1;

	memset(seg, 0, sizeof(*seg));

	seg->flags = get_umr_flags(wr->wr.sig_handover.access_flags) |
				   MLX5_ACCESS_MODE_KLM;
	seg->qpn_mkey7_0 = cpu_to_be32((sig_key & 0xff) | 0xffffff00);
	seg->flags_pd = cpu_to_be32(MLX5_MKEY_REMOTE_INVAL | sigerr << 26 |
				    MLX5_MKEY_BSF_EN | pdn);
	seg->len = cpu_to_be64(length);
	seg->xlt_oct_size = cpu_to_be32(be16_to_cpu(get_klm_octo(nelements)));
	seg->bsfs_octo_size = cpu_to_be32(MLX5_MKEY_BSF_OCTO_SIZE);
}

static void set_sig_umr_segment(struct mlx5_wqe_umr_ctrl_seg *umr,
				struct ib_send_wr *wr, u32 nelements)
{
	memset(umr, 0, sizeof(*umr));

	umr->flags = MLX5_FLAGS_INLINE | MLX5_FLAGS_CHECK_FREE;
	umr->klm_octowords = get_klm_octo(nelements);
	umr->bsf_octowords = cpu_to_be16(MLX5_MKEY_BSF_OCTO_SIZE);
	umr->mkey_mask = sig_mkey_mask();
}


static int set_sig_umr_wr(struct ib_send_wr *wr, struct mlx5_ib_qp *qp,
			  void **seg, int *size)
{
	struct mlx5_ib_mr *sig_mr = to_mmr(wr->wr.sig_handover.sig_mr);
	u32 pdn = get_pd(qp)->pdn;
	u32 klm_oct_size;
	int region_len, ret;

	if (unlikely(wr->num_sge != 1) ||
	    unlikely(wr->wr.sig_handover.access_flags &
		     IB_ACCESS_REMOTE_ATOMIC) ||
	    unlikely(!sig_mr->sig) || unlikely(!qp->signature_en) ||
	    unlikely(!sig_mr->sig->sig_status_checked))
		return -EINVAL;

	/* length of the protected region, data + protection */
	region_len = wr->sg_list->length;
	if (wr->wr.sig_handover.prot &&
	    (wr->wr.sig_handover.prot->lkey != wr->sg_list->lkey  ||
	     wr->wr.sig_handover.prot->addr != wr->sg_list->addr  ||
	     wr->wr.sig_handover.prot->length != wr->sg_list->length))
		region_len += wr->wr.sig_handover.prot->length;

	/**
	 * KLM octoword size - if protection was provided
	 * then we use strided block format (3 octowords),
	 * else we use single KLM (1 octoword)
	 **/
	klm_oct_size = wr->wr.sig_handover.prot ? 3 : 1;

	set_sig_umr_segment(*seg, wr, klm_oct_size);
	*seg += sizeof(struct mlx5_wqe_umr_ctrl_seg);
	*size += sizeof(struct mlx5_wqe_umr_ctrl_seg) / 16;
	if (unlikely((*seg == qp->sq.qend)))
		*seg = mlx5_get_send_wqe(qp, 0);

	set_sig_mkey_segment(*seg, wr, klm_oct_size, region_len, pdn);
	*seg += sizeof(struct mlx5_mkey_seg);
	*size += sizeof(struct mlx5_mkey_seg) / 16;
	if (unlikely((*seg == qp->sq.qend)))
		*seg = mlx5_get_send_wqe(qp, 0);

	ret = set_sig_data_segment(wr, qp, seg, size);
	if (ret)
		return ret;

	sig_mr->sig->sig_status_checked = false;
	return 0;
}

static int set_psv_wr(struct ib_sig_domain *domain,
		      u32 psv_idx, void **seg, int *size)
{
	struct mlx5_seg_set_psv *psv_seg = *seg;

	memset(psv_seg, 0, sizeof(*psv_seg));
	psv_seg->psv_num = cpu_to_be32(psv_idx);
	switch (domain->sig_type) {
	case IB_SIG_TYPE_NONE:
		break;
	case IB_SIG_TYPE_T10_DIF:
		psv_seg->transient_sig = cpu_to_be32(domain->sig.dif.bg << 16 |
						     domain->sig.dif.app_tag);
		psv_seg->ref_tag = cpu_to_be32(domain->sig.dif.ref_tag);
		break;
	default:
		pr_err("Bad signature type given.\n");
		return 1;
	}

	*seg += sizeof(*psv_seg);
	*size += sizeof(*psv_seg) / 16;

	return 0;
}

static int set_frwr_li_wr(void **seg, struct ib_send_wr *wr, int *size,
			  struct mlx5_core_dev *mdev, struct mlx5_ib_pd *pd, struct mlx5_ib_qp *qp)
{
	int writ = 0;
	int li;

	li = wr->opcode == IB_WR_LOCAL_INV ? 1 : 0;
	if (unlikely(wr->send_flags & IB_SEND_INLINE))
		return -EINVAL;

	set_frwr_umr_segment(*seg, wr, li);
	*seg += sizeof(struct mlx5_wqe_umr_ctrl_seg);
	*size += sizeof(struct mlx5_wqe_umr_ctrl_seg) / 16;
	if (unlikely((*seg == qp->sq.qend)))
		*seg = mlx5_get_send_wqe(qp, 0);
	set_mkey_segment(*seg, wr, li, &writ);
	*seg += sizeof(struct mlx5_mkey_seg);
	*size += sizeof(struct mlx5_mkey_seg) / 16;
	if (unlikely((*seg == qp->sq.qend)))
		*seg = mlx5_get_send_wqe(qp, 0);
	if (!li) {
		if (unlikely(wr->wr.fast_reg.page_list_len >
			     wr->wr.fast_reg.page_list->max_page_list_len))
			return	-ENOMEM;

		set_frwr_pages(*seg, wr, mdev, pd, writ);
		*seg += sizeof(struct mlx5_wqe_data_seg);
		*size += (sizeof(struct mlx5_wqe_data_seg) / 16);
	}
	return 0;
}

static void set_indir_mkey_segment(struct mlx5_mkey_seg *seg,
				   struct ib_send_wr *wr, u32 pdn)
{
	u32 list_len = wr->wr.indir_reg.indir_list_len;

	memset(seg, 0, sizeof(*seg));

	seg->flags = get_umr_flags(wr->wr.indir_reg.access_flags) |
				   MLX5_ACCESS_MODE_KLM;
	seg->qpn_mkey7_0 = cpu_to_be32(0xffffff00 |
			   mlx5_mkey_variant(wr->wr.indir_reg.mkey));
	seg->flags_pd = cpu_to_be32(MLX5_MKEY_REMOTE_INVAL | pdn);
	seg->len = cpu_to_be64(wr->wr.indir_reg.length);
	seg->start_addr = cpu_to_be64(wr->wr.indir_reg.iova_start);
	seg->xlt_oct_size = cpu_to_be32(be16_to_cpu(get_klm_octo(list_len * 2)));
}

static void set_indir_data_seg(struct ib_send_wr *wr, struct mlx5_ib_qp *qp,
			       u32 pa_key, void **seg, int *size)
{
	struct mlx5_wqe_data_seg *data = *seg;
	struct mlx5_ib_indir_reg_list *mirl;
	struct ib_sge *sg_list = wr->wr.indir_reg.indir_list->sg_list;
	u32 list_len = wr->wr.indir_reg.indir_list_len;
	int i;

	mirl = to_mindir_list(wr->wr.indir_reg.indir_list);
	for (i = 0; i < list_len; i++) {
		mirl->klms[i].va = cpu_to_be64(sg_list[i].addr);
		mirl->klms[i].key = cpu_to_be32(sg_list[i].lkey);
		mirl->klms[i].bcount = cpu_to_be32(sg_list[i].length);
	}

	data->byte_count = cpu_to_be32(ALIGN(sizeof(struct mlx5_klm) *
				       list_len, 64));
	data->lkey = cpu_to_be32(pa_key);
	data->addr = cpu_to_be64(mirl->map);
	*seg += sizeof(*data);
	*size += sizeof(*data) / 16;
}

static void set_indir_umr_segment(struct mlx5_wqe_umr_ctrl_seg *umr,
				  struct ib_send_wr *wr)
{
	u64 mask;
	u32 list_len = wr->wr.indir_reg.indir_list_len;

	memset(umr, 0, sizeof(*umr));

	umr->flags = MLX5_UMR_CHECK_NOT_FREE;
	umr->klm_octowords = get_klm_octo(list_len * 2);
	mask = MLX5_MKEY_MASK_LEN		|
		MLX5_MKEY_MASK_PAGE_SIZE	|
		MLX5_MKEY_MASK_START_ADDR	|
		MLX5_MKEY_MASK_EN_RINVAL	|
		MLX5_MKEY_MASK_KEY		|
		MLX5_MKEY_MASK_LR		|
		MLX5_MKEY_MASK_LW		|
		MLX5_MKEY_MASK_RR		|
		MLX5_MKEY_MASK_RW		|
		MLX5_MKEY_MASK_A		|
		MLX5_MKEY_MASK_FREE;

	umr->mkey_mask = cpu_to_be64(mask);
}

static int set_indir_reg_wr(struct ib_send_wr *wr, struct mlx5_ib_qp *qp,
			    void **seg, int *size)
{
	struct mlx5_ib_pd *pd = get_pd(qp);

	if (unlikely(wr->send_flags & IB_SEND_INLINE))
		return -EINVAL;

	set_indir_umr_segment(*seg, wr);
	*seg += sizeof(struct mlx5_wqe_umr_ctrl_seg);
	*size += sizeof(struct mlx5_wqe_umr_ctrl_seg) / 16;
	if (unlikely(*seg == qp->sq.qend))
		*seg = mlx5_get_send_wqe(qp, 0);

	set_indir_mkey_segment(*seg, wr, pd->pdn);
	*seg += sizeof(struct mlx5_mkey_seg);
	*size += sizeof(struct mlx5_mkey_seg) / 16;
	if (unlikely(*seg == qp->sq.qend))
		*seg = mlx5_get_send_wqe(qp, 0);

	set_indir_data_seg(wr, qp, pd->pa_lkey, seg, size);

	return 0;
}

static void dump_wqe(struct mlx5_ib_qp *qp, int idx, int size_16)
{
	__be32 *p = NULL;
	int tidx = idx;
	int i, j;

	pr_debug("dump wqe at %p\n", mlx5_get_send_wqe(qp, tidx));
	for (i = 0, j = 0; i < size_16 * 4; i += 4, j += 4) {
		if ((i & 0xf) == 0) {
			void *buf = mlx5_get_send_wqe(qp, tidx);
			tidx = (tidx + 1) & (qp->sq.wqe_cnt - 1);
			p = buf;
			j = 0;
		}
		pr_debug("%08x %08x %08x %08x\n", be32_to_cpu(p[j]),
			 be32_to_cpu(p[j + 1]), be32_to_cpu(p[j + 2]),
			 be32_to_cpu(p[j + 3]));
	}
}

static void mlx5_bf_copy(u64 __iomem *dst, u64 *src,
			 unsigned bytecnt, struct mlx5_ib_qp *qp)
{
	while (bytecnt > 0) {
		__iowrite64_copy(dst++, src++, 8);
		__iowrite64_copy(dst++, src++, 8);
		__iowrite64_copy(dst++, src++, 8);
		__iowrite64_copy(dst++, src++, 8);
		__iowrite64_copy(dst++, src++, 8);
		__iowrite64_copy(dst++, src++, 8);
		__iowrite64_copy(dst++, src++, 8);
		__iowrite64_copy(dst++, src++, 8);
		bytecnt -= 64;
		if (unlikely(src == qp->sq.qend))
			src = mlx5_get_send_wqe(qp, 0);
	}
}

static u8 get_fence(u8 fence, struct ib_send_wr *wr)
{
	if (unlikely(wr->opcode == IB_WR_LOCAL_INV &&
		     wr->send_flags & IB_SEND_FENCE))
		return MLX5_FENCE_MODE_STRONG_ORDERING;

	if (unlikely(fence)) {
		if (wr->send_flags & IB_SEND_FENCE)
			return MLX5_FENCE_MODE_SMALL_AND_FENCE;
		else
			return fence;

	} else {
		return 0;
	}
}

static int begin_wqe(struct mlx5_ib_qp *qp, void **seg,
		     struct mlx5_wqe_ctrl_seg **ctrl,
		     struct ib_send_wr *wr, unsigned *idx,
		     int *size, int nreq)
{
	int err = 0;

	if (unlikely(mlx5_wq_overflow(&qp->sq, nreq, qp->ibqp.send_cq))) {
		mlx5_ib_warn(to_mdev(qp->ibqp.device), "work queue overflow\n");
		err = -ENOMEM;
		return err;
	}

	*idx = qp->sq.cur_post & (qp->sq.wqe_cnt - 1);
	*seg = mlx5_get_send_wqe(qp, *idx);
	*ctrl = *seg;
	*(uint32_t *)(*seg + 8) = 0;
	(*ctrl)->imm = send_ieth(wr);
	(*ctrl)->fm_ce_se = qp->sq_signal_bits |
		(wr->send_flags & IB_SEND_SIGNALED ?
		 MLX5_WQE_CTRL_CQ_UPDATE : 0) |
		(wr->send_flags & IB_SEND_SOLICITED ?
		 MLX5_WQE_CTRL_SOLICITED : 0);

	*seg += sizeof(**ctrl);
	*size = sizeof(**ctrl) / 16;

	return err;
}

static void finish_wqe(struct mlx5_ib_qp *qp,
		       struct mlx5_wqe_ctrl_seg *ctrl,
		       u8 size, unsigned idx,
		       struct ib_send_wr *wr,
		       int nreq, u8 fence, u8 next_fence,
		       u32 mlx5_opcode)
{
	u8 opmod = 0;

	ctrl->opmod_idx_opcode = cpu_to_be32(((u32)(qp->sq.cur_post) << 8) |
					     mlx5_opcode | ((u32)opmod << 24));
	ctrl->qpn_ds = cpu_to_be32(size | (qp->mqp.qpn << 8));
	ctrl->fm_ce_se |= fence;
	qp->fm_cache = next_fence;
	if (unlikely(qp->wq_sig))
		ctrl->signature = wq_sig(ctrl);

	qp->sq.swr_ctx[idx].wrid = wr->wr_id;
	qp->sq.swr_ctx[idx].w_list.opcode = mlx5_opcode;
	qp->sq.swr_ctx[idx].wqe_head = qp->sq.head + nreq;
	qp->sq.cur_post += DIV_ROUND_UP(size * 16, MLX5_SEND_WQE_BB);
	qp->sq.swr_ctx[idx].w_list.next = qp->sq.cur_post;
	qp->sq.swr_ctx[idx].sig_piped = !!(wr->send_flags & IB_SEND_SIG_PIPELINED);
}

int mlx5_ib_post_send(struct ib_qp *ibqp, struct ib_send_wr *wr,
		      struct ib_send_wr **bad_wr)
{
	struct mlx5_wqe_ctrl_seg *ctrl = NULL;  /* compiler warning */
	struct mlx5_ib_dev *dev = to_mdev(ibqp->device);
	struct mlx5_core_dev *mdev = dev->mdev;
	struct mlx5_ib_qp *qp = to_mqp(ibqp);
	struct mlx5_ib_mr *mr;
	struct mlx5_wqe_data_seg *dpseg;
	struct mlx5_wqe_xrc_seg *xrc;
	struct mlx5_bf *bf = qp->bf;
	int uninitialized_var(size);
	void *qend = qp->sq.qend;
	unsigned long flags;
	unsigned idx;
	int err = 0;
	int inl = 0;
	int num_sge;
	void *seg;
	int nreq;
	int i;
	u8 next_fence = 0;
	u8 fence;

	spin_lock_irqsave(&qp->sq.lock, flags);

	if (mdev->state == MLX5_DEVICE_STATE_INTERNAL_ERROR) {
		err = -EIO;
		*bad_wr = wr;
		nreq = 0;
		goto out;
	}

	for (nreq = 0; wr; nreq++, wr = wr->next) {
		if (unlikely(wr->opcode >= ARRAY_SIZE(mlx5_ib_opcode))) {
			mlx5_ib_warn(dev, "Ivalid opcode 0x%x\n", wr->opcode);
			err = -EINVAL;
			*bad_wr = wr;
			goto out;
		}

		fence = qp->fm_cache;
		num_sge = wr->num_sge;
		if (unlikely(num_sge > qp->sq.max_gs)) {
			mlx5_ib_warn(dev, "Max gs exceeded %d (max = %d)\n", wr->num_sge, qp->sq.max_gs);
			err = -ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		err = begin_wqe(qp, &seg, &ctrl, wr, &idx, &size, nreq);
		if (err) {
			mlx5_ib_warn(dev, "Failed to prepare WQE\n");
			err = -ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		switch (ibqp->qp_type) {
		case IB_QPT_XRC_INI:
			xrc = seg;
			xrc->xrc_srqn = htonl(wr->xrc_remote_srq_num);
			seg += sizeof(*xrc);
			size += sizeof(*xrc) / 16;
			/* fall through */
		case IB_QPT_RC:
			switch (wr->opcode) {
			case IB_WR_RDMA_READ:
			case IB_WR_RDMA_WRITE:
			case IB_WR_RDMA_WRITE_WITH_IMM:
				set_raddr_seg(seg, wr->wr.rdma.remote_addr,
					      wr->wr.rdma.rkey);
				seg += sizeof(struct mlx5_wqe_raddr_seg);
				size += sizeof(struct mlx5_wqe_raddr_seg) / 16;
				break;

			case IB_WR_ATOMIC_CMP_AND_SWP:
			case IB_WR_ATOMIC_FETCH_AND_ADD:
			case IB_WR_MASKED_ATOMIC_CMP_AND_SWP:
				mlx5_ib_warn(dev, "Atomic operations are not supported yet\n");
				err = -ENOSYS;
				*bad_wr = wr;
				goto out;

			case IB_WR_LOCAL_INV:
				next_fence = MLX5_FENCE_MODE_INITIATOR_SMALL;
				qp->sq.swr_ctx[idx].wr_data = IB_WR_LOCAL_INV;
				ctrl->imm = cpu_to_be32(wr->ex.invalidate_rkey);
				err = set_frwr_li_wr(&seg, wr, &size, mdev, to_mpd(ibqp->pd), qp);
				if (err) {
					mlx5_ib_warn(dev, "Failed to prepare LOCAL_INV WQE\n");
					*bad_wr = wr;
					goto out;
				}
				num_sge = 0;
				break;

			case IB_WR_FAST_REG_MR:
				next_fence = MLX5_FENCE_MODE_INITIATOR_SMALL;
				qp->sq.swr_ctx[idx].wr_data = IB_WR_FAST_REG_MR;
				ctrl->imm = cpu_to_be32(wr->wr.fast_reg.rkey);
				err = set_frwr_li_wr(&seg, wr, &size, mdev, to_mpd(ibqp->pd), qp);
				if (err) {
					mlx5_ib_warn(dev, "Failed to prepare FAST_REG_MR WQE\n");
					*bad_wr = wr;
					goto out;
				}
				num_sge = 0;
				break;

			case IB_WR_REG_INDIR_MR:
				next_fence = MLX5_FENCE_MODE_INITIATOR_SMALL;
				qp->sq.swr_ctx[idx].wr_data = IB_WR_REG_INDIR_MR;
				ctrl->imm = cpu_to_be32(wr->wr.indir_reg.mkey);
				err = set_indir_reg_wr(wr, qp, &seg, &size);
				if (err) {
					mlx5_ib_warn(dev, "Failed to prepare indir_reg wqe\n");
					*bad_wr = wr;
					goto out;
				}
				num_sge = 0;
				break;

			case IB_WR_REG_SIG_MR:
				qp->sq.swr_ctx[idx].wr_data = IB_WR_REG_SIG_MR;
				mr = to_mmr(wr->wr.sig_handover.sig_mr);

				ctrl->imm = cpu_to_be32(mr->ibmr.rkey);
				err = set_sig_umr_wr(wr, qp, &seg, &size);
				if (err) {
					mlx5_ib_warn(dev, "Failed to prepare REG_SIG_MR WQE\n");
					*bad_wr = wr;
					goto out;
				}

				finish_wqe(qp, ctrl, size, idx, wr,
					   nreq, get_fence(fence, wr),
					   next_fence, MLX5_OPCODE_UMR);
				/*
				 * SET_PSV WQEs are not signaled and solicited
				 * on error
				 */
				wr->send_flags &= ~IB_SEND_SIGNALED;
				wr->send_flags |= IB_SEND_SOLICITED;
				err = begin_wqe(qp, &seg, &ctrl, wr,
						&idx, &size, nreq);
				if (err) {
					mlx5_ib_warn(dev, "Failed to prepare REG_SIG_MR WQE\n");
					err = -ENOMEM;
					*bad_wr = wr;
					goto out;
				}

				err = set_psv_wr(&wr->wr.sig_handover.sig_attrs->mem,
						 mr->sig->psv_memory.psv_idx, &seg,
						 &size);
				if (err) {
					mlx5_ib_warn(dev, "Failed to prepare REG_SIG_MR WQE\n");
					*bad_wr = wr;
					goto out;
				}

				finish_wqe(qp, ctrl, size, idx, wr,
					   nreq, get_fence(fence, wr),
					   next_fence, MLX5_OPCODE_SET_PSV);
				err = begin_wqe(qp, &seg, &ctrl, wr,
						&idx, &size, nreq);
				if (err) {
					mlx5_ib_warn(dev, "Failed to prepare REG_SIG_MR WQE\n");
					err = -ENOMEM;
					*bad_wr = wr;
					goto out;
				}

				next_fence = MLX5_FENCE_MODE_INITIATOR_SMALL;
				err = set_psv_wr(&wr->wr.sig_handover.sig_attrs->wire,
						 mr->sig->psv_wire.psv_idx, &seg,
						 &size);
				if (err) {
					mlx5_ib_warn(dev, "Failed to prepare REG_SIG_MR WQE\n");
					*bad_wr = wr;
					goto out;
				}

				finish_wqe(qp, ctrl, size, idx, wr,
					   nreq, get_fence(fence, wr),
					   next_fence, MLX5_OPCODE_SET_PSV);
				num_sge = 0;
				goto skip_psv;

			default:
				break;
			}
			break;

		case IB_QPT_UC:
			switch (wr->opcode) {
			case IB_WR_RDMA_WRITE:
			case IB_WR_RDMA_WRITE_WITH_IMM:
				set_raddr_seg(seg, wr->wr.rdma.remote_addr,
					      wr->wr.rdma.rkey);
				seg  += sizeof(struct mlx5_wqe_raddr_seg);
				size += sizeof(struct mlx5_wqe_raddr_seg) / 16;
				break;

			default:
				break;
			}
			break;

		case IB_QPT_SMI:
			if (!mlx5_core_is_pf(mdev)) {
				err = -EINVAL;
				mlx5_ib_warn(dev, "Only physical function is allowed to send SMP MADs\n");
				*bad_wr = wr;
				goto out;
			}
		case IB_QPT_GSI:
			set_datagram_seg(seg, wr);
			seg += sizeof(struct mlx5_wqe_datagram_seg);
			size += sizeof(struct mlx5_wqe_datagram_seg) / 16;
			if (unlikely((seg == qend)))
				seg = mlx5_get_send_wqe(qp, 0);
			break;

		case MLX5_IB_QPT_SW_CNAK:
			set_mlx_seg(seg, &((struct mlx5_send_wr *)wr)->sel.mlx);
			seg += sizeof(struct mlx5_mlx_seg);
			size += sizeof(struct mlx5_mlx_seg) / 16;
			if (unlikely((seg == qend)))
				seg = mlx5_get_send_wqe(qp, 0);
			break;
		case IB_QPT_UD:
			set_datagram_seg(seg, wr);
			seg += sizeof(struct mlx5_wqe_datagram_seg);
			size += sizeof(struct mlx5_wqe_datagram_seg) / 16;

			if (unlikely((seg == qend)))
				seg = mlx5_get_send_wqe(qp, 0);

			/* handle qp that supports ud offload */
			if (qp->flags & IB_QP_CREATE_IPOIB_UD_LSO) {
				struct mlx5_wqe_eth_pad *pad;
				pad = seg;
				memset(pad, 0, sizeof(struct mlx5_wqe_eth_pad));
				seg += sizeof(struct mlx5_wqe_eth_pad);
				size += sizeof(struct mlx5_wqe_eth_pad) / 16;
				seg = set_eth_seg(seg, wr, qend, qp, &size);
				if (unlikely((seg == qend)))
					seg = mlx5_get_send_wqe(qp, 0);
			}
			break;
		case MLX5_IB_QPT_REG_UMR:
			if (wr->opcode != MLX5_IB_WR_UMR) {
				err = -EINVAL;
				mlx5_ib_warn(dev, "bad opcode\n");
				goto out;
			}
			qp->sq.swr_ctx[idx].wr_data = MLX5_IB_WR_UMR;
			ctrl->imm = cpu_to_be32(wr->wr.fast_reg.rkey);
			set_reg_umr_segment(seg, wr, !!(MLX5_CAP_GEN(mdev, atomic)));
			seg += sizeof(struct mlx5_wqe_umr_ctrl_seg);
			size += sizeof(struct mlx5_wqe_umr_ctrl_seg) / 16;
			if (unlikely((seg == qend)))
				seg = mlx5_get_send_wqe(qp, 0);
			set_reg_mkey_segment(seg, wr);
			seg += sizeof(struct mlx5_mkey_seg);
			size += sizeof(struct mlx5_mkey_seg) / 16;
			if (unlikely((seg == qend)))
				seg = mlx5_get_send_wqe(qp, 0);
			break;

		default:
			break;
		}

		if (wr->send_flags & IB_SEND_INLINE && num_sge) {
			int uninitialized_var(sz);

			err = set_data_inl_seg(qp, wr, seg, &sz);
			if (unlikely(err)) {
				mlx5_ib_warn(dev, "Failed to prepare inline data segment\n");
				*bad_wr = wr;
				goto out;
			}
			inl = 1;
			size += sz;
		} else {
			dpseg = seg;
			for (i = 0; i < num_sge; i++) {
				if (unlikely(dpseg == qend)) {
					seg = mlx5_get_send_wqe(qp, 0);
					dpseg = seg;
				}
				if (likely(wr->sg_list[i].length)) {
					set_data_ptr_seg(dpseg, wr->sg_list + i);
					size += sizeof(struct mlx5_wqe_data_seg) / 16;
					dpseg++;
				}
			}
		}

		finish_wqe(qp, ctrl, size, idx, wr, nreq,
			   get_fence(fence, wr), next_fence,
			   mlx5_ib_opcode[wr->opcode]);
skip_psv:
		if (0)
			dump_wqe(qp, idx, size);
	}

out:
	if (likely(nreq)) {
		qp->sq.head += nreq;

		/* Make sure that descriptors are written before
		 * updating doorbell record and ringing the doorbell
		 */
		wmb();

		qp->db.db[MLX5_SND_DBR] = cpu_to_be32(qp->sq.cur_post);

		/* Make sure doorbell record is visible to the HCA before
		 * we hit doorbell */
		wmb();

		if (bf->need_lock)
			spin_lock(&bf->lock);
		else
			__acquire(&bf->lock);

		/* TBD enable WC */
		if (0 && nreq == 1 && bf->uuarn && inl && size > 1 && size <= bf->buf_size / 16) {
			mlx5_bf_copy(bf->reg + bf->offset, (u64 *)ctrl, ALIGN(size * 16, 64), qp);
			/* wc_wmb(); */
		} else {
			mlx5_write64((__be32 *)ctrl, bf->regreg + bf->offset,
				     MLX5_GET_DOORBELL_LOCK(&bf->lock32));
			/* Make sure doorbells don't leak out of SQ spinlock
			 * and reach the HCA out of order.
			 */
			mmiowb();
		}
		bf->offset ^= bf->buf_size;
		if (bf->need_lock)
			spin_unlock(&bf->lock);
		else
			__release(&bf->lock);
	}

	spin_unlock_irqrestore(&qp->sq.lock, flags);

	return err;
}

static void set_sig_seg(struct mlx5_rwqe_sig *sig, int size)
{
	sig->signature = calc_sig(sig, size);
}

int mlx5_ib_post_recv(struct ib_qp *ibqp, struct ib_recv_wr *wr,
		      struct ib_recv_wr **bad_wr)
{
	struct mlx5_ib_qp *qp = to_mqp(ibqp);
	struct mlx5_wqe_data_seg *scat;
	struct mlx5_rwqe_sig *sig;
	struct mlx5_ib_dev *dev = to_mdev(ibqp->device);
	struct mlx5_core_dev *mdev = dev->mdev;
	unsigned long flags;
	int err = 0;
	int nreq;
	int ind;
	int i;

	spin_lock_irqsave(&qp->rq.lock, flags);

	if (mdev->state == MLX5_DEVICE_STATE_INTERNAL_ERROR) {
		err = -EIO;
		*bad_wr = wr;
		nreq = 0;
		goto out;
	}

	ind = qp->rq.head & (qp->rq.wqe_cnt - 1);

	for (nreq = 0; wr; nreq++, wr = wr->next) {
		if (mlx5_wq_overflow(&qp->rq, nreq, qp->ibqp.recv_cq)) {
			err = -ENOMEM;
			*bad_wr = wr;
			goto out;
		}

		if (unlikely(wr->num_sge > qp->rq.max_gs)) {
			err = -EINVAL;
			*bad_wr = wr;
			goto out;
		}

		scat = get_recv_wqe(qp, ind);
		if (qp->wq_sig)
			scat++;

		for (i = 0; i < wr->num_sge; i++)
			set_data_ptr_seg(scat + i, wr->sg_list + i);

		if (i < qp->rq.max_gs) {
			scat[i].byte_count = 0;
			scat[i].lkey       = cpu_to_be32(MLX5_INVALID_LKEY);
			scat[i].addr       = 0;
		}

		if (qp->wq_sig) {
			sig = (struct mlx5_rwqe_sig *)scat;
			set_sig_seg(sig, (qp->rq.max_gs + 1) << 2);
		}

		qp->rq.rwr_ctx[ind].wrid = wr->wr_id;

		ind = (ind + 1) & (qp->rq.wqe_cnt - 1);
	}

out:
	if (likely(nreq)) {
		qp->rq.head += nreq;

		/* Make sure that descriptors are written before
		 * doorbell record.
		 */
		wmb();

		*qp->db.db = cpu_to_be32(qp->rq.head & 0xffff);
	}

	spin_unlock_irqrestore(&qp->rq.lock, flags);

	return err;
}

static inline enum ib_qp_state to_ib_qp_state(enum mlx5_qp_state mlx5_state)
{
	switch (mlx5_state) {
	case MLX5_QP_STATE_RST:      return IB_QPS_RESET;
	case MLX5_QP_STATE_INIT:     return IB_QPS_INIT;
	case MLX5_QP_STATE_RTR:      return IB_QPS_RTR;
	case MLX5_QP_STATE_RTS:      return IB_QPS_RTS;
	case MLX5_QP_STATE_SQ_DRAINING:
	case MLX5_QP_STATE_SQD:      return IB_QPS_SQD;
	case MLX5_QP_STATE_SQER:     return IB_QPS_SQE;
	case MLX5_QP_STATE_ERR:      return IB_QPS_ERR;
	default:		     return -1;
	}
}

static inline enum ib_mig_state to_ib_mig_state(int mlx5_mig_state)
{
	switch (mlx5_mig_state) {
	case MLX5_QP_PM_ARMED:		return IB_MIG_ARMED;
	case MLX5_QP_PM_REARM:		return IB_MIG_REARM;
	case MLX5_QP_PM_MIGRATED:	return IB_MIG_MIGRATED;
	default: return -1;
	}
}

static int to_ib_qp_access_flags(int mlx5_flags)
{
	int ib_flags = 0;

	if (mlx5_flags & MLX5_QP_BIT_RRE)
		ib_flags |= IB_ACCESS_REMOTE_READ;
	if (mlx5_flags & MLX5_QP_BIT_RWE)
		ib_flags |= IB_ACCESS_REMOTE_WRITE;
	if (mlx5_flags & MLX5_QP_BIT_RAE)
		ib_flags |= IB_ACCESS_REMOTE_ATOMIC;

	return ib_flags;
}

static void to_ib_ah_attr(struct mlx5_ib_dev *ibdev, struct ib_ah_attr *ib_ah_attr,
				struct mlx5_qp_path *path)
{
	struct mlx5_core_dev *dev = ibdev->mdev;

	memset(ib_ah_attr, 0, sizeof(*ib_ah_attr));
	ib_ah_attr->port_num	  = path->port;

	if (ib_ah_attr->port_num == 0 ||
	    ib_ah_attr->port_num > MLX5_CAP_GEN(dev, num_ports))
		return;

	ib_ah_attr->sl = path->dci_cfi_prio_sl & 0xf;

	ib_ah_attr->dlid	  = be16_to_cpu(path->rlid);
	ib_ah_attr->src_path_bits = path->grh_mlid & 0x7f;
	ib_ah_attr->static_rate   = path->static_rate ? path->static_rate - 5 : 0;
	ib_ah_attr->ah_flags      = (path->grh_mlid & (1 << 7)) ? IB_AH_GRH : 0;
	if (ib_ah_attr->ah_flags) {
		ib_ah_attr->grh.sgid_index = path->mgid_index;
		ib_ah_attr->grh.hop_limit  = path->hop_limit;
		ib_ah_attr->grh.traffic_class =
			(be32_to_cpu(path->tclass_flowlabel) >> 20) & 0xff;
		ib_ah_attr->grh.flow_label =
			be32_to_cpu(path->tclass_flowlabel) & 0xfffff;
		memcpy(ib_ah_attr->grh.dgid.raw,
		       path->rgid, sizeof(ib_ah_attr->grh.dgid.raw));
	}
}

static int query_raw_qp_sq_state(struct mlx5_ib_dev *dev,
				 struct mlx5_ib_qp *qp, u8 *sq_state)
{
	void *out;
	void *sqc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(query_sq_out);
	out = mlx5_vzalloc(inlen);
	if (!out)
		return -ENOMEM;

	err = mlx5_core_query_sq(dev->mdev, qp->msq.qpn, out);
	if (err)
		goto out;

	sqc = MLX5_ADDR_OF(query_sq_out, out, sq_context);
	*sq_state = MLX5_GET(sqc, sqc, state);
	qp->sq_state = *sq_state;

out:
	kvfree(out);
	return err;
}

static int query_raw_qp_rq_state(struct mlx5_ib_dev *dev,
				 struct mlx5_ib_qp *qp, u8 *rq_state)
{
	void *out;
	void *rqc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(query_rq_out);
	out = mlx5_vzalloc(inlen);
	if (!out)
		return -ENOMEM;

	err = mlx5_core_query_rq(dev->mdev, qp->mrq.qpn, out);
	if (err)
		goto out;

	rqc = MLX5_ADDR_OF(query_rq_out, out, rq_context);
	*rq_state = MLX5_GET(rqc, rqc, state);
	qp->rq_state = *rq_state;

out:
	kvfree(out);
	return err;
}

static int sqrq_state_to_qp_state(u8 sq_state, u8 rq_state,
				  struct mlx5_ib_qp *qp, u8 *qp_state)
{
	static const u8 sqrq_trans[MLX5_RQ_NUM_STATE][MLX5_SQ_NUM_STATE] = {
		[MLX5_RQC_STATE_RST] = {
			[MLX5_SQC_STATE_RST]	= IB_QPS_RESET,
			[MLX5_SQC_STATE_RDY]	= MLX5_QP_STATE_BAD,
			[MLX5_SQC_STATE_ERR]	= MLX5_QP_STATE_BAD,
		},
		[MLX5_RQC_STATE_RDY] = {
			[MLX5_SQC_STATE_RST]	= MLX5_QP_STATE_BAD,
			[MLX5_SQC_STATE_RDY]	= MLX5_QP_STATE,
			[MLX5_SQC_STATE_ERR]	= IB_QPS_SQE,
		},
		[MLX5_RQC_STATE_ERR] = {
			[MLX5_SQC_STATE_RST]    = MLX5_QP_STATE_BAD,
			[MLX5_SQC_STATE_RDY]	= MLX5_QP_STATE_BAD,
			[MLX5_SQC_STATE_ERR]	= IB_QPS_ERR,
		},
	};

	*qp_state = sqrq_trans[rq_state][sq_state];

	if (*qp_state == MLX5_QP_STATE_BAD)
		return -EINVAL;

	if (*qp_state == MLX5_QP_STATE) {
		if (qp->state == IB_QPS_INIT ||
		    qp->state == IB_QPS_RTR ||
		    qp->state == IB_QPS_RTS) {
			*qp_state = qp->state;
		} else {
			return -EINVAL;
		}
	}

	return 0;
}

static int sq_state_to_qp_state(u8 sq_state, struct mlx5_ib_qp *qp,
				u8 *qp_state)
{
	switch (sq_state) {
	case MLX5_SQC_STATE_RST:
		*qp_state = IB_QPS_RESET;
		break;
	case MLX5_SQC_STATE_RDY:
		if (qp->state == IB_QPS_INIT ||
		    qp->state == IB_QPS_RTR ||
		    qp->state == IB_QPS_RTS)
			*qp_state = qp->state;
		else
			return -EINVAL;
		break;
	case MLX5_SQC_STATE_ERR:
		if (qp->state == IB_QPS_SQE ||
		    qp->state == IB_QPS_ERR)
			*qp_state = qp->state;
		else
			return -EINVAL;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int rq_state_to_qp_state(u8 rq_state, struct mlx5_ib_qp *qp,
				u8 *qp_state)
{
	switch (rq_state) {
	case MLX5_RQC_STATE_RST:
		*qp_state = IB_QPS_RESET;
		break;
	case MLX5_RQC_STATE_RDY:
		if (qp->state == IB_QPS_INIT ||
		    qp->state == IB_QPS_RTR ||
		    qp->state == IB_QPS_RTS)
			*qp_state = qp->state;
		else
			return -EINVAL;
		break;
	case MLX5_RQC_STATE_ERR:
		*qp_state = IB_QPS_ERR;
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int query_raw_qp_state(struct mlx5_ib_dev *dev, struct mlx5_ib_qp *qp,
			      u8 *raw_qp_state)
{
	int err;
	u8 sq_state = 0;
	u8 rq_state = 0;

	if (!qp->sq.wqe_cnt && !qp->rq.wqe_cnt)
		return -EINVAL;

	if (qp->sq.wqe_cnt) {
		err = query_raw_qp_sq_state(dev, qp, &sq_state);
		if (err)
			return err;
	}

	if (qp->rq.wqe_cnt) {
		err = query_raw_qp_rq_state(dev, qp, &rq_state);
		if (err)
			return err;
	}

	if (qp->sq.wqe_cnt && qp->rq.wqe_cnt)
		return sqrq_state_to_qp_state(sq_state, rq_state, qp,
					      raw_qp_state);
	else if (qp->sq.wqe_cnt)
		return sq_state_to_qp_state(sq_state, qp, raw_qp_state);
	else
		return rq_state_to_qp_state(rq_state, qp, raw_qp_state);
}

int mlx5_ib_query_qp(struct ib_qp *ibqp, struct ib_qp_attr *qp_attr, int qp_attr_mask,
		     struct ib_qp_init_attr *qp_init_attr)
{
	struct mlx5_ib_dev *dev = to_mdev(ibqp->device);
	struct mlx5_ib_qp *qp = to_mqp(ibqp);
	struct mlx5_query_qp_mbox_out *outb;
	struct mlx5_qp_context *context;
	int mlx5_state;
	int err = 0;
	u8 raw_qp_state;

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	/*
	 * Wait for any outstanding page faults, in case the user frees memory
	 * based upon this query's result.
	 */
	flush_workqueue(mlx5_ib_page_fault_wq);
#endif

	mutex_lock(&qp->mutex);
	if (qp->ibqp.qp_type == IB_QPT_RAW_PACKET) {
		err = query_raw_qp_state(dev, qp, &raw_qp_state);
		if (err)
			goto out;
		qp->state = raw_qp_state;
		qp_attr->port_num = 1;
	} else {
		outb = kzalloc(sizeof(*outb), GFP_KERNEL);
		if (!outb) {
			err = -ENOMEM;
			goto out;
		}

		context = &outb->ctx;
		err = mlx5_core_qp_query(dev->mdev, &qp->mqp, outb,
					 sizeof(*outb));
		if (err) {
			kfree(outb);
			goto out;
		}

		mlx5_state = be32_to_cpu(context->flags) >> 28;

		qp->state		     = to_ib_qp_state(mlx5_state);
		qp_attr->path_mtu	     = context->mtu_msgmax >> 5;
		qp_attr->path_mig_state	     =
			to_ib_mig_state((be32_to_cpu(context->flags) >> 11) & 0x3);
		qp_attr->qkey		     = be32_to_cpu(context->qkey);
		qp_attr->rq_psn		     = be32_to_cpu(context->rnr_nextrecvpsn) & 0xffffff;
		qp_attr->sq_psn		     = be32_to_cpu(context->next_send_psn) & 0xffffff;
		qp_attr->dest_qp_num	     = be32_to_cpu(context->log_pg_sz_remote_qpn) & 0xffffff;
		qp_attr->qp_access_flags     =
			to_ib_qp_access_flags(be32_to_cpu(context->params2));

		if (qp->ibqp.qp_type == IB_QPT_RC || qp->ibqp.qp_type == IB_QPT_UC) {
			to_ib_ah_attr(dev, &qp_attr->ah_attr, &context->pri_path);
			to_ib_ah_attr(dev, &qp_attr->alt_ah_attr, &context->alt_path);
			qp_attr->alt_pkey_index = be16_to_cpu(context->alt_path.pkey_index);
			qp_attr->alt_port_num	= qp_attr->alt_ah_attr.port_num;
		}

		qp_attr->pkey_index = be16_to_cpu(context->pri_path.pkey_index);
		qp_attr->port_num = context->pri_path.port;

		/* qp_attr->en_sqd_async_notify is only applicable in modify qp */
		qp_attr->sq_draining = mlx5_state == MLX5_QP_STATE_SQ_DRAINING;

		qp_attr->max_rd_atomic = 1 << ((be32_to_cpu(context->params1) >> 21) & 0x7);

		qp_attr->max_dest_rd_atomic =
			1 << ((be32_to_cpu(context->params2) >> 21) & 0x7);
		qp_attr->min_rnr_timer	    =
			(be32_to_cpu(context->rnr_nextrecvpsn) >> 24) & 0x1f;
		qp_attr->timeout	    = context->pri_path.ackto_lt >> 3;
		qp_attr->retry_cnt	    = (be32_to_cpu(context->params1) >> 16) & 0x7;
		qp_attr->rnr_retry	    = (be32_to_cpu(context->params1) >> 13) & 0x7;
		qp_attr->alt_timeout	    = context->alt_path.ackto_lt >> 3;

		if (be32_to_cpu(context->flags_pd) & MLX5_QP_DRAIN_SIGERR)
			qp_init_attr->create_flags |= IB_QP_CREATE_SIGNATURE_PIPELINE;


		kfree(outb);
	}

	qp_attr->qp_state	     = qp->state;
	qp_attr->cur_qp_state	     = qp_attr->qp_state;
	qp_attr->cap.max_recv_wr     = qp->rq.wqe_cnt;
	qp_attr->cap.max_recv_sge    = qp->rq.max_gs;

	if (!ibqp->uobject) {
		qp_attr->cap.max_send_wr  = qp->sq.max_post;
		qp_attr->cap.max_send_sge = qp->sq.max_gs;
		qp_init_attr->qp_context = ibqp->qp_context;
	} else {
		qp_attr->cap.max_send_wr  = 0;
		qp_attr->cap.max_send_sge = 0;
	}

	qp_init_attr->qp_type = ibqp->qp_type;
	qp_init_attr->recv_cq = ibqp->recv_cq;
	qp_init_attr->send_cq = ibqp->send_cq;
	qp_init_attr->srq = ibqp->srq;
	qp_attr->cap.max_inline_data = qp->max_inline_data;

	qp_init_attr->cap	     = qp_attr->cap;

	qp_init_attr->create_flags = 0;
	if (qp->flags & MLX5_IB_QP_BLOCK_MULTICAST_LOOPBACK)
		qp_init_attr->create_flags |= IB_QP_CREATE_BLOCK_MULTICAST_LOOPBACK;

	qp_init_attr->sq_sig_type = qp->sq_signal_bits & MLX5_WQE_CTRL_CQ_UPDATE ?
		IB_SIGNAL_ALL_WR : IB_SIGNAL_REQ_WR;

	if (qp->flags & MLX5_IB_QP_CAP_CROSS_CHANNEL)
		qp_init_attr->create_flags |= IB_QP_CREATE_CROSS_CHANNEL;

	if (qp->flags & MLX5_IB_QP_CAP_MANAGED_SEND)
		qp_init_attr->create_flags |= IB_QP_CREATE_MANAGED_SEND;

	if (qp->flags & MLX5_IB_QP_CAP_MANAGED_RECV)
		qp_init_attr->create_flags |= IB_QP_CREATE_MANAGED_RECV;

out:
	mutex_unlock(&qp->mutex);
	return err;
}

struct ib_xrcd *mlx5_ib_alloc_xrcd(struct ib_device *ibdev,
					  struct ib_ucontext *context,
					  struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(ibdev);
	struct mlx5_ib_xrcd *xrcd;
	int err;

	if (!MLX5_CAP_GEN(dev->mdev, xrc))
		return ERR_PTR(-ENOSYS);

	xrcd = kmalloc(sizeof(*xrcd), GFP_KERNEL);
	if (!xrcd)
		return ERR_PTR(-ENOMEM);

	err = mlx5_core_xrcd_alloc(dev->mdev, &xrcd->xrcdn);
	if (err) {
		kfree(xrcd);
		return ERR_PTR(-ENOMEM);
	}

	return &xrcd->ibxrcd;
}

int mlx5_ib_dealloc_xrcd(struct ib_xrcd *xrcd)
{
	struct mlx5_ib_dev *dev = to_mdev(xrcd->device);
	u32 xrcdn = to_mxrcd(xrcd)->xrcdn;
	int err;

	err = mlx5_core_xrcd_dealloc(dev->mdev, xrcdn);
	if (err) {
		mlx5_ib_warn(dev, "failed to dealloc xrcdn 0x%x\n", xrcdn);
		return err;
	}

	kfree(xrcd);

	return 0;
}

static u32 atomic_mode_dct(struct mlx5_ib_dev *dev)
{
	unsigned long mask;
	unsigned long tmp;

	mask = MLX5_CAP_ATOMIC(dev->mdev, atomic_size_qp) &
	       MLX5_CAP_ATOMIC(dev->mdev, atomic_size_dc);

	tmp = find_last_bit(&mask, BITS_PER_LONG);
	if (tmp < 2)
		return MLX5_ATOMIC_MODE_DCT_NONE;

	if (tmp == 2)
		return MLX5_ATOMIC_MODE_DCT_CX;

	return tmp << MLX5_ATOMIC_MODE_DCT_OFF;
}

static u32 ib_to_dct_acess(struct mlx5_ib_dev *dev, u32 ib_flags)
{
	u32 flags = 0;

	if (ib_flags & IB_ACCESS_REMOTE_READ)
		flags |= MLX5_DCT_BIT_RRE;
	if (ib_flags & IB_ACCESS_REMOTE_WRITE)
		flags |= (MLX5_DCT_BIT_RWE | MLX5_DCT_BIT_RRE);
	if (ib_flags & IB_ACCESS_REMOTE_ATOMIC) {
		flags |= (MLX5_DCT_BIT_RAE | MLX5_DCT_BIT_RWE | MLX5_DCT_BIT_RRE);
		flags |= atomic_mode_dct(dev);
	}

	return flags;
}

static void mlx5_ib_dct_event(struct mlx5_core_dct *dct, enum mlx5_event type)
{
	struct ib_dct *ibdct = &to_mibdct(dct)->ibdct;
	struct ib_event event;

	if (ibdct->event_handler) {
		event.device     = ibdct->device;
		event.element.dct = ibdct;
		switch (type) {
		case MLX5_EVENT_TYPE_WQ_INVAL_REQ_ERROR:
			event.event = IB_EXP_EVENT_DCT_REQ_ERR;
			break;
		case MLX5_EVENT_TYPE_WQ_ACCESS_ERROR:
			event.event = IB_EXP_EVENT_DCT_ACCESS_ERR;
			break;
		case MLX5_EVENT_TYPE_DCT_KEY_VIOLATION:
			event.event = IB_EXP_EVENT_DCT_KEY_VIOLATION;
			break;
		default:
			pr_warn("mlx5_ib: Unexpected event type %d on DCT %06x\n",
				type, dct->dctn);
			return;
		}

		ibdct->event_handler(&event, ibdct->dct_context);
	}
}

struct ib_dct *mlx5_ib_create_dct(struct ib_pd *pd,
				  struct ib_dct_init_attr *attr,
				  struct ib_udata *udata)
{
	struct mlx5_create_dct_mbox_in *in;
	struct mlx5_dct_context *dctx;
	struct mlx5_ib_create_dct ucmd;
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_dct *dct;
	void *dctc;
	int cqe_sz;
	int err;
	u32 uidx = 0;
	u32 cqn;

	if (pd && pd->uobject) {
		if (ib_copy_from_udata(&ucmd, udata, sizeof(ucmd))) {
			mlx5_ib_err(dev, "copy failed\n");
			return ERR_PTR(-EFAULT);
		}

		if (udata->inlen)
			uidx = ucmd.uidx;
		else
			uidx = 0xffffff;
	} else {
		uidx = 0xffffff;
	}

	dct = kzalloc(sizeof(*dct), GFP_KERNEL);
	if (!dct)
		return ERR_PTR(-ENOMEM);

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in) {
		err = -ENOMEM;
		goto err_alloc;
	}

	dctx = &in->context;

	cqn = to_mcq(attr->cq)->mcq.cqn;
	if (cqn & 0xff000000) {
		mlx5_ib_warn(dev, "invalid cqn 0x%x\n", cqn);
		err = -EINVAL;
		goto err_alloc;
	}
	dctx->cqn = cpu_to_be32(cqn);
	dctx->flags |= cpu_to_be32(ib_to_dct_acess(dev, attr->access_flags));

	if (attr->inline_size) {
		cqe_sz = mlx5_ib_get_cqe_size(dev, attr->cq);
		if (cqe_sz == 128) {
			dctx->cs_res = MLX5_DCT_CS_RES_64;
			attr->inline_size = 64;
		} else {
			attr->inline_size = 0;
		}
	}
	dctx->min_rnr = attr->min_rnr_timer;
	dctx->srqn = cpu_to_be32(to_msrq(attr->srq)->msrq.srqn);
	dctx->pdn = cpu_to_be32(to_mpd(pd)->pdn);
	dctx->tclass_flow_label |= cpu_to_be32(attr->tclass << 24);
	dctx->tclass_flow_label |= cpu_to_be32(attr->flow_label);
	dctx->access_key = cpu_to_be64(attr->dc_key);
	dctx->mtu = attr->mtu;
	dctx->port = attr->port;
	dctx->pkey_index = cpu_to_be16(attr->pkey_index);
	dctx->mgid_index = attr->gid_index;
	dctx->hop_limit = attr->hop_limit;

	if (MLX5_CAP_GEN(dev->mdev, cqe_version)) {
		dctc = MLX5_ADDR_OF(create_dct_in, in, dct_context_entry);
		/* 0xffffff means we ask to work with cqe version 0 */
		MLX5_SET(dctc, dctc, user_index, uidx);
	}

	err = mlx5_core_create_dct(dev->mdev, &dct->mdct, in);
	if (err)
		goto err_alloc;

	dct->ibdct.dct_num = dct->mdct.dctn;
	dct->mdct.event = mlx5_ib_dct_event;
	kfree(in);
	return &dct->ibdct;

err_alloc:
	kfree(in);
	kfree(dct);
	return ERR_PTR(err);
}

int mlx5_ib_destroy_dct(struct ib_dct *dct)
{
	struct mlx5_ib_dev *dev = to_mdev(dct->device);
	struct mlx5_ib_dct *mdct = to_mdct(dct);
	int err;

	err = mlx5_core_destroy_dct(dev->mdev, &mdct->mdct);
	if (!err)
		kfree(mdct);

	return err;
}

int dct_to_ib_access(u32 dc_flags)
{
	u32 flags = 0;

	if (dc_flags & MLX5_DCT_BIT_RRE)
		flags |= IB_ACCESS_REMOTE_READ;
	if (dc_flags & MLX5_QP_BIT_RWE)
		flags |= IB_ACCESS_REMOTE_WRITE;
	if ((dc_flags & MLX5_ATOMIC_MODE_CX) == MLX5_ATOMIC_MODE_CX)
		flags |= IB_ACCESS_REMOTE_ATOMIC;

	return flags;
}

int mlx5_ib_query_dct(struct ib_dct *dct, struct ib_dct_attr *attr)
{
	struct mlx5_ib_dev *dev = to_mdev(dct->device);
	struct mlx5_ib_dct *mdct = to_mdct(dct);
	struct mlx5_query_dct_mbox_out *out;
	struct mlx5_dct_context *ctx;
	int err;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out)
		return -ENOMEM;

	err = mlx5_core_dct_query(dev->mdev, &mdct->mdct, out);
	if (err)
		goto out;

	ctx = &out->ctx;

	attr->dc_key = be64_to_cpu(ctx->access_key);
	attr->port = ctx->port;
	attr->access_flags = dct_to_ib_access(be32_to_cpu(ctx->flags));
	attr->min_rnr_timer = ctx->min_rnr & 0x1f;
	attr->tclass = be32_to_cpu(ctx->tclass_flow_label) >> 24;
	attr->flow_label = be32_to_cpu(ctx->tclass_flow_label) & 0xfffff;
	attr->mtu = ctx->mtu & 7;
	attr->pkey_index = be16_to_cpu(ctx->pkey_index);
	attr->gid_index = ctx->mgid_index;
	attr->hop_limit = ctx->hop_limit;
	attr->key_violations = be32_to_cpu(ctx->access_violations);
	attr->state = ctx->state & 0xf;

out:
	kfree(out);
	return err;
}

int mlx5_ib_arm_dct(struct ib_dct *dct, struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(dct->device);
	struct mlx5_ib_dct *mdct = to_mdct(dct);
	struct mlx5_ib_arm_dct ucmd;
	struct mlx5_ib_arm_dct_resp resp;
	int err;

	err = ib_copy_from_udata(&ucmd, udata, sizeof(ucmd));
	if (err) {
		mlx5_ib_err(dev, "copy failed\n");
		return err;
	}

	if (ucmd.reserved0 || ucmd.reserved1)
		return -EINVAL;

	err = mlx5_core_arm_dct(dev->mdev, &mdct->mdct);
	if (err)
		goto out;

	memset(&resp, 0, sizeof(resp));
	err = ib_copy_to_udata(udata, &resp, sizeof(resp));
	if (err)
		mlx5_ib_err(dev, "copy failed\n");

out:
	return err;
}

static int  mlx5_ib_create_rq(struct mlx5_ib_rwq *rwq, struct ib_pd *pd,
			      struct ib_wq_init_attr *init_attr)
{
	struct mlx5_ib_dev *dev;
	__be64 *rq_pas0;
	void *in;
	void *rqc;
	void *wq;
	int inlen;
	int err;

	dev = to_mdev(pd->device);

	if (init_attr->mp_rq.use_mp_rq) {
		if (MLX5_CAP_GEN(dev->mdev, striding_rq) != RQ_TYPE_STRIDE)
			return -EOPNOTSUPP;

		if (init_attr->mp_rq.use_shift & ~IB_MP_RQ_2BYTES_SHIFT ||
		    init_attr->mp_rq.single_stride_log_num_of_bytes < MLX5_MIN_SINGLE_STRIDE_LOG_NUM_BYTES ||
		    init_attr->mp_rq.single_stride_log_num_of_bytes > MLX5_MAX_SINGLE_STRIDE_LOG_NUM_BYTES ||
		    init_attr->mp_rq.single_wqe_log_num_of_strides < MLX5_MIN_SINGLE_WQE_LOG_NUM_STRIDES ||
		    init_attr->mp_rq.single_wqe_log_num_of_strides > MLX5_MAX_SINGLE_WQE_LOG_NUM_STRIDES)
			return -EINVAL;
	}

	inlen = MLX5_ST_SZ_BYTES(create_rq_in) + sizeof(u64) * rwq->rq_num_pas;
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	rqc = MLX5_ADDR_OF(create_rq_in, in, ctx);
	if (init_attr->vlan_offloads & IB_WQ_CVLAN_STRIPPING) {
		if (!(MLX5_CAP_GEN(dev->mdev, eth_net_offloads) &&
		      MLX5_CAP_ETH(dev->mdev, vlan_cap)))
			return -EOPNOTSUPP;
	} else {
		MLX5_SET(rqc, rqc, vsd, 1);
	}
	MLX5_SET(rqc,  rqc, mem_rq_type,
		 MLX5_RQC_MEM_RQ_TYPE_MEMORY_RQ_INLINE);
	MLX5_SET(rqc, rqc, user_index, rwq->user_index);
	MLX5_SET(rqc,  rqc, cqn, to_mcq(init_attr->cq)->mcq.cqn);
	MLX5_SET(rqc,  rqc, state, MLX5_RQC_STATE_RST);
	MLX5_SET(rqc,  rqc, flush_in_error_en, 1);

	if (init_attr->flags & IB_CREATE_WQ_FLAG_SCATTER_FCS) {
		if (!MLX5_CAP_GEN(dev->mdev, eth_net_offloads) ||
		    !MLX5_CAP_ETH(dev->mdev, scatter_fcs)) {
			mlx5_ib_dbg(dev, "Scatter FCS is not supported by the HCA\n");
			err = -EOPNOTSUPP;
			goto out;
		} else {
			MLX5_SET(rqc, rqc, scatter_fcs, 1);
		}
	}

	wq = MLX5_ADDR_OF(rqc, rqc, wq);
	if (init_attr->mp_rq.use_mp_rq) {
		MLX5_SET(wq, wq, wq_type, MLX5_WQ_TYPE_STRQ_CYCLIC);
		MLX5_SET(wq, wq, log_wqe_num_of_strides,
			 (init_attr->mp_rq.single_wqe_log_num_of_strides -
			  MLX5_MIN_SINGLE_WQE_LOG_NUM_STRIDES));
		MLX5_SET(wq, wq, log_wqe_stride_size,
			 (init_attr->mp_rq.single_stride_log_num_of_bytes -
			  MLX5_MIN_SINGLE_STRIDE_LOG_NUM_BYTES));
		if (init_attr->mp_rq.use_shift == IB_MP_RQ_2BYTES_SHIFT)
			MLX5_SET(wq, wq, two_byte_shift_en, 0x1);
	} else {
		MLX5_SET(wq, wq, wq_type, MLX5_WQ_TYPE_CYCLIC);
	}
	if (MLX5_CAP_GEN(dev->mdev, end_pad)) {
		if (init_attr->flags & IB_CREATE_WQ_FLAG_RX_END_PADDING)
			MLX5_SET(wq, wq, end_padding_mode, MLX5_WQ_END_PAD_MODE_ALIGN);
		else
			MLX5_SET(wq, wq, end_padding_mode, MLX5_WQ_END_PAD_MODE_NONE);
	}
	MLX5_SET(wq, wq, log_wq_stride, rwq->log_rq_stride);
	MLX5_SET(wq, wq, log_wq_sz, rwq->log_rq_size);
	MLX5_SET(wq, wq, pd, to_mpd(pd)->pdn);
	MLX5_SET(wq, wq, page_offset, rwq->rq_page_offset);
	MLX5_SET(wq, wq, log_wq_pg_sz, rwq->log_page_size);
	MLX5_SET(wq, wq, wq_signature, rwq->wq_sig);
	MLX5_SET64(wq, wq, dbr_addr, rwq->db.dma);
	rq_pas0 = (__be64 *)MLX5_ADDR_OF(wq, wq, pas);
	mlx5_ib_populate_pas(dev, rwq->umem, rwq->page_shift, rq_pas0, 0);
	err = mlx5_core_create_rq(dev->mdev, in, inlen, &rwq->rqn);
out:
	kvfree(in);

	return err;
}

static int set_user_rq_size(struct mlx5_ib_dev *dev,
			    struct ib_wq_init_attr *wq_init_attr,
			    struct mlx5_ib_create_wq *ucmd,
			    struct mlx5_ib_rwq *rwq)
{
	/* TBD: Sanity check RQ size before proceeding */
	rwq->wqe_count = ucmd->rq_wqe_count;
	rwq->wqe_shift = ucmd->rq_wqe_shift;
	rwq->buf_size = (rwq->wqe_count << rwq->wqe_shift);
	rwq->log_rq_stride = rwq->wqe_shift;
	rwq->log_rq_size = ilog2(rwq->wqe_count);
	return 0;
}

static int mlx5_ib_prepare_user_rq(struct ib_pd *pd,
				   struct ib_wq_init_attr *init_attr,
				   struct ib_udata *udata,
				   struct mlx5_ib_rwq *rwq)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_create_wq ucmd;
	int err;

	if (ib_copy_from_udata(&ucmd, udata, sizeof(ucmd))) {
		mlx5_ib_err(dev, "copy failed\n");
		return -EFAULT;
	}

	err = set_user_rq_size(dev, init_attr, &ucmd, rwq);
	if (err) {
		mlx5_ib_warn(dev, "err %d\n", err);
		return err;
	}

	err = create_user_rq(dev, pd, rwq, &ucmd);
	if (err) {
		mlx5_ib_warn(dev, "err %d\n", err);
		return err;
	}

	rwq->user_index = ucmd.user_index;
	return 0;
}

struct ib_wq *mlx5_ib_create_wq(struct ib_pd *pd,
				struct ib_wq_init_attr *init_attr,
				struct ib_udata *udata)
{
	struct mlx5_ib_dev *dev = to_mdev(pd->device);
	struct mlx5_ib_rwq *rwq;
	int err;

	if (!udata) {
		mlx5_ib_warn(dev, "no udata\n");
		return ERR_PTR(-ENOSYS);
	}

	switch (init_attr->wq_type) {
	case IB_WQT_SRQ:
		mlx5_ib_err(dev, "unsupported wq type SRQ\n");
		return ERR_PTR(-ENOSYS);
	case IB_WQT_RQ:
		rwq = kzalloc(sizeof(*rwq), GFP_KERNEL);
		if (!rwq)
			return ERR_PTR(-ENOMEM);
		err = mlx5_ib_prepare_user_rq(pd, init_attr, udata, rwq);
		if (err)
			goto err;
		err = mlx5_ib_create_rq(rwq, pd, init_attr);
		if (err) {
			mlx5_ib_warn(dev, "create RQ failed: %d\n", err);
			goto err_user_rq;
		}
		break;
	default:
		mlx5_ib_warn(dev, "unsupported wq type %d\n",
			     init_attr->wq_type);
		return ERR_PTR(-EINVAL);
	}

	rwq->ibwq.wq_num = rwq->rqn;
	rwq->ibwq.state = IB_WQS_RESET;
	return &rwq->ibwq;

err_user_rq:
	destroy_user_rq(pd, rwq);
err:
	kfree(rwq);
	return ERR_PTR(err);
}

int mlx5_ib_destroy_wq(struct ib_wq *wq)
{
	struct mlx5_ib_rwq *rwq = to_mrwq(wq);
	struct mlx5_ib_dev *dev = to_mdev(wq->device);

	if (wq->wq_type != IB_WQT_RQ)
		return -EINVAL;

	mlx5_core_destroy_rq(dev->mdev, rwq->rqn);
	destroy_user_rq(wq->pd, rwq);
	kfree(rwq);

	return 0;
}

struct ib_rwq_ind_table *mlx5_ib_create_rwq_ind_table(struct ib_device *device,
						      struct ib_rwq_ind_table_init_attr *init_attr,
						      struct ib_udata *udata)
{
	struct mlx5_ib_rwq_ind_table *rwq_ind_tbl;
	struct mlx5_ib_dev *dev;
	int inlen;
	int err;
	int log_tbl_sz = init_attr->log_ind_tbl_size;
	int sz = 1 << log_tbl_sz;
	int i;
	u32 *in;
	void *rqtc;

	if (!udata)
		return ERR_PTR(-ENOSYS);

	dev = to_mdev(device);

	if (init_attr->log_ind_tbl_size >
	    MLX5_CAP_GEN(dev->mdev, log_max_rqt_size)) {
		mlx5_ib_dbg(dev, "log_ind_tbl_size = %d is bigger than supported = %d\n",
			    init_attr->log_ind_tbl_size,
			    MLX5_CAP_GEN(dev->mdev, log_max_rqt_size));
		return ERR_PTR(-EINVAL);
	}

	rwq_ind_tbl = kzalloc(sizeof(*rwq_ind_tbl), GFP_KERNEL);
	if (!rwq_ind_tbl)
		return ERR_PTR(-ENOMEM);

	inlen = MLX5_ST_SZ_BYTES(create_rqt_in) + sizeof(u32) * sz;
	in = mlx5_vzalloc(inlen);
	if (!in) {
		err = -ENOMEM;
		goto err;
	}

	rqtc = MLX5_ADDR_OF(create_rqt_in, in, rqt_context);

	MLX5_SET(rqtc, rqtc, rqt_actual_size, sz);
	MLX5_SET(rqtc, rqtc, rqt_max_size, sz);

	for (i = 0; i < sz; i++)
		MLX5_SET(rqtc, rqtc, rq_num[i], init_attr->ind_tbl[i]->wq_num);

	err = mlx5_core_create_rqt(dev->mdev, in, inlen, &rwq_ind_tbl->rqtn);
	kvfree(in);

	if (err)
		goto err;

	rwq_ind_tbl->ib_rwq_ind_tbl.ind_tbl_num = rwq_ind_tbl->rqtn;
	return &rwq_ind_tbl->ib_rwq_ind_tbl;
err:
	kfree(rwq_ind_tbl);
	return ERR_PTR(err);
}

int mlx5_ib_destroy_rwq_ind_table(struct ib_rwq_ind_table *ib_rwq_ind_tbl)
{
	struct mlx5_ib_dev *dev;
	struct mlx5_ib_rwq_ind_table *rwq_ind_tbl = to_mrwq_ind_table(ib_rwq_ind_tbl);

	dev = to_mdev(ib_rwq_ind_tbl->device);
	mlx5_core_destroy_rqt(dev->mdev, rwq_ind_tbl->rqtn);

	kfree(rwq_ind_tbl);
	return 0;
}

int mlx5_ib_modify_wq(struct ib_wq *wq, struct ib_wq_attr *wq_attr,
		      enum ib_wq_attr_mask attr_mask, struct ib_udata *udata)
{
	struct mlx5_ib_rwq *rwq = to_mrwq(wq);
	struct mlx5_ib_dev *dev = to_mdev(wq->device);
	int wq_state;
	int curr_wq_state;
	void *in;
	void *rqc;
	int inlen;
	int err;

	inlen = MLX5_ST_SZ_BYTES(modify_rq_in);
	in = mlx5_vzalloc(inlen);
	if (!in)
		return -ENOMEM;

	rqc = MLX5_ADDR_OF(modify_rq_in, in, ctx);

	MLX5_SET(modify_rq_in, in, rqn, rwq->rqn);
	curr_wq_state = (attr_mask & IB_WQ_CUR_STATE) ?
		wq_attr->curr_wq_state : wq->state;
	wq_state = (attr_mask & IB_WQ_STATE) ?
		wq_attr->wq_state : curr_wq_state;
	if (curr_wq_state == IB_WQS_ERR)
		curr_wq_state = MLX5_RQC_STATE_ERR;
	if (wq_state == IB_WQS_ERR)
		wq_state = MLX5_RQC_STATE_ERR;
	MLX5_SET(modify_rq_in, in, rq_state, curr_wq_state);
	MLX5_SET(rqc, rqc, state, wq_state);
	if (attr_mask & IB_WQ_VLAN_OFFLOADS) {
		MLX5_SET(modify_rq_in, in, bitmask.vsd, 1);
		if (wq_attr->vlan_offloads & IB_WQ_CVLAN_STRIPPING) {
			if (!(MLX5_CAP_GEN(dev->mdev, eth_net_offloads) &&
			      MLX5_CAP_ETH(dev->mdev, vlan_cap)))
				return -EOPNOTSUPP;
			MLX5_SET(rqc, rqc, vsd, 0);
		} else {
			MLX5_SET(rqc, rqc, vsd, 1);
		}
	}

	err = mlx5_core_modify_rq(dev->mdev, in, inlen);
	kvfree(in);
	if (!err)
		rwq->ibwq.state = (wq_state == MLX5_RQC_STATE_ERR) ? IB_WQS_ERR : wq_state;

	return err;
}
