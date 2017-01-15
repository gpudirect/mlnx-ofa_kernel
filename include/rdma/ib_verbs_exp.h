/*
 * Copyright (c) 2015 Mellanox Technologies Ltd.  All rights reserved.
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

#ifndef IB_VERBS_EXP_H
#define IB_VERBS_EXP_H

#include <rdma/ib_verbs.h>


enum ib_exp_device_cap_flags2 {
	IB_EXP_DEVICE_DC_TRANSPORT		= 1 << 0,
	IB_EXP_DEVICE_QPG			= 1 << 1,
	IB_EXP_DEVICE_UD_RSS			= 1 << 2,
	IB_EXP_DEVICE_UD_TSS			= 1 << 3,
	IB_EXP_DEVICE_EXT_ATOMICS		= 1 << 4,
	IB_EXP_DEVICE_NOP			= 1 << 5,
	IB_EXP_DEVICE_UMR			= 1 << 6,
	IB_EXP_DEVICE_ODP			= 1 << 7,
	IB_EXP_DEVICE_ROCE_MODE_1_5		= 1 << 8,
	IB_EXP_DEVICE_ROCE_MODE_2		= 1 << 9,
	IB_EXP_DEVICE_VXLAN_SUPPORT	        = 1 << 10,
	IB_EXP_DEVICE_RX_CSUM_TCP_UDP_PKT	= 1 << 11,
	IB_EXP_DEVICE_RX_CSUM_IP_PKT		= 1 << 12,
	IB_EXP_DEVICE_EC_OFFLOAD		= 1 << 13,
	IB_EXP_DEVICE_EXT_MASKED_ATOMICS	= 1 << 14,
	IB_EXP_DEVICE_RX_TCP_UDP_PKT_TYPE       = 1 << 15,
	IB_EXP_DEVICE_SCATTER_FCS		= 1 << 16,
	IB_EXP_DEVICE_MEM_WINDOW		= IB_DEVICE_MEM_WINDOW,
	IB_EXP_DEVICE_MEM_MGT_EXTENSIONS	= IB_DEVICE_MEM_MGT_EXTENSIONS,
	/* Jumping to 23 as of next capability in include/rdma/ib_verbs.h */
	/*
	 * Devices can set either IB_DEVICE_MEM_WINDOW_TYPE_2A or
	 * IB_DEVICE_MEM_WINDOW_TYPE_2B if it supports type 2A or type 2B
	 * memory windows. It can set neither to indicate it doesn't support
	 * type 2 windows at all.
	 */
	IB_EXP_DEVICE_MEM_WINDOW_TYPE_2A	= IB_DEVICE_MEM_WINDOW_TYPE_2A,
	IB_EXP_DEVICE_MEM_WINDOW_TYPE_2B	= IB_DEVICE_MEM_WINDOW_TYPE_2B,
	IB_EXP_DEVICE_CROSS_CHANNEL		= IB_DEVICE_CROSS_CHANNEL,
	IB_EXP_DEVICE_MANAGED_FLOW_STEERING	= IB_DEVICE_MANAGED_FLOW_STEERING,
	IB_EXP_DEVICE_MR_ALLOCATE		= IB_DEVICE_MR_ALLOCATE,
	IB_EXP_DEVICE_SHARED_MR			= IB_DEVICE_SHARED_MR,
	IB_EXP_DEVICE_MASK =	IB_EXP_DEVICE_MEM_WINDOW |
				IB_EXP_DEVICE_MEM_MGT_EXTENSIONS |
				IB_EXP_DEVICE_MEM_WINDOW_TYPE_2A |
				IB_EXP_DEVICE_MEM_WINDOW_TYPE_2B |
				IB_EXP_DEVICE_MR_ALLOCATE |
				IB_EXP_DEVICE_SHARED_MR |
				IB_EXP_DEVICE_EC_OFFLOAD |
				IB_EXP_DEVICE_CROSS_CHANNEL |
				IB_EXP_DEVICE_MANAGED_FLOW_STEERING
};

struct ib_exp_umr_caps {
	u32                max_reg_descriptors;
	u32                max_send_wqe_inline_klms;
	u32                max_umr_recursion_depth;
	u32                max_umr_stride_dimenson;
};


struct ib_exp_odp_caps {
	uint64_t	general_odp_caps;
	struct {
		uint32_t	rc_odp_caps;
		uint32_t	uc_odp_caps;
		uint32_t	ud_odp_caps;
		uint32_t	dc_odp_caps;
		uint32_t	xrc_odp_caps;
		uint32_t	raw_eth_odp_caps;
	} per_transport_caps;
};

enum ib_exp_supported_qp_types {
	IB_EXP_QPT_RC		= 1ULL << 0,
	IB_EXP_QPT_UC		= 1ULL << 1,
	IB_EXP_QPT_UD		= 1ULL << 2,
	IB_EXP_QPT_XRC_INIT	= 1ULL << 3,
	IB_EXP_QPT_XRC_TGT	= 1ULL << 4,
	IB_EXP_QPT_RAW_PACKET	= 1ULL << 5,
};

struct ib_exp_rx_hash_caps {
	uint32_t max_rwq_indirection_tables;
	uint32_t max_rwq_indirection_table_size;
	uint8_t  supported_hash_functions; /* from ib_rx_hash_function_flags */
	uint64_t supported_packet_fields;	/* from ib_rx_hash_fields */
	uint32_t supported_qps;  /* from ib_exp_supported_qp_types */
};

struct ib_exp_mp_rq_caps {
	uint32_t supported_qps; /* use ib_exp_supported_qp_types */
	uint32_t allowed_shifts; /* use ib_mp_rq_shifts */
	uint8_t min_single_wqe_log_num_of_strides;
	uint8_t max_single_wqe_log_num_of_strides;
	uint8_t min_single_stride_log_num_of_bytes;
	uint8_t max_single_stride_log_num_of_bytes;
};

struct ib_exp_masked_atomic_caps {
	u32 max_fa_bit_boudary;
	u32 log_max_atomic_inline_arg;
	u64 masked_log_atomic_arg_sizes;
	u64 masked_log_atomic_arg_sizes_network_endianness;
};

enum ib_exp_device_attr_comp_mask {
	IB_EXP_DEVICE_ATTR_WITH_TIMESTAMP_MASK	= 1ULL << 1,
	IB_EXP_DEVICE_ATTR_WITH_HCA_CORE_CLOCK	= 1ULL << 2,
	IB_EXP_DEVICE_ATTR_CAP_FLAGS2		= 1ULL << 3,
	IB_EXP_DEVICE_ATTR_DC_REQ_RD		= 1ULL << 4,
	IB_EXP_DEVICE_ATTR_DC_RES_RD		= 1ULL << 5,
	IB_EXP_DEVICE_ATTR_INLINE_RECV_SZ	= 1ULL << 6,
	IB_EXP_DEVICE_ATTR_RSS_TBL_SZ		= 1ULL << 7,
	IB_EXP_DEVICE_ATTR_EXT_ATOMIC_ARGS	= 1ULL << 8,
	IB_EXP_DEVICE_ATTR_UMR                  = 1ULL << 9,
	IB_EXP_DEVICE_ATTR_ODP			= 1ULL << 10,
	IB_EXP_DEVICE_ATTR_MAX_DCT		= 1ULL << 11,
	IB_EXP_DEVICE_ATTR_MAX_CTX_RES_DOMAIN	= 1ULL << 12,
	IB_EXP_DEVICE_ATTR_RX_HASH		= 1ULL << 13,
	IB_EXP_DEVICE_ATTR_MAX_WQ_TYPE_RQ	= 1ULL << 14,
	IB_EXP_DEVICE_ATTR_MAX_DEVICE_CTX	= 1ULL << 15,
	IB_EXP_DEVICE_ATTR_MP_RQ		= 1ULL << 16,
	IB_EXP_DEVICE_ATTR_VLAN_OFFLOADS	= 1ULL << 17,
	IB_EXP_DEVICE_ATTR_EC_CAPS		= 1ULL << 18,
	IB_EXP_DEVICE_ATTR_EXT_MASKED_ATOMICS	= 1ULL << 19,
	IB_EXP_DEVICE_ATTR_RX_PAD_END_ALIGN	= 1ULL << 20,
	IB_EXP_DEVICE_ATTR_TSO_CAPS		= 1ULL << 21,
	IB_EXP_DEVICE_ATTR_PACKET_PACING_CAPS	= 1ULL << 22,
};

struct ib_exp_ec_caps {
	uint32_t	max_ec_data_vector_count;
	uint32_t	max_ec_calc_inflight_calcs;
};

struct ib_exp_tso_caps {
	__u32 max_tso; /* Maximum tso payload size in bytes */

	/* Corresponding bit will be set if qp type from
	 * 'enum ib_qp_type' is supported, e.g.
	 * supported_qpts |= 1 << IB_QPT_RAW_PACKET
	 */
	__u32 supported_qpts;
};

struct ib_exp_packet_pacing_caps {
	__u32 qp_rate_limit_min;
	__u32 qp_rate_limit_max; /* In kpbs */

	/* Corresponding bit will be set if qp type from
	 * 'enum ib_qp_type' is supported, e.g.
	 * supported_qpts |= 1 << IB_QPT_RAW_PACKET
	 */
	__u32 supported_qpts;
	__u32 reserved;
};

struct ib_exp_device_attr {
	struct ib_device_attr	base;
	/* Use IB_EXP_DEVICE_ATTR_... for exp_comp_mask */
	uint32_t		exp_comp_mask;
	uint64_t		device_cap_flags2;
	uint32_t		dc_rd_req;
	uint32_t		dc_rd_res;
	uint32_t		inline_recv_sz;
	uint32_t		max_rss_tbl_sz;
	/*
	 * This field is a bit mask for the supported atomic argument sizes.
	 * A bit set signifies an argument of size of 2 ^ bit_nubmer bytes is
	 * supported.
	 * Defines which masked operation sizes are supported with same
	 * endianness as stated in atomic_cap field.
	 */
	u64				atomic_arg_sizes;
	u32				max_fa_bit_boudary;
	u32				log_max_atomic_inline_arg;
	struct ib_exp_umr_caps		umr_caps;
	struct ib_exp_odp_caps		odp_caps;
	uint32_t			max_dct;
	uint32_t			max_ctx_res_domain;
	struct ib_exp_rx_hash_caps	rx_hash_caps;
	uint32_t			max_wq_type_rq;
	uint32_t			max_device_ctx;
	struct ib_exp_mp_rq_caps	mp_rq_caps;
	u16				vlan_offloads;
	struct ib_exp_ec_caps   	ec_caps;
	struct ib_exp_masked_atomic_caps masked_atomic_caps;
	/*
	 * The alignment of the padding end address.
	 * Which means that when RX end of packet padding is enabled the device
	 * will padd the end of RX packet up until the next address which is
	 * aligned to the rx_pad_end_addr_align size.
	 */
	u16				rx_pad_end_addr_align;
	struct ib_exp_tso_caps		tso_caps;
	struct ib_exp_packet_pacing_caps packet_pacing_caps;
};

struct ib_exp_qp_init_attr {
	void                  (*event_handler)(struct ib_event *, void *);
	void		       *qp_context;
	struct ib_cq	       *send_cq;
	struct ib_cq	       *recv_cq;
	struct ib_srq	       *srq;
	struct ib_xrcd	       *xrcd;     /* XRC TGT QPs only */
	struct ib_qp_cap	cap;
	union {
		struct ib_qp *qpg_parent; /* see qpg_type */
		struct ib_qpg_init_attrib parent_attrib;
	};
	enum ib_sig_type	sq_sig_type;
	enum ib_qp_type		qp_type;
	enum ib_qp_create_flags	create_flags;
	enum ib_qpg_type	qpg_type;
	u8			port_num; /* special QP types only */
	u32			max_inl_recv;
	struct ib_rx_hash_conf	*rx_hash_conf;
};


int ib_exp_query_device(struct ib_device *device,
			struct ib_exp_device_attr *device_attr);


enum ib_exp_mr_rereg_flags {
	IB_EXP_MR_REREG_TRANS		= IB_MR_REREG_TRANS,
	IB_EXP_MR_REREG_PD		= IB_MR_REREG_PD,
	IB_EXP_MR_REREG_ACCESS		= IB_MR_REREG_ACCESS,
	IB_EXP_MR_REREG_SUPPORTED	= ((IB_EXP_MR_REREG_ACCESS << 1) - 1)
};


#endif /* IB_VERBS_EXP_H */
