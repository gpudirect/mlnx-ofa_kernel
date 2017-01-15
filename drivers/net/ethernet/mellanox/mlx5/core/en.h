/*
 * Copyright (c) 2015, Mellanox Technologies. All rights reserved.
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
#ifndef __MLX5_EN_H__
#define __MLX5_EN_H__

#include <linux/if_vlan.h>
#include <linux/etherdevice.h>
#include <linux/timecounter.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/net_tstamp.h>
#include <linux/hashtable.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/device.h>
#include <linux/mlx5/qp.h>
#include <linux/mlx5/cq.h>
#include <linux/mlx5/transobj.h>
#include "linux/mlx5/vport.h"
#include "wq.h"
#include "mlx5_core.h"
#include "en_stats.h"
#include <linux/mlx5/fs.h>

#define MLX5E_MAX_NUM_TC	8
#define MLX5E_MAX_NUM_PRIO	8
#define MLX5E_MIN_NUM_PRIO	0
#define MLX5E_MAX_MTU		9600
#define MXL5_HW_MIN_MTU		64
#define MXL5E_MIN_MTU		(MXL5_HW_MIN_MTU + ETH_FCS_LEN)

#define MLX5E_PARAMS_MINIMUM_LOG_SQ_SIZE                0x7
#define MLX5E_PARAMS_DEFAULT_LOG_SQ_SIZE                0xa
#define MLX5E_PARAMS_MAXIMUM_LOG_SQ_SIZE                0xd
#define MLX5E_PARAMS_MINIMUM_LOG_STRIDING_RQ_SIZE	0x1
#define MLX5E_PARAMS_DEFAULT_LOG_STRIDING_RQ_SIZE	0x4
#define MLX5E_PARAMS_MAXIMUM_LOG_STRIDING_RQ_SIZE	0x7
#define MLX5E_PARAMS_DEFAULT_LOG_WQE_STRIDE_SIZE	7
#define MLX5E_PARAMS_DEFAULT_LOG_WQE_NUM_STRIDES	10
#define MLX5E_PARAMS_DEFAULT_MIN_STRIDING_RX_WQES	4
#define MLX5E_PARAMS_STRIDING_MTU			1500
#define MLX5E_PARAMS_MPWQE_LOG_WQE_SIZE			\
				(MLX5E_PARAMS_DEFAULT_LOG_WQE_STRIDE_SIZE + \
				 MLX5E_PARAMS_DEFAULT_LOG_WQE_NUM_STRIDES)
#define MLX5_MPWRQ_WQE_PAGE_ORDER			\
			(MLX5E_PARAMS_MPWQE_LOG_WQE_SIZE - PAGE_SHIFT > 0 ? \
			 MLX5E_PARAMS_MPWQE_LOG_WQE_SIZE - PAGE_SHIFT : 0)
#define MLX5_MPWRQ_PAGES_PER_WQE	BIT(MLX5_MPWRQ_WQE_PAGE_ORDER)
#define MLX5_MPWRQ_MTTS_PER_WQE		ALIGN(MLX5_MPWRQ_PAGES_PER_WQE, 8)
#define MLX5_CHANNEL_MAX_NUM_MTTS			\
			(MLX5_MPWRQ_MTTS_PER_WQE *	\
			 BIT(MLX5E_PARAMS_MAXIMUM_LOG_STRIDING_RQ_SIZE))
#define MLX5_UMR_ALIGN				(2048)

#define MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE                0x7
#define MLX5E_PARAMS_DEFAULT_LOG_RQ_SIZE                0xa
#define MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE                0xd

#define MLX5E_PARAMS_DEFAULT_LRO_WQE_SZ                 (63 * 1024)
#define MLX5E_DEFAULT_LRO_TIMEOUT                       32
#define MLX5E_LRO_TIMEOUT_ARR_SIZE                      4

#define MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC      0x10
#define MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_USEC_FROM_CQE	0x8
#define MLX5E_PARAMS_DEFAULT_RX_CQ_MODERATION_PKTS      0x20
#define MLX5E_PARAMS_DEFAULT_TX_CQ_MODERATION_USEC      0x10
#define MLX5E_PARAMS_DEFAULT_TX_CQ_MODERATION_PKTS      0x20
#define MLX5E_PARAMS_DEFAULT_MIN_RX_WQES                0x80

#define MLX5E_RSS_TOEPLITZ_KEY_SIZE	MLX5_FLD_SZ_BYTES(tirc, \
							  rx_hash_toeplitz_key)
#define MLX5E_LOG_INDIR_RQT_SIZE       0x7
#define MLX5E_INDIR_RQT_SIZE           BIT(MLX5E_LOG_INDIR_RQT_SIZE)
#define MLX5E_MAX_NUM_CHANNELS         (MLX5E_INDIR_RQT_SIZE >> 1)
#define MLX5E_MAX_NUM_SQS              (MLX5E_MAX_NUM_CHANNELS * MLX5E_MAX_NUM_TC)
#define MLX5E_MAX_RL_QUEUES            2048
#define MLX5E_TX_CQ_POLL_BUDGET        128
#define MLX5E_UPDATE_STATS_INTERVAL    200 /* msecs */
#define MLX5E_SQ_BF_BUDGET             16
#define MLX5E_SERVICE_TASK_DELAY       (HZ / 4)

#define MLX5E_INDICATE_WQE_ERR	       0xffff
#define MLX5E_MSG_LEVEL                NETIF_MSG_LINK

#define mlx5e_dbg(mlevel, priv, format, ...)                    \
do {                                                            \
	if (NETIF_MSG_##mlevel & (priv)->msg_level)             \
		netdev_warn(priv->netdev, format,               \
			    ##__VA_ARGS__);                     \
} while (0)

#define MLX5_SET_CFG(p, f, v) MLX5_SET(create_flow_group_in, p, f, v)

enum {
	MLX5E_LINK_SPEED,
	MLX5E_LINK_STATE,
	MLX5E_HEALTH_INFO,
	MLX5E_LOOPBACK,
	MLX5E_INTERRUPT,
	MLX5E_NUM_SELF_TEST,
};

enum {
	MLX5E_CON_PROTOCOL_802_1_RP,
	MLX5E_CON_PROTOCOL_R_ROCE_RP,
	MLX5E_CON_PROTOCOL_R_ROCE_NP,
	MLX5E_CONG_PROTOCOL_NUM,
};

#define HEADER_COPY_SIZE		(128 - NET_IP_ALIGN)
#define MLX5E_LOOPBACK_TEST_PAYLOAD	(HEADER_COPY_SIZE - ETH_HLEN)

#define MLX5E_MAX_BW_ALLOC 100 /* Max percentage of BW allocation */

struct mlx5e_cq_moder {
	u16 usec;
	u16 pkts;
};

struct mlx5e_params {
	u8  log_sq_size;
	u8  log_rq_size;
	u16 num_channels;
	u8  default_vlan_prio;
	u8  num_tc;
	u8  rx_cq_period_mode;
	u16 num_rl_txqs;
	struct mlx5e_cq_moder rx_cq_moderation;
	struct mlx5e_cq_moder tx_cq_moderation;
	u16 min_rx_wqes;
	bool lro_en;
	u32 lro_wqe_sz;
	u8  rss_hfunc;
	u8 toeplitz_hash_key[MLX5E_RSS_TOEPLITZ_KEY_SIZE];
	u32 indirection_rqt[MLX5E_INDIR_RQT_SIZE];
	u32 lro_timeout;
	bool rx_am_enabled;
};

enum {
	MLX5E_RQ_STATE_ACTIVE,
	MLX5E_RQ_STATE_UMR_WQE_IN_PROGRESS,
	MLX5E_RQ_STATE_AM,
};

struct mlx5e_rq;
struct mlx5e_rx_wqe;
struct mlx5e_cq;
typedef void (*mlx5e_clean_rq_fn)(struct mlx5e_rq *rq);
typedef int (*mlx5e_alloc_rx_wqe_fn)(struct mlx5e_rq *rq,
				     struct mlx5e_rx_wqe *wqe, u16 ix);
typedef void (*mlx5e_dealloc_rx_wqe_fn)(struct mlx5e_rq *rq, u16 ix);
/* poll rx cq is depend on the type of the RQ */
typedef struct sk_buff* (*mlx5e_poll_rx_cq_fn)(struct mlx5_cqe64 *cqe,
						   struct mlx5e_rq *rq,
						   u16 *bytes_recv,
						   struct mlx5e_rx_wqe **ret_wqe,
						   __be16 *ret_wqe_id_be);
typedef bool (*mlx5e_is_rx_pop_fn)(struct mlx5e_rq *rq);

struct mlx5e_dma_info {
	struct page     *page;
	dma_addr_t      addr;
};

struct mlx5e_umr_dma_info {
	__be64                *mtt;
	__be64                *mtt_no_align;
	dma_addr_t             mtt_addr;
	struct mlx5e_dma_info *dma_info;
};

struct mlx5e_umr_wqe {
	struct mlx5_wqe_ctrl_seg       ctrl;
	struct mlx5_wqe_umr_ctrl_seg   uctrl;
	struct mlx5_mkey_seg           mkc;
	struct mlx5_wqe_data_seg       data;
};

struct mlx5e_rx_wqe_info {
	union {
		struct mlx5e_dma_info     dma_info;
		struct mlx5e_umr_dma_info umr;
	};
	u16 skbs_frags[MLX5_MPWRQ_PAGES_PER_WQE];
	u16 used_strides;

	void (*dma_pre_sync)(struct device *pdev,
			     struct mlx5e_rx_wqe_info *wi,
			     u32 wqe_offset, u32 len);
	u32  (*add_skb_frag)(struct mlx5e_rq *rq,
			     struct sk_buff *skb,
			     struct mlx5e_rx_wqe_info *wi,
			     u32 page_idx, u32 frag_offset, u32 len);
	void (*copy_skb_header)(struct device *pdev,
				struct sk_buff *skb,
				struct mlx5e_rx_wqe_info *wi,
				u32 page_idx, u32 offset,
				u32 headlen);
	void (*free_wqe)(struct mlx5e_rq *rq, struct mlx5e_rx_wqe_info *wi);
};

struct mlx5e_cq {
	/* data path - accessed per cqe */
	struct mlx5_cqwq           wq;

	/* data path - accessed per napi poll */
	u16			   event_ctr;
	struct napi_struct        *napi;
	struct mlx5_core_cq        mcq;
	struct mlx5e_channel      *channel;

	/* control */
	struct mlx5_wq_ctrl        wq_ctrl;
} ____cacheline_aligned_in_smp;

static const char mlx5e_priv_flags[][ETH_GSTRING_LEN] = {
	/* to be added in future commits */
	"hw_lro",
	"sniffer",
	"dcbx_handle_by_fw",
	"qos_with_dcbx_by_fw",
	"rx_cqe_moder",
};

struct mlx5e_rx_am_stats {
	int ppms; /* packets per msec */
	int epms; /* events per msec */
};

struct mlx5e_rx_am_sample {
	ktime_t		time;
	unsigned int	pkt_ctr;
	u16		event_ctr;
};

struct mlx5e_rx_am { /* Adaptive Moderation */
	u8				state;
	struct mlx5e_rx_am_stats	prev_stats;
	struct mlx5e_rx_am_sample	start_sample;
	struct work_struct		work;
	u8				profile_ix;
	u8				mode;
	u8				tune_state;
	u8				steps_right;
	u8				steps_left;
	u8				tired;
};

struct mlx5e_rq {
	/* data path */
	struct mlx5_wq_ll      wq;
	u32                    wqe_sz;
	struct sk_buff       **skb;
	struct mlx5e_rx_wqe_info *wqe_info;
	__be32                 mkey_be;
	struct mlx5_core_mr   *umr_mr;
	__be32                 umr_mkey_be;
	u16		       num_of_strides_in_wqe;
	u16		       stride_size;
	u16		       current_wqe;
	mlx5e_alloc_rx_wqe_fn  alloc_wqe;
	mlx5e_dealloc_rx_wqe_fn dealloc_wqe;
	mlx5e_poll_rx_cq_fn    mlx5e_poll_specific_rx_cq;
	mlx5e_is_rx_pop_fn     is_poll;
	struct device         *pdev;
	struct net_device     *netdev;
	struct mlx5e_rq_stats  stats;
	struct mlx5e_cq        cq;

	unsigned long          state;
	int                    ix;

	struct mlx5e_rx_am     am; /* Adaptive Moderation */

	/* control */
	struct mlx5_wq_ctrl    wq_ctrl;
	u32                    rqn;
	struct mlx5e_channel  *channel;
	enum rq_type	       rq_type;
	mlx5e_clean_rq_fn      clean_rq;
} ____cacheline_aligned_in_smp;

struct mlx5e_tx_wqe_info {
	u32 num_bytes;
	u8  num_wqebbs;
	u8  num_dma;
};

enum mlx5e_dma_map_type {
	MLX5E_DMA_MAP_SINGLE,
	MLX5E_DMA_MAP_PAGE
};

struct mlx5e_sq_dma {
	dma_addr_t              addr;
	u32                     size;
	enum mlx5e_dma_map_type type;
};

enum {
	MLX5E_SQ_STATE_WAKE_TXQ_ENABLE,
	MLX5E_SQ_TX_TIMEOUT,
};

struct mlx5e_sq_flow_map {
	struct hlist_node hlist;
	u32               dst_ip;
	u16               dst_port;
	u16               queue_index;
};

struct mlx5e_ico_wqe_info {
	u8  opcode;
	u8  num_wqebbs;
};

struct mlx5e_sq {
	/* data path */

	/* dirtied @completion */
	u16                        cc;
	u32                        dma_fifo_cc;

	/* dirtied @xmit */
	u16                        pc ____cacheline_aligned_in_smp;
	u32                        dma_fifo_pc;
	u16                        bf_offset;
	u16                        prev_cc;
	u8                         bf_budget;
	struct mlx5e_sq_stats      stats;

	struct mlx5e_cq            cq;

	/* pointers to per packet info: write@xmit, read@completion */
	struct sk_buff           **skb;
	struct mlx5e_sq_dma       *dma_fifo;
	struct mlx5e_tx_wqe_info  *wqe_info;

	/* read only */
	struct mlx5_wq_cyc         wq;
	u32                        dma_fifo_mask;
	void __iomem              *uar_map;
	void __iomem              *uar_bf_map;
	struct netdev_queue       *txq;
	u32                        sqn;
	u16                        bf_buf_size;
	u16                        max_inline;
	u16                        edge;
	struct device             *pdev;
	__be32                     mkey_be;
	unsigned long              state;

	/* control path */
	struct mlx5_wq_ctrl        wq_ctrl;
	struct mlx5_uar            uar;
	struct mlx5e_channel      *channel;
	int                        tc;
	int                        tx_ind;
	u32                        rate_limit;
	struct mlx5e_sq_flow_map   flow_map;
	struct mlx5e_ico_wqe_info *ico_wqe_info;
} ____cacheline_aligned_in_smp;

static inline bool mlx5e_sq_has_room_for(struct mlx5e_sq *sq, u16 n)
{
	return (((sq->wq.sz_m1 & (sq->cc - sq->pc)) >= n) ||
		(sq->cc  == sq->pc));
}

enum channel_flags {
	MLX5E_CHANNEL_NAPI_SCHED = 1,
};

struct mlx5e_channel {
	/* data path */
	struct mlx5e_rq            rq;
	struct mlx5e_sq           *sq;
	struct mlx5e_sq            icosq;   /* internal control operations */
	struct napi_struct         napi;
	struct device             *pdev;
	struct net_device         *netdev;
	__be32                     mkey_be;
	u8                         num_tc;
	unsigned long              flags;

	/* data path - accessed per napi poll */
	struct irq_desc           *irq_desc;

	/* control */
	struct mlx5e_priv         *priv;
	int                        ix;
	int                        num_tx;
	int                        cpu;

	struct dentry             *dfs_root;
};

enum mlx5e_traffic_types {
	MLX5E_TT_IPV4_TCP,
	MLX5E_TT_IPV6_TCP,
	MLX5E_TT_IPV4_UDP,
	MLX5E_TT_IPV6_UDP,
	MLX5E_TT_IPV4_IPSEC_AH,
	MLX5E_TT_IPV6_IPSEC_AH,
	MLX5E_TT_IPV4_IPSEC_ESP,
	MLX5E_TT_IPV6_IPSEC_ESP,
	MLX5E_TT_IPV4,
	MLX5E_TT_IPV6,
	MLX5E_TT_ANY,
	MLX5E_NUM_TT
};

static inline bool mlx5e_tunnel_stateless_supported(struct mlx5_core_dev *mdev)
{
	return (MLX5_CAP_ETH(mdev, tunnel_stateless_vxlan) ||
		MLX5_CAP_ETH(mdev, tunnel_statless_gre));
}

enum {
	MLX5E_RQT_SPREADING  = 0,
	MLX5E_RQT_DEFAULT_RQ = 1,
	MLX5E_NUM_RQT        = 2,
};

enum {
	MLX5E_RQ_FLAG_SWLRO = (1 << 0),
	MLX5E_PRIV_FLAGS_SNIFFER_EN = (1 << 1),
	MLX5E_PRIV_FLAGS_DCBX_HANDLE_BY_FW   = (1 << 2),
	MLX5E_PRIV_FLAGS_QOS_WITH_DCBX_BY_FW = (1 << 3),
	MLX5E_PRIV_FLAGS_RX_CQE_BASED_MODER = (1 << 4),
};

enum {
	MAX_SNIFFER_FLOW_RULE_NUM = (FS_MAX_TYPES << 4),
};

enum mlx5e_sniffer_types {
	MLX5E_SNIFFER_TX,
	MLX5E_SNIFFER_RX,
	MLX5E_LEFTOVERS_RX,
	MLX5E_SNIFFER_NUM_TYPE,
};

struct mlx5_sniffer_rule_info {
	struct mlx5_core_fs_mask *fg_mask;
	u32 *fte_match_value;
	int rule_type;
};

struct sniffer_work {
	struct work_struct  work;
	struct mlx5_sniffer_rule_info *rule_info;
	struct mlx5e_priv  *priv;
};

struct mlx5e_sniffer_flow {
	struct mlx5_flow_rule *rx_dst;
	bool valid;
	u8 ref_cnt;
};

struct mlx5e_flow_sniffer {
	struct workqueue_struct *sniffer_wq;

	struct mlx5_flow_table *rx_ft;
	struct mlx5_flow_table *tx_ft;
	struct mlx5_flow_table *leftovers_ft;
	struct mlx5e_sniffer_flow flow_arr[MAX_SNIFFER_FLOW_RULE_NUM];
	struct mlx5_flow_rule *tx_dst;
	struct mlx5e_sniffer_flow leftovers_flow_arr[LEFTOVERS_RULE_NUM];
	struct mlx5_flow_handler *bypass_event;
};

struct mlx5e_eth_ft_type {
	struct mlx5_core_fs_dst *dst;
};

struct mlx5e_l2_rule {
	u8			addr[ETH_ALEN + 2];
	struct mlx5_flow_rule   *rule;
};

struct mlx5e_flow_vlan {
	struct mlx5_core_fs_ft		*vlan_ft;
	struct mlx5_core_fs_fg		*tagged_fg;
	struct mlx5_core_fs_fg		*untagged_fg;
};

struct mlx5e_flow_main {
	struct mlx5_core_fs_ft		*main_ft;
	struct mlx5_core_fs_fg		*fg[9];
};

#define MLX5E_L2_ADDR_HASH_SIZE (1 << BITS_PER_BYTE)

struct mlx5e_flow_table {
	int num_groups;
	struct mlx5_flow_table *t;
	struct mlx5_flow_group **g;
};

struct mlx5e_l2_table {
	struct mlx5e_flow_table	   ft;
	struct hlist_head          netdev_uc[MLX5E_L2_ADDR_HASH_SIZE];
	struct hlist_head          netdev_mc[MLX5E_L2_ADDR_HASH_SIZE];
	struct mlx5e_l2_rule   broadcast;
	struct mlx5e_l2_rule   allmulti;
	struct mlx5e_l2_rule   promisc;
	bool                       broadcast_enabled;
	bool                       allmulti_enabled;
	bool                       promisc_enabled;
};

enum {
	MLX5E_STATE_ASYNC_EVENTS_ENABLE,
	MLX5E_STATE_OPENED,
};

enum {
	MLX5E_WOL_DISABLE	= 0,
	MLX5E_WOL_SECURED_MAGIC = 1 << 1,
	MLX5E_WOL_MAGIC		= 1 << 2,
	MLX5E_WOL_ARP		= 1 << 3,
	MLX5E_WOL_BROADCAST	= 1 << 4,
	MLX5E_WOL_MULTICAST	= 1 << 5,
	MLX5E_WOL_UNICAST	= 1 << 6,
	MLX5E_WOL_PHY_ACTIVITY	= 1 << 7,
};

enum mlx5e_tunnel_rule_type {
	MLX5E_TUNNEL_RULE_TYPE_VXLAN,
};

struct mlx5e_vlan_table {
	struct mlx5e_flow_table ft;
	unsigned long active_vlans[BITS_TO_LONGS(VLAN_N_VID)];
	struct mlx5_flow_rule	*active_vlans_rule[VLAN_N_VID];
	struct mlx5_flow_rule	*untagged_rule;
	struct mlx5_flow_rule	*any_svlan_rule;
	struct mlx5_flow_rule	*any_cvlan_rule;
	bool			filter_disabled;
};

struct mlx5e_vxlan_db {
	spinlock_t		lock;
	struct radix_tree_root	tree;
};

struct mlx5e_ttc_table {
	struct mlx5e_flow_table ft;
	struct mlx5_flow_rule	*flow_rules[MLX5E_NUM_TT];
};

#define ARFS_HASH_SHIFT BITS_PER_BYTE
#define ARFS_HASH_SIZE BIT(BITS_PER_BYTE)
struct arfs_table {
	struct mlx5e_flow_table  ft;
	struct mlx5_flow_rule    *default_rule;
	struct hlist_head	 rules_hash[ARFS_HASH_SIZE];
};

enum  arfs_type {
	ARFS_IPV4_TCP,
	ARFS_IPV6_TCP,
	ARFS_IPV4_UDP,
	ARFS_IPV6_UDP,
	ARFS_NUM_TYPES,
};

struct mlx5e_arfs_tables {
	struct arfs_table arfs_tables[ARFS_NUM_TYPES];
	/* Protect aRFS rules list */
	spinlock_t                     arfs_lock;
	struct list_head               rules;
	int                            last_filter_id;
	struct workqueue_struct        *wq;
};

/* NIC prio FTS */
enum {
	MLX5E_VLAN_FT_LEVEL = 0,
	MLX5E_L2_FT_LEVEL,
	MLX5E_OUTER_TTC_FT_LEVEL,
	MLX5E_INNER_TTC_FT_LEVEL,
	MLX5E_ARFS_FT_LEVEL
};

struct mlx5e_flow_steering {
	struct mlx5_flow_namespace	*ns;
	struct mlx5e_vlan_table		vlan;
	struct mlx5e_l2_table		l2;
	struct mlx5e_ttc_table          outer_ttc;
	struct mlx5e_ttc_table		inner_ttc;
	struct mlx5e_arfs_tables        arfs;
	struct mlx5e_flow_sniffer	sniffer;
};

struct mlx5e_ecn_rp_attributes {
	struct mlx5_core_dev	*mdev;
	/* ATTRIBUTES */
	struct kobj_attribute	enable;
	struct kobj_attribute	clamp_tgt_rate;
	struct kobj_attribute	clamp_tgt_rate_ati;
	struct kobj_attribute	rpg_time_reset;
	struct kobj_attribute	rpg_byte_reset;
	struct kobj_attribute	rpg_threshold;
	struct kobj_attribute	rpg_max_rate;
	struct kobj_attribute	rpg_ai_rate;
	struct kobj_attribute	rpg_hai_rate;
	struct kobj_attribute	rpg_gd;
	struct kobj_attribute	rpg_min_dec_fac;
	struct kobj_attribute	rpg_min_rate;
	struct kobj_attribute	rate2set_fcnp;
	struct kobj_attribute	dce_tcp_g;
	struct kobj_attribute	dce_tcp_rtt;
	struct kobj_attribute	rreduce_mperiod;
	struct kobj_attribute	initial_alpha_value;
};

struct mlx5e_ecn_np_attributes {
	struct mlx5_core_dev	*mdev;
	/* ATTRIBUTES */
	struct kobj_attribute	enable;
	struct kobj_attribute	min_time_between_cnps;
	struct kobj_attribute	cnp_dscp;
	struct kobj_attribute	cnp_802p_prio;
};

union mlx5e_ecn_attributes {
	struct mlx5e_ecn_rp_attributes rp_attr;
	struct mlx5e_ecn_np_attributes np_attr;
};

struct mlx5e_ecn_ctx {
	union mlx5e_ecn_attributes ecn_attr;
	struct kobject *ecn_proto_kobj;
	struct kobject *ecn_enable_kobj;
};

struct mlx5e_ecn_enable_ctx {
	int cong_protocol;
	int priority;
	struct mlx5_core_dev	*mdev;

	struct kobj_attribute	enable;
};

#define MLX5E_NIC_DEFAULT_PRIO	0

struct mlx5e_tstamp {
	rwlock_t                   lock;
	struct cyclecounter        cycles;
	struct timecounter         clock;
	struct ptp_clock          *ptp;
	struct ptp_clock_info      ptp_info;
	struct hwtstamp_config     hwtstamp_config;
	u32                        nominal_c_mult;
	unsigned long              last_overflow_check;
	unsigned long              overflow_period;
};

struct mlx5e_direct_tir {
	u32              tirn;
	u32              rqtn;
};

struct mlx5e_cee_config {
	/* bw pct for priority group */
	u8                         pg_bw_pct[CEE_DCBX_MAX_PGS];
	u8                         prio_to_pg_map[CEE_DCBX_MAX_PRIO];
	bool                       pfc_setting[CEE_DCBX_MAX_PRIO];
	bool                       pfc_enable;
};

struct mlx5e_dcbx {
	enum mlx5_dcbx_oper_mode   mode;
	struct mlx5e_cee_config    cee_cfg; /* pending configuration */

	/* The only setting that cannot be read from FW */
	u8                         tc_tsa[IEEE_8021QAZ_MAX_TCS];
};

struct mlx5e_priv {
	/* priv data path fields - start */
	int                        default_vlan_prio;
	struct mlx5e_sq            **txq_to_sq_map;
	int tc_to_txq_map[MLX5E_MAX_NUM_CHANNELS][MLX5E_MAX_NUM_TC];
	DECLARE_HASHTABLE(flow_map_hash, ilog2(MLX5E_MAX_RL_QUEUES));
	/* priv data path fields - end */

	unsigned long              state;
	struct mutex               state_lock; /* Protects Interface state */
	struct mlx5_uar            cq_uar;
	u32                        pdn;
	u32                        tdn;
	struct mlx5_core_mr        mr;

	struct mlx5e_channel     **channel;
	u32                        tisn[MLX5E_MAX_NUM_TC];
	u32                        indir_rqtn;


	struct mlx5e_direct_tir    outer_direct_tir[MLX5E_MAX_NUM_CHANNELS];
	u32                        outer_tirn[MLX5E_NUM_TT];
	u32                        inner_tirn[MLX5E_NUM_TT];
	u32                        sniffer_tirn[MLX5E_SNIFFER_NUM_TYPE];
	u32                        tx_rates[MLX5E_MAX_NUM_SQS + MLX5E_MAX_RL_QUEUES];

	struct mlx5e_vxlan_db      vxlan;
	struct mlx5e_flow_steering fs;
	bool                       loopback_ok;
	bool                       validate_loopback;

	struct mlx5e_params        params;
	spinlock_t                 async_events_spinlock; /* sync hw events */
	struct workqueue_struct    *wq;
	struct work_struct         update_carrier_work;
	struct work_struct         set_rx_mode_work;
	struct work_struct         tx_timeout_work;
	struct delayed_work        update_stats_work;
	struct delayed_work        service_task;

	struct mlx5e_dcbx          dcbx;

	struct mlx5_core_dev      *mdev;
	struct {
		__u32 flag;
		u32 mst_size;
	} dump;
	struct net_device         *netdev;
	struct mlx5e_stats         stats;
	struct mlx5e_tstamp        tstamp;
	u32                        pflags;
	u16                        counter_set_id;

	struct dentry *dfs_root;
	u32 msg_level;

	struct kobject *ecn_root_kobj;

	struct mlx5e_ecn_ctx ecn_ctx[MLX5E_CONG_PROTOCOL_NUM];
	struct mlx5e_ecn_enable_ctx ecn_enable_ctx[MLX5E_CONG_PROTOCOL_NUM][8];
	int			   internal_error;
};

#define MLX5E_NET_IP_ALIGN 2

struct mlx5e_tx_wqe {
	struct mlx5_wqe_ctrl_seg ctrl;
	struct mlx5_wqe_eth_seg  eth;
};

struct mlx5e_rx_wqe {
	struct mlx5_wqe_srq_next_seg  next;
	struct mlx5_wqe_data_seg      data;
};

static inline u16 mlx5_min_rx_wqes(int wq_type, u32 wq_size)
{
	if (wq_type == RQ_TYPE_STRIDE)
		return min_t(u16, MLX5E_PARAMS_DEFAULT_MIN_STRIDING_RX_WQES,
			     wq_size / 2);

	return min_t(u16, MLX5E_PARAMS_DEFAULT_MIN_RX_WQES,
		     wq_size / 2);
}

static inline int mlx5_min_log_rq_size(int wq_type)
{
	if (wq_type == RQ_TYPE_STRIDE)
		return MLX5E_PARAMS_MINIMUM_LOG_STRIDING_RQ_SIZE;

	return MLX5E_PARAMS_MINIMUM_LOG_RQ_SIZE;
}

static inline int mlx5_max_log_rq_size(int wq_type)
{
	if (wq_type == RQ_TYPE_STRIDE)
		return MLX5E_PARAMS_MAXIMUM_LOG_STRIDING_RQ_SIZE;

	return MLX5E_PARAMS_MAXIMUM_LOG_RQ_SIZE;
}

void mlx5e_send_nop(struct mlx5e_sq *sq, bool notify_hw);
u16 mlx5e_select_queue(struct net_device *dev, struct sk_buff *skb,
		       void *accel_priv, select_queue_fallback_t fallback);
netdev_tx_t mlx5e_xmit(struct sk_buff *skb, struct net_device *dev);

void mlx5e_completion_event(struct mlx5_core_cq *mcq);
void mlx5e_cq_error_event(struct mlx5_core_cq *mcq, enum mlx5_event event);
int mlx5e_napi_poll(struct napi_struct *napi, int budget);
bool mlx5e_poll_tx_cq(struct mlx5e_cq *cq);
void mlx5e_free_tx_descs(struct mlx5e_sq *sq);
struct sk_buff *mlx5e_poll_default_rx_cq(struct mlx5_cqe64 *cqe,
					 struct mlx5e_rq *rq,
					 u16 *ret_bytes_recv,
					 struct mlx5e_rx_wqe **ret_wqe,
					 __be16 *ret_wqe_id_be);
struct sk_buff *mlx5e_poll_striding_rx_cq(struct mlx5_cqe64 *cqe,
					  struct mlx5e_rq *rq,
					  u16 *ret_bytes_recv,
					  struct mlx5e_rx_wqe **ret_wqe,
					  __be16 *ret_wqe_id_be);
bool mlx5e_poll_rx_cq(struct mlx5e_cq *cq, int budget);
bool is_poll_striding_wqe(struct mlx5e_rq *rq);
void free_rq_res(struct mlx5e_rq *rq);
void free_striding_rq_res(struct mlx5e_rq *rq);
int mlx5e_alloc_rx_wqe(struct mlx5e_rq *rq, struct mlx5e_rx_wqe *wqe, u16 ix);
void mlx5e_dealloc_rx_wqe(struct mlx5e_rq *rq, u16 ix);
int mlx5e_alloc_striding_rx_wqe(struct mlx5e_rq *rq,
				struct mlx5e_rx_wqe *wqe, u16 ix);
void mlx5e_post_rx_fragmented_mpwqe(struct mlx5e_rq *rq);
void mlx5e_complete_rx_linear_mpwqe(struct mlx5e_rq *rq,
				    struct mlx5_cqe64 *cqe,
				    u16 byte_cnt,
				    struct mlx5e_rx_wqe_info *wi,
				    struct sk_buff *skb);
void mlx5e_complete_rx_fragmented_mpwqe(struct mlx5e_rq *rq,
					struct mlx5_cqe64 *cqe,
					u16 byte_cnt,
					struct mlx5e_rx_wqe_info *wi,
					struct sk_buff *skb);
void mlx5e_free_rx_linear_mpwqe(struct mlx5e_rq *rq,
				struct mlx5e_rx_wqe_info *wi);
void mlx5e_free_rx_fragmented_mpwqe(struct mlx5e_rq *rq,
				    struct mlx5e_rx_wqe_info *wi);
void mlx5e_dealloc_striding_rx_wqe(struct mlx5e_rq *rq, u16 ix);

bool mlx5e_post_rx_wqes(struct mlx5e_rq *rq);
void mlx5e_free_rx_descs(struct mlx5e_rq *rq);
void mlx5e_prefetch_cqe(struct mlx5e_cq *cq);
struct mlx5_cqe64 *mlx5e_get_cqe(struct mlx5e_cq *cq);

void mlx5e_rx_am(struct mlx5e_rq *rq);
void mlx5e_rx_am_work(struct work_struct *work);
struct mlx5e_cq_moder mlx5e_am_get_def_profile(u8 rx_cq_period_mode);

void mlx5e_update_stats(struct mlx5e_priv *priv);

int mlx5e_create_flow_steering(struct mlx5e_priv *priv);
void mlx5e_destroy_flow_steering(struct mlx5e_priv *priv);
void mlx5e_init_eth_addr(struct mlx5e_priv *priv);
void mlx5e_destroy_flow_table(struct mlx5e_flow_table *ft);
void mlx5e_set_rx_mode_core(struct mlx5e_priv *priv);
void mlx5e_set_rx_mode_work(struct work_struct *work);

void mlx5e_fill_hwstamp(struct mlx5e_tstamp *clock,
			struct skb_shared_hwtstamps *hwts,
			u64 timestamp);
void mlx5e_ptp_overflow_check(struct mlx5e_priv *priv);
void mlx5e_ptp_init(struct mlx5e_priv *priv);
void mlx5e_ptp_cleanup(struct mlx5e_priv *priv);

int mlx5e_vlan_rx_add_vid(struct net_device *dev, __always_unused __be16 proto,
			  u16 vid);
int mlx5e_vlan_rx_kill_vid(struct net_device *dev, __always_unused __be16 proto,
			   u16 vid);
void mlx5e_enable_vlan_filter(struct mlx5e_priv *priv);
void mlx5e_disable_vlan_filter(struct mlx5e_priv *priv);
int mlx5e_add_all_vlan_rules(struct mlx5e_priv *priv);
void mlx5e_del_all_vlan_rules(struct mlx5e_priv *priv);
int mlx5e_add_tunneling_rule(struct mlx5e_priv *priv,
			     enum mlx5e_tunnel_rule_type rule_type,
			     u16 port_proto, u16 ethertype,
			     struct mlx5_flow_rule **rule_p);
void mlx5e_del_tunneling_rule(struct mlx5e_priv *priv,
			      struct mlx5_flow_rule **rule_p);

int mlx5e_open_locked(struct net_device *netdev);
int mlx5e_close_locked(struct net_device *netdev);
int mlx5e_update_priv_params(struct mlx5e_priv *priv,
			     struct mlx5e_params *new_params);
u32 mlx5e_choose_lro_timeout(struct mlx5_core_dev *mdev,
			     u32 wanted_timeout);

void mlx5e_create_debugfs(struct mlx5e_priv *priv);
void mlx5e_destroy_debugfs(struct mlx5e_priv *priv);
void mlx5e_self_test(struct net_device *dev,
		     struct ethtool_test *etest,
		     u64 *buf);

int mlx5e_sysfs_create(struct net_device *dev);
void mlx5e_sysfs_remove(struct net_device *dev);
int mlx5e_rl_init_sysfs(struct net_device *netdev);
void mlx5e_rl_remove_sysfs(struct net_device *netdev);
int mlx5e_modify_rqs_vsd(struct mlx5e_priv *priv, int vsd);
void mlx5e_build_default_indir_rqt(struct mlx5_core_dev *mdev,
				   u32 *indirection_rqt, int len,
				   int num_channels);
int mlx5e_setup_tc(struct net_device *netdev, u8 tc);
void mlx5e_build_tir_ctx_common(struct mlx5e_priv *priv, void *tirc);
/*sniffer functions*/
int mlx5e_sniffer_turn_on(struct net_device *dev);
int mlx5e_sniffer_turn_off(struct net_device *dev);
int mlx5e_sniffer_open_tir(struct mlx5e_priv *priv, int tt);
void mlx5e_sniffer_initialize_private_data(void);

void mlx5e_set_rx_cq_mode_params(struct mlx5e_params *params,
				 u8 cq_period_mode);

static inline void mlx5e_tx_notify_hw(struct mlx5e_sq *sq,
				      struct mlx5_wqe_ctrl_seg *ctrl, int bf_sz)
{
	u16 ofst = MLX5_BF_OFFSET + sq->bf_offset;

	/* ensure wqe is visible to device before updating doorbell record */
	wmb();

	*sq->wq.db = cpu_to_be32(sq->pc);

	/* ensure doorbell record is visible to device before ringing the
	 * doorbell */
	wmb();

	if (bf_sz) {
		__iowrite64_copy(sq->uar_bf_map + ofst, ctrl, bf_sz);

		/* flush the write-combining mapped buffer */
		wmb();

	} else {
		mlx5_write64((__be32 *)ctrl, sq->uar_map + ofst, NULL);
	}

	sq->bf_offset ^= sq->bf_buf_size;
}

static inline void mlx5e_cq_arm(struct mlx5e_cq *cq)
{
	struct mlx5_core_cq *mcq;

	mcq = &cq->mcq;
	mlx5_cq_arm(mcq, MLX5_CQ_DB_REQ_NOT, mcq->uar->map, NULL, cq->wq.cc);
}

static inline int mlx5e_max_num_channels(int num_comp_vectors)
{
	return min_t(int, num_comp_vectors, MLX5E_MAX_NUM_CHANNELS);
}

static inline enum rq_type mlx5e_get_rq_type_cap(struct mlx5_core_dev *mdev)
{
	if (MLX5_CAP_GEN(mdev, striding_rq) &&
	    MLX5_CAP_GEN(mdev, umr_ptr_rlky) &&
	    MLX5_CAP_ETH(mdev, reg_umr_sq))
		return RQ_TYPE_STRIDE;
	return RQ_TYPE_NONE;
}

static inline u16 mlx5e_get_mtt_octw(u16 npages)
{
	return ALIGN(npages, 8) / 2;
}

extern const struct ethtool_ops mlx5e_ethtool_ops;
extern const struct dcbnl_rtnl_ops mlx5e_dcbnl_ops;
int mlx5e_dcbnl_set_dcbx_mode(struct mlx5e_priv *priv,
			      enum mlx5_dcbx_oper_mode mode);
void mlx5e_dcbnl_query_dcbx_mode(struct mlx5e_priv *priv,
				 enum mlx5_dcbx_oper_mode *mode);
void mlx5e_dcbnl_initialize(struct net_device *netdev);

#ifndef CONFIG_RFS_ACCEL
static inline int mlx5e_arfs_create_tables(struct mlx5e_priv *priv)
{
	return 0;
}

static inline int mlx5e_arfs_init_tables(struct mlx5e_priv *priv)
{
	return 0;
}

static inline void mlx5e_arfs_shutdown_tables(struct mlx5e_priv *priv) {}
static inline void mlx5e_arfs_destroy_tables(struct mlx5e_priv *priv) {}
#else
int mlx5e_arfs_create_tables(struct mlx5e_priv *priv);
int mlx5e_arfs_init_tables(struct mlx5e_priv *priv);
void mlx5e_arfs_destroy_tables(struct mlx5e_priv *priv);
void mlx5e_arfs_shutdown_tables(struct mlx5e_priv *priv);
int mlx5e_arfs_enable(struct mlx5e_priv *priv);
int mlx5e_arfs_disable(struct mlx5e_priv *priv);
int mlx5e_rx_flow_steer(struct net_device *dev, const struct sk_buff *skb,
			u16 rxq_index, u32 flow_id);
#endif

int mlx5e_get_dump_flag(struct net_device *netdev, struct ethtool_dump *dump);
int mlx5e_get_dump_data(struct net_device *netdev, struct ethtool_dump *dump,
			void *buffer);
int mlx5e_set_dump(struct net_device *dev, struct ethtool_dump *dump);

#endif /* __MLX5_EN_H__ */
