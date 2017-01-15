/*
 * Copyright (c) 2013-2015, Mellanox Technologies, Ltd.  All rights reserved.
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

#ifndef __MLX5_CORE_H__
#define __MLX5_CORE_H__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/mlx5/driver.h>

#define DRIVER_NAME "mlx5_core"

#define DRIVER_MAJOR_VER	"3.4"
#define DRIVER_MINOR_VER	"1.0.0"
#define DRIVER_SUB_MINOR_VER "0"
#define DRIVER_RELDATE	"25 Sep 2016"
#define DRIVER_VERSION DRIVER_MAJOR_VER "-" DRIVER_MINOR_VER

#define OS_NAME_FOR_FW "Linux"
#define MLX5_DEFAULT_COMP_IRQ_NAME "mlx5_comp%d"

extern int mlx5_core_debug_mask;

#define MLX5_MAX_NUM_TC 8

#define mlx5_core_dbg(__dev, format, ...)				\
	dev_dbg(&(__dev)->pdev->dev, "%s:%s:%d:(pid %d): " format,	\
		 (__dev)->priv.name, __func__, __LINE__, current->pid,	\
		 ##__VA_ARGS__)

#define mlx5_core_dbg_mask(__dev, mask, format, ...)			\
do {									\
	if ((mask) & mlx5_core_debug_mask)				\
		mlx5_core_dbg(__dev, format, ##__VA_ARGS__);		\
} while (0)

#define mlx5_core_err(__dev, format, ...)				\
	dev_err(&(__dev)->pdev->dev, "%s:%s:%d:(pid %d): " format,	\
	       (__dev)->priv.name, __func__, __LINE__, current->pid,	\
	       ##__VA_ARGS__)

#define mlx5_core_warn(__dev, format, ...)				\
	dev_warn(&(__dev)->pdev->dev, "%s:%s:%d:(pid %d): " format,	\
		(__dev)->priv.name, __func__, __LINE__, current->pid,	\
		##__VA_ARGS__)

#define mlx5_core_info(__dev, format, ...)				\
	dev_info(&(__dev)->pdev->dev, format, ##__VA_ARGS__)

enum {
	MLX5_CMD_DATA, /* print command payload only */
	MLX5_CMD_TIME, /* print command execution time */
};

enum mlx5_icmd_conf_address {
	MLX5_ICMD_CTRL		= 0x0,		/* RW */
	MLX5_ICMD_MAILBOX_SZ	= 0x1000,	/* RO */
	MLX5_ICMD_SYNDROME	= 0x1008,	/* RO */
	MLX5_ICMD_MAILBOX	= 0x100000,	/* RW */
};

enum mlx5_icmd_ctrl_opcode {
	MLX5_ICMD_ACCESS_REG	= 0x9001,
};

enum mlx5_icmd_access_reg_id {
	MLX5_ICMD_MCION		= 0x9052,
};

enum mlx5_icmd_access_reg_method {
	MLX5_ICMD_QUERY		= 0x1,
	MLX5_ICMD_WRITE		= 0x2,
};

enum {
	MLX5_ICMD_ACCESS_REG_DATA_DW_SZ	= 0x2,
};

struct mlx5_icmd_ctrl_bits {
	u16	opcode;
	u8	status;
	u8	busy;
} __packed;

struct mlx5_icmd_access_reg_input_bits {
	u16	constant_1_2;
	u8	reserved_0[0x2];
	u16	register_id;
	u8	method;
	u8	constant_3;
	u8	reserved_1[0x8];
	u16	len;
	u8	reserved_2[0x2];
	u32	reg_data[MLX5_ICMD_ACCESS_REG_DATA_DW_SZ];
} __packed;

struct mlx5_icmd_access_reg_output_bits {
	u8	reserved_0[0x2];
	u8	status;
	u8	reserved_1[0x1];
	u16	register_id;
	u8	reserved_2[0xA];
	u16	len;
	u8	reserved_3[0x2];
	u32	reg_data[MLX5_ICMD_ACCESS_REG_DATA_DW_SZ];
} __packed;

struct mlx5_mcion_reg {
	u8	reserved_0[0x1];
	u8	module;
	u8	reserved_1[0x5];
	u8	module_status;
} __packed;

static inline int mlx5_cmd_exec_check_status(struct mlx5_core_dev *dev, u32 *in,
					     int in_size, u32 *out,
					     int out_size)
{
	int err;

	err = mlx5_cmd_exec(dev, in, in_size, out, out_size);
	if (err)
		return err;

	return mlx5_cmd_status_to_err(dev, (struct mlx5_outbox_hdr *)out);
}

int mlx5_query_hca_caps(struct mlx5_core_dev *dev);
int mlx5_query_board_id(struct mlx5_core_dev *dev);

int mlx5_cmd_init_hca(struct mlx5_core_dev *dev);
int mlx5_cmd_teardown_hca(struct mlx5_core_dev *dev);
void mlx5_core_event(struct mlx5_core_dev *dev, enum mlx5_dev_event event,
			    unsigned long param);
void mlx5_enter_error_state(struct mlx5_core_dev *dev);
void mlx5_add_pci_to_irq_name(struct mlx5_core_dev *dev, const char *src_name,
			      char *dest_name);
void mlx5_rename_comp_eq(struct mlx5_core_dev *dev, unsigned int eq_ix,
			 char *name);
int mlx5_core_sriov_configure(struct pci_dev *dev, int num_vfs);
int mlx5_core_enable_hca(struct mlx5_core_dev *dev, u16 func_id);
int mlx5_core_disable_hca(struct mlx5_core_dev *dev, u16 func_id);
int mlx5_create_scheduling_element_cmd(struct mlx5_core_dev *dev, u8 hierarchy,
				       void *context, u32 *element_id);
int mlx5_modify_scheduling_element_cmd(struct mlx5_core_dev *dev, u8 hierarchy,
				       void *context, u32 element_id,
				       u32 modify_bitmask);
int mlx5_destroy_scheduling_element_cmd(struct mlx5_core_dev *dev, u8 hierarchy,
					u32 element_id);
int mlx5_max_tc(struct mlx5_core_dev *mdev);
int mlx5_modify_port_ets_tc_bw_alloc(struct mlx5_core_dev *mdev,
				     u8 tc_tx_bw[MLX5_MAX_NUM_TC],
				     u8 tc_group[MLX5_MAX_NUM_TC]);
int mlx5_query_port_ets_tc_bw_alloc(struct mlx5_core_dev *mdev,
				    u8 tc_tx_bw[MLX5_MAX_NUM_TC]);
int mlx5_modify_port_priority2tc(struct mlx5_core_dev *mdev,
				 u8 prio2tc[MLX5_MAX_NUM_TC]);
int mlx5_query_port_priority2tc(struct mlx5_core_dev *mdev,
				u8 prio2tc[MLX5_MAX_NUM_TC]);
int mlx5_modify_port_ets_rate_limit(struct mlx5_core_dev *mdev,
				    u8 max_bw_value[MLX5_MAX_NUM_TC],
				    u8 max_bw_unit[MLX5_MAX_NUM_TC]);
int mlx5_query_port_ets_rate_limit(struct mlx5_core_dev *mdev,
				   u8 max_bw_value[MLX5_MAX_NUM_TC],
				   u8 max_bw_unit[MLX5_MAX_NUM_TC]);
struct mlx5_eq *mlx5_eqn2eq(struct mlx5_core_dev *dev, int eqn);
int mlx5_vector2eq(struct mlx5_core_dev *dev, int vector, struct mlx5_eq *eqc);
void mlx5_cq_tasklet_cb(unsigned long data);
u32 mlx5_get_msix_vec(struct mlx5_core_dev *dev, int vecidx);

int mlx5_mst_dump_init(struct mlx5_core_dev *dev);
int mlx5_mst_capture(struct mlx5_core_dev *dev);
u32 mlx5_mst_dump(struct mlx5_core_dev *dev, void *buff, u32 buff_sz);
void mlx5_mst_free_capture(struct mlx5_core_dev *dev);
void mlx5_mst_dump_cleanup(struct mlx5_core_dev *dev);

int mlx5_icmd_access_register(struct mlx5_core_dev *dev,
			      int reg_id,
			      int method,
			      void *io_buff,
			      u32 io_buff_dw_sz);

void mlx5e_init(void);
void mlx5e_cleanup(void);

/*Sniffer callback for RoCE rules*/
enum roce_action {
	ROCE_ON,
	ROCE_OFF,
};

void mlx5e_sniffer_roce_mode_notify(
	struct mlx5_core_dev *mdev,
	int action);

#endif /* __MLX5_CORE_H__ */
