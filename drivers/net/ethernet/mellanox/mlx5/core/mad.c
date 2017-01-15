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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mlx5/driver.h>
#include <linux/mlx5/cmd.h>
#include <rdma/ib_mad.h>
#include "mlx5_core.h"

static int can_do_mad_ifc(struct mlx5_core_dev *dev, u8 port_num, u8 *data)
{
	struct mlx5_hca_vport_context *rep;
	bool has_smi;
	int err;

	if (data[1] != IB_MGMT_CLASS_SUBN_LID_ROUTED &&
	    data[1] != IB_MGMT_CLASS_SUBN_DIRECTED_ROUTE)
		return 1;
	if (MLX5_CAP_GEN(dev, ib_virt) && !mlx5_core_is_pf(dev))
		return 0;
	rep = kzalloc(sizeof(*rep), GFP_KERNEL);
	if (!rep)
		return 0;
	err = mlx5_core_query_hca_vport_context(dev, 0, port_num, 0, rep);
	has_smi = rep->has_smi;
	kfree(rep);
	if (err || !has_smi)
		return 0;
	return 1;
}

int mlx5_core_mad_ifc(struct mlx5_core_dev *dev, void *inb, void *outb,
		      u16 opmod, u8 port)
{
	struct mlx5_mad_ifc_mbox_in *in = NULL;
	struct mlx5_mad_ifc_mbox_out *out = NULL;
	int err;

	in = kzalloc(sizeof(*in), GFP_KERNEL);
	if (!in)
		return -ENOMEM;

	out = kzalloc(sizeof(*out), GFP_KERNEL);
	if (!out) {
		err = -ENOMEM;
		goto out;
	}

	in->hdr.opcode = cpu_to_be16(MLX5_CMD_OP_MAD_IFC);
	in->hdr.opmod = cpu_to_be16(opmod);
	in->port = port;

	memcpy(in->data, inb, sizeof(in->data));
	if (!can_do_mad_ifc(dev, port, in->data))
		return -EPERM;

	err = mlx5_cmd_exec_check_status(dev, (void *)in, sizeof(*in),
					 (void *)out, sizeof(*out));
	if (!err)
		memcpy(outb, out->data, sizeof(out->data));

out:
	kfree(out);
	kfree(in);
	return err;
}
EXPORT_SYMBOL_GPL(mlx5_core_mad_ifc);
