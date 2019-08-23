/*
 * Copyright (c) 2017, Mellanox Technologies inc.  All rights reserved.
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

#include <rdma/rdma_user_ioctl.h>
#include <rdma/uverbs_ioctl.h>
#include "rdma_core.h"
#include "uverbs.h"

static bool uverbs_is_attr_cleared(const struct ib_uverbs_attr *uattr,
				   u16 len)
{
	if (uattr->len > sizeof(((struct ib_uverbs_attr *)0)->data))
		return ib_is_buffer_cleared(u64_to_user_ptr(uattr->data) + len,
					    uattr->len - len);

	return !memchr_inv((const void *)&uattr->data + len,
			   0, uattr->len - len);
}

static int uverbs_process_idrs_arr_attr(struct ib_uverbs_file *ufile,
					struct uverbs_objs_arr_attr *attr,
					const struct ib_uverbs_attr *uattr,
					const struct uverbs_attr_spec *spec)
{
	const struct uverbs_object_spec *object;
	int err;
	int i = 0; /* Initialization for error flow */

	if (!ufile->ucontext || uattr->attr_data.reserved)
		return -EINVAL;

	if (uattr->len % sizeof(u32))
		return -EINVAL;

	attr->len = uattr->len / sizeof(u32);

	if (attr->len < spec->u2.objs_arr.min_len ||
	    attr->len > spec->u2.objs_arr.max_len)
		return -EINVAL;

	attr->uobjects = kvmalloc_array(attr->len, sizeof(*attr->uobjects),
					GFP_KERNEL);
	if (!attr->uobjects)
		return -ENOMEM;

	/* Since idr is 4B and *uobjects is >= 4B, we can use
	 * attr->uobjects to store idrs array and avoid additional memory
	 * allocation. The idrs array is offset to the end of the uobjects
	 * array so we will be able to read a 4B idr and replace with a
	 * 8B pointer.
	 */
	if (uattr->len > sizeof(uattr->data)) {
		err = copy_from_user((u8 *)attr->uobjects + uattr->len,
				     u64_to_user_ptr(uattr->data),
				     uattr->len);
		if (err) {
			err = -EFAULT;
			goto err_objs_arr;
		}
	} else {
		memcpy((u8 *)attr->uobjects + uattr->len, &uattr->data,
		       uattr->len);
	}

	object = uverbs_get_object(ufile, spec->u2.objs_arr.obj_type);
	if (!object) {
		err = -EINVAL;
		goto err_objs_arr;
	}

	for (i = 0; i < attr->len; i++) {
		attr->uobjects[i] =
			uverbs_get_uobject_from_context(object->type_attrs,
							ufile->ucontext,
							spec->u2.objs_arr.access,
							((u32 *)attr->uobjects)[attr->len + i]);
		if (IS_ERR(attr->uobjects[i])) {
			err = PTR_ERR(attr->uobjects[i]);
			goto err_objs_arr;
		}
	}

	return 0;

err_objs_arr:
	while (i > 0)
		uverbs_finalize_object(attr->uobjects[--i],
				       spec->u2.objs_arr.access, false);

	kvfree(attr->uobjects);
	return err;
}

static int uverbs_process_attr(struct ib_uverbs_file *ufile,
			       const struct ib_uverbs_attr *uattr,
			       u16 attr_id,
			       const struct uverbs_attr_spec_hash *attr_spec_bucket,
			       struct uverbs_attr_bundle_hash *attr_bundle_h,
			       struct ib_uverbs_attr __user *uattr_ptr)
{
	const struct uverbs_attr_spec *spec;
	const struct uverbs_attr_spec *val_spec;
	struct uverbs_attr *e;
	const struct uverbs_object_spec *object;
	struct uverbs_obj_attr *o_attr;
	struct uverbs_attr *elements = attr_bundle_h->attrs;
	int err;

	if (attr_id >= attr_spec_bucket->num_attrs) {
		if (uattr->flags & UVERBS_ATTR_F_MANDATORY)
			return -EINVAL;
		else
			return 0;
	}

	if (test_bit(attr_id, attr_bundle_h->valid_bitmap))
		return -EINVAL;

	spec = &attr_spec_bucket->attrs[attr_id];
	val_spec = spec;
	e = &elements[attr_id];
	e->uattr = uattr_ptr;

	switch (spec->type) {
	case UVERBS_ATTR_TYPE_ENUM_IN:
		if (uattr->attr_data.enum_data.elem_id >= spec->u.enum_def.num_elems)
			return -EOPNOTSUPP;

		if (uattr->attr_data.enum_data.reserved)
			return -EINVAL;

		val_spec = &spec->u2.enum_def.ids[uattr->attr_data.enum_data.elem_id];

		/* Currently we only support PTR_IN based enums */
		if (val_spec->type != UVERBS_ATTR_TYPE_PTR_IN)
			return -EOPNOTSUPP;

		e->ptr_attr.enum_id = uattr->attr_data.enum_data.elem_id;
	/* fall through */
	case UVERBS_ATTR_TYPE_PTR_IN:
		/* Ensure that any data provided by userspace beyond the known
		 * struct is zero. Userspace that knows how to use some future
		 * longer struct will fail here if used with an old kernel and
		 * non-zero content, making ABI compat/discovery simpler.
		 */
		if (uattr->len > val_spec->u.ptr.len &&
		    val_spec->zero_trailing &&
		    !uverbs_is_attr_cleared(uattr, val_spec->u.ptr.len))
			return -EOPNOTSUPP;

	/* fall through */
	case UVERBS_ATTR_TYPE_PTR_OUT:
		if (uattr->len < val_spec->u.ptr.min_len ||
		    (!val_spec->zero_trailing &&
		     uattr->len > val_spec->u.ptr.len))
			return -EINVAL;

		if (spec->type != UVERBS_ATTR_TYPE_ENUM_IN &&
		    uattr->attr_data.reserved)
			return -EINVAL;

		e->ptr_attr.len = uattr->len;
		e->ptr_attr.flags = uattr->flags;

		if (val_spec->alloc_and_copy && !uverbs_attr_ptr_is_inline(e)) {
			void *p;

			p = kvmalloc(uattr->len, GFP_KERNEL);
			if (!p)
				return -ENOMEM;

			e->ptr_attr.ptr = p;

			if (copy_from_user(p, u64_to_user_ptr(uattr->data),
					   uattr->len)) {
				kvfree(p);
				return -EFAULT;
			}
		} else {
			e->ptr_attr.data = uattr->data;
		}
		break;

	case UVERBS_ATTR_TYPE_IDR:
		if (uattr->data >> 32)
			return -EINVAL;
	/* fall through */
	case UVERBS_ATTR_TYPE_FD:
		if (uattr->attr_data.reserved)
			return -EINVAL;

		if (uattr->len != 0 || !ufile->ucontext ||
		    uattr->data > INT_MAX)
			return -EINVAL;

		o_attr = &e->obj_attr;
		object = uverbs_get_object(ufile, spec->u.obj.obj_type);
		if (!object)
			return -EINVAL;

		o_attr->uobject = uverbs_get_uobject_from_context(
					object->type_attrs,
					ufile->ucontext,
					spec->u.obj.access,
					(int)uattr->data);

		if (IS_ERR(o_attr->uobject))
			return PTR_ERR(o_attr->uobject);

		if (spec->u.obj.access == UVERBS_ACCESS_NEW) {
			u64 id = o_attr->uobject->id;

			/* Copy the allocated id to the user-space */
			if (put_user(id, &e->uattr->data)) {
				uverbs_finalize_object(o_attr->uobject,
						       UVERBS_ACCESS_NEW,
						       false);
				return -EFAULT;
			}
		}

		break;

	case UVERBS_ATTR_TYPE_IDRS_ARRAY:
		err = uverbs_process_idrs_arr_attr(ufile, &e->objs_arr_attr,
						   uattr, spec);
		if (err)
			return err;

		break;
	default:
		return -EOPNOTSUPP;
	}

	set_bit(attr_id, attr_bundle_h->valid_bitmap);
	return 0;
}

static int uverbs_finalize_attrs(struct uverbs_attr_bundle *attrs_bundle,
				 struct uverbs_attr_spec_hash *const *spec_hash,
				 size_t num, bool commit)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < num; i++) {
		struct uverbs_attr_bundle_hash *curr_bundle =
			&attrs_bundle->hash[i];
		const struct uverbs_attr_spec_hash *curr_spec_bucket =
			spec_hash[i];
		unsigned int j;

		if (!curr_spec_bucket)
			continue;

		for (j = 0; j < curr_bundle->num_attrs; j++) {
			struct uverbs_attr *attr;
			const struct uverbs_attr_spec *spec;
			int current_ret;

			if (!uverbs_attr_is_valid_in_hash(curr_bundle, j))
				continue;

			attr = &curr_bundle->attrs[j];
			spec = &curr_spec_bucket->attrs[j];

			if (spec->type == UVERBS_ATTR_TYPE_IDR ||
			    spec->type == UVERBS_ATTR_TYPE_FD) {
				current_ret = uverbs_finalize_object(
					attr->obj_attr.uobject,
					spec->u.obj.access, commit);
				if (!ret)
					ret = current_ret;
			} else if (spec->type == UVERBS_ATTR_TYPE_PTR_IN &&
				   spec->alloc_and_copy &&
				   !uverbs_attr_ptr_is_inline(attr)) {
				kvfree(attr->ptr_attr.ptr);
			} else if (spec->type == UVERBS_ATTR_TYPE_IDRS_ARRAY) {
				for (i = 0; i < attr->objs_arr_attr.len; i++) {
					current_ret =
						uverbs_finalize_object(attr->objs_arr_attr.uobjects[i],
								       spec->u2.objs_arr.access, commit);
					if (!ret)
						ret = current_ret;
				}
				kvfree(attr->objs_arr_attr.uobjects);
			}
		}
	}
	return ret;
}

static int uverbs_uattrs_process(struct ib_uverbs_file *ufile,
				 const struct ib_uverbs_attr *uattrs,
				 size_t num_uattrs,
				 const struct uverbs_method_spec *method,
				 struct uverbs_attr_bundle *attr_bundle,
				 struct ib_uverbs_attr __user *uattr_ptr)
{
	size_t i;
	int ret = 0;
	int num_given_buckets = 0;

	for (i = 0; i < num_uattrs; i++) {
		const struct ib_uverbs_attr *uattr = &uattrs[i];
		u16 attr_id = uattr->attr_id;
		struct uverbs_attr_spec_hash *attr_spec_bucket;

		ret = uverbs_ns_idx(&attr_id, method->num_buckets);
		if (ret < 0 || !method->attr_buckets[ret]) {
			if (uattr->flags & UVERBS_ATTR_F_MANDATORY) {
				uverbs_finalize_attrs(attr_bundle,
						      method->attr_buckets,
						      num_given_buckets,
						      false);
				return ret;
			}
			continue;
		}

		/*
		 * ret is the found ns, so increase num_given_buckets if
		 * necessary.
		 */
		if (ret >= num_given_buckets)
			num_given_buckets = ret + 1;

		attr_spec_bucket = method->attr_buckets[ret];
		ret = uverbs_process_attr(ufile, uattr, attr_id,
					  attr_spec_bucket,
					  &attr_bundle->hash[ret], uattr_ptr++);
		if (ret) {
			uverbs_finalize_attrs(attr_bundle,
					      method->attr_buckets,
					      num_given_buckets,
					      false);
			return ret;
		}
	}

	return num_given_buckets;
}

static int uverbs_validate_kernel_mandatory(const struct uverbs_method_spec *method_spec,
					    struct uverbs_attr_bundle *attr_bundle)
{
	unsigned int i;

	for (i = 0; i < attr_bundle->num_buckets; i++) {
		struct uverbs_attr_spec_hash *attr_spec_bucket =
			method_spec->attr_buckets[i];

		if (!attr_spec_bucket)
			continue;

		if (!bitmap_subset(attr_spec_bucket->mandatory_attrs_bitmask,
				   attr_bundle->hash[i].valid_bitmap,
				   attr_spec_bucket->num_attrs))
			return -EINVAL;
	}

	for (; i < method_spec->num_buckets; i++) {
		struct uverbs_attr_spec_hash *attr_spec_bucket =
			method_spec->attr_buckets[i];

		if (!bitmap_empty(attr_spec_bucket->mandatory_attrs_bitmask,
				  attr_spec_bucket->num_attrs))
			return -EINVAL;
	}

	return 0;
}

static int uverbs_handle_method(struct ib_uverbs_attr __user *uattr_ptr,
				const struct ib_uverbs_attr *uattrs,
				size_t num_uattrs,
				struct ib_device *ibdev,
				struct ib_uverbs_file *ufile,
				const struct uverbs_method_spec *method_spec,
				struct uverbs_attr_bundle *attr_bundle)
{
	int ret;
	int finalize_ret;
	int num_given_buckets;

	num_given_buckets = uverbs_uattrs_process(
		ufile, uattrs, num_uattrs, method_spec, attr_bundle, uattr_ptr);
	if (num_given_buckets <= 0)
		return -EINVAL;

	attr_bundle->num_buckets = num_given_buckets;
	ret = uverbs_validate_kernel_mandatory(method_spec, attr_bundle);
	if (ret)
		goto cleanup;

	ret = method_spec->handler(ibdev, ufile, attr_bundle);
cleanup:
	finalize_ret = uverbs_finalize_attrs(attr_bundle,
					     method_spec->attr_buckets,
					     attr_bundle->num_buckets,
					     !ret);

	return ret ? ret : finalize_ret;
}

#define UVERBS_OPTIMIZE_USING_STACK_SZ  256
static long ib_uverbs_cmd_verbs(struct ib_device *ib_dev,
				struct ib_uverbs_file *file,
				struct ib_uverbs_ioctl_hdr *hdr,
				void __user *buf)
{
	const struct uverbs_object_spec *object_spec;
	const struct uverbs_method_spec *method_spec;
	long err = 0;
	unsigned int i;
	struct {
		struct ib_uverbs_attr		*uattrs;
		struct uverbs_attr_bundle	*uverbs_attr_bundle;
	} *ctx = NULL;
	struct uverbs_attr *curr_attr;
	unsigned long *curr_bitmap;
	size_t ctx_size;
	uintptr_t data[UVERBS_OPTIMIZE_USING_STACK_SZ / sizeof(uintptr_t)];

	if (hdr->driver_id != ib_dev->driver_id)
		return -EINVAL;

	object_spec = uverbs_get_object(file, hdr->object_id);
	if (!object_spec)
		return -EPROTONOSUPPORT;

	method_spec = uverbs_get_method(object_spec, hdr->method_id);
	if (!method_spec)
		return -EPROTONOSUPPORT;

	if ((method_spec->flags & UVERBS_ACTION_FLAG_CREATE_ROOT) ^ !file->ucontext)
		return -EINVAL;

	ctx_size = sizeof(*ctx) +
		   sizeof(struct uverbs_attr_bundle) +
		   sizeof(struct uverbs_attr_bundle_hash) * method_spec->num_buckets +
		   sizeof(*ctx->uattrs) * hdr->num_attrs +
		   sizeof(*ctx->uverbs_attr_bundle->hash[0].attrs) *
		   method_spec->num_child_attrs +
		   sizeof(*ctx->uverbs_attr_bundle->hash[0].valid_bitmap) *
			(method_spec->num_child_attrs / BITS_PER_LONG +
			 method_spec->num_buckets);

	if (ctx_size <= UVERBS_OPTIMIZE_USING_STACK_SZ)
		ctx = (void *)data;
	if (!ctx)
		ctx = kmalloc(ctx_size, GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->uverbs_attr_bundle = (void *)ctx + sizeof(*ctx);
	ctx->uattrs = (void *)(ctx->uverbs_attr_bundle + 1) +
			      (sizeof(ctx->uverbs_attr_bundle->hash[0]) *
			       method_spec->num_buckets);
	curr_attr = (void *)(ctx->uattrs + hdr->num_attrs);
	curr_bitmap = (void *)(curr_attr + method_spec->num_child_attrs);

	/*
	 * We just fill the pointers and num_attrs here. The data itself will be
	 * filled at a later stage (uverbs_process_attr)
	 */
	for (i = 0; i < method_spec->num_buckets; i++) {
		unsigned int curr_num_attrs;

		if (!method_spec->attr_buckets[i])
			continue;

		curr_num_attrs = method_spec->attr_buckets[i]->num_attrs;

		ctx->uverbs_attr_bundle->hash[i].attrs = curr_attr;
		curr_attr += curr_num_attrs;
		ctx->uverbs_attr_bundle->hash[i].num_attrs = curr_num_attrs;
		ctx->uverbs_attr_bundle->hash[i].valid_bitmap = curr_bitmap;
		bitmap_zero(curr_bitmap, curr_num_attrs);
		curr_bitmap += BITS_TO_LONGS(curr_num_attrs);
	}

	err = copy_from_user(ctx->uattrs, buf,
			     sizeof(*ctx->uattrs) * hdr->num_attrs);
	if (err) {
		err = -EFAULT;
		goto out;
	}

	err = uverbs_handle_method(buf, ctx->uattrs, hdr->num_attrs, ib_dev,
				   file, method_spec, ctx->uverbs_attr_bundle);

	/*
	 * EPROTONOSUPPORT is ONLY to be returned if the ioctl framework can
	 * not invoke the method because the request is not supported.  No
	 * other cases should return this code.
	*/
	if (unlikely(err == -EPROTONOSUPPORT)) {
		WARN_ON_ONCE(err == -EPROTONOSUPPORT);
		err = -EINVAL;
	}
out:
	if (ctx != (void *)data)
		kfree(ctx);
	return err;
}

#define IB_UVERBS_MAX_CMD_SZ 4096

long ib_uverbs_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct ib_uverbs_file *file = filp->private_data;
	struct ib_uverbs_ioctl_hdr __user *user_hdr =
		(struct ib_uverbs_ioctl_hdr __user *)arg;
	struct ib_uverbs_ioctl_hdr hdr;
	struct ib_device *ib_dev;
	int srcu_key;
	long err;

	srcu_key = srcu_read_lock(&file->device->disassociate_srcu);
	ib_dev = srcu_dereference(file->device->ib_dev,
				  &file->device->disassociate_srcu);
	if (!ib_dev) {
		err = -EIO;
		goto out;
	}

	if (cmd == RDMA_VERBS_IOCTL) {
		err = copy_from_user(&hdr, user_hdr, sizeof(hdr));

		if (err || hdr.length > IB_UVERBS_MAX_CMD_SZ ||
		    hdr.length != sizeof(hdr) + hdr.num_attrs * sizeof(struct ib_uverbs_attr)) {
			err = -EINVAL;
			goto out;
		}

		if (hdr.reserved1 || hdr.reserved2) {
			err = -EPROTONOSUPPORT;
			goto out;
		}

		err = ib_uverbs_cmd_verbs(ib_dev, file, &hdr,
					  (__user void *)arg + sizeof(hdr));
	} else {
		if (!ib_dev->exp_ioctl) {
			err = -ENOIOCTLCMD;
			goto out;
		}

		if (!file->ucontext) {
			err = -ENODEV;
			goto out;
		}
		/* provider should provide it's own locking mechanism */
		err = ib_dev->exp_ioctl(file->ucontext, cmd, arg);
	}
out:
	srcu_read_unlock(&file->device->disassociate_srcu, srcu_key);

	return err;
}

int uverbs_get_flags64(u64 *to, const struct uverbs_attr_bundle *attrs_bundle,
		       size_t idx, u64 allowed_bits)
{
	const struct uverbs_attr *attr;
	u64 flags;

	attr = uverbs_attr_get(attrs_bundle, idx);
	/* Missing attribute means 0 flags */
	if (IS_ERR(attr)) {
		*to = 0;
		return 0;
	}

	/*
	 * New userspace code should use 8 bytes to pass flags, but we
	 * transparently support old userspaces that were using 4 bytes as
	 * well.
	 */
	if (attr->ptr_attr.len == 8)
		flags = attr->ptr_attr.data;
	else if (attr->ptr_attr.len == 4)
		flags = *(u32 *)&attr->ptr_attr.data;
	else
		return -EINVAL;

	if (flags & ~allowed_bits)
		return -EINVAL;

	*to = flags;
	return 0;
}
EXPORT_SYMBOL(uverbs_get_flags64);

int uverbs_get_flags32(u32 *to, const struct uverbs_attr_bundle *attrs_bundle,
		       size_t idx, u64 allowed_bits)
{
	u64 flags;
	int ret;

	ret = uverbs_get_flags64(&flags, attrs_bundle, idx, allowed_bits);
	if (ret)
		return ret;

	if (flags > U32_MAX)
		return -EINVAL;
	*to = flags;

	return 0;
}
EXPORT_SYMBOL(uverbs_get_flags32);

int _uverbs_get_const(s64 *to, const struct uverbs_attr_bundle *attrs_bundle,
		      size_t idx, s64 lower_bound, u64 upper_bound,
		      s64  *def_val)
{
	const struct uverbs_attr *attr;

	attr = uverbs_attr_get(attrs_bundle, idx);
	if (IS_ERR(attr)) {
		if ((PTR_ERR(attr) != -ENOENT) || !def_val)
			return PTR_ERR(attr);

		*to = *def_val;
		goto bound_check;
	}

	*to = attr->ptr_attr.data;

bound_check:
	if (*to < lower_bound || (*to > 0 && (u64)*to > upper_bound))
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL(_uverbs_get_const);
