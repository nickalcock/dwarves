/*
 * libctf_loader.c
 *
 * Copyright (C)2025, Oracle and/or its affiliates.
 * Bruce McCulloch <bruce.mcculloch@oracle.com>
 * 
 * Based on btf_loader.c
 * 
 * Copyright (C) 2018 Arnaldo Carvalho de Melo <acme@kernel.org>
 *
 * Based on ctf_loader.c that, in turn, was based on ctfdump.c: CTF dumper.
 *
 * Copyright (C) 2008 David S. Miller <davem@davemloft.net>
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stddef.h>
#include <malloc.h>
#include <string.h>
#include <limits.h>
#include <libgen.h>
#include <linux/btf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <zlib.h>

#include <gelf.h>

#include <ctf-api.h>

#include "dutil.h"
#include "dwarves.h"

static void *tag__alloc(const size_t size)
{
	struct tag *tag = zalloc(size);

	if (tag != NULL)
		tag->top_level = 1;

	return tag;
}

static int cu__load_ftype(struct cu *cu, struct ftype *proto, uint32_t tag, const struct btf_type *tp, uint32_t id)
{
	const struct btf_param *param = btf_params(tp);
	int i;
	size_t nargs_type, nargs_name;
	ctf_id_t ret_type;
	ctf_func_type_flags_t flags;

	proto->tag.tag	= tag;
	proto->tag.type = tp->type;
	INIT_LIST_HEAD(&proto->parms);
	INIT_LIST_HEAD(&proto->template_type_params);
	INIT_LIST_HEAD(&proto->template_value_params);
	proto->template_parameter_pack = NULL;
	proto->formal_parameter_pack = NULL;

	ctf_id_t *func_arg_types = ctf_func_type(cu->ctf_fp, id, &ret_type, &flags, &nargs_type);
	const char **func_arg_names = ctf_func_arg_names(cu->ctf_fp, id, &nargs_name);
	for (i = 0; i < nargs_type; ++i, param++) {
		if (func_arg_types[i] == 0)
			proto->unspec_parms = 1;
		else {
			struct parameter *p = tag__alloc(sizeof(*p));

			if (p == NULL)
				goto out_free_parameters;
			p->tag.tag  = DW_TAG_formal_parameter;
			p->tag.type = func_arg_types[i];
			p->name	    = func_arg_names[i];
			ftype__add_parameter(proto, p);
		}
	}

	cu__add_tag_with_id(cu, &proto->tag, id);

	return 0;
out_free_parameters:
	ftype__delete(proto, cu);
	return -ENOMEM;
}

static int create_new_function(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct function *func = tag__alloc(sizeof(*func));

	if (func == NULL)
		return -ENOMEM;

	// for BTF this is not really the type of the return of the function,
	// but the prototype, the return type is the one in type_id
	func->btf = 1;
	func->proto.tag.tag = DW_TAG_subprogram;
	func->proto.tag.type = tp->type;
	func->name = ctf_type_aname(cu->ctf_fp, id);
	INIT_LIST_HEAD(&func->lexblock.tags);
	cu__add_tag_with_id(cu, &func->proto.tag, id);

	return 0;
}

static struct base_type *base_type__new(const char *name, uint32_t attrs,
					uint8_t float_type, size_t size)
{
        struct base_type *bt = tag__alloc(sizeof(*bt));

	if (bt != NULL) {
		bt->name = name;
		bt->bit_size = size;
		bt->is_signed = attrs & BTF_INT_SIGNED;
		bt->is_bool = attrs & BTF_INT_BOOL;
		bt->name_has_encoding = false;
		bt->float_type = float_type;
		INIT_LIST_HEAD(&bt->node);
	}
	return bt;
}

static void type__init(struct type *type, uint32_t tag, const char *name, size_t size)
{
	__type__init(type);
	INIT_LIST_HEAD(&type->namespace.tags);
	type->size = size;
	type->namespace.tag.tag = tag;
	type->namespace.name = name;
	type->template_parameter_pack = NULL;
}

static struct type *type__new(uint16_t tag, const char *name, size_t size)
{
        struct type *type = tag__alloc(sizeof(*type));

	if (type != NULL)
		type__init(type, tag, name, size);

	return type;
}

static struct class *class__new(const char *name, size_t size, bool is_union)
{
	struct class *class = tag__alloc(sizeof(*class));
	uint32_t tag = is_union ? DW_TAG_union_type : DW_TAG_structure_type;

	if (class != NULL) {
		type__init(&class->type, tag, name, size);
		INIT_LIST_HEAD(&class->vtable);
	}

	return class;
}

static struct variable *variable__new(const char *name, uint32_t linkage)
{
	struct variable *var = tag__alloc(sizeof(*var));

	if (var != NULL) {
		var->external = linkage == BTF_VAR_GLOBAL_ALLOCATED;
		var->name = name;
		var->ip.tag.tag = DW_TAG_variable;
	}

	return var;
}

static int create_new_int_type(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	uint32_t attrs = btf_int_encoding(tp);
	const char *name = ctf_type_aname(cu->ctf_fp, id);
	struct base_type *base = base_type__new(name, attrs, 0, btf_int_bits(tp));

	if (base == NULL)
		return -ENOMEM;

	base->tag.tag = DW_TAG_base_type;
	cu__add_tag_with_id(cu, &base->tag, id);

	return 0;
}

static int create_new_float_type(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	const char *name = ctf_type_aname(cu->ctf_fp, id);
	struct base_type *base = base_type__new(name, 0, BT_FP_SINGLE, tp->size * 8);

	if (base == NULL)
		return -ENOMEM;

	base->tag.tag = DW_TAG_base_type;
	cu__add_tag_with_id(cu, &base->tag, id);

	return 0;
}

static int create_new_array(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct btf_array *ap = btf_array(tp);
	struct array_type *array = tag__alloc(sizeof(*array));

	if (array == NULL)
		return -ENOMEM;

	/* FIXME: where to get the number of dimensions?
	 * it it flattened? */
	array->dimensions = 1;
	array->nr_entries = malloc(sizeof(uint32_t));

	if (array->nr_entries == NULL) {
		free(array);
		return -ENOMEM;
	}

	array->nr_entries[0] = ap->nelems;
	array->tag.tag = DW_TAG_array_type;
	array->tag.type = ap->type;

	cu__add_tag_with_id(cu, &array->tag, id);

	return 0;
}

static int create_members(struct cu *cu, const struct btf_type *tp, struct type *class, uint32_t id)
{
	ctf_next_t *i = NULL;
	ssize_t offset;
	int bit_width;
	const char *name;
	ctf_id_t membtype;

	while ((offset = ctf_member_next(cu->ctf_fp, id, &i, &name, &membtype, &bit_width, 1)) != CTF_ERR) {
		struct class_member *member = zalloc(sizeof(*member));

		if (member == NULL)
			return -ENOMEM;

		member->tag.tag    = DW_TAG_member;
		member->tag.type   = membtype;
		member->name	   = name;
		member->bit_offset = offset;
		member->byte_offset = offset / 8;
		member->bitfield_size = bit_width;
		/* sizes added here instead of in class__fixup_btf_bitfields.  */
		member->byte_size = ctf_type_size(cu->ctf_fp, membtype);
		member->bit_size = member->bit_size / 8;
		type__add_member(class, member);
	}

	return 0;
}

static int create_new_class(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	// Fixup name, as libctf will return "struct <name>".
	struct class *class = class__new(ctf_type_aname(cu->ctf_fp, id) + 7, 
					tp->size, false);
	int member_size = create_members(cu, tp, &class->type, id);

	if (member_size < 0)
		goto out_free;

	cu__add_tag_with_id(cu, &class->type.namespace.tag, id);

	return 0;
out_free:
	class__delete(class, cu);
	return -ENOMEM;
}

static int create_new_union(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct type *un = type__new(DW_TAG_union_type, ctf_type_aname(cu->ctf_fp, id), tp->size);
	int member_size = create_members(cu, tp, un, id);

	if (member_size < 0)
		goto out_free;

	cu__add_tag_with_id(cu, &un->namespace.tag, id);

	return 0;
out_free:
	type__delete(un, cu);
	return -ENOMEM;
}

static struct enumerator *enumerator__new(const char *name, uint64_t value)
{
	struct enumerator *en = tag__alloc(sizeof(*en));

	if (en != NULL) {
		en->name = name;
		en->value = value;
		en->tag.tag = DW_TAG_enumerator;
	}

	return en;
}

static int create_new_enumeration(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	const char *enum_name;
	ctf_next_t *it = NULL;
	ctf_enum_value_t enum_value;
	struct type *enumeration = type__new(DW_TAG_enumeration_type,
					     ctf_type_aname(cu->ctf_fp, id),
					     tp->size ? tp->size * 8 : (sizeof(int) * 8));

	if (enumeration == NULL)
		return -ENOMEM;
	
	// perhaps check the ctf_encoding_t->cte_format here instead
	enumeration->is_signed_enum = !!btf_kflag(tp);

	while ((enum_name = ctf_enum_next(cu->ctf_fp, id, &it, &enum_value)) != NULL) {
		uint64_t value = enum_value.val.uval;

		if (!enumeration->is_signed_enum)
			value = (uint32_t)enum_value.val.uval;

		struct enumerator *enumerator = enumerator__new(enum_name, value);

		if (enumerator == NULL)
			goto out_free;

		enumeration__add(enumeration, enumerator);
	}

	cu__add_tag_with_id(cu, &enumeration->namespace.tag, id);

	return 0;
out_free:
	enumeration__delete(enumeration, cu);
	return -ENOMEM;
}

#if LIBBPF_MAJOR_VERSION >= 1
static struct enumerator *enumerator__new64(const char *name, uint64_t value)
{
	struct enumerator *en = tag__alloc(sizeof(*en));

	if (en != NULL) {
		en->name = name;
		en->value = value; // Value is already 64-bit, as this is used with DWARF as well
		en->tag.tag = DW_TAG_enumerator;
	}

	return en;
}

static int create_new_enumeration64(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	const char *enum_name;
	ctf_next_t *it = NULL;
	ctf_enum_value_t enum_value;
	struct type *enumeration = type__new(DW_TAG_enumeration_type,
					     ctf_type_aname(cu->ctf_fp, id),
					     tp->size ? tp->size * 8 : (sizeof(int) * 8));

	if (enumeration == NULL)
		return -ENOMEM;
	
	// perhaps check the ctf_encoding_t->cte_format here instead
	enumeration->is_signed_enum = !!btf_kflag(tp);

	while ((enum_name = ctf_enum_next(cu->ctf_fp, id, &it, &enum_value)) != NULL) {
		uint64_t value = enum_value.val.uval;

		struct enumerator *enumerator = enumerator__new64(enum_name, value);

		if (enumerator == NULL)
			goto out_free;

		enumeration__add(enumeration, enumerator);
	}

	cu__add_tag_with_id(cu, &enumeration->namespace.tag, id);

	return 0;
out_free:
	enumeration__delete(enumeration, cu);
	return -ENOMEM;
}
#else
static int create_new_enumeration64(struct cu *cu __maybe_unused, const struct btf_type *tp __maybe_unused, uint32_t id __maybe_unused)
{
	return -ENOTSUP;
}
#endif

static int create_new_subroutine_type(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct ftype *proto = tag__alloc(sizeof(*proto));

	if (proto == NULL)
		return -ENOMEM;

	return cu__load_ftype(cu, proto, DW_TAG_subroutine_type, tp, id);
}

static int create_new_forward_decl(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct class *fwd = class__new(ctf_type_aname(cu->ctf_fp, id), 0, btf_kflag(tp));

	if (fwd == NULL)
		return -ENOMEM;
	fwd->type.declaration = 1;
	cu__add_tag_with_id(cu, &fwd->type.namespace.tag, id);
	return 0;
}

static int create_new_typedef(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct type *type = type__new(DW_TAG_typedef, ctf_type_aname(cu->ctf_fp, id), 0);

	if (type == NULL)
		return -ENOMEM;

	type->namespace.tag.type = tp->type;
	cu__add_tag_with_id(cu, &type->namespace.tag, id);

	return 0;
}

static int create_new_variable(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct btf_var *bvar = btf_var(tp);
	struct variable *var = variable__new(ctf_type_aname(cu->ctf_fp, id), bvar->linkage);

	if (var == NULL)
		return -ENOMEM;

	var->ip.tag.type = tp->type;
	cu__add_tag_with_id(cu, &var->ip.tag, id);
	return 0;
}

static int create_new_datasec(struct cu *cu __maybe_unused, const struct btf_type *tp __maybe_unused, uint32_t id __maybe_unused)
{
	//cu__add_tag_with_id(cu, &datasec->tag, id);

	/*
	 * FIXME: this will not be used to reconstruct some original C code,
	 * its about runtime placement of variables so just ignore this for now
	 */
	return 0;
}

static int create_new_tag(struct cu *cu, int type, const struct btf_type *tp, uint32_t id)
{
	struct tag *tag = zalloc(sizeof(*tag));

	if (tag == NULL)
		return -ENOMEM;

	switch (type) {
	case BTF_KIND_CONST:	tag->tag = DW_TAG_const_type;	   break;
	case BTF_KIND_PTR:	tag->tag = DW_TAG_pointer_type;    break;
	case BTF_KIND_RESTRICT:	tag->tag = DW_TAG_restrict_type;   break;
	case BTF_KIND_VOLATILE:	tag->tag = DW_TAG_volatile_type;   break;
	case BTF_KIND_TYPE_TAG:	tag->tag = DW_TAG_LLVM_annotation; break;
	default:
		free(tag);
		fprintf(stderr, "%s: Unknown type %d\n\n", __func__, type);
		return 0;
	}

	tag->type = tp->type;
	cu__add_tag_with_id(cu, tag, id);

	return 0;
}

static struct attributes *attributes__realloc(struct attributes *attributes, const char *value)
{
	struct attributes *result;
	uint64_t cnt;
	size_t sz;

	cnt = attributes ? attributes->cnt : 0;
	sz = sizeof(*attributes) + (cnt + 1) * sizeof(*attributes->values);
	result = realloc(attributes, sz);
	if (!result)
		return NULL;
	if (!attributes)
		result->cnt = 0;
	result->values[cnt] = value;
	result->cnt++;
	return result;
}

static int process_decl_tag(struct cu *cu, const struct btf_type *tp, uint32_t id)
{
	struct tag *tag = cu__type(cu, tp->type);
	struct attributes *tmp;

	if (tag == NULL)
		tag = cu__function(cu, tp->type);

	if (tag == NULL)
		tag = cu__tag(cu, tp->type);

	if (tag == NULL) {
		fprintf(stderr, "WARNING: BTF_KIND_DECL_TAG for unknown BTF id %d\n", tp->type);
		return 0;
	}

	const char *attribute = ctf_type_aname(cu->ctf_fp, id);
	tmp = attributes__realloc(tag->attributes, attribute);
	if (!tmp)
		return -ENOMEM;

	tag->attributes = tmp;

	return 0;
}

static int libctf__load_types(struct cu *cu, ctf_dict_t *fp)
{
	ctf_id_t type_id;
	ctf_next_t *i = NULL;
	
	int err;

	while ((type_id = ctf_type_next(fp, &i, NULL, 1)) != CTF_ERR)
	{
		int kind = ctf_type_kind(fp, type_id);
		const struct btf_type *type_ptr = (const struct btf_type *) ctf_type_data(fp, type_id, 0);

		switch (kind) {
		case BTF_KIND_INT:
			err = create_new_int_type(cu, type_ptr, type_id);
			break;
		case BTF_KIND_ARRAY:
			err = create_new_array(cu, type_ptr, type_id);
			break;
		case BTF_KIND_STRUCT:
			err = create_new_class(cu, type_ptr, type_id);
			break;
		case BTF_KIND_UNION:
			err = create_new_union(cu, type_ptr, type_id);
			break;
		case BTF_KIND_ENUM:
			err = create_new_enumeration(cu, type_ptr, type_id);
			break;
		case BTF_KIND_ENUM64:
			err = create_new_enumeration64(cu, type_ptr, type_id);
			break;
		case BTF_KIND_FWD:
			err = create_new_forward_decl(cu, type_ptr, type_id);
			break;
		case BTF_KIND_TYPEDEF:
			err = create_new_typedef(cu, type_ptr, type_id);
			break;
		case BTF_KIND_VAR:
			err = create_new_variable(cu, type_ptr, type_id);
			break;
		case BTF_KIND_DATASEC:
			err = create_new_datasec(cu, type_ptr, type_id);
			break;
		case BTF_KIND_VOLATILE:
		case BTF_KIND_PTR:
		case BTF_KIND_CONST:
		case BTF_KIND_RESTRICT:
		/* For type tag it's a bit of a lie.
		 * In DWARF it is encoded as a child tag of whatever type it
		 * applies to. Here we load it as a standalone tag with a pointer
		 * to a next type only to have a valid ID in the types table.
		 */
		case BTF_KIND_TYPE_TAG:
			err = create_new_tag(cu, kind, type_ptr, type_id);
			break;
		case BTF_KIND_UNKN:
			cu__table_nullify_type_entry(cu, type_id);
			fprintf(stderr, "libctf: id: %ld, Unknown kind %d\n", type_id, kind);
			fflush(stderr);
			err = 0;
			break;
		case BTF_KIND_FUNC_PROTO:
			err = create_new_subroutine_type(cu, type_ptr, type_id);
			break;
		case BTF_KIND_FUNC:
			// BTF_KIND_FUNC corresponding to a defined subprogram.
			err = create_new_function(cu, type_ptr, type_id);
			break;
		case BTF_KIND_FLOAT:
			err = create_new_float_type(cu, type_ptr, type_id);
			break;
		case BTF_KIND_DECL_TAG:
			err = process_decl_tag(cu, type_ptr, type_id);
			break;
		default:
			fprintf(stderr, "libctf: id: %ld, Unknown kind %d\n", type_id, kind);
			fflush(stderr);
			err = 0;
			break;
		}

		if (err < 0)
			return err;
	}
	return 0;
}

static void libctf__cu_delete(struct cu *cu)
{
	btf__free(cu->priv);
	cu->priv = NULL;
}

static int libbpf_log(enum libbpf_print_level level __maybe_unused, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

struct debug_fmt_ops libctf__ops;

static int cus__load_btf_libctf(struct cus *cus, struct conf_load *conf, const char *filename)
{
	ctf_dict_t *fp;
	ctf_archive_t *ctf;
	ctf_error_t err = -1;

	// Pass a zero for addr_size, we'll get it after we load via btf__pointer_size()
	struct cu *cu = cu__new(filename, 0, NULL, 0, filename, false);
	if (cu == NULL)
		return -1;

	// cu set up
	cu->language = LANG_C;
	cu->uses_global_strings = false;
	cu->dfops = &libctf__ops;

	libbpf_set_print(libbpf_log);

	// libctf opening procedure (parent)
	if ((ctf = ctf_open (filename, NULL, &err)) == NULL)
		goto open_err;
	if ((fp = ctf_dict_open (ctf, NULL, &err)) == NULL)
		goto open_err;

	// hold the dict for the cu
	cu->ctf_fp = fp;

	err = libctf__load_types(cu, fp);
	if (err != 0)
		goto out_free;

	/*
	 * The app stole this cu, possibly deleting it,
	 * so forget about it
	 */
	if (conf && conf->steal && conf->steal(cu, conf))
		return 0;

	// add newly created cu
	cus__add(cus, cu);
	return err;

out_free:
	cu__delete(cu); // will call btf__free(cu->priv);
	return err;
open_err:
	fprintf (stderr, "%s: cannot open: %s\n", filename, ctf_errmsg (err));
	return -1;
}

struct debug_fmt_ops libctf__ops = {
	.name		= "libctf",
	.load_file	= cus__load_btf_libctf,
	.cu__delete	= libctf__cu_delete,
};
