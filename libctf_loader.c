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
#include <assert.h> // Paranoia check: remove
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

static void libctf__errwarn(ctf_dict_t *fp)
{
	ctf_next_t *it = NULL;
	char *errtext;
	ctf_error_t err;

	/* Dump accumulated errors and warnings.  */
	while ((errtext = ctf_errwarning_next(fp, &it, NULL, &err)) != NULL) {
		fprintf(stderr, "libctf: %s", errtext);
		free(errtext);
	}
	if (err != ECTF_NEXT_END)
		fprintf(stderr, "libctf error: cannot get CTF errors: %s",
			ctf_errmsg(err));
}

static int libctf__collect_kfuncs(ctf_dict_t *ctf, Elf *elf)
{
	struct gobuffer btf_kfunc_ranges = {};
	Elf_Data *symbols = NULL;
	Elf_Data *idlist = NULL;
	Elf_Scn *symscn = NULL;
	int symbols_shndx = -1;
	size_t idlist_addr = 0;
	int err = -1;
	int idlist_shndx = -1;
	size_t strtabidx = 0;
	Elf_Scn *scn = NULL;
	Elf *elf = NULL;
	GElf_Shdr shdr;
	size_t strndx;
	char *secname;
	int nr_syms;
	int i = 0;

	if (elf_version(EV_CURRENT) == EV_NONE) {
		elf_error("Cannot set libelf version");
		goto out;
	}

	/* Locate symbol table and .BTF_ids sections */
	if (elf_getshdrstrndx(elf, &strndx) < 0)
		goto out;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		Elf_Data *data;

		i++;
		if (!gelf_getshdr(scn, &shdr)) {
			elf_error("Failed to get ELF section(%d) hdr", i);
			goto out;
		}

		secname = elf_strptr(elf, strndx, shdr.sh_name);
		if (!secname) {
			elf_error("Failed to get ELF section(%d) hdr name", i);
			goto out;
		}

		if (shdr.sh_type == SHT_SYMTAB) {
			data = elf_getdata(scn, 0);
			if (!data) {
				elf_error("Failed to get ELF section(%d) data", i);
				goto out;
			}

			symbols_shndx = i;
			symscn = scn;
			symbols = data;
			strtabidx = shdr.sh_link;
		} else if (!strcmp(secname, BTF_IDS_SECTION)) {
			/* .BTF_ids section consists of uint32_t elements,
			 * and thus might need byte order conversion.
			 * However, it has type PROGBITS, hence elf_getdata()
			 * won't automatically do the conversion.
			 * Use elf_getdata_rawchunk() instead,
			 * ELF_T_WORD tells it to do the necessary conversion.
			 */
			data = elf_getdata_rawchunk(elf, shdr.sh_offset, shdr.sh_size, ELF_T_WORD);
			if (!data) {
				elf_error("Failed to get %s ELF section(%d) data",
					  BTF_IDS_SECTION, i);
				goto out;
			}

			idlist_shndx = i;
			idlist_addr = shdr.sh_addr;
			idlist = data;
		}
	}

	/* Cannot resolve symbol or .BTF_ids sections. Nothing to do. */
	if (symbols_shndx == -1 || idlist_shndx == -1) {
		err = 0;
		goto out;
	}

	if (!gelf_getshdr(symscn, &shdr)) {
		elf_error("Failed to get ELF symbol table header");
		goto out;
	}
	nr_syms = shdr.sh_size / shdr.sh_entsize;

	/* First collect all kfunc set ranges.
	 *
	 * Note we choose not to sort these ranges and accept a linear
	 * search when doing lookups. Reasoning is that the number of
	 * sets is ~O(100) and not worth the additional code to optimize.
	 */
	for (i = 0; i < nr_syms; i++) {
		struct btf_kfunc_set_range range = {};
		const char *name;
		GElf_Sym sym;

		if (!gelf_getsym(symbols, i, &sym)) {
			elf_error("Failed to get ELF symbol(%d)", i);
			goto out;
		}

		if (sym.st_shndx != idlist_shndx)
			continue;

		name = elf_strptr(elf, strtabidx, sym.st_name);
		if (!is_sym_kfunc_set(&sym, name, idlist, idlist_addr))
			continue;

		range.start = sym.st_value;
		range.end = sym.st_value + sym.st_size;
		gobuffer__add(&btf_kfunc_ranges, &range, sizeof(range));
	}

	/* Now inject BTF with kfunc decl tag for detected kfuncs */
	for (i = 0; i < nr_syms; i++) {
		const struct btf_kfunc_set_range *ranges;
		const struct btf_id_and_flag *pair;
		ctf_id_t elf_fn;
		unsigned int ranges_cnt;
		char *func, *name;
		ptrdiff_t off;
		GElf_Sym sym;
		bool found;
		int j;

		if (!gelf_getsym(symbols, i, &sym)) {
			elf_error("Failed to get ELF symbol(%d)", i);
			goto out;
		}

		if (sym.st_shndx != idlist_shndx)
			continue;

		name = elf_strptr(elf, strtabidx, sym.st_name);
		func = get_func_name(name);
		if (!func)
			continue;

		/* Check if function belongs to a kfunc set */
		ranges = gobuffer__entries(&btf_kfunc_ranges);
		ranges_cnt = gobuffer__nr_entries(&btf_kfunc_ranges);
		found = false;
		for (j = 0; j < ranges_cnt; j++) {
			size_t addr = sym.st_value;

			if (ranges[j].start <= addr && addr < ranges[j].end) {
				found = true;
				off = addr - idlist_addr;
				if (off < 0 || off + sizeof(*pair) > idlist->d_size) {
					fprintf(stderr, "%s: kfunc '%s' offset outside section '%s'\n",
						__func__, func, BTF_IDS_SECTION);
					free(func);
					goto out;
				}
				pair = idlist->d_buf + off;
				break;
			}
		}
		if (!found) {
			free(func);
			continue;
		}

		elf_fn = ctf_lookup_by_name (ctf, func);
		if (elf_fn != CTF_ERR && ctf_type_kind (elf_fn) != BTF_KIND_FUNC) {
			elf_fn->kfusnc = true;
			elf_fn->kfunc_flags = pair->flags;
		}
		free(func);
	}

	err = 0;
out:
	__gobuffer__delete(&btf_kfunc_ranges);
	return err;
}

static int cus__load_btf_libctf(struct cus *cus, struct conf_load *conf, const char *filename)
{
	ctf_dict_t *input_dict = NULL, *link = NULL, *fp, *against_dict = NULL;
	ctf_archive_t *ctf, *against = NULL, *linked;
	ctf_error_t err = -1;
	int fd;
	unsigned char *out;
	ctf_sect_t s = {0};
	int is_btf;
	Elf *elf = NULL;

	// Pass a zero for addr_size, we'll get it after we load via btf__pointer_size()
	struct cu *cu = cu__new(filename, 0, NULL, 0, filename, false);
	if (cu == NULL)
		return -1;

	elf_version(EV_CURRENT);
	fd = open(filename, O_RDONLY);
        elf = elf_begin(fd, ELF_C_READ, NULL);

        // cu set up
	cu->language = LANG_C;
	cu->uses_global_strings = false;
	cu->dfops = &libctf__ops;
	cu->elf = elf;

	libbpf_set_print(libbpf_log);

	// libctf opening procedure
	if ((ctf = ctf_fdopen(fd, filename, NULL, &err)) == NULL)
		goto open_err;

	// Kludgy as hell dedup-against-parent code.  Should use an arg, not
	// an env var.

	// Set the default output format to BTF: make sure libctf
	// supports the same version of BTF as pahole.

	if (ctf_version(0, sizeof(struct btf_header), LIBCTF_BTM_BTF) < 0)
		goto ctf_err;

	if ((link = ctf_create(NULL, &err)) == NULL)
		goto create_err;

	if ((input_dict = ctf_dict_open(ctf, NULL, &err)) == NULL)
		goto kfunc_err;

	if (libctf_collect_kfuncs(input_dict, elf) < 0)
		goto kfunc_err;

	// BTF is less strict about duplicate enums than CTF.
	if (ctf_dict_set_flag(link, CTF_STRICT_NO_DUP_ENUMERATORS, 0) < 0)
		goto link_err;

	if (getenv("PAHOLE_AGAINST") != NULL) {

		if ((against = ctf_open(getenv("PAHOLE_AGAINST"), NULL, &err)) == NULL) {
			filename = getenv("PAHOLE_AGAINST");
			goto open_err;
		}

		// Deduplicate.
		if ((ctf_link_against(link, against, ctf, filename,
				      CTF_LINK_SHARE_DUPLICATED)) < 0)
			goto link_err;
	} else {
		// Deduplicate.
		if (ctf_link_add(link, ctf, filename, NULL) < 0)
			goto link_err;

		if ((ctf_link(link, CTF_LINK_SHARE_UNCONFLICTED)) < 0)
			goto link_err;
	}

	/*
	 * Serialize the deduplicated dict to lower it to BTF, close
	 * everything, then open it again.
	 */

	if ((out = ctf_link_write(link, &s.cts_size, (size_t) -1,
				  &is_btf)) == NULL)
		goto link_err;

	/* Temporary paranoia check, XXX remove.  */
	assert (is_btf);

	ctf_dict_close(input_dict);
	ctf_dict_close(link);
	ctf_arc_close(against);
	ctf_arc_close(ctf);

	s.cts_data = (void *) out;

	if (getenv("PAHOLE_AGAINST") != NULL) {
		if ((against_dict = ctf_dict_open(against, NULL,
						  &err)) == NULL)
			goto open_err;
	}

	if ((linked = ctf_arc_bufopen(&s, NULL, NULL,
				      &err)) == NULL)
		goto open_err;

	if (ctf_arc_set_parent(linked, against_dict) < 0)
		goto open_err;

	/*
	 * For now, just look at the first dict in the archive: unambiguous,
	 * unconflicting types.
	 */
	if ((fp = ctf_dict_open(linked, NULL, &err)) == NULL)
		goto open_err;

	ctf_dict_close(against_dict);

	close(fd);
	elf_end(elf);
	return err;

out_free:
	cu__delete(cu); // will call btf__free(cu->priv);
	close(fd);
	if(elf)
		elf_end(elf);
	return err;
ctf_err:
	fprintf(stderr, "%s: ctf error: %s\n", filename, ctf_errmsg(err));
	libctf__errwarn(NULL);
	close(fd);
	if(elf)
		elf_end(elf);
	return -1;
link_err:
	fprintf(stderr, "%s: ctf error deduplicating: %s\n", filename, ctf_errmsg(ctf_errno(link)));
	libctf__errwarn(link);
	ctf_dict_close(link);
	ctf_arc_close(against);
	/* Fall through. */
kfunc_err:
	ctf_dict_close(input_dict);
	ctf_arc_close(ctf);
	close(fd);
	if(elf)
		elf_end(elf);
	return -1;
create_err:
	fprintf(stderr, "%s: cannot create dict for linking purposes: %s\n",
		filename, ctf_errmsg(err));
	libctf__errwarn(NULL);
	close(fd);
	if(elf)
		elf_end(elf);
	return -1;
open_err:
	fprintf(stderr, "%s: cannot open: %s\n", filename, ctf_errmsg(err));
	libctf__errwarn(NULL);
	close(fd);
	if(elf)
		elf_end(elf);
	return -1;
}

struct debug_fmt_ops libctf__ops = {
	.name		= "libctf",
	.load_file	= cus__load_btf_libctf,
	.cu__delete	= libctf__cu_delete,
};
