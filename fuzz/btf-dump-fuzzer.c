// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Libbpf-fuzz contributors */
/*
 * btf-dump-fuzzer: drives libbpf's BTF -> C declaration dumper
 * (src/btf_dump.c) with attacker-controlled BTF.
 *
 * Threat model: BTF blobs travel inside BPF ELF objects produced by
 * untrusted toolchains and are later fed to `bpftool btf dump file`
 * (btf_dump__*).  A malformed type graph (self-referencing composites,
 * bogus type ids, huge array nelems, anonymous chains) must not corrupt
 * memory while the declaration emitter walks it.
 *
 * Input is either a full BPF ELF object (bpf_object__open_mem, then take
 * its .BTF) or a raw .BTF section blob (detected by the 0xeb9f magic),
 * which lets the mutator focus on the type section itself.
 */

#include "btf.h"
#include "libbpf.h"

#include <stddef.h>
#include <stdint.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return 0;
}

/* Drain all btf_dump output; we only care about the walking, not the text. */
static void dump_printf_fn(void *ctx, const char *fmt, va_list args)
{
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	LIBBPF_OPTS(btf_dump_type_data_opts, data_opts);
	struct bpf_object *obj = NULL;
	struct btf_dump *d = NULL;
	struct btf *btf = NULL;
	__u32 nr_types, data_limit, i;

	libbpf_set_print(libbpf_print_fn);

	if (size >= 2 && data[0] == 0x9f && data[1] == 0xeb) {
		/* raw .BTF section blob */
		btf = btf__new(data, size);
		if (libbpf_get_error(btf))
			return 0;
	} else {
		opts.object_name = "fuzz-object";
		obj = bpf_object__open_mem(data, size, &opts);
		if (libbpf_get_error(obj))
			return 0;
		btf = bpf_object__btf(obj);
		if (btf == NULL) {
			bpf_object__close(obj);
			return 0;
		}
	}

	d = btf_dump__new(btf, dump_printf_fn, NULL, NULL);
	if (libbpf_get_error(d))
		goto out;

	/* Pass 1: emit a C declaration for every type id. */
	nr_types = btf__type_cnt(btf);
	for (i = 1; i < nr_types; i++)
		btf_dump__dump_type(d, i);

	btf_dump__free(d);
	d = NULL;

	/* Pass 2: formatted data output, restricted to scalar top-level
	 * types (INT, PTR, ENUM, ENUM64) using the raw input as the data
	 * buffer.  Composites and arrays are excluded: data dumping
	 * iterates once per array element / member, and nelems as well as
	 * element size (resolvable to 0 for malformed element types) are
	 * attacker-controlled, so a single fuzzed type can exceed any
	 * timeout (observed: struct member arrays with huge nelems).
	 * Declaration dumping above still covers every type.
	 */
	d = btf_dump__new(btf, dump_printf_fn, NULL, NULL);
	if (libbpf_get_error(d))
		goto out;

	data_limit = nr_types < 32 ? nr_types : 32;
	for (i = 1; i < data_limit; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		__u16 kind;

		if (!t)
			continue;
		kind = btf_kind(t);
		if (kind != BTF_KIND_INT && kind != BTF_KIND_PTR &&
		    kind != BTF_KIND_ENUM && kind != BTF_KIND_ENUM64)
			continue;
		btf_dump__dump_type_data(d, i, data, size, &data_opts);
	}

out:
	if (d)
		btf_dump__free(d);
	if (obj)
		bpf_object__close(obj);	/* frees the object's BTF */
	else
		btf__free(btf);
	return 0;
}
