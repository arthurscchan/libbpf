// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2026 Libbpf-fuzz contributors */
/*
 * linker-fuzzer: drives libbpf's static linker (src/linker.c) with an
 * attacker-controlled BPF ELF object buffer.
 *
 * Threat model: `bpftool gen object out.o in1.o in2.o ...` feeds object
 * files that may come from untrusted sources into bpf_linker__add_buf().
 * The linker parses ELF sections, merges BTF from multiple inputs,
 * resolves symbols and applies relocations across files; all of that
 * must survive malformed or adversarial object files.
 */

#include "libbpf.h"

#include <stddef.h>
#include <stdint.h>

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	DECLARE_LIBBPF_OPTS(bpf_linker_opts, opts);

	if (size == 0)
		return 0;

	libbpf_set_print(libbpf_print_fn);

	struct bpf_linker *lnk = bpf_linker__new("/tmp/fuzz-linker-out.bpf.o", &opts);
	if (!lnk)
		return 0;

	if (bpf_linker__add_buf(lnk, (void *)data, size, NULL) == 0)
		bpf_linker__finalize(lnk);

	bpf_linker__free(lnk);
	return 0;
}
