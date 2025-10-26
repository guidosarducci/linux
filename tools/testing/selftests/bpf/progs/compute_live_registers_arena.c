// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include "bpf_arena_common.h"
#include "bpf_misc.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARENA);
	__uint(map_flags, BPF_F_MMAPABLE);
	__uint(max_entries, 1);
} arena SEC(".maps");

#ifdef __BPF_FEATURE_ADDR_SPACE_CAST
SEC("?fentry.s/" SYS_PREFIX "sys_getpgid")
__log_level(2)
__msg(" 6: .12345.... (85) call bpf_arena_alloc_pages")
__msg(" 7: 0......... (bf) r1 = addr_space_cast(r0, 0, 1)")
__msg(" 8: .1........ (b7) r2 = 42")
__naked void addr_space_cast(void)
{
	asm volatile (
		"r1 = %[arena] ll;"
		"r2 = 0;"
		"r3 = 1;"
		"r4 = 0;"
		"r5 = 0;"
		"call %[bpf_arena_alloc_pages];"
		"r1 = addr_space_cast(r0, 0, 1);"
		"r2 = 42;"
		"*(u64 *)(r1 +0) = r2;"
		"r0 = 0;"
		"exit;"
		:
		: __imm(bpf_arena_alloc_pages),
		  __imm_addr(arena)
		: __clobber_all);
}
#endif

/* to retain debug info for BTF generation */
void kfunc_root(void)
{
	bpf_arena_alloc_pages(0, 0, 0, 0, 0);
}

char _license[] SEC("license") = "GPL";

