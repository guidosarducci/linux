/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ASM_EXTABLE_H
#define __ASM_EXTABLE_H

#include <asm/byteorder.h>

/*
 * The typical exception table consists of pairs of addresses: the first
 * is the address of an instruction that is allowed to fault, and the
 * second is the fixup address at which the program should continue. No
 * registers are modified in this case, so it is entirely up to the
 * continuation code to figure out what to do.
 *
 * Newer typed exceptions are supported by replacing the second address
 * with fields indicating a typed exception, the handler type invoked and
 * the type-specific data available to it. Since ARM insn addresses are
 * minimum 2-byte aligned, the LSB is_type flag is zero when a valid fixup
 * address is set. This scheme is backwards compatible while allowing
 * considerable flexibility in actions taken by continuation code.
 *
 * All the routines below use bits of fixup code that are out of line
 * with the main instruction path.  This means when everything is well,
 * we don't even have to jump over them.  Further, they do not intrude
 * on our cache or tlb entries.
 */

struct exception_table_entry
{
	unsigned long insn;
	union {
		unsigned long fixup;
		struct {
#if defined(__LITTLE_ENDIAN_BITFIELD)
			unsigned long	is_typed: 1,
					type:	  3,
					data:	 28;
#elif defined (__BIG_ENDIAN_BITFIELD)
			unsigned long	data:	 28,
					type:	  3,
					is_typed: 1;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
		};
	};
};

#ifdef CONFIG_BPF_JIT
bool ex_handler_bpf(const struct exception_table_entry *ex,
		    struct pt_regs *regs);
#else /* !CONFIG_BPF_JIT */
static inline
bool ex_handler_bpf(const struct exception_table_entry *ex,
		    struct pt_regs *regs)
{
	return false;
}
#endif /* !CONFIG_BPF_JIT */

extern bool fixup_exception(struct pt_regs *regs);
#endif
