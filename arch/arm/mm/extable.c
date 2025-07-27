// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/arch/arm/mm/extable.c
 */
#include <linux/extable.h>
#include <linux/uaccess.h>

#include <asm/asm-extable.h>

static bool ex_handler_untyped(const struct exception_table_entry *ex,
			       struct pt_regs *regs)
{
	regs->ARM_pc = ex->fixup;
#ifdef CONFIG_THUMB2_KERNEL
	/* Clear the IT state to avoid nasty surprises in the fixup */
	regs->ARM_cpsr &= ~PSR_IT_MASK;
#endif
	return true;
}

bool fixup_exception(struct pt_regs *regs)
{
	const struct exception_table_entry *ex;

	ex = search_exception_tables(instruction_pointer(regs));
	if (!ex)
		return false;

	if (!ex->is_typed)
		return ex_handler_untyped(ex, regs);

	switch (ex->type) {
	case EX_TYPE_BPF:
		return ex_handler_bpf(ex, regs);
	}

	BUG();
}
