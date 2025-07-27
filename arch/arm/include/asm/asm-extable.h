/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __ASM_ASM_EXTABLE_H
#define __ASM_ASM_EXTABLE_H

#include <linux/bits.h>

#define EX_TYPE_BPF		0

/* Data fields for EX_TYPE_BPF */
#define EX_DATA_FIX_OFF		GENMASK_U8(3, 0) /* pc forward offset */
#define EX_DATA_REG		GENMASK_U8(7, 4) /* base ARM reg to clear */
#define EX_DATA_RD_FLAG		BIT(8)		 /* flag reg pair e.g LDRD */


#endif /* __ASM_ASM_EXTABLE_H */
