// SPDX-License-Identifier: GPL-2.0-only
/*
 * Just-In-Time compiler for eBPF filters on MIPS32
 * Copyright (c) 2021 Tony Ambardar <Tony.Ambardar@gmail.com>
 *
 * Based on code from:
 *
 * Copyright (c) 2017 Cavium, Inc.
 * Author: David Daney <david.daney@cavium.com>
 *
 * Copyright (c) 2014 Imagination Technologies Ltd.
 * Author: Markos Chandras <markos.chandras@imgtec.com>
 */

#include <linux/errno.h>
#include <linux/filter.h>
#include <asm/uasm.h>

#include "ebpf_jit.h"

static int gen_imm_insn(const struct bpf_insn *insn, struct jit_ctx *ctx,
			int idx)
{
	int dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
	int upper_bound, lower_bound, shamt;
	int imm = insn->imm;

	if (dst < 0)
		return dst;

	switch (BPF_OP(insn->code)) {
	case BPF_MOV:
	case BPF_ADD:
		upper_bound = S16_MAX;
		lower_bound = S16_MIN;
		break;
	case BPF_SUB:
		upper_bound = -(int)S16_MIN;
		lower_bound = -(int)S16_MAX;
		break;
	case BPF_AND:
	case BPF_OR:
	case BPF_XOR:
		upper_bound = 0xffff;
		lower_bound = 0;
		break;
	case BPF_RSH:
	case BPF_LSH:
	case BPF_ARSH:
		/* Shift amounts are truncated, no need for bounds */
		upper_bound = S32_MAX;
		lower_bound = S32_MIN;
		break;
	default:
		return -EINVAL;
	}

	/*
	 * Immediate move clobbers the register, so no sign/zero
	 * extension needed.
	 */
	if (lower_bound <= imm && imm <= upper_bound) {
		/* single insn immediate case */
		switch (BPF_OP(insn->code) | BPF_CLASS(insn->code)) {
		case BPF_ALU64 | BPF_MOV:
			emit_instr(ctx, addiu, LO(dst), MIPS_R_ZERO, imm);
			if (imm < 0)
				gen_signext_insn(dst, ctx);
			else
				gen_zext_insn(dst, true, ctx);
			break;
		case BPF_ALU | BPF_MOV:
			emit_instr(ctx, addiu, LO(dst), MIPS_R_ZERO, imm);
			break;
		case BPF_ALU64 | BPF_AND:
			if (imm >= 0)
				gen_zext_insn(dst, true, ctx);
			fallthrough;
		case BPF_ALU | BPF_AND:
			emit_instr(ctx, andi, LO(dst), LO(dst), imm);
			break;
		case BPF_ALU64 | BPF_OR:
			if (imm < 0)
				emit_instr(ctx, nor, HI(dst),
						MIPS_R_ZERO, MIPS_R_ZERO);
			fallthrough;
		case BPF_ALU | BPF_OR:
			emit_instr(ctx, ori, LO(dst), LO(dst), imm);
			break;
		case BPF_ALU64 | BPF_XOR:
			if (imm < 0)
				emit_instr(ctx, nor, HI(dst),
							HI(dst), MIPS_R_ZERO);
			fallthrough;
		case BPF_ALU | BPF_XOR:
			emit_instr(ctx, xori, LO(dst), LO(dst), imm);
			break;
		case BPF_ALU64 | BPF_ADD:
			emit_instr(ctx, addiu, LO(dst), LO(dst), imm);
			if (imm < 0)
				emit_instr(ctx, addiu, HI(dst), HI(dst), -1);
			emit_instr(ctx, sltiu, MIPS_R_AT, LO(dst), imm);
			/* sltu sets all bits 1 in R6 ISA i.e. == -1 */
			if (MIPS_ISA_REV >= 6)
				emit_instr(ctx, subu, HI(dst),
							HI(dst), MIPS_R_AT);
			else
				emit_instr(ctx, addu, HI(dst),
							HI(dst), MIPS_R_AT);
			break;
		case BPF_ALU64 | BPF_SUB:
			emit_instr(ctx, addiu, MIPS_R_AT, LO(dst), -imm);
			if (imm < 0)
				emit_instr(ctx, addiu, HI(dst), HI(dst), 1);
			emit_instr(ctx, sltu, MIPS_R_AT, LO(dst), MIPS_R_AT);
			/* sltu sets all bits 1 in R6 ISA i.e. == -1 */
			if (MIPS_ISA_REV >= 6)
				emit_instr(ctx, addu, HI(dst),
							HI(dst), MIPS_R_AT);
			else
				emit_instr(ctx, subu, HI(dst),
							HI(dst), MIPS_R_AT);
			emit_instr(ctx, addiu, LO(dst), LO(dst), -imm);
			break;
		case BPF_ALU64 | BPF_ARSH:
			shamt = imm & 0x3f;
			if (shamt >= 32) {
				emit_instr(ctx, sra, LO(dst),
							HI(dst), shamt - 32);
				emit_instr(ctx, sra, HI(dst), HI(dst), 31);
			} else if (shamt > 0) {
				emit_instr(ctx, srl, LO(dst), LO(dst), shamt);
				emit_instr(ctx, ins, LO(dst), HI(dst),
							32 - shamt, shamt);
				emit_instr(ctx, sra, HI(dst), HI(dst), shamt);
			}
			break;
		case BPF_ALU64 | BPF_RSH:
			shamt = imm & 0x3f;
			if (shamt >= 32) {
				emit_instr(ctx, srl, LO(dst),
							HI(dst), shamt - 32);
				emit_instr(ctx, and, HI(dst),
							HI(dst), MIPS_R_ZERO);
			} else if (shamt > 0) {
				emit_instr(ctx, srl, LO(dst), LO(dst), shamt);
				emit_instr(ctx, ins, LO(dst), HI(dst),
							32 - shamt, shamt);
				emit_instr(ctx, srl, HI(dst), HI(dst), shamt);
			}
			break;
		case BPF_ALU64 | BPF_LSH:
			shamt = imm & 0x3f;
			if (shamt >= 32) {
				emit_instr(ctx, sll, HI(dst),
							LO(dst), shamt - 32);
				emit_instr(ctx, and, LO(dst),
							LO(dst), MIPS_R_ZERO);
			} else if (shamt > 0) {
				emit_instr(ctx, srl, MIPS_R_AT,
							LO(dst), 32 - shamt);
				emit_instr(ctx, sll, HI(dst), HI(dst), shamt);
				emit_instr(ctx, sll, LO(dst), LO(dst), shamt);
				emit_instr(ctx, or, HI(dst),
							HI(dst), MIPS_R_AT);
			}
			break;
		case BPF_ALU | BPF_RSH:
			emit_instr(ctx, srl, LO(dst), LO(dst), imm & 0x1f);
			break;
		case BPF_ALU | BPF_LSH:
			emit_instr(ctx, sll, LO(dst), LO(dst), imm & 0x1f);
			break;
		case BPF_ALU | BPF_ARSH:
			emit_instr(ctx, sra, LO(dst), LO(dst), imm & 0x1f);
			break;
		case BPF_ALU | BPF_ADD:
			emit_instr(ctx, addiu, LO(dst), LO(dst), imm);
			break;
		case BPF_ALU | BPF_SUB:
			emit_instr(ctx, addiu, LO(dst), LO(dst), -imm);
			break;
		default:
			return -EINVAL;
		}
	} else {
		/* multi insn immediate case */
		if (BPF_OP(insn->code) == BPF_MOV) {
			gen_imm_to_reg(insn, LO(dst), ctx);
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				gen_signext_insn(dst, ctx);
		} else {
			gen_imm_to_reg(insn, MIPS_R_AT, ctx);
			switch (BPF_OP(insn->code) | BPF_CLASS(insn->code)) {
			case BPF_ALU64 | BPF_AND:
				if (imm >= 0)
					gen_zext_insn(dst, true, ctx);
				fallthrough;
			case BPF_ALU | BPF_AND:
				emit_instr(ctx, and, LO(dst), LO(dst),
								MIPS_R_AT);
				break;
			case BPF_ALU64 | BPF_OR:
				if (imm < 0)
					emit_instr(ctx, nor, HI(dst),
						MIPS_R_ZERO, MIPS_R_ZERO);
			fallthrough;
			case BPF_ALU | BPF_OR:
				emit_instr(ctx, or, LO(dst), LO(dst),
								MIPS_R_AT);
				break;
			case BPF_ALU64 | BPF_XOR:
				if (imm < 0)
					emit_instr(ctx, nor, HI(dst),
							HI(dst), MIPS_R_ZERO);
			fallthrough;
			case BPF_ALU | BPF_XOR:
				emit_instr(ctx, xor, LO(dst), LO(dst),
								MIPS_R_AT);
				break;
			case BPF_ALU64 | BPF_ADD:
				emit_instr(ctx, addu, LO(dst),
							LO(dst), MIPS_R_AT);
				if (imm < 0)
					emit_instr(ctx, addiu, HI(dst), HI(dst), -1);
				emit_instr(ctx, sltu, MIPS_R_AT,
							LO(dst), MIPS_R_AT);
				/* sltu sets all bits 1 in R6 ISA i.e. == -1 */
				if (MIPS_ISA_REV >= 6)
					emit_instr(ctx, subu, HI(dst),
							HI(dst), MIPS_R_AT);
				else
					emit_instr(ctx, addu, HI(dst),
							HI(dst), MIPS_R_AT);
				break;
			case BPF_ALU64 | BPF_SUB:
				emit_instr(ctx, subu, LO(dst),
							LO(dst), MIPS_R_AT);
				if (imm < 0)
					emit_instr(ctx, addiu, HI(dst), HI(dst), 1);
				emit_instr(ctx, sltu, MIPS_R_AT,
							MIPS_R_AT, LO(dst));
				/* sltu sets all bits 1 in R6 ISA i.e. == -1 */
				if (MIPS_ISA_REV >= 6)
					emit_instr(ctx, addu, HI(dst),
							HI(dst), MIPS_R_AT);
				else
					emit_instr(ctx, subu, HI(dst),
							HI(dst), MIPS_R_AT);
				break;
			case BPF_ALU | BPF_ADD:
				emit_instr(ctx, addu, LO(dst), LO(dst),
								MIPS_R_AT);
				break;
			case BPF_ALU | BPF_SUB:
				emit_instr(ctx, subu, LO(dst), LO(dst),
								MIPS_R_AT);
				break;
			default:
				return -EINVAL;
			}
		}
	}

	return 0;
}

/* Returns the number of insn slots consumed. */
int build_one_insn(const struct bpf_insn *insn, struct jit_ctx *ctx,
			  int this_idx, int exit_idx)
{
	const int bpf_class = BPF_CLASS(insn->code);
	const int bpf_size = BPF_SIZE(insn->code);
	const int bpf_src = BPF_SRC(insn->code);
	const int bpf_op = BPF_OP(insn->code);
	int src, dst, r, mem_off, b_off;
	bool need_swap, did_move, cmp_eq;
	unsigned int target = 0;
	u64 t64u;
	s64 t64s;

	switch (insn->code) {
	case BPF_ALU64 | BPF_ADD | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_SUB | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_LSH | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_RSH | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_ARSH | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_XOR | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_MOV | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_OR | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_AND | BPF_K: /* ALU64_IMM */
	case BPF_ALU | BPF_MOV | BPF_K: /* ALU32_IMM */
	case BPF_ALU | BPF_ADD | BPF_K: /* ALU32_IMM */
	case BPF_ALU | BPF_SUB | BPF_K: /* ALU32_IMM */
	case BPF_ALU | BPF_OR | BPF_K: /* ALU32_IMM */
	case BPF_ALU | BPF_AND | BPF_K: /* ALU32_IMM */
	case BPF_ALU | BPF_LSH | BPF_K: /* ALU32_IMM */
	case BPF_ALU | BPF_RSH | BPF_K: /* ALU32_IMM */
	case BPF_ALU | BPF_XOR | BPF_K: /* ALU32_IMM */
	case BPF_ALU | BPF_ARSH | BPF_K: /* ALU32_IMM */
		r = gen_imm_insn(insn, ctx, this_idx);
		if (r < 0)
			return r;
		break;
	case BPF_ALU64 | BPF_MUL | BPF_K: /* ALU64_IMM */
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		if (insn->imm == 1) /* Mult by 1 is a nop */
			break;
		src = MIPS_R_T8; /* Use tmp reg pair for imm */
		gen_imm_to_reg(insn, LO(src), ctx);
		emit_instr(ctx, sra, HI(src), LO(src), 31);
		emit_instr(ctx, mul, HI(dst), HI(dst), LO(src));
		emit_instr(ctx, mul, MIPS_R_AT, LO(dst), HI(src));
		emit_instr(ctx, addu, HI(dst), HI(dst), MIPS_R_AT);
		if (MIPS_ISA_REV >= 6) {
			emit_instr(ctx, mulu, LO(dst), LO(dst), LO(src));
			emit_instr(ctx, muhu, MIPS_R_AT, LO(dst), LO(src));
		} else {
			emit_instr(ctx, multu, LO(dst), LO(src));
			emit_instr(ctx, mfhi, MIPS_R_AT);
			emit_instr(ctx, mflo, LO(dst));
		}
		emit_instr(ctx, addu, HI(dst), HI(dst), MIPS_R_AT);
		break;
	case BPF_ALU64 | BPF_NEG | BPF_K: /* ALU64_IMM */
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		emit_instr(ctx, subu, LO(dst), MIPS_R_ZERO, LO(dst));
		emit_instr(ctx, subu, HI(dst), MIPS_R_ZERO, HI(dst));
		emit_instr(ctx, sltu, MIPS_R_AT, MIPS_R_ZERO, LO(dst));
		/* sltu sets all bits 1 in R6 ISA i.e. == -1 */
		if (MIPS_ISA_REV >= 6)
			emit_instr(ctx, addu, HI(dst), HI(dst), MIPS_R_AT);
		else
			emit_instr(ctx, subu, HI(dst), HI(dst), MIPS_R_AT);
		break;
	case BPF_ALU | BPF_MUL | BPF_K: /* ALU_IMM */
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		if (insn->imm == 1) /* Mult by 1 is a nop */
			break;
		gen_imm_to_reg(insn, MIPS_R_AT, ctx);
		if (MIPS_ISA_REV >= 6) {
			emit_instr(ctx, mulu, LO(dst), LO(dst), MIPS_R_AT);
		} else {
			emit_instr(ctx, multu, LO(dst), MIPS_R_AT);
			emit_instr(ctx, mflo, LO(dst));
		}
		break;
	case BPF_ALU | BPF_NEG | BPF_K: /* ALU_IMM */
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		emit_instr(ctx, subu, LO(dst), MIPS_R_ZERO, LO(dst));
		break;
	case BPF_ALU | BPF_DIV | BPF_K: /* ALU_IMM */
	case BPF_ALU | BPF_MOD | BPF_K: /* ALU_IMM */
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		if (insn->imm == 1) {
			/* div by 1 is a nop, mod by 1 is zero */
			if (bpf_op == BPF_MOD)
				emit_instr(ctx, move, LO(dst), MIPS_R_ZERO);
			break;
		}
		gen_imm_to_reg(insn, MIPS_R_AT, ctx);
		if (MIPS_ISA_REV >= 6) {
			if (bpf_op == BPF_DIV)
				emit_instr(ctx, divu_r6, LO(dst),
							LO(dst), MIPS_R_AT);
			else
				emit_instr(ctx, modu, LO(dst),
							LO(dst), MIPS_R_AT);
			break;
		}
		emit_instr(ctx, divu, LO(dst), MIPS_R_AT);
		if (bpf_op == BPF_DIV)
			emit_instr(ctx, mflo, LO(dst));
		else
			emit_instr(ctx, mfhi, LO(dst));
		break;
	case BPF_ALU64 | BPF_DIV | BPF_K: /* ALU64_IMM */
	case BPF_ALU64 | BPF_MOD | BPF_K: /* ALU64_IMM */
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		/* div by 1 is a nop, mod by 1 is zero */
		if (insn->imm == 1) {
			if (bpf_op == BPF_MOD) {
				emit_instr(ctx, move, LO(dst), MIPS_R_ZERO);
				emit_instr(ctx, move, HI(dst), MIPS_R_ZERO);
			}
			break;
		}
		/* check for overflow and optimize div/mod by -1 */
		if (insn->imm == -1) {
			b_off = bpf_op == BPF_MOD ? 5 * 4 : 6 * 4;
			emit_instr(ctx, bnez, LO(dst), b_off);
			/* Delay slot */
			emit_instr(ctx, lui, MIPS_R_AT, -0x8000);
			emit_instr(ctx, bne, HI(dst), MIPS_R_AT, b_off - 2 * 4);
			emit_instr(ctx, nop);
			/* Overflow confirmed */
			if (bpf_op == BPF_MOD) {
				emit_instr(ctx, b, 3 * 4);
				emit_instr(ctx, nop);
			} else {
				emit_instr(ctx, move, LO(dst), MIPS_R_ZERO);
				emit_instr(ctx, b, 5 * 4);
				/* Delay slot */
				emit_instr(ctx, move, HI(dst), MIPS_R_ZERO);
			}
			/* div by -1 is neg, mod by -1 is zero */
			if (bpf_op == BPF_MOD) {
				emit_instr(ctx, move, LO(dst), MIPS_R_ZERO);
				emit_instr(ctx, move, HI(dst), MIPS_R_ZERO);
			} else {
				emit_instr(ctx, subu, LO(dst),
							MIPS_R_ZERO, LO(dst));
				emit_instr(ctx, subu, HI(dst),
							MIPS_R_ZERO, HI(dst));
				emit_instr(ctx, sltu, MIPS_R_AT,
							MIPS_R_ZERO, LO(dst));
				/* sltu sets all bits 1 in R6 ISA i.e. == -1 */
				if (MIPS_ISA_REV >= 6)
					emit_instr(ctx, addu, HI(dst),
							HI(dst), MIPS_R_AT);
				else
					emit_instr(ctx, subu, HI(dst),
							HI(dst), MIPS_R_AT);
			}
			break;
		}
		gen_imm_to_reg(insn, MIPS_R_AT, ctx);

		/* Make dst unsigned using neg and shift sign to divisor */
		emit_instr(ctx, bgez, HI(dst), 6 * 4);
		emit_instr(ctx, subu, MIPS_R_T8, MIPS_R_ZERO, LO(dst));
		emit_instr(ctx, subu, HI(dst), MIPS_R_ZERO, HI(dst));
		emit_instr(ctx, sltu, LO(dst), MIPS_R_ZERO, MIPS_R_T8);
		/* sltu sets all bits 1 in R6 ISA i.e. == -1 */
		if (MIPS_ISA_REV >= 6)
			emit_instr(ctx, addu, HI(dst), HI(dst), LO(dst));
		else
			emit_instr(ctx, subu, HI(dst), HI(dst), LO(dst));
		emit_instr(ctx, move, LO(dst), MIPS_R_T8);
		emit_instr(ctx, subu, MIPS_R_AT, MIPS_R_ZERO, MIPS_R_AT);

		if (MIPS_ISA_REV >= 6) {
			if (bpf_op == BPF_DIV) {
				emit_instr(ctx, div_r6, LO(dst), LO(dst), MIPS_R_AT);
				emit_instr(ctx, div_r6, HI(dst), HI(dst), MIPS_R_AT);
				emit_instr(ctx, mod, MIPS_R_AT, HI(dst), MIPS_R_AT);
				emit_instr(ctx, addu, LO(dst), LO(dst), MIPS_R_AT);
			} else {
				emit_instr(ctx, mod, LO(dst), LO(dst), MIPS_R_AT);
				gen_zext_insn(dst, true, ctx);
			}
			break;
		}
		emit_instr(ctx, div, LO(dst), MIPS_R_AT);
		if (bpf_op == BPF_DIV) {
			emit_instr(ctx, mflo, LO(dst));
			emit_instr(ctx, div, HI(dst), MIPS_R_AT);
			emit_instr(ctx, mflo, HI(dst));
			emit_instr(ctx, mfhi, MIPS_R_AT);
			emit_instr(ctx, addu, LO(dst), LO(dst), MIPS_R_AT);
		} else {
			emit_instr(ctx, mfhi, LO(dst));
			gen_zext_insn(dst, true, ctx);
		}
		break;
	case BPF_ALU64 | BPF_DIV | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_MOD | BPF_X: /* ALU64_REG */
		return -EINVAL;
	case BPF_ALU64 | BPF_MUL | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_ADD | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_SUB | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_MOV | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_XOR | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_OR | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_AND | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_LSH | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_RSH | BPF_X: /* ALU64_REG */
	case BPF_ALU64 | BPF_ARSH | BPF_X: /* ALU64_REG */
		src = ebpf_to_mips_reg(ctx, insn, REG_SRC_FP_OK);
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (src < 0 || dst < 0)
			return -EINVAL;
		did_move = false;
		if (insn->src_reg == BPF_REG_10) {
			if (bpf_op == BPF_MOV) {
				emit_instr(ctx, addiu, LO(dst),
						MIPS_R_SP, ctx->bpf_stack_off);
				gen_zext_insn(dst, true, ctx);
				did_move = true;
			} else { /* Use T8 reg pair tmp for ALU64 arithmetic */
				src = MIPS_R_T8;
				emit_instr(ctx, addiu, LO(src),
						MIPS_R_SP, ctx->bpf_stack_off);
				emit_instr(ctx, move, HI(src), MIPS_R_ZERO);
			}
		}
		switch (bpf_op) {
		case BPF_MOV:
			if (!did_move) {
				emit_instr(ctx, move, LO(dst), LO(src));
				emit_instr(ctx, move, HI(dst), HI(src));
			}
			break;
		case BPF_ADD:
			emit_instr(ctx, addu, HI(dst), HI(dst), HI(src));
			emit_instr(ctx, addu, MIPS_R_AT, LO(dst), LO(src));
			emit_instr(ctx, sltu, MIPS_R_AT, MIPS_R_AT, LO(dst));
			/* sltu sets all bits 1 in R6 ISA i.e. == -1 */
			if (MIPS_ISA_REV >= 6)
				emit_instr(ctx, subu, HI(dst),
							HI(dst), MIPS_R_AT);
			else
				emit_instr(ctx, addu, HI(dst),
							HI(dst), MIPS_R_AT);
			emit_instr(ctx, addu, LO(dst), LO(dst), LO(src));
			break;
		case BPF_SUB:
			emit_instr(ctx, subu, HI(dst), HI(dst), HI(src));
			emit_instr(ctx, subu, MIPS_R_AT, LO(dst), LO(src));
			emit_instr(ctx, sltu, MIPS_R_AT, LO(dst), MIPS_R_AT);
			/* sltu sets all bits 1 in R6 ISA i.e. == -1 */
			if (MIPS_ISA_REV >= 6)
				emit_instr(ctx, addu, HI(dst),
							HI(dst), MIPS_R_AT);
			else
				emit_instr(ctx, subu, HI(dst),
							HI(dst), MIPS_R_AT);
			emit_instr(ctx, subu, LO(dst), LO(dst), LO(src));
			break;
		case BPF_XOR:
			emit_instr(ctx, xor, LO(dst), LO(dst), LO(src));
			emit_instr(ctx, xor, HI(dst), HI(dst), HI(src));
			break;
		case BPF_OR:
			emit_instr(ctx, or, LO(dst), LO(dst), LO(src));
			emit_instr(ctx, or, HI(dst), HI(dst), HI(src));
			break;
		case BPF_AND:
			emit_instr(ctx, and, LO(dst), LO(dst), LO(src));
			emit_instr(ctx, and, HI(dst), HI(dst), HI(src));
			break;
		case BPF_MUL:
			emit_instr(ctx, mul, HI(dst), HI(dst), LO(src));
			emit_instr(ctx, mul, MIPS_R_AT, LO(dst), HI(src));
			emit_instr(ctx, addu, HI(dst), HI(dst), MIPS_R_AT);
			if (MIPS_ISA_REV >= 6) {
				emit_instr(ctx, mulu, LO(dst), LO(dst), LO(src));
				emit_instr(ctx, muhu, MIPS_R_AT, LO(dst), LO(src));
			} else {
				emit_instr(ctx, multu, LO(dst), LO(src));
				emit_instr(ctx, mfhi, MIPS_R_AT);
				emit_instr(ctx, mflo, LO(dst));
			}
			emit_instr(ctx, addu, HI(dst), HI(dst), MIPS_R_AT);
			break;
		case BPF_DIV:
		case BPF_MOD:
			return -EINVAL;
		case BPF_LSH:
			emit_instr(ctx, beqz, LO(src), 11 * 4);
			emit_instr(ctx, addiu, MIPS_R_AT, LO(src), -32);
			emit_instr(ctx, bltz, MIPS_R_AT, 4 * 4);
			emit_instr(ctx, nop);
			emit_instr(ctx, sllv, HI(dst), LO(dst), MIPS_R_AT);
			emit_instr(ctx, and, LO(dst), LO(dst), MIPS_R_ZERO);
			emit_instr(ctx, b, 5 * 4);
			emit_instr(ctx, subu, MIPS_R_AT, MIPS_R_ZERO, MIPS_R_AT);
			emit_instr(ctx, srlv, MIPS_R_AT, LO(dst), MIPS_R_AT);
			emit_instr(ctx, sllv, HI(dst), HI(dst), LO(src));
			emit_instr(ctx, sllv, LO(dst), LO(dst), LO(src));
			emit_instr(ctx, or, HI(dst), HI(dst), MIPS_R_AT);
			break;
		case BPF_RSH:
			emit_instr(ctx, beqz, LO(src), 11 * 4);
			emit_instr(ctx, addiu, MIPS_R_AT, LO(src), -32);
			emit_instr(ctx, bltz, MIPS_R_AT, 4 * 4);
			emit_instr(ctx, nop);
			emit_instr(ctx, srlv, LO(dst), HI(dst), MIPS_R_AT);
			emit_instr(ctx, and, HI(dst), HI(dst), MIPS_R_ZERO);
			emit_instr(ctx, b, 5 * 4);
			emit_instr(ctx, subu, MIPS_R_AT, MIPS_R_ZERO, MIPS_R_AT);
			emit_instr(ctx, sllv, MIPS_R_AT, HI(dst), MIPS_R_AT);
			emit_instr(ctx, srlv, HI(dst), HI(dst), LO(src));
			emit_instr(ctx, srlv, LO(dst), LO(dst), LO(src));
			emit_instr(ctx, or, LO(dst), LO(dst), MIPS_R_AT);
			break;
		case BPF_ARSH:
			emit_instr(ctx, beqz, LO(src), 11 * 4);
			emit_instr(ctx, addiu, MIPS_R_AT, LO(src), -32);
			emit_instr(ctx, bltz, MIPS_R_AT, 4 * 4);
			emit_instr(ctx, nop);
			emit_instr(ctx, srav, LO(dst), HI(dst), MIPS_R_AT);
			emit_instr(ctx, sra, HI(dst), HI(dst), 31);
			emit_instr(ctx, b, 5 * 4);
			emit_instr(ctx, subu, MIPS_R_AT, MIPS_R_ZERO, MIPS_R_AT);
			emit_instr(ctx, sllv, MIPS_R_AT, HI(dst), MIPS_R_AT);
			emit_instr(ctx, srav, HI(dst), HI(dst), LO(src));
			emit_instr(ctx, srlv, LO(dst), LO(dst), LO(src));
			emit_instr(ctx, or, LO(dst), LO(dst), MIPS_R_AT);
			break;
		default:
			pr_err("ALU64_REG NOT HANDLED\n");
			return -EINVAL;
		}
		break;
	case BPF_ALU | BPF_MOV | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_ADD | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_SUB | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_XOR | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_OR | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_AND | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_MUL | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_DIV | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_MOD | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_LSH | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_RSH | BPF_X: /* ALU_REG */
	case BPF_ALU | BPF_ARSH | BPF_X: /* ALU_REG */
		src = ebpf_to_mips_reg(ctx, insn, REG_SRC_FP_OK);
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (src < 0 || dst < 0)
			return -EINVAL;
		/* Special BPF_MOV zext insn from verifier. */
		if (insn_is_zext(insn)) {
			gen_zext_insn(dst, true, ctx);
			break;
		}
		did_move = false;
		if (insn->src_reg == BPF_REG_10) {
			if (bpf_op == BPF_MOV) {
				emit_instr(ctx, addiu, LO(dst),
						MIPS_R_SP, ctx->bpf_stack_off);
				did_move = true;
			} else { /* Use T8 reg pair tmp for ALU32 arithmetic */
				src = MIPS_R_T8;
				emit_instr(ctx, addiu, LO(src),
						MIPS_R_SP, ctx->bpf_stack_off);
			}
		}
		switch (bpf_op) {
		case BPF_MOV:
			if (!did_move)
				emit_instr(ctx, move, LO(dst), LO(src));
			break;
		case BPF_ADD:
			emit_instr(ctx, addu, LO(dst), LO(dst), LO(src));
			break;
		case BPF_SUB:
			emit_instr(ctx, subu, LO(dst), LO(dst), LO(src));
			break;
		case BPF_XOR:
			emit_instr(ctx, xor, LO(dst), LO(dst), LO(src));
			break;
		case BPF_OR:
			emit_instr(ctx, or, LO(dst), LO(dst), LO(src));
			break;
		case BPF_AND:
			emit_instr(ctx, and, LO(dst), LO(dst), LO(src));
			break;
		case BPF_MUL:
			emit_instr(ctx, mul, LO(dst), LO(dst), LO(src));
			break;
		case BPF_DIV:
		case BPF_MOD:
			if (MIPS_ISA_REV >= 6) {
				if (bpf_op == BPF_DIV)
					emit_instr(ctx, divu_r6, LO(dst),
							LO(dst), LO(src));
				else
					emit_instr(ctx, modu, LO(dst),
							LO(dst), LO(src));
				break;
			}
			emit_instr(ctx, divu, LO(dst), LO(src));
			if (bpf_op == BPF_DIV)
				emit_instr(ctx, mflo, LO(dst));
			else
				emit_instr(ctx, mfhi, LO(dst));
			break;
		case BPF_LSH:
			emit_instr(ctx, sllv, LO(dst), LO(dst), LO(src));
			break;
		case BPF_RSH:
			emit_instr(ctx, srlv, LO(dst), LO(dst), LO(src));
			break;
		case BPF_ARSH:
			emit_instr(ctx, srav, LO(dst), LO(dst), LO(src));
			break;
		default:
			pr_err("ALU_REG NOT HANDLED\n");
			return -EINVAL;
		}
		break;
	case BPF_JMP | BPF_EXIT:
		if (this_idx + 1 < exit_idx) {
			b_off = b_imm(exit_idx, ctx);
			if (is_bad_offset(b_off)) {
				target = j_target(ctx, exit_idx);
				if (target == (unsigned int)-1)
					return -E2BIG;
				emit_instr(ctx, j, target);
			} else {
				emit_instr(ctx, b, b_off);
			}
			emit_instr(ctx, nop);
		}
		break;
	case BPF_JMP32 | BPF_JSLT | BPF_X:
	case BPF_JMP32 | BPF_JSLE | BPF_X:
	case BPF_JMP32 | BPF_JSGT | BPF_X:
	case BPF_JMP32 | BPF_JSGE | BPF_X:
	case BPF_JMP32 | BPF_JSGT | BPF_K:
	case BPF_JMP32 | BPF_JSGE | BPF_K:
	case BPF_JMP32 | BPF_JSLT | BPF_K:
	case BPF_JMP32 | BPF_JSLE | BPF_K:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return -EINVAL;

		if (bpf_src == BPF_X) {
			src = ebpf_to_mips_reg(ctx, insn, REG_SRC_NO_FP);
			if (src < 0)
				return -EINVAL;
		} else if (insn->imm == 0) { /* and BPF_K */
			src = MIPS_R_ZERO;
		} else {
			src = MIPS_R_T8;
			gen_imm_to_reg(insn, LO(src), ctx);
		}

		cmp_eq = bpf_op == BPF_JSLE || bpf_op == BPF_JSGE;
		switch (bpf_op) {
		case BPF_JSGE:
			emit_instr(ctx, slt, MIPS_R_AT, LO(dst), LO(src));
			break;
		case BPF_JSLT:
			emit_instr(ctx, slt, MIPS_R_AT, LO(dst), LO(src));
			break;
		case BPF_JSGT:
			emit_instr(ctx, slt, MIPS_R_AT, LO(src), LO(dst));
			break;
		case BPF_JSLE:
			emit_instr(ctx, slt, MIPS_R_AT, LO(src), LO(dst));
			break;
		}

		src = MIPS_R_AT;
		dst = MIPS_R_ZERO;
		goto jeq_common;

	case BPF_JMP | BPF_JSLT | BPF_X:
	case BPF_JMP | BPF_JSLE | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_K:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return -EINVAL;

		if (bpf_src == BPF_X) {
			src = ebpf_to_mips_reg(ctx, insn, REG_SRC_NO_FP);
			if (src < 0)
				return -EINVAL;
		} else if (insn->imm == 0) { /* and BPF_K */
			src = MIPS_R_ZERO;
		} else {
			src = MIPS_R_T8;
			gen_imm_to_reg(insn, LO(src), ctx);
			if (insn->imm < 0)
				gen_signext_insn(src, ctx);
			else
				gen_zext_insn(src, true, ctx);
		}

		cmp_eq = bpf_op == BPF_JSGT || bpf_op == BPF_JSGE;

		if (bpf_op == BPF_JSGT || bpf_op == BPF_JSLE) {
			/* Check dst <= src */
			emit_instr(ctx, bne, HI(dst), HI(src), 4 * 4);
			/* Delay slot */
			emit_instr(ctx, slt, MIPS_R_AT, HI(dst), HI(src));
			emit_instr(ctx, bne, LO(dst), LO(src), 2 * 4);
			/* Delay slot */
			emit_instr(ctx, sltu, MIPS_R_AT, LO(dst), LO(src));
			emit_instr(ctx, nor, MIPS_R_AT, MIPS_R_ZERO, MIPS_R_AT);
		} else {
			/* Check dst < src */
			emit_instr(ctx, bne, HI(dst), HI(src), 2 * 4);
			/* Delay slot */
			emit_instr(ctx, slt, MIPS_R_AT, HI(dst), HI(src));
			emit_instr(ctx, sltu, MIPS_R_AT, LO(dst), LO(src));
		}

		src = MIPS_R_AT;
		dst = MIPS_R_ZERO;
		goto jeq_common;

	case BPF_JMP | BPF_JLT | BPF_X:
	case BPF_JMP | BPF_JLE | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_K:
	case BPF_JMP | BPF_JGE | BPF_K:
	case BPF_JMP | BPF_JLT | BPF_K:
	case BPF_JMP | BPF_JLE | BPF_K:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return -EINVAL;

		if (bpf_src == BPF_X) {
			src = ebpf_to_mips_reg(ctx, insn, REG_SRC_NO_FP);
			if (src < 0)
				return -EINVAL;
		} else if (insn->imm == 0) { /* and BPF_K */
			src = MIPS_R_ZERO;
		} else {
			src = MIPS_R_T8;
			gen_imm_to_reg(insn, LO(src), ctx);
			if (insn->imm < 0)
				gen_signext_insn(src, ctx);
			else
				gen_zext_insn(src, true, ctx);
		}

		cmp_eq = bpf_op == BPF_JGT || bpf_op == BPF_JGE;

		if (bpf_op == BPF_JGT || bpf_op == BPF_JLE) {
			/* Check dst <= src */
			emit_instr(ctx, bne, HI(dst), HI(src), 4 * 4);
			/* Delay slot */
			emit_instr(ctx, sltu, MIPS_R_AT, HI(dst), HI(src));
			emit_instr(ctx, bne, LO(dst), LO(src), 2 * 4);
			/* Delay slot */
			emit_instr(ctx, sltu, MIPS_R_AT, LO(dst), LO(src));
			emit_instr(ctx, nor, MIPS_R_AT, MIPS_R_ZERO, MIPS_R_AT);
		} else {
			/* Check dst < src */
			emit_instr(ctx, bne, HI(dst), HI(src), 2 * 4);
			/* Delay slot */
			emit_instr(ctx, sltu, MIPS_R_AT, HI(dst), HI(src));
			emit_instr(ctx, sltu, MIPS_R_AT, LO(dst), LO(src));
		}

		src = MIPS_R_AT;
		dst = MIPS_R_ZERO;
		goto jeq_common;

	case BPF_JMP32 | BPF_JLT | BPF_X:
	case BPF_JMP32 | BPF_JLE | BPF_X:
	case BPF_JMP32 | BPF_JGT | BPF_X:
	case BPF_JMP32 | BPF_JGE | BPF_X:
	case BPF_JMP32 | BPF_JGT | BPF_K:
	case BPF_JMP32 | BPF_JGE | BPF_K:
	case BPF_JMP32 | BPF_JLT | BPF_K:
	case BPF_JMP32 | BPF_JLE | BPF_K:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return -EINVAL;

		if (bpf_src == BPF_X) {
			src = ebpf_to_mips_reg(ctx, insn, REG_SRC_NO_FP);
			if (src < 0)
				return -EINVAL;
		} else if (insn->imm == 0) { /* and BPF_K */
			src = MIPS_R_ZERO;
		} else {
			src = MIPS_R_T8;
			gen_imm_to_reg(insn, LO(src), ctx);
		}

		cmp_eq = bpf_op == BPF_JLE || bpf_op == BPF_JGE;
		switch (bpf_op) {
		case BPF_JGE:
			emit_instr(ctx, sltu, MIPS_R_AT, LO(dst), LO(src));
			break;
		case BPF_JLT:
			emit_instr(ctx, sltu, MIPS_R_AT, LO(dst), LO(src));
			break;
		case BPF_JGT:
			emit_instr(ctx, sltu, MIPS_R_AT, LO(src), LO(dst));
			break;
		case BPF_JLE:
			emit_instr(ctx, sltu, MIPS_R_AT, LO(src), LO(dst));
			break;
		}

		src = MIPS_R_AT;
		dst = MIPS_R_ZERO;
		goto jeq_common;

	case BPF_JMP | BPF_JEQ | BPF_X: /* JMP_REG */
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP32 | BPF_JEQ | BPF_X:
	case BPF_JMP32 | BPF_JNE | BPF_X:
		src = ebpf_to_mips_reg(ctx, insn, REG_SRC_FP_OK);
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_FP_OK);
		if (src < 0 || dst < 0)
			return -EINVAL;
		/*
		 * Allow pointer comparison with BPF FP as src or dst, using
		 * T8 as temp reg pair. TODO also for MIPS64
		 */
		if (insn->dst_reg == BPF_REG_10) {
			dst = MIPS_R_T8;
			emit_instr(ctx, addiu, LO(dst),
						MIPS_R_SP, ctx->bpf_stack_off);
			emit_instr(ctx, move, HI(dst), MIPS_R_ZERO);
		}
		if (insn->src_reg == BPF_REG_10) {
			src = MIPS_R_T8;
			emit_instr(ctx, addiu, LO(src),
						MIPS_R_SP, ctx->bpf_stack_off);
			emit_instr(ctx, move, HI(src), MIPS_R_ZERO);
		}

		cmp_eq = (bpf_op == BPF_JEQ);
		if (bpf_class == BPF_JMP) {
			emit_instr(ctx, beq, HI(dst), HI(src), 2 * 4);
			/* Delay slot */
			emit_instr(ctx, move, MIPS_R_AT, LO(src));
			/* Make low words unequal if high word unequal. */
			emit_instr(ctx, addu, MIPS_R_AT, LO(dst), MIPS_R_SP);
			dst = LO(dst);
			src = MIPS_R_AT;
		} else { /* BPF_JMP32 */
			dst = LO(dst);
			src = LO(src);
		}
		goto jeq_common;

	case BPF_JMP | BPF_JSET | BPF_X: /* JMP_REG */
	case BPF_JMP32 | BPF_JSET | BPF_X:
		src = ebpf_to_mips_reg(ctx, insn, REG_SRC_NO_FP);
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (src < 0 || dst < 0)
			return -EINVAL;
		emit_instr(ctx, and, MIPS_R_AT, LO(dst), LO(src));
		if (bpf_class == BPF_JMP) {
			emit_instr(ctx, and, MIPS_R_T8, HI(dst), HI(src));
			emit_instr(ctx, or, MIPS_R_AT, MIPS_R_AT, MIPS_R_T8);
		}
		cmp_eq = false;
		dst = MIPS_R_AT;
		src = MIPS_R_ZERO;
jeq_common:
		/*
		 * If the next insn is EXIT and we are jumping arround
		 * only it, invert the sense of the compare and
		 * conditionally jump to the exit.  Poor man's branch
		 * chaining.
		 */
		if ((insn + 1)->code == (BPF_JMP | BPF_EXIT) && insn->off == 1) {
			b_off = b_imm(exit_idx, ctx);
			if (is_bad_offset(b_off)) {
				target = j_target(ctx, exit_idx);
				if (target == (unsigned int)-1)
					return -E2BIG;
				cmp_eq = !cmp_eq;
				b_off = 4 * 3;
				if (!(ctx->offsets[this_idx] & OFFSETS_B_CONV)) {
					ctx->offsets[this_idx] |= OFFSETS_B_CONV;
					ctx->long_b_conversion = 1;
				}
			}

			if (cmp_eq)
				emit_instr(ctx, bne, dst, src, b_off);
			else
				emit_instr(ctx, beq, dst, src, b_off);
			emit_instr(ctx, nop);
			if (ctx->offsets[this_idx] & OFFSETS_B_CONV) {
				emit_instr(ctx, j, target);
				emit_instr(ctx, nop);
			}
			return 2; /* We consumed the exit. */
		}
		b_off = b_imm(this_idx + insn->off + 1, ctx);
		if (is_bad_offset(b_off)) {
			target = j_target(ctx, this_idx + insn->off + 1);
			if (target == (unsigned int)-1)
				return -E2BIG;
			cmp_eq = !cmp_eq;
			b_off = 4 * 3;
			if (!(ctx->offsets[this_idx] & OFFSETS_B_CONV)) {
				ctx->offsets[this_idx] |= OFFSETS_B_CONV;
				ctx->long_b_conversion = 1;
			}
		}

		if (cmp_eq)
			emit_instr(ctx, beq, dst, src, b_off);
		else
			emit_instr(ctx, bne, dst, src, b_off);
		emit_instr(ctx, nop);
		if (ctx->offsets[this_idx] & OFFSETS_B_CONV) {
			emit_instr(ctx, j, target);
			emit_instr(ctx, nop);
		}
		break;

	case BPF_JMP | BPF_JEQ | BPF_K: /* JMP_IMM */
	case BPF_JMP | BPF_JNE | BPF_K: /* JMP_IMM */
	case BPF_JMP32 | BPF_JEQ | BPF_K: /* JMP_IMM */
	case BPF_JMP32 | BPF_JNE | BPF_K: /* JMP_IMM */
		cmp_eq = (bpf_op == BPF_JEQ);
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_FP_OK);
		if (dst < 0)
			return dst;
		if (insn->dst_reg == BPF_REG_10) {
			dst = MIPS_R_T8;
			emit_instr(ctx, addiu, LO(dst),
						MIPS_R_SP, ctx->bpf_stack_off);
			emit_instr(ctx, move, HI(dst), MIPS_R_ZERO);
		}
		if (insn->imm == 0) {
			src = MIPS_R_ZERO;
			if (bpf_class == BPF_JMP32) {
				dst = LO(dst);
			} else { /* BPF_JMP */
				emit_instr(ctx, or, MIPS_R_AT, LO(dst), HI(dst));
				dst = MIPS_R_AT;
			}
		} else if (bpf_class == BPF_JMP32) {
			gen_imm_to_reg(insn, MIPS_R_AT, ctx);
			src = MIPS_R_AT;
			dst = LO(dst);
		} else { /* BPF_JMP */
			gen_imm_to_reg(insn, MIPS_R_AT, ctx);
			/* If low words equal, check high word vs imm sign. */
			emit_instr(ctx, beq, LO(dst), MIPS_R_AT, 2 * 4);
			emit_instr(ctx, nop);
			/* Make high word signs unequal if low words unequal. */
			emit_instr(ctx, nor, MIPS_R_AT, MIPS_R_ZERO, HI(dst));
			emit_instr(ctx, sra, MIPS_R_AT, MIPS_R_AT, 31);
			src = MIPS_R_AT;
			dst = HI(dst);
		}
		goto jeq_common;

	case BPF_JMP | BPF_JSET | BPF_K: /* JMP_IMM */
	case BPF_JMP32 | BPF_JSET | BPF_K: /* JMP_IMM */
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;

		t64u = (u32)insn->imm;
		gen_imm_to_reg(insn, MIPS_R_AT, ctx);
		emit_instr(ctx, and, MIPS_R_AT, LO(dst), MIPS_R_AT);
		if (bpf_class == BPF_JMP && insn->imm < 0)
			emit_instr(ctx, or, MIPS_R_AT, MIPS_R_AT, HI(dst));
		src = MIPS_R_AT;
		dst = MIPS_R_ZERO;
		cmp_eq = false;
		goto jeq_common;

	case BPF_JMP | BPF_JA:
		/*
		 * Prefer relative branch for easier debugging, but
		 * fall back if needed.
		 */
		b_off = b_imm(this_idx + insn->off + 1, ctx);
		if (is_bad_offset(b_off)) {
			target = j_target(ctx, this_idx + insn->off + 1);
			if (target == (unsigned int)-1)
				return -E2BIG;
			emit_instr(ctx, j, target);
		} else {
			emit_instr(ctx, b, b_off);
		}
		emit_instr(ctx, nop);
		break;
	case BPF_LD | BPF_DW | BPF_IMM:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
		gen_imm_to_reg(insn, LO(dst), ctx);
		gen_imm_to_reg(insn+1, HI(dst), ctx);
		return 2; /* Double slot insn */

	case BPF_JMP | BPF_CALL:
		ctx->flags |= EBPF_SAVE_RA;
		emit_push_args(ctx, insn);
		t64s = (s64)insn->imm + (long)__bpf_call_base;
		emit_const_to_reg(ctx, MIPS_R_T9, (u64)t64s);
		emit_instr(ctx, jalr, MIPS_R_RA, MIPS_R_T9);
		/* delay slot */
		emit_instr(ctx, nop);
		break;

	case BPF_JMP | BPF_TAIL_CALL:
		if (emit_bpf_tail_call(ctx, this_idx))
			return -EINVAL;
		break;

	case BPF_ALU | BPF_END | BPF_FROM_BE:
	case BPF_ALU | BPF_END | BPF_FROM_LE:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		if (dst < 0)
			return dst;
#ifdef __BIG_ENDIAN
		need_swap = (bpf_src == BPF_FROM_LE);
#else
		need_swap = (bpf_src == BPF_FROM_BE);
#endif
		if (insn->imm == 16) {
			if (need_swap)
				emit_instr(ctx, wsbh, LO(dst), LO(dst));
			emit_instr(ctx, andi, LO(dst), LO(dst), 0xffff);
		} else if (insn->imm == 32) {
			if (need_swap) {
				emit_instr(ctx, wsbh, LO(dst), LO(dst));
				emit_instr(ctx, rotr, LO(dst), LO(dst), 16);
			}
		} else { /* 64-bit*/
			if (need_swap) {
				emit_instr(ctx, wsbh, MIPS_R_AT, LO(dst));
				emit_instr(ctx, wsbh, LO(dst), HI(dst));
				emit_instr(ctx, rotr, HI(dst), MIPS_R_AT, 16);
				emit_instr(ctx, rotr, LO(dst), LO(dst), 16);
			}
		}
		break;

	case BPF_ST | BPF_DW | BPF_MEM:
	case BPF_ST | BPF_B | BPF_MEM:
	case BPF_ST | BPF_H | BPF_MEM:
	case BPF_ST | BPF_W | BPF_MEM:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_FP_OK);
		if (dst < 0)
			return -EINVAL;
		mem_off = insn->off;
		gen_imm_to_reg(insn, MIPS_R_AT, ctx);

		if (insn->dst_reg == BPF_REG_10) {
			dst = MIPS_R_SP;
			mem_off += ctx->bpf_stack_off;
		}
		switch (bpf_size) {
		case BPF_B:
			emit_instr(ctx, sb, MIPS_R_AT, mem_off, LO(dst));
			break;
		case BPF_H:
			emit_instr(ctx, sh, MIPS_R_AT, mem_off, LO(dst));
			break;
		case BPF_W:
			emit_instr(ctx, sw, MIPS_R_AT, mem_off, LO(dst));
			break;
		case BPF_DW:
			/* Memory order == register order in pair */
			emit_instr(ctx, sw, MIPS_R_AT, OFFLO(mem_off), LO(dst));
			if (insn->imm < 0) {
				emit_instr(ctx, nor, MIPS_R_AT,
						MIPS_R_ZERO, MIPS_R_ZERO);
				emit_instr(ctx, sw, MIPS_R_AT,
						OFFHI(mem_off), LO(dst));
			} else {
				emit_instr(ctx, sw, MIPS_R_ZERO,
						OFFHI(mem_off), LO(dst));
			}
			break;
		}
		break;

	case BPF_LDX | BPF_DW | BPF_MEM:
	case BPF_LDX | BPF_B | BPF_MEM:
	case BPF_LDX | BPF_H | BPF_MEM:
	case BPF_LDX | BPF_W | BPF_MEM:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_NO_FP);
		src = ebpf_to_mips_reg(ctx, insn, REG_SRC_FP_OK);
		if (src < 0 || dst < 0)
			return -EINVAL;
		mem_off = insn->off;

		if (insn->src_reg == BPF_REG_10) {
			src = MIPS_R_SP;
			mem_off += ctx->bpf_stack_off;
		}
		switch (bpf_size) {
		case BPF_B:
			emit_instr(ctx, lbu, LO(dst), mem_off, LO(src));
			break;
		case BPF_H:
			emit_instr(ctx, lhu, LO(dst), mem_off, LO(src));
			break;
		case BPF_W:
			emit_instr(ctx, lw, LO(dst), mem_off, LO(src));
			break;
		case BPF_DW:
			/*
			 * Careful: update HI(dst) first in case dst == src,
			 * since only LO(src) is the usable pointer.
			 */
			emit_instr(ctx, lw, HI(dst), OFFHI(mem_off), LO(src));
			emit_instr(ctx, lw, LO(dst), OFFLO(mem_off), LO(src));
			break;
		}
		break;

	case BPF_STX | BPF_DW | BPF_XADD:
		return -EINVAL;
	case BPF_STX | BPF_W | BPF_XADD:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_FP_OK);
		src = ebpf_to_mips_reg(ctx, insn, REG_SRC_FP_OK);
		if (src < 0 || dst < 0)
			return -EINVAL;
		mem_off = insn->off;
		/*
		 * Drop reg pair scheme for more efficient temp register usage
		 * given BPF_W mode.
		 */
		dst = LO(dst);
		src = LO(src);

		if (insn->dst_reg == BPF_REG_10) {
			dst = MIPS_R_SP;
			mem_off += ctx->bpf_stack_off;
		}
		if (insn->src_reg == BPF_REG_10) { /* TODO also for MIPS64*/
			src = MIPS_R_T8;
			emit_instr(ctx, addiu, src,
						MIPS_R_SP, ctx->bpf_stack_off);
		}
		/*
		 * If mem_off does not fit within the 9 bit ll/sc instruction
		 * immediate field, use a temp reg.
		 */
		if (MIPS_ISA_REV >= 6 &&
		    (mem_off >= BIT(8) || mem_off < -BIT(8))) {
			emit_instr(ctx, addiu, MIPS_R_T9, dst, mem_off);
			mem_off = 0;
			dst = MIPS_R_T9;
		}
		emit_instr(ctx, ll, MIPS_R_AT, mem_off, dst);
		emit_instr(ctx, addu, MIPS_R_AT, MIPS_R_AT, src);
		emit_instr(ctx, sc, MIPS_R_AT, mem_off, dst);
		/*
		 * On failure back up to LL (-4 insns of 4 bytes each)
		 */
		emit_instr(ctx, beqz, MIPS_R_AT, -4 * 4);
		emit_instr(ctx, nop);
		break;

	case BPF_STX | BPF_DW | BPF_MEM:
	case BPF_STX | BPF_B | BPF_MEM:
	case BPF_STX | BPF_H | BPF_MEM:
	case BPF_STX | BPF_W | BPF_MEM:
		dst = ebpf_to_mips_reg(ctx, insn, REG_DST_FP_OK);
		src = ebpf_to_mips_reg(ctx, insn, REG_SRC_FP_OK);
		if (src < 0 || dst < 0)
			return -EINVAL;
		mem_off = insn->off;

		if (insn->dst_reg == BPF_REG_10) {
			dst = MIPS_R_SP;
			mem_off += ctx->bpf_stack_off;
		}
		/* Use temp T8 reg pair to hold BPF FP if src. */
		if (insn->src_reg == BPF_REG_10) { /* TODO also for MIPS64*/
			src = MIPS_R_T8;
			emit_instr(ctx, addiu, LO(src),
						MIPS_R_SP, ctx->bpf_stack_off);
			emit_instr(ctx, move, HI(src), MIPS_R_ZERO);
		}
		switch (bpf_size) {
		case BPF_B:
			emit_instr(ctx, sb, LO(src), mem_off, LO(dst));
			break;
		case BPF_H:
			emit_instr(ctx, sh, LO(src), mem_off, LO(dst));
			break;
		case BPF_W:
			emit_instr(ctx, sw, LO(src), mem_off, LO(dst));
			break;
		case BPF_DW:
			emit_instr(ctx, sw, LO(src), OFFLO(mem_off), LO(dst));
			emit_instr(ctx, sw, HI(src), OFFHI(mem_off), LO(dst));
			break;
		}
		break;

	default:
		pr_err("NOT HANDLED %d - (%02x)\n",
		       this_idx, (unsigned int)insn->code);
		return -EINVAL;
	}
	/*
	 * Handle zero-extension if the verifier is unable to patch and
	 * insert it's own special zext insns.
	 */
	if ((bpf_class == BPF_ALU && !(bpf_op == BPF_END && insn->imm == 64)) ||
	    (bpf_class == BPF_LDX && bpf_size != BPF_DW))
		gen_zext_insn(dst, false, ctx);
	return 1;
}

/* Enable the verifier to insert zext insn for ALU32 ops as needed. */
bool bpf_jit_needs_zext(void)
{
	return true;
}
