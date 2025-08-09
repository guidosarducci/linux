/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024 Meta Platforms, Inc. and affiliates. */

#ifndef _UPTR_TEST_COMMON_H
#define _UPTR_TEST_COMMON_H

#define MAGIC_VALUE 0xabcd1234
#define PAGE_SIZE 4096

#ifdef __BPF__
#define __bpf_md_ptr(type, name) type name
#else
#define __uptr
#define __kptr
#endif

struct user_data { //BPF + USER
	int a;
	int b;
	int result;
	int nested_result;
};

struct nested_udata { //BPF + USER
	__bpf_md_ptr(struct user_data __uptr, *udata);
};

#ifdef __BPF__
struct large_data { //BPF
	__u8 one_page[PAGE_SIZE];
	int a;
};

struct large_uptr { //BPF
	struct large_data __uptr *udata;
};

struct empty_data { //BPF
};

struct empty_uptr { //BPF
	struct empty_data __uptr *udata;
};

/* Avoid fwd btf type being generated for the following struct */
typedef struct tls_uptr_dummy {
	/*
	 * Force the compiler to generate the actual definition of tld_meta_u
	 * and tld_data_u in BTF. Without it, tld_meta_u and u_tld_data will
	 * be BTF_KIND_FWD.
	 */
	struct large_data ldata[0];
	struct empty_data edata[0];
	struct user_data udata[0];
	struct cgroup cgrp[0];
} *tls_uptr_dummy_t;

struct kstruct_uptr { //BPF
	struct cgroup __uptr *cgrp;
	tls_uptr_dummy_t dummy[0];
};
#endif

struct value_type { //BPF + USER
	__bpf_md_ptr(struct user_data __uptr, *udata);
	__bpf_md_ptr(struct cgroup __kptr, *cgrp);
	struct nested_udata nested;
#ifdef __BPF__
	tls_uptr_dummy_t dummy[0];
#endif
};

struct value_lock_type { //BPF + USER
	__bpf_md_ptr(struct user_data __uptr, *udata);
	struct bpf_spin_lock lock;
#ifdef __BPF__
	tls_uptr_dummy_t dummy[0];
#endif
};

#endif
