/* Copyright (c) 2016 PLUMgrid
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") rxcnt = {
	.type = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size = 4,
	.value_size = sizeof(long),
	.max_entries = 1,
};

SEC("vale_bpf") 
int vale_bpf_prog(struct vale_bpf_md *ctx)
{
  long *value;
	value = bpf_map_lookup_elem(&rxcnt, &(long*){0});
	if (value)
		*value += 1;

	return 1;
}

char _license[] SEC("license") = "GPL";
