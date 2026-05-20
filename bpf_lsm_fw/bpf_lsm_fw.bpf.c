#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#ifndef AF_INET
#define AF_INET 2
#endif

char LICENSE[] SEC("license") = "GPL";

struct rule_key {
	char comm[TASK_COMM_LEN];
	__u32 dst_ip;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct rule_key);
	__type(value, __u8);
} blocked_rules SEC(".maps");

SEC("lsm/socket_connect")
int BPF_PROG(lsm_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	struct sockaddr_in sin = {};
	struct rule_key key = {};
	__u8 *blocked;
	__u16 dport;
	__u32 ip_host;

	(void)sock;

	if (ret)
		return ret;

	if (!address || addrlen < sizeof(sin))
		return 0;

	if (bpf_probe_read_kernel(&sin, sizeof(sin), address))
		return 0;

	if (sin.sin_family != AF_INET)
		return 0;

	key.dst_ip = sin.sin_addr.s_addr;
	bpf_get_current_comm(&key.comm, sizeof(key.comm));

	dport = bpf_ntohs(sin.sin_port);
	ip_host = bpf_ntohl(key.dst_ip);

	blocked = bpf_map_lookup_elem(&blocked_rules, &key);
	if (blocked && *blocked) {
		bpf_printk("lsm_fw block comm=%s ip=0x%x port=%d", key.comm, ip_host, dport);
		return -EPERM;
	}

	bpf_printk("lsm_fw allow comm=%s ip=0x%x port=%d", key.comm, ip_host, dport);
	return 0;
}
