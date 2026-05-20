#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

#ifndef AF_INET
#define AF_INET 2
#endif

char LICENSE[] SEC("license") = "GPL";

struct rule_key {
	__u64 exe_ino;
	__u64 exe_dev;
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
	struct task_struct *task;
	struct mm_struct *mm;
	struct file *exe_file;
	struct inode *inode;
	struct super_block *sb;
	struct sockaddr_in sin = {};
	struct rule_key key = {};
	char exe_name[64] = {};
	struct dentry *dentry;
	const unsigned char *name_ptr;
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

	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return 0;

	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return 0;

	exe_file = BPF_CORE_READ(mm, exe_file);
	if (!exe_file)
		return 0;

	inode = BPF_CORE_READ(exe_file, f_inode);
	if (!inode)
		return 0;

	sb = BPF_CORE_READ(inode, i_sb);
	if (!sb)
		return 0;

	key.exe_ino = BPF_CORE_READ(inode, i_ino);
	key.exe_dev = BPF_CORE_READ(sb, s_dev);
	key.dst_ip = sin.sin_addr.s_addr;

	dentry = BPF_CORE_READ(exe_file, f_path.dentry);
	if (dentry) {
		name_ptr = BPF_CORE_READ(dentry, d_name.name);
		if (name_ptr)
			bpf_probe_read_kernel_str(exe_name, sizeof(exe_name), (const void *)name_ptr);
	}

	dport = bpf_ntohs(sin.sin_port);
	ip_host = bpf_ntohl(key.dst_ip);

	blocked = bpf_map_lookup_elem(&blocked_rules, &key);
	if (blocked && *blocked) {
		bpf_printk("lsm_fw block exe=%s dev=%llu ino=%llu ip=0x%x port=%d",
			   exe_name, key.exe_dev, key.exe_ino, ip_host, dport);
		return -EPERM;
	}

	bpf_printk("lsm_fw allow exe=%s dev=%llu ino=%llu ip=0x%x port=%d",
		   exe_name, key.exe_dev, key.exe_ino, ip_host, dport);
	return 0;
}
