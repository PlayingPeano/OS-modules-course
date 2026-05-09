#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/tcp.h>
#include <net/ip.h>

MODULE_DESCRIPTION("Log outgoing TCP connections with optional dport filter");
MODULE_AUTHOR("PlayingPeano");
MODULE_LICENSE("GPL");

static unsigned short dst_port = 0;
module_param(dst_port, ushort, 0644);
MODULE_PARM_DESC(dst_port, "Destination TCP port filter (0 disables filter)");

static unsigned int tcp_connlog_hookfn(void *priv,
				       struct sk_buff *skb,
				       const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct tcphdr *tcph;

	if (!skb)
		return NF_ACCEPT;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (!iph || iph->version != 4 || iph->protocol != IPPROTO_TCP)
		return NF_ACCEPT;

	if (!pskb_may_pull(skb, ip_hdrlen(skb) + sizeof(struct tcphdr)))
		return NF_ACCEPT;

	tcph = tcp_hdr(skb);
	if (!tcph)
		return NF_ACCEPT;

	if (!(tcph->syn) || tcph->ack)
		return NF_ACCEPT;

	if (dst_port != 0 && ntohs(tcph->dest) != dst_port)
		return NF_ACCEPT;

	pr_info("tcp_conn: %pI4:%u -> %pI4:%u\n",
		&iph->saddr, ntohs(tcph->source),
		&iph->daddr, ntohs(tcph->dest));

	return NF_ACCEPT;
}

static struct nf_hook_ops tcp_connlog_nfho = {
	.hook = tcp_connlog_hookfn,
	.hooknum = NF_INET_LOCAL_OUT,
	.pf = PF_INET,
	.priority = NF_IP_PRI_FIRST,
};

static int __init tcp_connlog_init(void)
{
	int err;

	err = nf_register_net_hook(&init_net, &tcp_connlog_nfho);
	if (err)
		return err;

	pr_info("tcp_conn_logger loaded (dst_port=%u)\n", dst_port);
	return 0;
}

static void __exit tcp_connlog_exit(void)
{
	nf_unregister_net_hook(&init_net, &tcp_connlog_nfho);
	pr_info("tcp_conn_logger unloaded\n");
}

module_init(tcp_connlog_init);
module_exit(tcp_connlog_exit);
