/*
* tcpstat-Collects TCP flows info using jprobes, adapted from tcpprobe.c
* monitors TCP parameters: srtt,rttvar, total_retrans and snd_cwnd for each TCP
* connection.
* It stores only the recent values of the parameters and doesn't maintain
* history. The collected
* information is communicated to the userspace program when requested using
* Netlink.
*/
#define pr_fmt(fmt) "tcpstat: %s:%d: " fmt, __FUNCTION__, __LINE__

#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <net/sock.h>
#include <net/tcp.h>

MODULE_AUTHOR("Dejene B. Oljira <oljideje@kau.se>");
MODULE_DESCRIPTION("TCP Flow Monitor");
static int maxflows __read_mostly = 100;
MODULE_PARM_DESC(maxflows, "Maximum number of flows");
module_param(maxflows, int, 0);

#define NETLINK_USER 31
struct sock *nl_sk = NULL;
struct nlmsghdr *nlh;
int pid;

typedef struct _tcp_stat {
  u32 saddr;
  u32 daddr;
  u16 sport;
  u16 dport;
  u32 srtt;
  u32 rttvar;
  u32 snd_cwnd;
  u32 total_retrans;
  struct list_head list;

} tcp_stat;

LIST_HEAD(tcpstat_list);

static int flow_count = 0;

static tcp_stat *find_flow(const struct inet_sock *inet)

{
  tcp_stat *tcpflow;

  list_for_each_entry(tcpflow, &tcpstat_list, list) {
    if (inet->inet_saddr == tcpflow->saddr &&
        inet->inet_daddr == tcpflow->daddr &&
        inet->inet_sport == tcpflow->sport &&
        inet->inet_dport == tcpflow->dport)
      return tcpflow;
  }
  return NULL;
}

static void tcpstat_list_free(void) {

  /* Go thru the list and free the memory. */
  tcp_stat *ptr, *next;
  list_for_each_entry_safe(ptr, next, &tcpstat_list, list) {
    /*Delete list using included functions*/
    list_del(&ptr->list);
    /*free list memory*/
    kfree(ptr);
  }
}

/*
 * Hook inserted to be called before each receive packet.
 * Note: arguments must match tcp_rcv_established()!
 */
static void jtcp_rcv_established(struct sock *sk, struct sk_buff *skb,
                                 const struct tcphdr *th, unsigned int len) {
  const struct tcp_sock *tp = tcp_sk(sk);
  const struct inet_sock *inet = inet_sk(sk);
  tcp_stat *tcpflow = NULL;
  tcp_stat *nflow;
  if (flow_count > 0)
    tcpflow = find_flow(inet);
  if (flow_count < maxflows && tcpflow == NULL) {
    printk(KERN_INFO "Adding log for new TCP conn (%u) \n", flow_count);
    // tcp_stat *nflow;
    nflow = kmalloc(sizeof(*nflow), GFP_KERNEL);
    nflow->saddr = inet->inet_saddr;
    nflow->srtt = tp->srtt_us >> 3;
    nflow->rttvar = tp->rttvar_us >> 3;
    nflow->daddr = inet->inet_daddr;
    nflow->snd_cwnd = tp->snd_cwnd;
    nflow->sport = inet->inet_sport;
    nflow->dport = inet->inet_dport;
    nflow->total_retrans = tp->total_retrans;
    INIT_LIST_HEAD(&nflow->list);
    list_add_tail(&(nflow->list), &(tcpstat_list));
    flow_count += 1;

  } else if (flow_count < maxflows && tcpflow != NULL) {

    tcpflow->srtt = tp->srtt_us >> 3;
    tcpflow->rttvar = tp->rttvar_us >> 3;
    tcpflow->total_retrans = tp->total_retrans;
    tcpflow->snd_cwnd = tp->snd_cwnd;
  }

  jprobe_return();
}

/*
static void jtcp_done(struct sock *sk) {

  const struct inet_sock *inet = inet_sk(sk);
  tcp_stat *ptr, *next;
  list_for_each_entry_safe(ptr, next, &tcpstat_list, list) {
    if (inet->inet_saddr == ptr->saddr && inet->inet_daddr == ptr->daddr &&
        inet->inet_sport == ptr->sport && inet->inet_dport == ptr->dport) {
      list_del(&ptr->list);
      kfree(ptr);
      jprobe_return();
    }
  }
  jprobe_return();
}
*/
static int tcpstat_sprint(char *tbuf, tcp_stat *tcpflow, int n) {

  return scnprintf(tbuf, n, "IP src: %pI4 dst: %pI4 Port src: %u dst: %u srtt: "
                            "%u rttvar: %u total_retrans:%u snd_cwnd: %d\n",
                   &tcpflow->saddr, &tcpflow->daddr, ntohs(tcpflow->sport),
                   ntohs(tcpflow->dport), tcpflow->srtt, tcpflow->rttvar,
                   tcpflow->total_retrans, tcpflow->snd_cwnd);
}

static void hello_nl_recv_msg(struct sk_buff *skb) {
  // struct nlmsghdr *nlh;
  struct sk_buff *skb_out;
  int msg_size;
  char msg[256];
  int res, width;
  tcp_stat *tcpflow;
  // printk(KERN_INFO "Netlink rcvd msg payload:%s\n",(char*)nlmsg_data(nlh));

  list_for_each_entry(tcpflow, &tcpstat_list, list) {

    width = tcpstat_sprint(msg, tcpflow, sizeof(msg));
    msg_size = strlen(msg);
    nlh = (struct nlmsghdr *)skb->data;
    pid = nlh->nlmsg_pid;
    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
      printk(KERN_ERR "Failed to allocate new skb\n");
      return;
    }
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0;
    strncpy(nlmsg_data(nlh), msg, msg_size);
    res = nlmsg_unicast(nl_sk, skb_out, pid);
    if (res < 0)
      printk(KERN_INFO "Error while sending back to user\n");
  }
}

static struct jprobe tcp_jprobe = {
    .entry = jtcp_rcv_established,
    .kp =
        {
            .symbol_name = "tcp_rcv_established",
        },
};
/*
static struct jprobe tcp_jprobe_done = {
    .kp =
        {
            .symbol_name = "tcp_done",
        },
    .entry = (kprobe_opcode_t *)jtcp_done,
};
*/
static int __init tcpprobe_init(void) {
  int ret;
  struct netlink_kernel_cfg cfg = {
      .input = hello_nl_recv_msg,
  };

  nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
  if (!nl_sk) {
    printk(KERN_ALERT "Error creating netlink socket.\n");
    return -1;
  }
  ret = register_jprobe(&tcp_jprobe);
  if (ret < 0) {
    pr_err(KERN_INFO "register_jprobe failed, returned %d\n", ret);
    return -1;
  }
  pr_info("Registered tcp_jprobe  at %p, handler addr %p\n", tcp_jprobe.kp.addr,
          tcp_jprobe.entry);
 /*
  ret = register_jprobe(&tcp_jprobe_done);
  if (ret < 0) {
    pr_err(KERN_INFO "register_jprobe_done failed, returned %d\n", ret);
    return -1;
  }
  pr_info("Registered tcp_jprobe_done  at %p, handler addr %p\n",
          tcp_jprobe_done.kp.addr, tcp_jprobe_done.entry);
 */
  return 0;
}

static void __exit tcpprobe_exit(void) {
  unregister_jprobe(&tcp_jprobe);
  pr_info("jprobe at %p unregistered\n", tcp_jprobe.kp.addr);
  /*
  unregister_jprobe(&tcp_jprobe_done);
  pr_info("jprobe at %p unregistered\n", tcp_jprobe_done.kp.addr);
 */
 tcpstat_list_free();

  netlink_kernel_release(nl_sk);
}

module_init(tcpprobe_init);
module_exit(tcpprobe_exit);
MODULE_LICENSE("GPL");
