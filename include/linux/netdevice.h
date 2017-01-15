#ifndef _COMPAT_LINUX_NETDEVICE_H
#define _COMPAT_LINUX_NETDEVICE_H 1

#include "../../compat/config.h"

#include_next <linux/netdevice.h>

/* supports eipoib flags */
#ifndef IFF_EIPOIB_VIF
#define IFF_EIPOIB_VIF  0x800       /* IPoIB VIF intf(eg ib0.x, ib1.x etc.), using IFF_DONT_BRIDGE */
#endif

#ifndef SET_ETHTOOL_OPS
#define SET_ETHTOOL_OPS(netdev,ops) \
    ( (netdev)->ethtool_ops = (ops) )
#endif

#if !defined(HAVE_NETDEV_EXTENDED_HW_FEATURES)     && \
    !defined(HAVE_NETDEV_OPS_EXT_NDO_FIX_FEATURES) && \
    !defined(HAVE_NETDEV_OPS_EXT_NDO_SET_FEATURES) && \
    !defined(HAVE_NDO_SET_FEATURES)
#define LEGACY_ETHTOOL_OPS
#endif

#ifndef NETDEV_BONDING_INFO
#define NETDEV_BONDING_INFO     0x0019
#endif


#ifndef HAVE_NETDEV_MASTER_UPPER_DEV_GET_RCU
#define netdev_master_upper_dev_get_rcu(x) (x)->master
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18)
#ifdef HAVE_ALLOC_ETHERDEV_MQ
#ifndef HAVE_NETIF_SET_REAL_NUM_TX_QUEUES
static inline void netif_set_real_num_tx_queues(struct net_device *netdev,
						unsigned int txq)
{
	netdev->real_num_tx_queues = txq;
}
#endif
#endif
#endif /* LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 18) */

#ifndef HAVE_NETDEV_RSS_KEY_FILL
static inline void netdev_rss_key_fill(void *addr, size_t len)
{
	__be32 *hkey;

	hkey = (__be32 *)addr;
	hkey[0] = cpu_to_be32(0xD181C62C);
	hkey[1] = cpu_to_be32(0xF7F4DB5B);
	hkey[2] = cpu_to_be32(0x1983A2FC);
	hkey[3] = cpu_to_be32(0x943E1ADB);
	hkey[4] = cpu_to_be32(0xD9389E6B);
	hkey[5] = cpu_to_be32(0xD1039C2C);
	hkey[6] = cpu_to_be32(0xA74499AD);
	hkey[7] = cpu_to_be32(0x593D56D9);
	hkey[8] = cpu_to_be32(0xF3253C06);
	hkey[9] = cpu_to_be32(0x2ADC1FFC);
}
#endif

#ifndef NAPI_POLL_WEIGHT
/* Default NAPI poll() weight
 * Device drivers are strongly advised to not use bigger value
 */
#define NAPI_POLL_WEIGHT 64
#endif

#ifndef NETDEV_JOIN
#define NETDEV_JOIN           0x0014
#endif

#ifndef NETDEV_MASTER_UPPER_DEV_LINK_4_PARAMS
#define netdev_master_upper_dev_link(a,b,c,d) netdev_master_upper_dev_link(a,b)
#endif

#ifdef HAVE_ALLOC_NETDEV_MQS_6_PARAMS
#define alloc_netdev_mqs(a, b, c, d, e) alloc_netdev_mqs(a, b, NET_NAME_UNKNOWN, c, d, e)
#endif

#ifdef alloc_netdev_mq
#undef alloc_netdev_mq
#define alloc_netdev_mq(sizeof_priv, name, setup, count) \
    alloc_netdev_mqs(sizeof_priv, name, setup, count, count)
#endif

#ifdef alloc_netdev
#undef alloc_netdev
#define alloc_netdev(sizeof_priv, name, name_assign_type, setup) \
	alloc_netdev_mqs(sizeof_priv, name, setup, 1, 1)
#endif

#endif	/* _COMPAT_LINUX_NETDEVICE_H */
