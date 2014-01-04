# -*- coding: utf-8 -*-

try:
    from enum import Enum
except ImportError:
    Enum = object

# Responses from hook functions.
NF_DROP		= 0
NF_ACCEPT	= 1
NF_STOLEN	= 2
NF_QUEUE	= 3
NF_REPEAT	= 4
NF_STOP		= 5
NF_MAX_VERDICT	= NF_STOP

# we overload the higher bits for encoding auxiliary data such as the queue
# number or errno values. Not nice, but better than additional function
# arguments.
NF_VERDICT_MASK = 0x000000ff

# extra verdict flags have mask 0x0000ff00
NF_VERDICT_FLAG_QUEUE_BYPASS = 0x00008000

# queue number (NF_QUEUE) or errno (NF_DROP)
NF_VERDICT_QMASK = 0xffff0000
NF_VERDICT_QBITS = 16

#define NF_QUEUE_NR(x) ((((x) << 16) & NF_VERDICT_QMASK) | NF_QUEUE)
def NF_QUEUE_NR(x): return ((((x) << 16) & NF_VERDICT_QMASK) | NF_QUEUE)

#define NF_DROP_ERR(x) (((-x) << 16) | NF_DROP)
def NF_DROP_ERR(x): return (((-x) << 16) | NF_DROP)

# Generic cache responses from hook functions.
# <= 0x2000 is used for protocol-flags.
NFC_UNKNOWN = 0x4000
NFC_ALTERED = 0x8000

# NF_VERDICT_BITS should be 8 now, but userspace might break if this changes
NF_VERDICT_BITS = 16

class NfInetHooks(Enum):
    NF_INET_PRE_ROUTING		= 0
    NF_INET_LOCAL_IN		= 1
    NF_INET_FORWARD		= 2
    NF_INET_LOCAL_OUT		= 3
    NF_INET_POST_ROUTING	= 4
    NF_INET_NUMHOOKS		= 5
NF_INET_PRE_ROUTING	= 0
NF_INET_LOCAL_IN	= 1
NF_INET_FORWARD		= 2
NF_INET_LOCAL_OUT	= 3
NF_INET_POST_ROUTING	= 4
NF_INET_NUMHOOKS	= 5

# enum
NFPROTO_UNSPEC		= 0
NFPROTO_IPV4		= 2
NFPROTO_ARP		= 3
NFPROTO_BRIDGE		= 7
NFPROTO_IPV6		= 10
NFPROTO_DECNET		= 12
NFPROTO_NUMPROTO	= 13

"""
union nf_inet_addr
	__u32		all[4]
	__be32		ip
	__be32		ip6[4]
	struct in_addr	in
	struct in6_addr	in6
"""
