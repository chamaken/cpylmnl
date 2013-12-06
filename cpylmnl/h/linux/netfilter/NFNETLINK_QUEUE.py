# Generated by h2py from ./h/linux/netfilter/nfnetlink_queue.h

from __future__ import absolute_import

NFQNL_MSG_PACKET = 0
NFQNL_MSG_VERDICT = 1
NFQNL_MSG_CONFIG = 2
NFQNL_MSG_VERDICT_BATCH = 3
NFQNL_MSG_MAX = 4
NFQA_UNSPEC = 0
NFQA_PACKET_HDR = 1
NFQA_VERDICT_HDR = 2
NFQA_MARK = 3
NFQA_TIMESTAMP = 4
NFQA_IFINDEX_INDEV = 5
NFQA_IFINDEX_OUTDEV = 6
NFQA_IFINDEX_PHYSINDEV = 7
NFQA_IFINDEX_PHYSOUTDEV = 8
NFQA_HWADDR = 9
NFQA_PAYLOAD = 10
NFQA_CT = 11
NFQA_CT_INFO = 12
NFQA_CAP_LEN = 13
NFQA_SKB_INFO = 14
__NFQA_MAX = 15
NFQA_MAX = (__NFQA_MAX - 1)
NFQNL_CFG_CMD_NONE = 0
NFQNL_CFG_CMD_BIND = 1
NFQNL_CFG_CMD_UNBIND = 2
NFQNL_CFG_CMD_PF_BIND = 3
NFQNL_CFG_CMD_PF_UNBIND = 4
NFQNL_COPY_NONE = 0
NFQNL_COPY_META = 1
NFQNL_COPY_PACKET = 2
NFQA_CFG_UNSPEC = 0
NFQA_CFG_CMD = 1
NFQA_CFG_PARAMS = 2
NFQA_CFG_QUEUE_MAXLEN = 3
NFQA_CFG_MASK = 4
NFQA_CFG_FLAGS = 5
__NFQA_CFG_MAX = 6
NFQA_CFG_MAX = (__NFQA_CFG_MAX-1)
NFQA_CFG_F_FAIL_OPEN = (1 << 0)
NFQA_CFG_F_CONNTRACK = (1 << 1)
NFQA_CFG_F_GSO = (1 << 2)
NFQA_CFG_F_MAX = (1 << 3)
NFQA_SKB_CSUMNOTREADY = (1 << 0)
NFQA_SKB_GSO = (1 << 1)
