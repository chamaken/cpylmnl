# -*- coding: utf-8 -*-

import ctypes

try:
    from enum import Enum
except ImportError:
    Enum = object


# TCP tracking.

# This is exposed to userspace (ctnetlink)
# enum tcp_conntrack
class TcpConntrack(Enum):
    TCP_CONNTRACK_NONE		= 0
    TCP_CONNTRACK_SYN_SENT	= 1
    TCP_CONNTRACK_SYN_RECV	= 2
    TCP_CONNTRACK_ESTABLISHED	= 3
    TCP_CONNTRACK_FIN_WAIT	= 4
    TCP_CONNTRACK_CLOSE_WAIT	= 5
    TCP_CONNTRACK_LAST_ACK	= 6
    TCP_CONNTRACK_TIME_WAIT	= 7
    TCP_CONNTRACK_CLOSE		= 8
    TCP_CONNTRACK_LISTEN	= 9 # obsolete
    TCP_CONNTRACK_SYN_SENT2	= TCP_CONNTRACK_LISTEN
    TCP_CONNTRACK_MAX		= 10
    TCP_CONNTRACK_IGNORE	= 11
    TCP_CONNTRACK_RETRANS	= 12
    TCP_CONNTRACK_UNACK		= 13
    TCP_CONNTRACK_TIMEOUT_MAX	= 14
TCP_CONNTRACK_NONE		= 0
TCP_CONNTRACK_SYN_SENT		= 1
TCP_CONNTRACK_SYN_RECV		= 2
TCP_CONNTRACK_ESTABLISHED	= 3
TCP_CONNTRACK_FIN_WAIT		= 4
TCP_CONNTRACK_CLOSE_WAIT	= 5
TCP_CONNTRACK_LAST_ACK		= 6
TCP_CONNTRACK_TIME_WAIT		= 7
TCP_CONNTRACK_CLOSE		= 8
TCP_CONNTRACK_LISTEN		= 9
TCP_CONNTRACK_SYN_SENT2		= TCP_CONNTRACK_LISTEN
TCP_CONNTRACK_MAX		= 10
TCP_CONNTRACK_IGNORE		= 11
TCP_CONNTRACK_RETRANS		= 12
TCP_CONNTRACK_UNACK		= 13
TCP_CONNTRACK_TIMEOUT_MAX	= 14

# Window scaling is advertised by the sender
IP_CT_TCP_FLAG_WINDOW_SCALE		= 0x01

# SACK is permitted by the sender
IP_CT_TCP_FLAG_SACK_PERM		= 0x02

# This sender sent FIN first
IP_CT_TCP_FLAG_CLOSE_INIT		= 0x04

# Be liberal in window checking
IP_CT_TCP_FLAG_BE_LIBERAL		= 0x08

# Has unacknowledged data
IP_CT_TCP_FLAG_DATA_UNACKNOWLEDGED	= 0x10

#The field td_maxack has been set
IP_CT_TCP_FLAG_MAXACK_SET		= 0x20

class NfCtTcpFlags(ctypes.Structure):
    """struct nf_ct_tcp_flags
    """
    _fields_ = [("flags",	ctypes.c_uint8), # __u8 flags
                ("mask",	ctypes.c_uint8)] # __u8 mask
