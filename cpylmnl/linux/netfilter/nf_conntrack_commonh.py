# -*- coding: utf-8 -*-

try:
    from enum import Enum
except ImportError:
    Enum = object


# Connection state tracking for netfilter.  This is separated from,
# but required by, the NAT layer; it can also be used by an iptables
# extension.

# enum ip_conntrack_info
class IpConntrackInfo(Enum):
    # Part of an established connection (either direction).
    IP_CT_ESTABLISHED		= 0

    # Like NEW, but related to an existing connection, or ICMP error
    # (in either direction).
    IP_CT_RELATED		= 1

    # Started a new connection to track (only
    # IP_CT_DIR_ORIGINAL); may be a retransmission.
    IP_CT_NEW			= 2

    # >= this indicates reply direction
    IP_CT_IS_REPLY		= 3

    IP_CT_ESTABLISHED_REPLY	= IP_CT_ESTABLISHED + IP_CT_IS_REPLY
    IP_CT_RELATED_REPLY		= IP_CT_RELATED + IP_CT_IS_REPLY
    IP_CT_NEW_REPLY		= IP_CT_NEW + IP_CT_IS_REPLY

    # Number of distinct IP_CT types (no NEW in reply dirn).
    IP_CT_NUMBER		= IP_CT_IS_REPLY * 2 - 1
IP_CT_ESTABLISHED	= 0
IP_CT_RELATED		= 1
IP_CT_NEW		= 2
IP_CT_IS_REPLY		= 3
IP_CT_ESTABLISHED_REPLY	= IP_CT_ESTABLISHED + IP_CT_IS_REPLY
IP_CT_RELATED_REPLY	= IP_CT_RELATED + IP_CT_IS_REPLY
IP_CT_NEW_REPLY		= IP_CT_NEW + IP_CT_IS_REPLY
IP_CT_NUMBER		= IP_CT_IS_REPLY * 2 - 1


NF_CT_STATE_INVALID_BIT = (1 << 0)
def NF_CT_STATE_BIT(ctinfo): return (1 << ((ctinfo) % IP_CT_IS_REPLY + 1))
NF_CT_STATE_UNTRACKED_BIT = (1 << (IP_CT_NUMBER + 1))

# Bitset representing status of connection.
# enum ip_conntrack_status
class IpConntrackStatus(Enum):
    # It's an expected connection: bit 0 set.  This bit never changed
    IPS_EXPECTED_BIT		= 0
    IPS_EXPECTED		= (1 << IPS_EXPECTED_BIT)

    # We've seen packets both ways: bit 1 set.  Can be set, not unset.
    IPS_SEEN_REPLY_BIT		= 1
    IPS_SEEN_REPLY		= (1 << IPS_SEEN_REPLY_BIT)

    # Conntrack should never be early-expired.
    IPS_ASSURED_BIT		= 2
    IPS_ASSURED			= (1 << IPS_ASSURED_BIT)

    # Connection is confirmed: originating packet has left box
    IPS_CONFIRMED_BIT		= 3
    IPS_CONFIRMED		= (1 << IPS_CONFIRMED_BIT)

    # Connection needs src nat in orig dir.  This bit never changed.
    IPS_SRC_NAT_BIT		= 4
    IPS_SRC_NAT			= (1 << IPS_SRC_NAT_BIT)

    # Connection needs dst nat in orig dir.  This bit never changed.
    IPS_DST_NAT_BIT		= 5
    IPS_DST_NAT			= (1 << IPS_DST_NAT_BIT)

    # Both together.
    IPS_NAT_MASK		= (IPS_DST_NAT | IPS_SRC_NAT)

    # Connection needs TCP sequence adjusted.
    IPS_SEQ_ADJUST_BIT		= 6
    IPS_SEQ_ADJUST		= (1 << IPS_SEQ_ADJUST_BIT)

    # NAT initialization bits.
    IPS_SRC_NAT_DONE_BIT	= 7
    IPS_SRC_NAT_DONE		= (1 << IPS_SRC_NAT_DONE_BIT)

    IPS_DST_NAT_DONE_BIT	= 8
    IPS_DST_NAT_DONE		= (1 << IPS_DST_NAT_DONE_BIT)

    # Both together
    IPS_NAT_DONE_MASK		= (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE)

    # Connection is dying (removed from lists), can not be unset.
    IPS_DYING_BIT		= 9
    IPS_DYING			= (1 << IPS_DYING_BIT)

    # Connection has fixed timeout.
    IPS_FIXED_TIMEOUT_BIT	= 10
    IPS_FIXED_TIMEOUT		= (1 << IPS_FIXED_TIMEOUT_BIT)

    # Conntrack is a template
    IPS_TEMPLATE_BIT		= 11
    IPS_TEMPLATE		= (1 << IPS_TEMPLATE_BIT)

    # Conntrack is a fake untracked entry
    IPS_UNTRACKED_BIT		= 12
    IPS_UNTRACKED		= (1 << IPS_UNTRACKED_BIT)

    # Conntrack got a helper explicitly attached via CT target.
    IPS_HELPER_BIT		= 13
    IPS_HELPER			= (1 << IPS_HELPER_BIT)
IPS_EXPECTED_BIT	= 0
IPS_EXPECTED		= (1 << IPS_EXPECTED_BIT)
IPS_SEEN_REPLY_BIT	= 1
IPS_SEEN_REPLY		= (1 << IPS_SEEN_REPLY_BIT)
IPS_ASSURED_BIT		= 2
IPS_ASSURED		= (1 << IPS_ASSURED_BIT)
IPS_CONFIRMED_BIT	= 3
IPS_CONFIRMED		= (1 << IPS_CONFIRMED_BIT)
IPS_SRC_NAT_BIT		= 4
IPS_SRC_NAT		= (1 << IPS_SRC_NAT_BIT)
IPS_DST_NAT_BIT		= 5
IPS_DST_NAT		= (1 << IPS_DST_NAT_BIT)
IPS_NAT_MASK		= (IPS_DST_NAT | IPS_SRC_NAT)
IPS_SEQ_ADJUST_BIT	= 6
IPS_SEQ_ADJUST		= (1 << IPS_SEQ_ADJUST_BIT)
IPS_SRC_NAT_DONE_BIT	= 7
IPS_SRC_NAT_DONE	= (1 << IPS_SRC_NAT_DONE_BIT)
IPS_DST_NAT_DONE_BIT	= 8
IPS_DST_NAT_DONE	= (1 << IPS_DST_NAT_DONE_BIT)
IPS_NAT_DONE_MASK	= (IPS_DST_NAT_DONE | IPS_SRC_NAT_DONE)
IPS_DYING_BIT		= 9
IPS_DYING		= (1 << IPS_DYING_BIT)
IPS_FIXED_TIMEOUT_BIT	= 10
IPS_FIXED_TIMEOUT	= (1 << IPS_FIXED_TIMEOUT_BIT)
IPS_TEMPLATE_BIT	= 11
IPS_TEMPLATE		= (1 << IPS_TEMPLATE_BIT)
IPS_UNTRACKED_BIT	= 12
IPS_UNTRACKED		= (1 << IPS_UNTRACKED_BIT)
IPS_HELPER_BIT		= 13
IPS_HELPER		= (1 << IPS_HELPER_BIT)

# Connection tracking event types
# enum ip_conntrack_events
class IpConntrackEvents(Enum):
    IPCT_NEW		= 0  # new conntrack
    IPCT_RELATED	= 1  # related conntrack
    IPCT_DESTROY	= 2  # destroyed conntrack
    IPCT_REPLY		= 3  # connection has seen two-way traffic
    IPCT_ASSURED	= 4  # connection status has changed to assured
    IPCT_PROTOINFO	= 5  # protocol information has changed
    IPCT_HELPER		= 6  # new helper has been set
    IPCT_MARK		= 7  # new mark has been set
    IPCT_SEQADJ		= 8  # sequence adjustment has changed
    IPCT_NATSEQADJ	= IPCT_SEQADJ
    IPCT_SECMARK	= 9  # new security mark has been set
    IPCT_LABEL		= 10 # new connlabel has been set
IPCT_NEW		= 0
IPCT_RELATED	= 1
IPCT_DESTROY	= 2
IPCT_REPLY		= 3
IPCT_ASSURED	= 4
IPCT_PROTOINFO	= 5
IPCT_HELPER		= 6
IPCT_MARK		= 7
IPCT_SEQADJ		= 8
IPCT_NATSEQADJ	= IPCT_SEQADJ
IPCT_SECMARK	= 9
IPCT_LABEL		= 10

# enum ip_conntrack_expect_events
class IpConntrackExpectEvents(Enum):
    IPEXP_NEW		= 0 # new expectation
    IPEXP_DESTROY	= 1 # destroyed expectation
IPEXP_NEW		= 0
IPEXP_DESTROY	= 1

# expectation flags
NF_CT_EXPECT_PERMANENT	= 0x1
NF_CT_EXPECT_INACTIVE	= 0x2
NF_CT_EXPECT_USERSPACE	= 0x4
