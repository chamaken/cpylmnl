# -*- coding: utf-8 -*-

from ctypes import *
from cpylmnl.nlstruct import NLStructure
import cpylmnl.linux.netlinkh as netlink

GENL_NAMSIZ		= 16 # length of family name

GENL_MIN_ID		= netlink.NLMSG_MIN_TYPE
GENL_MAX_ID		= 1023

class Genlmsghdr(NLStructure):
    """struct genlmsghdr
    """
    _fields_ = [("cmd",		c_uint8),   # __u8	cmd
                ("version",	c_uint8),   # __u8	version
                ("reserved",	c_uint16)]  # __u16	reserved

GENL_HDR_LEN		= netlink.NLMSG_ALIGN(sizeof(Genlmsghdr))

GENL_ADMIN_PERM		= 0x01
GENL_CMD_CAP_DO		= 0x02
GENL_CMD_CAP_DUMP	= 0x04
GENL_CMD_CAP_HASPOL	= 0x08

# List of reserved static generic netlink identifiers:
GENL_ID_GENERATE	= 0
GENL_ID_CTRL		= netlink.NLMSG_MIN_TYPE
GENL_ID_VFS_DQUOT	= netlink.NLMSG_MIN_TYPE + 1
GENL_ID_PMCRAID		= netlink.NLMSG_MIN_TYPE + 2


# Controller
# enum
CTRL_CMD_UNSPEC		= 0
CTRL_CMD_NEWFAMILY	= 1
CTRL_CMD_DELFAMILY	= 2
CTRL_CMD_GETFAMILY	= 3
CTRL_CMD_NEWOPS		= 4
CTRL_CMD_DELOPS		= 5
CTRL_CMD_GETOPS		= 6
CTRL_CMD_NEWMCAST_GRP	= 7
CTRL_CMD_DELMCAST_GRP	= 8
CTRL_CMD_GETMCAST_GRP	= 9
__CTRL_CMD_MAX		= 10
CTRL_CMD_MAX		= (__CTRL_CMD_MAX - 1)

# enum
CTRL_ATTR_UNSPEC	= 0
CTRL_ATTR_FAMILY_ID	= 1
CTRL_ATTR_FAMILY_NAME	= 2
CTRL_ATTR_VERSION	= 3
CTRL_ATTR_HDRSIZE	= 4
CTRL_ATTR_MAXATTR	= 5
CTRL_ATTR_OPS		= 6
CTRL_ATTR_MCAST_GROUPS	= 7
__CTRL_ATTR_MAX		= 8
CTRL_ATTR_MAX		= (__CTRL_ATTR_MAX - 1)

# enum
CTRL_ATTR_OP_UNSPEC	= 0
CTRL_ATTR_OP_ID		= 1
CTRL_ATTR_OP_FLAGS	= 2
__CTRL_ATTR_OP_MAX	= 3
CTRL_ATTR_OP_MAX	= (__CTRL_ATTR_OP_MAX - 1)

# enum
CTRL_ATTR_MCAST_GRP_UNSPEC	= 0
CTRL_ATTR_MCAST_GRP_NAME	= 1
CTRL_ATTR_MCAST_GRP_ID		= 2
__CTRL_ATTR_MCAST_GRP_MAX	= 3
CTRL_ATTR_MCAST_GRP_MAX		= (__CTRL_ATTR_MCAST_GRP_MAX - 1)
