# -*- coding: utf-8 -*-

from __future__ import absolute_import

from ctypes import *
import errno

from .linux import netlinkh as netlink

LIBMNL = CDLL("libmnl.so", use_errno=True)

c_socklen_t = c_uint
c_pid_t = c_int
try:
    from ctypes import c_ssize_t
except ImportError:
    c_ssize_t = c_longlong

'''
treat inner struct as opaque, c_void_p

class MnlSocket(Structure):
    """struct mnl_socket
    """
    _fields_ = [("fd",		c_int),      # int fd
                ("addr",	SockaddrNl)] # struct sockaddr_nl	addr


class MnlNlmsgBatch(Structure):
    """struct mnl_nlmsg_batch
    """
    _fields_ = [
	# the buffer that is used to store the batch.
	("buf",		c_void_p), # void *buf
	("limit",	c_size_t), # size_t limit
	("buflen",	c_size_t), # size_t buflen
	# the current netlink message in the batch.
        ("cur",		c_void_p), # void *cur
	("overflow",	c_bool)]   # bool overflow
'''

###
## Netlink socket API
###
# extern struct mnl_socket *mnl_socket_open(int type);
c_socket_open = LIBMNL.mnl_socket_open
c_socket_open.argtypes = [c_int]
# c_socket_open.restype = POINTER(MnlSocket)
c_socket_open.restype = c_void_p

# extern int mnl_socket_bind(struct mnl_socket *nl, unsigned int groups, pid_t pid);
c_socket_bind = LIBMNL.mnl_socket_bind
# c_socket_bind.argtypes = [POINTER(MnlSocket), c_uint, c_pid_t]
c_socket_bind.argtypes = [c_void_p, c_uint, c_pid_t]
c_socket_bind.restype = c_int

# extern int mnl_socket_set_ringopt(struct mnl_socket *nl, struct nl_mmap_req *req, enum mnl_ring_types type);
c_socket_set_ringopt = LIBMNL.mnl_socket_set_ringopt
c_socket_set_ringopt.argtypes = [c_void_p, POINTER(netlink.NlMmapReq), c_int]
c_socket_set_ringopt.restype = c_int

# extern int mnl_socket_map_ring(struct mnl_socket *nl);
c_socket_map_ring = LIBMNL.mnl_socket_map_ring
c_socket_map_ring.argtypes = [c_void_p]
c_socket_map_ring.restype = c_int

# extern struct nl_mmap_hdr *mnl_socket_get_frame(const struct mnl_socket *nl, enum mnl_ring_types type);
c_socket_get_frame = LIBMNL.mnl_socket_get_frame
c_socket_get_frame.argtypes = [c_void_p, c_int]
c_socket_get_frame.restype = POINTER(netlink.NlMmapHdr)

# extern int mnl_socket_advance_ring(const struct mnl_socket *nl, enum mnl_ring_types type);
c_socket_advance_ring = LIBMNL.mnl_socket_advance_ring
c_socket_advance_ring.argtypes = [c_void_p, c_int]
c_socket_advance_ring.restype = c_int

# extern int mnl_socket_close(struct mnl_socket *nl);
c_socket_close = LIBMNL.mnl_socket_close
# c_socket_close.argtypes = [POINTER(MnlSocket)]
c_socket_close.argtypes = [c_void_p]
c_socket_close.restype = c_int

# extern int mnl_socket_get_fd(const struct mnl_socket *nl);
c_socket_get_fd = LIBMNL.mnl_socket_get_fd
# c_socket_get_fd.argtypes = [(POINTER(MnlSocket))]
c_socket_get_fd.argtypes = [c_void_p]
c_socket_get_fd.restype = c_int

# extern unsigned int mnl_socket_get_portid(const struct mnl_socket *nl);
c_socket_get_portid = LIBMNL.mnl_socket_get_portid
# c_socket_get_portid.argtypes = [POINTER(MnlSocket)]
c_socket_get_portid.argtypes = [c_void_p]
c_socket_get_portid.restype = c_uint

# extern ssize_t mnl_socket_sendto(const struct mnl_socket *nl, const void *req, size_t siz);
c_socket_sendto = LIBMNL.mnl_socket_sendto
# c_socket_sendto.argtypes = [(POINTER(MnlSocket)), c_void_p, c_size_t]
c_socket_sendto.argtypes = [c_void_p, c_void_p, c_size_t]
c_socket_sendto.restype = c_ssize_t

# extern ssize_t mnl_socket_recvfrom(const struct mnl_socket *nl, void *buf, size_t siz);
c_socket_recvfrom = LIBMNL.mnl_socket_recvfrom
# c_socket_recvfrom.argtypes = [POINTER(MnlSocket), c_void_p, c_size_t]
c_socket_recvfrom.argtypes = [c_void_p, c_void_p, c_size_t]
c_socket_recvfrom.restype = c_ssize_t

# extern int mnl_socket_setsockopt(const struct mnl_socket *nl, int type, void *buf, socklen_t len);
c_socket_setsockopt = LIBMNL.mnl_socket_setsockopt
# c_socket_setsockopt.argtypes = [POINTER(MnlSocket), c_int, c_void_p, c_socklen_t]
c_socket_setsockopt.argtypes = [c_void_p, c_int, c_void_p, c_socklen_t]
c_socket_setsockopt.restype = c_int

# extern int mnl_socket_getsockopt(const struct mnl_socket *nl, int type, void *buf, socklen_t *len);
c_socket_getsockopt = LIBMNL.mnl_socket_getsockopt
# c_socket_getsockopt.argtypes = [POINTER(MnlSocket), c_int, c_void_p, c_void_p]
c_socket_getsockopt.argtypes = [c_void_p, c_int, c_void_p, c_void_p]
c_socket_getsockopt.restype = c_int

###
## Netlink message API
###
# extern size_t mnl_nlmsg_size(size_t len);
c_nlmsg_size = LIBMNL.mnl_nlmsg_size
c_nlmsg_size.argtypes = [c_size_t]
c_nlmsg_size.restype = c_size_t

# extern size_t mnl_nlmsg_get_payload_len(const struct nlmsghdr *nlh);
c_nlmsg_get_payload_len = LIBMNL.mnl_nlmsg_get_payload_len
c_nlmsg_get_payload_len.argtypes = [POINTER(netlink.Nlmsghdr)]
c_nlmsg_get_payload_len.restype = c_size_t

## Netlink message header builder
# extern struct nlmsghdr *mnl_nlmsg_put_header(void *buf);
c_nlmsg_put_header = LIBMNL.mnl_nlmsg_put_header
c_nlmsg_put_header.argtypes = [c_void_p]
c_nlmsg_put_header.restype = POINTER(netlink.Nlmsghdr)

# extern void *mnl_nlmsg_put_extra_header(struct nlmsghdr *nlh, size_t size);
c_nlmsg_put_extra_header = LIBMNL.mnl_nlmsg_put_extra_header
c_nlmsg_put_extra_header.argtypes = [POINTER(netlink.Nlmsghdr), c_size_t]
c_nlmsg_put_extra_header.restype = c_void_p

## Netlink message iterators
# extern bool mnl_nlmsg_ok(const struct nlmsghdr *nlh, int len);
c_nlmsg_ok = LIBMNL.mnl_nlmsg_ok
c_nlmsg_ok.argtypes = [POINTER(netlink.Nlmsghdr), c_int]
c_nlmsg_ok.restype = c_bool

# extern struct nlmsghdr *mnl_nlmsg_next(const struct nlmsghdr *nlh, int *len);
c_nlmsg_next = LIBMNL.mnl_nlmsg_next
c_nlmsg_next.argtypes = [POINTER(netlink.Nlmsghdr), c_void_p]
c_nlmsg_next.restype = POINTER(netlink.Nlmsghdr)

## Netlink sequence tracking
# extern bool mnl_nlmsg_seq_ok(const struct nlmsghdr *nlh, unsigned int seq);
c_nlmsg_seq_ok = LIBMNL.mnl_nlmsg_seq_ok
c_nlmsg_seq_ok.argtypes = [POINTER(netlink.Nlmsghdr), c_uint]
c_nlmsg_seq_ok.restype = c_bool

## Netlink portID checking
# extern bool mnl_nlmsg_portid_ok(const struct nlmsghdr *nlh, unsigned int portid);
c_nlmsg_portid_ok = LIBMNL.mnl_nlmsg_portid_ok
c_nlmsg_portid_ok.argtypes = [POINTER(netlink.Nlmsghdr), c_uint]
c_nlmsg_portid_ok.restype = c_bool

## Netlink message getters
# extern void *mnl_nlmsg_get_payload(const struct nlmsghdr *nlh);
c_nlmsg_get_payload = LIBMNL.mnl_nlmsg_get_payload
c_nlmsg_get_payload.argtypes = [POINTER(netlink.Nlmsghdr)]
c_nlmsg_get_payload.restype = c_void_p

# extern void *mnl_nlmsg_get_payload_offset(const struct nlmsghdr *nlh, size_t offset);
c_nlmsg_get_payload_offset = LIBMNL.mnl_nlmsg_get_payload_offset
c_nlmsg_get_payload_offset.argtypes = [POINTER(netlink.Nlmsghdr), c_size_t]
c_nlmsg_get_payload_offset.restype = c_void_p

# extern void *mnl_nlmsg_get_payload_tail(const struct nlmsghdr *nlh);
c_nlmsg_get_payload_tail = LIBMNL.mnl_nlmsg_get_payload_tail
c_nlmsg_get_payload_tail.argtypes = [POINTER(netlink.Nlmsghdr)]
c_nlmsg_get_payload_tail.restype = c_void_p

## Netlink message printer
c_fdopen = CDLL("libc.so.6").fdopen
c_fdopen.argtypes = [c_int, c_char_p]
c_fdopen.restype = c_void_p
# extern void mnl_nlmsg_fprintf(FILE *fd, const void *data, size_t datalen, size_t extra_header_size);
c_nlmsg_fprintf = LIBMNL.mnl_nlmsg_fprintf
c_nlmsg_fprintf.argtypes = [c_void_p, c_void_p, c_size_t, c_size_t]

## Message batch helpers
# extern struct mnl_nlmsg_batch *mnl_nlmsg_batch_start(void *buf, size_t bufsiz);
c_nlmsg_batch_start = LIBMNL.mnl_nlmsg_batch_start
c_nlmsg_batch_start.argtypes = [c_void_p, c_size_t]
# c_nlmsg_batch_start.restype = POINTER(MnlNlmsgBatch)
c_nlmsg_batch_start.restype = c_void_p

# extern bool mnl_nlmsg_batch_next(struct mnl_nlmsg_batch *b);
c_nlmsg_batch_next = LIBMNL.mnl_nlmsg_batch_next
# c_nlmsg_batch_next.argtypes = [POINTER(MnlNlmsgBatch)]
c_nlmsg_batch_next.argtypes = [c_void_p]
c_nlmsg_batch_next.restype = c_bool

# extern void mnl_nlmsg_batch_stop(struct mnl_nlmsg_batch *b);
c_nlmsg_batch_stop = LIBMNL.mnl_nlmsg_batch_stop
# c_nlmsg_batch_stop.argtypes = [POINTER(MnlNlmsgBatch)]
c_nlmsg_batch_stop.argtypes = [c_void_p]

# extern size_t mnl_nlmsg_batch_size(struct mnl_nlmsg_batch *b);
c_nlmsg_batch_size = LIBMNL.mnl_nlmsg_batch_size
# c_nlmsg_batch_size.argtypes = [POINTER(MnlNlmsgBatch)]
c_nlmsg_batch_size.argtypes = [c_void_p]
c_nlmsg_batch_size.restype = c_size_t

# extern void mnl_nlmsg_batch_reset(struct mnl_nlmsg_batch *b);
c_nlmsg_batch_reset = LIBMNL.mnl_nlmsg_batch_reset
# c_nlmsg_batch_reset.argtypes = [POINTER(MnlNlmsgBatch)]
c_nlmsg_batch_reset.argtypes = [c_void_p]

# extern void *mnl_nlmsg_batch_head(struct mnl_nlmsg_batch *b);
c_nlmsg_batch_head = LIBMNL.mnl_nlmsg_batch_head
# c_nlmsg_batch_reset.argtypes = [POINTER(MnlNlmsgBatch)]
c_nlmsg_batch_reset.argtypes = [c_void_p]
c_nlmsg_batch_reset.restype = c_void_p

# extern void *mnl_nlmsg_batch_current(struct mnl_nlmsg_batch *b);
c_nlmsg_batch_current = LIBMNL.mnl_nlmsg_batch_current
# c_nlmsg_batch_current.argtypes = [POINTER(MnlNlmsgBatch)]
c_nlmsg_batch_current.argtypes = [c_void_p]
c_nlmsg_batch_current.restype = c_void_p

# extern bool mnl_nlmsg_batch_is_empty(struct mnl_nlmsg_batch *b);
c_nlmsg_batch_is_empty = LIBMNL.mnl_nlmsg_batch_is_empty
# c_nlmsg_batch_is_empty.argtypes = [POINTER(MnlNlmsgBatch)]
c_nlmsg_batch_is_empty.argtypes = [c_void_p]
c_nlmsg_batch_is_empty.restype = c_bool


###
##  Netlink attributes API
###
## TLV attribute getters
# extern uint16_t mnl_attr_get_type(const struct nlattr *attr);
c_attr_get_type = LIBMNL.mnl_attr_get_type
c_attr_get_type.argtypes = [POINTER(netlink.Nlattr)]
c_attr_get_type.restype = c_uint16

# extern uint16_t mnl_attr_get_len(const struct nlattr *attr);
c_attr_get_len = LIBMNL.mnl_attr_get_len
c_attr_get_len.argtypes = [POINTER(netlink.Nlattr)]
c_attr_get_len.restype = c_uint16

# extern uint16_t mnl_attr_get_payload_len(const struct nlattr *attr);
c_attr_get_payload_len = LIBMNL.mnl_attr_get_payload_len
c_attr_get_payload_len.argtypes = [POINTER(netlink.Nlattr)]
c_attr_get_payload_len.restype = c_uint16

# extern void *mnl_attr_get_payload(const struct nlattr *attr);
c_attr_get_payload = LIBMNL.mnl_attr_get_payload
c_attr_get_payload.argtypes = [POINTER(netlink.Nlattr)]
c_attr_get_payload.restype = c_void_p

# extern uint8_t mnl_attr_get_u8(const struct nlattr *attr);
c_attr_get_u8 = LIBMNL.mnl_attr_get_u8
c_attr_get_u8.argtypes = [POINTER(netlink.Nlattr)]
c_attr_get_u8.restype = c_uint8

# extern uint16_t mnl_attr_get_u16(const struct nlattr *attr);
c_attr_get_u16 = LIBMNL.mnl_attr_get_u16
c_attr_get_u16.argtypes = [POINTER(netlink.Nlattr)]
c_attr_get_u16.restype = c_uint16

# extern uint32_t mnl_attr_get_u32(const struct nlattr *attr);
c_attr_get_u32 = LIBMNL.mnl_attr_get_u32
c_attr_get_u32.argtypes = [POINTER(netlink.Nlattr)]
c_attr_get_u32.restype = c_uint32

# extern uint64_t mnl_attr_get_u64(const struct nlattr *attr);
c_attr_get_u64 = LIBMNL.mnl_attr_get_u64
c_attr_get_u64.argtypes = [POINTER(netlink.Nlattr)]
c_attr_get_u64.restype = c_uint64

# extern const char *mnl_attr_get_str(const struct nlattr *attr);
c_attr_get_str = LIBMNL.mnl_attr_get_str
c_attr_get_str.argtypes = [POINTER(netlink.Nlattr)]
c_attr_get_str.restype = c_char_p

## TLV attribute putters
# extern void mnl_attr_put(struct nlmsghdr *nlh, uint16_t type, size_t len, const void *data);
c_attr_put = LIBMNL.mnl_attr_put
c_attr_put.argtypes = [POINTER(netlink.Nlmsghdr), c_uint16, c_size_t, c_void_p]

# extern void mnl_attr_put_u8(struct nlmsghdr *nlh, uint16_t type, uint8_t data);
c_attr_put_u8 = LIBMNL.mnl_attr_put_u8
c_attr_put_u8.argtypes = [POINTER(netlink.Nlmsghdr), c_uint16, c_uint8]

# extern void mnl_attr_put_u16(struct nlmsghdr *nlh, uint16_t type, uint16_t data);
c_attr_put_u16 = LIBMNL.mnl_attr_put_u16
c_attr_put_u16.argtypes = [POINTER(netlink.Nlmsghdr), c_uint16, c_uint16]

# extern void mnl_attr_put_u32(struct nlmsghdr *nlh, uint16_t type, uint32_t data);
c_attr_put_u32 = LIBMNL.mnl_attr_put_u32
c_attr_put_u32.argtypes = [POINTER(netlink.Nlmsghdr), c_uint16, c_uint32]

# extern void mnl_attr_put_u64(struct nlmsghdr *nlh, uint16_t type, uint64_t data);
c_attr_put_u64 = LIBMNL.mnl_attr_put_u64
c_attr_put_u64.argtypes = [POINTER(netlink.Nlmsghdr), c_uint16, c_uint64]

# extern void mnl_attr_put_str(struct nlmsghdr *nlh, uint16_t type, const char *data);
c_attr_put_str = LIBMNL.mnl_attr_put_str
c_attr_put_str.argtypes = [POINTER(netlink.Nlmsghdr), c_uint16, c_char_p]

# extern void mnl_attr_put_strz(struct nlmsghdr *nlh, uint16_t type, const char *data);
c_attr_put_strz = LIBMNL.mnl_attr_put_strz
c_attr_put_strz.argtypes = [POINTER(netlink.Nlmsghdr), c_uint16, c_char_p]


## TLV attribute putters with buffer boundary checkings
# extern bool mnl_attr_put_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, size_t len, const void *data);
c_attr_put_check = LIBMNL.mnl_attr_put_check
c_attr_put_check.argtypes = [POINTER(netlink.Nlmsghdr), c_size_t, c_uint16, c_size_t, c_void_p]
c_attr_put_check.restype = c_bool

# extern bool mnl_attr_put_u8_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, uint8_t data);
c_attr_put_u8_check = LIBMNL.mnl_attr_put_u8_check
c_attr_put_u8_check.argtypes = [POINTER(netlink.Nlmsghdr), c_size_t, c_uint16, c_uint8]
c_attr_put_u8_check.restype = c_bool

# extern bool mnl_attr_put_u16_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, uint16_t data);
c_attr_put_u16_check = LIBMNL.mnl_attr_put_u16_check
c_attr_put_u16_check.argtypes = [POINTER(netlink.Nlmsghdr), c_size_t, c_uint16, c_uint16]
c_attr_put_u16_check.restype = c_bool

# extern bool mnl_attr_put_u32_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, uint32_t data);
c_attr_put_u32_check = LIBMNL.mnl_attr_put_u32_check
c_attr_put_u32_check.argtypes = [POINTER(netlink.Nlmsghdr), c_size_t, c_uint16, c_uint32]
c_attr_put_u32_check.restype = c_bool

# extern bool mnl_attr_put_u64_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, uint64_t data);
c_attr_put_u64_check = LIBMNL.mnl_attr_put_u64_check
c_attr_put_u64_check.argtypes = [POINTER(netlink.Nlmsghdr), c_size_t, c_uint16, c_uint64]
c_attr_put_u64_check.restype = c_bool

# extern bool mnl_attr_put_str_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, const char *data);
c_attr_put_str_check = LIBMNL.mnl_attr_put_str_check
c_attr_put_str_check.argtypes = [POINTER(netlink.Nlmsghdr), c_size_t, c_uint16, c_char_p]
c_attr_put_str_check.restype = c_bool

# extern bool mnl_attr_put_strz_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, const char *data);
c_attr_put_strz_check = LIBMNL.mnl_attr_put_strz_check
c_attr_put_strz_check.argtypes = [POINTER(netlink.Nlmsghdr), c_size_t, c_uint16, c_char_p]
c_attr_put_strz_check.restype = c_bool


## TLV attribute nesting
# extern struct nlattr *mnl_attr_nest_start(struct nlmsghdr *nlh, uint16_t type);
c_attr_nest_start = LIBMNL.mnl_attr_nest_start
c_attr_nest_start.argtypes = [POINTER(netlink.Nlmsghdr), c_uint16]
c_attr_nest_start.restype = POINTER(netlink.Nlattr)

# extern struct nlattr *mnl_attr_nest_start_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type);
c_attr_nest_start_check = LIBMNL.mnl_attr_nest_start_check
c_attr_nest_start_check.argtypes = [POINTER(netlink.Nlmsghdr), c_size_t, c_uint16]
c_attr_nest_start_check.restype = POINTER(netlink.Nlattr)

# extern void mnl_attr_nest_end(struct nlmsghdr *nlh, struct nlattr *start);
c_attr_nest_end = LIBMNL.mnl_attr_nest_end
c_attr_nest_end.argtypes = [POINTER(netlink.Nlmsghdr), POINTER(netlink.Nlattr)]

# extern void mnl_attr_nest_cancel(struct nlmsghdr *nlh, struct nlattr *start);
c_attr_nest_cancel = LIBMNL.mnl_attr_nest_cancel
c_attr_nest_cancel.argtypes = [POINTER(netlink.Nlmsghdr), POINTER(netlink.Nlattr)]


# TLV validation
# extern int mnl_attr_type_valid(const struct nlattr *attr, uint16_t maxtype);
c_attr_type_valid = LIBMNL.mnl_attr_type_valid
c_attr_type_valid.argtypes = [POINTER(netlink.Nlattr), c_uint16]
c_attr_type_valid.restypes = c_int

# extern int mnl_attr_validate(const struct nlattr *attr, enum mnl_attr_data_type type);
c_attr_validate = LIBMNL.mnl_attr_validate
c_attr_validate.argtypes = [POINTER(netlink.Nlattr), c_int]
c_attr_validate.restype = c_int

# extern int mnl_attr_validate2(const struct nlattr *attr, enum mnl_attr_data_type type, size_t len);
c_attr_validate2 = LIBMNL.mnl_attr_validate2
c_attr_validate2.argtypes = [POINTER(netlink.Nlattr), c_int, c_size_t]
c_attr_validate2 .restype = c_int

## TLV iterators
# extern bool mnl_attr_ok(const struct nlattr *attr, int len);
c_attr_ok = LIBMNL.mnl_attr_ok
c_attr_ok.argtypes = [POINTER(netlink.Nlattr), c_int]
c_attr_ok.restype = c_bool

# extern struct nlattr *mnl_attr_next(const struct nlattr *attr);
c_attr_next = LIBMNL.mnl_attr_next
c_attr_next.argtypes = [POINTER(netlink.Nlattr)]
c_attr_next.restype = POINTER(netlink.Nlattr)


## macro
##define mnl_attr_for_each(attr, nlh, offset) \
#	for ((attr) = mnl_nlmsg_get_payload_offset((nlh), (offset)); \
#	     mnl_attr_ok((attr), (char *)mnl_nlmsg_get_payload_tail(nlh) - (char *)(attr)); \
#	     (attr) = mnl_attr_next(attr))
##define mnl_attr_for_each_nested(attr, nest) \
#	for ((attr) = mnl_attr_get_payload(nest); \
#	     mnl_attr_ok((attr), (char *)mnl_attr_get_payload(nest) + mnl_attr_get_payload_len(nest) - (char *)(attr)); \
#	     (attr) = mnl_attr_next(attr))
#
##define mnl_attr_for_each_payload(payload, payload_size) \
#	for ((attr) = (payload); \
#	     mnl_attr_ok((attr), (char *)(payload) + payload_size - (char *)(attr)); \
#	     (attr) = mnl_attr_next(attr))

## TLV callback-based attribute parsers
#typedef int (*mnl_attr_cb_t)(const struct nlattr *attr, void *data);
MNL_ATTR_CB_T = CFUNCTYPE(c_int, POINTER(netlink.Nlattr), c_void_p, use_errno=True)

# extern int mnl_attr_parse(const struct nlmsghdr *nlh, unsigned int offset, mnl_attr_cb_t cb, void *data);
c_attr_parse = LIBMNL.mnl_attr_parse
c_attr_parse.argtypes = [POINTER(netlink.Nlmsghdr), c_uint, MNL_ATTR_CB_T, py_object]
c_attr_parse.restype = c_int

# extern int mnl_attr_parse_nested(const struct nlattr *attr, mnl_attr_cb_t cb, void *data);
c_attr_parse_nested = LIBMNL.mnl_attr_parse_nested
c_attr_parse_nested.argtypes = [POINTER(netlink.Nlattr), MNL_ATTR_CB_T, py_object]
c_attr_parse_nested.restype = c_int

# extern int mnl_attr_parse_payload(const void *payload, size_t payload_len, mnl_attr_cb_t cb, void *data);
c_attr_parse_payload = LIBMNL.mnl_attr_parse_payload
c_attr_parse_payload.argtypes = [c_void_p, c_size_t, MNL_ATTR_CB_T, py_object]
c_attr_parse_payload.restype = c_int


##
# callback API
##
#typedef int (*mnl_cb_t)(const struct nlmsghdr *nlh, void *data);
MNL_CB_T = CFUNCTYPE(c_int, POINTER(netlink.Nlmsghdr), py_object)

# extern int mnl_cb_run(const void *buf, size_t numbytes, unsigned int seq,
#		      unsigned int portid, mnl_cb_t cb_data, void *data);
c_cb_run = LIBMNL.mnl_cb_run
c_cb_run.argtypes = [c_void_p, c_size_t, c_uint, c_uint, MNL_CB_T, py_object]
c_cb_run.restype = c_int

# extern int mnl_cb_run2(const void *buf, size_t numbytes, unsigned int seq,
#		       unsigned int portid, mnl_cb_t cb_data, void *data,
#		       mnl_cb_t *cb_ctl_array, unsigned int cb_ctl_array_len);
c_cb_run2 = LIBMNL.mnl_cb_run2
c_cb_run2.argtypes = [c_void_p, c_size_t, c_uint, c_uint, MNL_CB_T, py_object, POINTER(MNL_CB_T), c_uint]
c_cb_run2.restype = c_int


# helper
def c_raise_if_errno():
    en = get_errno()
    if en != 0:
        raise OSError(en, errno.errorcode[en])


def os_error():
    en = get_errno()
    return OSError(en, errno.errorcode[en])
