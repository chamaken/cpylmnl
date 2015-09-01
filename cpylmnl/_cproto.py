# -*- coding: utf-8 -*-

from __future__ import absolute_import

import errno, ctypes

from .linux import netlinkh as netlink

LIBMNL = ctypes.CDLL("libmnl.so", use_errno=True)

c_socklen_t = ctypes.c_uint
c_pid_t = ctypes.c_int
try:
    from ctypes import c_ssize_t
except ImportError:
    c_ssize_t = ctypes.c_longlong

"""handle inner struct - mnl_socket, mnl_nlmsg_batch, mnl_ring as opaque, ctypes.c_void_p"""

###
## Netlink socket API
###

c_socket_open = LIBMNL.mnl_socket_open
c_socket_open.__doc__ = """\
struct mnl_socket *mnl_socket_open(int type)"""
c_socket_open.argtypes = [ctypes.c_int]
c_socket_open.restype = ctypes.c_void_p

c_socket_fdopen = LIBMNL.mnl_socket_fdopen
c_socket_fdopen.__doc__ = """\
struct mnl_socket *mnl_socket_fdopen(int fd)"""
c_socket_fdopen.argtypes = [ctypes.c_int]
c_socket_fdopen.restype = ctypes.c_void_p

c_socket_bind = LIBMNL.mnl_socket_bind
c_socket_bind.__doc__ = """\
int mnl_socket_bind(struct mnl_socket *nl, unsigned int groups, pid_t pid)"""
c_socket_bind.argtypes = [ctypes.c_void_p, ctypes.c_uint, c_pid_t]
c_socket_bind.restype = ctypes.c_int

HAS_MNL_RING = False # whether libmnl has mmap extention or not

try: # ring functions
    c_socket_set_ringopt = LIBMNL.mnl_socket_set_ringopt
    c_socket_set_ringopt.__doc__ = """\
int mnl_socket_set_ringopt(struct mnl_socket *nl, enum mnl_ring_type type,
			   unsigned int block_size, unsigned int block_nf,
			   unsigned int frame_size, unsigned int frame_nr)"""
    c_socket_set_ringopt.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint, ctypes.c_uint]
    c_socket_set_ringopt.restype = ctypes.c_int

    c_socket_map_ring = LIBMNL.mnl_socket_map_ring
    c_socket_map_ring.__doc__ = """\
extern int mnl_socket_map_ring(struct mnl_socket *nl, int flags)"""
    c_socket_map_ring.argtypes = [ctypes.c_void_p, ctypes.c_int]
    c_socket_map_ring.restype = ctypes.c_int

    c_socket_unmap_ring = LIBMNL.mnl_socket_unmap_ring
    c_socket_unmap_ring.__doc__ = """\
extern int mnl_socket_unmap_ring(struct mnl_socket *nl)"""
    c_socket_unmap_ring.argtypes = [ctypes.c_void_p]
    c_socket_unmap_ring.restype = ctypes.c_int

    c_socket_get_ring = LIBMNL.mnl_socket_get_ring
    c_socket_get_ring.__doc__ = """\
struct mnl_ring *mnl_socket_get_ring(const struct mnl_socket *nl, enum mnl_ring_type type)"""
    c_socket_get_ring.argtypes = [ctypes.c_void_p, ctypes.c_int]
    c_socket_get_ring.restype = ctypes.c_void_p

    c_ring_advance = LIBMNL.mnl_ring_advance
    c_ring_advance.__doc__ = """\
void mnl_ring_advance(struct mnl_ring *ring)"""
    c_ring_advance.argtypes = [ctypes.c_void_p]
    c_ring_advance.restype = None

    c_ring_current_frame = LIBMNL.mnl_ring_current_frame
    c_ring_current_frame.__doc__ = """\
struct nl_mmap_hdr *mnl_ring_current_frame(const struct mnl_ring *ring)"""
    c_ring_current_frame.argtypes = [ctypes.c_void_p]
    c_ring_current_frame.restype = ctypes.POINTER(netlink.NlMmapHdr)
except AttributeError:
    HAS_MNL_RING = False
else:
    HAS_MNL_RING = True

c_socket_close = LIBMNL.mnl_socket_close
c_socket_close.__doc__ = """\
int mnl_socket_close(struct mnl_socket *nl)"""
c_socket_close.argtypes = [ctypes.c_void_p]

c_socket_get_fd = LIBMNL.mnl_socket_get_fd
c_socket_get_fd.__doc__ = """\
int mnl_socket_get_fd(const struct mnl_socket *nl)"""
c_socket_get_fd.argtypes = [ctypes.c_void_p]
c_socket_get_fd.restype = ctypes.c_int

c_socket_get_portid = LIBMNL.mnl_socket_get_portid
c_socket_get_portid.__doc__ = """\
unsigned int mnl_socket_get_portid(const struct mnl_socket *nl)"""
c_socket_get_portid.argtypes = [ctypes.c_void_p]
c_socket_get_portid.restype = ctypes.c_uint

c_socket_sendto = LIBMNL.mnl_socket_sendto
c_socket_sendto.__doc__ = """\
ssize_t mnl_socket_sendto(const struct mnl_socket *nl, const void *req, size_t siz)"""
c_socket_sendto.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
c_socket_sendto.restype = c_ssize_t

c_socket_recvfrom = LIBMNL.mnl_socket_recvfrom
c_socket_recvfrom.__doc__ = """\
ssize_t mnl_socket_recvfrom(const struct mnl_socket *nl, void *buf, size_t siz)"""
c_socket_recvfrom.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
c_socket_recvfrom.restype = c_ssize_t

c_socket_setsockopt = LIBMNL.mnl_socket_setsockopt
c_socket_setsockopt.__doc__ = """\
int mnl_socket_setsockopt(const struct mnl_socket *nl, int type, void *buf, socklen_t len)"""
c_socket_setsockopt.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, c_socklen_t]
c_socket_setsockopt.restype = ctypes.c_int

c_socket_getsockopt = LIBMNL.mnl_socket_getsockopt
c_socket_getsockopt.__doc__ = """\
int mnl_socket_getsockopt(const struct mnl_socket *nl, int type, void *buf, socklen_t *len)"""
c_socket_getsockopt.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
c_socket_getsockopt.restype = ctypes.c_int


###
## Netlink message API
###
c_nlmsg_size = LIBMNL.mnl_nlmsg_size
c_nlmsg_size.__doc__ = """\
size_t mnl_nlmsg_size(size_t len)"""
c_nlmsg_size.argtypes = [ctypes.c_size_t]
c_nlmsg_size.restype = ctypes.c_size_t

c_nlmsg_get_payload_len = LIBMNL.mnl_nlmsg_get_payload_len
c_nlmsg_get_payload_len.__doc__ = """\
size_t mnl_nlmsg_get_payload_len(const struct nlmsghdr *nlh)"""
c_nlmsg_get_payload_len.argtypes = [ctypes.POINTER(netlink.Nlmsghdr)]
c_nlmsg_get_payload_len.restype = ctypes.c_size_t

## Netlink message header builder
c_nlmsg_put_header = LIBMNL.mnl_nlmsg_put_header
c_nlmsg_put_header.__doc__ = """\
struct nlmsghdr *mnl_nlmsg_put_header(void *buf)"""
c_nlmsg_put_header.argtypes = [ctypes.c_void_p]
c_nlmsg_put_header.restype = ctypes.POINTER(netlink.Nlmsghdr)

c_nlmsg_put_extra_header = LIBMNL.mnl_nlmsg_put_extra_header
c_nlmsg_put_extra_header.__doc__ = """\
void *mnl_nlmsg_put_extra_header(struct nlmsghdr *nlh, size_t size)"""
c_nlmsg_put_extra_header.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_size_t]
c_nlmsg_put_extra_header.restype = ctypes.c_void_p

## Netlink message iterators
c_nlmsg_ok = LIBMNL.mnl_nlmsg_ok
c_nlmsg_ok.__doc__ = """\
bool mnl_nlmsg_ok(const struct nlmsghdr *nlh, int len)"""
c_nlmsg_ok.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_int]
c_nlmsg_ok.restype = ctypes.c_bool

c_nlmsg_next = LIBMNL.mnl_nlmsg_next
c_nlmsg_next.__doc__ = """\
struct nlmsghdr *mnl_nlmsg_next(const struct nlmsghdr *nlh, int *len)"""
c_nlmsg_next.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_void_p]
c_nlmsg_next.restype = ctypes.POINTER(netlink.Nlmsghdr)

## Netlink sequence tracking
c_nlmsg_seq_ok = LIBMNL.mnl_nlmsg_seq_ok
c_nlmsg_seq_ok.__doc__ = """\
mnl_nlmsg_seq_ok(const struct nlmsghdr *nlh, unsigned int seq)"""
c_nlmsg_seq_ok.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint]
c_nlmsg_seq_ok.restype = ctypes.c_bool

## Netlink portID checking
c_nlmsg_portid_ok = LIBMNL.mnl_nlmsg_portid_ok
c_nlmsg_portid_ok.__doc__ = """\
bool mnl_nlmsg_portid_ok(const struct nlmsghdr *nlh, unsigned int portid)"""
c_nlmsg_portid_ok.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint]
c_nlmsg_portid_ok.restype = ctypes.c_bool

## Netlink message getters
c_nlmsg_get_payload = LIBMNL.mnl_nlmsg_get_payload
c_nlmsg_get_payload.__doc__ = """\
void *mnl_nlmsg_get_payload(const struct nlmsghdr *nlh)"""
c_nlmsg_get_payload.argtypes = [ctypes.POINTER(netlink.Nlmsghdr)]
c_nlmsg_get_payload.restype = ctypes.c_void_p

c_nlmsg_get_payload_offset = LIBMNL.mnl_nlmsg_get_payload_offset
c_nlmsg_get_payload_offset.__doc__ = """\
void *mnl_nlmsg_get_payload(const struct nlmsghdr *nlh)"""
c_nlmsg_get_payload_offset.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_size_t]
c_nlmsg_get_payload_offset.restype = ctypes.c_void_p

c_nlmsg_get_payload_tail = LIBMNL.mnl_nlmsg_get_payload_tail
c_nlmsg_get_payload_tail.__doc__ = """\
extern void *mnl_nlmsg_get_payload_tail(const struct nlmsghdr *nlh)"""
c_nlmsg_get_payload_tail.argtypes = [ctypes.POINTER(netlink.Nlmsghdr)]
c_nlmsg_get_payload_tail.restype = ctypes.c_void_p

## Netlink message printer
c_fdopen = ctypes.CDLL("libc.so.6").fdopen
c_fdopen.argtypes = [ctypes.c_int, ctypes.c_char_p]
c_fdopen.restype = ctypes.c_void_p
c_nlmsg_fprintf = LIBMNL.mnl_nlmsg_fprintf
c_nlmsg_fprintf.__doc__ = """\
void mnl_nlmsg_fprintf(FILE *fd, const void *data, size_t datalen, size_t extra_header_size)"""
c_nlmsg_fprintf.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_size_t]

## Message batch helpers
c_nlmsg_batch_start = LIBMNL.mnl_nlmsg_batch_start
c_nlmsg_batch_start.__doc__ = """\
struct mnl_nlmsg_batch *mnl_nlmsg_batch_start(void *buf, size_t bufsiz)"""
c_nlmsg_batch_start.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
c_nlmsg_batch_start.restype = ctypes.c_void_p

c_nlmsg_batch_next = LIBMNL.mnl_nlmsg_batch_next
c_nlmsg_batch_next.__doc__ = """\
bool mnl_nlmsg_batch_next(struct mnl_nlmsg_batch *b)"""
c_nlmsg_batch_next.argtypes = [ctypes.c_void_p]
c_nlmsg_batch_next.restype = ctypes.c_bool

c_nlmsg_batch_stop = LIBMNL.mnl_nlmsg_batch_stop
c_nlmsg_batch_stop.__doc__ = """\
void mnl_nlmsg_batch_stop(struct mnl_nlmsg_batch *b)"""
c_nlmsg_batch_stop.argtypes = [ctypes.c_void_p]

c_nlmsg_batch_size = LIBMNL.mnl_nlmsg_batch_size
c_nlmsg_batch_size.__doc__ = """\
size_t mnl_nlmsg_batch_size(struct mnl_nlmsg_batch *b)"""
c_nlmsg_batch_size.argtypes = [ctypes.c_void_p]
c_nlmsg_batch_size.restype = ctypes.c_size_t

c_nlmsg_batch_reset = LIBMNL.mnl_nlmsg_batch_reset
c_nlmsg_batch_reset.__doc__ = """\
void mnl_nlmsg_batch_reset(struct mnl_nlmsg_batch *b)"""
c_nlmsg_batch_reset.argtypes = [ctypes.c_void_p]

c_nlmsg_batch_head = LIBMNL.mnl_nlmsg_batch_head
c_nlmsg_batch_head.__doc__ = """\
void *mnl_nlmsg_batch_head(struct mnl_nlmsg_batch *b)"""
c_nlmsg_batch_head.argtypes = [ctypes.c_void_p]
c_nlmsg_batch_head.restype = ctypes.c_void_p

c_nlmsg_batch_current = LIBMNL.mnl_nlmsg_batch_current
c_nlmsg_batch_current.__doc__ = """\
void *mnl_nlmsg_batch_current(struct mnl_nlmsg_batch *b)"""
c_nlmsg_batch_current.argtypes = [ctypes.c_void_p]
c_nlmsg_batch_current.restype = ctypes.c_void_p

c_nlmsg_batch_is_empty = LIBMNL.mnl_nlmsg_batch_is_empty
c_nlmsg_batch_is_empty.__doc__ = """\
bool mnl_nlmsg_batch_is_empty(struct mnl_nlmsg_batch *b)"""
c_nlmsg_batch_is_empty.argtypes = [ctypes.c_void_p]
c_nlmsg_batch_is_empty.restype = ctypes.c_bool

if HAS_MNL_RING:
    c_nlmsg_batch_reset_buffer = LIBMNL.mnl_nlmsg_batch_reset_buffer
    c_nlmsg_batch_reset_buffer.__doc__ = """\
void mnl_nlmsg_batch_reset_buffer(struct mnl_nlmsg_batch *b, void *buf, size_t limit)"""
    c_nlmsg_batch_reset_buffer.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]


###
##  Netlink attributes API
###
## TLV attribute getters
c_attr_get_type = LIBMNL.mnl_attr_get_type
c_attr_get_type.__doc__ = """\
uint16_t mnl_attr_get_type(const struct nlattr *attr)"""
c_attr_get_type.argtypes = [ctypes.POINTER(netlink.Nlattr)]
c_attr_get_type.restype = ctypes.c_uint16

c_attr_get_len = LIBMNL.mnl_attr_get_len
c_attr_get_len.__doc__ = """\
uint16_t mnl_attr_get_len(const struct nlattr *attr)"""
c_attr_get_len.argtypes = [ctypes.POINTER(netlink.Nlattr)]
c_attr_get_len.restype = ctypes.c_uint16

c_attr_get_payload_len = LIBMNL.mnl_attr_get_payload_len
c_attr_get_payload_len.__doc__ = """\
uint16_t mnl_attr_get_payload_len(const struct nlattr *attr)"""
c_attr_get_payload_len.argtypes = [ctypes.POINTER(netlink.Nlattr)]
c_attr_get_payload_len.restype = ctypes.c_uint16

c_attr_get_payload = LIBMNL.mnl_attr_get_payload
c_attr_get_payload.__doc__ = """\
void *mnl_attr_get_payload(const struct nlattr *attr)"""
c_attr_get_payload.argtypes = [ctypes.POINTER(netlink.Nlattr)]
c_attr_get_payload.restype = ctypes.c_void_p

c_attr_get_u8 = LIBMNL.mnl_attr_get_u8
c_attr_get_u8.__doc__ = """\
uint8_t mnl_attr_get_u8(const struct nlattr *attr)"""
c_attr_get_u8.argtypes = [ctypes.POINTER(netlink.Nlattr)]
c_attr_get_u8.restype = ctypes.c_uint8

c_attr_get_u16 = LIBMNL.mnl_attr_get_u16
c_attr_get_u16.__doc__ = """\
uint16_t mnl_attr_get_u16(const struct nlattr *attr)"""
c_attr_get_u16.argtypes = [ctypes.POINTER(netlink.Nlattr)]
c_attr_get_u16.restype = ctypes.c_uint16

c_attr_get_u32 = LIBMNL.mnl_attr_get_u32
c_attr_get_u32.__doc__ = """\
uint32_t mnl_attr_get_u32(const struct nlattr *attr)"""
c_attr_get_u32.argtypes = [ctypes.POINTER(netlink.Nlattr)]
c_attr_get_u32.restype = ctypes.c_uint32

c_attr_get_u64 = LIBMNL.mnl_attr_get_u64
c_attr_get_u64.__doc__ = """\
uint64_t mnl_attr_get_u64(const struct nlattr *attr)"""
c_attr_get_u64.argtypes = [ctypes.POINTER(netlink.Nlattr)]
c_attr_get_u64.restype = ctypes.c_uint64

c_attr_get_str = LIBMNL.mnl_attr_get_str
c_attr_get_str.__doc__ = """\
const char *mnl_attr_get_str(const struct nlattr *attr)"""
c_attr_get_str.argtypes = [ctypes.POINTER(netlink.Nlattr)]
c_attr_get_str.restype = ctypes.c_char_p

## TLV attribute putters
c_attr_put = LIBMNL.mnl_attr_put
c_attr_put.__doc__ = """\
void mnl_attr_put(struct nlmsghdr *nlh, uint16_t type, size_t len, const void *data)"""
c_attr_put.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint16, ctypes.c_size_t, ctypes.c_void_p]

c_attr_put_u8 = LIBMNL.mnl_attr_put_u8
c_attr_put_u8.__doc__ = """\
void mnl_attr_put_u8(struct nlmsghdr *nlh, uint16_t type, uint8_t data)"""
c_attr_put_u8.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint16, ctypes.c_uint8]

c_attr_put_u16 = LIBMNL.mnl_attr_put_u16
c_attr_put_u16.__doc__ = """\
void mnl_attr_put_u16(struct nlmsghdr *nlh, uint16_t type, uint16_t data)"""
c_attr_put_u16.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint16, ctypes.c_uint16]

c_attr_put_u32 = LIBMNL.mnl_attr_put_u32
c_attr_put_u32.__doc__ = """\
mnl_attr_put_u32(struct nlmsghdr *nlh, uint16_t type, uint32_t data)"""
c_attr_put_u32.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint16, ctypes.c_uint32]

c_attr_put_u64 = LIBMNL.mnl_attr_put_u64
c_attr_put_u64.__doc__ = """\
mnl_attr_put_u64(struct nlmsghdr *nlh, uint16_t type, uint64_t data)"""
c_attr_put_u64.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint16, ctypes.c_uint64]

c_attr_put_str = LIBMNL.mnl_attr_put_str
c_attr_put_str.__doc__ = """\
void mnl_attr_put_str(struct nlmsghdr *nlh, uint16_t type, const char *data)"""
c_attr_put_str.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint16, ctypes.c_char_p]

c_attr_put_strz = LIBMNL.mnl_attr_put_strz
c_attr_put_strz.__doc__ = """\
void mnl_attr_put_strz(struct nlmsghdr *nlh, uint16_t type, const char *data)"""
c_attr_put_strz.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint16, ctypes.c_char_p]

## TLV attribute putters with buffer boundary checkings
c_attr_put_check = LIBMNL.mnl_attr_put_check
c_attr_put_check.__doc__ = """\
bool mnl_attr_put_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, size_t len, const void *data)"""
c_attr_put_check.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_size_t, ctypes.c_uint16, ctypes.c_size_t, ctypes.c_void_p]
c_attr_put_check.restype = ctypes.c_bool

c_attr_put_u8_check = LIBMNL.mnl_attr_put_u8_check
c_attr_put_u8_check.__doc__ = """\
bool mnl_attr_put_u8_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, uint8_t data)"""
c_attr_put_u8_check.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_size_t, ctypes.c_uint16, ctypes.c_uint8]
c_attr_put_u8_check.restype = ctypes.c_bool

c_attr_put_u16_check = LIBMNL.mnl_attr_put_u16_check
c_attr_put_u16_check.__doc__ = """\
bool mnl_attr_put_u16_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, uint16_t data)"""
c_attr_put_u16_check.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_size_t, ctypes.c_uint16, ctypes.c_uint16]
c_attr_put_u16_check.restype = ctypes.c_bool

c_attr_put_u32_check = LIBMNL.mnl_attr_put_u32_check
c_attr_put_u32_check.__doc__ = """\
bool mnl_attr_put_u32_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, uint32_t data)"""
c_attr_put_u32_check.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_size_t, ctypes.c_uint16, ctypes.c_uint32]
c_attr_put_u32_check.restype = ctypes.c_bool

c_attr_put_u64_check = LIBMNL.mnl_attr_put_u64_check
c_attr_put_u64_check.__doc__ = """\
bool mnl_attr_put_u64_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, uint64_t data)"""
c_attr_put_u64_check.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_size_t, ctypes.c_uint16, ctypes.c_uint64]
c_attr_put_u64_check.restype = ctypes.c_bool

c_attr_put_str_check = LIBMNL.mnl_attr_put_str_check
c_attr_put_str_check.__doc__ = """\
mnl_attr_put_str_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, const char *data)"""
c_attr_put_str_check.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_size_t, ctypes.c_uint16, ctypes.c_char_p]
c_attr_put_str_check.restype = ctypes.c_bool

c_attr_put_strz_check = LIBMNL.mnl_attr_put_strz_check
c_attr_put_strz_check.__doc__ = """\
bool mnl_attr_put_strz_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type, const char *data)"""
c_attr_put_strz_check.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_size_t, ctypes.c_uint16, ctypes.c_char_p]
c_attr_put_strz_check.restype = ctypes.c_bool


## TLV attribute nesting
c_attr_nest_start = LIBMNL.mnl_attr_nest_start
c_attr_nest_start.__doc__ = """\
struct nlattr *mnl_attr_nest_start(struct nlmsghdr *nlh, uint16_t type)"""
c_attr_nest_start.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint16]
c_attr_nest_start.restype = ctypes.POINTER(netlink.Nlattr)

c_attr_nest_start_check = LIBMNL.mnl_attr_nest_start_check
c_attr_nest_start_check.__doc__ = """\
struct nlattr *mnl_attr_nest_start_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type)"""
c_attr_nest_start_check.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_size_t, ctypes.c_uint16]
c_attr_nest_start_check.restype = ctypes.c_void_p

c_attr_nest_end = LIBMNL.mnl_attr_nest_end
c_attr_nest_end.__doc__ = """\
void mnl_attr_nest_end(struct nlmsghdr *nlh, struct nlattr *start)"""
c_attr_nest_end.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.POINTER(netlink.Nlattr)]

c_attr_nest_cancel = LIBMNL.mnl_attr_nest_cancel
c_attr_nest_cancel.__doc__ = """\
void mnl_attr_nest_cancel(struct nlmsghdr *nlh, struct nlattr *start)"""
c_attr_nest_cancel.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.POINTER(netlink.Nlattr)]

# TLV validation
c_attr_type_valid = LIBMNL.mnl_attr_type_valid
c_attr_type_valid.__doc__ = """\
int mnl_attr_type_valid(const struct nlattr *attr, uint16_t maxtype)"""
c_attr_type_valid.argtypes = [ctypes.POINTER(netlink.Nlattr), ctypes.c_uint16]
c_attr_type_valid.restypes = ctypes.c_int

c_attr_validate = LIBMNL.mnl_attr_validate
c_attr_validate.__doc__ = """\
int mnl_attr_validate(const struct nlattr *attr, enum mnl_attr_data_type type)"""
c_attr_validate.argtypes = [ctypes.POINTER(netlink.Nlattr), ctypes.c_int]
c_attr_validate.restype = ctypes.c_int

c_attr_validate2 = LIBMNL.mnl_attr_validate2
c_attr_validate2.__doc__ = """\
int mnl_attr_validate2(const struct nlattr *attr, enum mnl_attr_data_type type, size_t len)"""
c_attr_validate2.argtypes = [ctypes.POINTER(netlink.Nlattr), ctypes.c_int, ctypes.c_size_t]
c_attr_validate2.restype = ctypes.c_int

## TLV iterators
c_attr_ok = LIBMNL.mnl_attr_ok
c_attr_ok.__doc__ = """\
bool mnl_attr_ok(const struct nlattr *attr, int len)"""
c_attr_ok.argtypes = [ctypes.POINTER(netlink.Nlattr), ctypes.c_int]
c_attr_ok.restype = ctypes.c_bool

c_attr_next = LIBMNL.mnl_attr_next
c_attr_next.__doc__ = """\
struct nlattr *mnl_attr_next(const struct nlattr *attr)"""
c_attr_next.argtypes = [ctypes.POINTER(netlink.Nlattr)]
c_attr_next.restype = ctypes.POINTER(netlink.Nlattr)


## TLV callback-based attribute parsers
MNL_ATTR_CB_T = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(netlink.Nlattr), ctypes.py_object, use_errno=True)
MNL_ATTR_CB_T.__doc__ = """\
typedef int (*mnl_attr_cb_t)(const struct nlattr *attr, void *data)"""

c_attr_parse = LIBMNL.mnl_attr_parse
c_attr_parse.__doc__ = """\
int mnl_attr_parse(const struct nlmsghdr *nlh, unsigned int offset, mnl_attr_cb_t cb, void *data)"""
c_attr_parse.argtypes = [ctypes.POINTER(netlink.Nlmsghdr), ctypes.c_uint, MNL_ATTR_CB_T, ctypes.py_object]
c_attr_parse.restype = ctypes.c_int

c_attr_parse_nested = LIBMNL.mnl_attr_parse_nested
c_attr_parse_nested.__doc__ = """\
int mnl_attr_parse_nested(const struct nlattr *attr, mnl_attr_cb_t cb, void *data)"""
c_attr_parse_nested.argtypes = [ctypes.POINTER(netlink.Nlattr), MNL_ATTR_CB_T, ctypes.py_object]
c_attr_parse_nested.restype = ctypes.c_int

c_attr_parse_payload = LIBMNL.mnl_attr_parse_payload
c_attr_parse_payload.__doc__ = """\
int mnl_attr_parse_payload(const void *payload, size_t payload_len, mnl_attr_cb_t cb, void *data)"""
c_attr_parse_payload.argtypes = [ctypes.c_void_p, ctypes.c_size_t, MNL_ATTR_CB_T, ctypes.py_object]
c_attr_parse_payload.restype = ctypes.c_int


##
# callback API
##
MNL_CB_T = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.POINTER(netlink.Nlmsghdr), ctypes.py_object, use_errno=True)
MNL_CB_T.__doc__ = """\
typedef int (*mnl_cb_t)(const struct nlmsghdr *nlh, void *data)"""

c_cb_run = LIBMNL.mnl_cb_run
c_cb_run.__doc__ = """\
int mnl_cb_run(const void *buf, size_t numbytes, unsigned int seq,
               unsigned int portid, mnl_cb_t cb_data, void *data)"""
c_cb_run.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint, ctypes.c_uint, MNL_CB_T, ctypes.py_object]
c_cb_run.restype = ctypes.c_int

c_cb_run2 = LIBMNL.mnl_cb_run2
c_cb_run2.__doc__ = """\
int mnl_cb_run2(const void *buf, size_t numbytes, unsigned int seq,
                unsigned int portid, mnl_cb_t cb_data, void *data,
                mnl_cb_t *cb_ctl_array, unsigned int cb_ctl_array_len)"""
c_cb_run2.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint, ctypes.c_uint, MNL_CB_T, ctypes.py_object, ctypes.POINTER(MNL_CB_T), ctypes.c_uint]
c_cb_run2.restype = ctypes.c_int


def os_error():
    """create OSError from C errno. And clear C errno"""
    en = ctypes.get_errno()
    ctypes.set_errno(0)
    if en == 0:
        return OSError(en, "(no errno found)")
    else:
        return OSError(en, errno.errorcode[en])
