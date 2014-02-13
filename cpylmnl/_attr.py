# -*- coding: utf-8 -*-

from __future__ import absolute_import, print_function

import sys, os, errno, ctypes

from .linux import netlinkh as netlink

from . import _cproto
from . import _libmnlh

"""
libmnl (http://www.netfilter.org/projects/libmnl/) attr.c
    implementation by python ctypes
"""

# uint16_t mnl_attr_get_type(const struct nlattr *attr)
attr_get_type		= _cproto.c_attr_get_type

# uint16_t mnl_attr_get_len(const struct nlattr *attr)
attr_get_len		= _cproto.c_attr_get_len

# uint16_t mnl_attr_get_payload_len(const struct nlattr *attr)
attr_get_payload_len	= _cproto.c_attr_get_payload_len

# void *mnl_attr_get_payload(const struct nlattr *attr)
attr_get_payload	= _cproto.c_attr_get_payload
def attr_get_payload_v(attr):
    return ctypes.cast(_cproto.c_attr_get_payload(attr),
                ctypes.POINTER(ctypes.c_ubyte * (attr.len - _libmnlh.MNL_ATTR_HDRLEN))).contents
def attr_get_payload_as(attr, cls):
    return ctypes.cast(_cproto.c_attr_get_payload(attr), ctypes.POINTER(cls)).contents

# bool mnl_attr_ok(const struct nlattr *attr, int len)
attr_ok			= _cproto.c_attr_ok

# struct nlattr *mnl_attr_next(const struct nlattr *attr)
def attr_next(attr):
    return _cproto.c_attr_next(attr).contents

# int mnl_attr_type_valid(const struct nlattr *attr, uint16_t max)
def attr_type_valid(attr, maxtype):
    ret = _cproto.c_attr_type_valid(attr, maxtype)
    if ret < 0: raise _cproto.os_error()

# int mnl_attr_validate(const struct nlattr *attr, enum mnl_attr_data_type type)
def attr_validate(attr, data_type):
    ret = _cproto.c_attr_validate(attr, data_type)
    if ret < 0: raise _cproto.os_error()

# int
# mnl_attr_validate2(const struct nlattr *attr, enum mnl_attr_data_type type,
#                    size_t exp_len)
def attr_validate2(attr, data_type, exp_len):
    ret = _cproto.c_attr_validate2(attr, data_type, exp_len)
    if ret < 0: raise _cproto.os_error()

# int
# mnl_attr_parse(const struct nlmsghdr *nlh, unsigned int offset,
#                mnl_attr_cb_t cb, void *data)
def attr_parse(nlh, offset, cb, data):
    ret = _cproto.c_attr_parse(nlh, offset, cb, data)
    if ret < 0: raise _cproto.os_error()
    return ret

# int
# mnl_attr_parse_nested(const struct nlattr *nested,
#                       mnl_attr_cb_t cb, void *data)
def attr_parse_nested(attr, cb, data):
    ret = _cproto.c_attr_parse_nested(attr, cb, data)
    if ret < 0: raise _cproto.os_error()
    return ret

# int mnl_attr_parse_payload(const void *payload, size_t payload_len,
# 	                     mnl_attr_cb_t cb, void *data)
def attr_parse_payload(payload, cb, data):
    """parse attributes in payload of Netlink message

    This function takes a pointer to the area that contains the attributes,
    commonly known as the payload of the Netlink message. Thus, you have to
    pass a buffer to the Netlink message payload, instead of the entire
    message.

    This function allows you to iterate over the sequence of attributes that are
    located at some payload offset. You can then put the attributes in one array
    as usual, or you can use any other data structure (such as lists or trees).

    This function propagates the return value of the callback, which can be
    MNL_CB_OK or MNL_CB_STOP, raises OSError in case of MNL_CB_ERROR.

    @type payload: buffer
    @param payload: payload of the Netlink message
    @type cb: mnl_attr_cb_t or attribute_cb decorator can be used
    @param cb: callback function that is called for each attribute
    @type data: any
    @param data: python object that is passed to the callback function

    @rtype: number
    @return MNL_CB_ERROR, MNL_CB_OK or MNL_CB_STOP
    """
    b = (ctypes.c_ubyte * len(payload)).from_buffer(payload)
    ret = _cproto.c_attr_parse_payload(b, len(payload), cb, data)
    if ret < 0: raise _cproto.os_error()
    return ret

# uint8_t mnl_attr_get_u8(const struct nlattr *attr)
attr_get_u8		= _cproto.c_attr_get_u8

# uint16_t mnl_attr_get_u16(const struct nlattr *attr)
attr_get_u16		= _cproto.c_attr_get_u16

# uint32_t mnl_attr_get_u32(const struct nlattr *attr)
attr_get_u32		= _cproto.c_attr_get_u32

# uint64_t mnl_attr_get_u64(const struct nlattr *attr)
attr_get_u64		= _cproto.c_attr_get_u64

# const char *mnl_attr_get_str(const struct nlattr *attr)
attr_get_str		= _cproto.c_attr_get_str

# void
# mnl_attr_put(struct nlmsghdr *nlh, uint16_t type, size_t len, const void *data)
def attr_put(nlh, attr_type, data):
    try:
        size = ctypes.sizeof(data)
    except TypeError:
        raise OSError(errno.EINVAL, "data must be ctypes type")
    _cproto.c_attr_put(nlh, attr_type, size, ctypes.byref(data))

# void mnl_attr_put_u8(struct nlmsghdr *nlh, uint16_t type, uint8_t data)
attr_put_u8		= _cproto.c_attr_put_u8

# void mnl_attr_put_u16(struct nlmsghdr *nlh, uint16_t type, uint16_t data)
attr_put_u16		= _cproto.c_attr_put_u16

# void mnl_attr_put_u32(struct nlmsghdr *nlh, uint16_t type, uint32_t data)
attr_put_u32		= _cproto.c_attr_put_u32

# void mnl_attr_put_u64(struct nlmsghdr *nlh, uint16_t type, uint64_t data)
attr_put_u64		= _cproto.c_attr_put_u64

# void mnl_attr_put_str(struct nlmsghdr *nlh, uint16_t type, const char *data)
attr_put_str		= _cproto.c_attr_put_str

# void mnl_attr_put_strz(struct nlmsghdr *nlh, uint16_t type, const char *data)
attr_put_strz		= _cproto.c_attr_put_strz

# struct nlattr *mnl_attr_nest_start(struct nlmsghdr *nlh, uint16_t type)
def attr_nest_start(nlh, attr_type):
    return _cproto.c_attr_nest_start(nlh, attr_type).contents

# bool mnl_attr_put_check(struct nlmsghdr *nlh, size_t buflen,
#                         uint16_t type, size_t len, const void *data)
def attr_put_check(nlh, buflen, attr_type, data):
    try:
        size = ctypes.sizeof(data)
    except TypeError:
        raise OSError(errno.EINVAL, "data must be ctypes type")
    return _cproto.c_attr_put_check(nlh, buflen, attr_type, size, data)

# bool
# mnl_attr_put_u8_check(struct nlmsghdr *nlh, size_t buflen,
#                       uint16_t type, uint8_t data)
attr_put_u8_check	= _cproto.c_attr_put_u8_check

# bool
# mnl_attr_put_u16_check(struct nlmsghdr *nlh, size_t buflen,
#                        uint16_t type, uint16_t data)
attr_put_u16_check	= _cproto.c_attr_put_u16_check

# bool
# mnl_attr_put_u32_check(struct nlmsghdr *nlh, size_t buflen,
#                        uint16_t type, uint32_t data)
attr_put_u32_check	= _cproto.c_attr_put_u32_check

# bool
# mnl_attr_put_u64_check(struct nlmsghdr *nlh, size_t buflen,
#                        uint16_t type, uint64_t data)
attr_put_u64_check	= _cproto.c_attr_put_u64_check

# bool
# mnl_attr_put_str_check(struct nlmsghdr *nlh, size_t buflen,
#                        uint16_t type, const char *data)
attr_put_str_check	= _cproto.c_attr_put_str_check

# bool
# mnl_attr_put_strz_check(struct nlmsghdr *nlh, size_t buflen,
#                         uint16_t type, const char *data)
attr_put_strz_check	= _cproto.c_attr_put_strz_check

# struct nlattr *
# mnl_attr_nest_start_check(struct nlmsghdr *nlh, size_t buflen, uint16_t type)
def attr_nest_start_check(nlh, buflen, attr_type):
    ret = _cproto.c_attr_nest_start_check(nlh, buflen, attr_type)
    if ret is None: return None
    return ctypes.cast(ret, ctypes.POINTER(netlink.Nlattr)).contents

# void
# mnl_attr_nest_end(struct nlmsghdr *nlh, struct nlattr *start)
attr_nest_end		= _cproto.c_attr_nest_end

# void
# mnl_attr_nest_cancel(struct nlmsghdr *nlh, struct nlattr *start)
attr_nest_cancel	= _cproto.c_attr_nest_cancel
