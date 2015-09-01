# -*- coding: utf-8 -*-
"""Python wrapper of libmnl using ctypes

---- Citing the original libmnl

libmnl is a minimalistic user-space library oriented to Netlink developers.
There are a lot of common tasks in parsing, validating, constructing of
both the Netlink header and TLVs that are repetitive and easy to get wrong.
This library aims to provide simple helpers that allows you to avoid
re-inventing the wheel in common Netlink tasks.

    "Simplify, simplify" -- Henry David Thoureau. Walden (1854)

The acronym libmnl stands for LIBrary Minimalistic NetLink.

libmnl homepage is:
     http://www.netfilter.org/projects/libmnl/

* Main Features
  - Small: the shared library requires around 30KB for an x86-based computer.
  - Simple: this library avoids complex abstractions that tend to hide Netlink
    details. It avoids elaborated object-oriented infrastructure and complex
    callback-based workflow.
  - Easy to use: the library simplifies the work for Netlink-wise developers.
    It provides functions to make socket handling, message building,
    validating, parsing and sequence tracking, easier.
  - Easy to re-use: you can use this library to build your own abstraction
    layer upon this library, if you want to provide another library that
    hides Netlink details to your users.
  - Decoupling: the interdependency of the main bricks that compose this
    library is reduced, i.e. the library provides many helpers, but the
    programmer is not forced to use them.

* Licensing terms
  This library is released under the LGPLv2.1 or any later (at your option).

* Dependencies
  You have to install the Linux kernel headers that you want to use to develop
  your application. Moreover, this library requires that you have some basics
  on Netlink.

* Git Tree
  The current development version of libmnl can be accessed at:
  http://git.netfilter.org/cgi-bin/gitweb.cgi?p=libmnl.git;a=summary

* Using libmnl
  You can access several example files under examples/ in the libmnl source
  code tree.
"""

from __future__ import absolute_import

import ctypes

from ._libmnlh import *
from . import _cproto
from . import _attr
from . import _nlmsg
from . import _callback
from . import _socket

from .linux import netlinkh as netlink


class Attr(netlink.Nlattr):
    """Netlink attribute helpers

    Netlink Type-Length-Value (TLV) attribute:

        |<-- 2 bytes -->|<-- 2 bytes -->|<-- variable -->|
        -------------------------------------------------
        |     length    |      type     |      value     |
        -------------------------------------------------
        |<--------- header ------------>|<-- payload --->|

    The payload of the Netlink message contains sequences of attributes that are
    expressed in TLV format.
    """

    def get_type(self):
        """get type of netlink attribute

        @rtype: number
        @return: the attribute type 
        """
        return _attr.attr_get_type(self)

    def get_len(self):
        """get length of netlink attribute

        @rtype: number
        @return: the attribute length that is the attribute header plus the
        attribute payload
        """
        return _attr.attr_get_len(self)

    def get_payload_len(self):
        """get the attribute payload-value length

        @rtype: number
        @return: the attribute payload-value length
        """
        return _attr.attr_get_payload_len(self)

    def get_payload(self):
        """get pointer to the attribute payload

        @rtype: ctypes.c_void_p
        @return: a pointer to the attribute payload
        """
        return _attr.attr_get_payload(self)

    def get_payload_v(self):
        """get buffer of the attribute payload

        This function wraps get_payload().

        @rtype: array of ctypes.c_ubyte
        @return : a buffer of the attribute payload
        """
        return _attr.attr_get_payload_v(self)

    def get_payload_as(self, c):
        """get the attribute payload as a specified instance

        This function wraps get_payload().
        Param c must be a ctypes data type.

        @type c: class
        @param c: class of return value

        @rtype: specified by param c
        @return: an instance of the attribute payload
        """
        return _attr.attr_get_payload_as(self, c)

    def ok(self, size):
        """check if there is room for an attribute in a buffer

        This function is used to check that a buffer, which is supposed to contain
        an attribute, has enough room for the attribute that it stores, i.e. this
        function can be used to verify that an attribute is neither malformed nor
        truncated.

        This function does not raise OSError in case of error since it is intended
        for iterations. Thus, it returns true on success and false on error.

        The size parameter may be negative in the case of malformed messages during
        attribute iteration, that is why we use a signed integer.

        @type size: number
        @param size: remaining bytes in a buffer that contains the attribute 
        @rtype: bool
        @return: true if ok
        """
        return _attr.attr_ok(self, size)

    def type_valid(self, maxtype):
        """check if the attribute type is valid

        This function allows to check if the attribute type is higher than the
        maximum supported type. If the attribute type is invalid, this function
        raises OSError.

        Strict attribute checking in user-space is not a good idea since you may
        run an old application with a newer kernel that supports new attributes.
        This leads to backward compatibility breakages in user-space. Better check
        if you support an attribute, if not, skip it.

        @type maxtype: number
        @param maxtype: maximum attribute type
        """
        _attr.attr_type_valid(self, maxtype)

    def validate(self, t):
        """validate netlink attribute (simplified version)

        The validation is based on the data type. Specifically, it checks that
        integers (u8, u16, u32 and u64) have enough room for them. This function
        raises OSError in case of error

        @type t: number
        @param t: data type (see MNL_TYPE_ constants)
        """
        _attr.attr_validate(self, t)

    def validate2(self, t, l):
        """validate netlink attribute (extended version)

        This function allows to perform a more accurate validation for attributes
        whose size is variable. If the size of the attribute is not what we expect,
        this functions raises OSError.

        @type t: number
        @param t: attribute type (see MNL_TYPE_ constants)
        @type l: number
        @param l: expected attribute data size
        """
        _attr.attr_validate2(self, t, l)

    def parse_nested(self, cb, d):
        """parse attributes inside a nest

        This function allows to iterate over the sequence of attributes that compose
        the Netlink message. You can then put the attribute in an array as it
        usually happens at this stage or you can use any other data structure (such
        as lists or trees).

        This function propagates the return value of the callback, which can be
        MNL_CB_OK or MNL_CB_STOP or raise OSError in case of MNL_CB_ERROR.

        @type cb: attr_cb (decorator)
        @param cb: callback function that is called for each attribute in the nest
        @type d: any
        @param d: data passed to the callback function
        """
        return _attr.attr_parse_nested(self, cb, d)

    def get_u8(self):
        """returns 8-bit unsigned integer attribute payload

        @rtype: number
        @return: the 8-bit value of the attribute payload
        """
        return _attr.attr_get_u8(self)

    def get_u16(self):
        """returns 16-bit unsigned integer attribute payload

        @rtype: number
        @return: the 16-bit value of the attribute payload
        """
        return _attr.attr_get_u16(self)

    def get_u32(self):
        """returns 32-bit unsigned integer attribute payload

        @rtype: number
        @return: the 32-bit value of the attribute payload
        """
        return _attr.attr_get_u32(self)

    def get_u64(self):
        """returns 64-bit unsigned integer attribute.

        @rtype: number
        @return: the 64-bit value of the attribute payload
        """
        return _attr.attr_get_u64(self)

    def get_str(self):
        """returns pointer to string attribute.

        @rtype: string
        @return: the payload of string attribute value
        """
        return _attr.attr_get_str(self)

    def next_attribute(self):
        """get the next attribute in the payload of a netlink message

        This function returns a next attribute after the one passed
        as parameter. You have to use mnl_attr_ok() to ensure that the next
        attribute is valid.

        @rtype: Attr
        @return: next attribute in the payload of a netlink message
        """
        return ctypes.cast(ctypes.addressof(_attr.attr_next(self)), ctypes.POINTER(self.__class__)).contents

    def nesteds(self):
        """mnl_attr_for_each_nested() macro in libmnl.h
        """
        a = self.get_payload_as(Attr)
        while a.ok(self.get_payload() + self.get_payload_len() - ctypes.addressof(a)):
            yield a
            a = a.next_attribute()


class Nlmsg(netlink.Nlmsghdr):
    """Netlink message helpers

    Netlink message:

	|<----------------- 4 bytes ------------------->|
	|<----- 2 bytes ------>|<------- 2 bytes ------>|
	|-----------------------------------------------|
	|      Message length (including header)        |
	|-----------------------------------------------|
	|     Message type     |     Message flags      |
	|-----------------------------------------------|
	|           Message sequence number             |
	|-----------------------------------------------|
	|                 Netlink PortID                |
	|-----------------------------------------------|
	|                                               |
	.                   Payload                     .
	|_______________________________________________|

    There is usually an extra header after the the Netlink header (at the
    beginning of the payload). This extra header is specific of the Netlink
    subsystem. After this extra header, it comes the sequence of attributes
    that are expressed in Type-Length-Value (TLV) format.
    """

    def parse(self, o, cb, d):
        """parse attributes

        This function allows to iterate over the sequence of attributes that compose
        the Netlink message. You can then put the attribute in an array as it
        usually happens at this stage or you can use any other data structure (such
        as lists or trees).

        This function propagates the return value of the callback, which can be
        MNL_CB_OK or MNL_CB_STOP or raise OSError in case of MNL_CB_ERROR.

        @type o: number
        @param o: offset to start parsing from (if payload is after any header)
        @type cb: attr_cb (decorator)
        @param cb: callback function that is called for each attribute
        @type d: any
        @param d: data that is passed to the callback function
        """
        return _attr.attr_parse(self, o, cb, d)

    def put(self, t, d):
        """add an attribute to netlink message

        This function updates the length field of the Netlink message (nlmsg_len)
        by adding the size (header + payload) of the new attribute.

        @type t: number
        @param t: netlink attribute type that you want to add 
        @type d: ctypes data type data
        @param d: the data that will be stored by the new attribute
        """
        _attr.attr_put(self, t, d)

    def put_u8(self, t, d):
        """add 8-bit unsigned integer attribute to netlink message

        This function updates the length field of the Netlink message (nlmsg_len)
        by adding the size (header + payload) of the new attribute.

        @type t: number
        @param t: netlink attribute type
        @type d: number
        @param d: 8-bit unsigned integer data that is stored by the new attribute
        """
        _attr.attr_put_u8(self, t, d)

    def put_u16(self, t, d):
        """add 16-bit unsigned integer attribute to netlink message

        This function updates the length field of the Netlink message (nlmsg_len)
        by adding the size (header + payload) of the new attribute.

        @type t: number
        @param t: netlink attribute type
        @type d: number
        @param d: 16-bit unsigned integer data that is stored by the new attribute
        """
        _attr.attr_put_u16(self, t, d)

    def put_u32(self, t, d):
        """add 32-bit unsigned integer attribute to netlink message

        This function updates the length field of the Netlink message (nlmsg_len)
        by adding the size (header + payload) of the new attribute.

        @type t: number
        @param t: netlink attribute type
        @type: d: number
        @param d: 32-bit unsigned integer data that is stored by the new attribute
        """
        _attr.attr_put_u32(self, t, d)

    def put_u64(self, t, d):
        """add 64-bit unsigned integer attribute to netlink message

        This function updates the length field of the Netlink message (nlmsg_len)
        by adding the size (header + payload) of the new attribute.

        @type t: number
        @param t: netlink attribute type
        @type d: number
        @param d: 64-bit unsigned integer data that is stored by the new attribute
        """
        _attr.attr_put_u64(self, t, d)

    def put_str(self, t, d):
        """add string attribute to netlink message

        This function updates the length field of the Netlink message (nlmsg_len)
        by adding the size (header + payload) of the new attribute.

        @type t: number
        @param t: netlink attribute type
        @type d: string
        @param d: string data that is stored by the new attribute
        """
        _attr.attr_put_str(self, t, d)

    def put_strz(self, t, d):
        """add string attribute to netlink message

        This function is similar to mnl_attr_put_str, but it includes the
        NUL/zero ('\\0') terminator at the end of the string.

        @type t: number
        @param t: netlink attribute type
        @type d: string
        @param d: string data that is stored by the new attribute
        """
        _attr.attr_put_strz(self, t, d)

    def nest_start(self, t):
        """start an attribute nest

        This function adds the attribute header that identifies the beginning of
        an attribute nest. This function always returns a valid Attr object
        beginning of the nest start.

        @type t: number
        @param t: netlink attribute type
        """
        return ctypes.cast(ctypes.addressof(_attr.attr_nest_start(self, t)), ctypes.POINTER(Attr)).contents

    def put_check(self, l, t, d):
        """add an attribute to netlink message

        This function first checks that the data can be added to the message
        (fits into the buffer) and then updates the length field of the Netlink
        message (nlmsg_len) by adding the size (header + payload) of the new
        attribute. The function returns true if the attribute could be added
        to the message, otherwise false is returned.

        @type l: number
        @param l: size of buffer which stores the message
        @type t: number
        @param t: netlink attribute type that you want to add
        @type d: ctypes data type data
        @param d: the data that will be stored by the new attribute

        @rtype: bool
        @return: if the attribute could be added to the message or not
        """
        return _attr.attr_put_check(self, l, t, d)

    def put_u8_check(self, l, t, d):
        """add 8-bit unsigned int attribute to netlink message

        This function first checks that the data can be added to the message
        (fits into the buffer) and then updates the length field of the Netlink
        message (nlmsg_len) by adding the size (header + payload) of the new
        attribute. The function returns true if the attribute could be added
        to the message, otherwise false is returned.

        @type l: number
        @param l: size of buffer which stores the message
        @type t: number
        @param t: netlink attribute type
        @type d: number
        @param d: 8-bit unsigned integer data that is stored by the new attribute

        @rtype: bool
        @return: if the attribute could be added to the message or not
        """
        return _attr.attr_put_u8_check(self, l, t, d)

    def put_u16_check(self, l, t, d):
        """add 16-bit unsigned int attribute to netlink message

        This function first checks that the data can be added to the message
        (fits into the buffer) and then updates the length field of the Netlink
        message (nlmsg_len) by adding the size (header + payload) of the new
        attribute. The function returns true if the attribute could be added
        to the message, otherwise false is returned.
        This function updates the length field of the Netlink message (nlmsg_len)
        by adding the size (header + payload) of the new attribute.

        @type l: number
        @param l: size of buffer which stores the message
        @type t: number
        @param t: netlink attribute type
        @param d: 16-bit unsigned integer data that is stored by the new attribute

        @rtype: bool
        @return: if the attribute could be added to the message or not
        """
        return _attr.attr_put_u16_check(self, l, t, d)

    def put_u32_check(self, l, t, d):
        """add 32-bit unsigned int attribute to netlink message

        This function first checks that the data can be added to the message
        (fits into the buffer) and then updates the length field of the Netlink
        message (nlmsg_len) by adding the size (header + payload) of the new
        attribute. The function returns true if the attribute could be added
        to the message, otherwise false is returned.
        This function updates the length field of the Netlink message (nlmsg_len)
        by adding the size (header + payload) of the new attribute.

        @type l: number
        @param l: size of buffer which stores the message
        @type t: number
        @param t: netlink attribute type
        @type d: number
        @param d: 32-bit unsigned integer data that is stored by the new attribute

        @rtype: bool
        @return: if the attribute could be added to the message or not
        """
        return _attr.attr_put_u32_check(self, l, t, d)

    def put_u64_check(self, l, t, d):
        """add 64-bit unsigned int attribute to netlink message

        This function first checks that the data can be added to the message
        (fits into the buffer) and then updates the length field of the Netlink
        message (nlmsg_len) by adding the size (header + payload) of the new
        attribute. The function returns true if the attribute could be added
        to the message, otherwise false is returned.
        This function updates the length field of the Netlink message (nlmsg_len)
        by adding the size (header + payload) of the new attribute.

        @type l: number
        @param l: size of buffer which stores the message
        @type t: number
        @param t: netlink attribute type
        @type d: number
        @param d: 64-bit unsigned integer data that is stored by the new attribute

        @rtype: bool
        @return: if the attribute could be added to the message or not
        """
        return _attr.attr_put_u64_check(self, l, t, d)

    def put_str_check(self, l, t, d):
        """add string attribute to netlink message

        This function first checks that the data can be added to the message
        (fits into the buffer) and then updates the length field of the Netlink
        message (nlmsg_len) by adding the size (header + payload) of the new
        attribute. The function returns true if the attribute could be added
        to the message, otherwise false is returned.
        This function updates the length field of the Netlink message (nlmsg_len)
        by adding the size (header + payload) of the new attribute.

        @type l: number
        @param l: size of buffer which stores the message
        @type t: number
        @param t: netlink attribute type
        @type d: string
        @param d: string data that is stored by the new attribute

        @rtype: bool
        @return: if the attribute could be added to the message or not
        """
        return _attr.attr_put_str_check(self, l, t, d)

    def put_strz_check(self, l, t, d):
        """add string attribute to netlink message

        This function is similar to mnl_attr_put_str, but it includes the
        NUL/zero ('\\0') terminator at the end of the string.

        This function first checks that the data can be added to the message
        (fits into the buffer) and then updates the length field of the Netlink
        message (nlmsg_len) by adding the size (header + payload) of the new
        attribute. The function returns true if the attribute could be added
        to the message, otherwise false is returned.

        @type l: number
        @param l: size of buffer which stores the message
        @type t: number
        @param t: netlink attribute type
        @type d: string
        @param d: string data that is stored by the new attribute

        @rtype: bool
        @return: if the attribute could be added to the message or not
        """
        return _attr.attr_put_strz_check(self, l, t, d)

    def nest_start_check(self, l, t):
        """start an attribute nest

        This function adds the attribute header that identifies the beginning of
        an attribute nest. If the nested attribute cannot be added then None,
        otherwise valid Attr object beginning of the nest is returned.

        @type l: number
        @param l: size of buffer which stores the message
        @type t: number
        @param t: netlink attribute type

        @rtype: Attr
        @return: Attr beginning of the nest or None if error
        """
        ret = _attr.attr_nest_start_check(self, l, t)
        if ret is None: return None
        return ctypes.cast(ctypes.addressof(ret), ctypes.POINTER(Attr)).contents

    def nest_end(self, a):
        """end an attribute nest

        This function updates the attribute header that identifies the nest.

        @type a: Attr
        @param a: attribute nest returned by mnl_attr_nest_start()
        """
        _attr.attr_nest_end(self, a)

    def nest_cancel(self, a):
        """cancel an attribute nest

        This function updates the attribute header that identifies the nest.

        @type a: Attr
        @param a: attribute nest returned by mnl_attr_nest_start()
        """
        _attr.attr_nest_cancel(self, a)


    @staticmethod
    def size(l):
        """calculate the size of Netlink message (without alignment)

        @type l: number
        @param l: length of the Netlink payload

        @rtype: number
        @return: the size of a netlink message (header plus payload) without alignment
        """
        return _nlmsg.nlmsg_size(l)

    def get_payload_len(self):
        """get the length of the Netlink payload

        This function returns the Length of the netlink payload, ie. the length
        of the full message minus the size of the Netlink header.

        @rtype: number
        @return: the Length of the netlink payload
        """
        return _nlmsg.nlmsg_get_payload_len(self)

    def put_extra_header(self, l):
        """reserve and prepare room for an extra header

        This function sets to zero the room that is required to put the extra
        header after the initial Netlink header. This function also increases
        the nlmsg_len field. You have to invoke mnl_nlmsg_put_header() before
        you call this function. This function returns a pointer to the extra
        header.

        @type l: number
        @param l: size of the extra header that we want to put

        @rtype: ctypes.c_void_p
        @return: a pointer to the extra header
        """
        return _nlmsg.nlmsg_put_extra_header(self, l)

    def put_extra_header_v(self, l):
        """reserve and prepare room for an extra header

        This function wraps put_extra_header()

        @type l: number
        @param l: size of the extra header that we want to put

        @rtype: array of ctypes.c_u_byte
        @return: the extra header buffer
        """
        return _nlmsg.nlmsg_put_extra_header_v(self, l)

    def put_extra_header_as(self, cls, size=None):
        """reserve and prepare room for an extra header

        This function wraps put_extra_header().
        Param cls must be a ctypes data type.

        @type l: number
        @param l: size of the extra header that we want to put
        @type cls: class
        @param cls: class of return value

        @rtype: specified by param c
        @return: an instance of the attribute payload
        """
        return _nlmsg.nlmsg_put_extra_header_as(self, cls, size)

    def get_payload(self):
        """get a pointer to the payload of the netlink message

        @rtype: ctypes.c_void_p
        @return: a pointer to the payload of the netlink message.
        """
        return _nlmsg.nlmsg_get_payload(self)

    def get_payload_v(self):
        """get a buffer of the payload of the netlink message

        This function wraps get_payload()

        @rtype: array of ctypes.c_u_byte
        @return: a buffer of the payload of the netlink message.
        """
        return _nlmsg.nlmsg_get_payload_v(self)

    def get_payload_as(self, c):
        """get the payload of the netlink message as a specified instance

        This function wraps get_payload(). 
        Param c must be a ctypes data type.

        @type c: class
        @param c: class of return value

        @rtype: specified by param c
        @return: the payload of the netlink message as a specified class.
        """
        return _nlmsg.nlmsg_get_payload_as(self, c)

    def get_payload_offset(self, o):
        """get a pointer to the payload of the message

        @type o: number
        @param o: offset to the payload of the attributes TLV set

        @rtype: ctypes.c_void_p
        @return: a pointer to the payload of the netlink message plus a given offset
        """
        return _nlmsg.nlmsg_get_payload_offset(self, o)

    def get_payload_offset_v(self, o):
        """get a buffer of the payload of the message

        This function wraps get_payload_offset().

        @type o: number
        @param o: offset to the payload of the attributes TLV set

        @rtype: array of ctypes.c_ubyte
        @return: a pointer to the payload of the netlink message plus a given offset
        """
        return _nlmsg.nlmsg_get_payload_offset_v(self, o)

    def get_payload_offset_as(self, o, c):
        """get the payload of the message as a specified instance

        This function wraps get_payload_offset().
        Param c must be a ctypes data type.

        @type c: class
        @param c: class of return value

        @rtype: specified by param c
        @return: the payload of the netlink message as a specified class.
        """
        return _nlmsg.nlmsg_get_payload_offset_as(self, o, c)

    def ok(self, size):
        """check a there is room for netlink message

        This function is used to check that a buffer that contains a netlink
        message has enough room for the netlink message that it stores, ie. this
        function can be used to verify that a netlink message is not malformed nor
        truncated.

        This function does not raise OSError in case of error since it is intended
        for iterations. Thus, it returns true on success and false on error.

        The size parameter may become negative in malformed messages during message
        iteration, that is why we use a signed integer.

        @type size: number
        @param size: remaining bytes in a buffer that contains the netlink message

        @rtype: bool
        @return: the netlink message is not malformed nor truncated
        """
        return _nlmsg.nlmsg_ok(self, size)

    def get_payload_tail(self):
        """get the ending of the netlink message

        This function returns a pointer to the netlink message tail. This is useful
        to build a message since we continue adding attributes at the end of the
        message.

        @rtype: ctypes.c_void_p
        @return: a pointer to the netlink message tail
        """
        return _nlmsg.nlmsg_get_payload_tail(self)

    def seq_ok(self, seq):
        """perform sequence tracking

        This functions returns true if the sequence tracking is fulfilled, otherwise
        false is returned. We skip the tracking for netlink messages whose sequence
        number is zero since it is usually reserved for event-based kernel
        notifications. On the other hand, if seq is set but the message sequence
        number is not set (i.e. this is an event message coming from kernel-space),
        then we also skip the tracking. This approach is good if we use the same
        socket to send commands to kernel-space (that we want to track) and to
        listen to events (that we do not track).

        @type seq: number
        @param seq: last sequence number used to send a message

        @rtype: bool
        @return: the sequence tracking is fulfilled or not
        """
        return _nlmsg.nlmsg_seq_ok(self, seq)

    def portid_ok(self, pid):
        """perform portID origin check

        This functions returns true if the origin is fulfilled, otherwise
        false is returned. We skip the tracking for netlink message whose portID
        is zero since it is reserved for event-based kernel notifications. On the
        other hand, if portid is set but the message PortID is not (i.e. this
        is an event message coming from kernel-space), then we also skip the
        tracking. This approach is good if we use the same socket to send commands
        to kernel-space (that we want to track) and to listen to events (that we
        do not track).

        @type pid: number
        @param pid: netlink portid that we want to check

        @rtype: bool
        @return: if the origin is fulfilled or not
        """
        return _nlmsg.nlmsg_portid_ok(self, pid)

    def next_header(self, size):
        """get the next netlink message in a multipart message

        This function returns a pointer to the next netlink message that is part
        of a multi-part netlink message. Netlink can batch several messages into
        one buffer so that the receiver has to iterate over the whole set of
        Netlink messages.

        @type size: number
        @param size: length of the remaining bytes in the buffer (passed by reference)
        """
        nlh, size = _nlmsg.nlmsg_next(self, size)
        return ctypes.cast(ctypes.addressof(nlh), ctypes.POINTER(self.__class__)).contents, size

    def put_header(self):
        """reserve and prepare room for Netlink header

        This function sets to zero the room that is required to put the Netlink
        header in the memory buffer passed as parameter. This function also
        initializes the nlmsg_len field to the size of the Netlink header. This
        function returns a pointer to the Netlink header structure.
        """
        _cproto.c_nlmsg_put_header(ctypes.addressof(self))

    @staticmethod
    def put_new_header(size):
        """create Netlink header and prepare room

        This function creates Netlink header and apply put_header() for it.

        @type size: number
        @param size: buffer size

        @rtype: Nlmsg
        @return: new created and room prepared Netlink header 
        """
        nlh = Nlmsg(bytearray(size))
        nlh.put_header()
        return nlh


    def fprint(self, elen, out=None):
        """print netlink message to file

        This function prints the netlink header to a file handle.
        It may be useful for debugging purposes. One example of the output
        is the following:

          ----------------        ------------------
          |  0000000040  |        | message length |
          | 00016 | R-A- |        |  type | flags  |
          |  1289148991  |        | sequence number|
          |  0000000000  |        |     port ID    |
          ----------------        ------------------
          | 00 00 00 00  |        |  extra header  |
          | 00 00 00 00  |        |  extra header  |
          | 01 00 00 00  |        |  extra header  |
          | 01 00 00 00  |        |  extra header  |
          |00008|--|00003|        |len |flags| type|
          | 65 74 68 30  |        |      data      |       e t h 0
          ----------------        ------------------

        This example above shows the netlink message that is send to kernel-space
        to set up the link interface eth0. The netlink and attribute header data
        are displayed in base 10 whereas the extra header and the attribute payload
        are expressed in base 16. The possible flags in the netlink header are:

        - R, that indicates that NLM_F_REQUEST is set.
        - M, that indicates that NLM_F_MULTI is set.
        - A, that indicates that NLM_F_ACK is set.
        - E, that indicates that NLM_F_ECHO is set.

        The lack of one flag is displayed with '-'. On the other hand, the possible
        attribute flags available are:

        - N, that indicates that NLA_F_NESTED is set.
        - B, that indicates that NLA_F_NET_BYTEORDER is set.

        @type elen: number
        @param elen: size of the extra header (if any)
        @type out: file
        @param out: output file object
        """
        _nlmsg.nlmsg_fprint(ctypes.cast(ctypes.addressof(self), ctypes.POINTER(ctypes.c_ubyte * self.nlmsg_len)).contents, elen, out)

    def attributes(self, offset):
        """mnl_attr_for_each() macro in libmnl.h
        """
        a = self.get_payload_offset_as(offset, Attr)
        while a.ok(self.get_payload_tail() - ctypes.addressof(a)):
            yield a
            a = a.next_attribute()



# to implement nlmsg_batch_current
class NlmsgBatch(object):
    """Netlink message batch helpers

    This library provides helpers to batch several messages into one single
    datagram. These helpers do not perform strict memory boundary checkings.

    The following figure represents a Netlink message batch:

      |<-------------- MNL_SOCKET_BUFFER_SIZE ------------->|
      |<-------------------- batch ------------------>|     |
      |-----------|-----------|-----------|-----------|-----------|
      |<- nlmsg ->|<- nlmsg ->|<- nlmsg ->|<- nlmsg ->|<- nlmsg ->|
      |-----------|-----------|-----------|-----------|-----------|
                                                  ^           ^
                                                  |           |
                                             message N   message N+1

    To start the batch, you have to create one by NlmsgBatch() and you can
    use .stop() method to release it. Or you can use it as context. You do not
    need to call .stop() in this case.

        with NlmsgBatch() as b:
            ... do something

    You have to .next_batch() to get room for a new message in the batch. If
    this function returns None, it means that the last message that was added
    (message N+1 in the figure above) does not fit the batch. Thus, you have to
    send the batch (which includes until message N) and, then, you have to call
    .reset() to re-initialize the batch (this moves message N+1 to the head of
    the buffer). For that reason, the buffer that you have to use to store the
    batch must be double of MNL_SOCKET_BUFFER_SIZE to ensure that the last
    message (message N+1) that did not fit into the batch is written inside
    valid memory boundaries.
    """

    def __init__(self, bufsize, limit): # start
        """initialize a batch

        The buffer that you pass must be double of MNL_SOCKET_BUFFER_SIZE. The
        limit must be half of the buffer size, otherwise expect funny memory
        corruptions 8-).

        You can allocate the buffer that you use to store the batch in the stack or
        the heap, no restrictions in this regard. This function returns None on
        error.

        @type bufsize: number
        @param bufsize: buffer size
        @type limit: number
        @param limit: maximum size of the batch (should be MNL_SOCKET_BUFFER_SIZE)
        """
        if bufsize < limit: raise ValueError("bufsize is smaller than limit")
        self._buf = bytearray(bufsize) # for current_v()
        self._batch = _nlmsg.nlmsg_batch_start(self._buf, limit)

    def stop(self):
        """release a batch

        This function releases the batch.
        """
        _nlmsg.nlmsg_batch_stop(self._batch)

    def next_batch(self):
        """get room for the next message in the batch

        This function returns false if the last message did not fit into the
        batch. Otherwise, it prepares the batch to provide room for the new
        Netlink message in the batch and returns true.

        You have to put at least one message in the batch before calling this
        function, otherwise your application is likely to crash.

        @rtype: bool
        @return: the last message did not fit into the batch or not
        """
        return _nlmsg.nlmsg_batch_next(self._batch)

    def reset(self):
        """reset the batch

        This function allows to reset a batch, so you can reuse it to create a
        new one. This function moves the last message which does not fit the
        batch to the head of the buffer, if any.
        """
        _nlmsg.nlmsg_batch_reset(self._batch)

    def size(self):
        """get current size of the batch

        @rtype: number
        @return: the current size of the batch
        """
        return _nlmsg.nlmsg_batch_size(self._batch)

    def head(self):
        """get head of this batch

        This function returns a pointer to the head of the batch, which is the
        beginning of the buffer that is used.

        @rtype: ctypes.c_void_p
        @return: a pointer to the head of the batch
        """
        return _nlmsg.nlmsg_batch_head_v(self._batch)

    def is_empty(self):
        """check if there is any message in the batch

        @rtype: bool
        @return: if the batch is empty or not
        """
        return _nlmsg.nlmsg_batch_is_empty(self._batch)

    def current(self):
        """returns current position in the batch

        This function returns a pointer to the current position in the buffer
        that is used to store the batch.

        @rtype: ctypes.c_void_p
        @return: a pointer to the current position in the buffer
        """
        return _nlmsg.nlmsg_batch_current(self._batch)

    def current_v(self):
        """returns current buffer in the batch

        This function wraps current().

        @rtype: array of ctypes.c_ubyte
        @return: the current position in the buffer as array
        """
        current = _nlmsg.nlmsg_batch_current(self._batch)
        size =  _nlmsg.nlmsg_batch_head(self._batch) + len(self._buf) - current
        return ctypes.cast(current, ctypes.POINTER(ctypes.c_ubyte * size)).contents

    def __enter__(self):
        return self

    def __exit__(self, t, v, tb):
        self.stop()
        return False


class Socket(object):
    """Netlink socket helpers
    """
    def __init__(self, bus_or_socket):
        """open a netlink socket

        The socket object is not dup'ed, and will be closed when the socket
        object created by this is closed.

        raises OSError on error.

        @type bus_or_socket: number
        @param bus_or_socket: the netlink socket bus ID (see NETLINK_* constants)
                              or pre-existig socket object
        """
        import socket
        if isinstance(bus_or_socket, socket.socket):
            # hold original socket here since socket will be invalid if caller
            # drops socket reference
            self._sock = bus_or_socket
            self._nls = _socket.socket_fdopen(bus_or_socket.fileno())
        else:
            self._nls = _socket.socket_open(bus_or_socket)

    def get_fd(self):
        """obtain file descriptor from netlink socket

        @rtype: number
        @return: the file descriptor of a given netlink socket
        """
        return _socket.socket_get_fd(self._nls)

    def fileno(self):
        """alias for get_fd()"""
        return self.get_fd()

    def get_portid(self):
        """obtain Netlink PortID from netlink socket

        This function returns the Netlink PortID of a given netlink socket.
        It's a common mistake to assume that this PortID equals the process ID
        which is not always true. This is the case if you open more than one
        socket that is binded to the same Netlink subsystem from the same process.

        @rtype: number
        @return: the Netlink PortID of a given netlink socket
        """
        return _socket.socket_get_portid(self._nls)

    def bind(self, groups, pid):
        """bind netlink socket

        On error, this function raises OSError. You can use MNL_SOCKET_AUTOPID
        which is 0 for automatic port ID selection.

        @type groups: number
        @param groups: the group of message you're interested in
        @type pid: number
        @param pid: the port ID you want to use (use zero for automatic selection)
        """
        _socket.socket_bind(self._nls, groups, pid)

    if _cproto.HAS_MNL_RING:
        def set_ringopt(self, rt, bs, bn, fs, fn):
            """
            """
            _socket.socket_set_ringopt(self._nls, rt, bs, bn, fs, fn)

        def map_ring(self, flags):
            """
            """
            _socket.socket_map_ring(self._nls, flags)

        def unmap_ring(self):
            """
            """
            _socket.socket_unmap_ring(self._nls)

        def get_ring(self, rt):
            """
            """
            return Ring(_socket.socket_get_ring(self._nls, rt))

    def sendto(self, buf):
        """send a netlink message of a certain size

        On error, it raises OSError. Otherwise, it returns the number of bytes
        sent.

        @type buf: bytearray or something buffer, not bytes
        @param buf: buffer containing the netlink message to be sent

        @rtype: number
        @return: the number of bytes sent
        """
        return _socket.socket_sendto(self._nls, buf)

    def send_nlmsg(self, nlh):
        """send a netlink message

        This function wraps sendto().

        @type nlh: Nlmsghdr or its subclass
        @param nlh: sending netlink message

        @rtype: number
        @return: the number of bytes sent
        """
        return _socket.socket_send_nlmsg(self._nls, nlh)

    def recv(self, size):
        """receive a netlink message

        This function wraps recv_into().

        @type size: number
        @param size: buffer size

        @rtype: number
        @return: the number of bytes received
        """
        return _socket.socket_recv(self._nls, size)

    def recv_into(self, buf):
        """receive a netlink message

        On error, it raises OSError. If errno is set to ENOSPC, it means that
        the buffer that you have passed to store the netlink message is too
        small, so you have received a truncated message.  To avoid this, you
        have to allocate a buffer of MNL_SOCKET_BUFFER_SIZE (which is 8KB, see
        linux/netlink.h for more information). Using this buffer size ensures
        that your buffer is big enough to store the netlink message without
        truncating it.

        @type buf: mutable buffer - bytearray
        @param buf: buffer that you want to use to store the netlink message

        @rtype: number
        @return: the number of bytes received
        """
        return _socket.socket_recv_into(self._nls, buf)

    def close(self):
        """close a given netlink socket

        On error, this function raises OSError.
        """
        if hasattr(self, "_sock"):
            self._sock.close()
            return 0
        return _socket.socket_close(self._nls)

    def setsockopt(self, t, b):
        """set Netlink socket option

        This function allows you to set some Netlink socket option. As of writing
        this (see linux/netlink.h), the existing options are:

        - #define NETLINK_ADD_MEMBERSHIP  1
        - #define NETLINK_DROP_MEMBERSHIP 2
        - #define NETLINK_PKTINFO         3
        - #define NETLINK_BROADCAST_ERROR 4
        - #define NETLINK_NO_ENOBUFS      5

        In the early days, Netlink only supported 32 groups expressed in a
        32-bits mask. However, since 2.6.14, Netlink may have up to 2^32 multicast
        groups but you have to use setsockopt() with NETLINK_ADD_MEMBERSHIP to
        join a given multicast group. This function internally calls setsockopt()
        to join a given netlink multicast group. You can still use mnl_bind()
        and the 32-bit mask to join a set of Netlink multicast groups.

        On error, this function raises OSError.

        @type t: number
        @param t: type of Netlink socket options
        @type b: bytes or bytearray
        @param b: the buffer that contains the data about this option
        """
        _socket.socket_setsockopt(self._nls, t, b)

    def getsockopt(self, t, size):
        """get a Netlink socket option

        On error, this function raises OSError

        @type t: number
        @param t: type of Netlink socket options
        @type size: number
        @param size: size of the information written in the buffer

        @rtype: bytes
        @return: the value of this option
        """
        return _socket.socket_getsockopt(self._nls, t, size)

    def getsockopt_as(self, t, c):
        """get a Netlink socket option

        This function wraps getsockopt().

        @type t: number
        @param t: type of Netlink socket options
        @type c: class
        @param c: class of return value

        @rtype: specified by param c
        @return: the option value as a specified class
        """
        return _socket.socket_getsockopt_ctype(self._nls, t, c)

    def __enter__(self):
        return self

    def __exit__(self, t, v, tb):
        _socket.socket_close(self._nls)
        return False


if _cproto.HAS_MNL_RING:
    class Ring(object):
        def __init__(self, ring):
            """
            """
            self._ring = ring

        def advance(self):
            """
            """
            _socket.ring_advance(self._ring)

        def current_frame(self):
            """
            """
            return _socket.ring_current_frame(self._ring)


def payload_attributes(payload): # buffer
    """mnl_attr_for_each_payload() macro in libmnl.h
    """
    p = ctypes.addressof((ctypes.c_ubyte * len(payload)).from_buffer(payload))
    a = Attr(payload)
    while a.ok(p + len(payload) - ctypes.addressof(a)):
        yield a
        a = a.next_attribute()


def ptrs2attrs(ptrs, size):
    return {i: j.contents
            for i, j in enumerate((ctypes.POINTER(Attr) * size).from_address(ptrs))
            if j}


from . import _callback
nlmsg_cb = _callback._cb_factory(Nlmsg, _cproto.MNL_CB_T)
attr_cb  = _callback._cb_factory(Attr, _cproto.MNL_ATTR_CB_T)


from ._nlmsg import nlmsg_put_header
from ._attr import attr_parse_payload
from ._callback import cb_run, cb_run2, mnl_cb_t, mnl_attr_cb_t
