#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from cpylmnl import netlink, h
import cpylmnl.nlstructs.genetlink as genl
import cpylmnl as mnl


log = logging.getLogger(__name__)


@mnl.attribute_cb
def parse_mc_grps_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    try:
        attr.type_valid(h.CTRL_ATTR_MCAST_GRP_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == h.CTRL_ATTR_MCAST_GRP_ID:
        try:
            attr.validate(mnl.MNL_TYPE_U32)
        except OSError as e:
            print("mnl_attr_validate: %s" % err, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == h.CTRL_ATTR_MCAST_GRP_NAME:
        try:
            attr.validate(mnl.MNL_TYPE_STRING)
        except OSError as e:
            print("mnl_attr_validate: %s" % err, file=sys.stderr)
            return mnl.MNL_CB_ERROR

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def parse_genl_mc_grps(nested):
    for attr in nested.nesteds():
        tb = dict()
        attr.parse_nested(parse_mc_grps_cb, tb)

        if h.CTRL_ATTR_MCAST_GRP_ID in tb:
            print("id-0x%x " % tb[h.CTRL_ATTR_MCAST_GRP_ID].get_u32(),	end='')
        if h.CTRL_ATTR_MCAST_GRP_NAME in tb:
            print("name: %s " % tb[h.CTRL_ATTR_MCAST_GRP_NAME].get_str(),	end='')

        print()


@mnl.attribute_cb
def parse_family_ops_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(h.CTRL_ATTR_OP_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    if attr_type == h.CTRL_ATTR_OP_ID:
        try:
            attr.validate(mnl.MNL_TYPE_U32)
        except OSError as e:
            print("mnl_attr_validate: %s" % e, file=sys.stderr)
            return mnl.MNL_CB_ERROR
    elif attr_type == h.CTRL_ATTR_OP_MAX:
        pass
    else:
        return mnl.MNL_CB_OK

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


def parse_genl_family_ops(nested):
    for attr in nested.nesteds():
        tb = dict()

        attr.parse_nested(parse_family_ops_cb, tb)
        if h.CTRL_ATTR_OP_ID in tb:
            print("id-0x%s " % tb[h.CTRL_ATTR_OP_ID].get_u32(), end='')
        if h.CTRL_ATTR_OP_MAX in tb:
            print("flags ", end='')
        print()


@mnl.attribute_cb
def data_attr_cb(attr, tb):
    attr_type = attr.get_type()

    try:
        attr.type_valid(h.CTRL_ATTR_MAX)
    except OSError as e:
        return mnl.MNL_CB_OK

    def _validate_factory(t):
        def _validate(attr):
            try:
                attr.validate(t)
            except OSError as e:
                print("mnl_attr_validate: %s" % e, file=sys.stderr)
                return mnl.MNL_CB_ERROR
            return mnl.MNL_CB_OK
        return _validate

    ftbl = {h.CTRL_ATTR_FAMILY_NAME:  _validate_factory(mnl.MNL_TYPE_STRING),
            h.CTRL_ATTR_FAMILY_ID:    _validate_factory(mnl.MNL_TYPE_U16),
            h.CTRL_ATTR_VERSION:      _validate_factory(mnl.MNL_TYPE_U32),
            h.CTRL_ATTR_HDRSIZE:      _validate_factory(mnl.MNL_TYPE_U32),
            h.CTRL_ATTR_MAXATTR:      _validate_factory(mnl.MNL_TYPE_U32),
            h.CTRL_ATTR_OPS:          _validate_factory(mnl.MNL_TYPE_NESTED),
            h.CTRL_ATTR_MCAST_GROUPS: _validate_factory(mnl.MNL_TYPE_NESTED),
            }

    ret = ftbl.get(attr_type, lambda a: (0, None))(attr)
    if ret != mnl.MNL_CB_OK:
        return ret

    tb[attr_type] = attr
    return mnl.MNL_CB_OK


@mnl.header_cb
def data_cb(nlh, tb):
    genlh = genl.Genlmsghdr(nlh.get_payload_v())

    tb = dict()
    nlh.parse(genl.Genlmsghdr.sizeof(), data_attr_cb, tb)

    h.CTRL_ATTR_FAMILY_NAME in tb and print("name=%s\t" % tb[h.CTRL_ATTR_FAMILY_NAME].get_str(), end='')
    h.CTRL_ATTR_FAMILY_ID in tb   and print("id=%u\t" % tb[h.CTRL_ATTR_FAMILY_ID].get_u16(),     end='')
    h.CTRL_ATTR_VERSION in tb	  and print("version=%u\t" % tb[h.CTRL_ATTR_VERSION].get_u16(),  end='')
    h.CTRL_ATTR_HDRSIZE in tb	  and print("hdrsize=%u\t" % tb[h.CTRL_ATTR_HDRSIZE].get_u32(),  end='')
    h.CTRL_ATTR_MAXATTR in tb	  and print("maxattr=%u\t" % tb[h.CTRL_ATTR_MAXATTR].get_u32(),  end='')
    print()

    if h.CTRL_ATTR_OPS in tb:
        print("ops:")
        parse_genl_family_ops(tb[h.CTRL_ATTR_OPS])
    if h.CTRL_ATTR_MCAST_GROUPS in tb:
        print("grps:")
        parse_genl_mc_grps(tb[h.CTRL_ATTR_MCAST_GROUPS])
    print()

    return mnl.MNL_CB_OK


def main():
    if len(sys.argv) > 2:
        print("%s [family name]" % sys.argv[0])
        sys.exit(-1)

    nlh = mnl.put_new_header(mnl.MNL_SOCKET_BUFFER_SIZE)
    nlh.type = h.GENL_ID_CTRL
    nlh.flags = netlink.NLM_F_REQUEST | netlink.NLM_F_ACK
    seq = int(time.time())
    nlh.seq = seq

    genlh = nlh.put_extra_header_as(genl.Genlmsghdr)
    genlh.cmd = h.CTRL_CMD_GETFAMILY
    genlh.version = 1

    nlh.put_u32(h.CTRL_ATTR_FAMILY_ID, h.GENL_ID_CTRL)
    if len(sys.argv) >= 2:
        nlh.put_strz(h.CTRL_ATTR_FAMILY_NAME, sys.argv[1])
    else:
        nlh.flags |= netlink.NLM_F_DUMP

    with mnl.Socket(netlink.NETLINK_GENERIC) as nl:
        nl.bind(0, mnl.MNL_SOCKET_AUTOPID)
        portid = nl.get_portid()
        nl.send_nlmsg(nlh)

        ret = mnl.MNL_CB_OK
        while ret > mnl.MNL_CB_STOP:
            buf = nl.recv(mnl.MNL_SOCKET_BUFFER_SIZE)
            ret = mnl.cb_run(buf, seq, portid, data_cb, None)

    if ret < 0: # not valid. cb_run may raise Exception
        print("mnl_cb_run returns ERROR", file=sys.stderr)


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
