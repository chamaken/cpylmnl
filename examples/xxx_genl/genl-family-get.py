#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function, absolute_import

import sys, logging, socket, time

from pylmnl import netlink
import pylmnl.netlink.rtnetlink as rtnl
import pylmnl.netlink.genetlink as genl
import pylmnl as mnl


log = logging.getLogger(__name__)


def parse_mc_grps_cb(attr, tb):
    attr_type = attr.get_type()

    # skip unsupported attribute in user-space
    rc, err = attr.type_valid(genl.CTRL_ATTR_MCAST_GRP.MAX)
    if not rc:
        return mnl.CB.OK, None

    if attr_type == genl.CTRL_ATTR_MCAST_GRP.ID:
        rc, err = attr.validate(mnl.TYPE.U32)
        if rc < 0:
            print("mnl_attr_validate: %s" % err)
            return mnl.CB.ERROR, None
    elif attr_type == genl.CTRL_ATTR_MCAST_GRP.NAME:
        rc, err = attr.validate(mnl.TYPE.STRING)
        if rc < 0:
            print("mnl_attr_validate: %s" % err)
            return mnl.CB.ERROR, None

    tb[attr_type] = attr
    return mnl.CB.OK, None


def parse_genl_mc_grps(nested):
    for attr in nested.nested_attrs():
        tb = dict()
        attr.parse_nested(parse_mc_grps_cb, tb)

        if genl.CTRL_ATTR_MCAST_GRP.ID in tb:
            print("id-0x%x " % tb[genl.CTRL_ATTR_MCAST_GRP.ID].get_u32(),	end='')
        if genl.CTRL_ATTR_MCAST_GRP.NAME in tb:
            print("name: %s " % tb[genl.CTRL_ATTR_MCAST_GRP.NAME].get_str(),	end='')

        print()


def parse_family_ops_cb(attr, tb):
    attr_type = attr.get_type()

    rc, err = attr.type_valid(genl.CTRL_ATTR_OP.MAX)
    if not rc:
        return mnl.CB.OK, None

    if attr_type == genl.CTRL_ATTR_OP.ID:
        rc, err = attr.validate(mnl.TYPE.U32)
        if rc < 0:
            print("mnl_attr_validate: %s" % err)
            return mnl.CB.ERROR, err
    elif attr_type == genl.CTRL_ATTR_OP.MAX:
        pass
    else:
        return mnl.CB.OK, None

    tb[attr_type] = attr
    return mnl.CB.OK, None


def parse_genl_family_ops(nested):
    for attr in nested.nested_attrs():
        tb = dict()

        attr.parse_nested(parse_family_ops_cb, tb)
        if genl.CTRL_ATTR_OP.ID in tb:
            print("id-0x%s " % tb[genl.CTRL_ATTR_OP.ID].get_u32(), end='')
        if genl.CTRL_ATTR_OP.MAX in tb:
            print("flags ", end='')
        print()


def data_attr_cb(attr, tb):
    attr_type = attr.get_type()

    rc, err = attr.type_valid(genl.CTRL_ATTR.MAX)
    if not rc:
        return mnl.CB.OK, None

    def _validate_factory(t):
        def _validate(attr):
            rc, err = attr.validate(t)
            if rc < 0:
                print("mnl_attr_validate: %s" % err, file=sys.stderr)
                return mnl.CB.ERROR, err
            return mnl.CB.OK, None
        return _validate

    ftbl = {genl.CTRL_ATTR.FAMILY_NAME:  _validate_factory(mnl.TYPE.STRING),
            genl.CTRL_ATTR.FAMILY_ID:	 _validate_factory(mnl.TYPE.U16),
            genl.CTRL_ATTR.VERSION:	 _validate_factory(mnl.TYPE.U32),
            genl.CTRL_ATTR.HDRSIZE:	 _validate_factory(mnl.TYPE.U32),
            genl.CTRL_ATTR.MAXATTR:	 _validate_factory(mnl.TYPE.U32),
            genl.CTRL_ATTR.OPS:		 _validate_factory(mnl.TYPE.NESTED),
            genl.CTRL_ATTR.MCAST_GROUPS: _validate_factory(mnl.TYPE.NESTED),
            }
    rc, err = ftbl.get(attr_type, lambda a: (0, None))(attr)
    if rc < 0:
        return rc, err

    tb[attr_type] = attr
    return mnl.CB.OK, None


def data_cb(nlh, tb):
    genlh = genl.GENLMsgHdr(nlh.get_payload())

    tb = dict()
    nlh.parse(genl.GENLMsgHdr.SIZEOF, data_attr_cb, tb)

    genl.CTRL_ATTR.FAMILY_NAME in tb and print("name=%s\t" % tb[genl.CTRL_ATTR.FAMILY_NAME].get_str(), end='')
    genl.CTRL_ATTR.FAMILY_ID in tb   and print("id=%u\t" % tb[genl.CTRL_ATTR.FAMILY_ID].get_u16(),     end='')
    genl.CTRL_ATTR.VERSION in tb	   and print("version=%u\t" % tb[genl.CTRL_ATTR.VERSION].get_u16(),  end='')
    genl.CTRL_ATTR.HDRSIZE in tb	   and print("hdrsize=%u\t" % tb[genl.CTRL_ATTR.HDRSIZE].get_u32(),  end='')
    genl.CTRL_ATTR.MAXATTR in tb	   and print("maxattr=%u\t" % tb[genl.CTRL_ATTR.MAXATTR].get_u32(),  end='')
    print()

    if genl.CTRL_ATTR.OPS in tb:
        print("ops:")
        parse_genl_family_ops(tb[genl.CTRL_ATTR.OPS])
    if genl.CTRL_ATTR.MCAST_GROUPS in tb:
        print("grps:")
        parse_genl_mc_grps(tb[genl.CTRL_ATTR.MCAST_GROUPS])
    print()

    return mnl.CB.OK, None


def main():
    if len(sys.argv) > 2:
        print("%s [family name]" % sys.argv[0])
        sys.exit(-1)

    nlh = mnl.Message()
    nlh = nlh.put_header()
    nlh.type = genl.GENL_ID_CTRL
    nlh.flags = netlink.NLM_F.REQUEST | netlink.NLM_F.ACK
    seq = int(time.time())
    nlh.seq = seq

    genlh = genl.GENLMsgHdr(nlh.put_extra_header(genl.GENLMsgHdr.SIZEOF))
    genlh.cmd = genl.CTRL_CMD.GETFAMILY
    genlh.version = 1

    nlh.attr_put_u32(genl.CTRL_ATTR.FAMILY_ID, genl.GENL_ID_CTRL)
    if len(sys.argv) >= 2:
        nlh.put_strz(genl.CTRL_ATTR.FAMILY_NAME, sys.argv[1])
    else:
        nlh.flags |= netlink.NLM_F.DUMP

    nl = mnl.Socket()
    nl.open(netlink.NETLINK_PROTO.GENERIC)
    nl.bind(0, mnl.SOCKET_AUTOPID)
    portid = nl.get_portid()

    nl.send_nlmsg(nlh)

    buf = nl.recvfrom(mnl.SOCKET_BUFFER_SIZE)
    err = None
    while len(buf) > 0:
        ret, err = mnl.cb_run(buf, seq, portid, data_cb, None)
        if ret <= 0:
            break
        buf = nl.recvfrom(mnl.SOCKET_BUFFER_SIZE)

    if err is not None:
        print("error: %s" % err, file=sys.stderr)
        sys.exit(-1)

    nl.close()

    return 0


if __name__ == '__main__':
    logging.basicConfig(level=logging.WARN,
                        format='%(asctime)s %(levelname)s %(module)s.%(funcName)s line: %(lineno)d %(message)s')
    main()
