#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import absolute_import

from ctypes import *

class RtnlLinkStats(Structure):
    """struct rtnl_link_stats
    """
    _fields_ = [("rx_packets",		c_uint32), # __u32 rx_packets	 /* total packets received	 */
                ("tx_packets",		c_uint32), # __u32 tx_packets	 /* total packets transmitted	 */
                ("rx_bytes",		c_uint32), # __u32 rx_bytes	 /* total bytes received	 */
                ("tx_bytes",		c_uint32), # __u32 tx_bytes	 /* total bytes transmitted	 */
                ("rx_errors",		c_uint32), # __u32 rx_errors	 /* bad packets received	 */
                ("tx_errors",		c_uint32), # __u32 tx_errors	 /* packet transmit problems	 */
                ("rx_dropped",		c_uint32), # __u32 rx_dropped	 /* no space in linux buffers	 */
                ("tx_dropped",		c_uint32), # __u32 tx_dropped	 /* no space available in linux	 */
                ("multicast",		c_uint32), # __u32 multicast	 /* multicast packets received	 */
                ("collisions",		c_uint32), # __u32 collisions

                ## detailed rx_errors:
                ("rx_length_errors",	c_uint32), # __u32 rx_length_errors
                ("rx_over_errors",	c_uint32), # __u32 rx_over_errors   /* receiver ring buff overflow  */
                ("rx_crc_errors",	c_uint32), # __u32 rx_crc_errors    /* recved pkt with crc error    */
                ("rx_frame_errors",	c_uint32), # __u32 rx_frame_errors  /* recv'd frame alignment error */
                ("rx_fifo_errors",	c_uint32), # __u32 rx_fifo_errors   /* recv'r fifo overrun	    */
                ("rx_missed_errors",	c_uint32), # __u32 rx_missed_errors /* receiver missed packet	    */

                ## detailed tx_errors
                ("tx_aborted_errors",	c_uint32), # __u32 tx_aborted_errors
                ("tx_carrier_errors",	c_uint32), # __u32 tx_carrier_errors
                ("tx_fifo_errors",	c_uint32), # __u32 tx_fifo_errors
                ("tx_heartbear_errors",	c_uint32), # __u32 tx_heartbeat_errors
                ("tx_window_errors",	c_uint32), # __u32 tx_window_errors

                ## for cslip etc
                ("rx_compressed",	c_uint32), # __u32 rx_compressed
                ("tx_compressed",	c_uint32)] # __u32 tx_compressed



class RtnlLinkStats64(Structure):
    """struct rtnl_link_stats64
    """
    _fields_ = [("rx_packets",		c_uint64), # __u64 rx_packets	 /* total packets received	 */
                ("tx_packets",		c_uint64), # __u64 tx_packets	 /* total packets transmitted	 */
                ("rx_bytes",		c_uint64), # __u64 rx_bytes	 /* total bytes received	 */
                ("tx_bytes",		c_uint64), # __u64 tx_bytes	 /* total bytes transmitted	 */
                ("rx_errors",		c_uint64), # __u64 rx_errors	 /* bad packets received	 */
                ("tx_errors",		c_uint64), # __u64 tx_errors	 /* packet transmit problems	 */
                ("rx_dropped",		c_uint64), # __u64 rx_dropped	 /* no space in linux buffers	 */
                ("tx_dropped",		c_uint64), # __u64 tx_dropped	 /* no space available in linux	 */
                ("multicast",		c_uint64), # __u64 multicast	 /* multicast packets received	 */
                ("collisions",		c_uint64), # __u64 collisions

                ## detailed rx_errors:
                ("rx_length_errors",	c_uint64), # __u64 rx_length_errors
                ("rx_over_errors",	c_uint64), # __u64 rx_over_errors   /* receiver ring buff overflow  */
                ("rx_crc_errors",	c_uint64), # __u64 rx_crc_errors    /* recved pkt with crc error    */
                ("rx_frame_errors",	c_uint64), # __u64 rx_frame_errors  /* recv'd frame alignment error */
                ("rx_fifo_errors",	c_uint64), # __u64 rx_fifo_errors   /* recv'r fifo overrun	    */
                ("rx_missed_errors",	c_uint64), # __u64 rx_missed_errors /* receiver missed packet	    */

                ## detailed tx_errors
                ("tx_aborted_errors",	c_uint64), # __u64 tx_aborted_errors
                ("tx_carrier_errors",	c_uint64), # __u64 tx_carrier_errors
                ("tx_fifo_errors",	c_uint64), # __u64 tx_fifo_errors
                ("tx_heartbear_errors",	c_uint64), # __u64 tx_heartbeat_errors
                ("tx_window_errors",	c_uint64), # __u64 tx_window_errors

                ## for cslip etc
                ("rx_compressed",	c_uint64), # __u64 rx_compressed
                ("tx_compressed",	c_uint64)] # __u64 tx_compressed


class RtnlLinkIfmap(Structure):
    """struct rtnl_link_ifmap

    The struct should be in sync with struct ifmap
    """
    _fields_ = [("mem_start",	c_uint), # __u64	mem_start
                ("mem_end",	c_uint), # __u64	mem_end
                ("base_addr",	c_uint), # __u64	base_addr
                ("irq",		c_uint), # __u16	irq
                ("dma",		c_uint), # __u8	dma
                ("port",	c_uint)] # __u8	port


class IflaCacheinfo(Structure):
    """struct ifla_cacheinfo
    """
    _fields_ = [("max_reasm_len",	c_uint32), # __u32 max_reasm_len;
                ("tstamp",		c_uint32), # __u32 tstamp;         /* ipv6InterfaceTable updated timestamp */
                ("reachable_time",	c_uint32), # __u32 reachable_time;
                ("retrans_time",	c_uint32)] # __u32 retrans_time;


class IflaVlanFlags(Structure):
    """struct ifla_vlan_flags
    """
    _fields_ = [("flags",	c_uint32), # __u32 flags
                ("mask",	c_uint32)] # __u32 mask


class IflaVlanQosMapping(Structure):
    """struct ifla_vlan_qos_mapping
    """
    _fields_ = [("from",	c_uint32), # __u32 from
                ("to",		c_uint32)] # __u32 to


class IflaVxlanPortRange(Structure):
    """struct ifla_vxlan_port_range
    """
    _fields_ = [("low",		c_uint16), # __be16 low
                ("high", 	c_uint16)] # __be16 high


class IflaVfMac(Structure):
    """struct ifla_vf_mac
    """
    _fields_ = [("vf",	c_uint32),     # __u32 vf
                ("mac",	c_uint8 * 32)] # __u8 mac[32] /* MAX_ADDR_LEN */


"""
struct ifla_vf_vlan {
	__u32 vf;
	__u32 vlan; /* 0 - 4095, 0 disables VLAN filter */
	__u32 qos;
};


struct ifla_vf_tx_rate {
	__u32 vf;
	__u32 rate; /* Max TX bandwidth in Mbps, 0 disables throttling */
};

struct ifla_vf_spoofchk {
	__u32 vf;
	__u32 setting;
};


struct ifla_vf_link_state {
	__u32 vf;
	__u32 link_state;
};


struct ifla_port_vsi {
	__u8 vsi_mgr_id;
	__u8 vsi_type_id[3];
	__u8 vsi_type_version;
	__u8 pad[3];
};
"""
