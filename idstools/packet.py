# Copyright (c) 2014 Jason Ish
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

"""Provides basic packet decoding."""

import struct
import socket

from idstools import util

ETHERTYPE_IP = 0x0800
ETHERTYPE_IP6 = 0x86dd

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17
IPPROTO_ICMPV6 = 58

ETHER_HDR_LEN = 14
IP_HDR_LEN = 20
IP6_HDR_LEN = 40
ICMP4_HDR_LEN = 4
ICMP6_HDR_LEN = 4
UDP_HDR_LEN = 8
TCP_HDR_LEN = 20

# IPv6 Extension Headers
IP6_EXT_HOP_BY_HOP = 0
IP6_EXT_DEST_OPTS = 60
IP6_EXT_ROUTING = 43
IP6_EXT_FRAGMENT = 44
IP6_EXT_AH = 51
IP6_EXT_ESP = 50
IP6_EXT_MOBILITY = 135

IP6_EXT_HEADER_TYPES = [
    IP6_EXT_HOP_BY_HOP,
    IP6_EXT_DEST_OPTS,
    IP6_EXT_ROUTING,
    IP6_EXT_FRAGMENT,
    IP6_EXT_AH,
    IP6_EXT_ESP,
    IP6_EXT_MOBILITY,
]

def printable_ethernet_addr(addr):
    """Return a formatted ethernet address from its raw form."""
    return ":".join(["%02x" % (x) for x in struct.unpack("BBBBBB", addr)])

def decode_icmp(pkt):
    """ Decode an ICMP packet. """
    icmp = {}

    (icmp["icmp_type"],
     icmp["icmp_code"],
     icmp["icmp_chksum"]) = struct.unpack(">BBH", pkt[0:ICMP4_HDR_LEN])

    icmp["icmp_payload"] = pkt[ICMP4_HDR_LEN:]

    return icmp

def decode_icmp6(pkt):
    """ Decode an ICMPv6 packet. """
    icmp = {}

    (icmp["icmp_type"],
     icmp["icmp_code"],
     icmp["icmp_chksum"]) = struct.unpack(">BBH", pkt[0:ICMP4_HDR_LEN])

    icmp["icmp_payload"] = pkt[ICMP6_HDR_LEN:]

    return icmp

def decode_udp(pkt):
    """Decode a UDP packet."""
    udp = {}

    (udp["udp_sport"],
     udp["udp_dport"],
     udp["udp_length"],
     udp["udp_chksum"]) = struct.unpack(">HHHH", pkt[0:UDP_HDR_LEN])

    udp["udp_payload"] = pkt[UDP_HDR_LEN:]

    return udp

def decode_tcp(pkt):
    """Decode a TCP packet."""
    tcp = {}

    (tcp["tcp_sport"],
     tcp["tcp_dport"],
     tcp["tcp_seq"],
     tcp["tcp_ack"],
     tcp["tcp_flags"],
     tcp["tcp_window"],
     tcp["tcp_chksum"],
     tcp["tcp_urgptr"]) = struct.unpack(">HHLLHHHH", pkt[0:TCP_HDR_LEN])

    tcp["tcp_offset"] = tcp["tcp_flags"] >> 12
    tcp["tcp_flags"] = tcp["tcp_flags"] & 0x1f

    data_offset = tcp["tcp_offset"] * 4
    if data_offset > TCP_HDR_LEN:
        tcp["tcp_options_raw"] = pkt[TCP_HDR_LEN:data_offset]
    tcp["tcp_payload"] = pkt[data_offset:]

    return tcp

def decode_ip(pkt):
    """Decode an IP packet."""
    ip = {}

    (ip["ip_version"],
     ip["ip_dscp"],
     ip["ip_length"],
     ip["ip_id"],
     ip["ip_offset"],
     ip["ip_ttl"],
     ip["ip_protocol"],
     ip["ip_chksum"],
     ip["ip_source"],
     ip["ip_destination"]) = struct.unpack(">BBHHHBBH4s4s", pkt[0:IP_HDR_LEN])

    ip["ip_ihl"] = ip["ip_version"] & 0xf
    ip["ip_version"] = ip["ip_version"] >> 4
    ip["ip_flags"] = ip["ip_offset"] >> 13
    ip["ip_offset"] = ip["ip_offset"] & 0x1fff
    ip["ip_source"] = socket.inet_ntoa(ip["ip_source"])
    ip["ip_destination"] = socket.inet_ntoa(ip["ip_destination"])

    ihl = ip["ip_ihl"] * 4
    if ihl > IP_HDR_LEN:
        ip["ip_options_raw"] = pkt[IP_HDR_LEN:ihl]

    if ip["ip_protocol"] == IPPROTO_ICMP:
        icmp = decode_icmp(pkt[ihl:])
        ip.update(icmp)
    elif ip["ip_protocol"] == IPPROTO_UDP:
        udp = decode_udp(pkt[ihl:])
        ip.update(udp)
    elif ip["ip_protocol"] == IPPROTO_TCP:
        tcp = decode_tcp(pkt[ihl:])
        ip.update(tcp)

    return ip

def decode_ip6(pkt):
    """Decode an IPv6 packet."""
    ip6 = {}

    (ip6["ip6_label"],
     ip6["ip6_length"],
     ip6["ip6_nh"],
     ip6["ip6_hop_limit"],
     ip6["ip6_source_raw"],
     ip6["ip6_destination_raw"]) = struct.unpack(
         ">LHBB16s16s", pkt[0:IP6_HDR_LEN])

    ip6["ip6_version"] = ip6["ip6_label"] >> 28
    ip6["ip6_class"] = (ip6["ip6_label"] >> 20) & 0xff
    ip6["ip6_label"] = ip6["ip6_label"] & 0xfffff
    ip6["ip6_source"] = util.decode_inet_addr(ip6["ip6_source_raw"])
    ip6["ip6_destination"] = util.decode_inet_addr(ip6["ip6_destination_raw"])

    offset = IP6_HDR_LEN

    # Skip over known extension headers.
    while True:
        if ip6["ip6_nh"] in IP6_EXT_HEADER_TYPES:
            ip6["ip6_nh"], ext_len = struct.unpack(">BB", pkt[offset:offset+2])
            offset += 8 + (ext_len * 8)
        else:
            break

    if ip6["ip6_nh"] == IPPROTO_UDP:
        ip6.update(decode_udp(pkt[offset:]))
    elif ip6["ip6_nh"] == IPPROTO_TCP:
        ip6.update(decode_tcp(pkt[offset:]))
    elif ip6["ip6_nh"] == IPPROTO_ICMPV6:
        ip6.update(decode_icmp6(pkt[offset:]))

    return ip6

def decode_ethernet(pkt):
    """Decode an ethernet packet."""
    ether = {}

    ether["ether_dst"], ether["ether_src"], ether["ether_type"] = struct.unpack(
        ">6s6sH", pkt[0:ETHER_HDR_LEN])

    ether["ether_dst"] = printable_ethernet_addr(ether["ether_dst"])
    ether["ether_src"] = printable_ethernet_addr(ether["ether_src"])

    if ether["ether_type"] == ETHERTYPE_IP:
        ether.update(decode_ip(pkt[ETHER_HDR_LEN:]))
    elif ether["ether_type"] == ETHERTYPE_IP6:
        ether.update(decode_ip6(pkt[ETHER_HDR_LEN:]))

    return ether
